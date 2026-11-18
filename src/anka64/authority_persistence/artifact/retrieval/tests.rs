use super::*;
use std::sync::atomic::{AtomicU64,Ordering};
static SERIAL:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {fn new()->Self {Self(std::env::temp_dir().join(format!("anka-sr110-{}-{}-{}",std::process::id(),
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),SERIAL.fetch_add(1,Ordering::Relaxed))))}}
impl Drop for Temp {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn caller()->Caller {Caller{owner:30,incarnation:4}}
fn limits()->Limits {Limits{max_payload:32768,window:257,owner_bytes:65536,total_bytes:131072,other_bytes:20000,work:200}}
fn bound()->RetrievalLimits {RetrievalLimits{max_bytes:32768,work:1000,timeout:Duration::from_secs(10)}}
fn manifest()->Manifest {Manifest{anchor:10,installation:20,artifact:40,generation:2,role:2,profile:1,
    size:ENVELOPE_HEADER as u64+80+10000,image:101,metadata:102,dependencies:103,provenance:104}}
fn bytes()->Vec<u8> {
    let mut b=b"ANKACS01".to_vec();
    for n in [1u64,2,1,10,20,40,2,9996,9996,0,10000,2,101,102,103,104] {b.extend(n.to_le_bytes());}
    for n in [10u64,20,80,3,84,10,20,90,4,94] {b.extend(n.to_le_bytes());}
    b.extend((0..10000).map(|n|n as u8));b
}
fn set(b:&mut[u8],index:usize,n:u64){b[8+index*8..16+index*8].copy_from_slice(&n.to_le_bytes());}
struct Proof {checks:usize,inspect:usize,deny_after:Option<usize>,boot:u64,valid:bool}
impl Default for Proof {fn default()->Self{Self{checks:0,inspect:0,deny_after:None,boot:9,valid:true}}}
impl Evidence for Proof {
    fn authorize(&mut self,s:Scope)->Verdict {
        self.checks+=1;
        if self.valid && s.manifest==manifest() && s.caller==caller() && s.boot==self.boot
            && !self.deny_after.is_some_and(|n|self.checks>n) {Verdict::Valid}else{Verdict::Invalid}
    }
    fn inspect(&mut self,r:&mut dyn Read)->Result<Manifest,Error> {
        self.inspect+=1;let expected=bytes();let mut offset=0;let mut chunk=[0u8;257];
        loop {let n=r.read(&mut chunk).map_err(io_error)?;if n==0 {break}
            if expected.get(offset..offset+n)!=Some(&chunk[..n]) {return Err(Error::CorruptRecord)} offset+=n;}
        if offset!=expected.len(){return Err(Error::CorruptRecord)}Ok(manifest())
    }
}
fn published()->(Temp,ArtifactStore,Proof) {
    let t=Temp::new();let mut s=ArtifactStore::create(&t.0,10,20,9,limits(),Selection{revision:7,artifact:55,generation:1}).unwrap();
    let mut p=Proof::default();let ticket=s.reserve(manifest(),caller(),&mut p).unwrap();
    for (i,chunk) in bytes().chunks(257).enumerate(){s.append(ticket,(i*257) as u64,chunk,&mut p).unwrap();}
    s.seal(ticket,&mut p).unwrap();s.publish(ticket,91,7,&mut p).unwrap();p.checks=0;p.inspect=0;(t,s,p)
}
#[test]
fn sr110_decode_preserves_exact_image_and_ordered_dependencies() {
    let b=bytes();let e=StoredEnvelope::decode(&b,manifest()).unwrap();
    assert_eq!(e.manifest(),manifest());assert_eq!(e.image(),&b[216..]);assert_eq!(e.code_size(),9996);
    assert_eq!(e.literal_start(),9996);assert_eq!(e.entry(),0);assert_eq!(e.dependency_count(),2);
    assert_eq!(e.dependency(0).unwrap().artifact,80);assert_eq!(e.dependency(1).unwrap().artifact,90);assert_eq!(e.dependency(2),None);
}
#[test]
fn sr110_decode_rejects_every_truncation_and_extra_tail() {
    let mut b=bytes();for n in 0..b.len(){assert!(StoredEnvelope::decode(&b[..n],manifest()).is_err(),"prefix {n}");}
    b.push(0);assert!(StoredEnvelope::decode(&b,manifest()).is_err());
}
#[test]
fn sr110_decode_rejects_header_geometry_overflow_and_unsupported_profile() {
    for (i,n) in [(0,2),(1,1),(2,0),(2,3),(7,0),(7,9995),(7,10004),(8,9995),(8,10001),
        (9,9996),(9,1),(10,u64::MAX),(10,9999),(11,0),(11,4097),(11,u64::MAX)] {
        let mut b=bytes();set(&mut b,i,n);assert!(StoredEnvelope::decode(&b,manifest()).is_err(),"word {i}={n}");
    }
    let mut b=bytes();b[0]^=1;assert!(StoredEnvelope::decode(&b,manifest()).is_err());
}
#[test]
fn sr110_decode_binds_all_persistent_identity_words() {
    for i in [3,4,5,6,12,13,14,15] {
        let mut b=bytes();let n=word(&b,8+i*8);set(&mut b,i,n+1);assert!(StoredEnvelope::decode(&b,manifest()).is_err());
    }
    let b=bytes();let mut m=manifest();m.size+=1;assert!(StoredEnvelope::decode(&b,m).is_err());
    let mut m=manifest();m.profile=2;assert!(StoredEnvelope::decode(&b,m).is_err());
}
#[test]
fn sr110_decode_dependency_namespace_and_zero_identity_reject() {
    for (offset,value) in [(136,11u64),(144,21),(152,0),(160,0),(168,0),(192,0)] {
        let mut b=bytes();b[offset..offset+8].copy_from_slice(&value.to_le_bytes());
        assert!(StoredEnvelope::decode(&b,manifest()).is_err());
    }
}
#[test]
fn sr110_file_read_is_exact_and_validates_full_payload_only_once() {
    let(t,mut s,mut p)=published();let head=fs::read(t.0.join(HEAD)).unwrap();let usage=s.usage().unwrap();
    let mut out=vec![0;manifest().size as usize];let mut budget=bound().start(manifest().size).unwrap();
    let scope=s.read_published_into(manifest(),caller(),&mut out,&mut p,&mut budget).unwrap();
    assert_eq!(out,bytes());assert_eq!(scope.action,Action::Read);assert_eq!(p.inspect,1);
    assert!(p.checks>40);assert!(budget.remaining<1000);assert_eq!(s.usage().unwrap(),usage);assert_eq!(fs::read(t.0.join(HEAD)).unwrap(),head);
}
#[test]
fn sr110_file_denial_precedes_validation_or_payload_reads() {
    let(_t,mut s,mut p)=published();p.valid=false;let mut out=vec![0;manifest().size as usize];let mut budget=bound().start(manifest().size).unwrap();
    assert_eq!(s.read_published_into(manifest(),caller(),&mut out,&mut p,&mut budget),Err(Error::Authority));
    assert_eq!(p.inspect,0);assert!(out.iter().all(|&b|b==0));
}
#[test]
fn sr110_file_manifest_substitution_and_wrong_extent_reject() {
    let(_t,mut s,mut p)=published();let mut out=vec![0;manifest().size as usize];let mut budget=bound().start(manifest().size).unwrap();
    let mut wrong=manifest();wrong.generation+=1;
    assert_eq!(s.read_published_into(wrong,caller(),&mut out,&mut p,&mut budget),Err(Error::Authority));
    assert_eq!(s.read_published_into(manifest(),caller(),&mut out[..10],&mut p,&mut budget),Err(Error::Authority));assert_eq!(p.inspect,0);
}
#[test]
fn sr110_file_midstream_revocation_never_returns_success() {
    let(t,mut s,mut p)=published();let head=fs::read(t.0.join(HEAD)).unwrap();p.deny_after=Some(4);
    let mut out=vec![0;manifest().size as usize];let mut budget=bound().start(manifest().size).unwrap();
    assert_eq!(s.read_published_into(manifest(),caller(),&mut out,&mut p,&mut budget),Err(Error::Authority));
    assert_eq!(&out[..257],&bytes()[..257]);assert!(out[257..].iter().all(|&b|b==0));
    // Buffer is private caller custody and must be destroyed before any refund.
    out.fill(0);assert_eq!(fs::read(t.0.join(HEAD)).unwrap(),head);
}
#[test]
fn sr110_file_cumulative_work_and_expired_deadline_fail_without_writes() {
    let(t,mut s,mut p)=published();let head=fs::read(t.0.join(HEAD)).unwrap();let mut out=vec![0;manifest().size as usize];
    let mut b=RetrievalBudget{remaining:8,deadline:Instant::now()+Duration::from_secs(10)};
    assert_eq!(s.read_published_into(manifest(),caller(),&mut out,&mut p,&mut b),Err(Error::Capacity));
    assert_eq!(b.remaining,0);
    let mut expired=RetrievalBudget{remaining:100,deadline:Instant::now()};let count=p.checks;
    assert_eq!(s.read_published_into(manifest(),caller(),&mut out,&mut p,&mut expired),Err(Error::ExpiredRequest));assert_eq!(count,p.checks);
    assert_eq!(fs::read(t.0.join(HEAD)).unwrap(),head);
}
#[test]
fn sr110_file_reopen_requires_current_boot_evidence() {
    let(t,s,mut p)=published();drop(s);let mut s=ArtifactStore::open(&t.0,10,20,10,limits()).unwrap();
    let mut out=vec![0;manifest().size as usize];let mut b=bound().start(manifest().size).unwrap();
    assert_eq!(s.read_published_into(manifest(),caller(),&mut out,&mut p,&mut b),Err(Error::Authority));
    p.boot=10;let mut b=bound().start(manifest().size).unwrap();s.read_published_into(manifest(),caller(),&mut out,&mut p,&mut b).unwrap();assert_eq!(out,bytes());
}
#[test]
fn sr110_file_corruption_rejects_before_independent_validation() {
    let(t,mut s,mut p)=published();let mut bad=bytes();bad[300]^=1;fs::write(t.0.join(DATA),bad).unwrap();
    let mut out=vec![0;manifest().size as usize];let mut b=bound().start(manifest().size).unwrap();
    assert_eq!(s.read_published_into(manifest(),caller(),&mut out,&mut p,&mut b),Err(Error::CorruptRecord));assert_eq!(p.inspect,0);
}
#[test]
fn sr110_budget_geometry_rejects_before_allocation() {
    for l in [RetrievalLimits{max_bytes:1,..bound()},RetrievalLimits{work:0,..bound()},RetrievalLimits{timeout:Duration::ZERO,..bound()}] {
        assert!(matches!(l.start(manifest().size),Err(Error::Capacity)));
    }
}
