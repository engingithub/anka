use super::*;
use std::{collections::BTreeSet,sync::atomic::{AtomicU64,Ordering}};
static SERIAL:AtomicU64=AtomicU64::new(0);
pub(crate) struct Temp(pub PathBuf);
impl Drop for Temp {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
pub(crate) fn manifest()->Manifest {Manifest{anchor:10,installation:20,artifact:99,generation:2,role:2,profile:1,size:10000,image:101,metadata:102,dependencies:103,provenance:104}}
pub(crate) fn caller()->Caller {Caller{owner:30,incarnation:4}}
pub(crate) fn request()->ReadRequest {ReadRequest{correlation:77,offset:4096,count:4096,manifest:manifest()}}
pub(crate) struct Proof {pub bytes:Vec<u8>,pub read:bool,pub checks:usize,pub inspections:usize,pub deny_after:Option<usize>,pub channels:BTreeSet<u64>,pub owner:Caller}
impl Evidence for Proof {
    fn authorize(&mut self,s:Scope)->Verdict {
        if s.manifest==manifest() && s.caller==caller() && (s.action!=Action::Read || self.read) {Verdict::Valid}else{Verdict::Invalid}
    }
    fn inspect(&mut self,r:&mut dyn Read)->Result<Manifest,Error> {
        self.inspections+=1;let mut b=[0;4096];let mut at=0;
        loop {let n=r.read(&mut b).map_err(io_error)?;if n==0 {break}
            if self.bytes.get(at..at+n)!=Some(&b[..n]) {return Err(Error::CorruptRecord)}at+=n;}
        if at!=self.bytes.len(){return Err(Error::CorruptRecord)}Ok(manifest())
    }
}
impl TransferEvidence for Proof {
    fn read_caller(&mut self,c:u64,r:&ReadRequest)->Result<Caller,Error> {
        self.checks+=1;
        if c==0 || !self.read || r.manifest!=manifest() || self.deny_after.is_some_and(|n|self.checks>n) {return Err(Error::Authority)}Ok(self.owner)
    }
}
pub(crate) struct Server {pub valid:bool}
impl ReadServerEvidence for Server {
    fn before_send(&mut self,c:u64,r:&ReadRequest)->Verdict {if c!=0 && self.valid && r.manifest==manifest(){Verdict::Valid}else{Verdict::Invalid}}
    fn current(&mut self,c:u64,r:&ReadRequest,reply:&[u8])->Verdict {
        if self.before_send(c,r)!=Verdict::Valid || reply.len()!=READ_REPLY_PREFIX+r.count as usize {return Verdict::Invalid}
        if reply[READ_REPLY_PREFIX..].iter().enumerate().all(|(i,b)|*b==(r.offset as usize+i)as u8){Verdict::Valid}else{Verdict::Invalid}
    }
}
pub(crate) fn fixture()->(Temp,ArtifactStore,Proof,Budget) {
    let t=Temp(std::env::temp_dir().join(format!("anka-ar110-{}-{}-{}",std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),SERIAL.fetch_add(1,Ordering::Relaxed))));
    let limits=Limits{max_payload:32768,window:4096,owner_bytes:65536,total_bytes:131072,other_bytes:20000,work:50};
    let mut s=ArtifactStore::create(&t.0,10,20,9,limits,Selection{revision:7,artifact:55,generation:1}).unwrap();
    let mut p=Proof{bytes:(0..10000).map(|n|n as u8).collect(),read:true,checks:0,inspections:0,deny_after:None,channels:BTreeSet::new(),owner:caller()};
    let ticket=s.reserve(manifest(),caller(),&mut p).unwrap();let data=p.bytes.clone();
    for(i,b)in data.chunks(4096).enumerate(){s.append(ticket,(i*4096)as u64,b,&mut p).unwrap();}
    s.seal(ticket,&mut p).unwrap();s.publish(ticket,91,7,&mut p).unwrap();p.inspections=0;
    (t,s,p,Budget::new(10000,100000,32768).unwrap())
}
fn put(b:&mut[u8],word:usize,n:u64){b[8+8*word..16+8*word].copy_from_slice(&n.to_le_bytes());}
#[test]
fn ar110_codec_exact_read_header_no_payload_and_full_width_role() {
    let r=request();let b=encode_read(r).unwrap();assert_eq!(b.len(),168);assert_eq!(&b[..8],b"ANKAUP01");assert_eq!(word(&b,1),7);assert_eq!(word(&b,5),4096);assert_eq!(decode_read(&b,true).unwrap(),r);
    assert!(decode(&b,true).is_err(),"legacy upload decoder must remain upload-only");
    for role in [0,1,258,65538,u64::MAX]{let mut bad=b;put(&mut bad,12,role);assert!(decode_read(&bad,true).is_err());}
}
#[test]
fn ar110_codec_every_request_truncation_tail_eof_and_reserved_field() {
    let b=encode_read(request()).unwrap();for n in 0..b.len(){assert!(decode_read(&b[..n],true).is_err());}
    let mut tail=b.to_vec();tail.push(0);assert!(decode_read(&tail,true).is_err());assert!(decode_read(&b,false).is_err());
    for (i,n) in [(0,2),(1,8),(2,0),(3,1),(5,0),(5,4097),(6,1),(7,1),(19,1)] {let mut bad=b;put(&mut bad,i,n);assert!(decode_read(&bad,true).is_err(),"word {i}");}
    let mut bad=b;bad[0]^=1;assert!(decode_read(&bad,true).is_err());
}
#[test]
fn ar110_codec_range_edges_and_overflow() {
    let r=ReadRequest{offset:9999,count:1,..request()};assert_eq!(decode_read(&encode_read(r).unwrap(),true).unwrap(),r);
    for (offset,count) in [(10000,1),(9999,2),(u64::MAX,2),(0,u64::MAX)]{assert!(encode_read(ReadRequest{offset,count,..request()}).is_err());}
}
#[test]
fn ar110_dispatch_actual_file_exact_reply_and_read_only_ledger() {
    let(t,mut s,mut p,mut b)=fixture();let head=fs::read(t.0.join(HEAD)).unwrap();let usage=s.usage().unwrap();let frame=encode_read(request()).unwrap();
    let reply=dispatch_read(&mut s,7,&frame,true,&mut b,&mut p).unwrap();assert_eq!(&reply.bytes()[..8],b"ANKARD01");assert_eq!(reply.bytes().len(),4296);
    assert_eq!(accept_read_reply(&frame,reply.bytes(),true,7,&mut Server{valid:true}).unwrap(),&p.bytes[4096..8192]);
    assert_eq!(p.inspections,1);assert_eq!(fs::read(t.0.join(HEAD)).unwrap(),head);assert_eq!(s.usage().unwrap(),usage);
    assert_eq!(b.remaining().0,9993,"dispatch plus two 3-unit scans");
}
#[test]
fn ar110_reply_every_truncation_tail_echo_and_content_substitution() {
    let(_t,mut s,mut p,mut b)=fixture();let frame=encode_read(request()).unwrap();let reply=dispatch_read(&mut s,7,&frame,true,&mut b,&mut p).unwrap();let good=reply.bytes();
    for n in 0..good.len(){assert!(accept_read_reply(&frame,&good[..n],true,7,&mut Server{valid:true}).is_err());}
    let mut tail=good.to_vec();tail.push(0);assert!(accept_read_reply(&frame,&tail,true,7,&mut Server{valid:true}).is_err());
    assert!(accept_read_reply(&frame,good,false,7,&mut Server{valid:true}).is_err());
    for i in [0,8,16,24,32,56,64,72,80,96,104,112,120,128,136,144,152,160,168,176,184,192,200,4295] {
        let mut bad=good.to_vec();bad[i]^=1;assert!(accept_read_reply(&frame,&bad,true,7,&mut Server{valid:true}).is_err(),"byte {i}");
    }
    assert!(accept_read_reply(&frame,good,true,7,&mut Server{valid:false}).is_err());
}
#[test]
fn ar110_dispatch_default_read_authority_and_malformed_input_never_inspect() {
    struct Deny;impl Evidence for Deny {}impl TransferEvidence for Deny {}
    let(t,mut s,mut p,mut b)=fixture();let head=fs::read(t.0.join(HEAD)).unwrap();let frame=encode_read(request()).unwrap();
    assert!(dispatch_read(&mut s,7,&frame,true,&mut b,&mut Deny).is_err());
    assert!(dispatch_read(&mut s,7,&frame[..167],true,&mut b,&mut p).is_err());assert_eq!(p.checks,0);
    p.read=false;assert!(dispatch_read(&mut s,7,&frame,true,&mut b,&mut p).is_err());assert_eq!(p.inspections,0);assert_eq!(fs::read(t.0.join(HEAD)).unwrap(),head);
}
#[test]
fn ar110_dispatch_revocation_after_inspection_and_corruption_never_disclose() {
    let(t,mut s,mut p,mut b)=fixture();let frame=encode_read(request()).unwrap();p.deny_after=Some(1);
    assert!(dispatch_read(&mut s,7,&frame,true,&mut b,&mut p).is_err());assert_eq!(p.inspections,1);
    p.deny_after=None;let mut bad=p.bytes.clone();bad[500]^=1;fs::write(t.0.join(DATA),bad).unwrap();let inspections=p.inspections;
    assert!(dispatch_read(&mut s,7,&frame,true,&mut b,&mut p).is_err());assert_eq!(p.inspections,inspections);
}
#[test]
fn ar110_dispatch_scan_budget_and_foreign_manifest_leave_backend_unchanged() {
    let(t,mut s,mut p,_)=fixture();let head=fs::read(t.0.join(HEAD)).unwrap();let mut b=Budget::new(6,10000,32768).unwrap();let frame=encode_read(request()).unwrap();
    assert!(matches!(dispatch_read(&mut s,7,&frame,true,&mut b,&mut p),Err(Error::Capacity)));assert_eq!(p.inspections,0);assert_eq!(b.remaining().0,0);
    let mut b=Budget::new(100,10000,32768).unwrap();let mut r=request();r.manifest.generation+=1;
    assert!(dispatch_read(&mut s,7,&encode_read(r).unwrap(),true,&mut b,&mut p).is_err());assert_eq!(fs::read(t.0.join(HEAD)).unwrap(),head);
}
#[test]
fn ar110_read_rejects_staging_and_stale_saved_ticket() {
    let(_t,mut s,mut p,mut b)=fixture();let frame=encode_read(request()).unwrap();let ticket=s.state.ticket;
    assert!(authorize_read(&s,7,&request(),Some((caller(),ticket+1)),&mut p).is_err());
    s.state.phase=Phase::Sealed;assert!(dispatch_read(&mut s,7,&frame,true,&mut b,&mut p).is_err());assert_eq!(p.inspections,0);
}
