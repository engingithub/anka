use super::*;
use std::sync::atomic::{AtomicU64,Ordering};
static SERIAL:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {fn new()->Self {Self(std::env::temp_dir().join(format!("anka-at110-{}-{}-{}",std::process::id(),
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),SERIAL.fetch_add(1,Ordering::Relaxed))))}}
impl Drop for Temp {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn limits()->Limits {Limits{max_payload:32768,window:4096,owner_bytes:65536,total_bytes:131072,other_bytes:20000,work:30}}
fn manifest()->Manifest {Manifest{anchor:10,installation:20,artifact:99,generation:2,role:2,profile:1,size:10000,image:101,metadata:102,dependencies:103,provenance:104}}
fn identity()->Caller {Caller{owner:30,incarnation:4}}
struct Proof {bytes:Vec<u8>,caller_calls:usize,deny_after:Option<usize>,valid:bool,server:bool,owner:Caller}
impl Proof {fn new()->Self {Self{bytes:(0..10000).map(|n|n as u8).collect(),caller_calls:0,deny_after:None,valid:true,server:true,owner:identity()}}}
impl Evidence for Proof {
    fn authorize(&mut self,s:Scope)->Verdict {if self.valid && s.manifest==manifest() && s.caller==identity(){Verdict::Valid}else{Verdict::Invalid}}
    fn inspect(&mut self,r:&mut dyn Read)->Result<Manifest,Error> {
        let mut bytes=Vec::new();r.read_to_end(&mut bytes).map_err(io_error)?;
        if bytes!=self.bytes {return Err(Error::CorruptRecord)}Ok(manifest())
    }
}
impl TransferEvidence for Proof {
    fn caller(&mut self,connection:u64,_:&Request<'_>)->Result<Caller,Error> {
        self.caller_calls+=1;
        if !matches!(connection,7|8) || !self.valid || self.deny_after.is_some_and(|n|self.caller_calls>n) {return Err(Error::Authority)}Ok(self.owner)
    }
}
impl ServerEvidence for Proof {fn current(&mut self,connection:u64,_:&Request<'_>,_:&[u8])->Verdict {
    if matches!(connection,7|8) && self.server {Verdict::Valid}else{Verdict::Invalid}
}}
fn fixture()->(Temp,ArtifactStore,Proof,Budget) {
    let t=Temp::new();let s=ArtifactStore::create(&t.0,10,20,9,limits(),Selection{revision:7,artifact:55,generation:1}).unwrap();
    (t,s,Proof::new(),Budget::new(100,100000,8600).unwrap())
}
fn req(op:Operation,ticket:u64)->Request<'static> {Request{operation:op,correlation:77,ticket,offset:0,publish_request:if matches!(op,Operation::Publish|Operation::Outcome){91}else{0},expected:if matches!(op,Operation::Publish|Operation::Outcome){7}else{0},manifest:manifest(),payload:&[]}}
fn wire(r:Request<'_>)->Vec<u8> {let mut out=[0;MAX_REQUEST];let n=encode(&r,&mut out).unwrap();out[..n].to_vec()}
fn exchange(s:&mut ArtifactStore,e:&mut Proof,b:&mut Budget,r:Request<'_>)->Outcome {
    let frame=wire(r);let reply=dispatch(s,7,&frame,true,b,e).unwrap();accept_reply(&frame,reply.bytes(),true,7,e).unwrap()
}
fn fill(s:&mut ArtifactStore,e:&mut Proof,b:&mut Budget,ticket:u64,start:usize) {
    let payload=e.bytes.clone();let mut at=start;
    while at<payload.len() {let end=(at+4096).min(payload.len());let mut r=req(Operation::Append,ticket);r.offset=at as u64;r.payload=&payload[at..end];
        assert_eq!(exchange(s,e,b,r).cursor,end as u64);at=end;}
}
fn sealed()->(Temp,ArtifactStore,Proof,Budget,u64) {
    let(t,mut s,mut e,mut b)=fixture();let ticket=exchange(&mut s,&mut e,&mut b,req(Operation::Begin,0)).ticket;
    fill(&mut s,&mut e,&mut b,ticket,0);assert_eq!(exchange(&mut s,&mut e,&mut b,req(Operation::Seal,ticket)).phase,2);(t,s,e,b,ticket)
}
#[test]
fn at110_request_golden_header_and_exact_roundtrip() {
    let bytes=wire(req(Operation::Begin,0));assert_eq!(bytes.len(),168);assert_eq!(&bytes[..8],b"ANKAUP01");
    assert_eq!(u64::from_le_bytes(bytes[24..32].try_into().unwrap()),77);
    assert_eq!(decode(&bytes,true).unwrap(),req(Operation::Begin,0));
    let payload=[0,255,17,0];let mut r=req(Operation::Append,3);r.offset=8;r.payload=&payload;
    let bytes=wire(r);assert_eq!(&bytes[HEADER..],&payload);assert_eq!(decode(&bytes,true).unwrap(),r);
}
#[test]
fn at110_request_truncation_tail_eof_and_header_damage_reject() {
    let payload=[42;64];let mut r=req(Operation::Append,3);r.payload=&payload;let bytes=wire(r);
    for n in 0..bytes.len(){assert!(decode(&bytes[..n],true).is_err());}
    let mut tail=bytes.clone();tail.push(0);assert!(decode(&tail,true).is_err());assert!(decode(&bytes,false).is_err());
    for (at,value) in [(0,0),(8,2),(16,7),(24,0),(48,255),(160,1)] {
        let mut bad=bytes.clone();bad[at]=value;assert!(decode(&bad,true).is_err(),"offset {at}");
    }
}
#[test]
fn at110_operation_shapes_reject_smuggled_fields_and_bounds() {
    let mut out=[0;MAX_REQUEST];
    for op in [Operation::Begin,Operation::Seal,Operation::Progress,Operation::Publish,Operation::Outcome] {
        let mut r=req(op,if matches!(op,Operation::Begin|Operation::Outcome){0}else{3});r.offset=1;assert!(encode(&r,&mut out).is_err());
    }
    let payload=[1;2];let mut r=req(Operation::Append,3);r.payload=&payload;r.offset=9999;assert!(encode(&r,&mut out).is_err());
    r.offset=u64::MAX;assert!(encode(&r,&mut out).is_err());r.offset=0;r.ticket=0;assert!(encode(&r,&mut out).is_err());
    let mut r=req(Operation::Begin,0);r.manifest.role=1;assert!(encode(&r,&mut out).is_err());
    r.manifest=manifest();r.manifest.profile=3;assert!(encode(&r,&mut out).is_err());
}
#[test]
fn at110_real_file_upload_seal_publish_and_exact_reply() {
    let(t,mut s,mut e,mut b,ticket)=sealed();let out=exchange(&mut s,&mut e,&mut b,req(Operation::Publish,ticket));
    assert_eq!((out.phase,out.revision,out.artifact,out.generation),(3,8,99,2));
    assert_eq!(fs::read(t.0.join("artifact.bytes")).unwrap(),e.bytes);assert_eq!(s.usage().unwrap().other,20000);
    assert_eq!(exchange(&mut s,&mut e,&mut b,req(Operation::Outcome,0)),out);
}
#[test]
fn at110_partial_upload_reopen_resume_preserves_prefix_and_work() {
    let(t,mut s,mut e,mut b)=fixture();let ticket=exchange(&mut s,&mut e,&mut b,req(Operation::Begin,0)).ticket;
    let payload=e.bytes[..4096].to_vec();let mut r=req(Operation::Append,ticket);r.payload=&payload;exchange(&mut s,&mut e,&mut b,r);
    let remaining=s.state.remaining;drop(s);let mut s=ArtifactStore::open(&t.0,10,20,10,limits()).unwrap();
    let out=exchange(&mut s,&mut e,&mut b,req(Operation::Begin,0));assert_eq!((out.ticket,out.cursor),(ticket,4096));assert_eq!(s.state.remaining,remaining);
    fill(&mut s,&mut e,&mut b,ticket,4096);exchange(&mut s,&mut e,&mut b,req(Operation::Seal,ticket));
    assert_eq!(exchange(&mut s,&mut e,&mut b,req(Operation::Publish,ticket)).revision,8);
}
#[test]
fn at110_lost_commit_reply_recovers_one_effect_after_reopen() {
    let(t,mut s,mut e,mut b,ticket)=sealed();e.caller_calls=0;e.deny_after=Some(1);
    let frame=wire(req(Operation::Publish,ticket));assert!(dispatch(&mut s,7,&frame,true,&mut b,&mut e).is_err());
    let charge=s.usage().unwrap();assert_eq!(s.state.selected.revision,8);drop(s);
    let mut s=ArtifactStore::open(&t.0,10,20,10,limits()).unwrap();e.deny_after=None;
    let frame=wire(req(Operation::Outcome,0));let reply=dispatch(&mut s,8,&frame,true,&mut b,&mut e).unwrap();
    assert_eq!(accept_reply(&frame,reply.bytes(),true,8,&mut e).unwrap().revision,8);assert_eq!(s.usage().unwrap(),charge);
    let mut changed=req(Operation::Outcome,0);changed.publish_request+=1;assert!(dispatch(&mut s,8,&wire(changed),true,&mut b,&mut e).is_err());
}
#[test]
fn at110_default_foreign_channel_and_changed_caller_deny_without_backend_effect() {
    struct Deny;impl Evidence for Deny {}impl TransferEvidence for Deny {}
    let(t,mut s,mut e,mut b)=fixture();let head=fs::read(t.0.join("artifact.record")).unwrap();let frame=wire(req(Operation::Begin,0));
    assert!(dispatch(&mut s,7,&frame,true,&mut b,&mut Deny).is_err());
    assert!(dispatch(&mut s,99,&frame,true,&mut b,&mut e).is_err());
    e.owner.incarnation+=1;assert!(dispatch(&mut s,7,&frame,true,&mut b,&mut e).is_err());
    assert_eq!(fs::read(t.0.join("artifact.record")).unwrap(),head);assert!(!t.0.join("artifact.bytes").exists());
}
#[test]
fn at110_manifest_substitution_and_stale_ticket_preserve_stage() {
    let(t,mut s,mut e,mut b)=fixture();let ticket=exchange(&mut s,&mut e,&mut b,req(Operation::Begin,0)).ticket;
    let before=fs::read(t.0.join("artifact.record")).unwrap();
    let mut r=req(Operation::Progress,ticket);r.manifest.provenance+=1;assert!(dispatch(&mut s,7,&wire(r),true,&mut b,&mut e).is_err());
    assert!(dispatch(&mut s,7,&wire(req(Operation::Progress,ticket+1)),true,&mut b,&mut e).is_err());
    assert_eq!(fs::read(t.0.join("artifact.record")).unwrap(),before);
}
#[test]
fn at110_malformed_attempts_spend_finite_work_without_verifying_or_storage() {
    let(t,mut s,mut e,_)=fixture();let mut b=Budget::new(2,1000,8600).unwrap();let before=fs::read(t.0.join("artifact.record")).unwrap();
    for _ in 0..3 {assert!(dispatch(&mut s,7,&[0;8],true,&mut b,&mut e).is_err());}
    assert_eq!(b.remaining(),(0,984));assert_eq!(e.caller_calls,0);assert_eq!(fs::read(t.0.join("artifact.record")).unwrap(),before);
    assert!(Budget::new(1,1000,8599).is_err());
    let mut b=Budget::new(2,10000,8600).unwrap();assert!(dispatch(&mut s,7,&[0;MAX_REQUEST+1],true,&mut b,&mut e).is_err());assert_eq!(b.remaining().0,0);
}
#[test]
fn at110_server_revocation_bad_reply_tail_and_payload_substitution_reject() {
    let(_t,mut s,mut e,mut b)=fixture();let ticket=exchange(&mut s,&mut e,&mut b,req(Operation::Begin,0)).ticket;
    let payload=e.bytes[..64].to_vec();let mut r=req(Operation::Append,ticket);r.payload=&payload;let frame=wire(r);
    let reply=dispatch(&mut s,7,&frame,true,&mut b,&mut e).unwrap();let bytes=reply.bytes();
    for n in 0..bytes.len() {assert!(accept_reply(&frame,&bytes[..n],true,7,&mut e).is_err());}
    assert!(accept_reply(&frame,bytes,false,7,&mut e).is_err());e.server=false;assert!(accept_reply(&frame,bytes,true,7,&mut e).is_err());e.server=true;
    let mut changed=frame.clone();changed[HEADER]^=1;assert!(accept_reply(&changed,bytes,true,7,&mut e).is_err());
    let mut bad=bytes.to_vec();bad.push(0);assert!(accept_reply(&frame,&bad,true,7,&mut e).is_err());
    let mut bad=bytes.to_vec();bad[40]=3;assert!(accept_reply(&frame,&bad,true,7,&mut e).is_err());
}
#[test]
fn at110_actual_payload_inspection_denies_corrupt_uploaded_bytes() {
    let(_t,mut s,mut e,mut b)=fixture();let ticket=exchange(&mut s,&mut e,&mut b,req(Operation::Begin,0)).ticket;
    let expected=e.bytes.clone();e.bytes[9999]^=1;fill(&mut s,&mut e,&mut b,ticket,0);e.bytes=expected;
    assert!(dispatch(&mut s,7,&wire(req(Operation::Seal,ticket)),true,&mut b,&mut e).is_err());
    assert_eq!(s.state.phase,Phase::Staging);assert_eq!(s.state.selected.revision,7);assert!(s.usage().unwrap().candidate>0);
}
#[test]
fn at110_exact_chunk_retry_does_not_refill_backend_or_dispatch_budget() {
    let(_t,mut s,mut e,mut b)=fixture();let ticket=exchange(&mut s,&mut e,&mut b,req(Operation::Begin,0)).ticket;
    let payload=e.bytes[..64].to_vec();let mut r=req(Operation::Append,ticket);r.payload=&payload;
    let first=exchange(&mut s,&mut e,&mut b,r);let backend=s.state.remaining;let dispatch_work=b.remaining().0;
    assert_eq!(exchange(&mut s,&mut e,&mut b,r),first);assert_eq!(s.state.remaining,backend-1);assert_eq!(b.remaining().0,dispatch_work-1);
    assert_eq!(exchange(&mut s,&mut e,&mut b,req(Operation::Progress,ticket)),first);
}
