use super::*;

#[derive(Clone,Copy)]
enum Fault { None, BeforeCommit, AfterCommit }
struct Store { state:State, fault:Fault, reads:u64, commits:u64 }
impl Store {
    fn new()->Self {Self {state:State{revision:7,value:55,boot:8,last:None},fault:Fault::None,reads:0,commits:0}}
}
impl DurableRecord for Store {
    fn load(&mut self,anchor:u64,installation:u64)->Result<State,Error> {
        if (anchor,installation)!=(10,20) {return Err(Error::Authority)}
        self.reads+=1;Ok(self.state.clone())
    }
    fn commit(&mut self,anchor:u64,installation:u64,before:&State,after:&State)->Result<(),Error> {
        if (anchor,installation)!=(10,20) {return Err(Error::Authority)}
        if &self.state!=before {return Err(Error::Conflict)}
        if matches!(self.fault,Fault::BeforeCommit) {return Err(Error::BackendUnavailable)}
        self.state=after.clone();self.commits+=1;
        if matches!(self.fault,Fault::AfterCommit) {Err(Error::CommitUncertain)} else {Ok(())}
    }
}
fn context()->Context {Context{anchor:10,installation:20,policy:3,challenge:71,now:100,selected:true}}
fn access()->Access {Access{anchor:10,installation:20,policy:3,caller:30,incarnation:4,operation:Operation::Select,first:90,until:110,authentic:Verdict::Valid,status:Verdict::Valid}}
fn request()->Request {Request{anchor:10,installation:20,policy:3,caller:30,incarnation:4,sequence:1,expected:7,operation:Operation::Select,argument:99,attempt:0}}
fn boot_request()->Request {Request{operation:Operation::ReserveBoot,argument:55,attempt:71,..request()}}
fn boot_access()->Access {Access{operation:Operation::ReserveBoot,..access()}}
fn enrollment()->Enrollment {Enrollment{anchor:10,installation:20,person:30,revision:1,enrolled:true}}
fn evidence()->BootEvidence {BootEvidence{head:8,boot:9,freshness:Verdict::Valid,artifact:Verdict::Valid}}

#[test]
fn t2_commit_and_exact_retry_preserve_one_effect() {
    let mut b=Store::new();let r=request();
    let first=transact(&mut b,context(),r,access(),true).unwrap();
    assert_eq!(first,Outcome{revision:8,value:99,boot:8});
    assert_eq!(transact(&mut b,context(),r,access(),false),Ok(first));
    assert_eq!(b.commits,1);assert_eq!(b.state.last,Some(r));
}
#[test]
fn t2_crash_before_commit_keeps_all_fields() {
    let mut b=Store::new();let old=b.state.clone();b.fault=Fault::BeforeCommit;
    assert_eq!(transact(&mut b,context(),request(),access(),true),Err(Error::BackendUnavailable));
    assert_eq!(b.state,old);b.fault=Fault::None;
    assert!(transact(&mut b,context(),request(),access(),true).is_ok());assert_eq!(b.commits,1);
}
#[test]
fn t2_lost_ack_and_recreated_coordinator_recover_same_boot() {
    let mut b=Store::new();b.fault=Fault::AfterCommit;
    assert_eq!(transact(&mut b,context(),boot_request(),boot_access(),true),Err(Error::CommitUncertain));
    // No coordinator memory is retained. Only backend durable image survives.
    let mut recovered=Store{state:b.state.clone(),fault:Fault::None,reads:0,commits:b.commits};
    let o=transact(&mut recovered,context(),boot_request(),boot_access(),false).unwrap();
    assert_eq!(o.boot,9);assert_eq!(recovered.commits,1);
}
#[test]
fn t2_retry_binds_every_request_field() {
    let mut b=Store::new();transact(&mut b,context(),request(),access(),true).unwrap();
    let old=b.state.clone();let r=request();
    let variants=[Request{anchor:11,..r},Request{installation:21,..r},Request{policy:4,..r},
        Request{caller:31,..r},Request{incarnation:5,..r},Request{sequence:2,..r},
        Request{expected:8,..r},Request{argument:100,..r},Request{attempt:71,..r},
        Request{operation:Operation::ReserveBoot,..r}];
    for r in variants {assert!(transact(&mut b,context(),r,access(),true).is_err());assert_eq!(b.state,old);}
}
#[test]
fn t2_competing_client_cannot_overwrite_commit() {
    let mut b=Store::new();transact(&mut b,context(),request(),access(),true).unwrap();
    let old=b.state.clone();
    let r=Request{caller:31,..request()};let a=Access{caller:31,..access()};
    assert_eq!(transact(&mut b,context(),r,a,true),Err(Error::Conflict));assert_eq!(b.state,old);
    // B can reread and make a new explicit request. A's old sequence is fenced.
    let r=Request{sequence:2,expected:8,argument:100,..r};
    assert!(transact(&mut b,context(),r,a,true).is_ok());
    assert_eq!(transact(&mut b,context(),request(),access(),true),Err(Error::ExpiredRequest));
    assert_eq!(b.state.value,100);assert_eq!(b.commits,2);
}
#[test]
fn t2_authority_denials_do_not_touch_backend() {
    let mut b=Store::new();
    for v in [Verdict::Unknown,Verdict::Invalid] {
        assert_eq!(transact(&mut b,context(),request(),Access{authentic:v,..access()},true),Err(Error::Authority));
        assert_eq!(transact(&mut b,context(),request(),Access{status:v,..access()},true),Err(Error::Authority));
    }
    for c in [Context{now:110,..context()},Context{selected:false,..context()},Context{policy:4,..context()}] {
        assert_eq!(transact(&mut b,c,request(),access(),true),Err(Error::Authority));
    }
    assert_eq!(b.reads,0);assert_eq!(b.commits,0);
}
#[test]
fn t2_revocation_also_blocks_outcome_retrieval() {
    let mut b=Store::new();transact(&mut b,context(),request(),access(),true).unwrap();
    let old=b.state.clone();
    assert_eq!(transact(&mut b,context(),request(),Access{status:Verdict::Invalid,..access()},false),Err(Error::Authority));
    assert_eq!(b.state,old);
}
#[test]
fn t2_capacity_and_geometry_fail_without_mutation() {
    let mut b=Store::new();let old=b.state.clone();
    assert_eq!(transact(&mut b,context(),request(),access(),false),Err(Error::Capacity));
    for r in [Request{argument:0,..request()},Request{attempt:71,..request()},Request{sequence:3,..request()},Request{expected:6,..request()}] {
        assert!(transact(&mut b,context(),r,access(),true).is_err());assert_eq!(b.state,old);
    }
}
#[test]
fn t2_counters_never_wrap() {
    let mut b=Store::new();b.state.revision=u64::MAX;
    assert_eq!(transact(&mut b,context(),Request{expected:u64::MAX,..request()},access(),true),Err(Error::Exhausted));
    let mut b=Store::new();b.state.boot=u64::MAX;
    assert_eq!(transact(&mut b,context(),boot_request(),boot_access(),true),Err(Error::Exhausted));
    let mut b=Store::new();b.state.last=Some(Request{sequence:u64::MAX,..request()});
    assert!(transact(&mut b,context(),request(),access(),true).is_err());
    assert_eq!(b.state.sequence(),u64::MAX);
}
#[test]
fn t2_boot_is_separate_from_reservation_and_single_admission() {
    let mut b=Store::new();transact(&mut b,context(),boot_request(),boot_access(),true).unwrap();
    let mut latch=BootLatch::default();assert!(!latch.accepts_saved_context(9));
    assert_eq!(latch.admit(context(),&b.state,boot_request(),boot_access(),enrollment(),evidence()),Ok(9));
    assert_eq!(latch.admit(context(),&b.state,boot_request(),boot_access(),enrollment(),evidence()),Err(Error::BootDenied));
    assert!(latch.accepts_saved_context(9));assert!(!latch.accepts_saved_context(8));
}
#[test]
fn t2_restart_requires_new_challenge_and_new_reservation() {
    let mut b=Store::new();transact(&mut b,context(),boot_request(),boot_access(),true).unwrap();
    let c=Context{challenge:72,..context()};let mut latch=BootLatch::default();
    assert_eq!(latch.admit(c,&b.state,boot_request(),boot_access(),enrollment(),evidence()),Err(Error::BootDenied));
    let r=Request{sequence:2,expected:8,attempt:72,..boot_request()};
    transact(&mut b,c,r,boot_access(),true).unwrap();
    assert_eq!(latch.admit(c,&b.state,r,boot_access(),enrollment(),BootEvidence{head:9,boot:10,..evidence()}),Ok(10));
    assert!(!latch.accepts_saved_context(9));
}
#[test]
fn t2_boot_rejects_unfresh_or_wrong_artifact_and_enrollment() {
    let mut b=Store::new();transact(&mut b,context(),boot_request(),boot_access(),true).unwrap();
    for e in [BootEvidence{freshness:Verdict::Unknown,..evidence()},BootEvidence{artifact:Verdict::Invalid,..evidence()},
        BootEvidence{head:9,..evidence()},BootEvidence{boot:10,..evidence()}] {
        assert_eq!(BootLatch::default().admit(context(),&b.state,boot_request(),boot_access(),enrollment(),e),Err(Error::BootDenied));
    }
    for e in [Enrollment{enrolled:false,..enrollment()},Enrollment{installation:21,..enrollment()}] {
        assert_eq!(BootLatch::default().admit(context(),&b.state,boot_request(),boot_access(),e,evidence()),Err(Error::BootDenied));
    }
}
#[test]
fn t2_backend_cas_rejects_stale_prepared_writer() {
    let mut b=Store::new();let before=b.state.clone();
    let Decision::Commit(after)=prepare(context(),&before,request(),access(),true).unwrap() else {panic!("expected new commit")};
    transact(&mut b,context(),request(),access(),true).unwrap();
    assert_eq!(b.commit(10,20,&before,&after),Err(Error::Conflict));assert_eq!(b.commits,1);
}
