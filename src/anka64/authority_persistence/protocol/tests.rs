use super::*;
use super::super::State;
fn req()->Request {Request{anchor:10,installation:20,policy:3,caller:30,incarnation:4,sequence:1,expected:7,operation:Operation::Select,argument:99,attempt:0}}
fn env()->Envelope{Envelope{correlation:42,request:req()}}
fn ctx()->Context{Context{anchor:10,installation:20,policy:3,challenge:71,now:100,selected:true}}
fn grant()->Access{Access{anchor:10,installation:20,policy:3,caller:30,incarnation:4,operation:Operation::Select,first:90,until:110,authentic:Verdict::Valid,status:Verdict::Valid}}
fn budget()->DispatchBudget{DispatchBudget{slots:0,slot_limit:4,bytes:0,byte_limit:1536,work:512,now:100,deadline:200}}
fn outcome()->Outcome{Outcome{revision:8,value:99,boot:8}}
fn evidence()->ClientEvidence{ClientEvidence{server:Verdict::Valid,pending_current:true}}
fn patch(bytes:&mut [u8],offset:usize,value:u64){bytes[offset..offset+8].copy_from_slice(&value.to_le_bytes());}
#[derive(Default)]
struct Auth{calls:usize,deny_at:usize,context:Option<Context>,access:Option<Access>}
impl Verifier for Auth {
    type Peer=u64;
    fn verify(&mut self,peer:&u64,_r:Request)->Option<(Context,Access)>{
        self.calls+=1;
        if *peer!=17 || (self.deny_at!=0 && self.calls>=self.deny_at){None}
        else {Some((self.context.unwrap_or_else(ctx),self.access.unwrap_or_else(grant)))}
    }
}
struct Store{state:State,reads:usize,commits:usize,error:Option<Error>,commit_then_error:bool}
impl Store {fn new()->Self{Self{state:State{revision:7,value:55,boot:8,last:None},reads:0,commits:0,error:None,commit_then_error:false}}}
impl DurableRecord for Store {
    fn load(&mut self,a:u64,i:u64)->Result<State,Error>{assert_eq!((a,i),(10,20));self.reads+=1;Ok(self.state.clone())}
    fn commit(&mut self,a:u64,i:u64,before:&State,after:&State)->Result<(),Error>{
        assert_eq!((a,i),(10,20));assert_eq!(before,&self.state);
        if let Some(e)=self.error {if !self.commit_then_error{return Err(e)}}
        self.state=after.clone();self.commits+=1;
        self.error.map_or(Ok(()),Err)
    }
}
fn run(b:&mut Store,a:&mut Auth,e:Envelope,capacity:bool)->Reply{
    let bytes=dispatch(b,a,&17,&e.encode().unwrap(),true,budget(),capacity).unwrap();
    Reply::decode(&bytes,true,e).unwrap()
}
#[test]
fn n110_request_golden_bytes_and_roundtrip(){
    let bytes=env().encode().unwrap();assert_eq!(&bytes[..8],b"ANKAPQ1\0");
    let words=[1,0,42,10,20,3,30,4,1,7,1,99,0];
    for (i,w) in words.iter().enumerate(){assert_eq!(&bytes[8+i*8..16+i*8],&(*w as u64).to_le_bytes());}
    assert_eq!(Envelope::decode(&bytes,true),Ok(env()));
    let e=Envelope{correlation:u64::MAX,request:Request{policy:u64::MAX,argument:u64::MAX,..req()}};
    assert_eq!(Envelope::decode(&e.encode().unwrap(),true),Ok(e));
}
#[test]
fn n110_every_truncated_request_tail_and_missing_eof_reject(){
    let bytes=env().encode().unwrap();
    for n in 0..REQUEST_BYTES{assert_eq!(Envelope::decode(&bytes[..n],true),Err(WireError::Length));}
    let mut extra=bytes.to_vec();extra.push(0);assert_eq!(Envelope::decode(&extra,true),Err(WireError::Length));
    assert_eq!(Envelope::decode(&bytes,false),Err(WireError::Incomplete));
}
#[test]
fn n110_request_header_and_shape_reject(){
    for (off,value) in [(0,0),(8,2),(16,1),(24,0),(32,0),(40,0),(56,0),(64,0),(72,0),(88,0),(88,3),(96,0),(104,1)]{
        let mut bytes=env().encode().unwrap();patch(&mut bytes,off,value);
        assert!(Envelope::decode(&bytes,true).is_err(),"offset {off}");
    }
    let e=Envelope{request:Request{operation:Operation::ReserveBoot,attempt:0,..req()},..env()};
    assert!(e.encode().is_err());
}
#[test]
fn n110_reply_golden_and_each_truncation_tail_eof(){
    let bytes=Reply::success(env(),outcome()).unwrap().encode();assert_eq!(&bytes[..8],b"ANKAPR1\0");
    assert_eq!(&bytes[8..112],&env().encode().unwrap()[8..]);
    assert_eq!(&bytes[112..120],&0u64.to_le_bytes());assert_eq!(&bytes[120..128],&8u64.to_le_bytes());
    assert_eq!(&bytes[128..136],&99u64.to_le_bytes());assert_eq!(&bytes[136..144],&8u64.to_le_bytes());
    assert_eq!(Reply::decode(&bytes,true,env()).unwrap().outcome(),Some(outcome()));
    for n in 0..REPLY_BYTES{assert!(Reply::decode(&bytes[..n],true,env()).is_err());}
    let mut tail=bytes.to_vec();tail.push(0);assert!(Reply::decode(&tail,true,env()).is_err());
    assert_eq!(Reply::decode(&bytes,false,env()),Err(WireError::Incomplete));
}
#[test]
fn n110_reply_binds_correlation_and_all_ten_request_words(){
    for off in (24..112).step_by(8){
        let mut bytes=Reply::success(env(),outcome()).unwrap().encode();bytes[off]^=1;
        assert!(Reply::decode(&bytes,true,env()).is_err(),"offset {off}");
    }
}
#[test]
fn n110_reply_headers_status_and_impossible_success_reject(){
    for (off,value) in [(0,0),(8,2),(16,1),(112,7),(120,9),(128,100)]{
        let mut bytes=Reply::success(env(),outcome()).unwrap().encode();patch(&mut bytes,off,value);
        assert!(Reply::decode(&bytes,true,env()).is_err(),"offset {off}");
    }
    let e=Envelope{request:Request{expected:u64::MAX,..req()},..env()};
    assert_eq!(Reply::success(e,Outcome{revision:0,..outcome()}),Err(WireError::Outcome));
    let e=Envelope{request:Request{operation:Operation::ReserveBoot,attempt:71,..req()},..env()};
    assert_eq!(Reply::success(e,Outcome{boot:0,..outcome()}),Err(WireError::Outcome));
}
#[test]
fn n110_every_error_status_zeroes_all_outcome_words(){
    for status in [Status::Denied,Status::Conflict,Status::Exhausted,Status::Unavailable,Status::Uncertain,Status::Invalid]{
        let bytes=Reply::failure(env(),status).unwrap().encode();assert_eq!(&bytes[120..],&[0;24]);
        assert_eq!(Reply::decode(&bytes,true,env()).unwrap().status(),status);
        for off in [120,128,136]{let mut bad=bytes;patch(&mut bad,off,1);assert_eq!(Reply::decode(&bad,true,env()),Err(WireError::Outcome));}
    }
    assert!(Reply::failure(env(),Status::Success).is_err());
}
#[test]
fn n110_malformed_dispatch_never_verifies_or_reads_backend(){
    let mut b=Store::new();let mut a=Auth::default();let bytes=env().encode().unwrap();
    for n in 0..REQUEST_BYTES{assert!(dispatch(&mut b,&mut a,&17,&bytes[..n],true,budget(),true).is_err());}
    assert!(dispatch(&mut b,&mut a,&17,&bytes,false,budget(),true).is_err());
    assert_eq!((a.calls,b.reads,b.commits),(0,0,0));
}
#[test]
fn n110_default_and_foreign_peer_deny_before_storage(){
    let mut b=Store::new();let bytes=env().encode().unwrap();
    let reply=dispatch(&mut b,&mut DenyAll,&(),&bytes,true,budget(),true).unwrap();
    assert_eq!(Reply::decode(&reply,true,env()).unwrap().status(),Status::Denied);
    let mut a=Auth::default();let reply=dispatch(&mut b,&mut a,&18,&bytes,true,budget(),true).unwrap();
    assert_eq!(Reply::decode(&reply,true,env()).unwrap().status(),Status::Denied);assert_eq!(b.reads,0);
}
#[test]
fn n110_claimed_identity_and_grant_bindings_cannot_authorize(){
    let r=req();let variants=[Request{anchor:11,..r},Request{installation:21,..r},Request{policy:4,..r},Request{caller:31,..r},Request{incarnation:5,..r},Request{operation:Operation::ReserveBoot,attempt:71,..r}];
    for request in variants{let mut b=Store::new();let mut a=Auth::default();assert_eq!(run(&mut b,&mut a,Envelope{request,..env()},true).status(),Status::Denied);assert_eq!(b.reads,0);}
    for access in [Access{authentic:Verdict::Unknown,..grant()},Access{status:Verdict::Invalid,..grant()},Access{until:100,..grant()},Access{first:101,..grant()}]{
        let mut b=Store::new();let mut a=Auth{access:Some(access),..Auth::default()};assert_eq!(run(&mut b,&mut a,env(),true).status(),Status::Denied);assert_eq!(b.reads,0);
    }
}
#[test]
fn n110_budget_limits_and_overflow_reject_before_verifier(){
    let good=budget();let variants=[DispatchBudget{slots:4,..good},DispatchBudget{slot_limit:0,..good},DispatchBudget{slot_limit:65,..good},DispatchBudget{bytes:1537,..good},DispatchBudget{bytes:u64::MAX,..good},DispatchBudget{byte_limit:383,..good},DispatchBudget{work:0,..good},DispatchBudget{work:513,..good},DispatchBudget{now:200,..good},DispatchBudget{deadline:0,..good}];
    let mut b=Store::new();let mut a=Auth::default();
    for budget in variants{let reply=dispatch(&mut b,&mut a,&17,&env().encode().unwrap(),true,budget,true).unwrap();assert_eq!(Reply::decode(&reply,true,env()).unwrap().status(),Status::Exhausted);}
    assert_eq!((a.calls,b.reads,b.commits),(0,0,0));
    assert!(DispatchBudget{slots:3,bytes:1152,work:1,now:199,..good}.admissible());
    assert!(DispatchBudget{bytes:u64::MAX-384,byte_limit:u64::MAX,..good}.admissible());
}
#[test]
fn n110_success_and_reconnected_exact_retry_have_one_effect(){
    let mut b=Store::new();let mut a=Auth::default();let first=run(&mut b,&mut a,env(),true);assert_eq!(first.outcome(),Some(outcome()));
    let retry=Envelope{correlation:43,..env()};assert_eq!(run(&mut b,&mut a,retry,false).outcome(),first.outcome());
    assert_eq!((b.commits,a.calls),(1,4));
}
#[test]
fn n110_revocation_before_reply_hides_outcome_without_rollback(){
    let mut b=Store::new();let mut a=Auth{deny_at:2,..Auth::default()};
    let reply=run(&mut b,&mut a,env(),true);assert_eq!(reply.status(),Status::Denied);assert_eq!(&reply.encode()[120..],&[0;24]);
    assert_eq!(b.commits,1);assert_eq!(b.state.value,99);
    assert_eq!(run(&mut b,&mut a,env(),false).status(),Status::Denied);assert_eq!(b.reads,1);
}
#[test]
fn n110_capacity_denial_and_backend_error_statuses_are_exact(){
    let mut b=Store::new();let mut a=Auth::default();assert_eq!(run(&mut b,&mut a,env(),false).status(),Status::Exhausted);assert_eq!(b.commits,0);
    for (error,want) in [(Error::Conflict,Status::Conflict),(Error::Exhausted,Status::Exhausted),(Error::BackendBusy,Status::Unavailable),(Error::CorruptRecord,Status::Unavailable),(Error::BackendUnavailable,Status::Unavailable),(Error::InvalidRequest,Status::Invalid),(Error::CommitUncertain,Status::Uncertain)]{
        let mut b=Store::new();b.error=Some(error);let r=run(&mut b,&mut Auth::default(),env(),true);assert_eq!(r.status(),want);assert_eq!(r.outcome(),None);
    }
}
#[test]
fn n110_uncertain_commit_recovery_does_not_duplicate_effect(){
    let mut b=Store::new();b.error=Some(Error::CommitUncertain);b.commit_then_error=true;
    let mut a=Auth::default();let reply=run(&mut b,&mut a,env(),true);assert_eq!(reply.status(),Status::Uncertain);assert_eq!(b.commits,1);
    assert_eq!(accept_reply(&reply.encode(),true,env(),evidence()),ClientResult::Unknown);
    // Models reopen/settle: retained state survives, volatile error is cleared.
    let mut recovered=Store{state:b.state,reads:0,commits:1,error:None,commit_then_error:false};
    assert_eq!(run(&mut recovered,&mut a,env(),false).outcome(),Some(outcome()));assert_eq!(recovered.commits,1);
}
#[test]
fn n110_boot_reservation_retry_returns_same_counter(){
    let e=Envelope{request:Request{operation:Operation::ReserveBoot,argument:55,attempt:71,..req()},..env()};
    let mut b=Store::new();let mut a=Auth{access:Some(Access{operation:Operation::ReserveBoot,..grant()}),..Auth::default()};
    let first=run(&mut b,&mut a,e,true);assert_eq!(first.outcome(),Some(Outcome{revision:8,value:55,boot:9}));
    assert_eq!(run(&mut b,&mut a,e,false).outcome(),first.outcome());assert_eq!(b.commits,1);
}
#[test]
fn n110_old_retry_after_peer_commit_preserves_new_record(){
    let mut b=Store::new();run(&mut b,&mut Auth::default(),env(),true);
    let e=Envelope{request:Request{caller:31,incarnation:5,sequence:2,expected:8,argument:101,..req()},..env()};
    let mut a=Auth{access:Some(Access{caller:31,incarnation:5,..grant()}),..Auth::default()};
    assert_eq!(run(&mut b,&mut a,e,true).status(),Status::Success);
    let old=b.state.clone();assert_eq!(run(&mut b,&mut Auth::default(),env(),true).status(),Status::Conflict);assert_eq!(b.state,old);assert_eq!(b.commits,2);
}
#[test]
fn n110_client_requires_current_bound_complete_canonical_reply(){
    let bytes=Reply::success(env(),outcome()).unwrap().encode();
    assert_eq!(accept_reply(&bytes,true,env(),evidence()),ClientResult::Success(outcome()));
    for e in [ClientEvidence{server:Verdict::Unknown,pending_current:true},ClientEvidence{server:Verdict::Invalid,pending_current:true},ClientEvidence{server:Verdict::Valid,pending_current:false}]{assert_eq!(accept_reply(&bytes,true,env(),e),ClientResult::Unknown);}
    assert_eq!(accept_reply(&bytes,false,env(),evidence()),ClientResult::Unknown);
    assert_eq!(accept_reply(&[],true,env(),evidence()),ClientResult::Unknown);
    assert_eq!(accept_reply(&bytes,true,Envelope{correlation:43,..env()},evidence()),ClientResult::Unknown);
    let mut bad=bytes;patch(&mut bad,112,8);assert_eq!(accept_reply(&bad,true,env(),evidence()),ClientResult::Unknown);
    let deny=Reply::failure(env(),Status::Denied).unwrap().encode();assert_eq!(accept_reply(&deny,true,env(),evidence()),ClientResult::Rejected(Status::Denied));
}
#[test]
#[cfg(any(target_os="linux",target_os="macos"))]
fn n110_file_backend_reopen_recovers_dispatch_outcome(){
    use super::super::file_backend::FileRecord;
    let stamp=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path=std::env::temp_dir().join(format!("anka110-protocol-{}-{stamp}",std::process::id()));
    let mut b=FileRecord::create(&path,10,20,&Store::new().state).unwrap();let mut a=Auth::default();
    let bytes=env().encode().unwrap();let first=dispatch(&mut b,&mut a,&17,&bytes,true,budget(),true).unwrap();drop(b);
    let mut reopened=FileRecord::open(&path,10,20).unwrap();let retry=dispatch(&mut reopened,&mut a,&17,&bytes,true,budget(),false).unwrap();
    assert_eq!(first,retry);assert_eq!(accept_reply(&retry,true,env(),evidence()),ClientResult::Success(outcome()));
    drop(reopened);std::fs::remove_dir_all(path).unwrap();
}
