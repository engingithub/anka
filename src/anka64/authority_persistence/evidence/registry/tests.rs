use super::*;
use super::super::super::{DurableRecord,Error,State as Record,Outcome};
use super::super::super::protocol::{self,guarded::{self,ReplySink,DeliveryError,DispatchError},DispatchBudget,Reply,Status};
use std::sync::{Arc,Mutex};
use std::io::{self,Write};
fn request()->Request {Request {anchor:10,installation:20,policy:3,caller:30,incarnation:4,sequence:1,expected:7,operation:Operation::Select,argument:99,attempt:0}}
fn envelope()->Envelope {Envelope {correlation:42,request:request()}}
fn context()->Context {Context {anchor:10,installation:20,policy:3,challenge:71,now:100,selected:true}}
fn config()->Config {Config {context:context(),runtime:5,serial:9,slots:2}}
fn snapshot()->Snapshot {
    let scope=Scope {runtime:5,connection:6,binding:7,local:40,peer:30,kind:Kind::Person,incarnation:4,
        role:Role::Caller,operation:Operation::Select,serial:9,challenge:71};
    Snapshot {context:context(),identity:Identity {issuer:10,subject:30,kind:Kind::Person,audience:20,policy:3,challenge:71,
        first:90,until:110,authentic:Verdict::Valid,possession:Verdict::Valid,status:Verdict::Valid},
        permit:Permit {issuer:10,subject:30,kind:Kind::Person,audience:20,policy:3,incarnation:4,role:Role::Caller,
            operation:Operation::Select,first:95,until:108,authentic:Verdict::Valid,status:Verdict::Valid},
        proof:BindingProof {scope,validated:Verdict::Valid},observed:Observation {scope,live:true,channel:Verdict::Valid}}
}
#[derive(Clone)]
struct Provider(Arc<Mutex<Snapshot>>);
impl Provider {
    fn new()->Self {Self(Arc::new(Mutex::new(snapshot())))}
    fn change(&self,f:impl FnOnce(&mut Snapshot)) {f(&mut self.0.lock().unwrap());}
}
impl CallerProvider for Provider {
    type Peer=u64;
    fn observe(&mut self,peer:&u64,_:Request)->Option<Snapshot> {if *peer==17 {Some(*self.0.lock().unwrap())} else {None}}
}
fn fixture()->(Provider,Registry<Provider>,Handle) {
    let p=Provider::new();let r=Registry::new(config(),p.clone()).unwrap();let h=r.register(17,request()).unwrap();(p,r,h)
}
fn budget()->UseBudget {UseBudget::new(16,105).unwrap()}
fn transport()->DispatchBudget {DispatchBudget {slots:0,slot_limit:4,bytes:0,byte_limit:1536,work:512,now:100,deadline:105}}
struct Store {record:Record,reads:usize,commits:usize,error:Option<Error>,during:Option<Box<dyn FnMut()>>}
impl Store {fn new()->Self {Self {record:Record {revision:7,value:55,boot:8,last:None},reads:0,commits:0,error:None,during:None}}}
impl DurableRecord for Store {
    fn load(&mut self,a:u64,i:u64)->Result<Record,Error> {assert_eq!((a,i),(10,20));self.reads+=1;if let Some(f)=&mut self.during {f();}Ok(self.record.clone())}
    fn commit(&mut self,a:u64,i:u64,b:&Record,n:&Record)->Result<(),Error> {
        assert_eq!((a,i),(10,20));assert_eq!(&self.record,b);
        if let Some(f)=&mut self.during {f();}
        if let Some(e)=self.error {return Err(e)}
        self.record=n.clone();self.commits+=1;Ok(())
    }
}
struct Sink {peer:Option<Handle>,bytes:Vec<u8>,limit:usize,error:Option<io::ErrorKind>,during:Option<Box<dyn FnMut()>>}
impl Sink {fn new(h:Handle)->Self {Self {peer:Some(h),bytes:Vec::new(),limit:144,error:None,during:None}}}
impl ReplySink for Sink {fn peer(&self)->Option<Handle> {self.peer}}
impl Write for Sink {
    fn write(&mut self,b:&[u8])->io::Result<usize> {
        if let Some(f)=&mut self.during {f();}
        if let Some(e)=self.error {return Err(io::Error::from(e))}
        let n=self.limit.min(b.len());self.bytes.extend_from_slice(&b[..n]);Ok(n)
    }
    fn flush(&mut self)->io::Result<()> {Ok(())}
}
fn run(s:&mut Store,r:&Registry<Provider>,h:Handle,b:&mut UseBudget)->guarded::PendingReply {
    guarded::dispatch(s,r,h,&envelope().encode().unwrap(),true,transport(),b,true).unwrap()
}
#[test]
fn e4_configuration_and_default_provider_deny() {
    for slots in [0,65] {assert!(Registry::new(Config {slots,..config()},DenyCallerProvider).is_err());}
    assert!(Registry::new(Config {runtime:0,..config()},DenyCallerProvider).is_err());
    assert!(Registry::new(Config {serial:0,..config()},DenyCallerProvider).is_err());
    let r=Registry::new(config(),DenyCallerProvider).unwrap();assert_eq!(r.register((),request()),Err(RegistryError::Denied));
    assert!(UseBudget::new(0,105).is_err());assert!(UseBudget::new(513,105).is_err());assert!(UseBudget::new(1,0).is_err());
}
#[test]
fn e4_fixed_capacity_does_not_evict_peer_and_reuse_changes_generation() {
    let (_,r,h)=fixture();let peer=r.register(17,request()).unwrap();assert_eq!(r.register(17,request()),Err(RegistryError::Capacity));
    r.retire(h).unwrap();let new=r.register(17,request()).unwrap();assert_eq!(new.index,h.index);assert_eq!(new.generation,h.generation+1);
    let mut b=budget();assert!(r.acquire(h,request(),&mut b).is_err());assert!(r.acquire(peer,request(),&mut b).is_ok());
}
#[test]
fn e4_foreign_registry_and_every_handle_substitution_deny() {
    let (_,r,h)=fixture();let (_,other,_)=fixture();let mut b=budget();assert!(other.acquire(h,request(),&mut b).is_err());
    for bad in [Handle {index:63,..h},Handle {generation:h.generation+1,..h},Handle {runtime:6,..h},
        Handle {serial:10,..h},Handle {connection:7,..h},Handle {binding:8,..h}] {
        assert!(r.acquire(bad,request(),&mut b).is_err());assert!(r.retire(bad).is_err());
    }
    assert!(r.acquire(h,request(),&mut b).is_ok());
}
#[test]
fn e4_acquire_is_not_effect_authority_and_guard_freezes_request() {
    let (_,r,h)=fixture();let mut b=budget();let bad=Request {caller:31,..request()};
    let mut guard=r.acquire(h,bad,&mut b).unwrap();assert_eq!(guard.request,bad);
    assert_eq!(guard.with_caller(|_,_| -> () {panic!("must not execute")}),Err(RegistryError::Denied));
    drop(guard);assert_eq!(b.remaining(),16);
}
#[test]
fn e4_authority_update_and_slot_changes_are_busy_while_held() {
    let (_,r,h)=fixture();let mut b=budget();let guard=r.acquire(h,request(),&mut b).unwrap();
    assert_eq!(r.update(context()),Err(RegistryError::Busy));assert_eq!(r.retire(h),Err(RegistryError::Busy));
    assert_eq!(r.register(17,request()),Err(RegistryError::Busy));assert_eq!(r.shutdown(),Err(RegistryError::Busy));
    drop(guard);assert_eq!(r.update(context()),Ok(10));
}
#[test]
fn e4_revocation_serial_invalidates_old_entries_until_republication() {
    let (p,r,h)=fixture();assert_eq!(r.update(context()),Ok(10));let mut b=budget();assert!(r.acquire(h,request(),&mut b).is_err());
    assert_eq!(r.register(17,request()),Err(RegistryError::Denied));
    r.retire(h).unwrap();p.change(|s|{s.observed.scope.serial=10;s.proof.scope=s.observed.scope;});
    let new=r.register(17,request()).unwrap();assert!(r.acquire(new,request(),&mut b).is_ok());assert!(r.acquire(h,request(),&mut b).is_err());
}
#[test]
fn e4_deadline_and_trusted_clock_are_rechecked_before_effect() {
    let (p,r,h)=fixture();let mut b=budget();let mut g=r.acquire(h,request(),&mut b).unwrap();
    p.change(|s|s.context.now=105);assert_eq!(g.with_caller(|_,_|()),Err(RegistryError::Denied));drop(g);
    p.change(|s|s.context.now=101);{let mut g=r.acquire(h,request(),&mut b).unwrap();assert!(g.with_caller(|_,_|()).is_ok());}
    p.change(|s|s.context.now=100);let mut g=r.acquire(h,request(),&mut b).unwrap();assert_eq!(g.with_caller(|_,_|()),Err(RegistryError::Denied));
}
#[test]
fn e4_current_provider_denial_never_invokes_backend() {
    let (p,r,h)=fixture();p.change(|s|s.permit.status=Verdict::Invalid);let mut s=Store::new();let mut b=budget();
    assert!(matches!(guarded::dispatch(&mut s,&r,h,&envelope().encode().unwrap(),true,transport(),&mut b,true),Err(DispatchError::Registry(RegistryError::Denied))));
    assert_eq!((s.reads,s.commits),(0,0));assert_eq!(b.remaining(),16);
}
#[test]
fn e4_scope_renewal_cannot_silently_extend_existing_entry() {
    let (p,r,h)=fixture();p.change(|s|{s.identity.until=200;s.permit.until=200;});let mut b=budget();
    let mut g=r.acquire(h,request(),&mut b).unwrap();assert_eq!(g.with_caller(|_,_|()),Err(RegistryError::Denied));drop(g);
    r.retire(h).unwrap();assert!(r.register(17,request()).is_ok());
}
#[test]
fn e4_work_is_not_refunded_by_error_release_or_reacquire() {
    let (_,r,h)=fixture();let mut b=UseBudget::new(1,105).unwrap();
    {let mut g=r.acquire(h,request(),&mut b).unwrap();assert_eq!(g.with_caller(|_,_|Err::<(),_>(Error::BackendUnavailable)),Ok(Err(Error::BackendUnavailable)));}
    assert_eq!(b.remaining(),0);assert!(r.acquire(h,request(),&mut b).is_err());
}
#[test]
fn e4_ticket_and_generation_exhaustion_never_wrap() {
    let (_,r,h)=fixture();{let mut s=r.state.lock().unwrap();s.counter=u64::MAX-1;}
    let mut b=budget();{let g=r.acquire(h,request(),&mut b).unwrap();assert_eq!(g.ticket,u64::MAX);}
    assert!(matches!(r.acquire(h,request(),&mut b),Err(RegistryError::Exhausted)));
    r.retire(h).unwrap();{let mut s=r.state.lock().unwrap();for slot in &mut s.slots {slot.generation=u64::MAX;}}
    assert_eq!(r.register(17,request()),Err(RegistryError::Capacity));
}
#[test]
fn e4_serial_exhaustion_preserves_existing_authority() {
    let (p,r,h)=fixture();{r.state.lock().unwrap().config.serial=u64::MAX;}
    assert_eq!(r.update(context()),Err(RegistryError::Exhausted));assert_eq!(r.state.lock().unwrap().config.serial,u64::MAX);
    r.retire(h).unwrap();p.change(|s|{s.observed.scope.serial=u64::MAX;s.proof.scope=s.observed.scope;});assert!(r.register(17,request()).is_ok());
}
#[test]
fn e4_restart_requires_fencing_drainage_and_fresh_runtime() {
    let (_,r,h)=fixture();let c=Context {challenge:72,..context()};let valid=RestartEvidence {fenced:Verdict::Valid,fresh:Verdict::Valid,drained:true};
    for e in [RestartEvidence {fenced:Verdict::Unknown,..valid},RestartEvidence {fresh:Verdict::Invalid,..valid},RestartEvidence {drained:false,..valid}] {
        assert_eq!(r.restart(c,6,e),Err(RegistryError::Denied));
    }
    assert_eq!(r.restart(c,5,valid),Err(RegistryError::Denied));assert_eq!(r.restart(context(),6,valid),Err(RegistryError::Denied));
    {let mut b=budget();let _g=r.acquire(h,request(),&mut b).unwrap();assert_eq!(r.restart(c,6,valid),Err(RegistryError::Busy));}
    let count=r.state.lock().unwrap().counter;assert_eq!(r.restart(c,6,valid),Ok(10));assert_eq!(r.state.lock().unwrap().counter,count);
    let mut b=budget();assert!(r.acquire(h,request(),&mut b).is_err());
}
#[test]
fn e4_shutdown_is_terminal_and_clears_entries() {
    let (_,r,h)=fixture();r.shutdown().unwrap();let mut b=budget();assert!(r.acquire(h,request(),&mut b).is_err());
    assert_eq!(r.register(17,request()),Err(RegistryError::Denied));assert_eq!(r.update(context()),Err(RegistryError::Denied));
    assert!(r.state.lock().unwrap().slots.iter().all(|s|s.entry.is_none()));
}
#[test]
fn e4_malformed_and_unfunded_dispatch_do_not_touch_backend() {
    let (_,r,h)=fixture();let mut s=Store::new();let mut b=budget();
    assert!(matches!(guarded::dispatch(&mut s,&r,h,&[],true,transport(),&mut b,true),Err(DispatchError::Wire(_))));
    let bad=DispatchBudget {work:0,..transport()};
    assert!(matches!(guarded::dispatch(&mut s,&r,h,&envelope().encode().unwrap(),true,bad,&mut b,true),Err(DispatchError::Budget)));
    assert_eq!((s.reads,s.commits,b.remaining()),(0,0,16));assert_eq!(r.state.lock().unwrap().counter,0);
}
#[test]
fn e4_guard_covers_backend_load_and_commit_and_errors_release_it() {
    let (_,r,h)=fixture();let r=Arc::new(r);let during=r.clone();let mut s=Store::new();
    s.during=Some(Box::new(move||{assert_eq!(during.update(context()),Err(RegistryError::Busy));}));
    s.error=Some(Error::BackendUnavailable);let mut b=budget();let mut reply=run(&mut s,&r,h,&mut b);
    assert_eq!(b.remaining(),15);let mut sink=Sink::new(h);reply.write_once(&r,&mut b,&mut sink).unwrap();
    assert_eq!(Reply::decode(&sink.bytes,true,envelope()).unwrap().status(),Status::Unavailable);
    assert_eq!(r.update(context()),Ok(10));
}
#[test]
fn e4_guarded_retry_and_partial_reply_commit_once() {
    let (_,r,h)=fixture();let mut s=Store::new();let mut b=budget();let _lost=run(&mut s,&r,h,&mut b);
    let mut reply=run(&mut s,&r,h,&mut b);let mut sink=Sink::new(h);sink.limit=47;
    for _ in 0..4 {reply.write_once(&r,&mut b,&mut sink).unwrap();}
    assert!(reply.complete());assert_eq!(s.commits,1);assert_eq!(b.remaining(),10);
    assert_eq!(Reply::decode(&sink.bytes,true,envelope()).unwrap().outcome(),Some(Outcome {revision:8,value:99,boot:8}));
}
#[test]
fn e4_revocation_after_commit_suppresses_reply_without_rollback() {
    let (_,r,h)=fixture();let mut s=Store::new();let mut b=budget();let mut reply=run(&mut s,&r,h,&mut b);
    r.update(context()).unwrap();let mut sink=Sink::new(h);
    assert!(matches!(reply.write_once(&r,&mut b,&mut sink),Err(DeliveryError::Registry(RegistryError::Denied))));
    assert!(sink.bytes.is_empty());assert_eq!((s.commits,s.record.value),(1,99));
    assert!(matches!(reply.write_once(&r,&mut b,&mut sink),Err(DeliveryError::Closed)));
}
#[test]
fn e4_disclosure_holds_lane_through_actual_write_and_revocation_stops_suffix() {
    let (_,r,h)=fixture();let r=Arc::new(r);let mut s=Store::new();let mut b=budget();let mut reply=run(&mut s,&r,h,&mut b);
    let mut sink=Sink::new(h);sink.limit=10;let during=r.clone();sink.during=Some(Box::new(move||{assert_eq!(during.update(context()),Err(RegistryError::Busy));}));
    assert_eq!(reply.write_once(&r,&mut b,&mut sink).unwrap(),10);r.update(context()).unwrap();
    assert!(reply.write_once(&r,&mut b,&mut sink).is_err());assert_eq!(sink.bytes.len(),10);assert_eq!(s.commits,1);
}
#[test]
fn e4_wrong_or_default_sink_cannot_receive_payload() {
    let (_,r,h)=fixture();let peer=r.register(17,request()).unwrap();let mut s=Store::new();let mut b=budget();
    for binding in [None,Some(peer)] {let mut reply=run(&mut s,&r,h,&mut b);let mut sink=Sink::new(h);sink.peer=binding;
        assert!(matches!(reply.write_once(&r,&mut b,&mut sink),Err(DeliveryError::Unbound)));assert!(sink.bytes.is_empty());}
}
#[test]
fn e4_nonblocking_write_failures_spend_work_without_prefix_loss() {
    let (_,r,h)=fixture();let mut s=Store::new();let mut b=budget();let mut reply=run(&mut s,&r,h,&mut b);let mut sink=Sink::new(h);
    for kind in [io::ErrorKind::WouldBlock,io::ErrorKind::Interrupted] {sink.error=Some(kind);assert!(reply.write_once(&r,&mut b,&mut sink).is_err());}
    assert!(sink.bytes.is_empty());assert_eq!(b.remaining(),13);sink.error=None;reply.write_once(&r,&mut b,&mut sink).unwrap();assert!(reply.complete());
}
#[test]
fn e4_expiry_between_commit_and_reply_and_zero_write_fail_closed() {
    let (p,r,h)=fixture();let mut s=Store::new();let mut b=budget();let mut reply=run(&mut s,&r,h,&mut b);let mut sink=Sink::new(h);
    p.change(|s|s.context.now=105);assert!(reply.write_once(&r,&mut b,&mut sink).is_err());assert!(sink.bytes.is_empty());
    let (_,r,h)=fixture();let mut s=Store::new();let mut b=budget();let mut reply=run(&mut s,&r,h,&mut b);let mut sink=Sink::new(h);sink.limit=0;
    assert!(reply.write_once(&r,&mut b,&mut sink).is_err());assert!(matches!(reply.write_once(&r,&mut b,&mut sink),Err(DeliveryError::Closed)));
}
#[test]
fn e4_panic_releases_holder_and_poison_denies_future_effects() {
    let (_,r,h)=fixture();let mut b=budget();
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {let mut g=r.acquire(h,request(),&mut b).unwrap();let _=g.with_caller(|_,_|panic!("test protected effect unwind"));}));
    assert!(result.is_err());assert_eq!(b.remaining(),15);assert_eq!(r.update(context()),Err(RegistryError::Poisoned));
    let s=match r.state.lock(){Err(p)=>p.into_inner(),Ok(_)=>panic!("must poison")};assert_eq!(s.holder,0);
}
#[test]
fn e4_storage_server_role_cannot_execute_caller_effect() {
    let p=Provider::new();p.change(|s|{s.identity.kind=Kind::Workload;s.permit.kind=Kind::Workload;s.permit.role=Role::StorageServer;
        s.observed.scope.kind=Kind::Workload;s.observed.scope.role=Role::StorageServer;s.proof.scope=s.observed.scope;});
    let r=Registry::new(config(),p).unwrap();let h=r.register(17,request()).unwrap();let mut b=budget();let mut g=r.acquire(h,request(),&mut b).unwrap();
    assert_eq!(g.with_caller(|_,_|()),Err(RegistryError::Denied));assert_eq!(g.recognize_server(31),Err(RegistryError::Denied));assert_eq!(g.recognize_server(30),Ok(()));
}

#[test]
fn e4_backend_uses_guard_frozen_request_and_disclosure_cannot_substitute_it() {
    let (_,r,h)=fixture();let mut s=Store::new();let mut b=budget();let mut g=r.acquire(h,request(),&mut b).unwrap();
    let changed=Request {argument:100,..request()};
    assert_eq!(g.disclose(changed,|| -> () {panic!("must not disclose")}),Err(RegistryError::Denied));
    assert!(g.execute(&mut s,true).unwrap().is_ok());assert_eq!(s.record.last,Some(request()));assert_eq!(s.record.value,99);
}

#[path="tests/guarded_loopback.rs"]
mod guarded_loopback;
