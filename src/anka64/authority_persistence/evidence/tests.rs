use super::*;
use super::super::{DurableRecord, Error, Outcome, State, authorized};
use protocol::{ClientResult, DispatchBudget, Reply, Status, Verifier};
use protocol::client::{Channel, Client, Config};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::io::{self, Cursor, Read, Write};

fn request() -> Request { Request { anchor:10, installation:20, policy:3, caller:30,
    incarnation:4, sequence:1, expected:7, operation:Operation::Select, argument:99, attempt:0 } }
fn envelope() -> Envelope { Envelope { correlation:42, request:request() } }
fn stream() -> StreamBinding { StreamBinding { connection:6,
    local:"127.0.0.1:4000".parse().unwrap(), remote:"127.0.0.1:5000".parse().unwrap() } }
fn snapshot(role: Role) -> Snapshot {
    let (peer,kind)=if role==Role::Caller { (30,Kind::Person) } else { (40,Kind::Workload) };
    let scope=Scope { runtime:5, connection:6, binding:7, local:50, peer, kind,
        incarnation:4, role, operation:Operation::Select, serial:9, challenge:71 };
    Snapshot {
        context:Context { anchor:10, installation:20, policy:3, challenge:71, now:100, selected:true },
        identity:Identity { issuer:10, subject:peer, kind, audience:20, policy:3, challenge:71,
            first:90, until:110, authentic:Verdict::Valid, possession:Verdict::Valid, status:Verdict::Valid },
        permit:Permit { issuer:10, subject:peer, kind, audience:20, policy:3, incarnation:4, role,
            operation:Operation::Select, first:95, until:108, authentic:Verdict::Valid, status:Verdict::Valid },
        proof:BindingProof { scope, validated:Verdict::Valid },
        observed:Observation { scope, live:true, channel:Verdict::Valid },
    }
}
#[derive(Clone)]
struct Provider { current:Rc<Cell<Snapshot>>, calls:Rc<Cell<usize>>, missing:bool }
impl Provider {
    fn new(role:Role) -> Self { Self { current:Rc::new(Cell::new(snapshot(role))), calls:Rc::new(Cell::new(0)), missing:false } }
    fn change(&self, f:impl FnOnce(&mut Snapshot)) { let mut s=self.current.get();f(&mut s);self.current.set(s); }
    fn get(&self) -> Option<Snapshot> { self.calls.set(self.calls.get()+1);if self.missing {None} else {Some(self.current.get())} }
}
impl CallerProvider for Provider {
    type Peer=u64;
    fn observe(&mut self, peer:&u64, _:Request) -> Option<Snapshot> { if *peer==17 {self.get()} else {None} }
}
impl StorageProvider for Provider {
    fn observe(&mut self, b:StreamBinding, _:Envelope) -> Option<Snapshot> {
        if b.local!=stream().local || b.remote!=stream().remote {return None}
        self.get()
    }
}
fn caller_fixture() -> (Provider,CallerAdapter<Provider>,CallerAdmission<u64>) {
    let p=Provider::new(Role::Caller);let mut a=CallerAdapter::new(p.clone());
    let h=a.admit(17,request()).unwrap();(p,a,h)
}
fn budget() -> DispatchBudget { DispatchBudget { slots:0, slot_limit:4, bytes:0, byte_limit:1536, work:512, now:0, deadline:1 } }
struct Store { state:State, reads:usize, commits:usize, revoke:Option<Provider> }
impl Store { fn new() -> Self { Self { state:State { revision:7, value:55, boot:8, last:None }, reads:0, commits:0, revoke:None } } }
impl DurableRecord for Store {
    fn load(&mut self,a:u64,i:u64) -> Result<State,Error> { assert_eq!((a,i),(10,20));self.reads+=1;Ok(self.state.clone()) }
    fn commit(&mut self,a:u64,i:u64,b:&State,n:&State) -> Result<(),Error> {
        assert_eq!((a,i),(10,20));assert_eq!(&self.state,b);self.state=n.clone();self.commits+=1;
        if let Some(p)=&self.revoke {p.change(|s|s.permit.status=Verdict::Invalid)}
        Ok(())
    }
}
fn dispatch(store:&mut Store,a:&mut CallerAdapter<Provider>,h:&CallerAdmission<u64>) -> Reply {
    let e=envelope();let bytes=protocol::dispatch(store,a,h,&e.encode().unwrap(),true,budget(),true).unwrap();
    Reply::decode(&bytes,true,e).unwrap()
}
#[test]
fn e110_caller_projects_exact_intersection_for_each_kind_and_operation() {
    for kind in [Kind::Person,Kind::Installation,Kind::Workload] {
        for operation in [Operation::Select,Operation::ReserveBoot] {
            let mut s=snapshot(Role::Caller);s.identity.kind=kind;s.permit.kind=kind;
            s.observed.scope.kind=kind;s.observed.scope.operation=operation;s.proof.scope=s.observed.scope;s.permit.operation=operation;
            let r=Request {operation,attempt:if operation==Operation::Select {0} else {71},..request()};
            let a=caller(s,r).unwrap();assert_eq!((a.first,a.until),(95,108));assert!(authorized(s.context,r,a));
        }
    }
}
#[test]
fn e110_identity_and_permit_are_independently_bound() {
    macro_rules! bad { ($group:ident,$field:ident,$value:expr) => {{
        let mut s=snapshot(Role::Caller);s.$group.$field=$value;
        assert!(caller(s,request()).is_none(),"{}.{}",stringify!($group),stringify!($field));
    }} }
    bad!(identity,issuer,11);bad!(identity,subject,31);bad!(identity,kind,Kind::Workload);
    bad!(identity,audience,21);bad!(identity,policy,4);bad!(identity,challenge,72);
    bad!(identity,first,101);bad!(identity,until,100);
    bad!(permit,issuer,11);bad!(permit,subject,31);bad!(permit,kind,Kind::Workload);
    bad!(permit,audience,21);bad!(permit,policy,4);bad!(permit,incarnation,5);
    bad!(permit,role,Role::StorageServer);bad!(permit,operation,Operation::ReserveBoot);
    bad!(permit,first,101);bad!(permit,until,100);
}
#[test]
fn e110_unknown_and_invalid_verdicts_never_admit() {
    for verdict in [Verdict::Unknown,Verdict::Invalid] {
        let changes:&[fn(&mut Snapshot,Verdict)]=&[
            |s,v|s.identity.authentic=v,|s,v|s.identity.possession=v,|s,v|s.identity.status=v,
            |s,v|s.permit.authentic=v,|s,v|s.permit.status=v,|s,v|s.proof.validated=v,|s,v|s.observed.channel=v];
        for change in changes {let mut s=snapshot(Role::Caller);change(&mut s,verdict);assert!(caller(s,request()).is_none());}
    }
}
#[test]
fn e110_binding_covers_every_scope_field_and_direction() {
    macro_rules! bad { ($field:ident,$value:expr) => {{
        let mut s=snapshot(Role::Caller);s.proof.scope.$field=$value;
        assert!(caller(s,request()).is_none(),"proof {}",stringify!($field));
        let mut s=snapshot(Role::Caller);s.observed.scope.$field=$value;
        assert!(caller(s,request()).is_none(),"observation {}",stringify!($field));
    }} }
    bad!(runtime,6);bad!(connection,7);bad!(binding,8);bad!(local,30);bad!(peer,50);
    bad!(kind,Kind::Workload);bad!(incarnation,5);bad!(role,Role::StorageServer);
    bad!(operation,Operation::ReserveBoot);bad!(serial,10);bad!(challenge,72);
}
#[test]
fn e110_coherent_zero_handles_and_unselected_context_deny() {
    macro_rules! zero { ($field:ident) => {{let mut s=snapshot(Role::Caller);
        s.observed.scope.$field=0;s.proof.scope=s.observed.scope;
        assert!(!admitted(s),"{}",stringify!($field));}} }
    zero!(runtime);zero!(connection);zero!(binding);zero!(local);zero!(peer);zero!(incarnation);zero!(serial);
    let mut s=snapshot(Role::Caller);s.context.selected=false;assert!(!admitted(s));
    s=snapshot(Role::Caller);s.observed.live=false;assert!(!admitted(s));
    // Consistently rewriting every copy still cannot make zero an authority root.
    s=snapshot(Role::Caller);s.context.anchor=0;s.identity.issuer=0;s.permit.issuer=0;assert!(!admitted(s));
    s=snapshot(Role::Caller);s.context.installation=0;s.identity.audience=0;s.permit.audience=0;assert!(!admitted(s));
    s=snapshot(Role::Caller);s.context.policy=0;s.identity.policy=0;s.permit.policy=0;assert!(!admitted(s));
    s=snapshot(Role::Caller);s.context.challenge=0;s.identity.challenge=0;s.observed.scope.challenge=0;s.proof.scope=s.observed.scope;assert!(!admitted(s));
}
#[test]
fn e110_validity_is_half_open_without_wrapping_or_widening() {
    for (now,ok) in [(94,false),(95,true),(107,true),(108,false),(u64::MAX,false)] {
        let mut s=snapshot(Role::Caller);s.context.now=now;assert_eq!(caller(s,request()).is_some(),ok);
    }
    let mut s=snapshot(Role::Caller);s.identity.first=99;s.identity.until=105;
    let a=caller(s,request()).unwrap();assert_eq!((a.first,a.until),(99,105));
    s.identity.first=u64::MAX;s.identity.until=1;assert!(!admitted(s));
}
#[test]
fn e110_request_scope_and_shape_are_checked_before_projection() {
    let s=snapshot(Role::Caller);
    macro_rules! bad { ($field:ident,$value:expr) => {assert!(caller(s,Request {$field:$value,..request()}).is_none(),stringify!($field));} }
    bad!(anchor,11);bad!(installation,21);bad!(policy,4);bad!(caller,31);bad!(incarnation,5);
    bad!(operation,Operation::ReserveBoot);bad!(sequence,0);bad!(argument,0);bad!(attempt,1);
    // Sequencing is T2's responsibility, not a fabricated restriction in E2.
    assert!(caller(s,Request {sequence:2,expected:8,argument:100,..request()}).is_some());
}
#[test]
fn e110_defaults_missing_provider_and_foreign_channel_deny() {
    assert!(CallerAdapter::new(DenyCallerProvider).admit((),request()).is_none());
    assert_eq!(StorageAdapter::new(DenyStorageProvider,40).verify(stream(),envelope()),Verdict::Invalid);
    let mut p=Provider::new(Role::Caller);p.missing=true;
    assert!(CallerAdapter::new(p).admit(17,request()).is_none());
    assert!(CallerAdapter::new(Provider::new(Role::Caller)).admit(18,request()).is_none());
}
#[test]
fn e110_admitted_handle_rechecks_time_revocation_and_live_state() {
    let changes: [fn(&mut Snapshot);4] = [|s|s.context.now=108,|s|s.permit.status=Verdict::Invalid,
        |s|s.identity.possession=Verdict::Unknown,|s|s.observed.live=false];
    for change in changes {
        let (p,mut a,h)=caller_fixture();assert!(a.verify(&h,request()).is_some());p.change(change);
        assert!(a.verify(&h,request()).is_none());assert_eq!(p.calls.get(),3);
    }
}
#[test]
fn e110_coherent_snapshot_and_policy_refresh_cannot_retarget_old_handle() {
    let (p,mut a,h)=caller_fixture();
    p.change(|s|{s.observed.scope.serial+=1;s.proof.scope=s.observed.scope;});
    assert!(a.verify(&h,request()).is_none());let fresh=a.admit(17,request()).unwrap();
    assert!(a.verify(&fresh,request()).is_some());
    p.change(|s|{s.context.policy+=1;s.identity.policy+=1;s.permit.policy+=1;});
    let r=Request {policy:4,..request()};assert!(a.verify(&fresh,r).is_none());assert!(a.admit(17,r).is_some());
}
#[test]
fn e110_restart_reconnect_and_coherent_peer_substitution_fence_old_admission() {
    let changes:&[fn(&mut Snapshot)]=&[
        |s|s.observed.scope.runtime+=1,|s|s.observed.scope.connection+=1,
        |s|s.observed.scope.binding+=1,|s|s.observed.scope.local+=1,
        |s|{s.context.challenge+=1;s.identity.challenge+=1;s.observed.scope.challenge+=1;},
        |s|{s.identity.subject+=1;s.permit.subject+=1;s.observed.scope.peer+=1;},
        |s|{s.permit.incarnation+=1;s.observed.scope.incarnation+=1;}];
    for change in changes {
        let (p,mut a,h)=caller_fixture();p.change(|s|{change(s);s.proof.scope=s.observed.scope;});
        let s=p.current.get();let r=Request {caller:s.observed.scope.peer,incarnation:s.observed.scope.incarnation,..request()};
        assert!(a.verify(&h,r).is_none());assert!(a.admit(17,r).is_some());
    }
}
#[test]
fn e110_renewal_requires_new_admission_not_silent_lifetime_extension() {
    let (p,mut a,h)=caller_fixture();p.change(|s|{s.identity.until=200;s.permit.until=200;});
    assert!(a.verify(&h,request()).is_none());assert!(a.admit(17,request()).is_some());
}
#[test]
fn e110_dispatch_denial_never_reads_or_mutates_backend() {
    let (p,mut a,h)=caller_fixture();p.change(|s|s.permit.status=Verdict::Invalid);
    let mut store=Store::new();assert_eq!(dispatch(&mut store,&mut a,&h).status(),Status::Denied);
    assert_eq!((store.reads,store.commits),(0,0));
}
#[test]
fn e110_dispatch_exact_retry_has_one_effect_and_checks_current_evidence() {
    let (p,mut a,h)=caller_fixture();let mut store=Store::new();
    let first=dispatch(&mut store,&mut a,&h);assert_eq!(first.status(),Status::Success);
    assert_eq!(dispatch(&mut store,&mut a,&h),first);assert_eq!(store.commits,1);
    p.change(|s|s.observed.live=false);assert_eq!(dispatch(&mut store,&mut a,&h).status(),Status::Denied);
    assert_eq!((store.reads,store.commits),(2,1));
}
#[test]
fn e110_revocation_after_commit_suppresses_outcome_without_rollback() {
    let (p,mut a,h)=caller_fixture();let mut store=Store::new();store.revoke=Some(p);
    let reply=dispatch(&mut store,&mut a,&h);assert_eq!(reply.status(),Status::Denied);assert_eq!(reply.outcome(),None);
    assert_eq!((store.commits,store.state.revision,store.state.value),(1,8,99));
    assert_eq!(dispatch(&mut store,&mut a,&h).status(),Status::Denied);assert_eq!(store.commits,1);
}
#[test]
fn e110_storage_role_is_separate_from_caller_and_person_identity() {
    let s=snapshot(Role::StorageServer);assert!(server(s,40,request()));assert!(caller(s,request()).is_none());
    assert!(!server(snapshot(Role::Caller),30,request()));assert!(!server(s,41,request()));
    let mut s=s;s.identity.kind=Kind::Person;s.permit.kind=Kind::Person;
    s.observed.scope.kind=Kind::Person;s.proof.scope=s.observed.scope;assert!(!server(s,40,request()));
    s.identity.kind=Kind::Installation;s.permit.kind=Kind::Installation;
    s.observed.scope.kind=Kind::Installation;s.proof.scope=s.observed.scope;assert!(server(s,40,request()));
    assert!(server(s,40,Request {caller:999,incarnation:8,..request()})); // caller != server
}
#[test]
fn e110_server_adapter_requires_actual_connection_and_expected_namespace() {
    let p=Provider::new(Role::StorageServer);let mut a=StorageAdapter::new(p.clone(),40);
    let mut b=stream();b.connection=7;assert_eq!(a.verify(b,envelope()),Verdict::Invalid);
    assert_eq!(a.verify(stream(),Envelope {request:Request {installation:21,..request()},..envelope()}),Verdict::Invalid);
    assert_eq!(a.verify(stream(),envelope()),Verdict::Valid);
    p.change(|s|s.observed.scope.serial+=1);assert_eq!(a.verify(stream(),envelope()),Verdict::Invalid);
    p.change(|s|s.proof.scope=s.observed.scope);assert_eq!(a.verify(stream(),envelope()),Verdict::Invalid);
}
#[test]
fn e110_server_reconnect_needs_new_bound_evidence_and_cannot_replay_old_stream() {
    let p=Provider::new(Role::StorageServer);let mut a=StorageAdapter::new(p.clone(),40);
    assert_eq!(a.verify(stream(),envelope()),Verdict::Valid);
    let b=StreamBinding {connection:7,..stream()};assert_eq!(a.verify(b,envelope()),Verdict::Invalid);
    p.change(|s|{s.observed.scope.connection=7;s.observed.scope.binding=8;s.proof.scope=s.observed.scope;});
    assert_eq!(a.verify(b,envelope()),Verdict::Valid);
    p.current.set(snapshot(Role::StorageServer));assert_eq!(a.verify(stream(),envelope()),Verdict::Invalid);
}
#[test]
fn e110_server_endpoint_substitution_cannot_keep_same_connection_id() {
    let p=Provider::new(Role::StorageServer);let mut a=StorageAdapter::new(p,40);
    assert_eq!(a.verify(stream(),envelope()),Verdict::Valid);
    assert_eq!(a.verify(StreamBinding {remote:stream().local,..stream()},envelope()),Verdict::Invalid);
}
// Synthetic channel/evidence ONLY in tests. Never installed as default authority.
struct MemoryChannel { input:Cursor<Vec<u8>>, written:Rc<RefCell<Vec<u8>>>, provider:Provider, revoke_at_eof:bool }
impl Read for MemoryChannel {
    fn read(&mut self,b:&mut [u8]) -> io::Result<usize> { let n=self.input.read(b)?;
        if n==0 && self.revoke_at_eof {self.provider.change(|s|s.permit.status=Verdict::Invalid)} Ok(n) }
}
impl Write for MemoryChannel {
    fn write(&mut self,b:&[u8]) -> io::Result<usize> {self.written.borrow_mut().extend_from_slice(b);Ok(b.len())}
    fn flush(&mut self) -> io::Result<()> {Ok(())}
}
impl Channel for MemoryChannel {
    fn prepare(&mut self) -> io::Result<(std::net::SocketAddr,std::net::SocketAddr)> {Ok((stream().local,stream().remote))}
    fn half_close(&mut self) -> io::Result<()> {Ok(())}
}
fn real_client(revoke_at_eof:bool) -> (Provider,Rc<RefCell<Vec<u8>>>,Client<MemoryChannel,StorageAdapter<Provider>>) {
    let p=Provider::new(Role::StorageServer);let written=Rc::new(RefCell::new(Vec::new()));
    let input=Reply::success(envelope(),Outcome {revision:8,value:99,boot:8}).unwrap().encode().to_vec();
    let channel=MemoryChannel {input:Cursor::new(input),written:written.clone(),provider:p.clone(),revoke_at_eof};
    let c=Client::start(channel,envelope(),Config::default(),StorageAdapter::new(p.clone(),40)).unwrap();
    // Test validator binds evidence to the actual freshly allocated client handle.
    p.change(|s|{s.observed.scope.connection=c.binding().connection;s.proof.scope=s.observed.scope;});
    (p,written,c)
}
#[test]
fn e110_client_adapter_roundtrip_uses_current_server_checks() {
    let (p,written,mut c)=real_client(false);
    let mut result=None;for _ in 0..8 {if result.is_none(){result=c.poll();}}
    assert_eq!(result,Some(ClientResult::Success(Outcome {revision:8,value:99,boot:8})));
    assert_eq!(written.borrow().as_slice(),envelope().encode().unwrap().as_slice());assert!(p.calls.get()>=5);
}
#[test]
fn e110_client_bad_server_emits_no_request_bytes() {
    let (p,written,mut c)=real_client(false);p.change(|s|s.identity.possession=Verdict::Invalid);
    assert_eq!(c.poll(),Some(ClientResult::Unknown));assert!(written.borrow().is_empty());
}
#[test]
fn e110_client_rechecks_after_eof_before_exposing_success() {
    let (_,_,mut c)=real_client(true);let mut result=None;
    for _ in 0..8 {if result.is_none(){result=c.poll();}}
    assert_eq!(result,Some(ClientResult::Unknown));
}
