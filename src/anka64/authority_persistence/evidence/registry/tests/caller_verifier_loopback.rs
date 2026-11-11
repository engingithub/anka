// Real loopback + counted backend; only checked signatures, channel metadata
// and current authority are fixtures. A replay modifies statements, never the
// observation of the newly accepted socket.
use super::*;
use super::super::super::super::{
    caller_verifier::{Authority, CallerVerifier, Credential, LiveChannel, Possession, Statements, Status},
    peer_binder::{EvidenceSource, PeerBinder, Transcript},
};

type Cell<T> = Rc<RefCell<T>>;
#[derive(Clone)] struct Channel(Cell<Option<(Context, Observation)>>);
#[derive(Clone)] struct Proofs(Cell<Option<(Credential, Possession)>>);
#[derive(Clone)] struct Grants(Cell<(Option<Status>, Option<Permit>)>);
impl LiveChannel for Channel {
    fn observe(&mut self, _: Transcript) -> Option<(Context, Observation)> { *self.0.borrow() }
}
impl Statements for Proofs {
    fn checked(&mut self, _: Transcript) -> Option<(Credential, Possession)> { *self.0.borrow() }
}
impl Authority for Grants {
    fn status(&mut self, _: u64, _: u64) -> Option<Status> { self.0.borrow().0 }
    fn permit(&mut self, _: Context, _: Scope, _: Request) -> Option<Permit> { self.0.borrow().1 }
}
type Adapter = CallerVerifier<Channel, Proofs, Grants>;
type Service = GuardedServer<Backend, PeerBinder<Adapter>>;
struct Fixture {
    channel: Channel, proofs: Proofs, grants: Grants, store: Cell<Store>, server: Service,
}
impl Fixture {
    fn new() -> Self {
        let channel = Channel(Default::default());
        let proofs = Proofs(Default::default());
        let grants = Grants(Default::default());
        let store = Rc::new(RefCell::new(Store::new()));
        let verifier = Adapter { channel: channel.clone(), statements: proofs.clone(), authority: grants.clone() };
        let registry = Registry::new(config(), PeerBinder::new(verifier)).unwrap();
        let server = Service::bind("127.0.0.1:0".parse().unwrap(), NetConfig::default(),
                                   Backend(store.clone()), registry).unwrap();
        Self { channel, proofs, grants, store, server }
    }
    fn counts(&self) -> (usize,usize) { let s=self.store.borrow(); (s.reads,s.commits) }
    fn tick(&mut self) {
        self.server.poll_verified(&mut |_,_| panic!("unexpected new peer"),true).unwrap();
    }
    fn open(&mut self, mut edit: impl FnMut(&Channel,&Proofs,&Grants)) -> (TcpStream,Option<Ticket>) {
        let c = TcpStream::connect(self.server.address().unwrap()).unwrap();
        let endpoint = c.local_addr().unwrap();
        c.set_nonblocking(true).unwrap();
        let Self { channel, proofs, grants, server, .. } = self;
        let ticket = wait_for("E10 accept", || {
            let mut seen = false;
            let result = server.poll_verified(&mut |stream,id| {
                seen = true;
                assert_eq!(stream.peer_addr().unwrap(),endpoint);
                let mut o = snapshot().observed;
                o.scope.connection=id;
                o.scope.binding=id.checked_add(11).unwrap();
                let t=Transcript {runtime:o.scope.runtime, connection:id, binding:o.scope.binding};
                *channel.0.borrow_mut()=Some((context(),o));
                *proofs.0.borrow_mut()=Some((Credential {reference:27,issuer:10,subject:30,
                    kind:Kind::Person,audience:20,policy:3,holder:88,first:90,until:110,signature:Verdict::Valid},
                    Possession {issuer:10,reference:27,signer:88,signed:BindingProof {scope:o.scope,validated:Verdict::Valid}}));
                *grants.0.borrow_mut()=(Some(Status {issuer:10,reference:27,policy:3,serial:9,
                    first:96,until:105,current:Verdict::Valid}),Some(snapshot().permit));
                edit(channel,proofs,grants);
                Some((t,request(),105))
            },true).unwrap();
            seen.then_some(result.accepted)
        });
        (c,ticket)
    }
}
#[test]
fn e10_funded_read_and_freshly_signed_retry_commit_once() {
    let mut f=Fixture::new();
    for n in 1..=2 {
        let (mut c,t)=f.open(|_,_,_| {}); assert!(t.is_some()); send_request(&mut c);
        wait_for("E10 reply", || { f.tick(); (f.server.usage()==(0,0)).then_some(()) });
        assert_eq!(tail(&mut c),expected().to_vec()); assert_eq!(f.counts(),(n,1));
    }
}
#[test]
fn e10_captured_signed_message_on_other_stream_never_reads() {
    let mut f=Fixture::new();
    let (_a,t)=f.open(|_,_,_| {}); let old=f.proofs.0.borrow().unwrap();
    assert!(f.server.cancel(t.unwrap()));
    let (mut b,t)=f.open(|ch,p,_| {
        assert_ne!(ch.0.borrow().unwrap().1.scope.connection,old.1.signed.scope.connection);
        *p.0.borrow_mut()=Some(old);
    });
    assert!(t.is_none()); assert!(tail(&mut b).is_empty()); assert_eq!(f.counts(),(0,0));
}
#[test]
fn e10_valid_possession_without_grant_authenticates_but_never_reads() {
    let mut f=Fixture::new();
    let (mut c,t)=f.open(|_,_,g| g.0.borrow_mut().1=None);
    let o=f.channel.0.borrow().unwrap().1.scope;
    let mut v=Adapter {channel:f.channel.clone(),statements:f.proofs.clone(),authority:f.grants.clone()};
    let auth=v.current(Transcript {runtime:o.runtime,connection:o.connection,binding:o.binding},request()).unwrap();
    assert_eq!((auth.identity.first,auth.identity.until),(90,110));
    assert!(auth.grant.is_none()); assert!(t.is_none()); assert!(tail(&mut c).is_empty());
    assert_eq!(f.counts(),(0,0));
}
#[test]
fn e10_hostile_primitive_receipts_never_read() {
    let mut f=Fixture::new();
    let edits: &[fn(&mut Credential,&mut Possession,&mut Status)] = &[
        |d,_,_| d.signature=Verdict::Unknown, |d,_,_| d.issuer=11, |d,_,_| d.until=100,
        |d,p,_| {d.holder=0;p.signer=0;}, |_,p,_| p.signer=77, |_,p,_| p.reference=28,
        |_,p,_| p.signed.validated=Verdict::Invalid, |_,p,_| p.signed.scope.operation=Operation::ReserveBoot,
        |_,_,s| s.reference=28, |_,_,s| s.issuer=11, |_,_,s| s.serial=8,
        |_,_,s| s.until=100, |_,_,s| s.first=101, |_,_,s| s.current=Verdict::Unknown,
    ];
    for edit in edits {
        let (mut c,t)=f.open(|_,pr,g| {
            let mut receipts=pr.0.borrow_mut(); let (d,p)=receipts.as_mut().unwrap();
            edit(d,p,g.0.borrow_mut().0.as_mut().unwrap());
        });
        assert!(t.is_none()); assert!(tail(&mut c).is_empty()); assert_eq!(f.counts(),(0,0));
    }
}
#[test]
fn e10_status_loss_after_eof_denies_dispatch() {
    let mut f=Fixture::new(); let (mut c,t)=f.open(|_,_,_| {}); let t=t.unwrap();
    send_request(&mut c);
    wait_for("E10 framed request", || {f.tick(); f.server.ready(t).then_some(())});
    assert_eq!(f.counts(),(0,0)); f.grants.0.borrow_mut().0=None;
    f.tick(); assert_eq!(f.server.usage(),(0,0)); assert!(tail(&mut c).is_empty()); assert_eq!(f.counts(),(0,0));
}
#[test]
fn e10_revocation_after_commit_suppresses_reply() {
    let mut f=Fixture::new(); let (mut c,t)=f.open(|_,_,_| {}); let t=t.unwrap();
    send_request(&mut c);
    wait_for("E10 durable effect", || {f.tick(); (f.counts()==(1,1)).then_some(())});
    assert_eq!(f.server.sent_bytes(t),Some(0));
    f.grants.0.borrow_mut().0.as_mut().unwrap().current=Verdict::Invalid;
    f.tick(); assert!(tail(&mut c).is_empty()); assert_eq!(f.counts(),(1,1));
}
