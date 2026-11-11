// E8: real accepted TCP streams; only the credential validator is a fixture.
use super::*;
use super::super::super::super::peer_binder::{
    CurrentEvidence, EvidenceSource, KeyAssociation, PeerBinder, Signer, Transcript,
};

#[derive(Clone, Default)]
struct Source(Rc<RefCell<Option<CurrentEvidence>>>);
impl EvidenceSource for Source {
    fn current(&mut self, _: Transcript, _: Request) -> Option<CurrentEvidence> {
        *self.0.borrow()
    }
}
type Verified = GuardedServer<Backend, PeerBinder<Source>>;
fn verified() -> (Verified, Source, Rc<RefCell<Store>>) {
    verified_with_work(512)
}
fn verified_with_work(work: u64) -> (Verified, Source, Rc<RefCell<Store>>) {
    let source = Source::default();
    let store = Rc::new(RefCell::new(Store::new()));
    let registry = Registry::new(config(), PeerBinder::new(source.clone())).unwrap();
    let server = Verified::bind("127.0.0.1:0".parse().unwrap(), NetConfig { work, ..NetConfig::default() },
        Backend(store.clone()), registry).unwrap();
    (server, source, store)
}
fn evidence(t: Transcript) -> CurrentEvidence {
    let mut s = snapshot();
    s.observed.scope.connection = t.connection;
    s.observed.scope.binding = t.binding;
    s.proof.scope = s.observed.scope;
    CurrentEvidence {
        context: s.context, actual: s.observed, identity: s.identity, proof: s.proof,
        key: KeyAssociation { issuer: 10, subject: 30, kind: Kind::Person, holder: 88, verified: Verdict::Valid },
        signer: Signer { transcript: t, holder: 88, verified: Verdict::Valid },
        grant: Some(s.permit),
    }
}
// Resolve a transcript only after observing the actual accepted stream. The
// fixture's synthetic handles are not a production authentication mechanism.
fn open(s: &mut Verified, source: &Source, mut alter: impl FnMut(&mut CurrentEvidence))
    -> (TcpStream, Option<Ticket>) {
    let c = TcpStream::connect(s.address().unwrap()).unwrap();
    let endpoint = c.local_addr().unwrap();
    c.set_nonblocking(true).unwrap();
    let t = wait_for("E8 resolver was not called", || {
        let mut called = false;
        let poll = s.poll_verified(&mut |stream, minted| {
            assert_eq!(stream.peer_addr().unwrap(), endpoint);
            let actual = Transcript { runtime: 5, connection: minted, binding: minted.checked_add(11).unwrap() };
            let mut e = evidence(actual);
            alter(&mut e);
            *source.0.borrow_mut() = Some(e);
            called = true;
            Some((actual, request(), 105))
        }, true).unwrap();
        called.then_some(poll.accepted)
    });
    (c,t)
}
fn poll(s: &mut Verified) {
    s.poll_verified(&mut |_,_| panic!("unexpected additional connection"), true).unwrap();
}
fn drain(s: &mut Verified) {
    wait_for("E8 slot cleanup", || { poll(s); (s.usage() == (0,0)).then_some(()) });
}
fn counts(store: &Rc<RefCell<Store>>) -> (usize,usize) {
    let b=store.borrow(); (b.reads,b.commits)
}

#[test]
fn e8_funded_authorized_request_and_fresh_retry_use_real_backend() {
    let (mut s, source, store)=verified();
    for reads in 1..=2 {
        let (mut c,t)=open(&mut s,&source,|_| {});
        assert!(t.is_some());
        send_request(&mut c); drain(&mut s);
        assert_eq!(tail(&mut c),expected().to_vec());
        assert_eq!(counts(&store),(reads,1)); // exact retry did not commit twice
    }
}
#[test]
fn e8_replayed_proof_or_entire_old_snapshot_on_new_tcp_stream_cannot_read() {
    let (mut s, source, store)=verified();
    let (_a,t)=open(&mut s,&source,|_| {});
    let old=source.0.borrow().as_ref().copied().unwrap();
    assert!(s.cancel(t.unwrap()));
    for complete_replay in [false,true] {
        let (mut b,t)=open(&mut s,&source,|fresh| {
            assert_ne!(fresh.actual.scope.connection, old.actual.scope.connection);
            if complete_replay { *fresh=old; }
            else { fresh.proof=old.proof; fresh.signer=old.signer; }
        });
        assert!(t.is_none()); assert!(tail(&mut b).is_empty());
        assert_eq!(counts(&store),(0,0)); assert_eq!(s.usage(),(0,0));
    }
}
#[test]
fn e8_recognized_peer_without_grant_cannot_read() {
    let (mut s,source,store)=verified();
    let (mut c,t)=open(&mut s,&source,|e| e.grant=None);
    assert!(t.is_none()); assert!(tail(&mut c).is_empty());
    assert_eq!(counts(&store),(0,0)); assert_eq!(s.usage(),(0,0));
}
#[test]
fn e8_key_signer_and_grant_substitutions_cannot_read() {
    let (mut s,source,store)=verified();
    let edits: &[fn(&mut CurrentEvidence)] = &[
        |e| e.key.issuer+=1, |e| e.key.subject+=1, |e| e.key.kind=Kind::Workload,
        |e| e.key.verified=Verdict::Unknown, |e| {e.key.holder=0;e.signer.holder=0;},
        |e| e.signer.holder+=1, |e| e.signer.verified=Verdict::Invalid,
        |e| e.signer.transcript.binding+=1, |e| e.signer.transcript.runtime+=1,
        |e| e.signer.transcript.connection+=1, |e| e.grant.as_mut().unwrap().operation=Operation::ReserveBoot,
    ];
    for edit in edits {
        let (mut c,t)=open(&mut s,&source,*edit);
        assert!(t.is_none()); assert!(tail(&mut c).is_empty());
        assert_eq!(counts(&store),(0,0)); assert_eq!(s.usage(),(0,0));
    }
}
#[test]
fn e8_loss_after_framing_denies_before_first_backend_read() {
    let (mut s,source,store)=verified();
    for lose_grant in [true,false] {
        let (mut c,t)=open(&mut s,&source,|_| {}); let t=t.unwrap();
        send_request(&mut c);
        wait_for("E8 exact frame and EOF", || {
            poll(&mut s); assert!(s.remaining(t).is_some()); s.ready(t).then_some(())
        });
        assert_eq!(counts(&store),(0,0));
        {
            let mut current=source.0.borrow_mut(); let e=current.as_mut().unwrap();
            if lose_grant {e.grant=None;} else {e.signer.transcript.binding+=1;}
        }
        poll(&mut s); assert_eq!(s.usage(),(0,0)); assert!(tail(&mut c).is_empty());
        assert_eq!(counts(&store),(0,0));
    }
}
#[test]
fn e8_signer_loss_after_commit_suppresses_reply_without_rollback() {
    let (mut s,source,store)=verified();
    let (mut c,t)=open(&mut s,&source,|_| {}); let t=t.unwrap(); send_request(&mut c);
    wait_for("commit before disclosure", || {
        poll(&mut s); assert!(s.remaining(t).is_some()); (counts(&store)==(1,1)).then_some(())
    });
    assert_eq!(s.sent_bytes(t),Some(0));
    source.0.borrow_mut().as_mut().unwrap().signer.verified=Verdict::Unknown;
    poll(&mut s); assert_eq!(s.usage(),(0,0)); assert!(tail(&mut c).is_empty());
    assert_eq!(counts(&store),(1,1));
}

#[test]
fn e8_unfunded_first_read_is_not_a_backend_capacity_denial() {
    // Only one read poll is funded; framing, EOF and dispatch need more.
    let (mut s,source,store)=verified_with_work(1);
    let (mut c,t)=open(&mut s,&source,|_| {}); assert!(t.is_some());
    send_request(&mut c); drain(&mut s);
    // Closing with unread input need not produce orderly socket EOF.
    assert_eq!(counts(&store),(0,0));
}
