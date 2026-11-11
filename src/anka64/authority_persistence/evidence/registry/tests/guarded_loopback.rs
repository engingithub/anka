// E6: exercise actual TCP streams through the E5 adapter. Provider and binder
// are deterministic test doubles. No credentials are accepted over the wire.
use super::*;
use super::protocol::transport::{Config as NetConfig, Ticket, guarded_server::GuardedServer};
use std::cell::RefCell;
use std::io::Read;
use std::net::{TcpStream,Shutdown};
use std::rc::Rc;
use std::time::{Duration, Instant};

struct BoundProvider;
impl CallerProvider for BoundProvider {
    type Peer = u64;
    fn observe(&mut self, peer:&u64, _:Request) -> Option<Snapshot> {
        let mut v=snapshot();
        v.observed.scope.connection=*peer;
        v.proof.scope=v.observed.scope;
        Some(v)
    }
}
struct Backend(Rc<RefCell<Store>>);
impl DurableRecord for Backend {
    fn load(&mut self,a:u64,i:u64)->Result<Record,Error> {self.0.borrow_mut().load(a,i)}
    fn commit(&mut self,a:u64,i:u64,b:&Record,n:&Record)->Result<(),Error> {
        self.0.borrow_mut().commit(a,i,b,n)
    }
}
type Server=GuardedServer<Backend,BoundProvider>;
fn server(work:u64)->(Server,Rc<RefCell<Store>>) {
    let store=Rc::new(RefCell::new(Store::new()));
    let registry=Registry::new(config(),BoundProvider).unwrap();
    let s=Server::bind("127.0.0.1:0".parse().unwrap(),NetConfig{work,slots:2,..NetConfig::default()},
        Backend(store.clone()),registry).unwrap();
    (s,store)
}
fn bind_fixture(_: &TcpStream,id:u64)->Option<(u64,Request,u64)> {Some((id,request(),105))}
fn tick(s:&mut Server) {s.poll(&mut bind_fixture,true).unwrap();}
// One test deadline per wait. Sleeping yields to the TCP stack; it is never
// evidence that a connection was accepted, a write succeeded or EOF arrived.
fn wait_for<T>(label: &str, mut step: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(value) = step() { return value; }
        assert!(start.elapsed() < Duration::from_secs(2), "timed out: {label}");
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn bind_client(s: &mut Server, mut bind: impl FnMut(&TcpStream,u64)->Option<(u64,Request,u64)>)
    -> (TcpStream, Option<Ticket>)
{
    let c = TcpStream::connect(s.address().unwrap()).unwrap();
    c.set_nonblocking(true).unwrap();
    let ticket = wait_for("listener did not call binder", || {
        let mut called = false;
        let report = s.poll(&mut |stream,id| { called = true; bind(stream,id) }, true).unwrap();
        called.then_some(report.accepted)
    });
    (c,ticket)
}
fn connect(s:&mut Server)->(TcpStream,Ticket) {
    let (c,t) = bind_client(s,bind_fixture);
    (c,t.expect("fresh bound peer was denied"))
}
fn temporary(e:&io::Error)->bool {
    matches!(e.kind(),io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted)
}
fn send_request(c:&mut TcpStream) {
    let data = envelope().encode().unwrap();
    let mut offset = 0;
    wait_for("writing request", || {
        match c.write(&data[offset..]) {
            Ok(0) => panic!("zero-length request write"),
            Ok(n) => offset += n,
            Err(e) if temporary(&e) => {},
            Err(e) => panic!("request write: {e}"),
        }
        (offset == data.len()).then_some(())
    });
    c.shutdown(Shutdown::Write).unwrap();
}
fn expected()->[u8;protocol::REPLY_BYTES] {
    Reply::success(envelope(),Outcome{revision:8,value:99,boot:8}).unwrap().encode()
}
fn tail(c:&mut TcpStream)->Vec<u8> {
    let mut out = Vec::new();
    wait_for("waiting for peer EOF", || {
        let mut buf = [0; protocol::REPLY_BYTES + 1];
        match c.read(&mut buf) {
            Ok(0) => Some(()),
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                assert!(out.len() <= protocol::REPLY_BYTES, "oversized reply");
                None
            },
            Err(e) if temporary(&e) => None,
            Err(e) => panic!("reply read before EOF: {e}"),
        }
    });
    out
}
fn until_commit(s:&mut Server,store:&Rc<RefCell<Store>>) {
    wait_for("backend commit", || {
        tick(s);
        assert!(s.usage().0 > 0, "all slots closed before commit");
        (store.borrow().commits == 1).then_some(())
    });
}
fn first_write(s:&mut Server,t:Ticket)->usize {
    wait_for("first guarded reply write", || {
        tick(s);
        let sent = s.sent_bytes(t).expect("reply closed before first bounded write");
        assert!(sent <= 64 && sent < protocol::REPLY_BYTES);
        (sent > 0).then_some(sent)
    })
}
#[test]
fn e6_loopback_resumes_exact_reply_and_refunds_once() {
    let(mut s,store)=server(512);
    let(mut c,t)=connect(&mut s); send_request(&mut c);
    until_commit(&mut s,&store);
    first_write(&mut s,t);
    assert_eq!(s.usage(),(1,384));
    wait_for("completed reply", || { tick(&mut s); (s.usage().0 == 0).then_some(()) });
    assert_eq!(tail(&mut c),expected().to_vec());
    assert_eq!(s.usage(),(0,0)); assert!(!s.cancel(t));
    assert_eq!(store.borrow().commits,1);
}
#[test]
fn e6_revoked_suffix_cannot_reach_old_or_reconnected_stream() {
    let(mut s,store)=server(512);
    let(mut a,at)=connect(&mut s);
    let(_b,bt)=connect(&mut s);
    send_request(&mut a);until_commit(&mut s,&store);
    let sent=first_write(&mut s,at);
    assert_eq!(s.update(context()),Ok(10));
    let (mut reconnect,ticket)=bind_client(&mut s,bind_fixture);
    assert!(ticket.is_none()); // binder ran; provider still on serial 9
    assert_eq!(tail(&mut a),expected()[..sent].to_vec());
    assert!(tail(&mut reconnect).is_empty());
    assert_eq!(s.usage(),(1,384));assert!(!s.cancel(at));assert!(s.cancel(bt));
    assert_eq!(s.usage(),(0,0));assert_eq!(store.borrow().commits,1);
}
#[test]
fn e6_rebinding_old_channel_number_is_denied_even_without_revocation() {
    let(mut s,store)=server(512);let mut old=0;
    let (_a,t)=bind_client(&mut s,|_,id|{old=id;Some((id,request(),105))});
    let ticket=t.expect("original binding rejected");
    assert!(s.cancel(ticket));
    let (mut b,replay)=bind_client(&mut s,|_,id|{ assert_ne!(id,old); Some((old,request(),105)) });
    assert!(replay.is_none());assert!(tail(&mut b).is_empty());
    assert_eq!(s.usage(),(0,0)); assert_eq!(store.borrow().reads,0);
    let(_c,ct)=connect(&mut s);assert!(!s.cancel(ticket));assert!(s.cancel(ct));
}
#[test]
fn e6_reads_dispatch_and_reply_share_one_poll_budget() {
    let mut work=256;
    let(mut s,store)=server(work);let(mut c,t)=connect(&mut s);send_request(&mut c);
    assert_eq!(s.remaining(t),Some(work));
    wait_for("commit and first write under original poll budget", || {
        tick(&mut s); work-=1;
        assert_eq!(s.remaining(t),Some(work),"budget changed across a poll");
        s.sent_bytes(t).filter(|&n| n>0)
    });
    assert_eq!(store.borrow().commits,1);
    assert!(s.cancel(t)); assert_eq!(s.usage(),(0,0));
}
#[test]
fn e6_expired_provider_deadline_never_enters_backend() {
    let(mut s,store)=server(512);
    let (mut c,t)=bind_client(&mut s,|_,id|Some((id,request(),100)));
    let t=t.expect("registration unexpectedly denied before dispatch");
    send_request(&mut c);
    wait_for("complete request and EOF before expiry check", || {
        tick(&mut s);
        assert!(s.remaining(t).is_some_and(|n| n>1),"closed or exhausted before dispatch");
        s.ready(t).then_some(())
    });
    tick(&mut s);
    assert_eq!(s.usage(),(0,0));assert!(tail(&mut c).is_empty());
    assert_eq!((store.borrow().reads,store.borrow().commits),(0,0));
}
