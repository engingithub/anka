use super::*;
use super::super::super::State;
use std::collections::VecDeque;
use std::net::Shutdown;
use std::thread;
fn envelope()->Envelope{Envelope{correlation:42,request:Request{anchor:10,installation:20,policy:3,caller:30,incarnation:4,sequence:1,expected:7,operation:Operation::Select,argument:99,attempt:0}}}
#[derive(Default)]
struct Auth{deny:bool,calls:usize}
impl Verifier for Auth {
    type Peer=u64;
    fn verify(&mut self,p:&u64,_:Request)->Option<(Context,Access)>{
        self.calls+=1;if self.deny || *p!=17{return None}
        Some((Context{anchor:10,installation:20,policy:3,challenge:71,now:100,selected:true},
            Access{anchor:10,installation:20,policy:3,caller:30,incarnation:4,operation:Operation::Select,first:90,until:110,authentic:Verdict::Valid,status:Verdict::Valid}))
    }
}
struct Store{state:State,reads:usize,commits:usize}
impl Store{fn new()->Self{Self{state:State{revision:7,value:55,boot:8,last:None},reads:0,commits:0}}}
impl DurableRecord for Store {
    fn load(&mut self,_:u64,_:u64)->Result<State,Error>{self.reads+=1;Ok(self.state.clone())}
    fn commit(&mut self,_:u64,_:u64,before:&State,after:&State)->Result<(),Error>{assert_eq!(before,&self.state);self.state=after.clone();self.commits+=1;Ok(())}
}
fn address()->SocketAddr{"127.0.0.1:0".parse().unwrap()}
fn server()->Server<Store,Auth>{Server::bind(address(),Config::default(),Store::new(),Auth::default()).unwrap()}
// EXPLICIT TEST authority fixture only: production must not authenticate by IP.
fn fixture_peer(_:SocketAddr)->Option<u64>{Some(17)}
fn tick<B:DurableRecord>(s:&mut Server<B,Auth>)->Poll{s.poll(&mut fixture_peer,true).unwrap()}
fn connect<B:DurableRecord>(s:&mut Server<B,Auth>)->(TcpStream,Ticket){
    let c=TcpStream::connect(s.address().unwrap()).unwrap();
    for _ in 0..100{if let Some(t)=tick(s).accepted{return(c,t)}thread::sleep(Duration::from_millis(1));}
    panic!("bounded accept did not complete")
}
fn receive<B:DurableRecord>(s:&mut Server<B,Auth>,c:&mut TcpStream)->Vec<u8>{
    c.set_nonblocking(true).unwrap();let mut out=Vec::new();let mut bytes=[0;145];
    for _ in 0..200{
        tick(s);
        match c.read(&mut bytes){Ok(0)=>return out,Ok(n)=>out.extend_from_slice(&bytes[..n]),Err(e) if transient(&e)=>{},Err(e)=>panic!("{e}")}
        thread::sleep(Duration::from_millis(1));
    }panic!("bounded reply did not complete")
}
fn exchange<B:DurableRecord>(s:&mut Server<B,Auth>,e:Envelope)->Reply{
    let (mut c,_)=connect(s);c.write_all(&e.encode().unwrap()).unwrap();c.shutdown(Shutdown::Write).unwrap();
    Reply::decode(&receive(s,&mut c),true,e).unwrap()
}
// Scripted stream exercises the SAME state engine with forced short writes and
// WouldBlock; real loopback tests below cover OS EOF and socket closure.
struct Io{reads:VecDeque<io::Result<Vec<u8>>>,written:Vec<u8>,chunk:usize,blocked:bool,zero:bool}
impl Io{fn request()->Self{Self{reads:VecDeque::from([Ok(envelope().encode().unwrap().to_vec()),Ok(vec![])]),written:vec![],chunk:7,blocked:false,zero:false}}}
impl Read for Io{fn read(&mut self,out:&mut [u8])->io::Result<usize>{match self.reads.pop_front(){Some(Ok(v))=>{assert!(v.len()<=out.len());out[..v.len()].copy_from_slice(&v);Ok(v.len())},Some(Err(e))=>Err(e),None=>Err(io::ErrorKind::WouldBlock.into())}}}
impl Write for Io{fn write(&mut self,b:&[u8])->io::Result<usize>{if self.blocked{return Err(io::ErrorKind::WouldBlock.into())}if self.zero{return Ok(0)}let n=b.len().min(self.chunk);self.written.extend_from_slice(&b[..n]);Ok(n)}fn flush(&mut self)->io::Result<()>{Ok(())}}
fn connection()->Connection<Io,u64>{Connection::new(Io::request(),17,1,Instant::now()+Duration::from_secs(5),512)}
fn advance(c:&mut Connection<Io,u64>,b:&mut Store,a:&mut Auth)->bool{
    step(c,b,a,DispatchBudget{slots:0,slot_limit:4,bytes:0,byte_limit:1536,work:512,now:0,deadline:1},true,Instant::now())
}
#[test]
fn n110_transport_short_writes_keep_exact_prefix_and_dispatch_once(){
    let(mut c,mut b,mut a)=(connection(),Store::new(),Auth::default());
    assert!(advance(&mut c,&mut b,&mut a));assert!(advance(&mut c,&mut b,&mut a));assert_eq!(b.commits,1);
    c.stream.blocked=true;assert!(advance(&mut c,&mut b,&mut a));assert_eq!(c.sent,0);c.stream.blocked=false;
    for _ in 0..30{if !advance(&mut c,&mut b,&mut a){break}}
    assert_eq!(c.sent,144);assert_eq!(b.commits,1);assert_eq!(Reply::decode(&c.stream.written,true,envelope()).unwrap().status(),Status::Success);
}
#[test]
fn n110_transport_revocation_suppresses_remaining_reply_without_rollback(){
    let(mut c,mut b,mut a)=(connection(),Store::new(),Auth::default());
    for _ in 0..3{assert!(advance(&mut c,&mut b,&mut a))}assert_eq!(c.sent,7);a.deny=true;
    assert!(!advance(&mut c,&mut b,&mut a));assert_eq!(c.stream.written.len(),7);assert_eq!(b.commits,1);
    assert_eq!(accept_reply(&c.stream.written,true,envelope(),ClientEvidence{server:Verdict::Valid,pending_current:true}),ClientResult::Unknown);
}
#[test]
fn n110_transport_deadline_work_and_zero_write_close_without_reexecution(){
    let(mut c,mut b,mut a)=(connection(),Store::new(),Auth::default());c.work=1;
    assert!(advance(&mut c,&mut b,&mut a));assert!(!advance(&mut c,&mut b,&mut a));assert_eq!(b.reads,0);
    c=connection();c.deadline=Instant::now();assert!(!advance(&mut c,&mut b,&mut a));assert_eq!(a.calls,0);
    c=connection();assert!(advance(&mut c,&mut b,&mut a));assert!(advance(&mut c,&mut b,&mut a));c.stream.zero=true;
    assert!(!advance(&mut c,&mut b,&mut a));assert_eq!(b.commits,1);
}
#[test]
fn n110_transport_fragmentation_requires_real_eof(){
    let mut s=server();let(mut c,_)=connect(&mut s);let bytes=envelope().encode().unwrap();
    c.write_all(&bytes[..43]).unwrap();for _ in 0..3{tick(&mut s);}assert_eq!(s.backend.reads,0);
    c.write_all(&bytes[43..]).unwrap();for _ in 0..3{tick(&mut s);}assert_eq!(s.backend.reads,0);
    c.shutdown(Shutdown::Write).unwrap();assert_eq!(Reply::decode(&receive(&mut s,&mut c),true,envelope()).unwrap().status(),Status::Success);
    assert_eq!(s.usage(),(0,0));assert_eq!(s.backend.commits,1);
}
#[test]
fn n110_transport_truncation_and_tail_never_touch_backend(){
    for n in [0,1,111,113]{let mut s=server();let(mut c,_)=connect(&mut s);let mut bytes=envelope().encode().unwrap().to_vec();bytes.push(0);
        c.write_all(&bytes[..n]).unwrap();c.shutdown(Shutdown::Write).unwrap();
        assert!(receive(&mut s,&mut c).is_empty());assert_eq!((s.backend.reads,s.verifier.calls),(0,0));assert_eq!(s.usage(),(0,0));}
}
#[test]
fn n110_transport_slot_and_byte_limits_preserve_other_client(){
    let mut s=Server::bind(address(),Config{byte_limit:384,..Config::default()},Store::new(),Auth::default()).unwrap();
    let(_a,t)=connect(&mut s);let mut b=TcpStream::connect(s.address().unwrap()).unwrap();assert!(tick(&mut s).accepted.is_none());assert_eq!(s.usage(),(1,384));
    assert!(s.cancel(t));assert!(!s.cancel(t));let next=tick(&mut s).accepted.unwrap();assert_ne!(t,next);assert!(!s.cancel(t));
    b.write_all(&envelope().encode().unwrap()).unwrap();b.shutdown(Shutdown::Write).unwrap();assert_eq!(receive(&mut s,&mut b).len(),144);assert_eq!(s.usage(),(0,0));
}
#[test]
fn n110_transport_stale_and_foreign_tickets_cannot_cancel_live_peer(){
    let(mut a,mut b)=(server(),server());let(_ca,ta)=connect(&mut a);let(_cb,tb)=connect(&mut b);
    assert!(!b.cancel(ta));assert_eq!(b.usage(),(1,384));assert!(a.cancel(ta));assert!(!a.cancel(ta));assert!(b.cancel(tb));
}
#[test]
fn n110_transport_idle_work_exhaustion_refunds_once(){
    let mut s=Server::bind(address(),Config{work:2,..Config::default()},Store::new(),Auth::default()).unwrap();let(_c,t)=connect(&mut s);
    for _ in 0..3{tick(&mut s);}assert_eq!(s.usage(),(0,0));assert!(!s.cancel(t));assert_eq!(s.backend.reads,0);
}
#[test]
fn n110_transport_shutdown_closes_all_owned_slots(){
    let mut s=server();let(_a,ta)=connect(&mut s);let(_b,tb)=connect(&mut s);s.shutdown();s.shutdown();
    assert_eq!(s.usage(),(0,0));assert!(!s.cancel(ta));assert!(!s.cancel(tb));assert!(s.address().is_err());assert_eq!(tick(&mut s).live,0);
}
#[test]
fn n110_transport_unbound_or_denied_peer_cannot_read_storage(){
    let mut s=server();let _c=TcpStream::connect(s.address().unwrap()).unwrap();
    s.poll(&mut |_|None,true).unwrap();assert_eq!(s.usage(),(0,0));assert_eq!(s.verifier.calls,0);
    s.verifier.deny=true;let(mut c,_)=connect(&mut s);c.write_all(&envelope().encode().unwrap()).unwrap();c.shutdown(Shutdown::Write).unwrap();
    assert!(receive(&mut s,&mut c).is_empty());assert_eq!(s.backend.reads,0);assert_eq!(s.usage(),(0,0));
}
#[test]
fn n110_transport_default_verifier_stays_fail_closed(){
    let mut s=Server::bind(address(),Config::default(),Store::new(),DenyAll).unwrap();
    let mut c=TcpStream::connect(s.address().unwrap()).unwrap();c.write_all(&envelope().encode().unwrap()).unwrap();c.shutdown(Shutdown::Write).unwrap();
    for _ in 0..10{s.poll(&mut |_|Some(()),true).unwrap();thread::sleep(Duration::from_millis(1));}
    assert_eq!(s.backend.reads,0);assert_eq!(s.usage(),(0,0));
}
#[test]
fn n110_transport_competing_client_conflicts_and_retry_is_exact(){
    let mut s=server();let(mut a,_)=connect(&mut s);let(mut b,_)=connect(&mut s);
    a.write_all(&envelope().encode().unwrap()).unwrap();a.shutdown(Shutdown::Write).unwrap();
    let other=Envelope{correlation:43,request:Request{caller:31,argument:100,..envelope().request}};
    // Same authorized caller, competing payload/expected revision.
    let other=Envelope{request:Request{caller:30,..other.request},..other};
    b.write_all(&other.encode().unwrap()).unwrap();b.shutdown(Shutdown::Write).unwrap();
    assert_eq!(Reply::decode(&receive(&mut s,&mut a),true,envelope()).unwrap().status(),Status::Success);
    assert_eq!(Reply::decode(&receive(&mut s,&mut b),true,other).unwrap().status(),Status::Conflict);
    assert_eq!(exchange(&mut s,Envelope{correlation:99,..envelope()}).status(),Status::Success);assert_eq!(s.backend.commits,1);
}
#[test]
fn n110_transport_identity_exhaustion_refuses_accept_without_wrap(){
    let mut s=server();s.next=u64::MAX;let _c=TcpStream::connect(s.address().unwrap()).unwrap();
    assert!(tick(&mut s).accepted.is_none());assert_eq!(s.usage(),(0,0));assert_eq!(s.next,u64::MAX);
}
#[test]
fn n110_transport_configuration_refuses_external_listener_and_bad_limits(){
    for c in [Config{slots:0,..Config::default()},Config{slots:65,..Config::default()},Config{byte_limit:383,..Config::default()},Config{work:513,..Config::default()},Config{timeout:Duration::ZERO,..Config::default()}]{
        assert!(Server::bind(address(),c,Store::new(),Auth::default()).is_err());}
    assert!(Server::bind("0.0.0.0:0".parse().unwrap(),Config::default(),Store::new(),Auth::default()).is_err());
}
#[test]
fn n110_transport_interrupted_and_failed_io_are_bounded(){
    let(mut c,mut b,mut a)=(connection(),Store::new(),Auth::default());
    c.stream.reads=VecDeque::from([Err(io::ErrorKind::Interrupted.into()),Err(io::ErrorKind::ConnectionReset.into())]);
    assert!(advance(&mut c,&mut b,&mut a));assert_eq!(c.work,511);assert!(!advance(&mut c,&mut b,&mut a));assert_eq!(b.reads,0);
}
#[cfg(any(target_os="linux",target_os="macos"))]
#[test]
fn n110_transport_file_reopen_after_lost_reply_recovers_one_effect(){
    use super::super::super::file_backend::FileRecord;
    let path=std::env::temp_dir().join(format!("anka110-loopback-{}-{}",std::process::id(),SERVICES.fetch_add(1,Ordering::Relaxed)));
    let initial=Store::new().state;let backend=FileRecord::create(&path,10,20,&initial).unwrap();
    let mut s=Server::bind(address(),Config::default(),backend,Auth::default()).unwrap();let(mut c,_)=connect(&mut s);
    c.write_all(&envelope().encode().unwrap()).unwrap();c.shutdown(Shutdown::Write).unwrap();
    for _ in 0..100{
        tick(&mut s);
        if s.connections.iter().any(|c|c.as_ref().is_some_and(|c|c.output.is_some())){break}
        thread::sleep(Duration::from_millis(1));
    }
    assert!(s.connections.iter().any(|c|c.as_ref().is_some_and(|c|c.output.is_some())));
    s.shutdown();drop(s);drop(c); // committed, but zero reply bytes sent
    let backend=FileRecord::open(&path,10,20).unwrap();let mut s=Server::bind(address(),Config::default(),backend,Auth::default()).unwrap();
    let r=exchange(&mut s,Envelope{correlation:100,..envelope()});assert_eq!(r.outcome(),Some(Outcome{revision:8,value:99,boot:8}));
    assert_eq!(s.backend.load(10,20).unwrap().revision,8);drop(s);std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn n110_transport_binder_unwind_refunds_temporary_reservation(){
    let mut s=server();let _c=TcpStream::connect(s.address().unwrap()).unwrap();
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
        s.poll(&mut |_|->Option<u64>{panic!("test binder failure")},true).unwrap();
    }));
    assert!(result.is_err());assert_eq!(s.usage(),(0,0));assert_eq!(s.backend.reads,0);
    let (_c,t)=connect(&mut s);assert!(s.cancel(t));assert_eq!(s.usage(),(0,0));
}
#[test]
fn n110_transport_expired_connection_refunds_without_touching_peer(){
    let mut s=server();let(_a,ta)=connect(&mut s);let(_b,tb)=connect(&mut s);
    let c=s.connections.iter_mut().flatten().find(|c|c.id==ta.sequence).unwrap();c.deadline=Instant::now();
    assert_eq!(tick(&mut s).closed,1);assert_eq!(s.usage(),(1,384));assert!(!s.cancel(ta));assert!(s.cancel(tb));assert_eq!(s.backend.reads,0);
}
