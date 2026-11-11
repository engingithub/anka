// Both ends use the real verifier adapters. Only the signed statements,
// authority lookups, and trusted channel observations below are fixtures.
use super::*;
use super::super::{caller_verifier::{CallerVerifier,LiveChannel,Possession,Statements,Status},peer_binder::{PeerBinder,Transcript},registry};
use super::super::super::{file_backend::FileRecord,DurableRecord,State,Error,Outcome};
use protocol::{client::{self,Client}, transport::{self,guarded_server::GuardedServer}, ClientResult};
use std::{cell::{Cell,RefCell},rc::Rc,io::{self,Read,Write},net::{TcpStream,TcpListener,SocketAddr,Shutdown},path::PathBuf,time::{Duration,Instant}};
use std::sync::atomic::{AtomicU64,Ordering};

fn ctx()->Context {Context{anchor:10,installation:20,policy:3,challenge:71,now:100,selected:true}}
fn request()->Request {Request{anchor:10,installation:20,policy:3,caller:30,incarnation:4,sequence:1,expected:7,operation:Operation::Select,argument:99,attempt:0}}
fn envelope()->Envelope {Envelope{correlation:42,request:request()}}
fn scope(connection:u64,server:bool,subject:u64)->Scope {
    Scope{runtime:if server{12}else{5},connection,binding:connection.checked_add(123).unwrap(),
        local:if server{30}else{40},peer:subject,kind:if server{Kind::Workload}else{Kind::Person},
        incarnation:4,role:if server{Role::StorageServer}else{Role::Caller},operation:Operation::Select,serial:9,challenge:71}
}
fn credential(o:Scope)->Credential {
    Credential{issuer:10,reference:o.peer+100,subject:o.peer,kind:o.kind,audience:20,policy:3,
        holder:o.peer+200,first:90,until:110,signature:Verdict::Valid}
}
fn proof(o:Scope)->BindingProof {BindingProof{scope:o,validated:Verdict::Valid}}
fn obs(o:Scope)->Observation {Observation{scope:o,live:true,channel:Verdict::Valid}}
#[derive(Clone)]
struct Grants {allowed:Rc<Cell<bool>>, status:Rc<Cell<Verdict>>}
impl Grants {
    fn new()->Self {Self{allowed:Rc::new(Cell::new(true)),status:Rc::new(Cell::new(Verdict::Valid))}}
}
impl Authority for Grants {
    fn status(&mut self,issuer:u64,reference:u64)->Option<Status> {
        Some(Status{issuer,reference,policy:3,serial:9,first:96,until:105,current:self.status.get()})
    }
    fn permit(&mut self,_:Context,o:Scope,_:Request)->Option<Permit> {
        self.allowed.get().then_some(Permit{issuer:10,subject:o.peer,kind:o.kind,audience:20,policy:3,
            incarnation:4,role:o.role,operation:Operation::Select,first:95,until:108,authentic:Verdict::Valid,status:Verdict::Valid})
    }
}
#[derive(Clone,Default)] struct Live(Rc<RefCell<Option<LiveStorage>>>);
impl StorageChannel for Live {
    fn live(&mut self,_:StreamBinding)->Option<LiveStorage>{*self.0.borrow()}
}
#[derive(Clone,Default)] struct Signed(Rc<RefCell<Option<(Credential,ServerPossession)>>>);
impl ServerStatements for Signed {
    fn checked_server(&mut self,_:StreamBinding)->Option<(Credential,ServerPossession)>{*self.0.borrow()}
}
type Provider=StorageVerifier<Live,Signed,Grants>;
type TestClient=Client<Wire,StorageAdapter<Provider>>;
struct ClientSide {live:Live, signed:Signed, grants:Grants}
impl ClientSide {
    fn new()->Self {Self{live:Live::default(),signed:Signed::default(),grants:Grants::new()}}
    fn start(&self,w:Wire)->TestClient {
        Client::start(w,envelope(),client::Config::default(),
            Provider::adapter(12,30,40,self.live.clone(),self.signed.clone(),self.grants.clone())).unwrap()
    }
    fn issue(&self,stream:StreamBinding,subject:u64){
        let o=scope(stream.connection,true,subject); let d=credential(o);
        *self.live.0.borrow_mut()=Some(LiveStorage{stream,binding:o.binding,context:ctx(),serial:9,observed:obs(o)});
        *self.signed.0.borrow_mut()=Some((d,ServerPossession{issuer:d.issuer,reference:d.reference,signer:d.holder,signed:proof(o)}));
    }
}
// Test hook precisely BETWEEN observing TCP EOF and the client's final verifier
// call. No production hooks; all bytes still pass through a real TCP stream.
struct Wire {tcp:TcpStream, revoke_at_eof:Option<Rc<Cell<Verdict>>>, max_write:usize}
impl Wire {fn new(tcp:TcpStream)->Self{Self{tcp,revoke_at_eof:None,max_write:usize::MAX}}}
impl client::Channel for Wire {
    fn prepare(&mut self)->io::Result<(SocketAddr,SocketAddr)>{
        self.tcp.set_nonblocking(true)?;Ok((self.tcp.local_addr()?,self.tcp.peer_addr()?))
    }
    fn half_close(&mut self)->io::Result<()>{self.tcp.shutdown(Shutdown::Write)}
}
impl Write for Wire {
    fn write(&mut self,b:&[u8])->io::Result<usize>{self.tcp.write(&b[..b.len().min(self.max_write)])}
    fn flush(&mut self)->io::Result<()>{self.tcp.flush()}
}
impl Read for Wire {
    fn read(&mut self,b:&mut[u8])->io::Result<usize>{
        let n=self.tcp.read(b)?;
        if n==0 {if let Some(flag)=self.revoke_at_eof.take(){flag.set(Verdict::Invalid);}}
        Ok(n)
    }
}
fn socket_pair()->(Wire,TcpStream){
    let l=TcpListener::bind("127.0.0.1:0").unwrap(); let c=TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (peer,_)=l.accept().unwrap(); peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    (Wire::new(c),peer)
}
fn received(mut peer:TcpStream)->Vec<u8>{let mut bytes=Vec::new();peer.read_to_end(&mut bytes).unwrap();bytes}
#[test]
fn e12_wrong_recognized_server_receives_zero_request_bytes(){
    let side=ClientSide::new();let(w,p)=socket_pair();let mut c=side.start(w);
    side.issue(c.binding(),41);assert_eq!(c.poll(),Some(ClientResult::Unknown));assert!(received(p).is_empty());
}
#[test]
fn e12_old_server_proof_on_new_stream_receives_zero_request_bytes(){
    let side=ClientSide::new();let(w,_p)=socket_pair();let mut c=side.start(w);
    side.issue(c.binding(),40);let old=side.signed.0.borrow().unwrap();
    c.cancel();let(w,p)=socket_pair();c.retry(w,43).unwrap();side.issue(c.binding(),40);
    assert_ne!(old.1.signed.scope.connection,c.binding().connection);*side.signed.0.borrow_mut()=Some(old);
    assert_eq!(c.poll(),Some(ClientResult::Unknown));assert!(received(p).is_empty());
}
#[test]
fn e12_revocation_after_short_write_discloses_only_that_prefix(){
    let side=ClientSide::new();let(mut w,p)=socket_pair();w.max_write=7;let mut c=side.start(w);
    side.issue(c.binding(),40);assert_eq!(c.poll(),None);side.grants.allowed.set(false);
    assert_eq!(c.poll(),Some(ClientResult::Unknown));assert_eq!(received(p),envelope().encode().unwrap()[..7].to_vec());
}
#[test]
fn e12_foreign_socket_and_stale_status_are_denied_before_first_write(){
    for attack in 0..4 {
        let side=ClientSide::new();let(w,p)=socket_pair();let mut c=side.start(w);side.issue(c.binding(),40);
        match attack {
            0=>side.live.0.borrow_mut().as_mut().unwrap().stream.remote="127.0.0.1:0".parse().unwrap(),
            1=>side.live.0.borrow_mut().as_mut().unwrap().serial=10,
            2=>side.signed.0.borrow_mut().as_mut().unwrap().1.signer=88,
            _=>side.grants.status.set(Verdict::Unknown),
        }
        assert_eq!(c.poll(),Some(ClientResult::Unknown));assert!(received(p).is_empty());
    }
}

#[derive(Clone,Default)] struct CallerLive(Rc<Cell<Option<Scope>>>);
impl LiveChannel for CallerLive {
    fn observe(&mut self,_:Transcript)->Option<(Context,Observation)>{Some((ctx(),obs(self.0.get()?)))}
}
#[derive(Clone,Default)] struct CallerSigned(Rc<Cell<Option<(Credential,Possession)>>>);
impl Statements for CallerSigned { fn checked(&mut self,_:Transcript)->Option<(Credential,Possession)>{self.0.get()} }
#[derive(Default)]
struct Counts {reads:Cell<usize>,commits:Cell<usize>}
struct CountedFile(FileRecord,Rc<Counts>);
impl DurableRecord for CountedFile {
    fn load(&mut self,a:u64,i:u64)->Result<State,Error>{self.1.reads.set(self.1.reads.get()+1);self.0.load(a,i)}
    fn commit(&mut self,a:u64,i:u64,b:&State,n:&State)->Result<(),Error>{
        self.0.commit(a,i,b,n)?;self.1.commits.set(self.1.commits.get()+1);Ok(())
    }
}
type VerifyingServer=GuardedServer<CountedFile,PeerBinder<CallerVerifier<CallerLive,CallerSigned,Grants>>>;
struct Service {server:VerifyingServer,live:CallerLive,signed:CallerSigned,grants:Grants}
impl Service {
    fn new(file:FileRecord,counts:Rc<Counts>)->Self {
        let live=CallerLive::default();let signed=CallerSigned::default();let grants=Grants::new();
        let verifier=CallerVerifier{channel:live.clone(),statements:signed.clone(),authority:grants.clone()};
        let registry=registry::Registry::new(registry::Config{context:ctx(),runtime:5,serial:9,slots:2},PeerBinder::new(verifier)).unwrap();
        let server=GuardedServer::bind("127.0.0.1:0".parse().unwrap(),transport::Config::default(),CountedFile(file,counts),registry).unwrap();
        Self{server,live,signed,grants}
    }
    fn connect(&self)->Wire {Wire::new(TcpStream::connect(self.server.address().unwrap()).unwrap())}
    fn tick(&mut self,b:StreamBinding)->transport::Poll{
        let Self{server,live,signed,..}=self;
        server.poll_verified(&mut |stream,id|{
            assert_eq!((stream.local_addr().unwrap(),stream.peer_addr().unwrap()),(b.remote,b.local));
            let o=scope(id,false,30);let d=credential(o);
            live.0.set(Some(o));signed.0.set(Some((d,Possession{issuer:d.issuer,reference:d.reference,signer:d.holder,signed:proof(o)})));
            Some((Transcript{runtime:o.runtime,connection:id,binding:o.binding},request(),105))
        },true).unwrap()
    }
    fn drive(&mut self,c:&mut TestClient)->ClientResult{
        let stop=Instant::now()+Duration::from_secs(4);
        loop {
            self.tick(c.binding());if let Some(r)=c.poll(){return r}
            assert!(Instant::now()<stop,"loopback failed to settle");std::thread::sleep(Duration::from_millis(1));
        }
    }
}
// Create an exclusive temp parent before installing a cleanup guard. Never
// clean a directory from a previous interrupted run or a different process.
struct Temp(PathBuf);
impl Temp {
    fn new()->Self {
        static IDS:AtomicU64=AtomicU64::new(1);
        loop {
            let path=std::env::temp_dir().join(format!("anka-e12-{}-{}",std::process::id(),IDS.fetch_add(1,Ordering::Relaxed)));
            match std::fs::create_dir(&path) {
                Ok(())=>return Self(path),Err(e) if e.kind()==io::ErrorKind::AlreadyExists=>continue,
                Err(e)=>panic!("create temp parent: {e}"),
            }
        }
    }
    fn file(&self)->PathBuf {self.0.join("installation")}
    fn provision(&self)->FileRecord {FileRecord::create(&self.file(),10,20,&State{revision:7,value:55,boot:8,last:None}).unwrap()}
    fn reopen(&self)->FileRecord {FileRecord::open(&self.file(),10,20).unwrap()}
}
impl Drop for Temp {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
#[test]
fn e12_unpermitted_caller_cannot_read_or_commit_file_record(){
    let temp=Temp::new();let counts=Rc::new(Counts::default());let mut host=Service::new(temp.provision(),counts.clone());
    host.grants.allowed.set(false);
    let side=ClientSide::new();let mut c=side.start(host.connect());side.issue(c.binding(),40);
    // The client recognizes the server and really writes before the server attempts admission.
    assert_eq!(c.poll(),None);
    let end=Instant::now()+Duration::from_secs(2);
    loop {let report=host.tick(c.binding());if report.closed==1{assert!(report.accepted.is_none());break}
        assert!(Instant::now()<end);std::thread::yield_now();}
    assert_eq!(host.drive(&mut c),ClientResult::Unknown);
    assert_eq!((counts.reads.get(),counts.commits.get()),(0,0));drop(host);
    assert_eq!(temp.reopen().load(10,20).unwrap().revision,7);
}
#[test]
fn e12_verified_file_commit_unknown_at_eof_reopen_and_exact_retry(){
    let temp=Temp::new();let counts=Rc::new(Counts::default());
    let mut host=Service::new(temp.provision(),counts.clone());let side=ClientSide::new();
    let mut wire=host.connect();wire.revoke_at_eof=Some(side.grants.status.clone());
    let mut c=side.start(wire);side.issue(c.binding(),40);
    assert_eq!(host.drive(&mut c),ClientResult::Unknown);
    // This flag changes ONLY on actual socket EOF, after the reply arrived.
    assert_eq!(side.grants.status.get(),Verdict::Invalid);
    assert_eq!((counts.reads.get(),counts.commits.get()),(1,1));drop(host);
    let mut disk=temp.reopen();let state=disk.load(10,20).unwrap();
    assert_eq!((state.revision,state.value,state.boot,state.last),(8,99,8,Some(request())));
    let mut restarted=Service::new(disk,counts.clone());
    side.grants.status.set(Verdict::Valid);let old=c.binding();
    c.retry(restarted.connect(),43).unwrap();assert_ne!(old.connection,c.binding().connection);
    side.issue(c.binding(),40);
    assert_eq!(restarted.drive(&mut c),ClientResult::Success(Outcome{revision:8,value:99,boot:8}));
    assert_eq!((counts.reads.get(),counts.commits.get()),(2,1));drop(restarted);
    assert_eq!(temp.reopen().load(10,20).unwrap(),state);
}
