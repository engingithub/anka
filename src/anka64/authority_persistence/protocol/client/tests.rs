use super::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::thread;
fn env()->Envelope{Envelope{correlation:42,request:Request{anchor:10,installation:20,policy:3,caller:30,incarnation:4,sequence:1,expected:7,operation:Operation::Select,argument:99,attempt:0}}}
fn good(e:Envelope)->Vec<u8>{Reply::success(e,Outcome{revision:8,value:99,boot:8}).unwrap().encode().to_vec()}
// Synthetic trusted-evidence fixture, never production authentication.
#[derive(Default)]
struct Gate{calls:usize,deny_at:usize,bound:Option<Binding>}
impl ServerVerifier for Gate{fn verify(&mut self,b:Binding,_:Envelope)->Verdict{
    self.calls+=1;if (self.deny_at>0 && self.calls>=self.deny_at) || self.bound.is_some_and(|x|x!=b){Verdict::Invalid}else{Verdict::Valid}
}}
struct Data{sent:Vec<u8>,reads:VecDeque<io::Result<Vec<u8>>>,chunk:usize,write_error:Option<io::ErrorKind>,half_error:Option<io::ErrorKind>,halves:usize,drops:usize}
struct Mock(Rc<RefCell<Data>>);
fn mock(reply:Vec<u8>,eof:bool)->(Mock,Rc<RefCell<Data>>){
    let mut reads=VecDeque::new();if !reply.is_empty(){reads.push_back(Ok(reply));}if eof{reads.push_back(Ok(vec![]));}
    let d=Rc::new(RefCell::new(Data{sent:vec![],reads,chunk:112,write_error:None,half_error:None,halves:0,drops:0}));(Mock(d.clone()),d)
}
impl Drop for Mock{fn drop(&mut self){self.0.borrow_mut().drops+=1;}}
impl Read for Mock{fn read(&mut self,out:&mut [u8])->io::Result<usize>{
    let mut d=self.0.borrow_mut();match d.reads.pop_front(){Some(Ok(mut bytes))=>{let n=bytes.len().min(out.len());out[..n].copy_from_slice(&bytes[..n]);if n<bytes.len(){bytes.drain(..n);d.reads.push_front(Ok(bytes));}Ok(n)},Some(Err(e))=>Err(e),None=>Err(io::ErrorKind::WouldBlock.into())}
}}
impl Write for Mock{fn write(&mut self,b:&[u8])->io::Result<usize>{let mut d=self.0.borrow_mut();if let Some(e)=d.write_error.take(){return Err(e.into())}let n=d.chunk.min(b.len());d.sent.extend_from_slice(&b[..n]);Ok(n)}fn flush(&mut self)->io::Result<()>{Ok(())}}
impl Channel for Mock{fn prepare(&mut self)->io::Result<(SocketAddr,SocketAddr)>{Ok(("127.0.0.1:1234".parse().unwrap(),"127.0.0.1:4321".parse().unwrap()))}fn half_close(&mut self)->io::Result<()>{let mut d=self.0.borrow_mut();if let Some(e)=d.half_error.take(){return Err(e.into())}d.halves+=1;Ok(())}}
fn drive<S:Channel,V:ServerVerifier>(c:&mut Client<S,V>)->ClientResult{for _ in 0..520{if let Some(r)=c.poll(){return r}}panic!("finite client did not terminate")}
fn start(reply:Vec<u8>,eof:bool)->(Client<Mock,Gate>,Rc<RefCell<Data>>){let(s,d)=mock(reply,eof);(Client::start(s,env(),Config::default(),Gate::default()).unwrap(),d)}
#[test]
fn n110_client_short_writes_and_fragmented_reply_are_exact(){
    let(mut c,d)=start(vec![],false);d.borrow_mut().chunk=3;
    for bytes in good(env()).chunks(7){d.borrow_mut().reads.push_back(Ok(bytes.to_vec()));}d.borrow_mut().reads.push_back(Ok(vec![]));
    assert!(matches!(drive(&mut c),ClientResult::Success(_)));assert_eq!(d.borrow().sent,env().encode().unwrap());assert_eq!((d.borrow().halves,d.borrow().drops),(1,1));
}
#[test]
fn n110_client_full_reply_without_eof_stays_pending(){
    let(mut c,d)=start(good(env()),false);for _ in 0..5{assert_eq!(c.poll(),None)}assert_eq!(c.received,144);
    assert_eq!(c.cancel(),ClientResult::Unknown);assert_eq!(d.borrow().drops,1);assert_eq!(c.poll(),Some(ClientResult::Unknown));
}
#[test]
fn n110_client_truncated_tailed_or_corrupted_reply_is_unknown(){
    for n in [0,1,143,145]{let mut bytes=good(env());bytes.push(0);let(mut c,_)=start(bytes[..n].to_vec(),true);assert_eq!(drive(&mut c),ClientResult::Unknown);}
    let mut bytes=good(env());bytes[16]=1;let(mut c,_)=start(bytes,true);assert_eq!(drive(&mut c),ClientResult::Unknown);
}
#[test]
fn n110_client_old_correlation_and_changed_request_are_unknown(){
    for e in [Envelope{correlation:43,..env()},Envelope{request:Request{caller:31,..env().request},..env()}]{let(mut c,_)=start(good(e),true);assert_eq!(drive(&mut c),ClientResult::Unknown);}
}
#[test]
fn n110_client_default_denial_sends_no_request_bytes(){
    let(s,d)=mock(good(env()),true);let mut c=Client::start(s,env(),Config::default(),DenyServer).unwrap();
    assert_eq!(drive(&mut c),ClientResult::Unknown);assert!(d.borrow().sent.is_empty());assert_eq!(d.borrow().halves,0);
}
#[test]
fn n110_client_revocation_stops_request_suffix(){
    let(mut c,d)=start(good(env()),true);d.borrow_mut().chunk=7;c.verifier.deny_at=2;
    assert_eq!(c.poll(),None);assert_eq!(c.poll(),Some(ClientResult::Unknown));assert_eq!(d.borrow().sent.len(),7);assert_eq!(d.borrow().halves,0);
}
#[test]
fn n110_client_rechecks_server_evidence_after_eof(){
    let(mut c,_)=start(good(env()),true);c.verifier.deny_at=5;
    assert_eq!(drive(&mut c),ClientResult::Unknown);assert_eq!(c.verifier.calls,5);
}
#[test]
fn n110_client_retry_changes_only_connection_and_correlation(){
    let(mut c,_)=start(vec![],true);assert_eq!(drive(&mut c),ClientResult::Unknown);
    let old=c.binding();let work=c.work;let deadline=c.deadline;let e=Envelope{correlation:43,..env()};let(s,d)=mock(good(e),true);
    c.retry(s,43).unwrap();assert_ne!(c.binding(),old);assert_eq!(c.work,work-1);assert_eq!(c.deadline,deadline);assert_eq!(c.envelope.request,env().request);
    assert!(matches!(drive(&mut c),ClientResult::Success(_)));assert_eq!(d.borrow().sent,e.encode().unwrap());
}
#[test]
fn n110_client_stale_connection_evidence_cannot_authorize_retry(){
    let(mut c,_)=start(vec![],true);c.verifier.bound=Some(c.binding());assert_eq!(drive(&mut c),ClientResult::Unknown);
    let(s,d)=mock(good(Envelope{correlation:43,..env()}),true);c.retry(s,43).unwrap();assert_eq!(drive(&mut c),ClientResult::Unknown);assert!(d.borrow().sent.is_empty());
}
#[test]
fn n110_client_completed_result_is_stable_and_cannot_retry(){
    let(mut c,_)=start(good(env()),true);let result=drive(&mut c);assert!(matches!(result,ClientResult::Success(_)));
    assert_eq!(c.cancel(),result);assert_eq!(c.poll(),Some(result));let(s,_)=mock(vec![],true);assert!(c.retry(s,43).is_err());
    let(mut c,_)=start(Reply::failure(env(),Status::Conflict).unwrap().encode().to_vec(),true);assert_eq!(drive(&mut c),ClientResult::Rejected(Status::Conflict));let(s,_)=mock(vec![],true);assert!(c.retry(s,43).is_err());
}
#[test]
fn n110_client_work_and_deadline_do_not_reset_on_retry(){
    let(s,d)=mock(good(env()),true);let mut c=Client::start(s,env(),Config{work:2,..Config::default()},Gate::default()).unwrap();
    assert_eq!(drive(&mut c),ClientResult::Unknown);assert_eq!(d.borrow().halves,0);let(s,_)=mock(vec![],true);assert!(c.retry(s,43).is_err());
    let(mut c,d)=start(good(env()),true);c.deadline=Instant::now();assert_eq!(drive(&mut c),ClientResult::Unknown);assert!(d.borrow().sent.is_empty());let(s,_)=mock(vec![],true);assert!(c.retry(s,43).is_err());
}
#[test]
fn n110_client_blocked_interrupted_and_zero_write_are_bounded(){
    let(mut c,d)=start(good(env()),true);d.borrow_mut().write_error=Some(io::ErrorKind::WouldBlock);assert_eq!(c.poll(),None);
    d.borrow_mut().write_error=Some(io::ErrorKind::Interrupted);assert_eq!(c.poll(),None);assert_eq!(c.sent,0);
    d.borrow_mut().half_error=Some(io::ErrorKind::WouldBlock);assert!(matches!(drive(&mut c),ClientResult::Success(_)));assert_eq!(d.borrow().halves,1);
    let(mut c,d)=start(good(env()),true);d.borrow_mut().chunk=0;assert_eq!(drive(&mut c),ClientResult::Unknown);
}
#[test]
fn n110_client_configuration_and_invalid_retry_are_rejected(){
    for cfg in [Config{work:0,..Config::default()},Config{work:513,..Config::default()},Config{timeout:Duration::ZERO,..Config::default()}]{let(s,_)=mock(vec![],true);assert!(Client::start(s,env(),cfg,Gate::default()).is_err());}
    let(mut c,_)=start(vec![],true);let(s,_)=mock(vec![],true);assert!(c.retry(s,43).is_err());c.cancel();
    for correlation in [0,42]{let(s,_)=mock(vec![],true);assert!(c.retry(s,correlation).is_err());}
    assert!(Client::connect("0.0.0.0:1".parse().unwrap(),env(),Config::default(),Gate::default()).is_err());
}
// Actual sockets use the same engine. This synthetic grant fixture authorizes
// only test requests; it must not be installed as production evidence validation.
use super::super::transport::{Server,Config as ServerConfig};
use super::super::super::State;
struct Store{state:State,commits:Rc<RefCell<usize>>}
impl DurableRecord for Store{fn load(&mut self,_:u64,_:u64)->Result<State,Error>{Ok(self.state.clone())}fn commit(&mut self,_:u64,_:u64,b:&State,a:&State)->Result<(),Error>{assert_eq!(b,&self.state);self.state=a.clone();*self.commits.borrow_mut()+=1;Ok(())}}
struct Auth;
impl Verifier for Auth{type Peer=();fn verify(&mut self,_:&(),_:Request)->Option<(Context,Access)>{Some((Context{anchor:10,installation:20,policy:3,challenge:71,now:100,selected:true},Access{anchor:10,installation:20,policy:3,caller:30,incarnation:4,operation:Operation::Select,first:90,until:110,authentic:Verdict::Valid,status:Verdict::Valid}))}}
fn server()->(Server<Store,Auth>,Rc<RefCell<usize>>){let commits=Rc::new(RefCell::new(0));(Server::bind("127.0.0.1:0".parse().unwrap(),ServerConfig::default(),Store{state:State{revision:7,value:55,boot:8,last:None},commits:commits.clone()},Auth).unwrap(),commits)}
fn together<B:DurableRecord>(s:&mut Server<B,Auth>,c:&mut Client<TcpStream,Gate>)->ClientResult{
    for _ in 0..200{s.poll(&mut |_|Some(()),true).unwrap();if let Some(r)=c.poll(){return r}thread::sleep(Duration::from_millis(1));}panic!("bounded exchange did not complete")
}
#[test]
fn n110_client_actual_loopback_exchange_and_cleanup(){
    let(mut s,count)=server();let mut c=Client::connect(s.address().unwrap(),env(),Config::default(),Gate::default()).unwrap();
    assert!(matches!(together(&mut s,&mut c),ClientResult::Success(_)));assert_eq!(*count.borrow(),1);assert_eq!(s.usage(),(0,0));
}
#[test]
fn n110_client_lost_reply_retry_over_real_stream_commits_once(){
    let(mut s,count)=server();let address=s.address().unwrap();let mut c=Client::connect(address,env(),Config::default(),Gate::default()).unwrap();
    for _ in 0..100{
        c.poll();s.poll(&mut |_|Some(()),true).unwrap();
        if *count.borrow()==1{break}thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(*count.borrow(),1);assert_eq!(c.cancel(),ClientResult::Unknown);
    c.retry(TcpStream::connect(address).unwrap(),43).unwrap();assert!(matches!(together(&mut s,&mut c),ClientResult::Success(_)));assert_eq!(*count.borrow(),1);
}
#[cfg(any(target_os="linux",target_os="macos"))]
#[test]
fn n110_client_file_backend_recreation_preserves_unknown_retry(){
    use super::super::super::file_backend::FileRecord;
    let path=std::env::temp_dir().join(format!("anka110-client-{}-{}",std::process::id(),CONNECTIONS.fetch_add(1,Ordering::Relaxed)));
    let initial=State{revision:7,value:55,boot:8,last:None};let backend=FileRecord::create(&path,10,20,&initial).unwrap();
    let mut s=Server::bind("127.0.0.1:0".parse().unwrap(),ServerConfig::default(),backend,Auth).unwrap();
    let mut c=Client::connect(s.address().unwrap(),env(),Config::default(),Gate::default()).unwrap();
    // Send and half-close; drive server to completion WITHOUT reading a reply.
    for _ in 0..100{assert_eq!(c.poll(),None);if c.phase==Phase::Receive{break}thread::sleep(Duration::from_millis(1));}
    assert_eq!(c.phase,Phase::Receive);
    let mut accepted=false;
    for _ in 0..200{let p=s.poll(&mut |_|Some(()),true).unwrap();accepted|=p.accepted.is_some();if accepted && s.usage()==(0,0){break}thread::sleep(Duration::from_millis(1));}
    assert!(accepted);assert_eq!(s.usage(),(0,0));
    c.cancel();s.shutdown();drop(s);
    let mut backend=FileRecord::open(&path,10,20).unwrap();assert_eq!(backend.load(10,20).unwrap().revision,8);let mut s=Server::bind("127.0.0.1:0".parse().unwrap(),ServerConfig::default(),backend,Auth).unwrap();
    c.retry(TcpStream::connect(s.address().unwrap()).unwrap(),43).unwrap();assert_eq!(together(&mut s,&mut c),ClientResult::Success(Outcome{revision:8,value:99,boot:8}));
    drop(s);let mut backend=FileRecord::open(&path,10,20).unwrap();assert_eq!(backend.load(10,20).unwrap().revision,8);drop(backend);std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn n110_client_canonical_negative_statuses_preserve_uncertainty(){
    for status in [Status::Denied,Status::Conflict,Status::Exhausted,Status::Unavailable,Status::Uncertain,Status::Invalid]{
        let(mut c,_)=start(Reply::failure(env(),status).unwrap().encode().to_vec(),true);
        let expected=if status==Status::Uncertain{ClientResult::Unknown}else{ClientResult::Rejected(status)};
        assert_eq!(drive(&mut c),expected);
    }
}
