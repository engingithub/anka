use super::*;
use std::{collections::BTreeSet,net::TcpListener,thread};
static SERIAL:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {fn new()->Self {Self(std::env::temp_dir().join(format!("anka-ag110-{}-{}-{}",std::process::id(),
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),SERIAL.fetch_add(1,Ordering::Relaxed))))}}
impl Drop for Temp {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn manifest()->Manifest {Manifest{anchor:10,installation:20,artifact:99,generation:2,role:2,profile:1,size:10000,image:101,metadata:102,dependencies:103,provenance:104}}
fn caller()->Caller {Caller{owner:30,incarnation:4}}
fn limits()->Limits {Limits{max_payload:32768,window:4096,owner_bytes:65536,total_bytes:131072,other_bytes:20000,work:50}}
fn config()->Config {Config{slots:2,byte_limit:2*CHARGE,work:100000,ingress:426500,timeout:Duration::from_secs(5)}}
struct Proof {channels:BTreeSet<u64>,deny:bool,grant:bool,owner:Caller,payload:Vec<u8>,panic_live:bool}
impl Proof {fn new()->Self {Self{channels:BTreeSet::new(),deny:false,grant:true,owner:caller(),payload:(0..10000).map(|n|n as u8).collect(),panic_live:false}}}
impl Evidence for Proof {
    fn authorize(&mut self,s:Scope)->Verdict {if self.grant && s.manifest==manifest() && s.caller==caller(){Verdict::Valid}else{Verdict::Invalid}}
    fn inspect(&mut self,r:&mut dyn Read)->Result<Manifest,Error> {
        let mut b=Vec::new();r.read_to_end(&mut b).map_err(io_error)?;if b!=self.payload{return Err(Error::CorruptRecord)}Ok(manifest())
    }
}
impl TransferEvidence for Proof {fn caller(&mut self,c:u64,_:&Request<'_>)->Result<Caller,Error> {
    self.live_channel(c)?;Ok(self.owner)
}}
impl TransportEvidence for Proof {
    // Explicit TEST binder. Production must verify stream-bound credentials;
    // the loopback address is deliberately not claimed to authenticate anyone.
    fn bind_stream(&mut self,s:&TcpStream,c:u64)->Result<(),Error> {
        if self.deny || s.peer_addr().is_err() || !self.channels.insert(c){return Err(Error::Authority)}Ok(())
    }
    fn live_channel(&mut self,c:u64)->Result<(),Error> {
        assert!(!self.panic_live,"injected provider unwind");
        if self.deny || !self.channels.contains(&c){Err(Error::Authority)}else{Ok(())}
    }
    fn retire_channel(&mut self,c:u64){self.channels.remove(&c);}
}
fn make_with(cfg:Config)->(Temp,Service<Proof>) {
    let t=Temp::new();let store=ArtifactStore::create(&t.0,10,20,1,limits(),Selection{revision:7,artifact:55,generation:1}).unwrap();
    let service=Service::new(store,Proof::new(),cfg).unwrap();(t,service)
}
fn make()->(Temp,Service<Proof>){make_with(config())}
fn pair()->(TcpStream,TcpStream) {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();let client=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let(server,_)=listener.accept().unwrap();client.set_nodelay(true).unwrap();(client,server)
}
fn connect(service:&Service<Proof>)->(TcpStream,Session<'_,Proof>) {
    let(c,s)=pair();(c,service.attach(s).unwrap())
}
fn req(op:Operation,ticket:u64)->Request<'static> {Request{operation:op,correlation:77,ticket,offset:0,
    publish_request:if matches!(op,Operation::Publish|Operation::Outcome){91}else{0},expected:if matches!(op,Operation::Publish|Operation::Outcome){7}else{0},manifest:manifest(),payload:&[]}}
fn wire(r:Request<'_>)->Vec<u8>{let mut b=[0;MAX_REQUEST];let n=encode(&r,&mut b).unwrap();b[..n].to_vec()}
fn until(session:&mut Session<'_,Proof>,phase:Phase) {
    for _ in 0..5000 {if session.phase==phase{return}assert!(!session.poll().unwrap());thread::sleep(Duration::from_micros(100));}
    panic!("bounded phase wait failed");
}
fn drain(session:&mut Session<'_,Proof>,client:&mut TcpStream)->Vec<u8> {
    client.set_nonblocking(true).unwrap();let mut out=Vec::new();let mut b=[0;512];let mut done=false;
    let mut terminal=None;let deadline=Instant::now()+Duration::from_secs(3);
    while Instant::now()<deadline {
        if !done {match session.poll(){Ok(x)=>done=x,Err(e)=>{terminal=Some(e.to_string());done=true;}}}
        if done {assert!(session.stream.is_none(),"terminal session retained its socket");}
        match client.read(&mut b) {
            Ok(0)=>return out,Ok(n)=>out.extend_from_slice(&b[..n]),
            Err(e) if transient(&e)=>{},
            Err(e) if done && e.kind()==io::ErrorKind::ConnectionReset=>return out,
            Err(e)=>panic!("client read: {e}; terminal={terminal:?}"),
        }
        thread::sleep(Duration::from_micros(100));
    }
    panic!("bounded response wait failed: phase={:?} done={done} received={} sent={} client_bytes={} socket_owned={} terminal={terminal:?}",
        session.phase,session.received,session.sent,out.len(),session.stream.is_some());
}

struct Server;
impl ServerEvidence for Server {fn current(&mut self,_:u64,_:&Request<'_>,_:&[u8])->Verdict {Verdict::Valid}}
fn exchange(service:&Service<Proof>,r:Request<'_>)->Outcome {
    let(mut client,mut session)=connect(service);let frame=wire(r);
    for chunk in frame.chunks(23){client.write_all(chunk).unwrap();session.poll().unwrap();}
    client.shutdown(Shutdown::Write).unwrap();let channel=session.channel;
    let bytes=drain(&mut session,&mut client);accept_reply(&frame,&bytes,true,channel,&mut Server).unwrap()
}
fn upload(service:&Service<Proof>)->u64 {
    let ticket=exchange(service,req(Operation::Begin,0)).ticket;
    let payload:Vec<u8>=(0..10000).map(|n|n as u8).collect();let mut off=0;
    for b in payload.chunks(4096){let mut r=req(Operation::Append,ticket);r.offset=off;r.payload=b;off+=b.len()as u64;assert_eq!(exchange(service,r).cursor,off);}
    assert_eq!(exchange(service,req(Operation::Seal,ticket)).phase,2);ticket
}
#[test]
fn ag110_tcp_upload_seal_publish_reopen_and_outcome() {
    let(t,s)=make();let ticket=upload(&s);let out=exchange(&s,req(Operation::Publish,ticket));assert_eq!(out.revision,8);
    assert_eq!(s.usage().unwrap().0,0);assert_eq!(s.usage().unwrap().1,0);drop(s);
    let store=ArtifactStore::open(&t.0,10,20,2,limits()).unwrap();let s=Service::new(store,Proof::new(),config()).unwrap();
    assert_eq!(exchange(&s,req(Operation::Outcome,0)),out);
    assert_eq!(fs::read(t.0.join("artifact.bytes")).unwrap(),(0..10000).map(|n|n as u8).collect::<Vec<_>>());
}
#[test]
fn ag110_partial_request_and_complete_frame_without_fin_do_not_dispatch() {
    let(t,s)=make();let(mut c,mut session)=connect(&s);let frame=wire(req(Operation::Begin,0));let head=fs::read(t.0.join("artifact.record")).unwrap();
    c.write_all(&frame[..41]).unwrap();for _ in 0..10{session.poll().unwrap();}
    assert_eq!(fs::read(t.0.join("artifact.record")).unwrap(),head);
    c.write_all(&frame[41..]).unwrap();for _ in 0..20{session.poll().unwrap();}
    assert_eq!(session.phase,Phase::Reading);assert_eq!(fs::read(t.0.join("artifact.record")).unwrap(),head);
    c.shutdown(Shutdown::Write).unwrap();let bytes=drain(&mut session,&mut c);assert!(!bytes.is_empty());
}
#[test]
fn ag110_truncation_tail_and_oversized_input_close_without_effect() {
    for n in [0,1,167,169,MAX_REQUEST+1] {
        let(t,s)=make();let(mut c,mut session)=connect(&s);let head=fs::read(t.0.join("artifact.record")).unwrap();
        let mut bytes=wire(req(Operation::Begin,0));bytes.resize(n,0);c.write_all(&bytes).unwrap();c.shutdown(Shutdown::Write).unwrap();
        assert!(drain(&mut session,&mut c).is_empty());assert_eq!(fs::read(t.0.join("artifact.record")).unwrap(),head);
        assert_eq!(s.usage().unwrap().0,0);
    }
}
#[test]
fn ag110_each_fragment_rechecks_grant_without_rolling_back_commit() {
    let(_t,s)=make();let ticket=upload(&s);let(mut c,mut session)=connect(&s);let frame=wire(req(Operation::Publish,ticket));
    c.write_all(&frame).unwrap();c.shutdown(Shutdown::Write).unwrap();until(&mut session,Phase::Sending);
    assert_eq!(s.lane.lock().unwrap().store.state.selected.revision,8);
    session.poll().unwrap();let prefix=session.sent;assert!(prefix>0 && prefix<=64);
    s.update(|p|p.grant=false).unwrap();let bytes=drain(&mut session,&mut c);assert_eq!(bytes.len(),prefix);
    assert_eq!(s.lane.lock().unwrap().store.state.selected.revision,8);
    s.update(|p|p.grant=true).unwrap();assert_eq!(exchange(&s,req(Operation::Outcome,0)).revision,8);
}
#[test]
fn ag110_changed_caller_cannot_receive_saved_reply() {
    let(_t,s)=make();let(mut c,mut session)=connect(&s);c.write_all(&wire(req(Operation::Begin,0))).unwrap();c.shutdown(Shutdown::Write).unwrap();
    until(&mut session,Phase::Sending);s.update(|p|p.owner.incarnation+=1).unwrap();assert!(drain(&mut session,&mut c).is_empty());
    assert_eq!(s.usage().unwrap().0,0);assert!(s.lane.lock().unwrap().store.usage().unwrap().candidate>0);
}
#[test]
fn ag110_transient_write_retains_prefix_and_spends_shared_work() {
    let(_t,s)=make();let(mut c,mut session)=connect(&s);c.write_all(&wire(req(Operation::Begin,0))).unwrap();c.shutdown(Shutdown::Write).unwrap();until(&mut session,Phase::Sending);
    let work=s.usage().unwrap().3;
    for cut in [IoCut::Blocked,IoCut::Interrupted]{session.io_cut=Some(cut);assert!(!session.poll().unwrap());assert_eq!(session.sent,0);}
    assert_eq!(s.usage().unwrap().3,work-2);assert!(!drain(&mut session,&mut c).is_empty());
}
#[test]
fn ag110_zero_write_and_cancel_preserve_stage_and_refund_once() {
    let(_t,s)=make();let(mut c,mut session)=connect(&s);c.write_all(&wire(req(Operation::Begin,0))).unwrap();c.shutdown(Shutdown::Write).unwrap();until(&mut session,Phase::Sending);
    session.io_cut=Some(IoCut::Zero);assert!(session.poll().is_err());let before=s.usage().unwrap();session.cancel();session.cancel();assert!(session.stream.is_none());assert_eq!(s.usage().unwrap(),before);
    assert!(s.lane.lock().unwrap().store.usage().unwrap().candidate>0);assert_eq!(before.0,0);assert_eq!(before.1,0);
}
#[test]
fn ag110_slot_limit_and_cancellation_preserve_other_session() {
    let(_t,s)=make_with(Config{slots:2,byte_limit:2*CHARGE,..config()});let(_a,mut a)=connect(&s);let(mut cb,mut b)=connect(&s);
    let(_c,c)=pair();assert!(matches!(s.attach(c),Err(TransportError::Capacity)));assert_eq!(s.usage().unwrap().0,2);
    let ingress=s.usage().unwrap().2;a.cancel();assert_eq!(s.usage().unwrap().2,ingress);assert_eq!(s.usage().unwrap().0,1);
    cb.write_all(&wire(req(Operation::Begin,0))).unwrap();cb.shutdown(Shutdown::Write).unwrap();assert!(!drain(&mut b,&mut cb).is_empty());assert_eq!(s.usage().unwrap().0,0);
}
#[test]
fn ag110_busy_lane_consumes_work_and_never_reads_socket() {
    let(_t,s)=make();let(mut c,mut session)=connect(&s);c.write_all(&wire(req(Operation::Begin,0))).unwrap();
    let work=s.work.load(Ordering::Relaxed);let lane=s.lane.lock().unwrap();assert!(!session.poll().unwrap());assert_eq!(session.received,0);
    assert!(matches!(s.update(|_|{}),Err(TransportError::Busy)));assert_eq!(s.work.load(Ordering::Relaxed),work-1);drop(lane);session.cancel();
}
#[test]
fn ag110_deadline_global_work_and_ingress_never_refill_on_reconnect() {
    let(_t,s)=make_with(Config{work:2,ingress:4265,..config()});let(_c,mut session)=connect(&s);assert!(!session.poll().unwrap());assert!(session.poll().is_err());
    let(_c,c)=pair();assert!(matches!(s.attach(c),Err(TransportError::Capacity)));assert_eq!(s.usage().unwrap().0,0);
    let(_t,s)=make_with(Config{ingress:4265,..config()});let(_c,mut session)=connect(&s);session.deadline=Instant::now();assert!(matches!(session.poll(),Err(TransportError::Deadline)));
    let(_c,c)=pair();assert!(matches!(s.attach(c),Err(TransportError::Capacity)));
}
#[test]
fn ag110_denied_binder_and_revoked_intake_do_not_touch_store() {
    let(t,s)=make();s.update(|p|p.deny=true).unwrap();let(_c,c)=pair();assert!(s.attach(c).is_err());assert_eq!(s.usage().unwrap().0,0);
    s.update(|p|p.deny=false).unwrap();let(mut c,mut session)=connect(&s);let head=fs::read(t.0.join("artifact.record")).unwrap();
    c.write_all(&wire(req(Operation::Begin,0))).unwrap();s.update(|p|p.deny=true).unwrap();assert!(session.poll().is_err());assert_eq!(session.received,0);
    assert_eq!(fs::read(t.0.join("artifact.record")).unwrap(),head);
}
#[test]
fn ag110_provider_panic_poison_prevents_redispatch_and_drop_refunds() {
    let(_t,s)=make();let(_c,mut session)=connect(&s);s.update(|p|p.panic_live=true).unwrap();
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||session.poll()));assert!(result.is_err());assert_eq!(session.phase,Phase::Closed);
    drop(session);assert!(s.lane.is_poisoned());let lane=s.lane.lock().unwrap_or_else(|e|e.into_inner());assert_eq!((lane.live,lane.bytes),(0,0));drop(lane);
    let(_c,c)=pair();assert!(matches!(s.attach(c),Err(TransportError::Poisoned)));
}
