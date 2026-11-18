use super::*;
use super::super::read::{self,client::ReadClient};
use super::super::read::tests::{fixture,request,Proof,Server,Temp};
use std::{net::TcpListener,thread};
impl TransportEvidence for Proof {
    // Test binder only: production must validate the actual stream's identity.
    fn bind_stream(&mut self,s:&TcpStream,c:u64)->Result<(),Error> {
        if s.peer_addr().is_err() || !self.channels.insert(c){return Err(Error::Authority)}Ok(())
    }
    fn live_channel(&mut self,c:u64)->Result<(),Error> {if self.channels.contains(&c){Ok(())}else{Err(Error::Authority)}}
    fn retire_channel(&mut self,c:u64){self.channels.remove(&c);}
}
fn service()->(Temp,Service<Proof>) {
    let(t,s,p,_)=fixture();let cfg=Config{slots:2,byte_limit:2*CHARGE,work:100000,ingress:426500,timeout:Duration::from_secs(5)};
    (t,Service::new(s,p,cfg).unwrap())
}
fn connect(s:&Service<Proof>)->(TcpStream,Session<'_,Proof>) {
    let l=TcpListener::bind("127.0.0.1:0").unwrap();let c=TcpStream::connect(l.local_addr().unwrap()).unwrap();let(server,_)=l.accept().unwrap();
    c.set_nodelay(true).unwrap();(c,s.attach(server).unwrap())
}
fn until(session:&mut Session<'_,Proof>,phase:Phase) {
    let deadline=Instant::now()+Duration::from_secs(3);
    while Instant::now()<deadline {if session.phase==phase{return}assert!(!session.poll().unwrap());thread::sleep(Duration::from_micros(100));}
    panic!("bounded read phase wait: {:?}",session.phase);
}
fn send(c:&mut TcpStream,session:&mut Session<'_,Proof>,frame:&[u8]) {
    for x in frame.chunks(19){c.write_all(x).unwrap();session.poll().unwrap();}c.shutdown(Shutdown::Write).unwrap();
}
fn drain(c:&mut TcpStream,session:&mut Session<'_,Proof>)->Vec<u8> {
    c.set_nonblocking(true).unwrap();let deadline=Instant::now()+Duration::from_secs(3);let mut out=Vec::new();let mut b=[0;31];let mut done=false;
    while Instant::now()<deadline {
        if !done {done=match session.poll(){Ok(x)=>x,Err(_)=>true};}
        match c.read(&mut b){Ok(0)=>return out,Ok(n)=>out.extend_from_slice(&b[..n]),Err(e) if transient(&e)=>{},
            Err(e) if done && e.kind()==io::ErrorKind::ConnectionReset=>return out,Err(e)=>panic!("read client IO: {e}")}
        thread::sleep(Duration::from_micros(100));
    }panic!("bounded read response wait");
}
fn client_frame(plan:&mut ReadClient,channel:u64,e:&mut Server)->Vec<u8> {
    let mut b=Vec::new();for off in (0..HEADER).step_by(23){b.extend_from_slice(plan.request_fragment(channel,off,(HEADER-off).min(23),e).unwrap());}b
}
fn consume(plan:&mut ReadClient,channel:u64,reply:&[u8],e:&mut Server) {
    for b in reply.chunks(31){assert!(!plan.receive(channel,b,false,e).unwrap());}assert!(plan.receive(channel,&[],true,e).unwrap());
}
#[test]
fn ar110_tcp_read_actual_file_fragmentation_fin_and_client_validation() {
    let(t,s)=service();let head=fs::read(t.0.join(HEAD)).unwrap();let(mut c,mut sess)=connect(&s);let channel=sess.channel;
    let mut plan=ReadClient::new(request(),1000,Duration::from_secs(10),CHARGE).unwrap();let mut e=Server{valid:true};plan.begin(channel,&mut e).unwrap();
    let frame=client_frame(&mut plan,channel,&mut e);send(&mut c,&mut sess,&frame);let reply=drain(&mut c,&mut sess);consume(&mut plan,channel,&reply,&mut e);
    assert_eq!(plan.payload(&mut e).unwrap(),&(4096..8192).map(|n|n as u8).collect::<Vec<_>>());
    assert_eq!(fs::read(t.0.join(HEAD)).unwrap(),head);assert_eq!(s.usage().unwrap().0,0);assert_eq!(s.usage().unwrap().1,0);
}
#[test]
fn ar110_tcp_no_request_eof_no_backend_inspection_and_bad_tail_rejects() {
    let(_t,s)=service();let(mut c,mut sess)=connect(&s);let frame=read::encode_read(request()).unwrap();c.write_all(&frame).unwrap();
    for _ in 0..12 {sess.poll().unwrap();}assert_eq!(sess.phase,Phase::Reading);assert_eq!(s.lane.lock().unwrap().proof.inspections,0);
    c.write_all(&[0]).unwrap();c.shutdown(Shutdown::Write).unwrap();assert!(drain(&mut c,&mut sess).is_empty());assert_eq!(s.lane.lock().unwrap().proof.inspections,0);
}
#[test]
fn ar110_tcp_read_revocation_suppresses_suffix_without_mutation() {
    let(t,s)=service();let head=fs::read(t.0.join(HEAD)).unwrap();let(mut c,mut sess)=connect(&s);
    send(&mut c,&mut sess,&read::encode_read(request()).unwrap());until(&mut sess,Phase::Sending);sess.poll().unwrap();let sent=sess.sent;assert!(sent>0 && sent<=64);
    s.update(|p|p.read=false).unwrap();assert_eq!(drain(&mut c,&mut sess).len(),sent);assert_eq!(fs::read(t.0.join(HEAD)).unwrap(),head);assert_eq!(s.usage().unwrap().1,0);
}
#[test]
fn ar110_tcp_changed_caller_and_denied_read_emit_no_response() {
    let(_t,s)=service();let(mut c,mut sess)=connect(&s);send(&mut c,&mut sess,&read::encode_read(request()).unwrap());until(&mut sess,Phase::Sending);
    s.update(|p|p.owner.incarnation+=1).unwrap();assert!(drain(&mut c,&mut sess).is_empty());
    s.update(|p|{p.owner=read::tests::caller();p.read=false;}).unwrap();let inspected=s.lane.lock().unwrap().proof.inspections;
    let(mut c,mut sess)=connect(&s);send(&mut c,&mut sess,&read::encode_read(request()).unwrap());assert!(drain(&mut c,&mut sess).is_empty());assert_eq!(s.lane.lock().unwrap().proof.inspections,inspected);
}
#[test]
fn ar110_tcp_retry_new_stream_keeps_client_budget_and_exact_range() {
    let(t,s)=service();let head=fs::read(t.0.join(HEAD)).unwrap();let mut e=Server{valid:true};let mut plan=ReadClient::new(request(),2000,Duration::from_secs(10),CHARGE).unwrap();
    let(mut c,mut sess)=connect(&s);let first=sess.channel;plan.begin(first,&mut e).unwrap();send(&mut c,&mut sess,&client_frame(&mut plan,first,&mut e));until(&mut sess,Phase::Sending);
    sess.poll().unwrap();sess.cancel();drop(c);drop(sess);let before=plan.remaining();
    let(mut c,mut sess)=connect(&s);let second=sess.channel;assert_ne!(first,second);plan.retry(second,&mut e).unwrap();assert_eq!(plan.remaining(),before-1);
    send(&mut c,&mut sess,&client_frame(&mut plan,second,&mut e));let reply=drain(&mut c,&mut sess);consume(&mut plan,second,&reply,&mut e);assert_eq!(plan.payload(&mut e).unwrap().len(),4096);
    assert_eq!(fs::read(t.0.join(HEAD)).unwrap(),head);assert_eq!(s.usage().unwrap().1,0);
}
#[test]
fn ar110_tcp_short_transient_writes_preserve_prefix_and_spend_work() {
    let(_t,s)=service();let(mut c,mut sess)=connect(&s);let frame=read::encode_read(request()).unwrap();send(&mut c,&mut sess,&frame);until(&mut sess,Phase::Sending);let before=s.usage().unwrap().3;
    for cut in [IoCut::Blocked,IoCut::Interrupted]{sess.io_cut=Some(cut);assert!(!sess.poll().unwrap());assert_eq!(sess.sent,0);}
    assert_eq!(s.usage().unwrap().3,before-2);let channel=sess.channel;let reply=drain(&mut c,&mut sess);assert_eq!(read::accept_read_reply(&frame,&reply,true,channel,&mut Server{valid:true}).unwrap().len(),4096);
}
#[test]
fn ar110_tcp_deadline_closes_owned_slot_without_disclosure() {
    let(_t,s)=service();let(mut c,mut sess)=connect(&s);send(&mut c,&mut sess,&read::encode_read(request()).unwrap());until(&mut sess,Phase::Sending);
    sess.deadline=Instant::now();assert!(matches!(sess.poll(),Err(TransportError::Deadline)));assert_eq!(s.usage().unwrap().1,0);assert!(sess.stream.is_none());
}
#[test]
fn ar110_tcp_cancelled_peer_refunds_only_its_slot() {
    let(_t,s)=service();let(ca,mut a)=connect(&s);let(mut cb,mut b)=connect(&s);assert_eq!(s.usage().unwrap().1,2*CHARGE);
    a.cancel();drop(ca);assert_eq!(s.usage().unwrap().1,CHARGE);let frame=read::encode_read(request()).unwrap();let channel=b.channel;
    send(&mut cb,&mut b,&frame);let bytes=drain(&mut cb,&mut b);assert!(read::accept_read_reply(&frame,&bytes,true,channel,&mut Server{valid:true}).is_ok());assert_eq!(s.usage().unwrap().1,0);
}
