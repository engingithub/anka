//! Actual TCP/EOF/file tests. Evidence replies are explicitly private fixtures;
//! real RSA/mTLS coverage remains in test_adapter.py. Not real Keycloak acceptance.
use super::*;
use std::{fs, net::TcpListener, sync::{Arc,Mutex}, time::{Duration,Instant}};
#[derive(Clone)]
struct Manual(Arc<Mutex<Now>>);
impl Clock for Manual {fn now(&mut self)->Now{*self.0.lock().unwrap()}}
struct Actual {channel:Channel,local:std::net::SocketAddr,peer:std::net::SocketAddr,live:Arc<Mutex<bool>>}
impl Transport for Actual {
    fn current(&mut self,s:&TcpStream)->Option<Channel>{
        (*self.live.lock().unwrap() && s.local_addr().ok()==Some(self.local) &&
            s.peer_addr().ok()==Some(self.peer)).then_some(self.channel)
    }
}
fn manifest()->store::Manifest{store::Manifest{anchor:10,installation:20,artifact:40,generation:2,
    role:2,profile:1,size:128,image:101,metadata:102,dependencies:103,provenance:104}}
fn request()->ReadRequest{ReadRequest{manifest:manifest(),correlation:50,offset:17,count:73}}
fn caller()->store::Caller{store::Caller{owner:30,incarnation:5}}
fn config()->Config {
    let scope=Scope{installation:20,policy:3,peer:30,kind:1,artifact:40,generation:2,request:50,
        operation:1,role:1,runtime:6,connection:7,binding:8,local:9,incarnation:5,serial:10,challenge:11};
    Config{domain:500,incarnation:5,grant_id:600,work:128,deadline:200,boot:9,
        identity:Configuration{issuer:10,audience:21,client:22,installation:20,policy:3,keyset:4,
            profile:1,max_age:5,max_bytes:16384,selected:Verdict::Valid},scope,
        grant:Grant{token:101,scope,first:95,until:145,permission:Verdict::Valid}}
}
fn profile()->Profile{Profile{config_path:PathBuf::from("/no/private/test/config"),token:b"a.b.c".to_vec(),
    issuer:"https://issuer/realms/r".into(),audience:"aud".into(),client:"client".into(),subject:"subject".into(),
    holder:[3;32],subject_id:31,holder_id:32,max_age:5}}
fn registration()->Registration{Registration{domain:500,grant_id:600,request:request(),caller:caller(),boot:9,ticket:1}}
type Bridge=ReadBridge<Manual,Actual>;
fn rig()->(Bridge,TcpStream,Manual,Arc<Mutex<bool>>){
    let clock=Manual(Arc::new(Mutex::new(Now{wall:100,tick:100})));
    let mut adapter=Adapter::new(config(),profile(),clock.clone()).unwrap();
    let q=adapter.owner.begin_query().unwrap();
    assert_eq!(adapter.complete_refresh(q,Ok(codec::Reply{outcome:1,times:[90,95,150],binding:[4;32]})),Ok(Refresh::Issued));
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();
    let peer=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (stream,_)=listener.accept().unwrap();
    let channel=Channel::from_authenticated_transport(30,config().scope,[3;32],[9;32]).unwrap();
    let live=Arc::new(Mutex::new(true));
    let transport=Actual{channel,local:stream.local_addr().unwrap(),peer:stream.peer_addr().unwrap(),live:live.clone()};
    (ReadBridge::new(adapter,stream,transport,registration()).unwrap(),peer,clock,live)
}
fn prepared<T:Transport>(b:&mut ReadBridge<Manual,T>)->PreparedUse{
    let challenge=b.prepare().unwrap();
    PreparedUse{channel:b.channel,proposal:challenge.proposal,reply:Some(codec::Reply{outcome:1,times:[0;3],binding:[4;32]})}
}
struct Content {bytes:Vec<u8>,inspections:usize,allow:bool}
impl store::Evidence for Content {
    fn authorize(&mut self,s:store::Scope)->Verdict{
        if self.allow && s.manifest==manifest() && s.caller==caller(){Verdict::Valid}else{Verdict::Invalid}
    }
    fn inspect(&mut self,r:&mut dyn Read)->Result<store::Manifest,ap::Error>{
        self.inspections+=1;let mut bytes=Vec::new();r.take(129).read_to_end(&mut bytes).map_err(|_|ap::Error::CorruptRecord)?;
        if bytes!=self.bytes{return Err(ap::Error::CorruptRecord)}Ok(manifest())
    }
}
struct Temp(PathBuf);
impl Drop for Temp{fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn file()->(Temp,store::ArtifactStore,Content,transfer::Budget){
    let path=std::env::temp_dir().join(format!("anka-lt110-{}-{}",std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    let t=Temp(path);let limits=store::Limits{max_payload:4096,window:4096,owner_bytes:65536,total_bytes:131072,other_bytes:0,work:100};
    let mut s=store::ArtifactStore::create(&t.0,10,20,9,limits,store::Selection{revision:7,artifact:0,generation:0}).unwrap();
    let mut content=Content{bytes:(0..128).collect(),inspections:0,allow:true};
    let ticket=s.reserve(manifest(),caller(),&mut content).unwrap();let bytes=content.bytes.clone();
    s.append(ticket,0,&bytes,&mut content).unwrap();s.seal(ticket,&mut content).unwrap();s.publish(ticket,91,7,&mut content).unwrap();
    drop(s);let s=store::ArtifactStore::open(&t.0,10,20,9,limits).unwrap();content.inspections=0;
    (t,s,content,transfer::Budget::new(100,10000,32768).unwrap())
}
// Readiness is a test-driver obligation, not an authority grant or EOF.
// A nonblocking intake may legally make zero progress. Wait outside the owner
// guard, then prepare a fresh proof for the actual read. Never refill work.
pub(super) fn readable(stream:&TcpStream) {
    use std::os::fd::AsRawFd;
    let deadline=Instant::now()+Duration::from_secs(2);
    loop {
        let remaining=deadline.checked_duration_since(Instant::now()).expect("fixture readiness deadline");
        let mut fd=libc::pollfd{fd:stream.as_raw_fd(),events:libc::POLLIN,revents:0};
        let timeout=remaining.as_millis().max(1).min(i32::MAX as u128)as i32;
        let ready=unsafe{libc::poll(&mut fd,1,timeout)};
        if ready<0 && io::Error::last_os_error().kind()==io::ErrorKind::Interrupted {continue}
        assert!(ready>0,"fixture socket not readable before deadline");
        assert_eq!(fd.revents&(libc::POLLERR|libc::POLLNVAL),0,"fixture socket error");
        assert_ne!(fd.revents&(libc::POLLIN|libc::POLLHUP),0,"unexpected readiness event");
        return;
    }
}
fn intake(b:&mut Bridge,p:&mut TcpStream,frame:&[u8]){
    p.write_all(frame).unwrap();p.shutdown(Shutdown::Write).unwrap();
    for _ in 0..16{
        readable(b.stream.as_ref().unwrap());
        let proof=prepared(b);if b.intake(proof).unwrap(){return}
    }
    panic!("actual EOF not observed");
}
#[test] fn lt110_actual_tcp_file_exact_reply_and_unchanged_ledger(){
    let(mut b,mut peer,_,_)=rig();let(t,mut store,mut content,mut budget)=file();
    let before=fs::read(t.0.join("artifact.record")).unwrap();let frame=read::encode_read(request()).unwrap();
    intake(&mut b,&mut peer,&frame);let p=prepared(&mut b);
    let mut reply=b.dispatch(p,&mut store,&frame,true,&mut budget,&mut content).unwrap();
    assert_eq!(content.inspections,1);let mut done=false;
    for _ in 0..16{let p=prepared(&mut b);if b.write(p,&mut reply,&store,&mut content).unwrap(){done=true;break}}
    assert!(done);assert!(b.stream.is_none());let mut raw=Vec::new();peer.read_to_end(&mut raw).unwrap();
    assert_eq!(&raw[32..200],&frame);assert_eq!(&raw[200..],&content.bytes[17..90]);
    assert_eq!(fs::read(t.0.join("artifact.record")).unwrap(),before);
}
#[test] fn lt110_no_socket_eof_means_no_backend_inspection(){
    let(mut b,mut peer,_,_)=rig();let(_t,mut store,mut content,mut budget)=file();
    let frame=read::encode_read(request()).unwrap();peer.write_all(&frame).unwrap();
    while b.received<frame.len(){
        readable(b.stream.as_ref().unwrap());
        let p=prepared(&mut b);assert!(!b.intake(p).unwrap());
    }
    let p=prepared(&mut b);assert!(b.dispatch(p,&mut store,&frame,true,&mut budget,&mut content).is_err());
    assert_eq!(content.inspections,0);
}
#[test] fn lt110_local_revocation_suppresses_unsent_suffix(){
    let(mut b,mut peer,_,_)=rig();let(_t,mut store,mut content,mut budget)=file();
    let frame=read::encode_read(request()).unwrap();intake(&mut b,&mut peer,&frame);
    let p=prepared(&mut b);let mut reply=b.dispatch(p,&mut store,&frame,true,&mut budget,&mut content).unwrap();
    let p=prepared(&mut b);assert!(!b.write(p,&mut reply,&store,&mut content).unwrap());
    let p=prepared(&mut b);b.revoker().revoke().unwrap();assert!(b.write(p,&mut reply,&store,&mut content).is_err());
    assert!(b.stream.is_none(),"denial must release the actual socket before bridge drop");
    let mut raw=Vec::new();peer.read_to_end(&mut raw).unwrap();assert_eq!(raw.len(),64);
}
#[test] fn lt110_changed_channel_or_expired_observation_prevents_intake(){
    for change in 0..3{let(mut b,mut peer,clock,live)=rig();peer.write_all(b"secret").unwrap();let p=prepared(&mut b);
        match change{0=>*live.lock().unwrap()=false,1=>clock.0.lock().unwrap().tick=105,_=>clock.0.lock().unwrap().wall=145}
        assert!(b.intake(p).is_err());assert_eq!(b.received,0);assert_eq!(b.view().unwrap().effects,0);}
}
#[test] fn lt110_private_prepared_proof_cannot_cross_owners_or_repeat(){
    let(mut a,_peer_a,_,_)=rig();let(mut b,_peer_b,_,_)=rig();let p=prepared(&mut a);
    assert!(b.intake(p).is_err());assert_eq!(b.received,0);
    let p=prepared(&mut a);let proposal=p.proposal;let channel=p.channel;
    a.intake(p).unwrap();let replay=PreparedUse{proposal,channel,reply:Some(codec::Reply{outcome:1,times:[0;3],binding:[4;32]})};
    assert!(a.intake(replay).is_err());
}
#[test] fn lt110_registration_is_explicit_and_full_range_bound(){
    let c=config();assert!(registration().matches(c));
    for which in 0..9{let mut r=registration();match which{
        0=>r.domain+=1,1=>r.grant_id+=1,2=>r.boot+=1,3=>r.caller.owner+=1,4=>r.caller.incarnation+=1,
        5=>r.request.correlation+=1,6=>r.request.manifest.artifact+=1,7=>r.request.manifest.generation+=1,_=>r.ticket=0}
        assert!(!r.matches(c));}
    let(mut b,mut peer,_,_)=rig();let(_t,mut store,mut content,mut budget)=file();
    let changed=ReadRequest{offset:18,..request()};let frame=read::encode_read(changed).unwrap();
    intake(&mut b,&mut peer,&frame);let p=prepared(&mut b);
    assert!(b.dispatch(p,&mut store,&frame,true,&mut budget,&mut content).is_err());assert_eq!(content.inspections,0);
}
#[test] fn lt110_read_projection_cannot_authorize_upload_or_skip_content_policy(){
    let mut c=Content{bytes:vec![],inspections:0,allow:true};
    let mut p=ReadProjection{registration:registration(),channel:7,content:&mut c};
    let scope=store::Scope{manifest:manifest(),caller:caller(),boot:9,ticket:1,action:store::Action::Read};
    assert_eq!(store::Evidence::authorize(&mut p,scope),Verdict::Valid);
    for action in [store::Action::Upload,store::Action::Publish,store::Action::Retire]{
        assert_eq!(store::Evidence::authorize(&mut p,store::Scope{action,..scope}),Verdict::Invalid);}
    p.content.allow=false;assert_eq!(store::Evidence::authorize(&mut p,scope),Verdict::Invalid);
}
#[test] fn lt110_bad_content_is_terminal_and_emits_no_reply(){
    let(mut b,mut peer,_,_)=rig();let(_t,mut store,mut content,mut budget)=file();
    let frame=read::encode_read(request()).unwrap();intake(&mut b,&mut peer,&frame);content.bytes[17]^=1;
    let p=prepared(&mut b);assert!(b.dispatch(p,&mut store,&frame,true,&mut budget,&mut content).is_err());
    let mut raw=Vec::new();peer.read_to_end(&mut raw).unwrap();assert!(raw.is_empty());
    assert_eq!(b.view().unwrap().mode,Mode::Poisoned);
    assert!(b.stream.is_none());b.close();assert!(b.stream.is_none());
    assert!(matches!(b.prepare(),Err(BridgeError::Closed)));
}

/// Only compiled into test builds. Real guest/file witness uses explicit trusted
/// evidence fixtures; this is NOT an authenticated deployment transport producer.
pub(crate) struct GuestFixture { bridge:ReadBridge<Manual,HostedTransport>, client:HostedClient, clock:Manual }
impl GuestFixture {
    pub(crate) fn new(request:ReadRequest,caller:store::Caller,boot:u64,ticket:u64)->Self {
        let clock=Manual(Arc::new(Mutex::new(Now{wall:100,tick:100})));
        let mut c=config();c.boot=boot;c.incarnation=caller.incarnation;
        c.scope.peer=caller.owner;c.scope.incarnation=caller.incarnation;c.scope.artifact=request.manifest.artifact;
        c.scope.generation=request.manifest.generation;c.scope.installation=request.manifest.installation;
        c.scope.request=request.correlation;c.grant.scope=c.scope;
        let mut a=Adapter::new(c,profile(),clock.clone()).unwrap();let q=a.owner.begin_query().unwrap();
        a.complete_refresh(q,Ok(codec::Reply{outcome:1,times:[90,95,150],binding:[4;32]})).unwrap();
        let r=Registration{domain:c.domain,grant_id:c.grant_id,request,caller,boot,ticket};
        let(bridge,client)=ReadBridge::hosted(a,r).unwrap();
        client.0.set_nonblocking(false).unwrap();client.0.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        Self{bridge,client,clock}
    }
    pub(crate) fn push(&mut self,bytes:&[u8])->Result<(),String>{
        self.client.write_all(bytes).map_err(|_|"fixture write".to_string())?;
        readable(self.bridge.stream.as_ref().unwrap());
        let p=prepared(&mut self.bridge);self.bridge.intake(p).map_err(|e|format!("{e:?}"))?;Ok(())
    }
    /// Faults are applied AFTER proof preparation to exercise the final guard.
    pub(crate) fn finish(&mut self,backend:&mut store::ArtifactStore,content:&mut impl store::Evidence,
        fault:u8)->Result<Vec<u8>,String>{
        self.client.finish_request().map_err(|_|"fixture FIN".to_string())?;
        for _ in 0..16{
            readable(self.bridge.stream.as_ref().unwrap());
            let p=prepared(&mut self.bridge);if self.bridge.intake(p).map_err(|e|format!("{e:?}"))?{break}
        }
        let p=prepared(&mut self.bridge);
        match fault {1=>self.bridge.revoker().revoke().unwrap(),2=>self.clock.0.lock().unwrap().tick=105,
            3=>self.bridge.transport.channel.binding[0]^=1,_=>{}}
        let frame=read::encode_read(self.bridge.registration.request).unwrap();
        let mut budget=transfer::Budget::new(128,10000,32768).unwrap();
        let mut reply=self.bridge.dispatch(p,backend,&frame,true,&mut budget,content).map_err(|e|format!("{e:?}"))?;
        let mut done=false;
        for _ in 0..80{let p=prepared(&mut self.bridge);if self.bridge.write(p,&mut reply,backend,content).map_err(|e|format!("{e:?}"))?{done=true;break}}
        if !done{return Err("fixture reply budget".into())}
        let mut bytes=Vec::new();self.client.read_to_end(&mut bytes).map_err(|_|"fixture reply".to_string())?;Ok(bytes)
    }
}

#[test] fn lt110_outage_does_not_refresh_age_and_verified_negative_closes(){
    for inactive in [false,true]{
        let(mut b,mut peer,clock,_)=rig();peer.write_all(b"x").unwrap();
        let q=b.adapter.owner.begin_query().unwrap();
        let reply=if inactive{Ok(codec::Reply{outcome:2,times:[90,95,150],binding:[4;32]})}else{Err(())};
        assert_eq!(b.adapter.complete_refresh(q,reply).unwrap(),if inactive{Refresh::Revoked}else{Refresh::Unavailable});
        if !inactive{
            readable(b.stream.as_ref().unwrap());
            let p=prepared(&mut b);b.intake(p).unwrap();let p=prepared(&mut b);
            clock.0.lock().unwrap().tick=105;assert!(b.intake(p).is_err());assert_eq!(b.received,1);
        }else{assert!(b.prepare().is_err());assert_eq!(b.received,0);}
    }
}

#[test] fn lt110_hosted_pair_rejects_a_different_actual_stream(){
    let clock=Manual(Arc::new(Mutex::new(Now{wall:100,tick:100})));
    let a=Adapter::new(config(),profile(),clock).unwrap();
    let(mut bridge,_client)=ReadBridge::hosted(a,registration()).unwrap();
    assert_eq!(bridge.transport.current(bridge.stream.as_ref().unwrap()),Some(bridge.channel));
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();
    let _other=TcpStream::connect(listener.local_addr().unwrap()).unwrap();let(stream,_)=listener.accept().unwrap();
    assert!(bridge.transport.current(&stream).is_none());
    assert_ne!(bridge.channel.binding,[0;32]);
}

#[test] fn lt110_independent_read_revocation_also_suppresses_suffix(){
    let(mut b,mut peer,_,_)=rig();let(_t,mut store,mut content,mut budget)=file();
    let frame=read::encode_read(request()).unwrap();intake(&mut b,&mut peer,&frame);
    let p=prepared(&mut b);let mut reply=b.dispatch(p,&mut store,&frame,true,&mut budget,&mut content).unwrap();
    let p=prepared(&mut b);assert!(!b.write(p,&mut reply,&store,&mut content).unwrap());
    let p=prepared(&mut b);content.allow=false;
    assert!(b.write(p,&mut reply,&store,&mut content).is_err());
    assert!(b.stream.is_none(),"denial must release the actual socket before bridge drop");
    let mut raw=Vec::new();peer.read_to_end(&mut raw).unwrap();assert_eq!(raw.len(),64);
}
