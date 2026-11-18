//! GA110 acceptance: real linked CC2 output, guest typed IO and NIC DMA, then
//! actual localhost TCP and AS110 durable files. Identity/retention providers
//! below are explicit fixtures, not production credential implementations.
use super::*;
use crate::anka64::{authority_persistence::{self as ap,artifact::{self as store,transfer as at}},
    compiler_adapter::RebuildPublicationAuthority,cc2_fixed_point,
    dev_runner::{DeveloperExecutionAuthority,DeveloperInputAuthority,DevelopmentRunConfig},
    os::{ProcessResult,compiler_retry::{service::RebuildService,publication::{CompilerPublicationReceipt,
        consumer::{CompilerStoragePolicy,PersistentDependency,PersistentLinkIdentity,LinkedCompilerReceipt}}}}};
use at::transport as ag;
use std::{collections::BTreeSet,fs,io::{self,Read,Write},net::{TcpListener,TcpStream,Shutdown},
    path::PathBuf,sync::{Arc,Mutex,atomic::{AtomicU64,Ordering}},time::{Duration,Instant}};
const SOURCE:&[u8]=include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/bin/storage_upload.c"));
fn caller()->store::Caller{store::Caller{owner:30,incarnation:4}}
fn limits()->store::Limits{store::Limits{max_payload:2*1024*1024,window:4096,owner_bytes:4*1024*1024,
    total_bytes:8*1024*1024,other_bytes:4096,work:20000}}
fn config()->ag::Config{ag::Config{slots:1,byte_limit:ag::CHARGE,work:200000,ingress:4*1024*1024,timeout:Duration::from_secs(60)}}
fn selected()->store::Selection{store::Selection{revision:7,artifact:0,generation:0}}
struct Temp(PathBuf);
impl Temp{fn new()->Self{
    static ID:AtomicU64=AtomicU64::new(1);
    Self(std::env::temp_dir().join(format!("anka-ga110-{}-{}-{}",std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),ID.fetch_add(1,Ordering::Relaxed))))
}}
impl Drop for Temp{fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
struct Policy{manifest:Option<store::Manifest>}
impl CompilerStoragePolicy for Policy{
    fn bind_link(&mut self,_:&LinkedCompilerReceipt<'_>,c:store::Caller)->Result<PersistentLinkIdentity,ap::Error>{
        if c!=caller(){return Err(ap::Error::Authority)}
        Ok(PersistentLinkIdentity{anchor:10,installation:20,artifact:900,generation:3,image:901,metadata:902,dependencies:903,provenance:904})
    }
    fn bind_module(&mut self,r:&CompilerPublicationReceipt<'_>,b:&[u8],i:usize)->Result<PersistentDependency,ap::Error>{
        if i!=0 || r.length!=b.len()as u64{return Err(ap::Error::Authority)}
        Ok(PersistentDependency{anchor:10,installation:20,artifact:800,generation:2,provenance:804})
    }
    fn current_binding(&mut self,m:store::Manifest,d:&[PersistentDependency])->ap::Verdict{
        let expected=PersistentDependency{anchor:10,installation:20,artifact:800,generation:2,provenance:804};
        if d!=[expected] || m.artifact!=900 || self.manifest.is_some_and(|old|old!=m){return ap::Verdict::Invalid;}
        self.manifest=Some(m);ap::Verdict::Valid
    }
    fn authorize(&mut self,s:store::Scope)->ap::Verdict{
        if Some(s.manifest)==self.manifest && s.caller==caller(){ap::Verdict::Valid}else{ap::Verdict::Invalid}
    }
}
struct Proof{manifest:store::Manifest,payload:Arc<Vec<u8>>,channels:BTreeSet<u64>}
impl store::Evidence for Proof{
    fn authorize(&mut self,s:store::Scope)->ap::Verdict{
        if s.manifest==self.manifest && s.caller==caller(){ap::Verdict::Valid}else{ap::Verdict::Invalid}
    }
    fn inspect(&mut self,r:&mut dyn Read)->Result<store::Manifest,ap::Error>{
        let mut b=[0;4096];
        for expected in self.payload.chunks(4096){
            r.read_exact(&mut b[..expected.len()]).map_err(|_|ap::Error::CorruptRecord)?;
            if &b[..expected.len()]!=expected{return Err(ap::Error::CorruptRecord)}
        }
        if r.read(&mut b[..1]).map_err(|_|ap::Error::CorruptRecord)?!=0{return Err(ap::Error::CorruptRecord)}
        Ok(self.manifest)
    }
}
impl at::TransferEvidence for Proof{
    fn read_caller(&mut self,c:u64,r:&at::read::ReadRequest)->Result<store::Caller,ap::Error>{
        if self.channels.contains(&c) && r.manifest==self.manifest{Ok(caller())}else{Err(ap::Error::Authority)}
    }
    fn caller(&mut self,c:u64,r:&at::Request<'_>)->Result<store::Caller,ap::Error>{
        if self.channels.contains(&c) && r.manifest==self.manifest{Ok(caller())}else{Err(ap::Error::Authority)}
    }
}
impl ag::TransportEvidence for Proof{
    fn bind_stream(&mut self,s:&TcpStream,c:u64)->Result<(),ap::Error>{
        if s.peer_addr().is_err() || !self.channels.insert(c){Err(ap::Error::Authority)}else{Ok(())}
    }
    fn live_channel(&mut self,c:u64)->Result<(),ap::Error>{if self.channels.contains(&c){Ok(())}else{Err(ap::Error::Authority)}}
    fn retire_channel(&mut self,c:u64){self.channels.remove(&c);}
}
fn service(s:store::ArtifactStore,m:store::Manifest,payload:&Arc<Vec<u8>>)->ag::Service<Proof>{
    ag::Service::new(s,Proof{manifest:m,payload:payload.clone(),channels:BTreeSet::new()},config()).unwrap()
}
struct Server{expected:[u8;at::MAX_REQUEST],len:usize,bound:Arc<Mutex<Option<ap::protocol::client::Binding>>>}
impl ap::protocol::client::ServerVerifier for Server{
    fn verify_artifact(&mut self,b:ap::protocol::client::Binding,r:&[u8])->ap::Verdict{
        let mut bound=self.bound.lock().unwrap();
        if b.connection!=0 && b.local==LOCAL.addr() && b.remote==STORAGE.addr() && r==&self.expected[..self.len]
            && *bound.get_or_insert(b)==b {ap::Verdict::Valid}else{ap::Verdict::Invalid}
    }
}
struct ReplyCheck<'a>{frame:&'a[u8]}
impl at::ServerEvidence for ReplyCheck<'_>{
    fn current(&mut self,c:u64,r:&at::Request<'_>,_:&[u8])->ap::Verdict{
        // This fixture is bound to the actual TCP peer/session below. The guest
        // independently uses Server::verify_artifact at its receive boundary.
        let mut bytes=[0;at::MAX_REQUEST];
        if c==1 && at::encode(r,&mut bytes).is_ok_and(|n|&bytes[..n]==self.frame){ap::Verdict::Valid}else{ap::Verdict::Invalid}
    }
}
struct Peer<'a>{client:TcpStream,session:ag::Session<'a,Proof>,expected:Vec<u8>,used:usize,
    reply:[u8;at::MAX_REPLY],len:usize,sent:usize,seq:u32,ack:u32,started:bool,closing:bool,fin:bool,
    cap:usize,lose:bool,loss_injected:bool,outcome:Option<at::Outcome>}
impl<'a> Peer<'a>{
    fn new(s:&'a ag::Service<Proof>,expected:Vec<u8>,cap:usize,lose:bool)->Self{
        let l=TcpListener::bind("127.0.0.1:0").unwrap();let client=TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (stream,_)=l.accept().unwrap();client.set_nodelay(true).unwrap();client.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        let session=s.attach(stream).unwrap();
        Self{client,session,expected,used:0,reply:[0;at::MAX_REPLY],len:0,sent:0,seq:900,ack:0,
            started:false,closing:false,fin:false,cap,lose,loss_injected:false,outcome:None}
    }
    fn frame(&self,flags:u8,body:&[u8],out:&mut[u8;N])->usize{
        let b=make(STORAGE,LOCAL,Segment{seq:self.seq,ack:self.ack,flags,window:self.cap as u16,body});
        out[..b.len()].copy_from_slice(&b);b.len()
    }
    fn next(&mut self,out:&mut[u8;N])->usize{
        if self.sent<self.len{let n=(self.len-self.sent).min(self.cap);
            let size=self.frame(ACK|PSH,&self.reply[self.sent..self.sent+n],out);self.sent+=n;self.seq+=n as u32;size
        }else if !self.fin{let n=self.frame(ACK|FIN,&[],out);self.fin=true;self.seq+=1;n}else{0}
    }
    fn finish(&mut self)->Result<(),String>{
        self.client.shutdown(Shutdown::Write).map_err(err)?;self.client.set_nonblocking(true).map_err(err)?;
        let until=Instant::now()+Duration::from_secs(10);let mut done=false;let mut eof=false;
        while Instant::now()<until{
            if !done{done=self.session.poll().map_err(err)?;}
            // Read into a separate buffer, including when the expected reply is
            // full, so tail bytes and real EOF remain observable.
            let mut b=[0;512];match self.client.read(&mut b){
                Ok(0)=>{eof=true;break},Ok(n)=>{
                    if n>self.reply.len()-self.len{return Err("artifact reply tail".into())}
                    self.reply[self.len..self.len+n].copy_from_slice(&b[..n]);self.len+=n;
                },Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)=>{},Err(e)=>return Err(err(e)),
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        if !done || !eof{return Err("artifact TCP reply deadline".into())}
        let o=at::accept_reply(&self.expected,&self.reply[..self.len],true,1,&mut ReplyCheck{frame:&self.expected}).map_err(err)?;
        self.outcome=Some(o);
        if self.lose{
            if o.phase!=3{return Err("loss point requires durable publication".into())}
            self.loss_injected=true;return Err("injected reply loss AFTER durable artifact publication".into());
        }
        Ok(())
    }
}
impl SelectPeer for Peer<'_>{
    fn exchange(&mut self,frame:&[u8],out:&mut[u8;N])->Result<usize,String>{
        let s=parse(LOCAL,STORAGE,frame).ok_or("invalid guest frame")?;
        if !self.started{
            if s.flags!=SYN || !s.body.is_empty(){return Err("expected SYN".into())}
            self.ack=s.seq.wrapping_add(1);self.started=true;let n=self.frame(SYN|ACK,&[],out);self.seq+=1;return Ok(n);
        }
        if s.seq!=self.ack || s.ack!=self.seq{return Err("artifact TCP sequence mismatch".into())}
        if self.closing{return Ok(self.next(out))}
        if s.flags==ACK && s.body.is_empty(){return Ok(0)}
        if s.flags==(ACK|PSH){
            if self.expected.get(self.used..self.used+s.body.len())!=Some(s.body){return Err("guest changed request".into())}
            self.client.write_all(s.body).map_err(err)?;self.session.poll().map_err(err)?;
            self.used+=s.body.len();self.ack=self.ack.wrapping_add(s.body.len()as u32);
            return Ok(self.frame(ACK,&[],out));
        }
        if s.flags!=(ACK|FIN) || !s.body.is_empty() || self.used!=self.expected.len(){return Err("incomplete artifact request FIN".into())}
        self.finish()?;self.ack=self.ack.wrapping_add(1);self.closing=true;Ok(self.next(out))
    }
}
fn request<'a>(m:store::Manifest,op:at::Operation,ticket:u64,offset:u64,payload:&'a[u8],correlation:u64)->at::Request<'a>{
    let publish=matches!(op,at::Operation::Publish|at::Operation::Outcome);
    at::Request{operation:op,correlation,ticket,offset,payload,manifest:m,publish_request:if publish{91}else{0},expected:if publish{7}else{0}}
}
fn encode(r:at::Request<'_>)->Vec<u8>{let mut b=[0;at::MAX_REQUEST];let n=at::encode(&r,&mut b).unwrap();b[..n].to_vec()}

#[test]
fn ga110_guest_source_uses_supported_subset(){
    let s=std::str::from_utf8(SOURCE).unwrap();
    assert!(!s.contains("//") && !s.contains("/*") && !s.contains("&&"));
    assert!(!s.contains('>'),"this probe must express greater-than checks with reversed < operands; CC2 currently only recognizes >> after >");
    assert!(s.contains("int main()"));assert_eq!(s.matches("n!=(0-2)").count(),2);
    assert!(s.contains("read_bytes(") && s.contains("ssend(") && s.contains("srecv(") && s.contains("sshut()"));
}
// Exercise the same peer/real TCP/file bridge without a compiler bootstrap.
fn wire_exchange(s:&ag::Service<Proof>,r:at::Request<'_>,lose:bool)->at::Outcome{
    let frame=encode(r);let mut peer=Peer::new(s,frame.clone(),64,lose);let mut out=[0;N];let mut seq=10;
    let n=peer.exchange(&make(LOCAL,STORAGE,Segment{seq,ack:0,flags:SYN,window:64,body:&[]}),&mut out).unwrap();
    let mut ack=parse(STORAGE,LOCAL,&out[..n]).unwrap().seq+1;seq+=1;
    for b in frame.chunks(64){peer.exchange(&make(LOCAL,STORAGE,Segment{seq,ack,flags:ACK|PSH,window:64,body:b}),&mut out).unwrap();seq+=b.len()as u32;}
    assert!(peer.outcome.is_none());
    let result=peer.exchange(&make(LOCAL,STORAGE,Segment{seq,ack,flags:ACK|FIN,window:64,body:&[]}),&mut out);seq+=1;
    if lose{assert!(result.is_err());assert!(peer.loss_injected);}else{
        let mut n=result.unwrap();let mut bytes=Vec::new();let mut fin=false;
        while n!=0{let seg=parse(STORAGE,LOCAL,&out[..n]).unwrap();bytes.extend_from_slice(seg.body);fin|=seg.flags&FIN!=0;
            ack=seg.seq+seg.body.len()as u32+u32::from(seg.flags&FIN!=0);
            n=peer.exchange(&make(LOCAL,STORAGE,Segment{seq,ack,flags:ACK,window:64,body:&[]}),&mut out).unwrap();}
        assert!(fin);assert_eq!(at::accept_reply(&frame,&bytes,true,1,&mut ReplyCheck{frame:&frame}).unwrap(),peer.outcome.unwrap());
    }
    peer.outcome.unwrap()
}
#[test]
fn ga110_nic_peer_tcp_file_publish_loss_and_reopen_outcome(){
    let temp=Temp::new();let payload=Arc::new((0..5000).map(|i|i as u8).collect::<Vec<_>>());
    let m=store::Manifest{anchor:10,installation:20,artifact:900,generation:3,role:2,profile:1,size:5000,image:901,metadata:902,dependencies:903,provenance:904};
    let backend=store::ArtifactStore::create(&temp.0,10,20,1,limits(),selected()).unwrap();let s=service(backend,m,&payload);
    let ticket=wire_exchange(&s,request(m,at::Operation::Begin,0,0,&[],1),false).ticket;
    for(i,b)in payload.chunks(4096).enumerate(){assert_eq!(wire_exchange(&s,request(m,at::Operation::Append,ticket,(i*4096)as u64,b,2+i as u64),false).cursor,(i*4096+b.len())as u64);}
    wire_exchange(&s,request(m,at::Operation::Seal,ticket,0,&[],4),false);
    let before=wire_exchange(&s,request(m,at::Operation::Publish,ticket,0,&[],5),true);assert_eq!(before.revision,8);
    assert_eq!(s.usage().unwrap().0,0);drop(s);
    let backend=store::ArtifactStore::open(&temp.0,10,20,2,limits()).unwrap();let s=service(backend,m,&payload);
    assert_eq!(wire_exchange(&s,request(m,at::Operation::Outcome,0,0,&[],6),false),before);
    assert_eq!(fs::read(temp.0.join("artifact.bytes")).unwrap(),*payload);
}

#[test]
#[ignore="real CC2 artifact upload over virtual NIC, guarded TCP and durable file; run explicitly in release mode"]
fn ga110_real_cc2_artifact_upload(){
    ga110_guest_source_uses_supported_subset();
    let exec=DeveloperExecutionAuthority::provision();let auth=RebuildPublicationAuthority::provision();
    let net=DeveloperFrameAuthority::provision();let input=DeveloperInputAuthority::provision();
    let lineage=cc2_fixed_point::witness_cc2_fixed_point(Some(&exec),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let mut compiler=RebuildService::new(&lineage,&exec).unwrap();
    let target_source=format!("int main(){{int value=0;{}return value-54;}}","value=value+1;".repeat(96));
    let image_epoch=super::guest_tests::compile(&mut compiler,target_source.as_bytes(),&exec,&auth);
    let upload_epoch=super::guest_tests::compile(&mut compiler,SOURCE,&exec,&auth);
    // A separate CS110 reference export supplies the expected canonical bytes.
    // The target store below receives every byte through guest syscalls/NIC/TCP.
    let reference=Temp::new();let mut store=store::ArtifactStore::create(&reference.0,10,20,1,limits(),selected()).unwrap();
    let mut policy=Policy{manifest:None};
    compiler.kernel.persist_linked_compiler_publication(image_epoch,&mut store,caller(),91,7,&mut policy).unwrap();drop(store);
    let manifest=policy.manifest.unwrap();let payload=Arc::new(fs::read(reference.0.join("artifact.bytes")).unwrap());
    assert!(payload.len()>4096,"real compiler payload must cross an Append boundary");
    assert_eq!(manifest.size,payload.len()as u64);assert_eq!(&payload[..8],b"ANKACS01");
    let baseline=compiler.kernel.fabric.scoped_pointers.total_reserved_bytes();
    let temp=Temp::new();let backend=store::ArtifactStore::create(&temp.0,10,20,1,limits(),selected()).unwrap();
    let mut s=Some(service(backend,manifest,&payload));let mut ticket=0;let mut correlation=1;let mut old=None;
    let chunks=payload.len().div_ceil(4096);
    for step in 0..chunks+4{
        let (op,offset,bytes,lose)=if step==0{(at::Operation::Begin,0,&[][..],false)}
            else if step<=chunks{let start=(step-1)*4096;(at::Operation::Append,start as u64,&payload[start..(start+4096).min(payload.len())],false)}
            else if step==chunks+1{(at::Operation::Seal,0,&[][..],false)}
            else if step==chunks+2{(at::Operation::Publish,0,&[][..],true)}
            else{(at::Operation::Outcome,0,&[][..],false)};
        let frame=encode(request(manifest,op,if matches!(op,at::Operation::Begin|at::Operation::Outcome){0}else{ticket},offset,bytes,correlation));
        correlation+=1;
        let cap=if step%2==0{64}else{1024};
        let mut peer=Peer::new(s.as_ref().unwrap(),frame.clone(),cap,lose);
        let bound=Arc::new(Mutex::new(None));
        let mut expected=[0;at::MAX_REQUEST];expected[..frame.len()].copy_from_slice(&frame);
        let verifier:ServerLane=Arc::new(Mutex::new(Server{expected,len:frame.len(),bound:bound.clone()}));
        eprintln!("GA110 guest {:?}: request={} queue={cap}",op,frame.len());
        let result=compiler.kernel.run_linked_compiler_publication_with_select(upload_epoch,&exec,
            SelectStream{capacity:SocketCapacity::new(cap,cap).unwrap(),request:StorageRequest::Artifact(&frame,&input),verifier,authority:&net,peer:&mut peer},
            DevelopmentRunConfig::default());
        if lose{assert!(result.is_err(),"lost publication reply must not be success");}
        else{assert_eq!(result.as_ref().unwrap().execution().child_result,ProcessResult::Exited(0));}
        drop(result);assert_eq!(peer.loss_injected,lose,"did not reach intended durable reply-loss point");
        let out=peer.outcome.expect("guest never reached guarded artifact dispatch");ticket=out.ticket;
        if matches!(op,at::Operation::Publish|at::Operation::Outcome){assert_eq!((out.revision,out.artifact,out.generation),(8,900,3));}
        let connection=bound.lock().unwrap().expect("guest never checked server authority").connection;
        if let Some(previous)=old{assert_ne!(previous,connection);}old=Some(connection);
        drop(peer);assert_eq!(s.as_ref().unwrap().usage().unwrap().0,0);
        assert_eq!(compiler.kernel.fabric.scoped_pointers.total_reserved_bytes(),baseline);
        assert!(compiler.kernel.linked_compiler_receipt(image_epoch).is_ok());
        if lose{drop(s.take());let backend=store::ArtifactStore::open(&temp.0,10,20,2,limits()).unwrap();s=Some(service(backend,manifest,&payload));}
    }
    assert_eq!(fs::read(temp.0.join("artifact.bytes")).unwrap(),*payload);
    eprintln!("GA110: actual CC2 linked image -> guest malloc/read/ssend/sshut/srecv -> NIC DMA -> guarded TCP -> durable file; lost publish reply + reopened exact Outcome revision 8 passed");
}

mod download_tests;
