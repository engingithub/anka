//! GD110 witnesses use the real guest pump, virtual NIC DMA and localhost TCP
//! service over an actual reopened immutable file. Providers are test fixtures.
use super::*;
use at::read::{self,ReadRequest};
use crate::anka64::authority_persistence::{artifact::retrieval::{StoredEnvelope,RetrievalLimits},protocol::client::{Binding,ServerVerifier}};
use crate::anka64::os::compiler_retry::publication::consumer::{DownloadConfig,DownloadConnection,DownloadTransport};
const DOWNLOAD:&[u8]=include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/bin/storage_download.c"));
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Fault{None,LostPrefix,CorruptPayload,Tail,NoFin}
struct ReadPeer<'a>{inner:Peer<'a>,fault:Fault,loss:bool}
impl ReadPeer<'_>{
    fn finish(&mut self)->Result<(),String>{
        let p=&mut self.inner;
        p.client.shutdown(Shutdown::Write).map_err(err)?;p.client.set_nonblocking(true).map_err(err)?;
        let until=Instant::now()+Duration::from_secs(10);let mut done=false;let mut eof=false;
        while Instant::now()<until{
            if !done{done=p.session.poll().map_err(err)?;}
            let mut b=[0;512];match p.client.read(&mut b){
                Ok(0)=>{eof=true;break},Ok(n)=>{
                    if n>p.reply.len()-p.len{return Err("read reply tail".into())}
                    p.reply[p.len..p.len+n].copy_from_slice(&b[..n]);p.len+=n;
                },Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)=>{},Err(e)=>return Err(err(e)),
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        if !done || !eof{return Err("read TCP deadline".into())}
        if self.fault==Fault::CorruptPayload{p.reply[p.len-1]^=1;}
        if self.fault==Fault::Tail{p.reply[p.len]=0;p.len+=1;}
        Ok(())
    }
    fn next(&mut self,out:&mut[u8;N])->Result<usize,String>{
        if self.fault==Fault::LostPrefix && self.inner.sent>=64{self.loss=true;return Err("injected lost reply AFTER 64-byte prefix, BEFORE FIN".into())}
        if self.fault==Fault::NoFin && self.inner.sent==self.inner.len{return Ok(0)}
        Ok(self.inner.next(out))
    }
}
impl SelectPeer for ReadPeer<'_>{
    fn exchange(&mut self,frame:&[u8],out:&mut[u8;N])->Result<usize,String>{
        let s=parse(LOCAL,STORAGE,frame).ok_or("invalid download frame")?;
        let p=&mut self.inner;
        if !p.started{
            if s.flags!=SYN || !s.body.is_empty(){return Err("expected SYN".into())}
            p.ack=s.seq.wrapping_add(1);p.started=true;let n=p.frame(SYN|ACK,&[],out);p.seq+=1;return Ok(n)
        }
        if s.seq!=p.ack || s.ack!=p.seq{return Err("read TCP sequence mismatch".into())}
        if p.closing{return self.next(out)}
        if s.flags==ACK && s.body.is_empty(){return Ok(0)}
        if s.flags==(ACK|PSH){
            if p.expected.get(p.used..p.used+s.body.len())!=Some(s.body){return Err("guest changed read request".into())}
            p.client.write_all(s.body).map_err(err)?;p.session.poll().map_err(err)?;
            p.used+=s.body.len();p.ack=p.ack.wrapping_add(s.body.len()as u32);return Ok(p.frame(ACK,&[],out))
        }
        if s.flags!=(ACK|FIN) || !s.body.is_empty() || p.used!=168{return Err("incomplete read FIN".into())}
        self.finish()?;let p=&mut self.inner;p.ack+=1;p.closing=true;self.next(out)
    }
}
impl Drop for ReadPeer<'_>{fn drop(&mut self){self.inner.reply.fill(0);}}
struct Factory<'a>{service:&'a ag::Service<Proof>,attempts:Vec<ReadRequest>,fault:Fault}
impl DownloadTransport for Factory<'_>{
    fn connect(&mut self,r:ReadRequest)->Result<DownloadConnection<'_>,String>{
        let index=self.attempts.len();self.attempts.push(r);
        let cap=if index%2==0{64}else{1024};
        let fault=if self.fault==Fault::LostPrefix && index!=0{Fault::None}else{self.fault};
        let inner=Peer::new(self.service,read::encode_read(r).unwrap().to_vec(),cap,false);
        Ok(DownloadConnection{capacity:SocketCapacity::new(cap,cap).unwrap(),peer:Box::new(ReadPeer{inner,fault,loss:false})})
    }
}
struct ReadPolicy{m:store::Manifest,bytes:Arc<Vec<u8>>,bindings:std::collections::BTreeMap<u64,(Binding,ReadRequest)>,
    deny_from:Option<u64>,dependencies:bool,panic_check:bool,panic_final:bool}
impl ReadPolicy{fn new(m:store::Manifest,bytes:Arc<Vec<u8>>)->Self{Self{m,bytes,bindings:Default::default(),deny_from:None,dependencies:true,panic_check:false,panic_final:false}}}
impl ServerVerifier for ReadPolicy{
    fn verify_read(&mut self,b:Binding,r:ReadRequest)->ap::Verdict{
        if self.panic_check{panic!("injected GD110 read provider unwind")}
        if b.connection==0 || b.local!=LOCAL.addr() || b.remote!=STORAGE.addr() || r.manifest!=self.m
            || self.deny_from.is_some_and(|off|r.offset>=off){return ap::Verdict::Invalid}
        if *self.bindings.entry(b.connection).or_insert((b,r))!=(b,r){return ap::Verdict::Invalid}ap::Verdict::Valid
    }
    fn verify_read_reply(&mut self,b:Binding,r:ReadRequest,reply:&[u8])->ap::Verdict{
        if self.verify_read(b,r)!=ap::Verdict::Valid{return ap::Verdict::Invalid}
        let expected=self.bytes.get(r.offset as usize..(r.offset+r.count)as usize);
        if reply.get(200..)==expected{ap::Verdict::Valid}else{ap::Verdict::Invalid}
    }
    fn verify_download(&mut self,e:StoredEnvelope<'_>)->ap::Verdict{
        if self.panic_final{panic!("injected GD110 final dependency provider unwind")}
        if self.dependencies && self.deny_from.is_none() && e.manifest()==self.m && e.image()==&self.bytes[176..]
            && e.dependency_count()==1 && e.dependency(0).map(|d|(d.artifact,d.generation,d.provenance))==Some((800,2,804))
            {ap::Verdict::Valid}else{ap::Verdict::Invalid}
    }
}
fn download_config()->DownloadConfig{DownloadConfig{limits:RetrievalLimits{max_bytes:2*1024*1024,work:10_000_000,timeout:Duration::from_secs(120)},
    window:4096,retries:1,run:DevelopmentRunConfig::default()}}
#[test]
fn gd110_guest_source_uses_supported_subset_and_waits_for_eof(){
    let s=std::str::from_utf8(DOWNLOAD).unwrap();assert!(!s.contains('>') && !s.contains("&&") && !s.contains("//"));
    assert!(s.contains("total=200+count"));assert!(s.contains("while(n==(0-2))"));
    assert!(s.find("while(n==(0-2))").unwrap()<s.find("write_bytes(").unwrap());
}
#[test]
fn gd110_real_tcp_file_read_peer_preserves_selection_and_handles_fragmentation(){
    let temp=Temp::new();let bytes=Arc::new(vec![42;5000]);
    let m=store::Manifest{anchor:10,installation:20,artifact:900,generation:3,role:2,profile:1,size:5000,image:901,metadata:902,dependencies:903,provenance:904};
    let mut backend=store::ArtifactStore::create(&temp.0,10,20,1,limits(),selected()).unwrap();
    let mut proof=Proof{manifest:m,payload:bytes.clone(),channels:BTreeSet::new()};
    let t=backend.reserve(m,caller(),&mut proof).unwrap();backend.append(t,0,&bytes[..4096],&mut proof).unwrap();backend.append(t,4096,&bytes[4096..],&mut proof).unwrap();
    backend.seal(t,&mut proof).unwrap();backend.publish(t,91,7,&mut proof).unwrap();drop(backend);
    let record=fs::read(temp.0.join("artifact.record")).unwrap();
    let service=service(store::ArtifactStore::open(&temp.0,10,20,2,limits()).unwrap(),m,&bytes);
    let r=ReadRequest{manifest:m,correlation:1,offset:4096,count:904};let inner=Peer::new(&service,read::encode_read(r).unwrap().to_vec(),64,false);
    let mut peer=ReadPeer{inner,fault:Fault::None,loss:false};let mut out=[0;N];let mut seq=10;let mut ack=0;
    let n=peer.exchange(&make(LOCAL,STORAGE,Segment{seq,ack,flags:SYN,window:64,body:&[]}),&mut out).unwrap();
    ack=parse(STORAGE,LOCAL,&out[..n]).unwrap().seq+1;seq+=1;
    for part in read::encode_read(r).unwrap().chunks(64){peer.exchange(&make(LOCAL,STORAGE,Segment{seq,ack,flags:ACK|PSH,window:64,body:part}),&mut out).unwrap();seq+=part.len()as u32;}
    let mut n=peer.exchange(&make(LOCAL,STORAGE,Segment{seq,ack,flags:ACK|FIN,window:64,body:&[]}),&mut out).unwrap();seq+=1;
    let mut response=Vec::new();let mut eof=false;
    while n!=0{let s=parse(STORAGE,LOCAL,&out[..n]).unwrap();response.extend_from_slice(s.body);eof|=s.flags&FIN!=0;
        ack=s.seq+s.body.len()as u32+u32::from(s.flags&FIN!=0);n=peer.exchange(&make(LOCAL,STORAGE,Segment{seq,ack,flags:ACK,window:64,body:&[]}),&mut out).unwrap();}
    assert!(eof);assert_eq!(&response[200..],&bytes[4096..]);drop(peer);assert_eq!(service.usage().unwrap().0,0);
    assert_eq!(fs::read(temp.0.join("artifact.record")).unwrap(),record);
}

#[test]
#[ignore="real CC2 guest download through typed sockets, NIC DMA, guarded TCP and reopened file; release only"]
fn gd110_real_cc2_guest_download(){
    gd110_guest_source_uses_supported_subset_and_waits_for_eof();
    let exec=DeveloperExecutionAuthority::provision();let auth=RebuildPublicationAuthority::provision();
    let net=DeveloperFrameAuthority::provision();let input=DeveloperInputAuthority::provision();
    let lineage=cc2_fixed_point::witness_cc2_fixed_point(Some(&exec),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let mut compiler=RebuildService::new(&lineage,&exec).unwrap();
    let source=format!("int main(){{int value=0;{}return value-54;}}","value=value+1;".repeat(96));
    let image_epoch=super::super::guest_tests::compile(&mut compiler,source.as_bytes(),&exec,&auth);
    let pump_epoch=super::super::guest_tests::compile(&mut compiler,DOWNLOAD,&exec,&auth);
    let temp=Temp::new();let mut backend=store::ArtifactStore::create(&temp.0,10,20,1,limits(),selected()).unwrap();let mut export=Policy{manifest:None};
    compiler.kernel.persist_linked_compiler_publication(image_epoch,&mut backend,caller(),91,7,&mut export).unwrap();drop(backend);
    let m=export.manifest.unwrap();let bytes=Arc::new(fs::read(temp.0.join("artifact.bytes")).unwrap());assert!(bytes.len()>8192);
    let record=fs::read(temp.0.join("artifact.record")).unwrap();
    let service=service(store::ArtifactStore::open(&temp.0,10,20,2,limits()).unwrap(),m,&bytes);
    let baseline=compiler.kernel.fabric.scoped_pointers.total_reserved_bytes();let epoch=compiler.kernel.compiler_publication_epoch();
    let verifier=Arc::new(Mutex::new(ReadPolicy::new(m,bytes.clone())));
    let mut factory=Factory{service:&service,attempts:Vec::new(),fault:Fault::LostPrefix};
    eprintln!("GD110: read {} bytes via CC2 guest, 64/1024-byte queues, first reply lost after prefix",bytes.len());
    {
        let view=compiler.kernel.download_stored_compiler_image(pump_epoch,m,&exec,&input,&net,verifier.clone(),&mut factory,download_config()).unwrap();
        assert_eq!(view.envelope().unwrap().image(),&bytes[176..]);
        assert_eq!(view.test_kernel().fabric.scoped_pointers.total_reserved_bytes(),baseline+(m.size+32768).div_ceil(4096)*4096);
        assert_eq!(view.test_kernel().compiler_publication_epoch(),epoch);
    }
    assert_eq!(factory.attempts.len(),bytes.len().div_ceil(4096)+1);
    assert_eq!((factory.attempts[0].offset,factory.attempts[1].offset),(0,0));
    for pair in factory.attempts.windows(2){assert!(pair[1].correlation>pair[0].correlation);}
    let bindings=verifier.lock().unwrap().bindings.len();assert_eq!(bindings,factory.attempts.len());
    assert_eq!(compiler.kernel.fabric.scoped_pointers.total_reserved_bytes(),baseline);
    // Same compiled pump, independently hostile real paths. All must retain no
    // private result or scratch and must leave the durable/publication state alone.
    for fault in [Fault::CorruptPayload,Fault::Tail,Fault::NoFin]{
        eprintln!("GD110: rejecting {fault:?}");
        let mut factory=Factory{service:&service,attempts:Vec::new(),fault};
        let mut config=download_config();config.limits.work=400_000;
        let v=Arc::new(Mutex::new(ReadPolicy::new(m,bytes.clone())));
        let result=compiler.kernel.download_stored_compiler_image(pump_epoch,m,&exec,&input,&net,v,&mut factory,config);
        assert!(result.is_err(),"{fault:?} accepted");drop(result);
        assert_eq!(compiler.kernel.fabric.scoped_pointers.total_reserved_bytes(),baseline,"{fault:?} leaked charge");
    }
    for which in 0..4{
        eprintln!("GD110: authority/dependency/unwind case {which}");
        let mut p=ReadPolicy::new(m,bytes.clone());
        match which{0=>p.deny_from=Some(4096),1=>p.dependencies=false,2=>p.panic_check=true,_=>p.panic_final=true}
        let v=Arc::new(Mutex::new(p));let mut factory=Factory{service:&service,attempts:Vec::new(),fault:Fault::None};
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
            let result=compiler.kernel.download_stored_compiler_image(pump_epoch,m,&exec,&input,&net,v,&mut factory,download_config());
            assert!(result.is_err());
        }));
        assert_eq!(result.is_err(),which>=2);assert_eq!(compiler.kernel.fabric.scoped_pointers.total_reserved_bytes(),baseline,"case {which} leaked charge");
    }
    assert_eq!(compiler.kernel.compiler_publication_epoch(),epoch);assert!(compiler.kernel.linked_compiler_receipt(image_epoch).is_ok());
    assert_eq!(fs::read(temp.0.join("artifact.record")).unwrap(),record);assert_eq!(fs::read(temp.0.join("artifact.bytes")).unwrap(),*bytes);
    assert_eq!(service.usage().unwrap().0,0);
    eprintln!("GD110: real multi-range/retry/private custody, corruption/tail/no-FIN, revocation, dependencies and unwind cleanup passed; no stored image execution");
}

mod launch_tests;

mod restart_tests;

mod local_bridge_tests;
