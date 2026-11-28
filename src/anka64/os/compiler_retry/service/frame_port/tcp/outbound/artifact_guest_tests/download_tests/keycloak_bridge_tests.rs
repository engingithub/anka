//! LK110 combined real Keycloak/holder/LG110/E11 and guest/file acceptance.
//! Disposable local content policy; no live or boot admission.
use super::*;
use crate::anka64::authority_persistence::evidence::local_grants::adapter::read_bridge::acceptance::{Session,CASES,event};
struct BridgePeer<'a>{wire:Arc<Mutex<Session>>,store:&'a mut store::ArtifactStore,request:read::ReadRequest,
    seq:u32,ack:u32,started:bool,closing:bool,sent:usize,reply:Vec<u8>,fin:bool,received:usize}
impl BridgePeer<'_>{
    fn frame(&self,flags:u8,body:&[u8],out:&mut[u8;N])->usize{
        let bytes=make(STORAGE,LOCAL,Segment{seq:self.seq,ack:self.ack,flags,window:1024,body});
        out[..bytes.len()].copy_from_slice(&bytes);bytes.len()
    }
    fn next(&mut self,out:&mut[u8;N])->usize{
        if self.sent<self.reply.len() || !self.fin {Session::before_delivery(&self.wire);}
        if self.sent<self.reply.len(){let n=(self.reply.len()-self.sent).min(1024);
            let size=self.frame(ACK|PSH,&self.reply[self.sent..self.sent+n],out);self.sent+=n;self.seq+=n as u32;size
        }else if !self.fin{let size=self.frame(ACK|FIN,&[],out);self.fin=true;self.seq+=1;size}else{0}
    }
}
impl SelectPeer for BridgePeer<'_>{
    fn exchange(&mut self,frame:&[u8],out:&mut[u8;N])->Result<usize,String>{
        let s=parse(LOCAL,STORAGE,frame).ok_or("invalid guest frame")?;
        if !self.started{
            if s.flags!=SYN || !s.body.is_empty(){return Err("expected SYN".into())}
            self.started=true;self.ack=s.seq.wrapping_add(1);let n=self.frame(SYN|ACK,&[],out);self.seq+=1;return Ok(n)
        }
        if s.seq!=self.ack || s.ack!=self.seq{return Err("bridge TCP sequence".into())}
        if self.closing{return Ok(self.next(out))}
        if s.flags==ACK && s.body.is_empty(){return Ok(0)}
        if s.flags==(ACK|PSH){
            let expected=read::encode_read(self.request).map_err(err)?;
            let end=self.received.checked_add(s.body.len()).ok_or("request overflow")?;
            if expected.get(self.received..end)!=Some(s.body){return Err("request substitution".into())}
            Session::renew(&self.wire);
            self.wire.lock().unwrap().push(s.body)?;self.received=end;self.ack+=s.body.len()as u32;return Ok(self.frame(ACK,&[],out))
        }
        if s.flags==(ACK|FIN) && s.body.is_empty() && self.received==at::HEADER{
            Session::renew(&self.wire);
            self.ack+=1;self.reply=self.wire.lock().unwrap().finish(self.store)?;
            Session::fault(&self.wire);
            self.closing=true;return Ok(self.next(out))
        }
        Err("unexpected bridge frame".into())
    }
}
impl Drop for BridgePeer<'_>{fn drop(&mut self){crate::anka64::os::typed_socket::select::download::scrub(&mut self.reply);}}
struct BridgeFactory<'a>{store:&'a mut store::ArtifactStore,manifest:store::Manifest,used:bool,session:Option<Arc<Mutex<Session>>>}
impl DownloadTransport for BridgeFactory<'_>{
    fn connect(&mut self,r:read::ReadRequest)->Result<DownloadConnection<'_>,String>{
        // Explicit single-range test allocation. Retry cannot allocate a fresh
        // owner, budget, incarnation or deadline, and a new range cannot widen it.
        if self.used || r.manifest!=self.manifest || r.offset!=0 || r.count!=r.manifest.size{return Err("one registered range only".into())}
        self.used=true;
        let wire=self.session.as_ref().ok_or("LK110 session missing")?.clone();
        Ok(DownloadConnection{capacity:SocketCapacity::new(1024,1024).unwrap(),peer:Box::new(BridgePeer{
            wire,store:self.store,request:r,seq:900,ack:0,started:false,closing:false,
            sent:0,reply:Vec::new(),fin:false,received:0})})
    }
}
#[test]
#[ignore="requires private LK110 parent driver and running disposable Keycloak lab; no live admission"]
fn lk110_real_keycloak_cc2_e11_file_bridge(){
    assert!(std::env::var_os("ANKA_LK110_STATE").is_some(),"use bridge_acceptance.py run");
    let exec=DeveloperExecutionAuthority::provision();let publish=RebuildPublicationAuthority::provision();
    let net=DeveloperFrameAuthority::provision();let input=DeveloperInputAuthority::provision();
    let fixed=cc2_fixed_point::witness_cc2_fixed_point(Some(&exec),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let mut compiler=RebuildService::new(&fixed,&exec).unwrap();
    let image_epoch=super::super::super::guest_tests::compile(&mut compiler,b"int main(){return 42;}\n",&exec,&publish);
    let pump_epoch=super::super::super::guest_tests::compile(&mut compiler,DOWNLOAD,&exec,&publish);
    let temp=Temp::new();let mut backend=store::ArtifactStore::create(&temp.0,10,20,1,limits(),selected()).unwrap();
    let mut export=Policy{manifest:None};
    compiler.kernel.persist_linked_compiler_publication(image_epoch,&mut backend,caller(),91,7,&mut export).unwrap();
    let m=export.manifest.unwrap();
    assert!(m.size<=4096,"LK110 acceptance deliberately allocates one range");drop(backend);
    let bytes=Arc::new(fs::read(temp.0.join("artifact.bytes")).unwrap());
    let record=fs::read(temp.0.join("artifact.record")).unwrap();
    let mut backend=store::ArtifactStore::open(&temp.0,10,20,1,limits()).unwrap();
    let baseline=compiler.kernel.fabric.scoped_pointers.total_reserved_bytes();
    let epoch=compiler.kernel.compiler_publication_epoch();
    let root=PathBuf::from(std::env::var_os("ANKA_LK110_STATE").expect("use bridge_acceptance.py run"));
    for (case,name) in CASES.iter().enumerate(){
        event(name); // Parent issues the real token AFTER expensive CC2 compilation.
        let request=ReadRequest{manifest:m,correlation:1,offset:0,count:m.size};
        let v=Arc::new(Mutex::new(Session::new(&root,request,caller(),bytes.clone(),LOCAL.addr(),STORAGE.addr(),case)));
        event("issued");
        let mut factory=BridgeFactory{store:&mut backend,manifest:m,used:false,session:Some(v.clone())};
        let mut cfg=download_config();cfg.retries=0;
        let result=compiler.kernel.download_stored_compiler_image(pump_epoch,m,&exec,&input,&net,v.clone(),&mut factory,cfg);
        if case<=1{let view=result.unwrap();assert_eq!(view.envelope().unwrap().image(),&bytes[176..]);drop(view);}
        else{assert!(result.is_err(),"LK110 case {case} accepted");drop(result);}
        v.lock().unwrap().assert_outcome();
        event("restore");
        println!("LK110 PASS {name}");
        assert_eq!(compiler.kernel.fabric.scoped_pointers.total_reserved_bytes(),baseline);
        assert_eq!(compiler.kernel.compiler_publication_epoch(),epoch);
        assert_eq!(fs::read(temp.0.join("artifact.record")).unwrap(),record);
        assert_eq!(fs::read(temp.0.join("artifact.bytes")).unwrap(),*bytes);
    }
    println!("LK110 COMPLETE 10; live=false boot=false");
}
