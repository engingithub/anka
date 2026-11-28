//! LT110 real CC2/typed-socket/NIC/TCP/file mechanics with PRIVATE authority
//! fixtures. It is intentionally not a real Keycloak or live-admission witness.
use super::*;
use crate::anka64::authority_persistence::evidence::local_grants::adapter::read_bridge::tests::GuestFixture;
struct BridgePeer<'a>{wire:GuestFixture,store:&'a mut store::ArtifactStore,proof:Proof,request:read::ReadRequest,
    fault:u8,seq:u32,ack:u32,started:bool,closing:bool,sent:usize,reply:Vec<u8>,fin:bool,received:usize}
impl BridgePeer<'_>{
    fn frame(&self,flags:u8,body:&[u8],out:&mut[u8;N])->usize{
        let bytes=make(STORAGE,LOCAL,Segment{seq:self.seq,ack:self.ack,flags,window:1024,body});
        out[..bytes.len()].copy_from_slice(&bytes);bytes.len()
    }
    fn next(&mut self,out:&mut[u8;N])->usize{
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
            self.wire.push(s.body)?;self.received=end;self.ack+=s.body.len()as u32;return Ok(self.frame(ACK,&[],out))
        }
        if s.flags==(ACK|FIN) && s.body.is_empty() && self.received==at::HEADER{
            self.ack+=1;self.reply=self.wire.finish(self.store,&mut self.proof,self.fault)?;
            self.closing=true;return Ok(self.next(out))
        }
        Err("unexpected bridge frame".into())
    }
}
impl Drop for BridgePeer<'_>{fn drop(&mut self){crate::anka64::os::typed_socket::select::download::scrub(&mut self.reply);}}
struct BridgeFactory<'a>{store:&'a mut store::ArtifactStore,manifest:store::Manifest,bytes:Arc<Vec<u8>>,used:bool,fault:u8}
impl DownloadTransport for BridgeFactory<'_>{
    fn connect(&mut self,r:read::ReadRequest)->Result<DownloadConnection<'_>,String>{
        // Explicit single-range test allocation. Retry cannot allocate a fresh
        // owner, budget, incarnation or deadline, and a new range cannot widen it.
        if self.used || r.manifest!=self.manifest || r.offset!=0 || r.count!=r.manifest.size{return Err("one registered range only".into())}
        self.used=true;
        let wire=GuestFixture::new(r,caller(),1,1);
        let proof=Proof{manifest:r.manifest,payload:self.bytes.clone(),channels:BTreeSet::new()};
        Ok(DownloadConnection{capacity:SocketCapacity::new(1024,1024).unwrap(),peer:Box::new(BridgePeer{
            wire,store:self.store,proof,request:r,fault:self.fault,seq:900,ack:0,started:false,closing:false,
            sent:0,reply:Vec::new(),fin:false,received:0})})
    }
}
#[test]
#[ignore="real CC2 fixed point and guest download; private authority fixtures, no live admission"]
fn lt110_real_cc2_guarded_file_bridge(){
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
    assert!(m.size<=4096,"LT110 witness deliberately allocates one range");drop(backend);
    let bytes=Arc::new(fs::read(temp.0.join("artifact.bytes")).unwrap());
    let record=fs::read(temp.0.join("artifact.record")).unwrap();
    let mut backend=store::ArtifactStore::open(&temp.0,10,20,1,limits()).unwrap();
    let baseline=compiler.kernel.fabric.scoped_pointers.total_reserved_bytes();
    let epoch=compiler.kernel.compiler_publication_epoch();
    for fault in 0..4{
        let v=Arc::new(Mutex::new(ReadPolicy::new(m,bytes.clone())));
        let mut factory=BridgeFactory{store:&mut backend,manifest:m,bytes:bytes.clone(),used:false,fault};
        let mut cfg=download_config();cfg.retries=0;
        let result=compiler.kernel.download_stored_compiler_image(pump_epoch,m,&exec,&input,&net,v,&mut factory,cfg);
        if fault==0{let view=result.unwrap();assert_eq!(view.envelope().unwrap().image(),&bytes[176..]);drop(view);}
        else{assert!(result.is_err(),"LT110 fault {fault} accepted");drop(result);}
        assert_eq!(compiler.kernel.fabric.scoped_pointers.total_reserved_bytes(),baseline);
        assert_eq!(compiler.kernel.compiler_publication_epoch(),epoch);
        assert_eq!(fs::read(temp.0.join("artifact.record")).unwrap(),record);
    }
    eprintln!("LT110: CC2/typed-socket/NIC/guarded TCP/file mechanics passed; authority fixtures; no live admission");
}
