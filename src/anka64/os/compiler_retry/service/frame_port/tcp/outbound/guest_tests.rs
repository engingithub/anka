//! End-to-end guest witness. Evidence providers are explicit deterministic
//! fixtures; file commits, CC2 code, receipts, syscalls and NIC DMA are real.
use super::*;
use crate::anka64::{authority_persistence::{self as ap,DurableRecord},
    authority_persistence::{file_backend::FileRecord,evidence::{self as ev,registry}},
    authority_persistence::protocol::{self as p,guarded},
    compiler_adapter::RebuildPublicationAuthority,dev_runner::{DeveloperExecutionAuthority,DevelopmentRunConfig},
    cc2_fixed_point,os::{ProcessResult,compiler_retry::service::RebuildService},
    source_bundle::{SourceBundle,SourceBundleMember}};
use std::{io::{self,Write},path::PathBuf,sync::{Arc,Mutex,atomic::{AtomicU64,Ordering}}};
use p::client::ServerVerifier;
const SOURCE:&[u8]=include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/bin/storage_select.c"));
fn env(correlation:u64)->Envelope {Envelope{correlation,request:ap::Request{anchor:10,installation:20,policy:3,
    caller:30,incarnation:4,sequence:1,expected:7,operation:ap::Operation::Select,argument:99,attempt:0}}}
fn context()->ap::Context {ap::Context{anchor:10,installation:20,policy:3,challenge:71,now:100,selected:true}}
struct Provider {connection:u64}
impl ev::CallerProvider for Provider {
    type Peer=u64;
    fn observe(&mut self,peer:&u64,r:ap::Request)->Option<ev::Snapshot>{
        if *peer!=self.connection || r!=env(42).request{return None;}
        let scope=ev::Scope{runtime:5,connection:*peer,binding:*peer,local:40,peer:30,kind:ev::Kind::Person,
            incarnation:4,role:ev::Role::Caller,operation:ap::Operation::Select,serial:9,challenge:71};
        Some(ev::Snapshot{context:context(),identity:ev::Identity{issuer:10,subject:30,kind:ev::Kind::Person,
            audience:20,policy:3,challenge:71,first:90,until:110,authentic:ap::Verdict::Valid,
            possession:ap::Verdict::Valid,status:ap::Verdict::Valid},
            permit:ev::Permit{issuer:10,subject:30,kind:ev::Kind::Person,audience:20,policy:3,incarnation:4,
                role:ev::Role::Caller,operation:ap::Operation::Select,first:95,until:108,
                authentic:ap::Verdict::Valid,status:ap::Verdict::Valid},
            proof:ev::BindingProof{scope,validated:ap::Verdict::Valid},
            observed:ev::Observation{scope,live:true,channel:ap::Verdict::Valid}})
    }
}
struct Server {envelope:Envelope,bound:Arc<Mutex<Option<p::client::Binding>>>}
impl ServerVerifier for Server {
    fn verify(&mut self,b:p::client::Binding,e:Envelope)->ap::Verdict{
        let mut bound=self.bound.lock().unwrap();
        if e==self.envelope && b.connection!=0 && b.local==LOCAL.addr() && b.remote==STORAGE.addr()
            && *bound.get_or_insert(b)==b {ap::Verdict::Valid}else{ap::Verdict::Invalid}
    }
}
struct Counted {file:FileRecord,commits:usize,reads:usize}
impl DurableRecord for Counted {
    fn load(&mut self,a:u64,i:u64)->Result<ap::State,ap::Error>{self.reads+=1;self.file.load(a,i)}
    fn commit(&mut self,a:u64,i:u64,b:&ap::State,n:&ap::State)->Result<(),ap::Error>{
        self.file.commit(a,i,b,n)?;self.commits+=1;Ok(())
    }
}
struct Bytes {handle:registry::Handle,bytes:[u8;p::REPLY_BYTES],used:usize}
impl Write for Bytes {
    fn write(&mut self,b:&[u8])->io::Result<usize>{
        let n=b.len().min(self.bytes.len()-self.used).min(64);
        self.bytes[self.used..self.used+n].copy_from_slice(&b[..n]);self.used+=n;Ok(n)
    }
    fn flush(&mut self)->io::Result<()>{Ok(())}
}
impl guarded::ReplySink for Bytes {fn peer(&self)->Option<registry::Handle>{Some(self.handle)}}
struct Peer {
    backend:Counted,registry:registry::Registry<Provider>,handle:registry::Handle,budget:registry::UseBudget,
    expected:Envelope,request:[u8;p::REQUEST_BYTES],used:usize,reply:[u8;p::REPLY_BYTES],sent:usize,
    seq:u32,ack:u32,started:bool,closing:bool,fin:bool,drop_reply:bool,loss_injected:bool,cap:usize,
}
impl Peer {
    fn new(file:FileRecord,e:Envelope,cap:usize,drop_reply:bool)->Self{
        static CONNECTION:AtomicU64=AtomicU64::new(1);
        let connection=CONNECTION.fetch_add(1,Ordering::Relaxed);
        let registry=registry::Registry::new(registry::Config{context:context(),runtime:5,serial:9,slots:1},Provider{connection}).unwrap();
        let handle=registry.register_connection(connection,e.request,connection).unwrap();
        Self{backend:Counted{file,reads:0,commits:0},registry,handle,budget:registry::UseBudget::new(32,105).unwrap(),
            expected:e,request:[0;p::REQUEST_BYTES],used:0,reply:[0;p::REPLY_BYTES],sent:0,
            seq:900,ack:0,started:false,closing:false,fin:false,drop_reply,loss_injected:false,cap}
    }
    fn frame(&self,seq:u32,flags:u8,body:&[u8],out:&mut[u8;N])->usize {
        let bytes=make(STORAGE,LOCAL,Segment{seq,ack:self.ack,flags,window:self.cap as u16,body});
        out[..bytes.len()].copy_from_slice(&bytes);bytes.len()
    }
    fn reply(&mut self,out:&mut[u8;N])->usize{
        if self.sent<p::REPLY_BYTES {
            let n=(p::REPLY_BYTES-self.sent).min(self.cap);
            let size=self.frame(self.seq,ACK|PSH,&self.reply[self.sent..self.sent+n],out);
            self.seq+=n as u32;self.sent+=n;size
        }else if !self.fin {
            let size=self.frame(self.seq,ACK|FIN,&[],out);self.seq+=1;self.fin=true;size
        }else{0}
    }
}
impl SelectPeer for Peer {
    fn exchange(&mut self,frame:&[u8],out:&mut[u8;N])->Result<usize,String>{
        let s=parse(LOCAL,STORAGE,frame).ok_or("invalid guest NIC frame")?;
        if !self.started {
            if s.flags!=SYN || !s.body.is_empty(){return Err("expected SYN".into());}
            self.ack=s.seq.wrapping_add(1);self.started=true;
            let n=self.frame(self.seq,SYN|ACK,&[],out);self.seq+=1;return Ok(n);
        }
        if s.seq!=self.ack || s.ack!=self.seq{return Err("sequence mismatch".into());}
        if self.closing {return Ok(self.reply(out));}
        if s.flags==ACK && s.body.is_empty(){return Ok(0);}
        if s.flags==(ACK|PSH) {
            if s.body.len()>p::REQUEST_BYTES-self.used{return Err("request tail".into());}
            self.request[self.used..self.used+s.body.len()].copy_from_slice(s.body);
            self.used+=s.body.len();self.ack=self.ack.wrapping_add(s.body.len() as u32);
            return Ok(self.frame(self.seq,ACK,&[],out));
        }
        if s.flags!=(ACK|FIN) || !s.body.is_empty(){return Err("expected request FIN".into());}
        assert_eq!(Envelope::decode(&self.request[..self.used],true).unwrap(),self.expected);
        let transport=p::DispatchBudget{slots:0,slot_limit:1,bytes:0,byte_limit:384,work:128,now:100,deadline:105};
        let mut pending=guarded::dispatch(&mut self.backend,&self.registry,self.handle,
            &self.request[..self.used],true,transport,&mut self.budget,true).map_err(err)?;
        if self.drop_reply {self.loss_injected=true;pending.cancel();return Err("injected reply loss AFTER durable commit".into());}
        let mut sink=Bytes{handle:self.handle,bytes:[0;p::REPLY_BYTES],used:0};
        while !pending.complete(){pending.write_once(&self.registry,&mut self.budget,&mut sink).map_err(err)?;}
        self.reply=sink.bytes;self.ack=self.ack.wrapping_add(1);self.closing=true;
        Ok(self.reply(out))
    }
}
struct Temp(PathBuf);
impl Temp {
    fn new()->Self {
        static IDS:AtomicU64=AtomicU64::new(1);
        loop {let path=std::env::temp_dir().join(format!("anka-guest-select-{}-{}",std::process::id(),IDS.fetch_add(1,Ordering::Relaxed)));
            match std::fs::create_dir(&path){Ok(())=>return Self(path),Err(e) if e.kind()==io::ErrorKind::AlreadyExists=>{},Err(e)=>panic!("temp: {e}")}}
    }
    fn path(&self)->PathBuf{self.0.join("record")}
    fn create(&self)->FileRecord{FileRecord::create(&self.path(),10,20,&ap::State{revision:7,value:55,boot:8,last:None}).unwrap()}
    fn open(&self)->FileRecord{FileRecord::open(&self.path(),10,20).unwrap()}
}
impl Drop for Temp {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
pub(super) fn compile(s:&mut RebuildService,source:&[u8],exec:&DeveloperExecutionAuthority,auth:&RebuildPublicationAuthority)->u64 {
    let bundle=SourceBundle::new("main.c",[SourceBundleMember::new("main.c",source.to_vec()).unwrap()]).unwrap();
    let job=s.submit(&bundle,0x40000,1_000_000_000,exec,auth).unwrap();
    let start=std::time::Instant::now();let mut last=start;
    let module=loop {
        assert!(start.elapsed().as_secs()<300,"guest Select compilation deadline");
        if let Some(epoch)=s.poll(job,exec,auth).unwrap(){break epoch;}
        if last.elapsed().as_secs()>=5{eprintln!("guest Select compile: {}s",start.elapsed().as_secs());last=std::time::Instant::now();}
    };
    s.link(&[module],exec,auth).unwrap()
}
#[test]
#[ignore="real CC2 guest Select through NIC and guarded FileRecord; run explicitly in release mode"]
fn g110_real_cc2_file_select(){
    g110_guest_source_uses_supported_lexical_subset();
    let exec=DeveloperExecutionAuthority::provision();let auth=RebuildPublicationAuthority::provision();
    let net=DeveloperFrameAuthority::provision();
    let lineage=cc2_fixed_point::witness_cc2_fixed_point(Some(&exec),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    // The lineage compiler must also lower the builtin, reject extra arguments,
    // and keep the legacy/raw-address profile closed.
    use crate::anka64::dev_compiler;
    let builtin=b"int main(){return sshut();}";
    dev_compiler::compile_protected_application_aom_with_linked_compiler(&lineage.cc2_2,builtin,&exec).unwrap();
    assert!(dev_compiler::compile_application_aom_with_linked_compiler(&lineage.cc2_2,builtin,&exec).is_err());
    assert!(dev_compiler::compile_protected_application_aom_with_linked_compiler(
        &lineage.cc2_2,b"int main(){return sshut(1);}",&exec).is_err());
    let mut service=RebuildService::new(&lineage,&exec).unwrap();
    let first=compile(&mut service,SOURCE,&exec,&auth);
    let original=std::str::from_utf8(SOURCE).unwrap();
    assert_eq!(original.matches("*(request+24)=42;").count(),1);
    let retry_source=original.replace("*(request+24)=42;","*(request+24)=43;");
    let retry=compile(&mut service,retry_source.as_bytes(),&exec,&auth);
    let baseline=service.kernel.fabric.scoped_pointers.total_reserved_bytes();
    for cap in [64,4096] {
        let temp=Temp::new();let mut file=Some(temp.create());let mut old=None;
        for (epoch,correlation,lose) in [(first,42,true),(retry,43,false)] {
            let mut peer=Peer::new(file.take().unwrap(),env(correlation),cap,lose);
            let binding=Arc::new(Mutex::new(None));
            let verifier:ServerLane=Arc::new(Mutex::new(Server{envelope:env(correlation),bound:binding.clone()}));
            let result=service.kernel.run_linked_compiler_publication_with_select(epoch,&exec,
                SelectStream{capacity:SocketCapacity::new(cap,cap).unwrap(),request:StorageRequest::Select(env(correlation)),verifier,authority:&net,peer:&mut peer},
                DevelopmentRunConfig::default());
            if lose {assert!(result.is_err(),"lost reply must not report success");}
            else {assert_eq!(result.as_ref().unwrap().execution().child_result,ProcessResult::Exited(0));}
            drop(result);
            assert_eq!(peer.loss_injected,lose,
                "expected post-commit reply loss was not reached; an earlier setup/runtime failure is not this witness");
            assert_eq!(peer.backend.reads,1,"guest never reached guarded storage dispatch");
            assert_eq!(peer.backend.commits,usize::from(lose));
            let current=binding.lock().unwrap().expect("guest never passed server evidence validation");
            if let Some(previous)=old{assert_ne!(current.connection,previous);}
            old=Some(current.connection);
            assert_eq!(peer.backend.reads,1);assert_eq!(peer.backend.commits,usize::from(lose));
            drop(peer); // release file lock and registry before reopening
            assert_eq!(service.kernel.fabric.scoped_pointers.total_reserved_bytes(),baseline);
            let mut reopened=temp.open();let state=reopened.load(10,20).unwrap();
            assert_eq!((state.revision,state.value,state.boot,state.last),(8,99,8,Some(env(42).request)));
            file=Some(reopened);
            assert!(service.kernel.linked_compiler_receipt(epoch).is_ok());
        }
        drop(file);
    }
    eprintln!("CC2 guest Select: 64/4096-byte queues, explicit FIN, guarded file commit, lost reply, reopen and identical retry passed");
}

#[test]
fn g110_guest_file_peer_fin_and_reopen_retry(){
    let temp=Temp::new();let mut file=Some(temp.create());
    for (correlation,lose) in [(42,true),(43,false)] {
        let mut peer=Peer::new(file.take().unwrap(),env(correlation),64,lose);
        let mut reply=[0u8;N];let mut seq=10;
        let syn=make(LOCAL,STORAGE,Segment{seq,ack:0,flags:SYN,window:64,body:&[]});
        let n=peer.exchange(&syn,&mut reply).unwrap();
        let mut ack=parse(STORAGE,LOCAL,&reply[..n]).unwrap().seq+1;seq+=1;
        let frame=make(LOCAL,STORAGE,Segment{seq,ack,flags:ACK,window:64,body:&[]});
        assert_eq!(peer.exchange(&frame,&mut reply).unwrap(),0);
        for body in env(correlation).encode().unwrap().chunks(64){
            let frame=make(LOCAL,STORAGE,Segment{seq,ack,flags:ACK|PSH,window:64,body});
            peer.exchange(&frame,&mut reply).unwrap();seq+=body.len() as u32;
        }
        assert_eq!((peer.backend.reads,peer.backend.commits),(0,0));
        let fin=make(LOCAL,STORAGE,Segment{seq,ack,flags:ACK|FIN,window:64,body:&[]});seq+=1;
        let result=peer.exchange(&fin,&mut reply);
        if lose {assert!(result.is_err());} else {
            let mut n=result.unwrap();let mut bytes=Vec::new();let mut eof=false;
            while n!=0 {
                let s=parse(STORAGE,LOCAL,&reply[..n]).unwrap();
                bytes.extend_from_slice(s.body);eof|=s.flags&FIN!=0;
                ack=s.seq+s.body.len() as u32+u32::from(s.flags&FIN!=0);
                let frame=make(LOCAL,STORAGE,Segment{seq,ack,flags:ACK,window:64,body:&[]});
                n=peer.exchange(&frame,&mut reply).unwrap();
            }
            assert_eq!(p::Reply::decode(&bytes,eof,env(correlation)).unwrap().outcome(),
                Some(ap::Outcome{revision:8,value:99,boot:8}));
        }
        assert_eq!(peer.backend.reads,1);assert_eq!(peer.backend.commits,usize::from(lose));
        drop(peer);file=Some(temp.open());
        assert_eq!(file.as_mut().unwrap().load(10,20).unwrap().revision,8);
    }
}

#[test]
fn g110_guest_source_uses_supported_lexical_subset(){
    // ankapp expands directives but preserves comments; the current protected
    // lexer only skips whitespace. Keep this probe in the supported subset.
    // Run before expensive bootstrap as well as in the quick test filter.
    let source=std::str::from_utf8(SOURCE).unwrap();
    assert!(source.trim_start().starts_with("int main()"));
    assert!(!source.contains("!=-"),"probe must express negative status as binary subtraction");
    assert_eq!(source.matches("n!=(0-2)").count(),2,
        "both send and receive loops must handle SOCKET_AGAIN using supported syntax");
    assert!(!source.contains("/*"),"probe contains unsupported block comments");
    assert!(!source.contains("//"),"probe contains unsupported line comments");
    for line in source.lines().filter(|line|!line.trim_start().starts_with("char ")) {
        assert!(!line.contains("request[") && !line.contains("reply["),
            "probe must use supported pointer arithmetic for element accesses");
    }
}
