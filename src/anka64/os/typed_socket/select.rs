//! One outbound storage transaction. The trusted scheduling thread serializes
//! verifier observations and effects; providers must honor E11's guard contract.
use super::*;
use crate::anka64::authority_persistence::{Operation,Verdict,protocol::{
    Envelope,REPLY_BYTES,ClientResult,ClientEvidence,accept_reply,
    client::{self,Binding,ServerVerifier}}};
use crate::anka64::authority_persistence::artifact::transfer as artifact;
use std::{net::SocketAddr,time::{Duration,Instant},sync::{Arc,Mutex}};
/// All policy changes for this adapter must use the same lane. Never hold it
/// while waiting for network readiness. Contention denies this offer.
pub(crate) type ServerLane = Arc<Mutex<dyn ServerVerifier+Send>>;

#[derive(Clone,Copy,PartialEq,Eq,Debug)]
enum Phase { Idle,Syn,Open,Closing,Fin,Reply,Failed }
pub(crate) struct Select {
    phase:Phase, binding:Binding, pub(super) verifier:ServerLane, verifier_size:u64, envelope:Option<Envelope>,
    request:[u8;artifact::MAX_REQUEST], request_len:usize, accepted:usize, sent:usize,
    reply:[u8;artifact::MAX_REPLY], reply_len:usize, received:usize, delivered:usize,
    work:u16, deadline:Instant,
}
impl Select {
    pub(crate) fn new(local:SocketAddr,remote:SocketAddr,env:Envelope,v:ServerLane)
        ->Result<Self,HeapError>{
        if env.request.operation!=Operation::Select {return Err(HeapError::Configuration);}
        let bytes=env.encode().map_err(|_|HeapError::Configuration)?;
        Self::create(local,remote,Some(env),&bytes,REPLY_BYTES,v)
    }
    pub(crate) fn new_artifact(local:SocketAddr,remote:SocketAddr,bytes:&[u8],v:ServerLane)
        ->Result<Self,HeapError>{
        artifact::decode(bytes,true).map_err(|_|HeapError::Configuration)?;
        Self::create(local,remote,None,bytes,bytes.len()+72,v)
    }
    fn create(local:SocketAddr,remote:SocketAddr,envelope:Option<Envelope>,bytes:&[u8],reply_len:usize,v:ServerLane)
        ->Result<Self,HeapError>{
        if bytes.len()>artifact::MAX_REQUEST || reply_len>artifact::MAX_REPLY{return Err(HeapError::Configuration);}
        let verifier_size=std::mem::size_of_val(&*v.try_lock().map_err(|_|HeapError::Busy)?) as u64;
        let mut request=[0;artifact::MAX_REQUEST];request[..bytes.len()].copy_from_slice(bytes);
        Ok(Self{phase:Phase::Idle,binding:Binding{connection:client::fresh_connection().map_err(|_|HeapError::Capacity(Resource::Identity))?,local,remote},
            verifier:v,verifier_size,envelope,request,request_len:bytes.len(),
            accepted:0,sent:0,reply:[0;artifact::MAX_REPLY],reply_len,received:0,delivered:0,
            work:if envelope.is_some(){512}else{4096},deadline:Instant::now()+Duration::from_secs(30)})
    }
    pub(crate) fn is_artifact(&self)->bool{self.envelope.is_none()}
    pub(crate) fn reply_len(&self)->usize{self.reply_len}
    fn validate_reply_using(&mut self,end:usize,v:&mut dyn ServerVerifier)->bool {
        if end!=self.reply_len{return false;}
        if let Some(env)=self.envelope {
            return !matches!(accept_reply(&self.reply[..end],true,env,
                ClientEvidence{server:Verdict::Valid,pending_current:true}),ClientResult::Unknown);
        }
        struct Check<'a>{v:&'a mut dyn ServerVerifier,b:Binding,request:&'a[u8]}
        impl artifact::ServerEvidence for Check<'_>{
            fn current(&mut self,c:u64,_:&artifact::Request<'_>,_:&[u8])->Verdict{
                if c!=self.b.connection{return Verdict::Invalid;}
                self.v.verify_artifact(self.b,self.request)
            }
        }
        let request=&self.request[..self.request_len];
        artifact::accept_reply(request,&self.reply[..end],true,self.binding.connection,
            &mut Check{v,b:self.binding,request}).is_ok()
    }
    #[cfg(test)]
    fn validate_reply(&mut self,end:usize)->bool {
        let lane=self.verifier.clone();let Ok(mut v)=lane.try_lock() else{return false;};
        self.validate_reply_using(end,&mut *v)
    }
    pub(super) fn verifier_bytes(&self)->u64{self.verifier_size}
    fn tick(&mut self)->Option<()>{
        if self.phase==Phase::Failed || self.work==0 || Instant::now()>=self.deadline {
            self.phase=Phase::Failed;return None;
        }
        self.work-=1;Some(())
    }
    fn current(&mut self)->Option<()>{
        let lane=self.verifier.clone();
        let mut v=lane.try_lock().ok()?;
        self.check_using(&mut *v)
    }
    fn check_using(&mut self,v:&mut dyn ServerVerifier)->Option<()> {
        self.tick()?;
        let verdict=match self.envelope {Some(env)=>v.verify(self.binding,env),
            None=>v.verify_artifact(self.binding,&self.request[..self.request_len])};
        if verdict!=Verdict::Valid || Instant::now()>=self.deadline {
            self.phase=Phase::Failed;return None;
        }
        Some(())
    }
    pub(super) fn allow_write(&mut self,n:usize,v:&mut dyn ServerVerifier)->Option<()> {
        if self.phase!=Phase::Open || n>self.request_len-self.accepted{return None;} self.check_using(v)
    }
    pub(super) fn accept(&mut self,bytes:&[u8])->bool{
        if self.request[..self.request_len].get(self.accepted..self.accepted.saturating_add(bytes.len()))!=Some(bytes){return false;}
        self.accepted+=bytes.len();true
    }
    pub(super) fn read_ready(&mut self,v:&mut dyn ServerVerifier)->Option<bool>{
        if self.phase==Phase::Reply {self.check_using(v)?;Some(true)} else { self.tick()?;Some(false) }
    }
    pub(super) fn refill(&mut self,queue:&mut [u8],used:&mut usize,fin:&mut bool){
        let n=(self.reply_len-self.delivered).min(queue.len()-*used);
        queue[*used..*used+n].copy_from_slice(&self.reply[self.delivered..self.delivered+n]);
        *used+=n;self.delivered+=n;*fin=self.delivered==self.reply_len;
    }
}

impl Drop for Select {
    fn drop(&mut self){self.request.fill(0);self.reply.fill(0);self.accepted=0;self.sent=0;self.received=0;self.delivered=0;}
}

impl Kernel {
    pub(crate) fn bind_select(&mut self,key:ProcessKey,cap:SocketCapacity,select:Select)
        ->Result<SocketTicket,HeapError>{
        // The receipt-managed application runner needs its own explicitly
        // authorized scheduling hook; never adopt an ordinary replay socket.
        if self.application_run.is_some(){return Err(HeapError::Busy);}
        self.bind_socket_window(key,SocketRights::Duplex,cap,cap.tx,Some(select))
    }
    /// Only the receipt runner calls this after SPAWN, before scheduling the child.
    /// The separate development NIC authority does not grant NIC access to the child.
    pub(crate) fn bind_application_select(&mut self,key:ProcessKey,cap:SocketCapacity,select:Select,
        _authority:&crate::anka64::os::compiler_retry::service::frame_port::DeveloperFrameAuthority)
        ->Result<SocketTicket,HeapError>{
        // Fresh process slots have generation zero; equality to the live slot
        // authenticates an incarnation. Zero is not an invalid process key.
        if self.processes.len()!=3 || key.slot!=2
            || !self.application_run.as_ref().is_some_and(|r|r.spawned && !r.socket)
            || self.processes[key.slot].parent!=Some(ProcessKey{slot:0,generation:self.processes[0].generation})
            || self.processes[key.slot].generation!=key.generation {return Err(HeapError::Owner);}
        self.compiler_heap_account(key)?;
        let t=self.bind_socket_window(key,SocketRights::Duplex,cap,cap.tx,Some(select))?;
        self.application_run.as_mut().unwrap().socket=true;
        Ok(t)
    }
    pub(in crate::anka64::os) fn application_select(&self,idx:usize)->bool {
        self.socket_endpoint.as_ref().is_some_and(|e|e.select.is_some()
            && e.ticket.owner.process.slot==idx && self.socket_current(e.ticket))
    }
    pub(in crate::anka64::os) fn application_artifact_input(&self,idx:usize)->bool {
        self.application_select(idx) && self.socket_endpoint.as_ref()
            .and_then(|e|e.select.as_ref()).is_some_and(Select::is_artifact)
    }
    fn outbound(&mut self,t:SocketTicket)->Result<&mut Endpoint,()> {
        if !self.socket_current(t){return Err(());}
        self.socket_endpoint.as_mut().filter(|e|e.select.is_some()).ok_or(())
    }
    pub(super) fn select_shutdown(&mut self,idx:usize,w:[u64;16],k:[Option<ScopedPointer>;6])->Option<u64>{
        let core=&self.processes.get(idx)?.core;
        if core.protected_syscall_image()!=Some((w,k)) || k[0].is_some(){return None;}
        let t=self.socket_endpoint.as_ref()?.ticket;
        if t.owner.process.slot!=idx || core.heap_owner().ok()?!=t.owner{return None;}
        let s=self.outbound(t).ok()?.select.as_mut()?;
        if s.phase!=Phase::Open || s.accepted!=s.request_len{return None;}
        s.current()?;s.phase=Phase::Closing;Some(0)
    }
    // The adapter invokes these effects ONLY with its own actual NIC and ticket.
    // Callback success means a frame was taken from the committed TX queue.
    pub(crate) fn select_handshake(&mut self,t:SocketTicket,syn:bool,tx:impl FnOnce()->Result<bool,()>)->Result<bool,()> {
        let s=self.outbound(t)?.select.as_mut().unwrap();s.tick().ok_or(())?;
        let expected=if syn{Phase::Idle}else{Phase::Syn};
        if s.phase!=expected{return Err(());}
        match tx(){Ok(false)=>return Ok(false),Err(())=>{s.phase=Phase::Failed;return Err(())},Ok(true)=>{}}
        s.phase=if syn{Phase::Syn}else{Phase::Open};Ok(true)
    }
    pub(crate) fn select_flush(&mut self,t:SocketTicket,credit:usize,tx:impl FnOnce(&[u8],bool)->Result<(),()>)
        ->Result<Option<(usize,bool)>,()> {
        let e=self.outbound(t)?;let s=e.select.as_mut().unwrap();
        if !matches!(s.phase,Phase::Open|Phase::Closing){return Err(());}
        let fin=e.tx==0 && s.phase==Phase::Closing && s.sent==s.request_len;
        let n=e.tx.min(credit);
        if credit==0 || (!fin && n==0) {s.tick().ok_or(())?;return Ok(None);}
        let lane=s.verifier.clone();
        let mut v=match lane.try_lock(){Ok(v)=>v,Err(std::sync::TryLockError::WouldBlock)=>return Ok(None),Err(_)=>return Err(())};
        s.check_using(&mut *v).ok_or(())?;
        let queue=&mut e.queues[e.capacity.rx..];
        if tx(&queue[..n],fin).is_err(){s.phase=Phase::Failed;return Err(());}
        consume(queue,&mut e.tx,n);s.sent+=n;
        if fin{s.phase=Phase::Fin;}
        Ok(Some((n,fin)))
    }
    pub(crate) fn select_reply(&mut self,t:SocketTicket,bytes:&[u8],eof:bool,ack:impl FnOnce()->Result<(),()>)->Result<(),()> {
        let e=self.outbound(t)?;let s=e.select.as_mut().unwrap();
        if s.phase!=Phase::Fin{return Err(());}
        let lane=s.verifier.clone();let mut v=lane.try_lock().map_err(|_|())?;
        s.check_using(&mut *v).ok_or(())?;
        if bytes.len()>s.reply_len-s.received {s.phase=Phase::Failed;return Err(());}
        if bytes.len()>e.capacity.rx{return Err(());} // whole fragment or nothing
        let end=s.received+bytes.len();
        s.reply[s.received..end].copy_from_slice(bytes);
        if eof {
            s.check_using(&mut *v).ok_or(())?;
            if !s.validate_reply_using(end,&mut *v){
                s.phase=Phase::Failed;return Err(());
            }
        }
        if ack().is_err(){s.phase=Phase::Failed;return Err(());}
        s.received=end;if eof{s.phase=Phase::Reply;} Ok(())
    }
}

#[cfg(test)]
mod artifact_tests {
    use super::*;
    struct Legacy;
    impl ServerVerifier for Legacy {fn verify(&mut self,_:Binding,_:Envelope)->Verdict{Verdict::Valid}}
    struct Artifact {frame:Vec<u8>,valid:bool}
    impl ServerVerifier for Artifact {
        fn verify_artifact(&mut self,b:Binding,r:&[u8])->Verdict{
            if self.valid && b.connection!=0 && r==self.frame {Verdict::Valid}else{Verdict::Invalid}
        }
    }
    fn frame()->Vec<u8> {
        use crate::anka64::authority_persistence::artifact::Manifest;
        let r=artifact::Request{operation:artifact::Operation::Append,correlation:1,ticket:1,offset:0,
            publish_request:0,expected:0,manifest:Manifest{anchor:10,installation:20,artifact:99,generation:1,
            role:2,profile:1,size:4096,image:101,metadata:102,dependencies:103,provenance:104},payload:&[255;4096]};
        let mut bytes=[0;artifact::MAX_REQUEST];let n=artifact::encode(&r,&mut bytes).unwrap();bytes[..n].to_vec()
    }
    fn select(bytes:&[u8],v:ServerLane)->Select {
        Select::new_artifact("127.0.0.1:1".parse().unwrap(),"127.0.0.1:2".parse().unwrap(),bytes,v).unwrap()
    }
    fn reply(bytes:&[u8])->Vec<u8> {
        let mut r=vec![0;72+bytes.len()];r[..8].copy_from_slice(b"ANKAUR01");
        for(i,w)in [1,bytes.len()as u64,1,4096,1,0,0,0].iter().enumerate(){r[8+i*8..16+i*8].copy_from_slice(&w.to_le_bytes());}
        r[72..].copy_from_slice(bytes);r
    }
    #[test]
    fn ga110_select_only_authority_cannot_send_artifact() {
        let bytes=frame();let mut s=select(&bytes,Arc::new(Mutex::new(Legacy)));
        s.phase=Phase::Open;assert!(s.current().is_none());assert_eq!(s.accepted,0);
    }
    #[test]
    fn ga110_exact_request_capacity_prefix_and_final_echo() {
        let bytes=frame();let mut s=select(&bytes,Arc::new(Mutex::new(Artifact{frame:bytes.clone(),valid:true})));
        assert_eq!((s.request_len,s.reply_len),(4264,4336));s.phase=Phase::Open;
        assert!(s.current().is_some());assert!(!s.accept(&[0]));assert_eq!(s.accepted,0);
        for b in bytes.chunks(1024){assert!(s.accept(b));}
        assert!(!s.accept(&[0]));assert_eq!(s.accepted,4264);
        s.reply.copy_from_slice(&reply(&bytes));assert!(s.validate_reply(4336));
        assert!(!s.validate_reply(4335));s.reply[4335]^=1;assert!(!s.validate_reply(4336));
        let mut tail=bytes.clone();tail.push(0);
        assert!(Select::new_artifact("127.0.0.1:1".parse().unwrap(),"127.0.0.1:2".parse().unwrap(),&tail,Arc::new(Mutex::new(Legacy))).is_err());
    }
    #[test]
    fn ga110_revocation_at_reply_and_fragmented_delivery() {
        let bytes=frame();let v=Arc::new(Mutex::new(Artifact{frame:bytes.clone(),valid:true}));let mut s=select(&bytes,v.clone());
        s.reply.copy_from_slice(&reply(&bytes));assert!(s.validate_reply(4336));
        v.lock().unwrap().valid=false;assert!(!s.validate_reply(4336));
        v.lock().unwrap().valid=true;let mut received=Vec::new();let mut fin=false;
        while !fin {let mut queue=[0;64];let mut n=0;s.refill(&mut queue,&mut n,&mut fin);received.extend_from_slice(&queue[..n]);}
        assert_eq!(received,reply(&bytes));assert_eq!(s.delivered,4336);
    }
}
