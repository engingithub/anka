//! One outbound storage transaction. The trusted scheduling thread serializes
//! verifier observations and effects; providers must honor E11's guard contract.
use super::*;
use crate::anka64::authority_persistence::{Operation,Verdict,protocol::{
    Envelope,REQUEST_BYTES,REPLY_BYTES,ClientResult,ClientEvidence,accept_reply,
    client::{self,Binding,ServerVerifier}}};
use std::{net::SocketAddr,time::{Duration,Instant},sync::{Arc,Mutex}};
/// All policy changes for this adapter must use the same lane. Never hold it
/// while waiting for network readiness. Contention denies this offer.
pub(crate) type ServerLane = Arc<Mutex<dyn ServerVerifier+Send>>;

#[derive(Clone,Copy,PartialEq,Eq,Debug)]
enum Phase { Idle,Syn,Open,Closing,Fin,Reply,Failed }
pub(crate) struct Select {
    phase:Phase, binding:Binding, pub(super) verifier:ServerLane, verifier_size:u64, envelope:Envelope,
    request:[u8;REQUEST_BYTES], accepted:usize, sent:usize,
    reply:[u8;REPLY_BYTES], received:usize, delivered:usize,
    work:u16, deadline:Instant,
}
impl Select {
    pub(crate) fn new(local:SocketAddr,remote:SocketAddr,env:Envelope,v:ServerLane)
        ->Result<Self,HeapError>{
        if env.request.operation!=Operation::Select {return Err(HeapError::Configuration);}
        let verifier_size=std::mem::size_of_val(&*v.try_lock().map_err(|_|HeapError::Busy)?) as u64;
        Ok(Self{phase:Phase::Idle,binding:Binding{connection:client::fresh_connection().map_err(|_|HeapError::Capacity(Resource::Identity))?,local,remote},
            verifier:v,verifier_size,envelope:env,request:env.encode().map_err(|_|HeapError::Configuration)?,
            accepted:0,sent:0,reply:[0;REPLY_BYTES],received:0,delivered:0,
            work:512,deadline:Instant::now()+Duration::from_secs(30)})
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
        if v.verify(self.binding,self.envelope)!=Verdict::Valid || Instant::now()>=self.deadline {
            self.phase=Phase::Failed;return None;
        }
        Some(())
    }
    pub(super) fn allow_write(&mut self,n:usize,v:&mut dyn ServerVerifier)->Option<()> {
        if self.phase!=Phase::Open || n>REQUEST_BYTES-self.accepted{return None;} self.check_using(v)
    }
    pub(super) fn accept(&mut self,bytes:&[u8])->bool{
        if self.request.get(self.accepted..self.accepted+bytes.len())!=Some(bytes){return false;}
        self.accepted+=bytes.len();true
    }
    pub(super) fn read_ready(&mut self,v:&mut dyn ServerVerifier)->Option<bool>{
        if self.phase==Phase::Reply {self.check_using(v)?;Some(true)} else { self.tick()?;Some(false) }
    }
    pub(super) fn refill(&mut self,queue:&mut [u8],used:&mut usize,fin:&mut bool){
        let n=(REPLY_BYTES-self.delivered).min(queue.len()-*used);
        queue[*used..*used+n].copy_from_slice(&self.reply[self.delivered..self.delivered+n]);
        *used+=n;self.delivered+=n;*fin=self.delivered==REPLY_BYTES;
    }
}

impl Kernel {
    pub(crate) fn bind_select(&mut self,key:ProcessKey,cap:SocketCapacity,select:Select)
        ->Result<SocketTicket,HeapError>{
        // The receipt-managed application runner needs its own explicitly
        // authorized scheduling hook; never adopt an ordinary replay socket.
        if self.application_run.is_some(){return Err(HeapError::Busy);}
        self.bind_socket_window(key,SocketRights::Duplex,cap,cap.tx,Some(select))
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
        if s.phase!=Phase::Open || s.accepted!=REQUEST_BYTES{return None;}
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
        let fin=e.tx==0 && s.phase==Phase::Closing && s.sent==REQUEST_BYTES;
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
        s.current().ok_or(())?;
        if bytes.len()>REPLY_BYTES-s.received {s.phase=Phase::Failed;return Err(());}
        if bytes.len()>e.capacity.rx{return Err(());} // whole fragment or nothing
        let end=s.received+bytes.len();
        s.reply[s.received..end].copy_from_slice(bytes);
        if eof {
            s.current().ok_or(())?;
            let evidence=ClientEvidence{server:Verdict::Valid,pending_current:true};
            if matches!(accept_reply(&s.reply[..end],true,s.envelope,evidence),ClientResult::Unknown){
                s.phase=Phase::Failed;return Err(());
            }
        }
        if ack().is_err(){s.phase=Phase::Failed;return Err(());}
        s.received=end;if eof{s.phase=Phase::Reply;} Ok(())
    }
}
