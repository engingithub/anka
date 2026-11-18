//! Trusted, single-target runtime refinement. Wire frames pass the same bounded
//! guest NIC driver and Fabric DMA pipeline as S4. No external network listener.
use super::{Driver,DriverHold,DeveloperFrameAuthority,Kernel,SESSION_CHARGE,N,err};
use crate::anka64::{state::ProcessKey,os::typed_socket::{select::{Select,ServerLane},SocketCapacity,SocketTicket},
    authority_persistence::protocol::Envelope};
use crate::anka64::os::typed_socket::select::download::DownloadLane;
use crate::anka64::authority_persistence::artifact::transfer::read::{ReadRequest,encode_read};
use std::sync::atomic::{AtomicU32,Ordering};
mod wire;
use wire::*;
static NEXT_ISS:AtomicU32=AtomicU32::new(1);

pub(crate) struct Session{driver:Driver,ticket:SocketTicket,snd:u32,rcv:u32,credit:usize,
    rx_window:u16,started:bool,connected:bool,local_fin:bool,ended:bool,events:u16,download:Option<DownloadLane>}
struct Cleanup<'a>{k:&'a mut Kernel,t:SocketTicket,input:Option<ProcessKey>}
impl Drop for Cleanup<'_>{fn drop(&mut self){let _=self.k.cancel_socket(self.t);if let Some(key)=self.input{self.k.detach_process_input(key);}}}
#[cfg(test)]
pub(crate) fn with_guest_select<T>(k:&mut Kernel,key:ProcessKey,cap:SocketCapacity,env:Envelope,
    verifier:ServerLane,net:&DeveloperFrameAuthority,
    run:impl FnOnce(&mut Kernel,&mut Session)->Result<T,String>)->Result<T,String>{
    with_storage_request(k,key,cap,StorageRequest::Select(env),verifier,net,run)
}
fn with_storage_request<T>(k:&mut Kernel,key:ProcessKey,cap:SocketCapacity,request:StorageRequest<'_>,
    verifier:ServerLane,net:&DeveloperFrameAuthority,
    run:impl FnOnce(&mut Kernel,&mut Session)->Result<T,String>)->Result<T,String>{
    if matches!(&request,StorageRequest::Artifact(..)|StorageRequest::Download(..)) && !k.application_select_realm(){
        return Err("artifact input requires the charged receipt application realm".into());
    }
    let owner=k.processes.get(key.slot).ok_or("invalid guest")?.core.heap_owner().map_err(err)?;
    if owner.process!=key{return Err("stale guest".into());}
    let download=match &request{StorageRequest::Download(_,_,d)=>Some(d.clone()),_=>None};
    let flow=match &request {
        StorageRequest::Select(env)=>Select::new(LOCAL.addr(),STORAGE.addr(),*env,verifier),
        StorageRequest::Artifact(bytes,_)=>Select::new_artifact(LOCAL.addr(),STORAGE.addr(),bytes,verifier),
        StorageRequest::Download(r,_,d)=>Select::new_download(LOCAL.addr(),STORAGE.addr(),*r,verifier,d.clone()),
    }.map_err(err)?;
    let artifact=flow.is_artifact();let reply_len=flow.reply_len();
    let t=if k.application_select_realm() {k.bind_application_select(key,cap,flow,net)}
        else {k.bind_select(key,cap,flow)}.map_err(err)?;
    let mut guard=Cleanup{k,t,input:None};
    let read_frame=match &request{StorageRequest::Download(r,_,_)=>Some(encode_read(*r).map_err(err)?),_=>None};
    let input_bytes=match &request{StorageRequest::Artifact(bytes,_)=>Some(*bytes),
        StorageRequest::Download(_,_,_)=>Some(read_frame.as_ref().unwrap().as_slice()),_=>None};
    if let Some(bytes)=input_bytes {
        // The receipt runner reserves INPUT_CHARGE before this copy. This is a
        // fresh exact input for this incarnation, not an unbounded host stream.
        let mut input=[0u8;crate::anka64::authority_persistence::artifact::transfer::MAX_REQUEST+8];
        input[..8].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        input[8..8+bytes.len()].copy_from_slice(bytes);
        let result=guard.k.provision_process_input(key,&input[..8+bytes.len()]).map_err(err);
        input.fill(0);result?;guard.input=Some(key);
    }
    // Application binding first admits this exact new child account. Reserve
    // driver storage before constructing it; all failure paths cancel the socket.
    let reg=&mut guard.k.fabric.scoped_pointers;
    let account=reg.heap_account(owner).ok_or("unfunded guest")?;
    let token=reg.reserve_host_storage(account,SESSION_CHARGE,reg.revision()).map_err(err)?;
    let mut charge=DriverHold{kernel:&mut *guard.k,token:Some(token)};
    let result=(||{
        let iss=NEXT_ISS.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|n|n.checked_add(8192)).map_err(err)?;
        let driver=Driver::new()?;
        let mut s=Session{driver,ticket:t,snd:iss,rcv:0,credit:0,rx_window:cap.rx().min(reply_len) as u16,
            started:false,connected:false,local_fin:false,ended:false,events:if artifact{4096}else{128},download};
        run(&mut *charge.kernel,&mut s)
    })();
    charge.kernel.fabric.scoped_pointers.release_host_storage(token).map_err(err)?;
    charge.token=None;result
}

impl Session{
    fn tick(&mut self)->Result<(),String>{if let Some(d)=&self.download {return d.try_lock().map_err(err)?.spend(1).map_err(err)}self.events=self.events.checked_sub(1).ok_or("Select NIC work exhausted")?;Ok(())}
    pub(crate) fn start(&mut self,k:&mut Kernel)->Result<Vec<u8>,String>{
        self.tick()?;if self.started{return Err("active open already started".into());}
        let syn=make(LOCAL,STORAGE,Segment{seq:self.snd,ack:0,flags:SYN,window:self.rx_window,body:&[]});
        let mut wire=None;
        if !k.select_handshake(self.ticket,true,||{if !self.driver.parked(){return Ok(false)}wire=Some(self.driver.tx(&syn).map_err(|_|())?);Ok(true)})
            .map_err(|_|"SYN denied")?{return Err("SYN backpressure".into())}
        self.started=true;self.snd=self.snd.wrapping_add(1);Ok(wire.unwrap())
    }
    pub(crate) fn receive(&mut self,k:&mut Kernel,frame:&[u8])->Result<Option<Vec<u8>>,String>{
        self.tick()?;if !self.started || self.ended || !k.socket_current(self.ticket){return Err("inactive connection".into());}
        let bytes=self.driver.rx(frame)?;
        let Some(s)=parse(STORAGE,LOCAL,&bytes) else{return Ok(None)};
        if s.ack!=self.snd{return Ok(None);}
        if !self.connected{
            if s.flags!=(SYN|ACK) || !s.body.is_empty(){return Ok(None);}
            let next=s.seq.wrapping_add(1);
            let ack=make(LOCAL,STORAGE,Segment{seq:self.snd,ack:next,flags:ACK,window:self.rx_window,body:&[]});
            let mut out=None;
            if !k.select_handshake(self.ticket,false,||{if !self.driver.parked(){return Ok(false)}out=Some(self.driver.tx(&ack).map_err(|_|())?);Ok(true)})
                .map_err(|_|"final handshake ACK denied")?{return Ok(None)}
            self.rcv=next;self.connected=true;self.credit=s.window as usize;return Ok(out)
        }
        if s.seq!=self.rcv || s.flags&ACK==0 || s.flags & !(PSH|ACK|FIN)!=0{return Ok(None);}
        if s.flags==ACK && s.body.is_empty(){self.credit=s.window as usize;return Ok(None);}
        if !self.local_fin{return Ok(None);}
        let fin=s.flags&FIN!=0;
        if !fin && s.body.is_empty(){return Ok(None);}
        let next=self.rcv.wrapping_add(s.body.len() as u32).wrapping_add(fin as u32);
        let ack=make(LOCAL,STORAGE,Segment{seq:self.snd,ack:next,flags:ACK,window:self.rx_window,body:&[]});
        let mut out=None;
        k.select_reply(self.ticket,s.body,fin,||{out=Some(self.driver.tx(&ack).map_err(|_|())?);Ok(())})
            .map_err(|_|"storage reply refused")?;
        self.rcv=next;self.credit=s.window as usize;self.ended=fin;Ok(out)
    }
    pub(crate) fn flush(&mut self,k:&mut Kernel)->Result<Option<Vec<u8>>,String>{
        self.tick()?;if !self.connected || self.local_fin{return Err("TX unavailable".into());}
        let mut wire=None;let seq=self.snd;let ack=self.rcv;let window=self.rx_window;
        let action=k.select_flush(self.ticket,self.credit,|body,fin|{
            let frame=make(LOCAL,STORAGE,Segment{seq,ack,flags:ACK|if fin{FIN}else{PSH},window,body});
            wire=Some(self.driver.tx(&frame).map_err(|_|())?);Ok(())
        }).map_err(|_|"payload or FIN denied")?;
        if let Some((n,fin))=action{self.snd=self.snd.wrapping_add(n as u32 + fin as u32);self.local_fin=fin;self.credit-=n+fin as usize;}
        Ok(wire)
    }
}

#[cfg(test)]
mod tests;

/// Trusted reference peer. It sees one committed frame and returns at most one
/// bounded reverse frame. It has no Kernel, Fabric, guest pointer or ticket.
/// This is an isolated virtual-NIC adapter, not an external TCP listener.
pub(crate) trait SelectPeer {
    fn exchange(&mut self,frame:&[u8],reply:&mut [u8;N])->Result<usize,String>;
}
#[derive(Clone)]
pub(crate) enum StorageRequest<'a> {
    Select(Envelope),
    Artifact(&'a[u8],&'a crate::anka64::dev_runner::DeveloperInputAuthority),
    Download(ReadRequest,&'a crate::anka64::dev_runner::DeveloperInputAuthority,DownloadLane),
}
pub(crate) struct SelectStream<'a> {
    pub(crate) capacity:SocketCapacity,
    pub(crate) request:StorageRequest<'a>,
    pub(crate) verifier:ServerLane,
    pub(crate) authority:&'a DeveloperFrameAuthority,
    pub(crate) peer:&'a mut dyn SelectPeer,
}
impl SelectStream<'_> {
    pub(crate) fn artifact_input(&self)->bool{matches!(&self.request,StorageRequest::Artifact(..)|StorageRequest::Download(..))}
    pub(crate) fn run(self,k:&mut Kernel,key:ProcessKey,rounds:usize)->Result<(),String>{
        if rounds==0 || rounds>2_000_000{return Err("invalid Select execution budget".into());}
        with_storage_request(k,key,self.capacity,self.request,self.verifier,self.authority,|k,s|{
            let syn=s.start(k)?;
            s.exchange(k,self.peer,syn)?;
            if !s.connected {return Err("Select handshake incomplete".into());}
            for _ in 0..rounds {
                if let Some(d)=&s.download{d.try_lock().map_err(err)?.spend(1).map_err(err)?;}
                if k.processes[0].exited(){return Ok(());}
                k.run(1,1);
                if let Some((op,_,result))=k.take_socket_call() {
                    if result==u64::MAX{return Err("guest Select syscall refused".into());}
                    if matches!(op,crate::anka64::os::SYS_SOCKET_SEND|crate::anka64::os::SYS_SOCKET_SHUT_WR) {
                        while !s.local_fin {
                            let Some(frame)=s.flush(k)? else {break};
                            s.exchange(k,self.peer,frame)?;
                        }
                    }
                }
            }
            Err("guest Select instruction budget exhausted".into())
        })
    }
}
impl Session {
    fn exchange(&mut self,k:&mut Kernel,peer:&mut dyn SelectPeer,mut frame:Vec<u8>)->Result<(),String>{
        // ACK-driven deterministic peer. Every exchange is bounded independently
        // of guest instructions, and each RX goes through Driver/Fabric.
        for _ in 0..256 {
            let mut reply=[0u8;N];let n=peer.exchange(&frame,&mut reply)?;
            if n==0{return Ok(());}
            if n>N{return Err("peer frame exceeds NIC extent".into());}
            match self.receive(k,&reply[..n])? {Some(ack)=>frame=ack,None=>return Ok(())}
        }
        Err("Select peer exchange budget exhausted".into())
    }
}
#[cfg(test)]
mod guest_tests;

#[cfg(all(test,any(target_os="linux",target_os="macos")))]
mod artifact_guest_tests;
