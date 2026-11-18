//! AG110: one bound TCP exchange, guarded from intake through reply disclosure.
//! All provider updates must use Service::update; independently mutable provider
//! state is outside the serialized-lane contract. No production crypto supplied.
use super::*;
use std::{io,net::{TcpStream,Shutdown},sync::{Mutex,TryLockError,atomic::{AtomicU64,Ordering}},time::{Duration,Instant}};
pub(crate) const CHARGE:u64=32768;
static CHANNELS:AtomicU64=AtomicU64::new(1);

pub(crate) trait TransportEvidence:TransferEvidence {
    /// Trusted admission must bind evidence to this actual stream. An address or
    /// the generated channel number alone is not authentication.
    fn bind_stream(&mut self,_stream:&TcpStream,_channel:u64)->Result<(),Error> {Err(Error::Authority)}
    fn live_channel(&mut self,_channel:u64)->Result<(),Error> {Err(Error::Authority)}
    fn retire_channel(&mut self,_channel:u64) {}
}
#[derive(Clone,Copy)]
pub(crate) struct Config {pub slots:usize,pub byte_limit:u64,pub work:u64,pub ingress:u64,pub timeout:Duration}
impl Config {fn valid(self)->bool {(1..=64).contains(&self.slots) && self.byte_limit>=CHARGE && self.work>0
    && self.ingress>=(MAX_REQUEST+1)as u64 && !self.timeout.is_zero() && self.timeout<=Duration::from_secs(60)}}
#[derive(Debug)]
pub(crate) enum TransportError {Authority(Error),Io(io::Error),Capacity,Deadline,Busy,Poisoned,Closed}
impl std::fmt::Display for TransportError {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        match self {
            Self::Authority(e)=>write!(f,"artifact authority/backend: {e:?}"),
            Self::Io(e)=>write!(f,"artifact transport IO: {e}"),
            Self::Capacity=>f.write_str("artifact transport capacity exhausted"),
            Self::Deadline=>f.write_str("artifact transport deadline reached"),
            Self::Busy=>f.write_str("artifact transport lane busy"),
            Self::Poisoned=>f.write_str("artifact transport lane poisoned"),
            Self::Closed=>f.write_str("artifact transport session closed"),
        }
    }
}
impl From<Error> for TransportError {fn from(e:Error)->Self {Self::Authority(e)}}
impl From<io::Error> for TransportError {fn from(e:io::Error)->Self {Self::Io(e)}}
struct State<P> {store:ArtifactStore,proof:P,live:usize,bytes:u64,ingress:u64,dispatch:Budget}
/// Owns the backend and evidence lane. No backend or provider mutable reference
/// escapes; sockets are handed in by the listener/embedding and never rebound.
pub(crate) struct Service<P:TransportEvidence> {lane:Mutex<State<P>>,config:Config,work:AtomicU64}
impl<P:TransportEvidence> Service<P> {
    pub(crate) fn new(store:ArtifactStore,proof:P,config:Config)->Result<Self,TransportError> {
        if !config.valid() || std::mem::size_of::<Session<'_,P>>()as u64>CHARGE {return Err(TransportError::Capacity)}
        Ok(Self{lane:Mutex::new(State{store,proof,live:0,bytes:0,ingress:config.ingress,
            dispatch:Budget::new(config.work,config.ingress,CHARGE)?}),config,work:AtomicU64::new(config.work)})
    }
    fn spend(&self)->Result<(),TransportError> {
        self.work.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|n|n.checked_sub(1))
            .map(|_|()).map_err(|_|TransportError::Capacity)
    }
    // Trusted callbacks must be bounded and must not reenter this service.
    pub(crate) fn update(&self,update:impl FnOnce(&mut P))->Result<(),TransportError> {
        let mut lane=self.lane.try_lock().map_err(lock_error)?;update(&mut lane.proof);Ok(())
    }
    pub(crate) fn usage(&self)->Result<(usize,u64,u64,u64),TransportError> {
        let lane=self.lane.try_lock().map_err(lock_error)?;
        Ok((lane.live,lane.bytes,lane.ingress,self.work.load(Ordering::Relaxed)))
    }
    pub(crate) fn attach(&self,stream:TcpStream)->Result<Session<'_,P>,TransportError> {
        self.spend()?;
        if !stream.peer_addr()?.ip().is_loopback() || !stream.local_addr()?.ip().is_loopback() {return Err(TransportError::Authority(Error::Authority))}
        stream.set_nonblocking(true)?;stream.set_nodelay(true)?;
        let deadline=Instant::now().checked_add(self.config.timeout).ok_or(TransportError::Capacity)?;
        let mut lane=self.lane.try_lock().map_err(lock_error)?;
        if lane.live>=self.config.slots || self.config.byte_limit-lane.bytes<CHARGE || lane.ingress<(MAX_REQUEST+1)as u64 {return Err(TransportError::Capacity)}
        let channel=CHANNELS.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|n|n.checked_add(1)).map_err(|_|TransportError::Capacity)?;
        lane.proof.bind_stream(&stream,channel)?;
        // After binding, only infallible reservation installation. If binding
        // unwinds, the lane is poisoned and can never admit another operation.
        lane.live+=1;lane.bytes+=CHARGE;lane.ingress-=(MAX_REQUEST+1)as u64;
        Ok(Session{service:self,stream:Some(stream),channel,deadline,phase:Phase::Reading,input:[0;MAX_REQUEST+1],received:0,
            reply:None,sent:0,caller:None,ticket:0,charged:true,#[cfg(test)] io_cut:None})
    }
}
fn lock_error<T>(e:TryLockError<T>)->TransportError {match e {TryLockError::WouldBlock=>TransportError::Busy,TryLockError::Poisoned(_)=>TransportError::Poisoned}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Phase {Reading,Ready,Sending,Closed}
#[cfg(test)] enum IoCut {Blocked,Interrupted,Zero}
pub(crate) struct Session<'a,P:TransportEvidence> {
    service:&'a Service<P>,stream:Option<TcpStream>,channel:u64,deadline:Instant,phase:Phase,
    input:[u8;MAX_REQUEST+1],received:usize,reply:Option<Reply>,sent:usize,
    caller:Option<Caller>,ticket:u64,charged:bool,
    #[cfg(test)] io_cut:Option<IoCut>,
}
impl<P:TransportEvidence> Session<'_,P> {
    /// true means the full reply was written and the connection closed. There
    /// is no redispatch after an effect, including cancellation or IO failure.
    pub(crate) fn poll(&mut self)->Result<bool,TransportError> {
        if self.phase==Phase::Closed {self.cancel();return Err(TransportError::Closed)}
        if Instant::now()>=self.deadline {self.cancel();return Err(TransportError::Deadline)}
        if let Err(e)=self.service.spend() {self.cancel();return Err(e)}
        let result=self.step();
        match result {
            Ok(true)=>{self.cancel();Ok(true)},
            Ok(false)|Err(TransportError::Busy)=>Ok(false),
            Err(e)=>{self.cancel();Err(e)},
        }
    }
    fn step(&mut self)->Result<bool,TransportError> {
        let service=self.service;
        let mut lane=service.lane.try_lock().map_err(lock_error)?;
        // Mark closed before calling provider/IO; panic cannot leave Ready live.
        let phase=std::mem::replace(&mut self.phase,Phase::Closed);
        lane.proof.live_channel(self.channel)?;
        match phase {
            Phase::Reading=>{
                if Instant::now()>=self.deadline {return Err(TransportError::Deadline)}
                let end=(self.received+64).min(self.input.len());
                match self.stream.as_mut().ok_or(TransportError::Closed)?.read(&mut self.input[self.received..end]) {
                    Ok(0)=>{read::validate_frame(&self.input[..self.received],true)?;self.phase=Phase::Ready;},
                    Ok(n)=>{self.received+=n;if self.received>MAX_REQUEST {return Err(Error::InvalidRequest.into())}self.phase=Phase::Reading;},
                    Err(e) if transient(&e)=>self.phase=Phase::Reading,
                    Err(e)=>return Err(e.into()),
                }
                Ok(false)
            }
            Phase::Ready=>{
                if read::is_read(&self.input[..self.received]) {
                    let request=read::decode_read(&self.input[..self.received],true)?;
                    let State{store,proof,dispatch:budget,..}=&mut *lane;
                    let caller=read::authorize_read(store,self.channel,&request,None,proof)?;
                    if Instant::now()>=self.deadline {return Err(TransportError::Deadline)}
                    let reply=read::dispatch_read(store,self.channel,&self.input[..self.received],true,budget,proof)?;
                    read::authorize_read(store,self.channel,&request,Some((caller,store.current_ticket().serial)),proof)?;
                    if Instant::now()>=self.deadline {return Err(TransportError::Deadline)}
                    self.caller=Some(caller);self.ticket=store.current_ticket().serial;
                    self.reply=Some(reply);self.phase=Phase::Sending;return Ok(false)
                }
                let request=decode(&self.input[..self.received],true)?;
                let caller=lane.proof.caller(self.channel,&request)?;
                if Instant::now()>=self.deadline {return Err(TransportError::Deadline)}
                let State{store,proof,dispatch:budget,..}=&mut *lane;
                let reply=super::dispatch(store,self.channel,&self.input[..self.received],true,budget,proof)?;
                if proof.caller(self.channel,&request)?!=caller {return Err(Error::Authority.into())}
                self.caller=Some(caller);self.ticket=store.current_ticket().serial;
                self.reply=Some(reply);self.phase=Phase::Sending;Ok(false)
            }
            Phase::Sending=>{
                if read::is_read(&self.input[..self.received]) {
                    let request=read::decode_read(&self.input[..self.received],true)?;
                    let State{store,proof,..}=&mut *lane;
                    let saved=(self.caller.ok_or(Error::Authority)?,self.ticket);
                    read::authorize_read(store,self.channel,&request,Some(saved),proof)?;
                } else {
                    let request=decode(&self.input[..self.received],true)?;
                    let caller=lane.proof.caller(self.channel,&request)?;
                    if Some(caller)!=self.caller {return Err(Error::Authority.into())}
                    let ticket=Ticket{anchor:request.manifest.anchor,installation:request.manifest.installation,serial:self.ticket,caller};
                    let State{store,proof,..}=&mut *lane;
                    if store.bound(ticket)?!=request.manifest {return Err(Error::Authority.into())}
                    let action=if matches!(request.operation,Operation::Publish|Operation::Outcome){Action::Publish}else{Action::Upload};
                    store.auth(proof,request.manifest,caller,self.ticket,action)?;
                }
                if Instant::now()>=self.deadline {return Err(TransportError::Deadline)}
                let reply=self.reply.as_ref().ok_or(TransportError::Closed)?.bytes();
                let end=(self.sent+64).min(reply.len());
                // Nonblocking write happens while the same lane excludes updates.
                #[cfg(test)]
                let result=match self.io_cut.take() {
                    Some(IoCut::Blocked)=>Err(io::ErrorKind::WouldBlock.into()),
                    Some(IoCut::Interrupted)=>Err(io::ErrorKind::Interrupted.into()),
                    Some(IoCut::Zero)=>Ok(0),None=>self.stream.as_mut().ok_or(TransportError::Closed)?.write(&reply[self.sent..end]),
                };
                #[cfg(not(test))]
                let result=self.stream.as_mut().ok_or(TransportError::Closed)?.write(&reply[self.sent..end]);
                match result {
                    Ok(n) if n>0 && n<=end-self.sent=>{self.sent+=n;self.phase=Phase::Sending;Ok(self.sent==reply.len())},
                    Ok(_)=>Err(io::Error::new(io::ErrorKind::WriteZero,"invalid reply progress").into()),
                    Err(e) if transient(&e)=>{self.phase=Phase::Sending;Ok(false)},
                    Err(e)=>Err(e.into()),
                }
            }
            Phase::Closed=>Err(TransportError::Closed),
        }
    }
    pub(crate) fn cancel(&mut self) {
        self.phase=Phase::Closed;
        // shutdown is advisory and can fail after a peer half-close. Drop the
        // owned descriptor now, rather than retaining it until Session::drop.
        if let Some(stream)=self.stream.take() {
            let _=stream.shutdown(Shutdown::Both);
            drop(stream);
        }
        self.input.fill(0);drop(self.reply.take());
        if self.charged {
            self.charged=false;
            // Poison never authorizes IO again, but closing owned buffers still
            // refunds their reservation. Skip callbacks through poisoned evidence.
            let poisoned=self.service.lane.is_poisoned();
            let mut lane=self.service.lane.lock().unwrap_or_else(|e|e.into_inner());
            lane.live-=1;lane.bytes-=CHARGE;
            if !poisoned {lane.proof.retire_channel(self.channel);}
        }
    }
}
impl<P:TransportEvidence> Drop for Session<'_,P> {fn drop(&mut self){self.cancel();}}
fn transient(e:&io::Error)->bool {matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)}
#[cfg(test)]
#[path="transport/tests.rs"]
mod tests;

#[cfg(test)]
#[path="transport/read_tests.rs"]
mod read_tests;
