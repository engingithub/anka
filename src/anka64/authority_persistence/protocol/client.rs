//! Bounded reference client. The server verifier is trusted integration, not a
//! claim in a reply. No bytes are sent until it recognizes this exact connection
//! and request namespace. Default verification denies; localhost is not identity.
use super::*;
use std::io::{self,Read,Write};
use std::net::{SocketAddr,Shutdown,TcpStream};
use std::sync::atomic::{AtomicU64,Ordering};
use std::time::{Duration,Instant};
static CONNECTIONS:AtomicU64=AtomicU64::new(1);
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
// Identity is process-local. Across restarts the evidence provider must bind a
// fresh authenticated channel/challenge; this counter is not durable identity.
pub(crate) struct Binding {pub connection:u64,pub local:SocketAddr,pub remote:SocketAddr}
pub(crate) trait ServerVerifier {
    /// Obtain CURRENT trusted evidence bound to this actual stream incarnation,
    /// expected anchor/installation/policy and server role. Addresses alone are
    /// insufficient. Implementations must not accept assertions from wire data.
    fn verify(&mut self,_binding:Binding,_expected:Envelope)->Verdict{Verdict::Invalid}
}
pub(crate) struct DenyServer;
impl ServerVerifier for DenyServer {}
/// Only trusted adapters implement Channel. All operations after prepare must
/// be nonblocking. TCP is the reference adapter; deterministic tests use a mock.
pub(crate) trait Channel:Read+Write {
    fn prepare(&mut self)->io::Result<(SocketAddr,SocketAddr)>;
    fn half_close(&mut self)->io::Result<()>;
}
impl Channel for TcpStream {
    fn prepare(&mut self)->io::Result<(SocketAddr,SocketAddr)>{self.set_nonblocking(true)?;Ok((self.local_addr()?,self.peer_addr()?))}
    fn half_close(&mut self)->io::Result<()>{self.shutdown(Shutdown::Write)}
}
#[derive(Clone,Copy,Debug)]
pub(crate) struct Config {pub work:u64,pub timeout:Duration}
impl Default for Config{fn default()->Self{Self{work:512,timeout:Duration::from_secs(5)}}}
impl Config{fn valid(self)->bool{(1..=512).contains(&self.work) && !self.timeout.is_zero() && self.timeout<=Duration::from_secs(60)}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Phase{Send,HalfClose,Receive,Terminal(ClientResult)}
fn invalid()->io::Error{io::Error::new(io::ErrorKind::InvalidInput,"invalid client lifecycle/configuration")}
fn transient(e:&io::Error)->bool{matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)}
// One namespace for host and virtual transports using the E11 adapter.
pub(crate) fn fresh_connection()->io::Result<u64> {
    CONNECTIONS.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|n|n.checked_add(1))
        .map_err(|_|io::Error::other("client connection identity exhausted"))
}
fn bind<S:Channel>(stream:&mut S)->io::Result<Binding>{
    let (local,remote)=stream.prepare()?;
    if !local.ip().is_loopback() || !remote.ip().is_loopback(){return Err(invalid())}
    let connection=fresh_connection()?;
    Ok(Binding{connection,local,remote})
}
/// One owned connection and one immutable durable request. Dropping/cancelling
/// closes the stream. No caller-provided EOF or pending-current flag is accepted.
/// Fixed buffers are 112 request + 145 reply guard bytes, independent of the wire.
pub(crate) struct Client<S:Channel,V:ServerVerifier>{
    stream:Option<S>,verifier:V,binding:Binding,envelope:Envelope,
    request:[u8;REQUEST_BYTES],reply:[u8;REPLY_BYTES+1],sent:usize,received:usize,
    phase:Phase,work:u64,deadline:Instant,
}
impl<S:Channel,V:ServerVerifier> Client<S,V>{
    pub(crate) fn start(stream:S,envelope:Envelope,config:Config,verifier:V)->io::Result<Self>{
        if !config.valid(){return Err(invalid())}
        Self::start_until(stream,envelope,config.work,Instant::now()+config.timeout,verifier)
    }
    fn start_until(mut stream:S,envelope:Envelope,work:u64,deadline:Instant,verifier:V)->io::Result<Self>{
        let request=envelope.encode().map_err(|_|invalid())?;
        if work==0 || Instant::now()>=deadline{return Err(invalid())}
        let binding=bind(&mut stream)?;
        Ok(Self{stream:Some(stream),verifier,binding,envelope,request,reply:[0;REPLY_BYTES+1],sent:0,received:0,
            phase:Phase::Send,work:work-1,deadline})
    }
    pub(crate) fn binding(&self)->Binding{self.binding}
    pub(crate) fn result(&self)->Option<ClientResult>{match self.phase{Phase::Terminal(r)=>Some(r),_=>None}}
    fn finish(&mut self,r:ClientResult)->Option<ClientResult>{self.stream.take();self.phase=Phase::Terminal(r);Some(r)}
    pub(crate) fn cancel(&mut self)->ClientResult{
        if let Some(r)=self.result(){r}else{self.finish(ClientResult::Unknown);ClientResult::Unknown}
    }
    /// An explicit retry can change only transport correlation and connection.
    /// All TEN durable request fields, remaining work and absolute deadline stay
    /// unchanged. It cannot reset the budget or retry an established result.
    pub(crate) fn retry(&mut self,mut stream:S,correlation:u64)->io::Result<()>{
        if self.result()!=Some(ClientResult::Unknown) || correlation==0 || correlation==self.envelope.correlation ||
            self.work==0 || Instant::now()>=self.deadline{return Err(invalid())}
        self.work-=1; // failed setup attempts also consume shared work
        let envelope=Envelope{correlation,request:self.envelope.request};
        let request=envelope.encode().map_err(|_|invalid())?;
        let binding=bind(&mut stream)?;
        self.stream=Some(stream);self.binding=binding;self.envelope=envelope;self.request=request;
        self.reply=[0;REPLY_BYTES+1];self.sent=0;self.received=0;self.phase=Phase::Send;Ok(())
    }
    /// At most one nonblocking stream action per call. WouldBlock/Interrupted
    /// consume work. The embedding controls cadence; callbacks must be bounded.
    pub(crate) fn poll(&mut self)->Option<ClientResult>{
        if let Some(r)=self.result(){return Some(r)}
        if self.work==0 || Instant::now()>=self.deadline{return self.finish(ClientResult::Unknown)}
        self.work-=1;
        if self.verifier.verify(self.binding,self.envelope)!=Verdict::Valid || Instant::now()>=self.deadline{
            return self.finish(ClientResult::Unknown)
        }
        match self.phase{
            Phase::Send=>match self.stream.as_mut().unwrap().write(&self.request[self.sent..]){
                Ok(n) if n>0 && n<=REQUEST_BYTES-self.sent=>{self.sent+=n;if self.sent==REQUEST_BYTES{self.phase=Phase::HalfClose;}None},
                Err(e) if transient(&e)=>None,_=>self.finish(ClientResult::Unknown),
            },
            Phase::HalfClose=>match self.stream.as_mut().unwrap().half_close(){
                Ok(())=>{self.phase=Phase::Receive;None},Err(e) if transient(&e)=>None,_=>self.finish(ClientResult::Unknown),
            },
            Phase::Receive=>match self.stream.as_mut().unwrap().read(&mut self.reply[self.received..]){
                Ok(0)=>{
                    // EOF alone is not enough: recheck current evidence after
                    // receiving and then require canonical size/echo/outcome.
                    if Instant::now()>=self.deadline || self.verifier.verify(self.binding,self.envelope)!=Verdict::Valid{
                        return self.finish(ClientResult::Unknown)
                    }
                    let r=accept_reply(&self.reply[..self.received],true,self.envelope,
                        ClientEvidence{server:Verdict::Valid,pending_current:true});
                    self.finish(r)
                },
                Ok(n) if n<=REPLY_BYTES+1-self.received=>{
                    self.received+=n;if self.received>REPLY_BYTES{self.finish(ClientResult::Unknown)}else{None}
                },
                Err(e) if transient(&e)=>None,_=>self.finish(ClientResult::Unknown),
            },
            Phase::Terminal(r)=>Some(r),
        }
    }
}
impl<V:ServerVerifier> Client<TcpStream,V>{
    /// Optional bounded connect convenience. Connect time shares the absolute
    /// deadline with all subsequent I/O/retries; no DNS lookup is performed.
    pub(crate) fn connect(address:SocketAddr,envelope:Envelope,config:Config,verifier:V)->io::Result<Self>{
        if !address.ip().is_loopback() || !config.valid() || envelope.encode().is_err(){return Err(invalid())}
        let deadline=Instant::now()+config.timeout;
        let stream=TcpStream::connect_timeout(&address,config.timeout)?;
        Self::start_until(stream,envelope,config.work,deadline,verifier)
    }
}
#[cfg(test)]
#[path="client/tests.rs"]
mod tests;
