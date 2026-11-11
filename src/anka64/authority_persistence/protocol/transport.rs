//! Bounded, manually-polled localhost reference transport. This is not an
//! authenticated network service: Peer comes from a trusted out-of-band binder.
//! Production callers must retain DenyAll until evidence verification is wired.
use super::*;
use std::io::{self,Read,Write};
use std::net::{SocketAddr,TcpListener,TcpStream};
use std::sync::atomic::{AtomicU64,Ordering};
use std::time::{Duration,Instant};
const CHARGE:u64=384; // Logical protocol charge, not allocator/socket RSS.
static SERVICES:AtomicU64=AtomicU64::new(1);
// Temporary accept reservation refunds on rejected binding, setup failure and
// unwinding from an embedding callback. Once installed, the slot owns the charge.
struct Reservation<'a>{live:&'a mut usize,bytes:&'a mut u64,installed:bool}
impl<'a> Reservation<'a>{fn new(live:&'a mut usize,bytes:&'a mut u64)->Self{
    *live+=1;*bytes+=CHARGE;Self{live,bytes,installed:false}
}}
impl Drop for Reservation<'_>{fn drop(&mut self){if !self.installed{*self.live-=1;*self.bytes-=CHARGE;}}}
#[derive(Clone,Copy,Debug)]
pub(crate) struct Config {pub slots:usize,pub byte_limit:u64,pub work:u64,pub timeout:Duration}
impl Default for Config {fn default()->Self{Self{slots:4,byte_limit:1536,work:512,timeout:Duration::from_secs(5)}}}
impl Config {
    fn valid(self)->bool{(1..=64).contains(&self.slots) && self.byte_limit>=CHARGE &&
        (1..=512).contains(&self.work) && !self.timeout.is_zero() && self.timeout<=Duration::from_secs(60)}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct Ticket {service:u64,sequence:u64}
#[derive(Debug)]
pub(crate) struct Poll {pub accepted:Option<Ticket>,pub closed:usize,pub live:usize}
struct Connection<S,P> {
    stream:S,peer:P,id:u64,deadline:Instant,work:u64,
    input:[u8;REQUEST_BYTES+1],received:usize,
    output:Option<[u8;REPLY_BYTES]>,sent:usize,
}
impl<S,P> Connection<S,P> {
    fn new(stream:S,peer:P,id:u64,deadline:Instant,work:u64)->Self{
        Self{stream,peer,id,deadline,work,input:[0;REQUEST_BYTES+1],received:0,output:None,sent:0}
    }
}
fn transient(e:&io::Error)->bool{matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)}
// true means retain; false means close and refund the owning slot. One read OR
// write per poll. EOF dispatch transitions once to output; never back to input.
fn step<S:Read+Write,B:DurableRecord,V:Verifier>(c:&mut Connection<S,V::Peer>,
    b:&mut B,v:&mut V,mut budget:DispatchBudget,capacity:bool,now:Instant)->bool
{
    if now>=c.deadline || c.work==0{return false}
    budget.work=c.work;c.work-=1;
    if let Some(output)=c.output.as_ref(){
        let Ok(e)=Envelope::decode(&c.input[..c.received],true) else{return false};
        // Recheck at EVERY partial output write, not only at commit. Previously
        // delivered bytes cannot be recalled; revocation suppresses the suffix.
        if super::dispatch::checked(v,&c.peer,e.request).is_none(){return false}
        if Instant::now()>=c.deadline{return false}
        return match c.stream.write(&output[c.sent..]) {
            Ok(0)=>false,
            Ok(n) if n<=REPLY_BYTES-c.sent=>{c.sent+=n;c.sent<REPLY_BYTES},
            Ok(_)=>false,
            Err(e)=>transient(&e),
        }
    }
    match c.stream.read(&mut c.input[c.received..]) {
        Ok(0)=>{
            if c.received!=REQUEST_BYTES || Instant::now()>=c.deadline{return false}
            // Actual EOF, actual owned reservation, fresh work snapshot.
            match dispatch(b,v,&c.peer,&c.input[..c.received],true,budget,capacity){
                Ok(reply)=>{c.output=Some(reply);true},Err(_)=>false,
            }
        },
        Ok(n) if n<=c.input.len()-c.received=>{c.received+=n;c.received<=REQUEST_BYTES},
        Ok(_)=>false,
        Err(e)=>transient(&e),
    }
}
/// Owns backend/verifier and serializes dispatches on this service lane. A binder
/// returning None rejects a connection without reading it. SocketAddr is only a
/// routing observation; it is NOT authenticated identity. The binder must not
/// create authority merely from loopback address or claimed request bytes.
pub(crate) struct Server<B:DurableRecord,V:Verifier> {
    listener:Option<TcpListener>,backend:B,verifier:V,config:Config,
    connections:Vec<Option<Connection<TcpStream,V::Peer>>>,
    live:usize,bytes:u64,service:u64,next:u64,
}
impl<B:DurableRecord,V:Verifier> Server<B,V> {
    pub(crate) fn bind(address:SocketAddr,config:Config,backend:B,verifier:V)->io::Result<Self>{
        if !address.ip().is_loopback() || !config.valid(){return Err(io::Error::new(io::ErrorKind::InvalidInput,"loopback/configuration required"))}
        let service=SERVICES.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|n|n.checked_add(1))
            .map_err(|_|io::Error::other("service identity exhausted"))?;
        let listener=TcpListener::bind(address)?;listener.set_nonblocking(true)?;
        let connections=(0..config.slots).map(|_|None).collect();
        Ok(Self{listener:Some(listener),backend,verifier,config,connections,live:0,bytes:0,service,next:0})
    }
    pub(crate) fn address(&self)->io::Result<SocketAddr>{self.listener.as_ref().ok_or_else(||io::Error::other("closed"))?.local_addr()}
    pub(crate) fn usage(&self)->(usize,u64){(self.live,self.bytes)}
    fn remove(&mut self,i:usize)->bool{
        if self.connections[i].take().is_some(){self.live-=1;self.bytes-=CHARGE;true}else{false}
    }
    pub(crate) fn cancel(&mut self,ticket:Ticket)->bool{
        if ticket.service!=self.service{return false}
        if let Some(i)=self.connections.iter().position(|c|c.as_ref().is_some_and(|c|c.id==ticket.sequence)){self.remove(i)}else{false}
    }
    pub(crate) fn shutdown(&mut self){self.listener.take();for i in 0..self.connections.len(){self.remove(i);}}
    /// Call at a suitable cadence (e.g. 10 ms when idle). WouldBlock/Interrupted
    /// consume finite work too. No sleeping/spinning or worker threads inside.
    /// Backend filesystem sync remains synchronous and outside this poll bound.
    pub(crate) fn poll<F:FnMut(SocketAddr)->Option<V::Peer>>(&mut self,bind_peer:&mut F,capacity:bool)->io::Result<Poll>{
        let mut report=Poll{accepted:None,closed:0,live:self.live};
        for i in 0..self.connections.len(){
            let budget=DispatchBudget{slots:self.live.saturating_sub(1) as u64,slot_limit:self.config.slots as u64,
                bytes:self.bytes.saturating_sub(CHARGE),byte_limit:self.config.byte_limit,
                work:1,now:0,deadline:1};
            // now/deadline represent the boolean Instant guard in step; subtract
            // ONLY this connection's charge to recover its pre-acquire snapshot.
            let keep=match self.connections[i].as_mut(){None=>continue,Some(c)=>
                step(c,&mut self.backend,&mut self.verifier,budget,capacity,Instant::now())};
            if !keep && self.remove(i){report.closed+=1;}
        }
        if self.live<self.config.slots && self.config.byte_limit.checked_sub(self.bytes).is_some_and(|n|n>=CHARGE){
            if let (Some(listener),Some(next))=(self.listener.as_ref(),self.next.checked_add(1)){
                match listener.accept(){
                    Ok((stream,address))=>{
                        // Reserve BEFORE binding or receiving bytes. The local
                        // temporary owns the reservation until inserted or dropped.
                        let mut reservation=Reservation::new(&mut self.live,&mut self.bytes);
                        let deadline=Instant::now()+self.config.timeout;
                        let peer=bind_peer(address);
                        let setup=stream.set_nonblocking(true);
                        if let (Some(peer),Ok(()))=(peer,setup){
                            let i=self.connections.iter().position(Option::is_none).expect("slot accounting");
                            self.next=next;
                            self.connections[i]=Some(Connection::new(stream,peer,next,deadline,self.config.work));
                            reservation.installed=true;
                            report.accepted=Some(Ticket{service:self.service,sequence:next});
                        }else{report.closed+=1;}
                    },
                    Err(e) if transient(&e)=>{},Err(e)=>return Err(e),
                }
            }
        }
        report.live=self.live;Ok(report)
    }
}
#[cfg(test)]
#[path="transport/tests.rs"]
mod tests;

#[path="transport/guarded_server.rs"]
pub(crate) mod guarded_server;
