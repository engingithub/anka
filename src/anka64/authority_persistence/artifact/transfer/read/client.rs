//! Bounded client-side exchange custody; the embedding owns the socket and
//! serializes evidence observations with each actual write/read. No guest ABI.
use super::*;
use std::time::{Duration,Instant};
const CHARGE:u64=32768;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum State {Idle,Receiving,Complete,Closed}
/// Owns both fixed frame buffers until scrub/drop. reserved_scratch is a trusted
/// pre-existing reservation, not a guest claim; this helper never refunds it.
/// Reconnect cannot reset work/deadline. Raw range bytes remain private, not code.
pub(crate) struct ReadClient {
    request:ReadRequest,frame:[u8;HEADER],reply:[u8;MAX_READ_REPLY+1],received:usize,
    channel:u64,work:u64,deadline:Instant,state:State,
}
impl ReadClient {
    pub(crate) fn new(request:ReadRequest,work:u64,timeout:Duration,reserved_scratch:u64)->Result<Self,Error> {
        if work==0 || timeout.is_zero() || reserved_scratch<CHARGE || std::mem::size_of::<Self>()as u64>CHARGE {return Err(Error::Capacity)}
        Ok(Self{request,frame:encode_read(request)?,reply:[0;MAX_READ_REPLY+1],received:0,channel:0,work,
            deadline:Instant::now().checked_add(timeout).ok_or(Error::Capacity)?,state:State::Idle})
    }
    fn check_deadline(&mut self)->Result<(),Error> {
        if Instant::now()>=self.deadline {self.close();Err(Error::ExpiredRequest)}else{Ok(())}
    }
    fn spend(&mut self)->Result<(),Error> {
        if self.state==State::Closed {return Err(Error::Authority)}
        if Instant::now()>=self.deadline {self.close();return Err(Error::ExpiredRequest)}
        self.work=match self.work.checked_sub(1){Some(n)=>n,None=>{self.close();return Err(Error::Capacity)}};Ok(())
    }
    pub(crate) fn begin(&mut self,channel:u64,e:&mut impl ReadServerEvidence)->Result<(),Error> {
        self.spend()?;
        if self.state!=State::Idle || channel==0 || e.before_send(channel,&self.request)!=Verdict::Valid {
            self.close();return Err(Error::Authority)
        }
        self.check_deadline()?;self.channel=channel;self.state=State::Receiving;Ok(())
    }
    /// Call in the same authority/IO lane immediately before each request write.
    /// A returned slice is not a saved authorization for a later write.
    pub(crate) fn request_fragment(&mut self,channel:u64,offset:usize,count:usize,e:&mut impl ReadServerEvidence)->Result<&[u8],Error> {
        self.spend()?;
        if self.state!=State::Receiving || self.channel!=channel || count==0 || count>64
            || offset.checked_add(count).is_none_or(|end|end>HEADER)
            || e.before_send(channel,&self.request)!=Verdict::Valid {self.close();return Err(Error::Authority)}
        self.check_deadline()?;Ok(&self.frame[offset..offset+count])
    }
    /// Append only bytes from the actual bound stream; EOF means real read(0),
    /// never an empty nonblocking poll. Partial replies expose no payload.
    pub(crate) fn receive(&mut self,channel:u64,bytes:&[u8],eof:bool,e:&mut impl ReadServerEvidence)->Result<bool,Error> {
        self.spend()?;
        if self.state!=State::Receiving || channel!=self.channel || bytes.len()>4096
            || self.received.checked_add(bytes.len()).is_none_or(|n|n>self.reply.len()) {
            self.close();return Err(Error::InvalidRequest)
        }
        self.reply[self.received..self.received+bytes.len()].copy_from_slice(bytes);self.received+=bytes.len();
        if self.received>READ_REPLY_PREFIX+self.request.count as usize {self.close();return Err(Error::InvalidRequest)}
        if !eof {return Ok(false)}
        if let Err(err)=accept_read_reply(&self.frame,&self.reply[..self.received],true,channel,e) {self.close();return Err(err)}
        if Instant::now()>=self.deadline {self.close();return Err(Error::ExpiredRequest)}
        self.state=State::Complete;Ok(true)
    }
    pub(crate) fn payload(&mut self,e:&mut impl ReadServerEvidence)->Result<&[u8],Error> {
        self.spend()?;
        if self.state!=State::Complete {return Err(Error::Conflict)}
        if e.current(self.channel,&self.request,&self.reply[..self.received])!=Verdict::Valid {self.close();return Err(Error::Authority)}
        if Instant::now()>=self.deadline {self.close();return Err(Error::ExpiredRequest)}
        Ok(&self.reply[READ_REPLY_PREFIX..self.received])
    }
    /// Lost/incomplete exchange only. Close the old actual stream before calling;
    /// the adapter must bind the fresh channel to a new authenticated stream.
    pub(crate) fn retry(&mut self,new_channel:u64,e:&mut impl ReadServerEvidence)->Result<(),Error> {
        self.spend()?;
        if self.state!=State::Receiving || new_channel==0 || new_channel==self.channel {self.close();return Err(Error::Authority)}
        let correlation=match self.request.correlation.checked_add(1){Some(n)=>n,None=>{self.close();return Err(Error::Exhausted)}};
        let next=ReadRequest{correlation,..self.request};
        if e.before_send(new_channel,&next)!=Verdict::Valid {self.close();return Err(Error::Authority)}
        self.check_deadline()?;self.scrub_reply();self.request=next;self.frame=encode_read(next)?;self.channel=new_channel;Ok(())
    }
    pub(crate) fn remaining(&self)->u64 {self.work}
    fn scrub_reply(&mut self) {
        for b in &mut self.reply {unsafe {std::ptr::write_volatile(b,0)}}self.received=0;
    }
    pub(crate) fn close(&mut self) {
        self.state=State::Closed;self.scrub_reply();
        for b in &mut self.frame {unsafe {std::ptr::write_volatile(b,0)}}
    }
}
impl Drop for ReadClient {fn drop(&mut self){self.close();}}
#[cfg(test)]
#[path="client/tests.rs"]
mod tests;
