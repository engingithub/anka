//! Deterministic ordered-stream adapter for the rebuilt guest. This boundary is
//! downstream of TCP reassembly. It cannot submit NIC work or access guest memory.
use super::Kernel;
use crate::anka64::os::{typed_socket::{SocketTicket,SOCKET_AGAIN,SOCKET_WINDOW},SYS_SOCKET_RECV,SYS_SOCKET_SEND};
use crate::anka64::state::ProcessKey;

pub(crate) struct DeveloperSocketAuthority { _private: () }
impl DeveloperSocketAuthority { pub(crate) fn provision()->Self { Self{_private:()} } }

pub(crate) struct OrderedStream<'a> {
    authority:&'a DeveloperSocketAuthority, first:&'a [u8], second:&'a [u8],
    fin:bool, window:usize,
}
impl<'a> OrderedStream<'a> {
    pub(crate) fn new(authority:&'a DeveloperSocketAuthority, first:&'a [u8],second:&'a [u8],
        fin:bool,window:usize)->Result<Self,&'static str> {
        if !(1..=SOCKET_WINDOW).contains(&window) || first.len()>SOCKET_WINDOW
            || second.len()>SOCKET_WINDOW-first.len() { return Err("invalid stream budget"); }
        Ok(Self{authority,first,second,fin,window})
    }
}
#[derive(Debug,Default,Clone,Copy,PartialEq,Eq)]
pub(crate) struct StreamProgress {
    pub(crate) receive_waits:usize, pub(crate) send_waits:usize, pub(crate) short_sends:usize,
}
pub(super) struct Bridge<'a> {
    stream:OrderedStream<'a>,ticket:Option<SocketTicket>,second_pending:bool,
    pub(super) progress:StreamProgress,
}
impl<'a> Bridge<'a> {
    pub(super) fn new(stream:OrderedStream<'a>)->Self {
        let second_pending=!stream.second.is_empty();
        Self{stream,ticket:None,second_pending,progress:StreamProgress::default()}
    }
    pub(super) fn attach(&mut self,k:&mut Kernel,child:ProcessKey)->Result<(),()> {
        let t=k.bind_application_socket(child,self.stream.window,self.stream.authority).map_err(|_|())?;
        self.ticket=Some(t);
        k.deliver_socket(t,self.stream.first,!self.second_pending && self.stream.fin)
    }
    pub(super) fn after_round(&mut self,k:&mut Kernel)->Result<(),()> {
        let Some((op,requested,result))=k.take_socket_call() else {return Ok(())};
        let t=self.ticket.ok_or(())?;
        match (op,result) {
            (SYS_SOCKET_RECV,SOCKET_AGAIN)=>{
                self.progress.receive_waits+=1;
                // In this deterministic adapter there is no future transport
                // event after the second fragment. Bound unsuccessful polling;
                // never manufacture FIN to terminate an open stream.
                if self.progress.receive_waits>64 {return Err(());}
                if self.second_pending {
                    k.deliver_socket(t,self.stream.second,self.stream.fin)?;
                    self.second_pending=false;
                }
            }
            (SYS_SOCKET_SEND,SOCKET_AGAIN)=>{self.progress.send_waits+=1;self.drain(k,t)?;}
            (SYS_SOCKET_SEND,n) if n>0 && n<requested=>{self.progress.short_sends+=1;}
            (SYS_SOCKET_SEND,n) if n==requested && n!=0=>{self.drain(k,t)?;}
            _=>{}
        }
        Ok(())
    }
    fn drain(&self,k:&mut Kernel,t:SocketTicket)->Result<(),()> {
        // byte_output is the charged report buffer. Socket mode disallows
        // console writes. Limit logical wire capture independently of capacity.
        let mut bytes=[0u8;SOCKET_WINDOW];
        let room=SOCKET_WINDOW.checked_sub(k.byte_output.len()).ok_or(())?;
        // Never dequeue a prefix that cannot fit the capture; full negotiated
        // window is an upper bound, but charge only the actual pending bytes.
        let pending=k.socket_pending_tx(t)?;
        if pending>room || pending>k.byte_output.capacity()-k.byte_output.len(){return Err(());}
        let n=k.take_socket_tx(t,&mut bytes[..pending])?;
        k.byte_output.extend_from_slice(&bytes[..n]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn s2_socket_plan_bounds_both_fragments_and_transmit_window() {
        let auth=DeveloperSocketAuthority::provision();let bytes=[42u8;1024];
        assert!(OrderedStream::new(&auth,&bytes[..1023],&bytes[..1],false,1).is_ok());
        assert!(OrderedStream::new(&auth,&bytes,&bytes[..1],true,1).is_err());
        for w in [0,1025,usize::MAX] {assert!(OrderedStream::new(&auth,&[],&[],true,w).is_err());}
    }
}
