//! AT110 bounded artifact framing/dispatch. One complete request per exchange;
//! transport must accumulate fragments within fixed bounds and observe EOF.
//! This is not a listener or a credential provider. Caller identity is derived
//! from current channel evidence, never from a wire-supplied owner field.
use super::*;
#[path="transfer/codec.rs"]
mod codec;
#[path="transfer/transport.rs"]
pub(crate) mod transport;
pub(crate) use codec::{Operation,Request,Outcome,Reply,decode,encode,accept_reply,ServerEvidence,HEADER,MAX_REQUEST,MAX_REPLY};

/// Must bind the actual connection/incarnation, exact request and current grant.
/// The backend separately rechecks Evidence for every operation/disclosure.
pub(crate) trait TransferEvidence:Evidence {
    fn caller(&mut self,_connection:u64,_request:&Request<'_>)->Result<Caller,Error> {Err(Error::Authority)}
}
/// Trusted transport reserves this scratch BEFORE receiving data. This struct
/// accounts a finite dispatch allowance; it does not itself allocate a socket
/// or charge a Kernel account. Integrators must retain the real reservation.
pub(crate) struct Budget {work:u64,ingress:u64}
impl Budget {
    pub(crate) fn new(work:u64,ingress:u64,reserved_scratch:u64)->Result<Self,Error> {
        if work==0 || ingress==0 || reserved_scratch<(MAX_REQUEST+MAX_REPLY) as u64 {return Err(Error::Capacity)}
        Ok(Self{work,ingress})
    }
    pub(crate) fn remaining(&self)->(u64,u64) {(self.work,self.ingress)}
    fn spend(&mut self,n:usize)->Result<(),Error> {
        if self.work==0 {return Err(Error::Capacity)}
        self.work-=1;
        if n>MAX_REQUEST || n as u64>self.ingress {self.work=0;return Err(Error::Capacity)}
        self.ingress-=n as u64;Ok(())
    }
}
/// No success reply on malformed input, revocation or uncertain commit. Retry
/// must keep the same publication request/expected revision; reconnect alone
/// grants neither authority nor a fresh work budget.
pub(crate) fn dispatch(store:&mut ArtifactStore,connection:u64,frame:&[u8],eof:bool,
    budget:&mut Budget,e:&mut impl TransferEvidence)->Result<Reply,Error>
{
    budget.spend(frame.len())?;
    let request=decode(frame,eof)?;
    if connection==0 {return Err(Error::Authority)}
    let caller=e.caller(connection,&request)?;
    if caller.owner==0 || caller.incarnation==0 {return Err(Error::Authority)}
    let m=request.manifest;
    let mut ticket=Ticket{anchor:m.anchor,installation:m.installation,serial:request.ticket,caller};
    if !matches!(request.operation,Operation::Begin|Operation::Outcome) && store.bound(ticket)?!=m {return Err(Error::Authority)}
    let action=if matches!(request.operation,Operation::Publish|Operation::Outcome) {Action::Publish}else{Action::Upload};
    let outcome=match request.operation {
        Operation::Begin=>{
            ticket=store.reserve(m,caller,e)?;
            let(cursor,sealed,_)=store.upload_progress(ticket,e)?;
            Outcome::private(ticket.serial,cursor,sealed)
        }
        Operation::Append=>{
            store.append(ticket,request.offset,request.payload,e)?;
            let(cursor,sealed,_)=store.upload_progress(ticket,e)?;
            Outcome::private(ticket.serial,cursor,sealed)
        }
        Operation::Seal=>{
            store.seal(ticket,e)?;
            Outcome::private(ticket.serial,m.size,true)
        }
        Operation::Progress=>{
            let(cursor,sealed,_)=store.upload_progress(ticket,e)?;
            Outcome::private(ticket.serial,cursor,sealed)
        }
        Operation::Publish=>Outcome::published(ticket.serial,m.size,
            store.publish(ticket,request.publish_request,request.expected,e)?),
        Operation::Outcome=>{
            let selected=store.publication_outcome(m,caller,request.publish_request,request.expected,e)?.ok_or(Error::Conflict)?;
            ticket=store.current_ticket();Outcome::published(ticket.serial,m.size,selected)
        }
    };
    let reply=codec::reply(frame,&request,outcome)?;
    // The effect may already be durable. Denial suppresses the outcome and
    // preserves its charge; it never rolls back or reallocates the publication.
    if e.caller(connection,&request)?!=caller {return Err(Error::Authority)}
    store.auth(e,m,caller,ticket.serial,action)?;
    Ok(reply)
}
#[cfg(test)]
#[path="transfer/tests.rs"]
mod tests;
