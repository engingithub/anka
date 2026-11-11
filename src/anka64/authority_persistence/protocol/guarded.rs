//! Guard-scoped reference dispatch. This is an additive entry point; the older
//! Verifier-only transport is not silently claimed to provide this exclusion.
use super::*;
use super::super::evidence::{CallerProvider,registry::{Registry,Handle,UseBudget,RegistryError}};
use std::io::{self,Write};

#[derive(Debug,PartialEq,Eq)]
pub(crate) enum DispatchError { Wire(WireError), Registry(RegistryError), Budget }
#[derive(Debug)]
pub(crate) enum DeliveryError { Registry(RegistryError), Unbound, Closed, Io(io::Error) }
/// A trusted transport adapter must bind this writer to its actual authenticated
/// channel handle. Default denial; addresses and caller-supplied IDs do not bind it.
pub(crate) trait ReplySink:Write { fn peer(&self)->Option<Handle> {None} }
/// Private bytes cannot be retrieved without a new guarded disclosure. Keep the
/// embedding's transport-slot reservation until completion/cancel/drop. Fixed
/// storage only; no detached uncharged Vec of response data is returned.
pub(crate) struct PendingReply { peer:Handle, envelope:Envelope, bytes:[u8;REPLY_BYTES], sent:usize, closed:bool }
impl PendingReply {
    #[cfg(test)]
    pub(crate) fn sent_bytes(&self) -> usize { self.sent }
    pub(crate) fn complete(&self)->bool {self.sent==REPLY_BYTES}
    pub(crate) fn cancel(&mut self) {self.bytes.fill(0);self.closed=true;}
    /// At most one nonblocking write. Both admission and actual write occur under
    /// the same lane. WouldBlock/Interrupted retain the prefix and spend one unit.
    pub(crate) fn write_once<P:CallerProvider,W:ReplySink>(&mut self,registry:&Registry<P>,budget:&mut UseBudget,sink:&mut W)->Result<usize,DeliveryError> {
        if self.closed {return Err(DeliveryError::Closed)}
        if self.complete() {return Ok(0)}
        if sink.peer()!=Some(self.peer) {self.cancel();return Err(DeliveryError::Unbound)}
        let result=(|| {
            let mut guard=registry.acquire(self.peer,self.envelope.request,budget)?;
            guard.disclose(self.envelope.request,||sink.write(&self.bytes[self.sent..]))
        })();
        match result {
            Err(e)=>{if e!=RegistryError::Busy {self.cancel();}Err(DeliveryError::Registry(e))},
            Ok(Ok(n)) if n>0 && n<=REPLY_BYTES-self.sent=>{
                self.sent+=n;if self.complete(){self.bytes.fill(0);}Ok(n)
            },
            Ok(Err(e)) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)=>Err(DeliveryError::Io(e)),
            Ok(Err(e))=>{self.cancel();Err(DeliveryError::Io(e))},
            Ok(Ok(_))=>{self.cancel();Err(DeliveryError::Io(io::Error::new(io::ErrorKind::WriteZero,"invalid reply write progress")))},
        }
    }
}
/// Canonical parse precedes authority/provider/backend calls. The guard is kept
/// across load + compare-and-commit, including error/unwind. It is released before
/// network waiting. PendingReply must revalidate to release even a single byte.
pub(crate) fn dispatch<B:DurableRecord,P:CallerProvider>(backend:&mut B,registry:&Registry<P>,peer:Handle,
    bytes:&[u8],ended:bool,transport_budget:DispatchBudget,budget:&mut UseBudget,capacity:bool)->Result<PendingReply,DispatchError>
{
    let e=Envelope::decode(bytes,ended).map_err(DispatchError::Wire)?;
    if !transport_budget.admissible() {return Err(DispatchError::Budget)}
    let result={
        let mut guard=registry.acquire(peer,e.request,budget).map_err(DispatchError::Registry)?;
        guard.execute(backend,capacity).map_err(DispatchError::Registry)?
    };
    let reply=match result {
        Ok(o)=>Reply::success(e,o).unwrap_or(Reply::failure(e,Status::Uncertain).map_err(DispatchError::Wire)?),
        Err(e2)=>Reply::failure(e,super::dispatch::status(e2)).map_err(DispatchError::Wire)?,
    };
    Ok(PendingReply {peer,envelope:e,bytes:reply.encode(),sent:0,closed:false})
}

impl Drop for PendingReply {
    fn drop(&mut self) {self.bytes.fill(0);}
}
