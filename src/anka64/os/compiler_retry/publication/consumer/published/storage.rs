//! CS110: borrowed, charged linked publication -> durable AS110 envelope.
//! Host integration only. The policy is trusted infrastructure, not guest claims.
use super::*;
use crate::anka64::authority_persistence::{Error as StoreError,Verdict};
use crate::anka64::authority_persistence::artifact::{ArtifactStore,Caller,Evidence,Manifest,Scope,Selection};
use std::io::Read;
mod envelope;
use envelope::Envelope;

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct PersistentDependency {
    pub anchor:u64,pub installation:u64,pub artifact:u64,pub generation:u64,pub provenance:u64,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct PersistentLinkIdentity {
    pub anchor:u64,pub installation:u64,pub artifact:u64,pub generation:u64,
    pub image:u64,pub metadata:u64,pub dependencies:u64,pub provenance:u64,
}
/// Maps authenticated live receipts to stable identities. current_binding must
/// independently establish exact identity mapping AND durable retention of the
/// ordered dependencies and provenance. IDs themselves are not authentication.
/// Implementations may not substitute guest claims for these obligations.
pub(crate) trait CompilerStoragePolicy {
    fn bind_link(&mut self,_receipt:&LinkedCompilerReceipt<'_>,_caller:Caller)
        ->Result<PersistentLinkIdentity,StoreError> {Err(StoreError::Authority)}
    fn bind_module(&mut self,_receipt:&CompilerPublicationReceipt<'_>,_bytes:&[u8],_index:usize)
        ->Result<PersistentDependency,StoreError> {Err(StoreError::Authority)}
    fn current_binding(&mut self,_manifest:Manifest,_dependencies:&[PersistentDependency])->Verdict {Verdict::Unknown}
    fn authorize(&mut self,_scope:Scope)->Verdict {Verdict::Unknown}
}
#[derive(Debug)]
pub(crate) enum CompilerStorageError {Publication(CompilerLinkError),Store(StoreError)}
impl From<CompilerLinkError> for CompilerStorageError {fn from(e:CompilerLinkError)->Self {Self::Publication(e)}}
impl From<StoreError> for CompilerStorageError {fn from(e:StoreError)->Self {Self::Store(e)}}

struct Export<'a> {kernel:&'a mut Kernel,charge:Option<HostStorageReservation>,dependencies:Vec<PersistentDependency>}
impl Drop for Export<'_> {
    fn drop(&mut self) {
        // Destroy charged backing before releasing the reservation, including unwind.
        drop(std::mem::take(&mut self.dependencies));
        if let Some(c)=self.charge.take() {let _=self.kernel.fabric.scoped_pointers.release_host_storage(c);}
    }
}
struct Proof<'a,'p,P> {envelope:Envelope<'a>,policy:&'p mut P}
impl<P:CompilerStoragePolicy> Evidence for Proof<'_,'_,P> {
    fn authorize(&mut self,s:Scope)->Verdict {
        if s.manifest!=self.envelope.manifest || self.policy.current_binding(s.manifest,self.envelope.dependencies)!=Verdict::Valid {
            return Verdict::Invalid
        }
        self.policy.authorize(s)
    }
    fn inspect(&mut self,input:&mut dyn Read)->Result<Manifest,StoreError> {
        let m=self.envelope.manifest;
        if self.policy.current_binding(m,self.envelope.dependencies)!=Verdict::Valid {return Err(StoreError::Authority)}
        let mut got=[0u8;4096];let mut want=[0u8;4096];let mut offset=0;
        while offset<m.size {
            let n=(m.size-offset).min(4096) as usize;
            input.read_exact(&mut got[..n]).map_err(|_|StoreError::CorruptRecord)?;
            self.envelope.copy(offset,&mut want[..n])?;
            if got[..n]!=want[..n] {return Err(StoreError::CorruptRecord)}
            offset+=n as u64;
        }
        if input.read(&mut got[..1]).map_err(|_|StoreError::CorruptRecord)?!=0 {return Err(StoreError::CorruptRecord)}
        if self.policy.current_binding(m,self.envelope.dependencies)!=Verdict::Valid {return Err(StoreError::Authority)}
        Ok(m)
    }
}
impl Kernel {
    /// No application authority is minted. Failure releases only export scratch;
    /// backend staging/uncertain commits remain charged and recoverable.
    pub(crate) fn persist_linked_compiler_publication(&mut self,epoch:u64,store:&mut ArtifactStore,
        caller:Caller,request:u64,expected:u64,policy:&mut impl CompilerStoragePolicy)
        ->Result<Selection,CompilerStorageError>
    {
        if request==0 || caller.owner==0 || caller.incarnation==0 {return Err(StoreError::InvalidRequest.into())}
        self.validate_linked_compiler_publication(epoch)?;
        let count=self.compiler_publications.links[&epoch].epochs.len();
        // Includes dependency vector, canonical header, nested comparison/IO
        // stack buffers and bookkeeping. Existing image custody stays charged.
        let bytes=(count as u64).checked_mul(std::mem::size_of::<PersistentDependency>() as u64)
            .and_then(|n|n.checked_add(32768)).ok_or(StoreError::Capacity)?;
        let (_,account)=self.compiler_candidate_account().map_err(CompilerLinkError::from)?;
        let charge=self.fabric.scoped_pointers.reserve_host_storage(account,bytes,self.fabric.scoped_pointers.revision())
            .map_err(CompilerLinkError::from)?;
        let mut export=Export{kernel:self,charge:Some(charge),dependencies:Vec::new()};
        export.dependencies.try_reserve_exact(count).map_err(|_|StoreError::Capacity)?;
        for index in 0..count {
            let link=&export.kernel.compiler_publications.links[&epoch];
            let receipt=export.kernel.compiler_publication_receipt(link.epochs[index]).ok_or(StoreError::Authority)?;
            let dependency=policy.bind_module(&receipt,link.modules[index].bytes(),index)?;
            export.dependencies.push(dependency);
        }
        let receipt=export.kernel.linked_compiler_receipt(epoch)?;
        let identity=policy.bind_link(&receipt,caller)?;
        let envelope=Envelope::new(receipt.image,receipt.profile,identity,&export.dependencies)?;
        let m=envelope.manifest;
        let mut proof=Proof{envelope,policy};
        if let Some(outcome)=store.publication_outcome(m,caller,request,expected,&mut proof)? {return Ok(outcome)}
        let ticket=store.reserve(m,caller,&mut proof)?;
        let (mut cursor,sealed,window)=store.upload_progress(ticket,&mut proof)?;
        let mut buffer=[0u8;4096];
        if !sealed {
            while cursor<m.size {
                let n=(m.size-cursor).min(window) as usize;
                proof.envelope.copy(cursor,&mut buffer[..n])?;
                store.append(ticket,cursor,&buffer[..n],&mut proof)?;
                cursor+=n as u64;
            }
            store.seal(ticket,&mut proof)?;
        }
        Ok(store.publish(ticket,request,expected,&mut proof)?)
    }
}
#[cfg(test)] mod tests;
