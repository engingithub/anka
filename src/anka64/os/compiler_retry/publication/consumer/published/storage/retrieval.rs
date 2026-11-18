//! Charged private retrieval, not linked publication or executable admission.
use super::*;
use crate::anka64::authority_persistence::artifact::retrieval::{RetrievalBudget,RetrievalLimits,RetrievalPolicy,StoredEnvelope};

// Covers the fixed view/guard, budget and bounded validation scratch. The file
// backend's own checksum buffer is already charged by AS110's retained ledger.
pub(super) const RETRIEVAL_OVERHEAD:u64=32768;

/// Exclusive Kernel borrow prevents custodian teardown/rebinding during private
/// custody. No Vec, heap pointer, receipt or execution grant can escape this guard.
pub(crate) struct RetrievedCompilerImage<'k> {
    pub(super) kernel:&'k mut Kernel,
    pub(super) owner:AllocationOwner,
    pub(super) charge:Option<HostStorageReservation>,
    pub(super) bytes:Vec<u8>,
    pub(super) manifest:Manifest,
    pub(super) budget:Option<RetrievalBudget>,
    pub(super) origin:Option<super::launch::ReadOrigin>,
    pub(super) read_verifier:Option<crate::anka64::os::typed_socket::select::ServerLane>,
}
impl<'k> RetrievedCompilerImage<'k> {
    pub(super) fn reserve(kernel:&'k mut Kernel,manifest:Manifest)->Result<Self,CompilerStorageError>{
        if manifest.role!=2 || !matches!(manifest.profile,1|2) || manifest.dependencies==0 {return Err(StoreError::InvalidRequest.into())}
        let n=usize::try_from(manifest.size).map_err(|_|StoreError::Capacity)?;
        let logical=manifest.size.checked_add(RETRIEVAL_OVERHEAD).ok_or(StoreError::Capacity)?;
        let (owner,account)=kernel.compiler_candidate_account().map_err(CompilerLinkError::from)?;
        let charge=kernel.fabric.scoped_pointers.reserve_host_storage(account,logical,kernel.fabric.scoped_pointers.revision())
            .map_err(CompilerLinkError::from)?;
        let mut result=Self{kernel,owner,charge:Some(charge),bytes:Vec::new(),manifest,budget:None,origin:None,read_verifier:None};
        result.bytes.try_reserve_exact(n).map_err(|_|StoreError::Capacity)?;
        if result.bytes.capacity()!=n {return Err(StoreError::Capacity.into())}
        result.bytes.resize(n,0);Ok(result)
    }
    pub(super) fn recheck(&self)->Result<(),CompilerStorageError>{
        if self.kernel.compiler_candidate_custodian().map_err(CompilerLinkError::from)?!=self.owner {return Err(CompilerLinkError::Binding.into())}
        self.kernel.fabric.scoped_pointers.check_host_storage(self.charge.ok_or(CompilerLinkError::Binding)?,
            self.owner,self.kernel.fabric.scoped_pointers.revision()).map_err(CompilerLinkError::from)?;Ok(())
    }
    #[cfg(test)]
    pub(crate) fn test_kernel(&self)->&Kernel {self.kernel}

    pub(crate) fn envelope(&self)->Result<StoredEnvelope<'_>,CompilerStorageError> {
        if self.kernel.compiler_candidate_custodian().map_err(CompilerLinkError::from)?!=self.owner {return Err(CompilerLinkError::Binding.into())}
        self.kernel.fabric.scoped_pointers.check_host_storage(self.charge.ok_or(CompilerLinkError::Binding)?,
            self.owner,self.kernel.fabric.scoped_pointers.revision()).map_err(CompilerLinkError::from)?;
        Ok(StoredEnvelope::decode(&self.bytes,self.manifest)?)
    }
}
impl Drop for RetrievedCompilerImage<'_> {
    fn drop(&mut self) {
        // All bytes are private host memory; no guest alias, DMA or external
        // work handle was ever issued. Destroy storage before refund, on every
        // error/unwind as well as successful guard release.
        for byte in &mut self.bytes {
            // SAFETY: exclusive live u8 references; volatile prevents dead-store
            // elimination of scrubbing before the allocation is returned.
            unsafe {std::ptr::write_volatile(byte,0)};
        }
        drop(std::mem::take(&mut self.bytes));
        drop(self.read_verifier.take());
        if let Some(charge)=self.charge.take() {
            let _=self.kernel.fabric.scoped_pointers.release_host_storage(charge);
        }
    }
}
impl Kernel {
    /// Returns only a charged immutable envelope snapshot. Fresh publication,
    /// execute grants and local code/frame/context reconstruction come later.
    /// `caller` is a storage evidence identity; it is NOT a raw process key.
    pub(crate) fn retrieve_stored_compiler_image<'k>(&'k mut self,store:&mut ArtifactStore,
        manifest:Manifest,caller:Caller,limits:RetrievalLimits,policy:&mut impl RetrievalPolicy)
        ->Result<RetrievedCompilerImage<'k>,CompilerStorageError>
    {
        let mut budget=limits.start(manifest.size)?;
        let mut result=RetrievedCompilerImage::reserve(self,manifest)?;
        let scope=store.read_published_into(manifest,caller,&mut result.bytes,policy,&mut budget)?;
        budget.bytes(manifest.size)?;
        let envelope=StoredEnvelope::decode(&result.bytes,manifest)?;
        budget.spend(envelope.dependency_count() as u64+1)?;
        if policy.validate_retrieved(scope,envelope)!=Verdict::Valid {return Err(StoreError::Authority.into())}
        budget.check()?;
        store.recheck_retrieval(scope,policy,&mut budget)?;
        // Reauthenticate the actual shared account; the return value stays in
        // this Kernel and cannot be used as an admission token elsewhere.
        result.envelope()?;
        result.budget=Some(budget);
        result.origin=Some(super::launch::ReadOrigin::File(scope));
        Ok(result)
    }
}
