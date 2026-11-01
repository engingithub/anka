//! Shared-Kernel publications -> existing protected guest linker.
//! Input and retained-result storage stay charged for the entire borrow. This
//! also reserves the bounded isolated guest linker before constructing it.
use super::*;
mod published;
pub(super) use published::PublishedCompilerLink;
pub(crate) use published::LinkedCompilerReceipt;
pub(crate) use published::LinkedCompilerRunReport;
use crate::anka64::ankald::{self, ApplicationLinkProfile, AnkaldLinkedImage};
use crate::anka64::dev_runner::DeveloperExecutionAuthority;
use crate::anka64::pointer_frames::ValidatedPointerModule;

#[derive(Debug)]
pub(crate) enum CompilerLinkError {
    Authority,
    Binding,
    Storage,
    Publication(PublicationError),
    Heap(HeapError),
    Link(ankald::AnkaldError),
    Executable(ankald::AnkaldPublishError),
    Register(crate::anka64::dev_shell::DevelopmentShellError),
    Run(crate::anka64::dev_runner::DevelopmentRunError),
}
impl From<PublicationError> for CompilerLinkError {
    fn from(e: PublicationError) -> Self { Self::Publication(e) }
}
impl From<HeapError> for CompilerLinkError {
    fn from(e: HeapError) -> Self { Self::Heap(e) }
}

/// No detached Vec, caller-supplied receipt, or guessed cross-Kernel handle.
/// The exclusive borrow keeps input publications/custodian alive across linking.
/// Dropping this guard releases ONLY its staging, never the input publications.
pub(crate) struct CompilerPublishedModules<'k> {
    kernel: &'k mut Kernel,
    owner: AllocationOwner,
    reservation: Option<HostStorageReservation>,
    image_reservation: Option<HostStorageReservation>,
    transport_reservation: Option<HostStorageReservation>,
    epochs: Vec<u64>,
    modules: Vec<ValidatedPointerModule>,
    linker: Vec<u8>,
    profile: ApplicationLinkProfile,
    image: Option<AnkaldLinkedImage>,
}

/// Borrowed linked data, not a publication receipt or executable authority.
/// Keep the guard while publishing/loading through the separate trusted gates.
pub(crate) struct CompilerLinkedOutput<'k> { inputs: CompilerPublishedModules<'k> }
impl CompilerLinkedOutput<'_> {
    pub(crate) fn image(&self) -> &AnkaldLinkedImage { self.inputs.image.as_ref().unwrap() }
    pub(crate) fn profile(&self) -> ApplicationLinkProfile { self.inputs.profile }
    pub(crate) fn dependency_epochs(&self) -> &[u64] { &self.inputs.epochs }
}
impl Drop for CompilerPublishedModules<'_> {
    fn drop(&mut self) {
        // Destroy payload BEFORE refund, including on any intermediate failure.
        drop(self.image.take());
        drop(std::mem::take(&mut self.modules));
        drop(std::mem::take(&mut self.linker));
        drop(std::mem::take(&mut self.epochs));
        if let Some(r)=self.transport_reservation.take() {
            let _=self.kernel.fabric.scoped_pointers.release_host_storage(r);
        }
        if let Some(r)=self.image_reservation.take() {
            let _=self.kernel.fabric.scoped_pointers.release_host_storage(r);
        }
        if let Some(r)=self.reservation.take() {
            let _=self.kernel.fabric.scoped_pointers.release_host_storage(r);
        }
        // A release failure retains its charge, consistent with capture guards.
    }
}

impl Kernel {
    fn recheck_link_publication(&mut self, epoch:u64) -> Result<(),CompilerLinkError> {
        // Validate live protected custody and host reservation before borrowing
        // the private immutable record. Recheck original sealed sources/tools:
        // yesterday's successful publication is not today's authority.
        self.compiler_publication_receipt(epoch).ok_or(CompilerLinkError::Binding)?;
        let r=self.compiler_publications.records.get(&epoch).ok_or(CompilerLinkError::Binding)?;
        let owner=r.job.key.custodian;
        let agent=self.processes[owner.process.slot].core.agent;
        recheck(&mut self.fabric,owner,agent,&r.job.inputs)?;
        Ok(())
    }

    pub(crate) fn borrow_compiler_publication_modules(&mut self, epochs:&[u64],
        profile:ApplicationLinkProfile) -> Result<CompilerPublishedModules<'_>,CompilerLinkError>
    {
        if epochs.is_empty() || epochs.len()>4096 {return Err(CompilerLinkError::Binding);}
        let (owner,account)=self.compiler_candidate_account()?;
        let mut total=0u64;
        let first=self.compiler_publication_receipt(epochs[0]).ok_or(CompilerLinkError::Binding)?;
        let linker=first.inputs.get(4).ok_or(CompilerLinkError::Binding)?;
        if linker.bytes.is_empty() {return Err(CompilerLinkError::Binding);}
        let linker_len=linker.bytes.len();
        // Allocation-free preflight over current Kernel records. Position is
        // retained exactly, including any duplicates; linker closure decides
        // whether duplicated definitions are valid rather than deduplicating.
        for &epoch in epochs {
            let r=self.compiler_publication_receipt(epoch).ok_or(CompilerLinkError::Binding)?;
            if r.role!=RebuildAdmissionRole::RelocatableModule || r.abi!=2
                || r.source_offset!=0 || r.permissions!=Permissions::READ
                || r.custodian!=owner || r.admission.is_empty()
                || r.length<112 || r.length>profile.module_limit()
                || r.inputs.get(4).is_none_or(|input|input.bytes!=linker.bytes) {
                return Err(CompilerLinkError::Binding);
            }
            total=total.checked_add(r.length).ok_or(CompilerLinkError::Storage)?;
        }
        // Same conservative parser allowance as capture, plus the exact linker,
        // ordered descriptors and bounded provenance-read scratch. This charge
        // is distinct from the separately reserved bounded linker machine.
        let charge=total.checked_mul(32)
            .and_then(|n|n.checked_add(linker_len as u64))
            .and_then(|n|n.checked_add(epochs.len() as u64*512+8192))
            .filter(|n|*n<=i64::MAX as u64).ok_or(CompilerLinkError::Storage)?;
        let reservation=self.fabric.scoped_pointers.reserve_host_storage(account,charge,
            self.fabric.scoped_pointers.revision())?;
        let mut guard=CompilerPublishedModules {kernel:self,owner,reservation:Some(reservation),
            image_reservation:None,transport_reservation:None,epochs:Vec::new(),modules:Vec::new(),linker:Vec::new(),profile,image:None};
        guard.epochs.try_reserve_exact(epochs.len()).map_err(|_|CompilerLinkError::Storage)?;
        guard.modules.try_reserve_exact(epochs.len()).map_err(|_|CompilerLinkError::Storage)?;
        guard.linker.try_reserve_exact(linker_len).map_err(|_|CompilerLinkError::Storage)?;
        if guard.epochs.capacity()>epochs.len() || guard.modules.capacity()>epochs.len()
            || guard.linker.capacity()>linker_len {return Err(CompilerLinkError::Storage);}
        guard.epochs.extend_from_slice(epochs);
        for &epoch in epochs {
            guard.kernel.recheck_link_publication(epoch)?;
            let r=guard.kernel.compiler_publication_receipt(epoch).ok_or(CompilerLinkError::Binding)?;
            let length=usize::try_from(r.length).map_err(|_|CompilerLinkError::Storage)?;
            if guard.linker.is_empty() {guard.linker.extend_from_slice(&r.inputs[4].bytes);}
            let mut bytes=Vec::new();
            bytes.try_reserve_exact(length).map_err(|_|CompilerLinkError::Storage)?;
            if bytes.capacity()>length {return Err(CompilerLinkError::Storage);}
            bytes.resize(length,0);
            for (index,chunk) in bytes.chunks_mut(4096).enumerate() {
                guard.kernel.read_compiler_publication(epoch,index as u64*4096,chunk)?;
            }
            // Bound parser work before any frame-exit traversal/allocation.
            super::super::capture::bounded_manifest(&bytes).ok_or(CompilerLinkError::Binding)?;
            let module=ValidatedPointerModule::from_aom_with_limit(&bytes,profile.module_limit())
                .map_err(|_|CompilerLinkError::Binding)?;
            guard.modules.push(module);
        }
        Ok(guard)
    }
}

impl<'k> CompilerPublishedModules<'k> {
    pub(crate) fn link(mut self, execution:Option<&DeveloperExecutionAuthority>)
        -> Result<CompilerLinkedOutput<'k>,CompilerLinkError>
    {
        execution.ok_or(CompilerLinkError::Authority)?;
        let limit=match self.profile {ApplicationLinkProfile::Standard=>1024*1024,
            ApplicationLinkProfile::Large=>2*1024*1024};
        let account=self.kernel.fabric.scoped_pointers.heap_account(self.owner)
            .ok_or(CompilerLinkError::Binding)?;
        self.image_reservation=Some(self.kernel.fabric.scoped_pointers.reserve_host_storage(
            account,limit,self.kernel.fabric.scoped_pointers.revision())?);
        for &epoch in &self.epochs {self.kernel.recheck_link_publication(epoch)?;}
        let transport=ankald::linker_storage_charge(&self.linker,&self.modules,self.profile)
            .map_err(CompilerLinkError::Link)?;
        self.transport_reservation=Some(self.kernel.fabric.scoped_pointers.reserve_host_storage(
            account,transport,self.kernel.fabric.scoped_pointers.revision())?);
        let image=ankald::run_accounted_application_ankald(&self.linker,&self.modules,self.profile)
            .map_err(CompilerLinkError::Link)?;
        // The callee has destroyed its entire isolated machine. On errors the
        // guard likewise refunds only after the callee's locals were dropped.
        if let Some(r)=self.transport_reservation.take() {
            self.kernel.fabric.scoped_pointers.release_host_storage(r)?;
        }
        if image.bytes.is_empty()
            || image.bytes.len() as u64>limit || image.bytes.capacity() as u64>limit {
            return Err(CompilerLinkError::Binding);
        }
        // The real runner already checks controls, input seals, actual zero
        // exit, and every guest patch/frame. Repeat structural output validation
        // before retaining bytes; never substitute a host-created linked image.
        ankald::validate_application_link_result(&self.modules,&image,self.profile)
            .map_err(CompilerLinkError::Link)?;
        for &epoch in &self.epochs {self.kernel.recheck_link_publication(epoch)?;}
        self.image=Some(image);
        // The isolated runner's remaining transport state is destroyed here.
        Ok(CompilerLinkedOutput {inputs:self})
    }
}

#[cfg(test)]
#[path="consumer_tests.rs"]
mod tests;
