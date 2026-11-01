//! Charged immutable source/tool ingress. Stored bytes remain in trusted Kernel
//! custody; a handle is not an execution grant or evidence of accepted lineage.
use super::*;
use crate::anka64::scoped_pointers::heap::HostStorageReservation;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompilerInputRole { EffectiveSource, Tool }
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompilerInputError {
    Unknown, Custodian, Role, Size, Storage,
    Heap(HeapError), Runtime(CompilerRuntimeError),
}
impl From<HeapError> for CompilerInputError {
    fn from(e: HeapError) -> Self { Self::Heap(e) }
}

/// No integer constructor or byte export. Borrow one immutable tool handle for
/// multiple consumers; retaining the same input does not copy or recharge it.
#[derive(Debug)]
pub(crate) struct CompilerInputHandle {
    reservation: HostStorageReservation,
    custodian: AllocationOwner,
}
struct Input {
    reservation: HostStorageReservation,
    custodian: AllocationOwner,
    role: CompilerInputRole,
    length: usize,
    charge: u64,
    bytes: Vec<u8>,
    discarding: bool,
}
#[derive(Default)]
pub(crate) struct CompilerInputs {
    records: BTreeMap<u64, Input>,
    #[cfg(test)]
    fail_after_copy: bool,
}
impl CompilerInputs {
    fn get(&self, h: &CompilerInputHandle) -> Result<&Input, CompilerInputError> {
        self.records.get(&h.reservation.incarnation())
            .filter(|r| r.reservation==h.reservation && r.custodian==h.custodian)
            .ok_or(CompilerInputError::Unknown)
    }
}

impl Kernel {
    /// The borrowed caller buffer is an ingress boundary, not already owned by
    /// this service. Reserve shared quota BEFORE allocating our immutable copy.
    pub(crate) fn ingest_compiler_input(&mut self, role: CompilerInputRole, source: &[u8])
        -> Result<CompilerInputHandle, CompilerInputError>
    {
        self.ingest_compiler_input_bounded(role,source,super::loader::SOURCE_LIMIT)
    }

    /// Explicit profile-1 ingress. The legacy API retains its 65528-byte bound;
    /// loader admission must still select the directory profile independently.
    pub(crate) fn ingest_compiler_directory_source(&mut self, source: &[u8])
        -> Result<CompilerInputHandle, CompilerInputError>
    {
        self.ingest_compiler_input_bounded(CompilerInputRole::EffectiveSource,source,
            crate::anka64::compiler_adapter::resources::growth::workspace::DIRECTORY_SOURCE_LIMIT)
    }

    fn ingest_compiler_input_bounded(&mut self, role: CompilerInputRole, source: &[u8], limit: usize)
        -> Result<CompilerInputHandle, CompilerInputError>
    {
        match role {
            CompilerInputRole::EffectiveSource if source.len()>limit =>
                return Err(CompilerInputError::Size),
            CompilerInputRole::Tool if source.is_empty() || source.len()>1024*1024 =>
                return Err(CompilerInputError::Size),
            _ => {},
        }
        let charge=u64::try_from(source.len()).ok()
            .and_then(|n| n.checked_add(std::mem::size_of::<Input>() as u64))
            .and_then(|n| n.checked_add(4096)).ok_or(CompilerInputError::Size)?;
        let (custodian,account)=self.compiler_candidate_account()?;
        let reservation=self.fabric.scoped_pointers.reserve_host_storage(
            account,charge,self.fabric.scoped_pointers.revision())?;
        let handle=CompilerInputHandle {reservation,custodian};
        let id=reservation.incarnation();
        if self.compiler_inputs.records.contains_key(&id) {
            self.fabric.scoped_pointers.release_host_storage(reservation)?;
            return Err(CompilerInputError::Storage);
        }
        // Register custody before any fallible payload allocation. Failed
        // cancellation retains an unreadable charged tombstone in Kernel.
        self.compiler_inputs.records.insert(id,Input {reservation,custodian,role,
            length:source.len(),charge,bytes:Vec::new(),discarding:false});
        let result=(|| {
            let r=self.compiler_inputs.records.get_mut(&id).unwrap();
            r.bytes.try_reserve_exact(source.len()).map_err(|_|CompilerInputError::Storage)?;
            if r.bytes.capacity()>source.len() {return Err(CompilerInputError::Storage);}
            r.bytes.extend_from_slice(source);
            #[cfg(test)]
            if self.compiler_inputs.fail_after_copy {return Err(CompilerInputError::Storage);}
            Ok(())
        })();
        if let Err(error)=result {
            let _=self.discard_compiler_input(&handle);
            return Err(error);
        }
        Ok(handle)
    }

    /// The immutable borrow prevents concurrent discard/mutation through Kernel.
    /// Tool bytes still require the existing linker/loader/lineage gates.
    pub(crate) fn compiler_input(&self, handle: &CompilerInputHandle,
        role: CompilerInputRole) -> Result<&[u8], CompilerInputError>
    {
        let r=self.compiler_inputs.get(handle)?;
        if r.role!=role {return Err(CompilerInputError::Role);}
        if r.discarding || r.bytes.len()!=r.length || r.bytes.capacity()>r.length {
            return Err(CompilerInputError::Storage);
        }
        if self.compiler_candidate_custodian()?!=r.custodian {return Err(CompilerInputError::Custodian);}
        if self.fabric.scoped_pointers.check_host_storage(r.reservation,r.custodian,
            self.fabric.scoped_pointers.revision())?!=r.charge {return Err(CompilerInputError::Storage);}
        Ok(&r.bytes)
    }

    /// Copy the exact admitted source into the existing five-region request.
    /// Both ingress and destination are charged at the copy peak. The ingress
    /// reservation remains valid for another attempt until explicitly discarded.
    pub(crate) fn load_compiler_request_from_input(&mut self, key: ProcessKey,
        budget: OutputRetryBudget, input: &CompilerInputHandle)
        -> Result<CompilerOutputAttempt, CompilerInputError>
    {
        self.load_compiler_input_layout(key,budget,input,None)
    }

    pub(crate) fn load_compiler_input_with_workspace(&mut self,key: ProcessKey,
        budget: OutputRetryBudget,input: &CompilerInputHandle,
        directory: crate::anka64::compiler_adapter::resources::growth::workspace::WorkspaceDirectory)
        -> Result<CompilerOutputAttempt,CompilerInputError>
    {
        self.load_compiler_input_layout(key,budget,input,Some(directory))
    }

    fn load_compiler_input_layout(&mut self,key: ProcessKey,budget: OutputRetryBudget,
        input: &CompilerInputHandle,
        directory: Option<crate::anka64::compiler_adapter::resources::growth::workspace::WorkspaceDirectory>)
        -> Result<CompilerOutputAttempt,CompilerInputError>
    {
        let n=self.compiler_input(input,CompilerInputRole::EffectiveSource)?.len();
        let owner=self.compiler_owner(key).map_err(CompilerInputError::Runtime)?;
        if owner==input.custodian {return Err(CompilerInputError::Custodian);}
        if n as u64!=budget.context().source_length() {return Err(CompilerInputError::Size);}
        // Move the Vec, never clone it. Exclusive Kernel custody excludes other
        // access. This loader can close only the distinct producer, so it cannot
        // remove the custodian's record. Restore payload on success AND error.
        let id=input.reservation.incarnation();
        let bytes=std::mem::take(&mut self.compiler_inputs.records.get_mut(&id).unwrap().bytes);
        let result=self.load_compiler_request_layout(key,budget,&bytes,directory);
        self.compiler_inputs.records.get_mut(&id).expect("independent input custodian survives loader")
            .bytes=bytes;
        result.map_err(CompilerInputError::Runtime)
    }

    /// Compose charged preprocessing ingress with the job coordinator without
    /// exporting a detached source copy. The original handle remains reusable;
    /// both source copies are charged during the coordinator's retained copy.
    pub(crate) fn begin_compiler_job_from_input(&mut self,attempt:CompilerOutputAttempt,
        inputs:super::publication::PublicationInputs,input:&CompilerInputHandle,
        authority:Option<&crate::anka64::compiler_adapter::RebuildPublicationAuthority>)
        ->Result<super::jobs::CompilerJobHandle,super::jobs::CompilerJobError> {
        let valid=self.compiler_input(input,CompilerInputRole::EffectiveSource).map(|_|());
        if let Err(error)=valid {
            if self.compiler_owner(attempt.owner.process).ok()==Some(attempt.owner) {
                self.finish_process(attempt.owner.process.slot,ProcessResult::ProtectionFault);
            }
            return Err(error.into());
        }
        if attempt.owner==input.custodian {return Err(CompilerInputError::Custodian.into());}
        let id=input.reservation.incarnation();
        let bytes=std::mem::take(&mut self.compiler_inputs.records.get_mut(&id).unwrap().bytes);
        let result=self.begin_compiler_job(attempt,inputs,&bytes,authority);
        self.compiler_inputs.records.get_mut(&id).expect("distinct ingress custodian survives job admission").bytes=bytes;
        result
    }

    pub(crate) fn discard_compiler_input(&mut self, input: &CompilerInputHandle)
        -> Result<(), CompilerInputError>
    {
        self.compiler_inputs.get(input)?;
        let id=input.reservation.incarnation();
        let r=self.compiler_inputs.records.get_mut(&id).unwrap();
        r.discarding=true;
        drop(std::mem::take(&mut r.bytes));
        self.fabric.scoped_pointers.release_host_storage(r.reservation)?;
        self.compiler_inputs.records.remove(&id);
        Ok(())
    }

    fn discard_input_storage(&mut self, owner: Option<AllocationOwner>) -> bool {
        let registry=&mut self.fabric.scoped_pointers;
        self.compiler_inputs.records.retain(|_,r| {
            if owner.is_some_and(|o|o!=r.custodian) {return true;}
            r.discarding=true;drop(std::mem::take(&mut r.bytes));
            registry.release_host_storage(r.reservation).is_err()
        });
        self.compiler_inputs.records.is_empty()
    }
    pub(crate) fn discard_compiler_inputs_owned_by(&mut self, owner: AllocationOwner) {
        self.discard_input_storage(Some(owner));
    }
    pub(crate) fn discard_all_compiler_inputs(&mut self) -> bool {self.discard_input_storage(None)}
}

#[cfg(test)]
mod tests;
