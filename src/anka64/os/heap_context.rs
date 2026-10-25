//! Borrowed current process descriptor shared by heap clients and cleanup roles.
use super::{Process, ProcessState};
use crate::anka64::scoped_pointers::heap::{AllocationOwner, CleanupWorkerIdentity, HeapError};
use crate::anka64::state::{AgentId, CapabilitySlotState, ObjectId, ProcessKey};

/// No Clone or public constructor. The immutable descriptor borrow prevents
/// mutation between the actual table check and the exclusive Fabric operation.
/// This confers neither a cleanup role nor authority to any memory object.
pub(crate) struct CurrentHeapProcess<'a> {
    process: &'a Process,
    key: ProcessKey,
}

/// Object-bound, borrowed census of ALL retained process descriptors. Kernel
/// alone constructs this value, immediately before calling Fabric. No bool or
/// caller-supplied mapping count can substitute for the actual process table.
pub(crate) struct CurrentHeapRetirement<'a> {
    worker: CurrentHeapProcess<'a>,
    object: ObjectId,
    _processes: &'a [Process],
}

impl<'a> CurrentHeapRetirement<'a> {
    pub(super) fn from_processes(
        processes: &'a [Process],
        key: ProcessKey,
        object: ObjectId,
    ) -> Result<Self, HeapError> {
        let worker = CurrentHeapProcess::from_processes(processes, key).ok_or(HeapError::Worker)?;
        for process in processes {
            let cap_reference = process.cap_table.as_ref().is_some_and(|table| {
                table.slots().iter().any(|slot| match slot.state {
                    CapabilitySlotState::Memory { object: id, .. }
                    | CapabilitySlotState::Device { object: id, .. } => id == object,
                    CapabilitySlotState::Free => false,
                })
            });
            if process.core.address_map.references_object(object)
                || cap_reference
                || process
                    .resources
                    .as_ref()
                    .is_some_and(|r| r.stack_obj == object || r.trap_obj == object)
            {
                return Err(HeapError::Busy);
            }
        }
        Ok(Self {
            worker,
            object,
            _processes: processes,
        })
    }

    pub(crate) fn worker(&self) -> &CurrentHeapProcess<'a> {
        &self.worker
    }
    pub(crate) fn object(&self) -> ObjectId {
        self.object
    }
}

impl<'a> CurrentHeapProcess<'a> {
    pub(super) fn from_processes(processes: &'a [Process], key: ProcessKey) -> Option<Self> {
        let process = processes
            .get(key.slot)
            .filter(|p| p.generation == key.generation && p.state == ProcessState::Running)?;
        Some(Self { process, key })
    }

    pub(crate) fn owner(&self) -> AllocationOwner {
        AllocationOwner {
            process: self.key,
            context: self.process.core.context_identity(),
            domain: self.process.core.domain,
        }
    }

    pub(crate) fn identity(&self) -> CleanupWorkerIdentity {
        let owner = self.owner();
        CleanupWorkerIdentity {
            process: owner.process,
            context: owner.context,
            domain: owner.domain,
        }
    }

    pub(crate) fn agent(&self) -> AgentId {
        self.process.core.agent
    }
}
