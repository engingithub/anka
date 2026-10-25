//! Guest integration uses private heap rows; no raw-address or legacy grant path.
use super::*;
use crate::anka64::scoped_pointers::heap::HeapJob;
use crate::anka64::state::{AccessKind, AgentId, MemoryRequest};

impl Fabric {
    /// Explicit software application profile. Runtime/loader objects live outside
    /// this pool; physical_high_watermark also includes it. Policy, not a C limit.
    pub(crate) fn with_application_heap(mem_size: usize) -> Result<Self, HeapError> {
        Self::with_private_heap_cpu_work(
            mem_size,
            RegistryLimits {
                slots: 4096,
                scopes: 4096,
                owners: 64,
                cleanup: 512,
                global_bytes: 64 * 1024 * 1024,
            },
            HeapPlacementLimits {
                physical_pool: PhysicalExtent {
                    base: 0x800000,
                    size: 0x200000,
                },
                physical_claims: 512,
                virtual_window: VirtualExtent {
                    base: 0x40000000,
                    size: 0x200000,
                },
                per_owner_claims: 128,
            },
            1,
            work::HeapWorkLimits {
                tickets: 16,
                requests: 16,
            },
        )
    }
    pub(crate) fn has_private_heap(&self) -> bool {
        self.private_heap.is_some()
    }
    /// Observation for the concurrent C acceptance test; this confers no access.
    #[cfg(test)]
    pub(crate) fn diagnostic_heap_extents(&self, owner: AllocationOwner) -> Vec<PhysicalExtent> {
        self.private_heap
            .iter()
            .flat_map(|h| h.rows.iter().flatten())
            .filter(|r| r.owner == owner)
            .map(|r| r.extents.physical)
            .collect()
    }
    pub(crate) fn heap_job_object(&self, job: HeapJob) -> Option<ObjectId> {
        self.private_heap
            .as_ref()?
            .rows
            .iter()
            .flatten()
            .find(|r| r.reservation == job.reservation && r.owner == job.owner)
            .map(|r| r.object)
    }
    pub(crate) fn heap_cleanup_snapshot(&self, job: HeapJob) -> Option<HeapCleanupSnapshot> {
        let row = *self
            .private_heap
            .as_ref()?
            .rows
            .iter()
            .flatten()
            .find(|r| r.reservation == job.reservation && r.owner == job.owner)?;
        Some(workers::cleanup_snapshot(row, job.progress?))
    }
    pub(crate) fn heap_object_for_pointer(
        &self,
        owner: AllocationOwner,
        agent: AgentId,
        pointer: ScopedPointer,
    ) -> Result<ObjectId, HeapError> {
        Ok(self.checked_live_heap(owner, agent, pointer)?.row.object)
    }
    pub(crate) fn authenticate_heap_token(
        &self,
        owner: AllocationOwner,
        agent: AgentId,
        pointer: ScopedPointer,
    ) -> Result<(), HeapError> {
        self.checked_live_heap(owner, agent, pointer).map(|_| ())
    }
    pub(crate) fn check_heap_application_span(
        &self,
        owner: AllocationOwner,
        agent: AgentId,
        pointer: ScopedPointer,
        length: u64,
    ) -> Result<(), HeapError> {
        let live = self.checked_live_heap(owner, agent, pointer)?;
        if length > 4096 || length > live.row.logical - live.pointer.position() {
            return Err(HeapError::Size);
        }
        Ok(())
    }
    pub(crate) fn read_heap_bytes(
        &self,
        owner: AllocationOwner,
        agent: AgentId,
        pointer: ScopedPointer,
        bytes: &mut [u8],
    ) -> Result<(), HeapError> {
        let live = self.checked_live_heap(owner, agent, pointer)?;
        if bytes.is_empty() {
            return Ok(());
        }
        let span = self.checked_heap_span(&live, bytes.len() as u64, false)?;
        bytes.copy_from_slice(&self.memory[span.bytes]);
        Ok(())
    }
    pub(crate) fn store_heap_token_in_local(
        &mut self,
        request: MemoryRequest,
        owner: AllocationOwner,
        pointer: ScopedPointer,
    ) -> Result<(), crate::anka64::state::FaultRecord> {
        if request.context.domain != owner.domain
            || self
                .authenticate_heap_token(owner, request.context.agent, pointer)
                .is_err()
        {
            return Err(
                self.pointer_cell_fault(&request, crate::anka64::state::FaultReason::NoCapability)
            );
        }
        let key = self.checked_pointer_cell(&request, AccessKind::Write)?;
        let words = pointer.words();
        let mut bytes = words[0].to_le_bytes().to_vec();
        bytes.extend_from_slice(&words[1].to_le_bytes());
        self.execute_write(request, bytes)?;
        self.pointer_cells.insert(key, pointer);
        Ok(())
    }
}
