//! C malloc/free dispatch and bounded Undertaker service. No user-supplied owner.
use super::*;
use crate::anka64::core::HeapEventPermit;
use crate::anka64::scoped_pointers::{
    ScopedPointer,
    heap::{AllocationOwner, CleanupWorker, HeapError, HeapReservation},
};

#[derive(Debug, Clone, Copy)]
pub(super) struct HeapService {
    worker: ProcessKey,
    role: CleanupWorker,
    owner_limit: u64,
    cursor: usize,
}
#[derive(Debug, Clone, Copy)]
pub(super) struct HeapFreeWait {
    owner: AllocationOwner,
    reservation: HeapReservation,
    object: ObjectId,
    event: HeapEventPermit,
}

impl Kernel {
    /// Loader-only admission for an exact new compiler process. Shares the
    /// same owner/global account policy and cleanup role as guest malloc.
    pub(super) fn compiler_heap_account(
        &mut self, key: ProcessKey,
    ) -> Result<crate::anka64::scoped_pointers::heap::OwnerAccount, HeapError> {
        let owner = self.process_heap_owner(key.slot)?;
        if owner.process != key || self.fabric.scoped_pointers.heap_account(owner).is_some() {
            return Err(HeapError::Owner);
        }
        let service = self.heap_service_ready()?;
        self.fabric.scoped_pointers.admit_owner(owner, service.owner_limit)
    }

    /// Current trusted custodian of retained compiler candidates. It is the
    /// existing non-guest-scheduled runtime service, never a supplied owner ID.
    pub(super) fn compiler_candidate_custodian(&self) -> Result<AllocationOwner, HeapError> {
        let service = self.heap_service_ready()?;
        self.process_heap_owner(service.worker.slot)
    }

    pub(super) fn compiler_candidate_account(&mut self) -> Result<
        (AllocationOwner, crate::anka64::scoped_pointers::heap::OwnerAccount), HeapError>
    {
        let service = self.heap_service_ready()?;
        let owner = self.process_heap_owner(service.worker.slot)?;
        let account = match self.fabric.scoped_pointers.heap_account(owner) {
            Some(account) => account,
            None => self.fabric.scoped_pointers.admit_owner(owner, service.owner_limit)?,
        };
        Ok((owner, account))
    }

    /// Explicit fresh runtime setup; reserve the cleanup role before admitting
    /// guest allocations. Its descriptor is kernel-owned, never guest scheduled.
    pub(crate) fn enable_heap_service(&mut self, owner_limit: u64) -> Result<(), HeapError> {
        if self.heap_service.is_some() {
            return Ok(());
        }
        if !self.fabric.has_private_heap() || owner_limit == 0 {
            return Err(HeapError::Configuration);
        }
        let domain = self.fabric.create_domain();
        while self.fabric.agents.contains_key(&AgentId(self.next_agent)) {
            self.next_agent = self
                .next_agent
                .checked_add(1)
                .ok_or(HeapError::Configuration)?;
        }
        let agent = AgentId(self.next_agent);
        self.next_agent = self
            .next_agent
            .checked_add(1)
            .ok_or(HeapError::Configuration)?;
        self.fabric
            .register_agent(agent, AgentKind::Cpu(CoreId(0)), domain);
        let worker = self.spawn(Anka64Core::new(agent, domain));
        let role = match self.enroll_cleanup_worker(worker, self.fabric.scoped_pointers.revision())
        {
            Ok(role) => role,
            Err(e) => {
                self.processes[worker.slot].state = ProcessState::Retired;
                self.fabric.destroy_domain(domain);
                self.fabric.agents.remove(&agent);
                return Err(e);
            }
        };
        self.heap_service = Some(HeapService {
            worker,
            role,
            owner_limit,
            cursor: 0,
        });
        Ok(())
    }
    pub(super) fn is_heap_service_process(&self, slot: usize) -> bool {
        self.heap_service.is_some_and(|s| {
            s.worker.slot == slot && self.processes[slot].generation == s.worker.generation
        })
    }
    fn heap_service_ready(&self) -> Result<HeapService, HeapError> {
        let service = self.heap_service.ok_or(HeapError::Configuration)?;
        let current = CurrentHeapProcess::from_processes(&self.processes, service.worker)
            .ok_or(HeapError::Worker)?;
        self.fabric
            .check_heap_service_worker(&current, service.role)?;
        Ok(service)
    }
    fn process_heap_owner(&self, slot: usize) -> Result<AllocationOwner, HeapError> {
        let proc = &self.processes[slot];
        let expected = AllocationOwner {
            process: ProcessKey {
                slot,
                generation: proc.generation,
            },
            context: proc.core.context_identity(),
            domain: proc.core.domain,
        };
        if proc.state != ProcessState::Running || proc.core.heap_owner()? != expected {
            return Err(HeapError::Owner);
        }
        Ok(expected)
    }
    pub(super) fn handle_malloc(
        &mut self,
        idx: usize,
        words: [u64; 16],
        kinds: [Option<ScopedPointer>; 6],
    ) {
        if self.processes[idx].core.protected_syscall_image() != Some((words, kinds))
            || words[0] != SYS_MALLOC
            || words[2..6].iter().any(|w| *w != 0)
            || kinds[..3].iter().any(Option::is_some)
        {
            self.finish_process(idx, ProcessResult::ProtectionFault);
            return;
        }
        let Some((owner, event)) = self.process_heap_owner(idx).ok().and_then(|o| {
            self.processes[idx]
                .core
                .prepare_heap_event(o)
                .ok()
                .map(|e| (o, e))
        }) else {
            self.finish_process(idx, ProcessResult::ProtectionFault);
            return;
        };
        let n = words[1];
        let status = if n == 0 {
            Some(0)
        } else if n > i64::MAX as u64 {
            Some(2)
        } else {
            None
        };
        if let Some(status) = status {
            self.processes[idx]
                .core
                .commit_heap_event(event, None, status, true);
            self.resume_from_trap(idx);
            return;
        }
        let result = (|| -> Result<(), HeapError> {
            let service = self.heap_service_ready()?;
            let account = match self.fabric.scoped_pointers.heap_account(owner) {
                Some(account) => account,
                None => self
                    .fabric
                    .scoped_pointers
                    .admit_owner(owner, service.owner_limit)?,
            };
            let reservation = self.fabric.scoped_pointers.reserve_heap(
                account,
                n,
                self.fabric.scoped_pointers.revision(),
            )?;
            let object = match self.fabric.attach_private_heap(
                reservation,
                owner,
                self.fabric.scoped_pointers.revision(),
            ) {
                Ok(object) => object,
                Err(e) => {
                    self.fabric.scoped_pointers.abort_heap(reservation)?;
                    return Err(e);
                }
            };
            let initialized = (|| {
                let mut init = self.fabric.private_heap_initialization(
                    reservation,
                    owner,
                    object,
                    self.fabric.scoped_pointers.revision(),
                )?;
                while !init.is_complete() {
                    let amount = (init.rounded_bytes() - init.initialized_bytes()).min(4096);
                    init = self.fabric.initialize_private_heap_chunk(
                        init,
                        owner,
                        amount,
                        self.fabric.scoped_pointers.revision(),
                    )?;
                }
                let service = self.heap_service_ready()?;
                // Reuse the complete process-map/capability/resource exclusion
                // census. This exclusive Kernel call has no callback between
                // the observation and the core/Fabric publication commit.
                CurrentHeapRetirement::from_processes(&self.processes, service.worker, object)?;
                self.fabric
                    .publish_heap_reply(&mut self.processes[idx].core, owner, event, init)
            })();
            if initialized.is_err() {
                let _ = self.fabric.close_attached_heap(reservation, owner, object);
            }
            initialized
        })();
        if result.is_err() {
            // Capacity/configuration failures never manufacture a pointer. Any
            // attached staging is fenced and remains charged until cleanup.
            if !self.processes[idx].core.valid_heap_event(event, owner) {
                self.finish_process(idx, ProcessResult::ProtectionFault);
                return;
            }
            self.processes[idx]
                .core
                .commit_heap_event(event, None, 1, true);
        }
        self.resume_from_trap(idx);
    }
    pub(super) fn handle_free(
        &mut self,
        idx: usize,
        words: [u64; 16],
        kinds: [Option<ScopedPointer>; 6],
    ) {
        if self.processes[idx].core.protected_syscall_image() != Some((words, kinds))
            || words[0] != SYS_FREE
            || words[1] != 0
            || words[4] != 0
            || words[5] != 0
            || kinds[0].is_some()
            || kinds[2].is_some()
        {
            self.finish_process(idx, ProcessResult::ProtectionFault);
            return;
        }
        let checked = (|| {
            let owner = self.process_heap_owner(idx)?;
            let event = self.processes[idx].core.prepare_heap_event(owner)?;
            match kinds[1] {
                None if words[2..4] == [0, 0] => Ok((owner, event, None)),
                Some(pointer) if pointer.words() == [words[2], words[3]] => {
                    self.heap_service_ready()?;
                    let reservation = self
                        .fabric
                        .scoped_pointers
                        .heap_free_reservation(pointer, owner)?;
                    let object = self.fabric.heap_object_for_pointer(
                        owner,
                        self.processes[idx].core.agent,
                        pointer,
                    )?;
                    Ok((owner, event, Some((reservation, object))))
                }
                _ => Err(HeapError::InvalidFree),
            }
        })();
        let Ok((owner, event, allocation)) = checked else {
            self.finish_process(idx, ProcessResult::ProtectionFault);
            return;
        };
        if let Some((reservation, object)) = allocation {
            if self
                .fabric
                .close_attached_heap(reservation, owner, object)
                .is_err()
            {
                self.finish_process(idx, ProcessResult::ProtectionFault);
                return;
            }
            self.processes[idx].heap_free_wait = Some(HeapFreeWait {
                owner,
                reservation,
                object,
                event,
            });
            // The ABI requires retirement. This software service additionally
            // waits for scrub/release/refund, so returned free capacity is reusable.
            self.advance_heap_cleanup();
        } else {
            self.processes[idx]
                .core
                .commit_heap_event(event, None, 0, false);
            self.resume_from_trap(idx);
        }
    }
    fn wake_heap_free(
        &mut self,
        reservation: HeapReservation,
        owner: AllocationOwner,
        object: ObjectId,
    ) {
        for i in 0..self.processes.len() {
            let Some(wait) = self.processes[i].heap_free_wait else {
                continue;
            };
            if wait.reservation != reservation || wait.owner != owner || wait.object != object {
                continue;
            }
            self.processes[i].heap_free_wait = None;
            if self.process_heap_owner(i) != Ok(owner)
                || !self.processes[i].core.valid_heap_event(wait.event, owner)
            {
                self.finish_process(i, ProcessResult::ProtectionFault);
                continue;
            }
            self.processes[i]
                .core
                .commit_heap_event(wait.event, None, 0, false);
            self.resume_from_trap(i);
        }
    }
    /// One bounded directory scan and at most one scrub chunk. Blocked rows do
    /// not starve unrelated jobs. Failed checks retain all custody and charges.
    pub(crate) fn advance_heap_cleanup(&mut self) -> bool {
        let Ok(service) = self.heap_service_ready() else {
            return false;
        };
        let capacity = self.fabric.scoped_pointers.heap_cleanup_capacity();
        for delta in 0..capacity {
            let index = (service.cursor + delta) % capacity;
            let Some(job) = self.fabric.scoped_pointers.heap_job(index) else {
                continue;
            };
            let Some(object) = self.fabric.heap_job_object(job) else {
                continue;
            };
            let attempt = (|| -> Result<(), HeapError> {
                let lease = match job.lease {
                    Some(lease) => {
                        self.authenticate_heap_cleanup(service.worker, lease, job.owner, object)?;
                        lease
                    }
                    None => self.claim_heap_cleanup(
                        service.worker,
                        service.role,
                        job.reservation,
                        job.owner,
                        object,
                        self.fabric.scoped_pointers.revision(),
                    )?,
                };
                if !job.retired {
                    self.retire_heap_authority(service.worker, lease, job.owner, object)?;
                } else if job.progress.is_none() {
                    self.begin_heap_scrub(service.worker, lease, job.owner, object)?;
                } else {
                    let snapshot = self
                        .fabric
                        .heap_cleanup_snapshot(job)
                        .ok_or(HeapError::StaleCleanup)?;
                    if snapshot.is_complete() {
                        self.release_clean_heap(service.worker, snapshot)?;
                        self.wake_heap_free(job.reservation, job.owner, object);
                    } else {
                        self.scrub_heap_chunk(
                            service.worker,
                            snapshot,
                            (snapshot.rounded_bytes() - snapshot.completed_bytes()).min(4096),
                        )?;
                    }
                }
                Ok(())
            })();
            if attempt.is_ok() {
                self.heap_service.as_mut().unwrap().cursor = (index + 1) % capacity;
                self.fabric.scoped_pointers.release_closed_heap_accounts();
                return true;
            }
        }
        self.fabric.scoped_pointers.release_closed_heap_accounts();
        false
    }
    pub(super) fn close_process_heap(&mut self, idx: usize) {
        self.processes[idx].heap_free_wait = None;
        let core = &self.processes[idx].core;
        let owner = AllocationOwner {
            process: ProcessKey {
                slot: idx,
                generation: self.processes[idx].generation,
            },
            context: core.context_identity(),
            domain: core.domain,
        };
        // Destroy any host candidate payload before closing its custodian's
        // account. Producer death does not match these independent owners.
        self.discard_compiler_jobs_owned_by(owner);
        self.discard_compiler_inputs_owned_by(owner);
        self.discard_compiler_candidates_owned_by(owner);
        self.discard_compiler_publications_owned_by(owner);
        if let Some(account) = self.fabric.scoped_pointers.heap_account(owner) {
            let _ = self.fabric.scoped_pointers.close_owner(account);
        }
    }
    pub(super) fn stop_heap_service(&mut self) {
        // One-shot teardown discards retained candidates before dismantling the
        // custodian. Failed refunds remain charged/quarantined, never forgotten.
        if !self.discard_all_compiler_jobs() { return; }
        if !self.discard_all_compiler_inputs() { return; }
        if !self.discard_all_compiler_candidates() { return; }
        if !self.discard_all_compiler_publications() { return; }
        // A one-shot runtime must not abandon the work it can finish. Each call
        // is bounded; progress ends at release or explicit retained quarantine.
        while self.advance_heap_cleanup() {}
        if let Some(service) = self.heap_service.take() {
            self.close_process_heap(service.worker.slot);
            self.fabric.scoped_pointers.release_closed_heap_accounts();
            let _ = self.fence_cleanup_worker(service.role);
            let _ = self.remove_cleanup_worker(service.role);
            let core = &self.processes[service.worker.slot].core;
            self.fabric.agents.remove(&core.agent);
            self.fabric.destroy_domain(core.domain);
            self.processes[service.worker.slot].state = ProcessState::Retired;
        }
    }
}

#[cfg(test)]
mod tests;
