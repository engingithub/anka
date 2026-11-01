//! C2.2 runtime capacity-retry bridge. Binds already-issued malloc tokens,
//! meters real instruction slices, captures a protected reply at SYS_EXIT,
//! then waits for the existing Undertaker before releasing a next-attempt budget.
//! C2.3 adds the five-region ABI-2 entry loader below. Guest CC2 migration and
//! successful artifact publication are still separate integration work.
use super::*;
use crate::anka64::compiler_adapter::resources::{
    CompilerReplyContext, CompilerReplyMetadata, CompilerResourceError, OutputRetryBudget,
    OutputRetryProposal,
};
use crate::anka64::scoped_pointers::{
    ScopedPointer,
    heap::{AllocationOwner, HeapError},
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompilerRuntimeError {
    Process,
    Buffers,
    Completed,
    ExecutionFailure,
    Heap(HeapError),
    Resource(CompilerResourceError),
    /// No retry. Success is only scalar metadata; publication is not implemented
    /// by this capacity-probe route. Source/representation errors stay terminal.
    TerminalMetadata(CompilerReplyMetadata),
}

impl From<HeapError> for CompilerRuntimeError {
    fn from(e: HeapError) -> Self {
        Self::Heap(e)
    }
}
impl From<CompilerResourceError> for CompilerRuntimeError {
    fn from(e: CompilerResourceError) -> Self {
        Self::Resource(e)
    }
}

/// One live process incarnation and two tokens captured from protected lanes
/// or retained directly from the trusted ABI-2 loader's initial publication.
/// No Clone, numeric constructor, guessed owner or guest-provided drain flag.
#[derive(Debug)]
pub(crate) struct CompilerOutputAttempt {
    owner: AllocationOwner,
    agent: AgentId,
    output: ScopedPointer,
    reply: ScopedPointer,
    budget: Option<OutputRetryBudget>,
    loaded_source: Option<ScopedPointer>,
    publication: Option<publication::PublicationKey>,
}

#[derive(Debug)]
pub(crate) struct CompilerRetryPending {
    owner: AllocationOwner,
    proposal: Option<OutputRetryProposal>,
}

#[derive(Debug)]
pub(crate) enum CompilerSlice {
    Running,
    AwaitingCleanup(CompilerRetryPending),
}

/// Kernel alone constructs this after observed process termination AND actual
/// owner/account/storage release. Bound to one proposed next context, consumed
/// together with the non-Clone proposal. This is not new-allocation admission.
pub(crate) struct CompilerRetryRelease {
    next: CompilerReplyContext,
}
impl CompilerRetryRelease {
    pub(crate) fn matches(&self, next: CompilerReplyContext) -> bool {
        self.next == next
    }
}

impl Kernel {
    fn compiler_owner(&self, key: ProcessKey) -> Result<AllocationOwner, CompilerRuntimeError> {
        let process = self
            .processes
            .get(key.slot)
            .ok_or(CompilerRuntimeError::Process)?;
        if process.generation != key.generation
            || process.state != ProcessState::Running
            || self.is_heap_service_process(key.slot)
        {
            return Err(CompilerRuntimeError::Process);
        }
        let owner = process.core.heap_owner()?;
        if owner.process != key
            || owner.domain != process.core.domain
            || owner.context != process.core.context_identity()
        {
            return Err(CompilerRuntimeError::Process);
        }
        Ok(owner)
    }

    /// Bind actual malloc-issued output in R4:R5 and reply in R2:R3. These are
    /// staging lanes for this runtime bridge, not a change to C1's service-entry
    /// R0:R1 request / R2:R3 reply ABI implemented by load_compiler_request.
    /// The owning client must have allocated through the shared heap service;
    /// scalar copies of the words, foreign, interior or stale tokens cannot bind.
    pub(crate) fn bind_compiler_output_attempt(
        &mut self,
        key: ProcessKey,
        budget: OutputRetryBudget,
    ) -> Result<CompilerOutputAttempt, CompilerRuntimeError> {
        let owner = self.compiler_owner(key)?;
        let process = &self.processes[key.slot];
        let core = &process.core;
        if !process.is_schedulable()
            || !core.protected_application()
            || core.halted
            || core.privilege != Privilege::User
            || !core.event_frames.is_empty()
        {
            return Err(CompilerRuntimeError::Process);
        }
        let pointer = |lane| {
            core.authenticated_pointer(&self.fabric, lane)
                .ok()
                .flatten()
                .ok_or(CompilerRuntimeError::Buffers)
        };
        let output = pointer(R4)?;
        let reply = pointer(R2)?;
        // Same current-custody/geometry/drain checks as terminal capture. This
        // reads initialized reply bytes but does not interpret them yet.
        self.fabric.read_compiler_capacity_reply(
            owner,
            core.agent,
            output,
            reply,
            budget.context().output_capacity(),
        )?;
        Ok(CompilerOutputAttempt {
            owner,
            agent: core.agent,
            output,
            reply,
            budget: Some(budget),
            loaded_source: None,
            publication: None,
        })
    }

    /// Execute one real, bounded instruction slice. Meter the entire dispatch
    /// before execution (conservative charging); faults/nonzero exits/protocol
    /// errors cannot yield another budget. Normal scheduling remains unchanged.
    pub(crate) fn run_compiler_retry_slice(
        &mut self,
        attempt: &mut CompilerOutputAttempt,
        quantum: usize,
    ) -> Result<CompilerSlice, CompilerRuntimeError> {
        let Some(budget) = self.drive_compiler_attempt(attempt, quantum)? else {
            return Ok(CompilerSlice::Running);
        };
        let key = attempt.owner.process;
        // The process is at an authenticated syscall halt. No callback, other
        // CPU slice or cleanup step can interleave this read and owner closure.
        let result = (|| {
            let bytes = self.fabric.read_compiler_capacity_reply(
                attempt.owner,
                attempt.agent,
                attempt.output,
                attempt.reply,
                budget.context().output_capacity(),
            )?;
            match budget.context().decode(&bytes)? {
                CompilerReplyMetadata::NeedOutputCapacity(need) => Ok(budget.propose_retry(&need)?),
                other => Err(CompilerRuntimeError::TerminalMetadata(other)),
            }
        })();
        // Every real zero-exit ends its owner, even if its report was malformed
        // or denied. Failure never rolls back authority retirement or refunds
        // cleanup early; existing published artifacts are not touched.
        self.finish_process(key.slot, ProcessResult::Exited(0));
        let proposal = result?;
        Ok(CompilerSlice::AwaitingCleanup(CompilerRetryPending {
            owner: attempt.owner,
            proposal: Some(proposal),
        }))
    }

    // Shared actual-execution boundary for retry-only and capture routes.
    fn drive_compiler_attempt(
        &mut self, attempt: &mut CompilerOutputAttempt, quantum: usize,
    ) -> Result<Option<OutputRetryBudget>, CompilerRuntimeError> {
        let key = attempt.owner.process;
        if self.compiler_owner(key)? != attempt.owner
            || self.processes[key.slot].core.agent != attempt.agent
            || !self.processes[key.slot].is_schedulable()
        {
            return Err(CompilerRuntimeError::Process);
        }
        let budget = attempt
            .budget
            .as_mut()
            .ok_or(CompilerRuntimeError::Completed)?;
        if let Err(e) = budget.reserve_work(
            u64::try_from(quantum).map_err(|_| CompilerRuntimeError::ExecutionFailure)?,
        ) {
            // Work exhaustion is terminal. No new work or retry is admitted;
            // cleanup still has its separately reserved service capacity.
            attempt.budget = None;
            self.finish_process(key.slot, ProcessResult::ProtectionFault);
            return Err(e.into());
        }
        let at_exit = self.run_process_with_exit_stop(key.slot, quantum, true);
        if !at_exit {
            if self.processes[key.slot].state != ProcessState::Running {
                attempt.budget = None;
                return Err(CompilerRuntimeError::ExecutionFailure);
            }
            return Ok(None);
        }
        let budget = attempt
            .budget
            .take()
            .ok_or(CompilerRuntimeError::Completed)?;
        let Some((words, kinds)) = self.processes[key.slot].core.protected_syscall_image() else {
            self.finish_process(key.slot, ProcessResult::ProtectionFault);
            return Err(CompilerRuntimeError::ExecutionFailure);
        };
        if words[0] != SYS_EXIT || words[1] != 0 || kinds[0].is_some() {
            self.finish_process(key.slot, ProcessResult::ProtectionFault);
            return Err(CompilerRuntimeError::ExecutionFailure);
        }
        Ok(Some(budget))
    }

    /// Perform at most one existing cleanup step. None means blocked/pending,
    /// never permission to reuse. All allocations of the old compiler owner
    /// must be released (not just its output); one stuck work ticket blocks it.
    pub(crate) fn poll_compiler_retry(
        &mut self,
        pending: &mut CompilerRetryPending,
    ) -> Result<Option<OutputRetryBudget>, CompilerRuntimeError> {
        let proposal = pending
            .proposal
            .as_ref()
            .ok_or(CompilerRuntimeError::Completed)?;
        if self
            .processes
            .get(pending.owner.process.slot)
            .is_some_and(|p| {
                p.generation == pending.owner.process.generation && p.state == ProcessState::Running
            })
        {
            return Err(CompilerRuntimeError::Process);
        }
        self.advance_heap_cleanup();
        if !self.fabric.compiler_heap_owner_released(pending.owner) {
            return Ok(None);
        }
        let release = CompilerRetryRelease {
            next: proposal.next_context(),
        };
        let proposal = pending
            .proposal
            .take()
            .ok_or(CompilerRuntimeError::Completed)?;
        Ok(Some(proposal.after_release(release)?))
    }
}

pub(super) mod loader;
pub(crate) mod capture;
pub(crate) mod retained;
pub(crate) mod publication;
pub(crate) mod flow;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod producer_tests;
