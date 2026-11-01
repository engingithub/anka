//! C2.5a synchronous, quota-reserved capture. No receipt or publication token.
//! The guard retains exclusive Kernel custody and the producer's live account.
//! retain() transfers storage/charges before allowing producer retirement.
use super::*;
use crate::anka64::aom::AomModule;
use crate::anka64::compiler_adapter::RebuildAdmissionRole;
use crate::anka64::pointer_frames::{ValidatedPointerModule, ValidatedPointerProgram};
use crate::anka64::scoped_pointers::heap::HeapReservation;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompilerCaptureError {
    Runtime(CompilerRuntimeError),
    Admission,
    Storage,
}
impl From<CompilerRuntimeError> for CompilerCaptureError {
    fn from(error: CompilerRuntimeError) -> Self { Self::Runtime(error) }
}
impl From<HeapError> for CompilerCaptureError {
    fn from(error: HeapError) -> Self { Self::Runtime(error.into()) }
}

pub(crate) enum CompilerCaptureSlice<'k> {
    Running,
    AwaitingCleanup(CompilerRetryPending),
    Captured(CapturedCompilerOutput<'k>),
}

/// Immutable bytes, still in synchronous coordinator custody. Not Clone and
/// no into_bytes(): detaching an uncharged Vec would bypass C2.5b accounting.
/// Holding this guard prevents scheduling, mutation, or cleanup through Kernel.
pub(crate) struct CapturedCompilerOutput<'k> {
    kernel: &'k mut Kernel,
    owner: AllocationOwner,
    reservation: Option<HeapReservation>,
    bytes: Vec<u8>,
    context: CompilerReplyContext,
    role: RebuildAdmissionRole,
    publication: Option<super::publication::PublicationKey>,
}
impl CapturedCompilerOutput<'_> {
    pub(crate) fn bytes(&self) -> &[u8] { &self.bytes }
    pub(crate) fn context(&self) -> CompilerReplyContext { self.context }
    pub(crate) fn role(&self) -> RebuildAdmissionRole { self.role }

    /// Move immutable bytes into independently charged runtime custody before
    /// this guard's Drop retires the producer. Failure still discards safely.
    pub(crate) fn retain(mut self) -> Result<super::retained::CompilerCandidateHandle,
        super::retained::CompilerCandidateError>
    {
        self.kernel.retain_compiler_candidate(self.owner, self.context, self.role, self.publication, &mut self.bytes)
    }
}
impl Drop for CapturedCompilerOutput<'_> {
    fn drop(&mut self) {
        // Destroy host staging BEFORE refund. Never-attached reservation backing
        // was never exposed; abort returns its exact extents without a scrub.
        drop(std::mem::take(&mut self.bytes));
        if let Some(reservation) = self.reservation.take() {
            // If abort is blocked, normal owner closure retains the obligation.
            let _ = self.kernel.fabric.scoped_pointers.abort_heap(reservation);
        }
        self.kernel.finish_process(self.owner.process.slot, ProcessResult::Exited(0));
    }
}

impl Kernel {
    pub(crate) fn run_compiler_capture_slice<'k>(
        &'k mut self, attempt: &mut CompilerOutputAttempt, quantum: usize,
        role: RebuildAdmissionRole,
    ) -> Result<CompilerCaptureSlice<'k>, CompilerCaptureError> {
        let Some(budget) = self.drive_compiler_attempt(attempt, quantum)? else {
            return Ok(CompilerCaptureSlice::Running);
        };
        let context = budget.context();
        let decoded = self.fabric.read_compiler_capacity_reply(
            attempt.owner, attempt.agent, attempt.output, attempt.reply,
            context.output_capacity(),
        ).map_err(CompilerRuntimeError::from)
            .and_then(|bytes| context.decode(&bytes).map_err(CompilerRuntimeError::from));
        let used = match decoded {
            Ok(CompilerReplyMetadata::SuccessMetadata { used_output }) => used_output,
            other => {
                let result = match other {
                    Ok(CompilerReplyMetadata::NeedOutputCapacity(need)) =>
                        budget.propose_retry(&need).map_err(CompilerRuntimeError::from),
                    Ok(metadata) => Err(CompilerRuntimeError::TerminalMetadata(metadata)),
                    Err(error) => Err(error),
                };
                self.finish_process(attempt.owner.process.slot, ProcessResult::Exited(0));
                return Ok(CompilerCaptureSlice::AwaitingCleanup(CompilerRetryPending {
                    owner: attempt.owner, proposal: Some(result?),
                }));
            }
        };
        // The read above checks actual token geometry, live current custody,
        // and drain state. The exclusive borrow fences all emulator writers.
        // Current application admission limit remains explicit (C3/C4 pending).
        let reserve = (|| -> Result<_, CompilerCaptureError> {
            if role == RebuildAdmissionRole::LinkedImage
                || used > crate::anka64::dev_compiler::DEVELOPMENT_COMPILER_OUTPUT_SIZE {
                return Err(CompilerCaptureError::Admission);
            }
            // Conservative staging + bounded parser-payload allowance; rounded
            // and charged by the existing shared service, not a second ledger.
            // The geometry preflight below prevents repeated-frame scan fanout.
            let charge = used.checked_mul(32).and_then(|n| n.checked_add(4096))
                .ok_or(CompilerCaptureError::Storage)?;
            let account = self.fabric.scoped_pointers.heap_account(attempt.owner)
                .ok_or(CompilerRuntimeError::Process)?;
            Ok(self.fabric.scoped_pointers.reserve_heap(
                account, charge, self.fabric.scoped_pointers.revision())?)
        })();
        let reservation = match reserve {
            Ok(reservation) => reservation,
            Err(error) => {
                self.finish_process(attempt.owner.process.slot, ProcessResult::Exited(0));
                return Err(error);
            }
        };
        // Construct the cleanup guard before any allocation, copy or validator.
        // Every subsequent error drops bytes and queues producer cleanup.
        let mut capture = CapturedCompilerOutput {
            kernel: self, owner: attempt.owner, reservation: Some(reservation),
            bytes: Vec::new(), context, role, publication: attempt.publication,
        };
        let length = usize::try_from(used).map_err(|_| CompilerCaptureError::Storage)?;
        capture.bytes.try_reserve_exact(length).map_err(|_| CompilerCaptureError::Storage)?;
        if capture.bytes.capacity() > length { return Err(CompilerCaptureError::Storage); }
        capture.bytes.resize(length, 0);
        for (index, chunk) in capture.bytes.chunks_mut(4096).enumerate() {
            let offset = i64::try_from(index * 4096).map_err(|_| CompilerCaptureError::Storage)?;
            let pointer = capture.kernel.fabric.scoped_pointers.add_heap_pointer(
                attempt.output, attempt.owner, offset)?;
            capture.kernel.fabric.read_heap_bytes(attempt.owner, attempt.agent, pointer, chunk)?;
        }
        admit(&capture.bytes, role)?;
        Ok(CompilerCaptureSlice::Captured(capture))
    }
}

// Allocation-free preflight: cap the SUM of scanned frame lengths before the
// existing parser constructs exits for each frame. Full validators still decide
// format/partition/rights/instructions; this cannot mint admission by itself.
fn bounded_manifest(bytes: &[u8]) -> Option<()> {
    fn word(bytes: &[u8], at: usize) -> Option<u64> {
        Some(u64::from_le_bytes(bytes.get(at..at.checked_add(8)?)?.try_into().ok()?))
    }
    let code = word(bytes, 40)?;
    let start = usize::try_from(word(bytes, 56)?).ok()?;
    let size = usize::try_from(word(bytes, 64)?).ok()?;
    let metadata = bytes.get(start..start.checked_add(size)?)?;
    let count = word(metadata, 24)?;
    if count == 0 || count > 4096 { return None; }
    let mut cursor = 32usize;
    let mut scanned = 0u64;
    for _ in 0..count {
        let start = word(metadata, cursor)?;
        let end = word(metadata, cursor.checked_add(8)?)?;
        scanned = scanned.checked_add(end.checked_sub(start)?)?;
        if scanned > code { return None; }
        let locals = word(metadata, cursor.checked_add(24)?)?;
        if locals > 4096 { return None; }
        cursor = cursor.checked_add(32)?.checked_add(usize::try_from(locals).ok()?.checked_mul(32)?)?;
        if cursor > metadata.len() { return None; }
    }
    if cursor != metadata.len() { return None; }
    Some(())
}

fn admit(bytes: &[u8], role: RebuildAdmissionRole) -> Result<(), CompilerCaptureError> {
    bounded_manifest(bytes).ok_or(CompilerCaptureError::Admission)?;
    match role {
        RebuildAdmissionRole::ClosedTranslationUnit => {
            let module = AomModule::parse(bytes).map_err(|_| CompilerCaptureError::Admission)?;
            if !module.relocations.is_empty() || module.symbols.iter().any(|s| s.is_import())
                || !matches!(ValidatedPointerProgram::from_image(&module.code, &module.rodata), Ok(Some(_))) {
                return Err(CompilerCaptureError::Admission);
            }
        }
        RebuildAdmissionRole::RelocatableModule => {
            ValidatedPointerModule::from_aom(bytes).map_err(|_| CompilerCaptureError::Admission)?;
        }
        RebuildAdmissionRole::LinkedImage => return Err(CompilerCaptureError::Admission),
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests;
