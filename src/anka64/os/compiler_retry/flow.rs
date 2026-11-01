//! C2.5c bounded composition of accepted capture, cleanup and publication gates.
//! Process admission and current lineage selection remain coordinator duties.
use super::*;
use super::capture::{CompilerCaptureError, CompilerCaptureSlice};
use super::publication::{PublicationError, PublicationInputs, PublicationKey};
use super::retained::{CompilerCandidateError, CompilerCandidateHandle};
use crate::anka64::compiler_adapter::{RebuildAdmissionRole, RebuildPublicationAuthority};

#[derive(Debug)]
pub(crate) enum CompilerFlowError {
    Completed,
    Capture(CompilerCaptureError),
    Runtime(CompilerRuntimeError),
    Publication(PublicationError),
    Candidate(CompilerCandidateError),
}

enum Stage {
    Executing(CompilerOutputAttempt),
    Cleaning(CompilerRetryPending),
    Retained(CompilerCandidateHandle),
    Finished,
}

/// Fixed-size orchestration state, not detached source or artifact storage.
/// All payload and cleanup obligations remain charged and owned by Kernel.
pub(crate) struct CompilerPublicationFlow {
    stage: Stage,
    frozen: PublicationKey,
    role: RebuildAdmissionRole,
    epoch: u64,
}

pub(crate) enum CompilerFlowProgress {
    Pending,
    /// Returned exactly once and only after actual producer release. The
    /// coordinator admits a fresh process with this budget, never a reset one.
    Retry(OutputRetryBudget),
    Published(u64),
}

impl Kernel {
    pub(crate) fn begin_compiler_publication_flow(&mut self, mut attempt: CompilerOutputAttempt,
        inputs: &PublicationInputs, role: RebuildAdmissionRole, epoch: u64,
        authority: Option<&RebuildPublicationAuthority>) -> Result<CompilerPublicationFlow, CompilerFlowError>
    {
        let frozen = match self.freeze_compiler_publication(&mut attempt,inputs,role,epoch,authority) {
            Ok(key) => key,
            Err(error) => {
                if self.compiler_owner(attempt.owner.process).ok() == Some(attempt.owner) {
                    self.finish_process(attempt.owner.process.slot,ProcessResult::ProtectionFault);
                }
                return Err(CompilerFlowError::Publication(error));
            }
        };
        Ok(CompilerPublicationFlow { stage:Stage::Executing(attempt), frozen, role, epoch })
    }

    /// One execution slice or one cleanup step. Never busy-waits or manufactures
    /// release, resets retry fuel, or publishes based on success metadata alone.
    pub(crate) fn advance_compiler_publication_flow(&mut self, flow:&mut CompilerPublicationFlow,
        quantum:usize, authority:Option<&RebuildPublicationAuthority>)
        -> Result<CompilerFlowProgress,CompilerFlowError>
    {
        let result = match &mut flow.stage {
            Stage::Executing(attempt) => {
                // Reduce the capture borrow before mutating the orchestration state.
                let next = match self.run_compiler_capture_slice(attempt,quantum,flow.role) {
                    Ok(CompilerCaptureSlice::Running) => Ok(None),
                    Ok(CompilerCaptureSlice::AwaitingCleanup(pending)) => Ok(Some(Stage::Cleaning(pending))),
                    Ok(CompilerCaptureSlice::Captured(capture)) => capture.retain()
                        .map(|h|Some(Stage::Retained(h))).map_err(CompilerFlowError::Candidate),
                    Err(e) => Err(CompilerFlowError::Capture(e)),
                };
                next.map(|next| { if let Some(stage)=next {flow.stage=stage;}
                    CompilerFlowProgress::Pending })
            }
            Stage::Cleaning(pending) => match self.poll_compiler_retry(pending) {
                Ok(None) => Ok(CompilerFlowProgress::Pending),
                Ok(Some(budget)) => match self.cancel_compiler_publication(flow.frozen) {
                    Ok(()) => {flow.stage=Stage::Finished;Ok(CompilerFlowProgress::Retry(budget))},
                    Err(e) => Err(CompilerFlowError::Publication(e)),
                },
                Err(e) => Err(CompilerFlowError::Runtime(e)),
            },
            Stage::Retained(handle) => match self.poll_compiler_candidate(handle) {
                Ok(false) => Ok(CompilerFlowProgress::Pending),
                Ok(true) => {
                    let committed=(|| -> Result<u64,PublicationError> {
                        if self.compiler_publication_epoch()!=flow.epoch {
                            flow.epoch=self.refresh_compiler_publication_epoch(handle,flow.epoch,authority)?;
                        }
                        self.publish_compiler_candidate(handle,flow.epoch,authority)
                    })();
                    match committed {
                        Ok(epoch)=>{flow.stage=Stage::Finished;Ok(CompilerFlowProgress::Published(epoch))},
                        Err(e)=>Err(CompilerFlowError::Publication(e)),
                    }
                },
                Err(e) => Err(CompilerFlowError::Candidate(e)),
            },
            Stage::Finished => return Err(CompilerFlowError::Completed),
        };
        if result.is_err() {
            // Fail closed. Failed cleanup keeps Kernel-owned charged obligations;
            // never replace the diagnostic with a fictitious successful refund.
            let _ = self.cancel_compiler_publication_flow(flow);
        }
        result
    }

    pub(crate) fn cancel_compiler_publication_flow(&mut self, flow:&mut CompilerPublicationFlow)
        -> Result<(),CompilerFlowError>
    {
        let stage=std::mem::replace(&mut flow.stage,Stage::Finished);
        match stage {
            Stage::Finished => return Err(CompilerFlowError::Completed),
            Stage::Executing(attempt) => {
                if self.compiler_owner(attempt.owner.process).ok()==Some(attempt.owner) {
                    self.finish_process(attempt.owner.process.slot,ProcessResult::ProtectionFault);
                }
            }
            Stage::Retained(handle) => {
                let result=self.discard_compiler_candidate(&handle);
                // Even when candidate cancellation fails, also drop the frozen
                // payload; both failure tombstones remain in Kernel custody.
                let frozen=self.cancel_compiler_publication(flow.frozen);
                result.map_err(CompilerFlowError::Candidate)?;
                return frozen.map_err(CompilerFlowError::Publication);
            }
            Stage::Cleaning(_) => {}, // Owner already closed; workers retain it.
        }
        self.cancel_compiler_publication(flow.frozen).map_err(CompilerFlowError::Publication)
    }
}

#[cfg(test)]
mod tests;
