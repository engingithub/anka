//! C2.1: concrete ABI-2 reply decoding and checked output-growth arithmetic.
//!
//! Refines the *scalar* report/need/growth/work guards in
//! `anka108_compiler_resources.kleis`. A decoded reply is metadata, not proof
//! of a valid artifact, current authority, normal termination or drainage.
//! The ABI-2 execution bridge must establish those facts independently before
//! acting on it. In particular, no API here refunds, allocates, retries a guest,
//! grants a pointer or publishes an artifact. ABI-1 errors have no retry route.

pub const COMPILER_RESOURCE_MAGIC: u64 = 0x4143_5232;
pub const COMPILER_RESOURCE_ABI: u64 = 2;
pub const COMPILER_REPLY_BYTES: usize = 128;
pub const COMPILER_OUTPUT_ROLE: u64 = 3;
use growth::workspace::WorkspaceDirectory;
const PAGE: u64 = 4096;
const AC2_MAX: u64 = i64::MAX as u64;

fn page_capacity(value: u64) -> bool {
    value != 0 && value <= AC2_MAX && value % PAGE == 0
}

/// Names of immutable records resolved by the trusted coordinator. These
/// words must come from its frozen job, never from the guest reply being read.
/// Numeric names, including a matching set, carry no authority themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompilerResourceBindings {
    pub source: u64,
    pub tools: u64,
    pub profile: u64,
    pub dependencies: u64,
    pub plan: u64,
}

impl CompilerResourceBindings {
    fn words(self) -> [u64; 5] {
        [
            self.source,
            self.tools,
            self.profile,
            self.dependencies,
            self.plan,
        ]
    }
}

/// Producer support is determined at admission, not inferred from a guest tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputGrowthSupport {
    FixedOnly,
    CompilerOutput,
}

/// A scalar snapshot of one coordinator-owned attempt. Current owner, object,
/// protected-kind and control checks still belong to the execution bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompilerReplyContext {
    job: u64,
    attempt: u64,
    bindings: CompilerResourceBindings,
    source_length: u64,
    output_capacity: u64,
    growth: OutputGrowthSupport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilerResourceError {
    InvalidConfiguration,
    ReplyLength,
    ReplyMagic,
    ReplyVersion,
    ReplyIdentity,
    ReplyBindings,
    ReplyReserved,
    ReplyStatus,
    ReplyFields,
    UnsupportedGrowth,
    CapacityBudgetDenied,
    RetryBudgetDenied,
    WorkBudgetDenied,
    AttemptExhausted,
}

impl CompilerReplyContext {
    pub(crate) fn source_length(&self) -> u64 { self.source_length }
    pub(crate) fn request_header(&self, owner: u64) -> [u64; 16] {
        let b = self.bindings;
        [COMPILER_RESOURCE_MAGIC, 2, 128, self.job, self.attempt, owner,
         b.source, b.tools, b.profile, b.dependencies, b.plan, 5, 128, 768, 128, 0]
    }

    pub(crate) fn output_capacity(&self) -> u64 {
        self.output_capacity
    }

    pub fn new(
        job: u64,
        attempt: u64,
        bindings: CompilerResourceBindings,
        source_length: u64,
        output_capacity: u64,
        growth: OutputGrowthSupport,
    ) -> Result<Self, CompilerResourceError> {
        if job == 0
            || attempt == 0
            || bindings.words().contains(&0)
            || source_length > AC2_MAX - 7
            || !page_capacity(output_capacity)
        {
            return Err(CompilerResourceError::InvalidConfiguration);
        }
        Ok(Self {
            job,
            attempt,
            bindings,
            source_length,
            output_capacity,
            growth,
        })
    }

    fn checked_reply_words(&self, bytes: &[u8]) -> Result<[u64;16],CompilerResourceError> {
        use CompilerResourceError::*;
        if bytes.len() != COMPILER_REPLY_BYTES {
            return Err(ReplyLength);
        }
        let mut w = [0u64; 16];
        for (word, chunk) in w.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(chunk.try_into().map_err(|_| ReplyLength)?);
        }
        if w[0] != COMPILER_RESOURCE_MAGIC {
            return Err(ReplyMagic);
        }
        if w[1] != COMPILER_RESOURCE_ABI {
            return Err(ReplyVersion);
        }
        if w[2] != self.job || w[3] != self.attempt {
            return Err(ReplyIdentity);
        }
        if w[10..15] != self.bindings.words() {
            return Err(ReplyBindings);
        }
        if w[15] != 0 {
            return Err(ReplyReserved);
        }
        if w[8] > self.source_length { return Err(ReplyFields); }
        Ok(w)
    }

    /// Decode the exact 128-byte little-endian reply, checking every word.
    /// Even SuccessMetadata must pass independent AOM/frame admission later.
    /// Only role 3 is enabled in C2; other known ABI roles are not retry hints.
    pub fn decode(&self, bytes: &[u8]) -> Result<CompilerReplyMetadata, CompilerResourceError> {
        use CompilerResourceError::*;
        let w=self.checked_reply_words(bytes)?;
        let (resource, minimum, used, cursor, diagnostic) = (w[5], w[6], w[7], w[8], w[9]);
        match w[4] {
            0 => {
                if resource != 0
                    || minimum != 0
                    || diagnostic != 0
                    || used < 112
                    || used > self.output_capacity
                    || used % 8 != 0
                    || cursor != self.source_length
                {
                    return Err(ReplyFields);
                }
                Ok(CompilerReplyMetadata::SuccessMetadata { used_output: used })
            }
            1 => {
                if resource != COMPILER_OUTPUT_ROLE
                    || self.growth != OutputGrowthSupport::CompilerOutput
                {
                    return Err(UnsupportedGrowth);
                }
                if minimum <= self.output_capacity
                    || minimum > AC2_MAX
                    || used != 0
                    || diagnostic != 0
                {
                    return Err(ReplyFields);
                }
                Ok(CompilerReplyMetadata::NeedOutputCapacity(
                    OutputCapacityNeed {
                        context: *self,
                        minimum,
                    },
                ))
            }
            2 | 3 => {
                if resource != 0 || minimum != 0 || used != 0 || diagnostic == 0 {
                    return Err(ReplyFields);
                }
                if w[4] == 2 {
                    Ok(CompilerReplyMetadata::SourceRejected { cursor, diagnostic })
                } else {
                    Ok(CompilerReplyMetadata::RepresentationRejected { cursor, diagnostic })
                }
            }
            // BudgetDenied, ExecutionFailure and ProtocolRejected belong to the
            // coordinator. No guest status, including legacy error 8, maps here.
            _ => Err(ReplyStatus),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CompilerReplyMetadata {
    SuccessMetadata { used_output: u64 },
    NeedOutputCapacity(OutputCapacityNeed),
    NeedWorkspaceCapacity(WorkspaceCapacityNeed),
    SourceRejected { cursor: u64, diagnostic: u64 },
    RepresentationRejected { cursor: u64, diagnostic: u64 },
}

/// Only a checked ABI-2 NeedCapacity reply can construct this value. It binds
/// the hint to its exact attempt, source/tools/profile/dependencies and plan.
#[derive(Debug, PartialEq, Eq)]
pub struct OutputCapacityNeed {
    context: CompilerReplyContext,
    minimum: u64,
}

impl OutputCapacityNeed {
    pub fn minimum(&self) -> u64 {
        self.minimum
    }
}

/// Exact profile-1 directory and job binding; only the checked decoder mints it.
#[derive(Debug, PartialEq, Eq)]
pub struct WorkspaceCapacityNeed {
    context: CompilerReplyContext,
    directory: WorkspaceDirectory,
    table: usize,
    minimum: u64,
}

/// Immutable trusted policy. The byte ceiling is only the output-region limit;
/// shared job/owner/global peak accounting is a separate admission requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputRetryPolicy {
    ceiling: u64,
    retries: u64,
    work_limit: u64,
}

impl OutputRetryPolicy {
    pub fn new(ceiling: u64, retries: u64, work_limit: u64) -> Result<Self, CompilerResourceError> {
        if !page_capacity(ceiling) || work_limit == 0 {
            return Err(CompilerResourceError::InvalidConfiguration);
        }
        Ok(Self {
            ceiling,
            retries,
            work_limit,
        })
    }

    pub fn start(
        self,
        context: CompilerReplyContext,
    ) -> Result<OutputRetryBudget, CompilerResourceError> {
        if context.output_capacity > self.ceiling {
            return Err(CompilerResourceError::CapacityBudgetDenied);
        }
        Ok(OutputRetryBudget {
            context,
            policy: self,
            remaining: self.retries,
            spent: 0,
            attempt_start: 0,
            workspace: None,
        })
    }
}

/// Cumulative scalar budget for a job. No Clone/Copy and no counter-reset API.
/// The coordinator must meter before each actual bounded execution slice.
#[derive(Debug, PartialEq, Eq)]
pub struct OutputRetryBudget {
    context: CompilerReplyContext,
    policy: OutputRetryPolicy,
    remaining: u64,
    spent: u64,
    attempt_start: u64,
    workspace: Option<WorkspaceDirectory>,
}

impl OutputRetryBudget {
    /// Bind once at trusted loader admission, before any guest work. Retried
    /// budgets already carry their directory; callers cannot substitute it.
    pub(crate) fn bind_workspace(&mut self, directory: Option<WorkspaceDirectory>)
        -> Result<(),CompilerResourceError> {
        if let Some(bound)=self.workspace {
            if directory!=Some(bound) { return Err(CompilerResourceError::ReplyBindings); }
        } else if directory.is_some() {
            if self.spent!=0 || self.remaining!=self.policy.retries {
                return Err(CompilerResourceError::ReplyBindings);
            }
            self.workspace=directory;
        }
        Ok(())
    }
    pub fn workspace_directory(&self) -> Option<WorkspaceDirectory> { self.workspace }

    /// Profile 0 continues to reject every non-output capacity role. Profile 1
    /// accepts only roles 32..38, in table-record units, never arbitrary bytes.
    pub fn decode(&self, bytes:&[u8]) -> Result<CompilerReplyMetadata,CompilerResourceError> {
        use CompilerResourceError::*;
        let w=self.context.checked_reply_words(bytes)?;
        if w[4]!=1 || w[5]==COMPILER_OUTPUT_ROLE { return self.context.decode(bytes); }
        let directory=self.workspace.ok_or(UnsupportedGrowth)?;
        if self.context.growth!=OutputGrowthSupport::CompilerOutput || !(32..=38).contains(&w[5]) {
            return Err(UnsupportedGrowth);
        }
        let table=(w[5]-32) as usize;
        if w[6]<=directory.words()[4*table+1] || w[6]>4096 || w[7]!=0 || w[9]!=0 {
            return Err(ReplyFields);
        }
        Ok(CompilerReplyMetadata::NeedWorkspaceCapacity(WorkspaceCapacityNeed {
            context:self.context,directory,table,minimum:w[6],
        }))
    }

    pub fn propose_workspace_retry(&self, need:&WorkspaceCapacityNeed)
        -> Result<OutputRetryProposal,CompilerResourceError> {
        use CompilerResourceError::*;
        if need.context!=self.context || self.workspace!=Some(need.directory) {return Err(ReplyBindings);}
        if self.remaining==0 {return Err(RetryBudgetDenied);}
        if self.spent<=self.attempt_start || self.spent>=self.policy.work_limit {return Err(WorkBudgetDenied);}
        let directory=need.directory.grow_table(need.table,need.minimum)
            .map_err(|_|CapacityBudgetDenied)?;
        let mut context=self.context;
        context.attempt=context.attempt.checked_add(1).ok_or(AttemptExhausted)?;
        Ok(OutputRetryProposal {next_budget:OutputRetryBudget {
            context,policy:self.policy,remaining:self.remaining-1,spent:self.spent,
            attempt_start:self.spent,workspace:Some(directory),
        }})
    }

    pub fn context(&self) -> CompilerReplyContext {
        self.context
    }
    /// Canonical immutable publication-plan snapshot, including actual policy
    /// and already-spent cumulative work. Never read back from guest metadata.
    pub(crate) fn publication_plan_words(&self) -> [u64; 22] {
        let mut words = [0; 22];
        words[..16].copy_from_slice(&self.context.request_header(0));
        words[16..].copy_from_slice(&[self.policy.ceiling, self.policy.retries,
            self.policy.work_limit, self.remaining, self.spent, self.attempt_start]);
        words
    }
    pub fn spent_work(&self) -> u64 {
        self.spent
    }
    pub fn remaining_retries(&self) -> u64 {
        self.remaining
    }

    /// Reserve the entire slice before dispatch. A rejected reservation leaves
    /// the counter intact; cancellation does not silently refund metered work.
    pub fn reserve_work(&mut self, slice: u64) -> Result<(), CompilerResourceError> {
        if slice == 0 || slice > self.policy.work_limit - self.spent {
            return Err(CompilerResourceError::WorkBudgetDenied);
        }
        self.spent += slice;
        Ok(())
    }

    /// Pure preview: leaves the running budget and attempt unchanged. This is
    /// deliberately NOT a launch/commit method. The bridge must first stop and
    /// drain old work, finish charged cleanup and establish fresh allocations,
    /// current frozen bindings and shared-budget admission. Kernel supplies the
    /// release receipt; the next owner still needs fresh allocation admission.
    pub fn propose_retry(
        &self,
        need: &OutputCapacityNeed,
    ) -> Result<OutputRetryProposal, CompilerResourceError> {
        use CompilerResourceError::*;
        if need.context != self.context {
            return Err(ReplyIdentity);
        }
        if need.minimum > self.policy.ceiling {
            return Err(CapacityBudgetDenied);
        }
        if self.remaining == 0 {
            return Err(RetryBudgetDenied);
        }
        if self.spent <= self.attempt_start || self.spent >= self.policy.work_limit {
            return Err(WorkBudgetDenied);
        }
        let next_attempt = self
            .context
            .attempt
            .checked_add(1)
            .ok_or(AttemptExhausted)?;
        // Check against the page-aligned ceiling first: rounding cannot exceed
        // it, including near AC2's signed maximum. Branch BEFORE doubling.
        let rounded = need.minimum.checked_add(PAGE - 1).ok_or(ReplyFields)? & !(PAGE - 1);
        let old = self.context.output_capacity;
        let geometric = if old <= self.policy.ceiling - old {
            old + old
        } else {
            self.policy.ceiling
        };
        let next_capacity = rounded.max(geometric);
        let mut next_context = self.context;
        next_context.attempt = next_attempt;
        next_context.output_capacity = next_capacity;
        Ok(OutputRetryProposal {
            next_budget: OutputRetryBudget {
                context: next_context,
                policy: self.policy,
                remaining: self.remaining - 1,
                spent: self.spent,
                attempt_start: self.spent,
                workspace: self.workspace,
            },
        })
    }
}

/// A sizing decision only. It exposes no allocation, refund, publication,
/// execution or public mutable next-budget handle. Kernel alone supplies the
/// release evidence for extracting the next budget; allocation remains separate.
#[derive(Debug, PartialEq, Eq)]
pub struct OutputRetryProposal {
    next_budget: OutputRetryBudget,
}

impl OutputRetryProposal {
    /// Only Kernel can construct this receipt, after the exact old owner has
    /// finished and the real cleanup service has released its allocations.
    pub(crate) fn after_release(
        self,
        release: super::super::os::CompilerRetryRelease,
    ) -> Result<OutputRetryBudget, CompilerResourceError> {
        if !release.matches(self.next_budget.context) {
            return Err(CompilerResourceError::ReplyIdentity);
        }
        Ok(self.next_budget)
    }

    pub(crate) fn next_context(&self) -> CompilerReplyContext {
        self.next_budget.context
    }

    pub fn next_attempt(&self) -> u64 {
        self.next_budget.context.attempt
    }
    pub fn output_capacity(&self) -> u64 {
        self.next_budget.context.output_capacity
    }
    pub fn remaining_retries(&self) -> u64 {
        self.next_budget.remaining
    }
    pub fn spent_work(&self) -> u64 {
        self.next_budget.spent
    }
}

#[cfg(test)]
mod tests;

/// C3/C4 pure checked geometry; not allocation or publication authority.
pub mod growth;
