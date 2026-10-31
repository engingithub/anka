//! C2.3 five-region ABI-2 entry loader for an already admitted, fresh protected
//! executable. Tool/source provenance still belongs to its trusted coordinator.
use super::*;
use crate::anka64::fabric::HeapInitialization;
use crate::anka64::scoped_pointers::heap::OwnerAccount;

const WORKSPACE: u64 = 0x6000;
const REQUEST: u64 = 768;
const SOURCE_LIMIT: usize = 65528;

impl Kernel {
    fn compiler_region_storage(
        &mut self,
        owner: AllocationOwner,
        account: OwnerAccount,
        size: u64,
    ) -> Result<HeapInitialization, HeapError> {
        let r = self.fabric.scoped_pointers.reserve_heap(
            account,
            size,
            self.fabric.scoped_pointers.revision(),
        )?;
        let object =
            match self
                .fabric
                .attach_private_heap(r, owner, self.fabric.scoped_pointers.revision())
            {
                Ok(object) => object,
                Err(error) => {
                    self.fabric.scoped_pointers.abort_heap(r)?;
                    return Err(error);
                }
            };
        let mut init = self.fabric.private_heap_initialization(
            r,
            owner,
            object,
            self.fabric.scoped_pointers.revision(),
        )?;
        while !init.is_complete() {
            init = self.fabric.initialize_private_heap_chunk(
                init,
                owner,
                (init.rounded_bytes() - init.initialized_bytes()).min(4096),
                self.fabric.scoped_pointers.revision(),
            )?;
        }
        Ok(init)
    }

    /// The admitted producer must speak ABI 2. No ABI-1 compiler is silently
    /// upgraded. Payload is the exact effective source supplied by the frozen
    /// coordinator record, with zero logical padding for its last word fetch.
    pub(crate) fn load_compiler_request(
        &mut self,
        key: ProcessKey,
        budget: OutputRetryBudget,
        source: &[u8],
    ) -> Result<CompilerOutputAttempt, CompilerRuntimeError> {
        let owner = self.compiler_owner(key)?;
        let core = &self.processes[key.slot].core;
        if !core.compiler_entry_ready(&self.fabric)
            || !self.processes[key.slot].is_schedulable()
            || source.len() > SOURCE_LIMIT
            || source.len() as u64 != budget.context().source_length()
            || self.fabric.scoped_pointers.heap_account(owner).is_some()
        {
            return Err(CompilerRuntimeError::Process);
        }
        let agent = core.agent;
        let account = self.compiler_heap_account(key)?;
        let loaded = (|| -> Result<_, CompilerRuntimeError> {
            let source_size = ((source.len() as u64 + 7) & !7).max(8);
            let s = self.compiler_region_storage(owner, account, source_size)?;
            let w = self.compiler_region_storage(owner, account, WORKSPACE)?;
            let o =
                self.compiler_region_storage(owner, account, budget.context().output_capacity())?;
            let q = self.compiler_region_storage(owner, account, REQUEST)?;
            let r = self.compiler_region_storage(owner, account, 128)?;
            let current = CurrentHeapProcess::from_processes(&self.processes, key)
                .ok_or(CompilerRuntimeError::Process)?;
            // Intermediate private tokens never reach the process registers.
            let source = self
                .fabric
                .publish_compiler_region(&current, s, 1, source, &[])?;
            let workspace = self
                .fabric
                .publish_compiler_region(&current, w, 2, &[], &[])?;
            let output = self
                .fabric
                .publish_compiler_region(&current, o, 3, &[], &[])?;
            let reply = self
                .fabric
                .publish_compiler_region(&current, r, 16, &[], &[])?;
            let request = self
                .fabric
                .describe_compiler_region(&current, q, 15, REQUEST)?;
            let regions = [source, workspace, output, request, reply];
            let mut bytes = [0u8; REQUEST as usize];
            for (word, dest) in budget
                .context()
                .request_header(account.serial())
                .into_iter()
                .zip(bytes.chunks_exact_mut(8))
            {
                dest.copy_from_slice(&word.to_le_bytes());
            }
            for (i, region) in regions.iter().enumerate() {
                for (word, dest) in region
                    .words
                    .iter()
                    .zip(bytes[128 + i * 128..256 + i * 128].chunks_exact_mut(8))
                {
                    dest.copy_from_slice(&word.to_le_bytes());
                }
            }
            let cells =
                std::array::from_fn::<_, 5, _>(|i| (160 + i as u64 * 128, regions[i].pointer));
            let request = self
                .fabric
                .publish_compiler_region(&current, q, 15, &bytes, &cells)?;
            // All fallible storage work has finished before entry installation.
            // Readiness cannot change during this exclusive Kernel call.
            let core = &mut self.processes[key.slot].core;
            core.install_pointer(R0, Some(request.pointer))
                .map_err(|_| CompilerRuntimeError::Buffers)?;
            core.install_pointer(R2, Some(reply.pointer))
                .map_err(|_| CompilerRuntimeError::Buffers)?;
            Ok(CompilerOutputAttempt {
                owner,
                agent,
                output: output.pointer,
                reply: reply.pointer,
                budget: Some(budget),
            })
        })();
        if loaded.is_err() {
            // Fence every partially attached/published region. Charges remain
            // until ordinary cleanup, and no partial request is executed.
            self.finish_process(key.slot, ProcessResult::ProtectionFault);
        }
        loaded
    }
}

#[cfg(test)]
mod tests;
