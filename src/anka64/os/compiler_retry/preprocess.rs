//! Shared admission for the restricted isolated guest preprocessor. The tool
//! and returned effective source are Kernel-owned inputs, not detached Vecs.
use super::*;
use super::inputs::{CompilerInputError,CompilerInputHandle,CompilerInputRole};
use crate::anka64::source_bundle::{self,AnkaPreprocessError,SourceBundle,PreprocessGrowthPolicy};
use crate::anka64::dev_runner::DeveloperExecutionAuthority;

#[derive(Debug)]
pub(crate) enum CompilerPreprocessError {
    Authority, Input(CompilerInputError), Heap(HeapError), Preprocess(AnkaPreprocessError),
}
pub(crate) struct AdmittedPreprocessedSource {
    pub(crate) input:CompilerInputHandle,
    pub(crate) attempts:u32,
    pub(crate) dispatched_budget:u64,
    pub(crate) output_capacity:u64,
}
impl Kernel {
    pub(crate) fn preprocess_compiler_source(&mut self,tool:&CompilerInputHandle,
        bundle:&SourceBundle,policy:PreprocessGrowthPolicy,
        authority:Option<&DeveloperExecutionAuthority>)
        ->Result<AdmittedPreprocessedSource,CompilerPreprocessError> {
        authority.ok_or(CompilerPreprocessError::Authority)?;
        let charge=source_bundle::storage::charge(
            self.compiler_input(tool,CompilerInputRole::Tool).map_err(CompilerPreprocessError::Input)?,
            bundle,policy).map_err(CompilerPreprocessError::Preprocess)?;
        let (_,account)=self.compiler_candidate_account().map_err(CompilerPreprocessError::Heap)?;
        let storage=self.fabric.scoped_pointers.reserve_host_storage(account,charge,
            self.fabric.scoped_pointers.revision()).map_err(CompilerPreprocessError::Heap)?;
        // Exclusive Kernel custody prevents tool replacement/discard while the
        // isolated machine runs. Its entire charge survives ALL capacity retries.
        let result=(|| {
            let image=self.compiler_input(tool,CompilerInputRole::Tool).map_err(CompilerPreprocessError::Input)?;
            let result=source_bundle::run_ankapp_growing_accounted(image,bundle,policy)
                .map_err(CompilerPreprocessError::Preprocess)?;
            // The isolated machine is already destroyed. Retain its exact output
            // under a separate charge BEFORE dropping the staging bytes/refund.
            let input=self.ingest_compiler_directory_source(&result.source.bytes)
                .map_err(CompilerPreprocessError::Input)?;
            let report=AdmittedPreprocessedSource {input,attempts:result.attempts,
                dispatched_budget:result.dispatched_budget,output_capacity:result.output_capacity};
            drop(result);Ok(report)
        })();
        if let Err(error)=self.fabric.scoped_pointers.release_host_storage(storage) {
            if let Ok(report)=&result {let _=self.discard_compiler_input(&report.input);}
            // Failed refund remains charged in the trusted host-storage ledger.
            return Err(CompilerPreprocessError::Heap(error));
        }
        result
    }
}
#[cfg(test)]
mod tests;
