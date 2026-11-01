//! C2.4: build the protected ABI-2 producer from checked-in C using the
//! accepted CC2 lineage and guest linker. This is not artifact publication,
//! a new fixed-point claim, or the C3 source/table-growth implementation.
use crate::anka64::{ankald, cc2_fixed_point, dev_compiler, dev_runner, pointer_frames};

pub(crate) const SOURCE: &[u8] =
    include_bytes!("../../../userspace/system/compiler/ankacc2_abi2.c");

#[derive(Debug)]
pub(crate) enum ProducerBuildError {
    Lineage(cc2_fixed_point::Cc2FixedPointError),
    Compile(dev_compiler::DevelopmentCompileError),
    Link(ankald::AnkaldError),
    Module(pointer_frames::PointerModuleError),
    ProtectedImage,
}

// Read and retain nested diagnostics instead of erasing them to silence dead_code.
impl std::fmt::Display for ProducerBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lineage(e) => write!(f, "CC2 lineage: {e:?}"),
            Self::Compile(e) => write!(f, "protected producer compilation: {e:?}"),
            Self::Module(e) => write!(f, "protected producer module validation: {e:?}"),
            Self::Link(e) => write!(f, "protected ABI-2 producer link: {e:?}"),
            Self::ProtectedImage => f.write_str("invalid protected producer image"),
        }
    }
}

pub(crate) fn build(
    lineage: &cc2_fixed_point::Cc2FixedPointWitness,
    authority: &dev_runner::DeveloperExecutionAuthority,
) -> Result<ankald::AnkaldLinkedImage, ProducerBuildError> {
    let (compiler, _, linker) = lineage.application_tools()
        .map_err(ProducerBuildError::Lineage)?;
    // The standalone source has no directives/comments requiring preprocessing.
    // No host parser, linker or patching contributes to the accepted artifact.
    let module = dev_compiler::compile_protected_producer_aom(compiler, SOURCE, authority)
        .map_err(ProducerBuildError::Compile)?;
    let checked = pointer_frames::ValidatedPointerModule::from_compiler_producer_aom(&module.bytes)
        .map_err(ProducerBuildError::Module)?;
    let image = ankald::run_compiler_producer_ankald(&linker.bytes, &checked)
        .map_err(ProducerBuildError::Link)?;
    let code = image.bytes.get(..image.code_size as usize)
        .ok_or(ProducerBuildError::ProtectedImage)?;
    let metadata = image.bytes.get(image.lit_start as usize..)
        .ok_or(ProducerBuildError::ProtectedImage)?;
    if image.entry != 0 || image.lit_start == 0
        || !matches!(pointer_frames::ValidatedPointerProgram::from_image(code, metadata), Ok(Some(_)))
    {
        return Err(ProducerBuildError::ProtectedImage);
    }
    Ok(image)
}

#[cfg(test)]
mod bootstrap_limits {
    #[test]
    fn c3_workspace_retry_producer_fits_bootstrap_function_directory() {
        // The checked-in source has one top-level definition header per line.
        // This is a cheap source-shape regression guard, not a general C parser
        // or a substitute for guest compilation/accepted lineage.
        let source=std::str::from_utf8(super::SOURCE).unwrap();
        let definitions=source.lines().filter(|line|
            line.starts_with("int ") && line.contains('(') && line.ends_with('{')).count();
        assert!(definitions>0 && definitions<=64,
            "ABI-2 producer has {definitions} definitions; the accepted bootstrap CC2 has 64 function slots");
    }
}
