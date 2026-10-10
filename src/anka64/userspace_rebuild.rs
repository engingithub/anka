//! First Phase 10.7 executable witness: a standalone typed word-pointer application.
//! Guest preprocessing, compilation and linking precede exact sealed publication.
use super::ankald::{publish_linked_image, run_ankald, AnkaldError, AnkaldPublishError, LinkedArtifactKey};
use super::cc2_fixed_point::{Cc2FixedPointError, Cc2FixedPointWitness};
use super::dev_compiler::{compile_application_aom_with_linked_compiler, DevelopmentCompileError};
use super::dev_runner::{run_registered_artifact, DeveloperExecutionAuthority, DevelopmentRunError, DevelopmentRunReport};
use super::dev_shell::{DevelopmentArtifactRegistry, DevelopmentShellError};
use super::fabric::Fabric;
use super::placement::PhysicalPlacementManager;
use super::source_bundle::{run_ankapp, AnkaPreprocessError, SourceBundle};

#[derive(Debug)]
pub enum RebuildError {
    CompilerExecutionAuthorityRequired,
    Producer(Cc2FixedPointError),
    Preprocess(AnkaPreprocessError),
    Compile(DevelopmentCompileError),
    Link(AnkaldError),
    UnsupportedEntry,
    Publish(AnkaldPublishError),
    Register(DevelopmentShellError),
}

pub struct RebuiltApplication {
    fabric: Fabric,
    placement: PhysicalPlacementManager,
    registry: DevelopmentArtifactRegistry,
    key: LinkedArtifactKey,
    effective_source: Vec<u8>,
}
impl RebuiltApplication {
    pub fn key(&self) -> LinkedArtifactKey { self.key }
    pub fn effective_source(&self) -> &[u8] { &self.effective_source }
    /// Compilation authority does not authorize execution of the resulting application.
    pub fn run(&mut self, authority: Option<&DeveloperExecutionAuthority>) -> Result<DevelopmentRunReport, DevelopmentRunError> {
        run_registered_artifact(&self.registry, authority, &mut self.fabric, &mut self.placement, "rebuilt-application")
    }
}

pub fn rebuild_application(
    producer: &Cc2FixedPointWitness,
    bundle: &SourceBundle,
    compiler_authority: Option<&DeveloperExecutionAuthority>,
) -> Result<RebuiltApplication, RebuildError> {
    let authority = compiler_authority.ok_or(RebuildError::CompilerExecutionAuthorityRequired)?;
    let (compiler, preprocessor, linker) = producer.application_tools().map_err(RebuildError::Producer)?;
    let effective = run_ankapp(&preprocessor.bytes, bundle).map_err(RebuildError::Preprocess)?;
    let aom = compile_application_aom_with_linked_compiler(compiler, &effective.bytes, authority)
        .map_err(RebuildError::Compile)?;
    let image = run_ankald(&linker.bytes, &[&aom.bytes], "main").map_err(RebuildError::Link)?;
    // Ordinary spawn currently enters at zero. Do not silently patch a linked image.
    if image.entry != 0 { return Err(RebuildError::UnsupportedEntry); }
    let mut fabric = Fabric::new(0x1000000);
    let mut placement = PhysicalPlacementManager::new(0x10000, 0x700000).expect("valid application pool");
    let artifact = publish_linked_image(&mut fabric, &mut placement, "rebuilt-application", &image)
        .map_err(RebuildError::Publish)?;
    let mut registry = DevelopmentArtifactRegistry::new();
    registry.register_linked_application(&fabric, &artifact).map_err(RebuildError::Register)?;
    Ok(RebuiltApplication { fabric, placement, registry, key: artifact.key, effective_source: effective.bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::cc2_fixed_point::witness_cc2_fixed_point;
    use super::super::source_bundle::SourceBundleMember;
    use super::super::os::ProcessResult;

    #[test]
    fn p107_registration_runs_the_exact_existing_publication() {
        use super::super::isa::{Asm64, R0, R1};
        let mut asm = Asm64::new();
        asm.movi(R1, 42); asm.movi(R0, 0); asm.trap(0);
        let bytes = asm.to_bytes();
        let image = super::super::ankald::AnkaldLinkedImage {
            code_size: bytes.len() as u64, bytes, lit_start: 0, entry: 0,
            process_slots_observed: 1,
        };
        let mut fabric = Fabric::new(0x1000000);
        let mut placement = PhysicalPlacementManager::new(0x10000, 0x700000).unwrap();
        let artifact = publish_linked_image(&mut fabric, &mut placement, "probe", &image).unwrap();
        let mut registry = DevelopmentArtifactRegistry::new();
        registry.register_linked_application(&fabric, &artifact).unwrap();
        let mut app = RebuiltApplication { fabric, placement, registry, key: artifact.key, effective_source: vec![] };
        assert!(matches!(app.run(None), Err(DevelopmentRunError::DeveloperExecutionAuthorityRequired)));
        let authority = DeveloperExecutionAuthority::provision();
        let report = app.run(Some(&authority)).unwrap();
        assert_eq!(report.child_result, ProcessResult::Exited(42));
        assert_eq!(report.artifact.object, artifact.key.object);
        assert_eq!(report.artifact.generation, artifact.key.generation);
    }

    fn bundle(source: &[u8]) -> SourceBundle {
        SourceBundle::new("/bin/pointer_probe.c", [SourceBundleMember::new("/bin/pointer_probe.c", source.to_vec()).unwrap()]).unwrap()
    }
    #[test]
    fn p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address() {
        let authority = DeveloperExecutionAuthority::provision();
        let mut producer = witness_cc2_fixed_point(Some(&authority),
            include_bytes!("../../userspace/system/compiler/ankacc2_stage3.c"),
            include_bytes!("../../userspace/system/compiler/ankapp.c"),
            include_bytes!("../../userspace/system/compiler/ankald.c")).unwrap();
        let source = include_bytes!("../../userspace/bin/pointer_probe.c");
        let mut application = rebuild_application(&producer, &bundle(source), Some(&authority)).unwrap();
        assert_eq!(application.effective_source(), source);
        assert!(matches!(application.run(None), Err(DevelopmentRunError::DeveloperExecutionAuthorityRequired)));
        let key = application.key();
        let report = application.run(Some(&authority)).unwrap();
        assert_eq!(report.child_result, ProcessResult::Exited(42));
        assert_eq!(report.artifact.object, key.object);
        assert_eq!(report.artifact.generation, key.generation);
        assert!(matches!(rebuild_application(&producer, &bundle(b"int main(){int x=40;int p=65536;*p=x;return 0;}"), Some(&authority)), Err(RebuildError::Compile(DevelopmentCompileError::CompilerRejected(9)))));
        assert!(matches!(rebuild_application(&producer, &bundle(source), None), Err(RebuildError::CompilerExecutionAuthorityRequired)));
        // Reuse the same freshly verified compiler lineage for the byte edge.
        let byte_source = include_bytes!("../../userspace/bin/byte_pointer_probe.c");
        let mut byte_application = rebuild_application(&producer, &bundle(byte_source), Some(&authority)).unwrap();
        assert_eq!(byte_application.effective_source(), byte_source);
        // Observe the exact published code, not a host-generated substitute.
        let artifact = byte_application.registry.get("rebuilt-application").unwrap();
        let extent = byte_application.placement.allocated_extent(artifact.key.object).unwrap();
        let code = byte_application.fabric.read_physical(extent.base, artifact.code_size);
        let instructions: Vec<_> = code.chunks_exact(4).map(|chunk|
            super::super::isa::decode(u32::from_le_bytes(chunk.try_into().unwrap()))).collect();
        use super::super::desc::Sem;
        assert!(instructions.iter().any(|i| i.desc.semantics == Sem::LoadByte && i.rd == 4 && i.rs1 == 4));
        assert!(instructions.iter().any(|i| i.desc.semantics == Sem::StoreByte && i.rd == 4 && i.rs1 == 5));
        assert!(!instructions.iter().any(|i| i.desc.semantics == Sem::Load && i.rd == 4 && i.rs1 == 4));
        assert!(!instructions.iter().any(|i| i.desc.semantics == Sem::Store && i.rd == 4 && i.rs1 == 5));
        let byte_report = byte_application.run(Some(&authority)).unwrap();
        // 255 (unsigned/truncated pointer) + 17 + 51 (neighbors) + 42 (local truncation).
        assert_eq!(byte_report.child_result, ProcessResult::Exited(365));
        assert!(matches!(rebuild_application(&producer, &bundle(b"int main(){char x=1;int *p=&x;return 0;}"), Some(&authority)), Err(RebuildError::Compile(DevelopmentCompileError::CompilerRejected(9)))));
        assert!(matches!(rebuild_application(&producer, &bundle(b"typedef void *VP;int main(){VP p;return *p;}"), Some(&authority)), Err(RebuildError::Compile(DevelopmentCompileError::CompilerRejected(9)))));
        let original_key = producer.cc2_1_key;
        producer.cc2_1_key = producer.cc2_2_key;
        assert!(matches!(producer.application_tools(), Err(Cc2FixedPointError::PublicationIdentityChanged)));
        producer.cc2_1_key = original_key;
        let entry = producer.cc2_1.entry;
        producer.cc2_1.entry = entry + 8;
        assert!(matches!(producer.application_tools(), Err(Cc2FixedPointError::PublicationIdentityChanged)));
        producer.cc2_1.entry = entry;
        producer.cc2_1.bytes[0] ^= 1;
        assert!(matches!(rebuild_application(&producer, &bundle(source), Some(&authority)), Err(RebuildError::Producer(Cc2FixedPointError::PublicationIdentityChanged))));
    }
}
