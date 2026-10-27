//! First Phase 10.7 executable witness: a standalone typed word-pointer application.
//! Guest preprocessing, compilation and linking precede exact sealed publication.
#[cfg(test)]
mod malloc_tests;
use super::ankald::{publish_linked_image, run_ankald, AnkaldError, AnkaldPublishError, LinkedArtifactKey};
use super::cc2_fixed_point::{Cc2FixedPointError, Cc2FixedPointWitness};
use super::dev_compiler::{compile_application_aom_with_linked_compiler, DevelopmentCompileError};
use super::dev_runner::{run_registered_artifact, DeveloperExecutionAuthority, DevelopmentRunError, DevelopmentRunReport};
use super::dev_shell::{DevelopmentArtifactRegistry, DevelopmentShellError};
use super::fabric::Fabric;
use super::compiler_adapter::{CompilerAdapterError, RebuildArtifactStore, RebuildPublicationAuthority, RebuildReceipt};
use super::placement::PhysicalPlacementManager;
use super::source_bundle::{run_ankapp, AnkaPreprocessError, SourceBundle};

#[derive(Debug)]
pub enum RebuildError {
    CompilerExecutionAuthorityRequired,
    PublicationAuthorityRequired,
    Adapter(CompilerAdapterError),
    Producer(Cc2FixedPointError),
    Preprocess(AnkaPreprocessError),
    Compile(DevelopmentCompileError),
    Link(AnkaldError),
    UnsupportedEntry,
    InvalidProtectedManifest,
    Publish(AnkaldPublishError),
    Register(DevelopmentShellError),
}

pub struct RebuiltApplication {
    fabric: Fabric,
    placement: PhysicalPlacementManager,
    registry: DevelopmentArtifactRegistry,
    key: LinkedArtifactKey,
    effective_source: Vec<u8>,
    compiler_artifacts: Option<RebuildArtifactStore>,
}
impl RebuiltApplication {
    pub fn key(&self) -> LinkedArtifactKey { self.key }
    pub fn effective_source(&self) -> &[u8] { &self.effective_source }
    pub fn rebuild_receipt(&self) -> Option<&RebuildReceipt> {
        let store = self.compiler_artifacts.as_ref()?;
        store.receipt(store.epoch())
    }
    pub fn compiled_aom(&self) -> Option<&[u8]> {
        let store = self.compiler_artifacts.as_ref()?;
        store.artifact_bytes(store.epoch())
    }
    /// Compilation authority does not authorize execution of the resulting application.
    pub fn run(&mut self, authority: Option<&DeveloperExecutionAuthority>) -> Result<DevelopmentRunReport, DevelopmentRunError> {
        run_registered_artifact(&self.registry, authority, &mut self.fabric, &mut self.placement, "rebuilt-application")
    }
    pub fn run_with_input(&mut self, authority: Option<&DeveloperExecutionAuthority>,
        input_authority: Option<&super::dev_runner::DeveloperInputAuthority>, input: &[u8])
        -> Result<DevelopmentRunReport, DevelopmentRunError> {
        super::dev_runner::run_registered_artifact_with_input(&self.registry, authority,
            input_authority, &mut self.fabric, &mut self.placement, "rebuilt-application", input)
    }
}

pub fn rebuild_application(
    producer: &Cc2FixedPointWitness,
    bundle: &SourceBundle,
    compiler_authority: Option<&DeveloperExecutionAuthority>,
) -> Result<RebuiltApplication, RebuildError> {
    rebuild_application_profile(producer,bundle,compiler_authority,None,false)
}

pub fn rebuild_protected_application(producer:&Cc2FixedPointWitness,bundle:&SourceBundle,
    compiler_authority:Option<&DeveloperExecutionAuthority>,
    publication_authority:Option<&RebuildPublicationAuthority>) -> Result<RebuiltApplication,RebuildError> {
    rebuild_application_profile(producer,bundle,compiler_authority,publication_authority,true)
}
fn adapter_error(error: CompilerAdapterError) -> RebuildError {
    match error {
        CompilerAdapterError::ExecutionAuthorityRequired => RebuildError::CompilerExecutionAuthorityRequired,
        CompilerAdapterError::PublicationAuthorityRequired => RebuildError::PublicationAuthorityRequired,
        CompilerAdapterError::Producer(error) => RebuildError::Producer(error),
        CompilerAdapterError::Preprocess(error) => RebuildError::Preprocess(error),
        CompilerAdapterError::Compile(error) => RebuildError::Compile(error),
        error => RebuildError::Adapter(error),
    }
}
fn rebuild_application_profile(producer:&Cc2FixedPointWitness,bundle:&SourceBundle,
    compiler_authority:Option<&DeveloperExecutionAuthority>,
    publication_authority:Option<&RebuildPublicationAuthority>,protected:bool) -> Result<RebuiltApplication,RebuildError> {
    let authority = compiler_authority.ok_or(RebuildError::CompilerExecutionAuthorityRequired)?;
    if protected && publication_authority.is_none() { return Err(RebuildError::PublicationAuthorityRequired); }
    let (compiler, preprocessor, linker) = producer.application_tools().map_err(RebuildError::Producer)?;
    let mut compiler_artifacts = None;
    let (effective_source, aom) = if protected {
        let mut store = RebuildArtifactStore::new();
        let epoch = store.compile(0, producer, bundle, Some(authority), publication_authority)
            .map_err(adapter_error)?;
        let source = store.receipt(epoch).expect("atomic receipt").effective_source.clone();
        let bytes = store.artifact_bytes(epoch).expect("atomic sealed AOM").to_vec();
        compiler_artifacts = Some(store);
        (source, bytes)
    } else {
        let effective = run_ankapp(&preprocessor.bytes, bundle).map_err(RebuildError::Preprocess)?;
        let aom = compile_application_aom_with_linked_compiler(compiler,&effective.bytes,authority)
            .map_err(RebuildError::Compile)?;
        (effective.bytes, aom.bytes)
    };
    let image = run_ankald(&linker.bytes, &[&aom], "main").map_err(RebuildError::Link)?;
    if protected {
        let code=image.bytes.get(..image.code_size as usize).ok_or(RebuildError::InvalidProtectedManifest)?;
        let metadata=image.bytes.get(image.lit_start as usize..).ok_or(RebuildError::InvalidProtectedManifest)?;
        if image.lit_start==0 || !matches!(super::pointer_frames::ValidatedPointerProgram::from_image(code,metadata),Ok(Some(_))) {
            return Err(RebuildError::InvalidProtectedManifest);
        }
    }
    // Ordinary spawn currently enters at zero. Do not silently patch a linked image.
    if image.entry != 0 { return Err(RebuildError::UnsupportedEntry); }
    let mut fabric = if protected { Fabric::with_application_heap(0x1000000).expect("valid protected application heap profile") } else { Fabric::new(0x1000000) };
    let mut placement = PhysicalPlacementManager::new(0x10000, 0x700000).expect("valid application pool");
    let artifact = publish_linked_image(&mut fabric, &mut placement, "rebuilt-application", &image)
        .map_err(RebuildError::Publish)?;
    let mut registry = DevelopmentArtifactRegistry::new();
    registry.register_linked_application(&fabric, &artifact).map_err(RebuildError::Register)?;
    Ok(RebuiltApplication { fabric, placement, registry, key: artifact.key, effective_source, compiler_artifacts })
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
        let mut app = RebuiltApplication { fabric, placement, registry, key: artifact.key, effective_source: vec![], compiler_artifacts: None };
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

    // All four module pieces share one fixed-point producer. Execute the exact
    // receipt-bound publication through ordinary registration and SYS_SPAWN.
    fn check_protected_module_emission(producer: &Cc2FixedPointWitness,
        execution: &DeveloperExecutionAuthority, publication: &RebuildPublicationAuthority) {
        use super::super::compiler_adapter::RebuildAdmissionRole;
        use super::super::pointer_frames::{ValidatedPointerModule, ValidatedPointerProgram};
        let (_, _, linker) = producer.application_tools().unwrap();
        let header = include_bytes!("../../userspace/bin/protected_modules/api.h");
        // Include operands are exact bundle keys, not relative filesystem paths.
        let caller = include_bytes!("../../userspace/bin/protected_modules/main.c");
        let callee = include_bytes!("../../userspace/bin/protected_modules/buffer.c");
        let mut modules = Vec::new();
        let mut store = RebuildArtifactStore::new();
        let mut epochs = Vec::new();
        for (root, source, frame_count) in [("/probe/main.c", caller.as_slice(), 2),
            ("/probe/buffer.c", callee.as_slice(), 2)] {
            let bundle = SourceBundle::new(root, [
                SourceBundleMember::new(root, source.to_vec()).unwrap(),
                SourceBundleMember::new("/probe/api.h", header.to_vec()).unwrap(),
            ]).unwrap();
            let epoch = store.compile_module(store.epoch(), producer, &bundle,
                Some(execution), Some(publication))
                .unwrap_or_else(|error| panic!("protected-module publication {root}: {error:?}"));
            let bytes = store.artifact_bytes(epoch).unwrap();
            let receipt = store.receipt(epoch).unwrap();
            assert_eq!(receipt.source_bundle, bundle);
            assert_eq!(receipt.role, RebuildAdmissionRole::RelocatableModule);
            assert_eq!(receipt.compiler_image, producer.cc2_1);
            let checked = ValidatedPointerModule::from_aom(bytes)
                .expect("fixed-point CC2 must emit a structurally valid protected module");
            assert_eq!(checked.bytes(), bytes);
            assert_eq!(checked.frames().len(), frame_count);
            let module = checked.module();
            assert!(module.symbol("unused").is_none());
            if root == "/probe/main.c" {
                assert_eq!(module.relocations.len(), 1);
                let relocation = &module.relocations[0];
                assert_eq!(module.symbols[relocation.symbol_index as usize].name, "touch");
                assert!(module.symbol("touch").unwrap().is_import());
                assert_eq!(checked.frames()[0].entry, module.symbol("tail").unwrap().value);
                assert_eq!(checked.frames()[1].entry, 0);
                assert_eq!(super::super::isa::decode(u32::from_le_bytes(module.code[..4].try_into().unwrap())).imm, 1);
                assert!(ValidatedPointerProgram::from_image(&module.code, &module.rodata).is_err());
            } else {
                assert!(module.symbol("tail").unwrap().is_import());
                assert_eq!(module.symbols.len(), 3);
                assert_eq!(module.relocations.len(), 1);
                assert!(ValidatedPointerProgram::from_image(&module.code, &module.rodata).is_err());
            }
            modules.push(checked);
            epochs.push(epoch);
        }
        let request = store.freeze_modules(&epochs).unwrap();
        assert!(matches!(store.link_modules(&request, None, Some(publication)),
            Err(CompilerAdapterError::ExecutionAuthorityRequired)));
        assert!(matches!(store.link_modules(&request, Some(execution), None),
            Err(CompilerAdapterError::PublicationAuthorityRequired)));
        let linked_epoch = store.link_modules(&request, Some(execution), Some(publication))
            .expect("guest ankald must publish the exact protected link and ordered receipt");
        assert_eq!(linked_epoch, 3);
        let linked = store.linked_image(linked_epoch).unwrap();
        let receipt = store.linked_receipt(linked_epoch).unwrap();
        assert_eq!(receipt.role, RebuildAdmissionRole::LinkedImage);
        assert_eq!(receipt.linker_image, *linker);
        assert_eq!(receipt.artifact_permissions, super::super::state::Permissions::READ);
        assert_eq!(receipt.dependencies.len(), 2);
        for (position, dependency) in receipt.dependencies.iter().enumerate() {
            assert_eq!(dependency.position, position);
            assert_eq!(&dependency.compiler_receipt, store.receipt(epochs[position]).unwrap());
            assert_eq!(dependency.aom_bytes, modules[position].bytes());
            assert_ne!(dependency.compiler_receipt.context, receipt.context);
            assert_ne!(dependency.transport_key.object, receipt.artifact_key.object);
        }
        let program = ValidatedPointerProgram::from_image(&linked.bytes[..linked.code_size as usize],
            &linked.bytes[linked.lit_start as usize..]).unwrap().unwrap();
        assert_eq!(program.frames.len(), 4);
        assert_eq!(linked.entry, 0);
        eprintln!("protected-module link: modules=2 frames=4 code={} metadata={} entry=0",
            linked.code_size, linked.bytes.len() as u64 - linked.code_size);
        eprintln!("protected-module publication: epoch={linked_epoch} dependencies=2 rights=READ");
        let receipt = receipt.clone();
        assert!(matches!(store.run_linked_application(&receipt, None),
            Err(CompilerAdapterError::ExecutionAuthorityRequired)));
        let report = store.run_linked_application(&receipt, Some(execution))
            .expect("receipt-bound protected modules must execute through ordinary spawn");
        assert_eq!(report.child_result, ProcessResult::Exited(0));
        assert_eq!(report.byte_output, [65, 0, 255, 66]);
        assert_eq!(report.artifact.object, receipt.artifact_key.object);
        assert_eq!(report.artifact.generation, receipt.artifact_key.generation);
        assert_eq!(report.presented_code_permissions, super::super::state::Permissions::RX);
        assert_eq!(report.presented_literal_permissions, Some(super::super::state::Permissions::READ));
        assert!(report.process_slots_observed >= 2);
        assert_eq!(store.linked_receipt(linked_epoch), Some(&receipt));
        assert_eq!(store.linked_image(linked_epoch), Some(&receipt.image));
        assert_eq!(store.epoch(), linked_epoch);
        eprintln!("protected-module execution: exit=0 output=[65,0,255,66] receipt=matched");

        // The already-published helper module is reused by both hostile callers.
        // Each remains a valid program structurally; runtime lifetime/bounds
        // checks must reject the attempted access before emitting any byte.
        // If an access unexpectedly succeeds, explicit SYS_EXIT must expose
        // that success instead of a root RET producing a misleading fault.
        for (name, source) in [
            ("escaped-local", b"#include \"/probe/api.h\"\nint main(){char *p=escape();return syscall(0,*p,0,0);}int tail(int x){return x;}".as_slice()),
            ("one-past", b"#include \"/probe/api.h\"\nint main(){char b[1];int status=touch(b+1,1);return syscall(0,status,0,0);}int tail(int x){return x;}".as_slice()),
        ] {
            let bundle = SourceBundle::new("/probe/main.c", [
                SourceBundleMember::new("/probe/main.c", source.to_vec()).unwrap(),
                SourceBundleMember::new("/probe/api.h", header.to_vec()).unwrap(),
            ]).unwrap();
            let caller_epoch = store.compile_module(store.epoch(), producer, &bundle,
                Some(execution), Some(publication)).unwrap();
            let request = store.freeze_modules(&[caller_epoch, epochs[1]]).unwrap();
            let epoch = store.link_modules(&request, Some(execution), Some(publication)).unwrap();
            let hostile = store.linked_receipt(epoch).unwrap().clone();
            let report = store.run_linked_application(&hostile, Some(execution)).unwrap();
            assert_eq!(report.child_result, ProcessResult::ProtectionFault, "{name}");
            assert!(report.byte_output.is_empty(), "{name}");
            assert_eq!(store.linked_image(linked_epoch), Some(&receipt.image));
            eprintln!("protected-module rejection: {name}=ProtectionFault output=[]");
        }
    }

    #[test]
    fn p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address() {
        let authority = DeveloperExecutionAuthority::provision();
        let publication = RebuildPublicationAuthority::provision();
        let mut producer = witness_cc2_fixed_point(Some(&authority),
            include_bytes!("../../userspace/system/compiler/ankacc2_stage3.c"),
            include_bytes!("../../userspace/system/compiler/ankapp.c"),
            include_bytes!("../../userspace/system/compiler/ankald.c")).unwrap();
        check_protected_module_emission(&producer, &authority, &publication);
        let mut local_probe = rebuild_protected_application(&producer,
            &bundle(include_bytes!("../../userspace/bin/local_initialization_probe.c")),
            Some(&authority), Some(&publication)).unwrap();
        let report = local_probe.run(Some(&authority)).unwrap();
        assert_eq!(report.child_result, ProcessResult::Exited(0));
        assert!(report.byte_output.is_empty());
        eprintln!("protected local initialization: fresh/reused bytes, typed nulls and nested arguments passed");
        super::malloc_tests::check_malloc_free(&producer, &authority, &publication);
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
        // Same exact CC2_1 lineage now emits protected ABI v2 code and manifests.
        let protected_source=include_bytes!("../../userspace/bin/protected_pointer_probe.c");
        assert!(matches!(rebuild_protected_application(&producer,&bundle(protected_source),Some(&authority),None),
            Err(RebuildError::PublicationAuthorityRequired)));
        let mut protected=rebuild_protected_application(&producer,&bundle(protected_source),Some(&authority),Some(&publication)).unwrap();
        assert_eq!(protected.effective_source(),protected_source);
        let receipt = protected.rebuild_receipt().unwrap();
        assert_eq!(receipt.effective_source, protected_source);
        assert_eq!(receipt.source_bundle, bundle(protected_source));
        assert_eq!(receipt.origin_compiler_key, producer.cc2_1_key);
        assert_eq!(receipt.compiler_image, producer.cc2_1);
        assert_eq!(receipt.target_profile, 2);
        assert_ne!(receipt.artifact_key.object, receipt.compiler_key.object);
        assert_ne!(receipt.artifact_key.object, receipt.source_key.object);
        let aom = protected.compiled_aom().unwrap();
        assert_eq!(receipt.artifact_length, aom.len() as u64);
        assert!(super::super::aom::AomModule::parse(aom).is_ok());
        let artifact=protected.registry.get("rebuilt-application").unwrap();
        let extent=protected.placement.allocated_extent(artifact.key.object).unwrap();
        let code=protected.fabric.read_physical(extent.base,artifact.code_size);
        let instructions:Vec<_>=code.chunks_exact(4).map(|c|super::super::isa::decode(u32::from_le_bytes(c.try_into().unwrap()))).collect();
        for semantic in [Sem::PointerFrame,Sem::PointerLocal,Sem::PointerAdd,Sem::PointerLoad,Sem::PointerStore,Sem::PointerRead,Sem::PointerWrite,Sem::PointerMove,Sem::PointerUnframe] {
            assert!(instructions.iter().any(|i|i.desc.semantics==semantic),"missing {semantic:?}");
        }
        assert!(!instructions.iter().any(|i|matches!(i.desc.semantics,Sem::Load|Sem::Store|Sem::LoadByte|Sem::StoreByte|Sem::Xchg)));
        assert_eq!(protected.run(Some(&authority)).unwrap().child_result,ProcessResult::Exited(10));
        for source in [
            b"int main(){char b[4];char *p=b+4;return syscall(0,*p,0,0);}".as_slice(),
            b"char *escape();int main(){char *p=escape();return syscall(0,*p,0,0);}char *escape(){char b;return &b;}".as_slice(),
            b"int main(){char b[4];char *p=b-1;return syscall(0,0,0,0);}".as_slice(),
            b"int main(){return syscall(1,65536,1,0);}".as_slice(),
            b"int main(){int b[2];int *p=b;*(p+2305843009213693952)=42;return syscall(0,*p,0,0);}".as_slice(),
            b"int main(){int b[2];int *p=b;return syscall(0,*(p-9223372036854775808),0,0);}".as_slice(),
        ] {
            let mut app=rebuild_protected_application(&producer,&bundle(source),Some(&authority),Some(&publication)).unwrap();
            assert_eq!(app.run(Some(&authority)).unwrap().child_result,ProcessResult::ProtectionFault);
        }
        let source=b"int main(){int b[2];int *p=b;*(p+1)=42;return syscall(0,*(p+1),0,0);}";
        let mut app=rebuild_protected_application(&producer,&bundle(source),Some(&authority),Some(&publication)).unwrap();
        assert_eq!(app.run(Some(&authority)).unwrap().child_result,ProcessResult::Exited(42));
        assert!(matches!(rebuild_protected_application(&producer,&bundle(b"int main(){char b[4];char *p=b;return p+p;}"),Some(&authority),Some(&publication)),Err(RebuildError::Compile(DevelopmentCompileError::CompilerRejected(9)))));
        let source=b"int main(){char b[1];char *p=b;*p=42;return syscall(0,*p,0,0);}";
        let mut app=rebuild_protected_application(&producer,&bundle(source),Some(&authority),Some(&publication)).unwrap();
        assert_eq!(app.run(Some(&authority)).unwrap().child_result,ProcessResult::Exited(42));
        assert!(matches!(rebuild_protected_application(&producer,&bundle(b"int main(){if(1){char b;}return syscall(0,0,0,0);}"),Some(&authority),Some(&publication)),Err(RebuildError::Compile(DevelopmentCompileError::CompilerRejected(9)))));
        // Phase 10.8 shares this exact fixed-point lineage, avoiding a second
        // expensive bootstrap solely for the typed-output integration witness.
        let output_source=include_bytes!("../../userspace/bin/typed_output_probe.c");
        let mut output=rebuild_protected_application(&producer,&bundle(output_source),Some(&authority),Some(&publication)).unwrap();
        let report=output.run(Some(&authority)).unwrap();
        assert_eq!(report.child_result,ProcessResult::Exited(0));
        assert_eq!(report.byte_output,vec![65,0,255,66]);
        for source in [b"int main(){return write_bytes(65536,4);}".as_slice(),
            b"int main(){int b[2];return write_bytes(b,8);}".as_slice(),
            b"int main(){char b[2];return write_bytes(b,b);}".as_slice()] {
            assert!(matches!(rebuild_protected_application(&producer,&bundle(source),Some(&authority),Some(&publication)),
                Err(RebuildError::Compile(DevelopmentCompileError::CompilerRejected(9)))));
        }
        // Typed input shares this exact fixed-point producer; do not bootstrap
        // it again in a separate full-suite test just to exercise read_bytes.
        let input_source=include_bytes!("../../userspace/bin/typed_input_probe.c");
        let mut input=rebuild_protected_application(&producer,&bundle(input_source),Some(&authority),Some(&publication)).unwrap();
        let input_authority=super::super::dev_runner::DeveloperInputAuthority::provision();
        assert!(matches!(input.run_with_input(Some(&authority),None,&[65,0,255,66,67]),
            Err(DevelopmentRunError::DeveloperInputAuthorityRequired)));
        let report=input.run_with_input(Some(&authority),Some(&input_authority),&[65,0,255,66,67]).unwrap();
        assert_eq!(report.child_result,ProcessResult::Exited(0));
        assert_eq!(report.byte_output,vec![65,0,255,66,67]);
        for source in [b"int main(){return read_bytes(65536,4);}".as_slice(),
            b"int main(){int b[2];return read_bytes(b,8);}".as_slice(),
            b"int main(){char b[2];return read_bytes(b,b);}".as_slice()] {
            assert!(matches!(rebuild_protected_application(&producer,&bundle(source),Some(&authority),Some(&publication)),
                Err(RebuildError::Compile(DevelopmentCompileError::CompilerRejected(9)))));
        }
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
