//! Phase 10.8 trusted compiler transport and in-memory AOM/receipt publication.
//! Guest ankapp and CC2 produce every source/output byte. Host code only checks
//! identity, transports bounded bytes and validates existing AOM/frame formats.
use std::collections::BTreeMap;

use super::ankald::{AnkaldLinkedImage, LinkedArtifactKey};
use super::aom::{AomError, AomModule};
use super::cc2_fixed_point::{Cc2FixedPointError, Cc2FixedPointWitness};
use super::dev_compiler::{compile_for_adapter, CompiledCImage, DevelopmentCompileError,
    DEVELOPMENT_COMPILER_OUTPUT_SIZE, DEVELOPMENT_COMPILER_SOURCE_SIZE};
use super::dev_runner::DeveloperExecutionAuthority;
use super::fabric::Fabric;
use super::placement::{PhysicalPlacementManager, PlacementError};
use super::pointer_frames::{ValidatedPointerModule, ValidatedPointerProgram};
use super::source_bundle::{run_ankapp_with_capacity, AnkaPreprocessError, SourceBundle};
use super::state::*;

mod protected_modules;
pub use protected_modules::{FrozenModuleLink, LinkedModuleDependency, LinkedRebuildReceipt};

/// ABI-2 wire validation and output-growth planning. The existing runner still
/// uses ABI 1; a plan from this module is not allocation or execution authority.
pub mod resources;
pub(crate) mod producer;

/// Validation role is evidence, never execution or publication authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebuildAdmissionRole { ClosedTranslationUnit, RelocatableModule, LinkedImage }

const COPY_LIMIT: u64 = 65536;
// Adapter ABI version, target profile, output bound. This is coordinator-owned
// immutable configuration, not an alleged identity supplied by an AOM header.
const PROFILE_WORDS: [u64; 3] = [1, 2, DEVELOPMENT_COMPILER_OUTPUT_SIZE];
pub(crate) fn profile_bytes() -> Vec<u8> {
    PROFILE_WORDS.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// Provisioned by explicit developer policy, independently of execution rights.
/// This host token is never accepted from a guest integer or filename.
pub struct RebuildPublicationAuthority { _private: () }
impl RebuildPublicationAuthority {
    pub fn provision() -> Self { Self { _private: () } }
}

#[derive(Debug)]
pub enum CompilerAdapterError {
    ExecutionAuthorityRequired,
    PublicationAuthorityRequired,
    StaleEpoch,
    EpochExhausted,
    Producer(Cc2FixedPointError),
    Preprocess(AnkaPreprocessError),
    Compile(DevelopmentCompileError),
    InvalidAom(AomError),
    InvalidProtectedManifest,
    BindingChanged,
    Placement(PlacementError),
    PublicationRejected,
    InvalidModuleDependency,
    DependencyChanged,
    Link(super::ankald::AnkaldError),
    Run(super::dev_runner::DevelopmentRunError),
}

/// Produced only by the isolated, terminal, compile-only execution bridge.
/// Moving the Fabric out of that bridge drops all runnable process state.
pub(crate) struct CompilerOutput {
    pub bytes: Vec<u8>,
    pub fabric: Fabric,
    pub placement: PhysicalPlacementManager,
    pub reader: DomainId,
    pub compiler_key: LinkedArtifactKey,
    pub arena_key: LinkedArtifactKey,
    pub workspace_object: ObjectId,
    pub source_key: LinkedArtifactKey,
    pub profile_key: LinkedArtifactKey,
    pub process_slot: u64,
    pub process_generation: u64,
    pub context: u64,
    pub domain: DomainId,
    pub source_length: u64,
}

fn exact_read_grant(fabric: &Fabric, reader: DomainId, key: LinkedArtifactKey, total: u64) -> bool {
    key.generation.0 != 0
        && fabric.objects.get(&key.object).is_some_and(|object|
            object.state == ObjectState::Sealed && object.generation == key.generation)
        && fabric.find_authorizing_cap(reader, key.object, 0, total, Permissions::READ)
            .is_some_and(|cap| cap.generation() == key.generation && cap.offset() == 0
                && cap.length() == total && cap.permissions() == Permissions::READ)
}

/// The same used/count/domain/key feed admission and the committed READ. No
/// physical host read or numeric-to-protected-pointer conversion stages bytes.
pub(crate) fn copy_sealed_prefix(fabric: &mut Fabric, reader: DomainId,
    key: LinkedArtifactKey, total: u64) -> Result<Vec<u8>, DevelopmentCompileError> {
    if total == 0 || total > DEVELOPMENT_COMPILER_OUTPUT_SIZE
        || !fabric.compiler_trace_safe(key.object)
        || !exact_read_grant(fabric, reader, key, total) {
        return Err(DevelopmentCompileError::AdapterReadDenied);
    }
    let agent = AgentId(match fabric.agents.keys().next_back() {
        Some(last) => last.0.checked_add(1).ok_or(DevelopmentCompileError::AdapterReadDenied)?,
        None => 0,
    });
    fabric.register_agent(agent, AgentKind::Cpu(CoreId(agent.0)), reader);
    let result = (|| {
        let mut staged = Vec::with_capacity(total as usize);
        while (staged.len() as u64) < total {
            let used = staged.len() as u64;
            let count = COPY_LIMIT.min(total - used);
            if !exact_read_grant(fabric, reader, key, total) {
                return Err(DevelopmentCompileError::AdapterReadDenied);
            }
            let bytes = fabric.execute_read(MemoryRequest {
                context: AccessContext { agent, domain: reader, privilege: Privilege::User },
                object: key.object, offset: used, width: Width::Byte,
                length: count, kind: AccessKind::Read,
            }).map_err(|_| DevelopmentCompileError::AdapterReadDenied)?;
            if bytes.len() as u64 != count {
                return Err(DevelopmentCompileError::AdapterReadDenied);
            }
            staged.extend_from_slice(&bytes);
        }
        Ok(staged)
    })();
    fabric.agents.remove(&agent);
    result
}

/// All object keys below belong to `context`'s isolated Fabric, except the
/// explicitly named origin key. Object numbers alone are not global identities.
/// A receipt is evidence only when obtained from this store; copying this data
/// grants neither publication nor application execution authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildReceipt {
    pub epoch: u64,
    pub role: RebuildAdmissionRole,
    pub context: u64,
    pub process_slot: u64,
    /// Injective encoding of concrete u32 process generation: u64(g) + 1.
    pub process_generation: u64,
    pub producer_domain: DomainId,
    pub origin_compiler_key: LinkedArtifactKey,
    pub compiler_key: LinkedArtifactKey,
    pub source_key: LinkedArtifactKey,
    pub profile_key: LinkedArtifactKey,
    pub artifact_key: LinkedArtifactKey,
    pub source_offset: u64,
    pub artifact_length: u64,
    pub target_profile: u64,
    pub source_bundle: SourceBundle,
    pub effective_source: Vec<u8>,
    pub compiler_image: AnkaldLinkedImage,
    pub preprocessor_image: CompiledCImage,
    pub linker_image: CompiledCImage,
}

struct Binding {
    origin_compiler_key: LinkedArtifactKey,
    compiler: AnkaldLinkedImage,
    preprocessor: CompiledCImage,
    linker: CompiledCImage,
    bundle: SourceBundle,
    source: Vec<u8>,
}

struct PublishedRebuild {
    fabric: Fabric,
    placement: PhysicalPlacementManager,
    reader: DomainId,
    context: u64,
    receipt: RebuildReceipt,
}

/// Artifact and receipt have one visibility point: insertion of one complete
/// immutable record under exclusive &mut access. There is no disk durability
/// claim. Failed attempts drop their private machine without changing records.
#[derive(Default)]
pub struct RebuildArtifactStore {
    epoch: u64,
    records: BTreeMap<u64, PublishedRebuild>,
    linked_records: BTreeMap<u64, protected_modules::PublishedLinkedRebuild>,
}
impl RebuildArtifactStore {
    pub fn new() -> Self { Self::default() }
    pub fn epoch(&self) -> u64 { self.epoch }
    pub fn receipt(&self, epoch: u64) -> Option<&RebuildReceipt> {
        self.records.get(&epoch).map(|record| &record.receipt)
    }
    pub fn artifact_bytes(&self, epoch: u64) -> Option<&[u8]> {
        let record = self.records.get(&epoch)?;
        let receipt = &record.receipt;
        if !exact_read_grant(&record.fabric, record.reader,
            receipt.artifact_key, receipt.artifact_length) { return None; }
        sealed_bytes(&record.fabric, &record.placement, receipt.artifact_key)
    }

    pub fn compile(&mut self, expected_epoch: u64, producer: &Cc2FixedPointWitness,
        bundle: &SourceBundle, execution: Option<&DeveloperExecutionAuthority>,
        publication: Option<&RebuildPublicationAuthority>) -> Result<u64, CompilerAdapterError> {
        self.compile_as(expected_epoch, producer, bundle, execution, publication,
            RebuildAdmissionRole::ClosedTranslationUnit)
    }

    /// Publish an unresolved protected AOM as immutable READ data. It cannot
    /// enter the closed application path by virtue of this admission role.
    pub fn compile_module(&mut self, expected_epoch: u64, producer: &Cc2FixedPointWitness,
        bundle: &SourceBundle, execution: Option<&DeveloperExecutionAuthority>,
        publication: Option<&RebuildPublicationAuthority>) -> Result<u64, CompilerAdapterError> {
        self.compile_as(expected_epoch, producer, bundle, execution, publication,
            RebuildAdmissionRole::RelocatableModule)
    }

    fn compile_as(&mut self, expected_epoch: u64, producer: &Cc2FixedPointWitness,
        bundle: &SourceBundle, execution: Option<&DeveloperExecutionAuthority>,
        publication: Option<&RebuildPublicationAuthority>, role: RebuildAdmissionRole)
        -> Result<u64, CompilerAdapterError> {
        execution.ok_or(CompilerAdapterError::ExecutionAuthorityRequired)?;
        publication.ok_or(CompilerAdapterError::PublicationAuthorityRequired)?;
        self.next_epoch(expected_epoch)?;
        let (compiler, preprocessor, linker) = producer.application_tools()
            .map_err(CompilerAdapterError::Producer)?;
        let effective = run_ankapp_with_capacity(&preprocessor.bytes, bundle,
            DEVELOPMENT_COMPILER_SOURCE_SIZE - 8).map_err(CompilerAdapterError::Preprocess)?;
        let output = compile_for_adapter(compiler, &effective.bytes)
            .map_err(CompilerAdapterError::Compile)?;
        // Revalidate exact sealed lineage, not just the public producer fields.
        producer.application_tools().map_err(CompilerAdapterError::Producer)?;
        let binding = Binding {
            origin_compiler_key: producer.cc2_1_key, compiler: compiler.clone(),
            preprocessor: preprocessor.clone(), linker: linker.clone(),
            bundle: bundle.clone(), source: effective.bytes,
        };
        if role == RebuildAdmissionRole::ClosedTranslationUnit {
            self.publish(expected_epoch, output, binding, publication)
        } else {
            self.publish_as(expected_epoch, output, binding, publication, role)
        }
    }

    fn next_epoch(&self, expected: u64) -> Result<u64, CompilerAdapterError> {
        if expected != self.epoch { return Err(CompilerAdapterError::StaleEpoch); }
        self.epoch.checked_add(1).ok_or(CompilerAdapterError::EpochExhausted)
    }

    fn publish(&mut self, expected_epoch: u64, output: CompilerOutput,
        binding: Binding, publication: Option<&RebuildPublicationAuthority>)
        -> Result<u64, CompilerAdapterError> {
        self.publish_as(expected_epoch, output, binding, publication,
            RebuildAdmissionRole::ClosedTranslationUnit)
    }

    fn publish_as(&mut self, expected_epoch: u64, mut output: CompilerOutput,
        binding: Binding, publication: Option<&RebuildPublicationAuthority>,
        role: RebuildAdmissionRole) -> Result<u64, CompilerAdapterError> {
        publication.ok_or(CompilerAdapterError::PublicationAuthorityRequired)?;
        let epoch = self.next_epoch(expected_epoch)?;
        validate_binding(&output, &binding)?;
        let module = AomModule::parse(&output.bytes).map_err(CompilerAdapterError::InvalidAom)?;
        match role {
            RebuildAdmissionRole::ClosedTranslationUnit => {
                // Retain the stronger existing admission; unresolved modules
                // must opt into their distinct non-executable role.
                if !module.relocations.is_empty() || module.symbols.iter().any(|s| s.is_import())
                    || !matches!(ValidatedPointerProgram::from_image(&module.code, &module.rodata), Ok(Some(_))) {
                    return Err(CompilerAdapterError::InvalidProtectedManifest);
                }
            }
            RebuildAdmissionRole::RelocatableModule => {
                ValidatedPointerModule::from_aom(&output.bytes)
                    .map_err(|_| CompilerAdapterError::InvalidProtectedManifest)?;
            }
            RebuildAdmissionRole::LinkedImage => return Err(CompilerAdapterError::InvalidProtectedManifest),
        }
        let profile_key = output.profile_key;
        let bytes = std::mem::take(&mut output.bytes);
        let artifact_key = publish_bytes(&mut output, "rebuilt-aom", &bytes)?;
        if [output.compiler_key.object, output.source_key.object, output.workspace_object,
            output.arena_key.object, profile_key.object].contains(&artifact_key.object) {
            return Err(CompilerAdapterError::PublicationRejected);
        }
        let receipt = RebuildReceipt {
            epoch, role, context: output.context, process_slot: output.process_slot,
            process_generation: output.process_generation, producer_domain: output.domain,
            origin_compiler_key: binding.origin_compiler_key, compiler_key: output.compiler_key,
            source_key: output.source_key, profile_key, artifact_key,
            source_offset: 8, artifact_length: bytes.len() as u64, target_profile: 2,
            source_bundle: binding.bundle, effective_source: binding.source,
            compiler_image: binding.compiler, preprocessor_image: binding.preprocessor,
            linker_image: binding.linker,
        };
        // No fallible operation or guest execution after this visibility point.
        self.records.insert(epoch, PublishedRebuild { fabric: output.fabric,
            placement: output.placement, reader: output.reader, context: output.context, receipt });
        self.epoch = epoch;
        Ok(epoch)
    }
}

fn sealed_bytes<'a>(fabric: &'a Fabric, placement: &PhysicalPlacementManager,
    key: LinkedArtifactKey) -> Option<&'a [u8]> {
    let object = fabric.objects.get(&key.object)?;
    if object.state != ObjectState::Sealed || object.generation != key.generation { return None; }
    let extent = placement.allocated_extent(key.object)?;
    Some(fabric.read_physical(extent.base, object.size))
}

fn validate_binding(output: &CompilerOutput, binding: &Binding) -> Result<(), CompilerAdapterError> {
    let source = sealed_bytes(&output.fabric, &output.placement, output.source_key)
        .ok_or(CompilerAdapterError::BindingChanged)?;
    let length = binding.source.len();
    if output.context == 0 || output.process_slot != 0 || output.process_generation == 0
        || output.source_length != length as u64 || length as u64 > DEVELOPMENT_COMPILER_SOURCE_SIZE - 8
        || source.get(..8) != Some((length as u64).to_le_bytes().as_slice())
        || source.get(8..8 + length) != Some(binding.source.as_slice())
        || source.get(8 + length..).is_none_or(|padding| padding.iter().any(|b| *b != 0))
        || sealed_bytes(&output.fabric, &output.placement, output.compiler_key) != Some(binding.compiler.bytes.as_slice())
        || sealed_bytes(&output.fabric, &output.placement, output.profile_key) != Some(profile_bytes().as_slice())
        || !output.fabric.compiler_trace_safe(output.arena_key.object)
        || !exact_read_grant(&output.fabric, output.reader, output.arena_key, output.bytes.len() as u64)
        || sealed_bytes(&output.fabric, &output.placement, output.arena_key)
            .and_then(|arena| arena.get(..output.bytes.len())) != Some(output.bytes.as_slice()) {
        return Err(CompilerAdapterError::BindingChanged);
    }
    Ok(())
}

fn publish_bytes(output: &mut CompilerOutput, label: &str, bytes: &[u8])
    -> Result<LinkedArtifactKey, CompilerAdapterError> {
    publish_read_only(&mut output.fabric, &mut output.placement, output.reader, label, bytes)
}

// Called only on an attempt-owned, terminal machine. Any failure drops that
// private Fabric/PM, leaving every previously visible store record unchanged.
fn publish_read_only(fabric: &mut Fabric, placement: &mut PhysicalPlacementManager,
    reader: DomainId, label: &str, bytes: &[u8]) -> Result<LinkedArtifactKey, CompilerAdapterError> {
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(CompilerAdapterError::PublicationRejected);
    }
    let object = fabric.alloc_object(label, bytes.len() as u64, ObjectKind::Memory);
    placement.allocate_and_place_object(fabric, object)
        .map_err(CompilerAdapterError::Placement)?;
    let before = fabric.objects[&object].generation;
    let after = before.0.checked_add(1).ok_or(CompilerAdapterError::PublicationRejected)?;
    if !fabric.zero_object_extent(object)
        || !fabric.initialize_object(object, 0, bytes)
        || !fabric.seal_object(object)
        || fabric.objects[&object].generation.0 != after
        || fabric.grant(reader, object, 0, bytes.len() as u64, Permissions::READ).is_none() {
        return Err(CompilerAdapterError::PublicationRejected);
    }
    Ok(LinkedArtifactKey { object, generation: Generation(after) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::isa::{Asm64, R0, R1, R2, R3, R4};
    use super::super::source_bundle::SourceBundleMember;

    pub(super) fn tiny_aom() -> Vec<u8> {
        let mut asm = Asm64::new();
        asm.pframe(0); asm.movi(R0, 0); asm.punframe(); asm.ret();
        let code = asm.to_bytes();
        let metadata: Vec<u8> = [1345400887u64, 2, 16, 1, 0, 16, 16, 0]
            .iter().flat_map(|word| word.to_le_bytes()).collect();
        let mut bytes = super::super::aom::AOM_MAGIC.to_vec();
        for word in [1u64, 112, 192, 112, 16, 8, 128, 64, 8, 192, 0, 192, 0] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend(code); bytes.extend(metadata);
        bytes
    }

    // Small guest ABI producer, NOT a substitute compiler/fixed-point witness.
    // It performs real Fabric writes, SYS_SEAL and protected launcher return.
    fn producer(bytes: &[u8], corrupt: Option<(i32, i32)>, status: i32) -> AnkaldLinkedImage {
        let mut asm = Asm64::new();
        asm.movi(R1, 73728);
        for (i, byte) in bytes.iter().enumerate() {
            asm.movi(R2, *byte as i32); asm.stb(R2, R1, i as i32);
        }
        asm.movi(R3, 68488); asm.ld(R4, R3, 0); asm.ld(R2, R4, 0);
        asm.movi(R3, 49152); asm.st(R2, R3, 0); asm.st(R2, R3, 8);
        asm.addi(R4, R4, 8); asm.st(R4, R3, 16);
        asm.movi(R2, bytes.len() as i32); asm.st(R2, R3, 72);
        // Dirty private scratch lies beyond the admitted serialized prefix.
        asm.movi(R3, 68456); asm.movi(R2, 131000); asm.add(R2, R2, R2);
        asm.st(R2, R3, 0); asm.add(R4, R1, R2);
        asm.movi(R2, 99); asm.st(R2, R4, 0);
        if let Some((address, value)) = corrupt {
            asm.movi(R3, address); asm.movi(R2, value); asm.st(R2, R3, 0);
        }
        asm.movi(R0, super::super::os::SYS_SEAL as i32); asm.trap(0);
        asm.movi(R0, status); asm.ret();
        if asm.to_bytes().len() % 8 != 0 { asm.nop(); }
        let bytes = asm.to_bytes();
        AnkaldLinkedImage { code_size: bytes.len() as u64, bytes, lit_start: 0,
            entry: 0, process_slots_observed: 1 }
    }

    pub(super) fn prepared(bytes: &[u8]) -> (CompilerOutput, Binding) {
        let compiler = producer(bytes, None, 0);
        let source = b"exact source\n".to_vec();
        let output = compile_for_adapter(&compiler, &source).unwrap();
        let bundle = SourceBundle::new("/test.c", [SourceBundleMember::new("/test.c", source.clone()).unwrap()]).unwrap();
        // These tools are lineage fixtures only; this test enters at the
        // private publication boundary and makes no guest preprocessing claim.
        let tool = CompiledCImage { bytes: vec![0; 8], code_size: 8, lit_start: 0,
            function_count: 1, process_slots_observed: 1 };
        let binding = Binding { origin_compiler_key: output.compiler_key, compiler,
            preprocessor: tool.clone(), linker: tool, bundle, source };
        (output, binding)
    }

    fn read_fixture(total: u64, rights: Permissions, grant_length: u64)
        -> (Fabric, DomainId, LinkedArtifactKey, Vec<u8>) {
        let mut fabric = Fabric::new(0x100000);
        let mut placement = PhysicalPlacementManager::new(0x1000, 0x80000).unwrap();
        let object = fabric.alloc_object("arena", total + 16, ObjectKind::Memory);
        placement.allocate_and_place_object(&mut fabric, object).unwrap();
        let bytes: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        assert!(fabric.initialize_object(object, 0, &bytes));
        assert!(fabric.initialize_object(object, total, &[255; 16]));
        assert!(fabric.seal_object(object));
        let reader = fabric.create_domain();
        fabric.grant(reader, object, 0, grant_length, rights).unwrap();
        let key = LinkedArtifactKey { object, generation: fabric.objects[&object].generation };
        (fabric, reader, key, bytes)
    }

    #[test]
    fn exact_prefix_uses_bounded_consecutive_fabric_reads() {
        for total in [65536, 65544, DEVELOPMENT_COMPILER_OUTPUT_SIZE] {
            let (mut fabric, reader, key, expected) = read_fixture(total, Permissions::READ, total);
            assert_eq!(copy_sealed_prefix(&mut fabric, reader, key, total).unwrap(), expected);
            let mut used = 0;
            for index in 0..total.div_ceil(COPY_LIMIT) {
                let tx = fabric.transaction(index as usize);
                assert_eq!(tx.request.object, key.object);
                assert_eq!(tx.request.context.domain, reader);
                assert_eq!(tx.request.offset, used);
                assert_eq!(tx.request.length, COPY_LIMIT.min(total - used));
                assert_eq!(tx.request.kind, AccessKind::Read);
                assert_eq!(tx.state, TxState::Committed);
                used += tx.request.length;
            }
            assert_eq!(used, total);
        }
    }

    #[test]
    fn copy_rejects_stale_wrong_domain_and_amplified_grants() {
        for (rights, length) in [(Permissions::RX, 128), (Permissions::READ, 120), (Permissions::READ, 136)] {
            let (mut fabric, reader, key, _) = read_fixture(128, rights, length);
            assert_eq!(copy_sealed_prefix(&mut fabric, reader, key, 128), Err(DevelopmentCompileError::AdapterReadDenied));
        }
        let (mut fabric, reader, mut key, _) = read_fixture(128, Permissions::READ, 128);
        key.generation = Generation(0);
        assert!(copy_sealed_prefix(&mut fabric, reader, key, 128).is_err());
        key.generation = Generation(1);
        let stranger = fabric.create_domain();
        assert!(copy_sealed_prefix(&mut fabric, stranger, key, 128).is_err());
        fabric.objects.get_mut(&key.object).unwrap().generation = Generation(2);
        assert!(copy_sealed_prefix(&mut fabric, reader, key, 128).is_err());
    }

    #[test]
    fn real_bridge_checks_source_controls_completion_and_return_status() {
        let aom = tiny_aom();
        let compiler = producer(&aom, None, 0);
        for source in [b"source".to_vec(), vec![b' '; 65528]] {
            let output = compile_for_adapter(&compiler, &source).unwrap();
            assert_eq!(output.bytes, aom);
            assert_eq!(output.source_length, source.len() as u64);
            assert_eq!(output.source_key.generation, Generation(1));
            assert_eq!(output.arena_key.generation, Generation(1));
        }
        assert!(matches!(compile_for_adapter(&compiler, &vec![0; 65529]), Err(DevelopmentCompileError::SourceTooLarge)));
        for corrupt in [(68480, 1), (68464, 0), (68488, 0), (68496, 0), (49152, 0), (68456, 112)] {
            assert!(matches!(compile_for_adapter(&producer(&aom, Some(corrupt), 0), b"source"),
                Err(DevelopmentCompileError::AdapterStateChanged)), "accepted {corrupt:?}");
        }
        assert!(matches!(compile_for_adapter(&producer(&aom, None, 7), b"source"),
            Err(DevelopmentCompileError::CompilerRejected(7))));
    }

    #[test]
    fn publication_binds_exact_source_profile_and_fresh_read_only_object() {
        let aom = tiny_aom();
        let (output, binding) = prepared(&aom);
        let arena_key = output.arena_key;
        let workspace = output.workspace_object;
        let mut store = RebuildArtifactStore::new();
        let authority = RebuildPublicationAuthority::provision();
        assert_eq!(store.publish(0, output, binding, Some(&authority)).unwrap(), 1);
        let receipt = store.receipt(1).unwrap();
        assert_eq!(store.artifact_bytes(1), Some(aom.as_slice()));
        assert_eq!(receipt.effective_source, b"exact source\n");
        assert_eq!(receipt.source_offset, 8);
        assert_eq!(receipt.target_profile, 2);
        assert_eq!(receipt.artifact_length, 192);
        assert!(![arena_key.object, workspace, receipt.source_key.object, receipt.compiler_key.object,
            receipt.profile_key.object].contains(&receipt.artifact_key.object));
        let record = &store.records[&1];
        let profile: Vec<u8> = PROFILE_WORDS.iter().flat_map(|word| word.to_le_bytes()).collect();
        assert_eq!(sealed_bytes(&record.fabric, &record.placement, receipt.profile_key), Some(profile.as_slice()));
        for domain in record.fabric.domains.keys() {
            for permission in [Permissions::WRITE, Permissions::EXECUTE, Permissions::SEAL] {
                assert!(record.fabric.find_authorizing_cap(*domain, receipt.artifact_key.object, 0, 1, permission).is_none());
            }
        }
    }

    #[test]
    fn failed_attempts_preserve_prior_artifact_and_receipt() {
        let authority = RebuildPublicationAuthority::provision();
        let mut store = RebuildArtifactStore::new();
        let (output, binding) = prepared(&tiny_aom());
        store.publish(0, output, binding, Some(&authority)).unwrap();
        let prior = store.receipt(1).unwrap().clone();
        let (output, binding) = prepared(&tiny_aom());
        assert!(matches!(store.publish(1, output, binding, None), Err(CompilerAdapterError::PublicationAuthorityRequired)));
        let (output, binding) = prepared(&tiny_aom());
        assert!(matches!(store.publish(0, output, binding, Some(&authority)), Err(CompilerAdapterError::StaleEpoch)));
        let (output, mut binding) = prepared(&tiny_aom());
        binding.compiler.bytes[0] ^= 1;
        assert!(matches!(store.publish(1, output, binding, Some(&authority)), Err(CompilerAdapterError::BindingChanged)));
        let (mut output, binding) = prepared(&tiny_aom());
        output.fabric.objects.get_mut(&output.compiler_key.object).unwrap().generation = Generation(2);
        assert!(matches!(store.publish(1, output, binding, Some(&authority)), Err(CompilerAdapterError::BindingChanged)));
        let mut malformed = tiny_aom(); malformed[0] ^= 1;
        let (output, binding) = prepared(&malformed);
        assert!(matches!(store.publish(1, output, binding, Some(&authority)), Err(CompilerAdapterError::InvalidAom(_))));
        let mut bad_table = tiny_aom(); bad_table[80] = 184; // symbol table overlaps rodata
        for malformed in [bad_table, tiny_aom()[..184].to_vec()] {
            let (output, binding) = prepared(&malformed);
            assert!(matches!(store.publish(1, output, binding, Some(&authority)), Err(CompilerAdapterError::InvalidAom(_))));
        }
        let (mut output, binding) = prepared(&tiny_aom());
        output.bytes.truncate(184); // partial accumulator cannot reuse a full-prefix grant
        assert!(matches!(store.publish(1, output, binding, Some(&authority)), Err(CompilerAdapterError::BindingChanged)));
        let mut wrong_profile = tiny_aom(); wrong_profile[136] = 1; // manifest v1, not v2
        let (output, binding) = prepared(&wrong_profile);
        assert!(matches!(store.publish(1, output, binding, Some(&authority)), Err(CompilerAdapterError::InvalidProtectedManifest)));
        assert_eq!(store.epoch(), 1);
        assert_eq!(store.records.len(), 1);
        assert_eq!(store.receipt(1), Some(&prior));
        assert_eq!(store.artifact_bytes(1), Some(tiny_aom().as_slice()));
        assert!(store.receipt(2).is_none());
        assert!(store.artifact_bytes(2).is_none());
        let (output, binding) = prepared(&tiny_aom());
        assert_eq!(store.publish(1, output, binding, Some(&authority)).unwrap(), 2);
        assert_eq!(store.receipt(1), Some(&prior));
        assert_ne!(store.receipt(2).unwrap().context, prior.context);
        assert_eq!(store.artifact_bytes(2), Some(tiny_aom().as_slice()));
    }

    #[test]
    fn publication_allocation_failure_and_epoch_exhaustion_are_atomic() {
        let authority = RebuildPublicationAuthority::provision();
        let mut store = RebuildArtifactStore::new();
        let (mut output, binding) = prepared(&tiny_aom());
        // Consume the real PM pool; the publication path must fail without
        // installing a receipt, even though compiler execution succeeded.
        let free = output.placement.free_bytes();
        let filler = output.fabric.alloc_object("full pool", free, ObjectKind::Memory);
        output.placement.allocate_and_place_object(&mut output.fabric, filler).unwrap();
        assert!(matches!(store.publish(0, output, binding, Some(&authority)), Err(CompilerAdapterError::Placement(_))));
        assert_eq!(store.epoch(), 0); assert!(store.records.is_empty());
        store.epoch = u64::MAX;
        let (output, binding) = prepared(&tiny_aom());
        assert!(matches!(store.publish(u64::MAX, output, binding, Some(&authority)), Err(CompilerAdapterError::EpochExhausted)));
        assert!(store.records.is_empty());
    }
}
