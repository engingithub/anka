//! Ordered protected-module dependencies and atomic linked-image receipts.
//! The request is frozen by the store; caller-supplied bytes or receipt copies
//! never establish current identity. All code/manifest construction is guest work.
use super::*;
use super::super::ankald::{run_application_ankald_for_publication,
    validate_application_link_result, ApplicationLinkProfile, AnkaldOutput};
use super::super::dev_runner::{run_registered_artifact, DevelopmentRunError, DevelopmentRunReport};
use super::super::dev_shell::DevelopmentArtifactRegistry;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrozenDependency {
    position: usize,
    receipt: RebuildReceipt,
    bytes: Vec<u8>,
}

/// Immutable ordered request. Store epoch and full dependency snapshots bind
/// the reservation; changing the store requires freezing a new request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenModuleLink {
    profile: ApplicationLinkProfile,
    expected_epoch: u64,
    dependencies: Vec<FrozenDependency>,
    linker: CompiledCImage,
}
impl FrozenModuleLink {
    pub fn profile(&self) -> ApplicationLinkProfile { self.profile }
    pub fn expected_epoch(&self) -> u64 { self.expected_epoch }
    pub fn module_count(&self) -> usize { self.dependencies.len() }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedModuleDependency {
    pub position: usize,
    /// Original context-qualified module identity and complete compiler lineage.
    pub compiler_receipt: RebuildReceipt,
    pub aom_bytes: Vec<u8>,
    /// Exact sealed input object consumed in the linked receipt's context.
    pub transport_key: LinkedArtifactKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedRebuildReceipt {
    pub profile: ApplicationLinkProfile,
    pub epoch: u64,
    pub role: RebuildAdmissionRole,
    pub context: u64,
    pub process_slot: u64,
    pub process_generation: u64,
    pub producer_domain: DomainId,
    pub artifact_key: LinkedArtifactKey,
    pub artifact_permissions: Permissions,
    /// Exact bytes, entry, code extent and merged-manifest boundary.
    pub image: AnkaldLinkedImage,
    pub linker_image: CompiledCImage,
    pub linker_key: LinkedArtifactKey,
    pub staging_key: LinkedArtifactKey,
    pub control_key: LinkedArtifactKey,
    pub dependencies: Vec<LinkedModuleDependency>,
}

pub(super) struct PublishedLinkedRebuild {
    fabric: Fabric,
    placement: PhysicalPlacementManager,
    reader: DomainId,
    context: u64,
    receipt: LinkedRebuildReceipt,
}

impl RebuildArtifactStore {
    pub fn linked_receipt(&self, epoch: u64) -> Option<&LinkedRebuildReceipt> {
        self.linked_records.get(&epoch).map(|record| &record.receipt)
    }

    /// READ data only. Application registration/loading and explicit execution
    /// authority remain separate; no module or receipt grants EXECUTE.
    pub fn linked_image(&self, epoch: u64) -> Option<&AnkaldLinkedImage> {
        let record = self.linked_records.get(&epoch)?;
        let receipt = &record.receipt;
        if record.context != receipt.context
            || receipt.role != RebuildAdmissionRole::LinkedImage
            || receipt.artifact_permissions != Permissions::READ
            || !exact_read_grant(&record.fabric, record.reader, receipt.artifact_key,
                receipt.image.bytes.len() as u64)
            || sealed_bytes(&record.fabric, &record.placement, receipt.artifact_key)
                != Some(receipt.image.bytes.as_slice()) { return None; }
        Some(&receipt.image)
    }

    /// Execute the exact current publication named by this complete receipt.
    /// A copied receipt selects evidence to compare; it grants no authority.
    /// Registration uses the existing sealed object in its original Fabric,
    /// and ordinary SYS_SPAWN admission derives RX code / READ metadata only
    /// after the caller explicitly authorizes application execution.
    pub fn run_linked_application(&mut self, expected: &LinkedRebuildReceipt,
        execution: Option<&DeveloperExecutionAuthority>)
        -> Result<DevelopmentRunReport, CompilerAdapterError> {
        execution.ok_or(CompilerAdapterError::ExecutionAuthorityRequired)?;
        self.validate_linked_execution(expected)?;
        let record = self.linked_records.get_mut(&expected.epoch)
            .ok_or(CompilerAdapterError::BindingChanged)?;
        let image = &record.receipt.image;
        let artifact = super::super::ankald::LinkedArtifact {
            key: record.receipt.artifact_key, logical_size: image.bytes.len() as u64,
            code_size: image.code_size, lit_start: image.lit_start, entry: image.entry,
            code_permissions: Permissions::RX, rodata_permissions: Some(Permissions::READ),
        };
        let mut registry = DevelopmentArtifactRegistry::new();
        registry.register_linked_application(&record.fabric, &artifact)
            .map_err(|error| CompilerAdapterError::Run(DevelopmentRunError::Artifact(error)))?;
        run_registered_artifact(&registry, execution, &mut record.fabric,
            &mut record.placement, "rebuilt-application").map_err(CompilerAdapterError::Run)
    }

    fn validate_linked_execution(&self, expected: &LinkedRebuildReceipt)
        -> Result<(), CompilerAdapterError> {
        let record = self.linked_records.get(&expected.epoch)
            .ok_or(CompilerAdapterError::BindingChanged)?;
        let receipt = &record.receipt;
        if receipt != expected || self.linked_image(expected.epoch).is_none()
            || receipt.context == 0 || receipt.process_slot != 0 || receipt.process_generation == 0
            || receipt.dependencies.is_empty() || receipt.dependencies.len() > 4096
            || sealed_bytes(&record.fabric, &record.placement, receipt.linker_key)
                != Some(receipt.linker_image.bytes.as_slice()) {
            return Err(CompilerAdapterError::BindingChanged);
        }
        let mut modules = Vec::with_capacity(receipt.dependencies.len());
        let mut distinct = std::collections::BTreeSet::from([
            receipt.artifact_key.object, receipt.linker_key.object,
            receipt.staging_key.object, receipt.control_key.object]);
        if distinct.len() != 4 { return Err(CompilerAdapterError::BindingChanged); }
        for (position, dependency) in receipt.dependencies.iter().enumerate() {
            let (compiler_receipt, bytes) = self.current_module(dependency.compiler_receipt.epoch)?;
            if dependency.position != position || compiler_receipt != &dependency.compiler_receipt
                || compiler_receipt.context == receipt.context
                || compiler_receipt.linker_image != receipt.linker_image
                || bytes != dependency.aom_bytes
                || !distinct.insert(dependency.transport_key.object)
                || sealed_bytes(&record.fabric, &record.placement, dependency.transport_key)
                    != Some(bytes) {
                return Err(CompilerAdapterError::DependencyChanged);
            }
            modules.push(ValidatedPointerModule::from_aom_with_limit(bytes, receipt.profile.module_limit())
                .map_err(|_| CompilerAdapterError::InvalidProtectedManifest)?);
        }
        // Recompute complete closure and exact guest patch/manifest checks.
        // No cached success flag, supplied byte buffer or receipt clone can
        // bypass admission. No new epoch or publication is created by a run.
        validate_application_link_result(&modules, &receipt.image, receipt.profile).map_err(CompilerAdapterError::Link)
    }

    pub fn freeze_modules(&self, epochs: &[u64]) -> Result<FrozenModuleLink, CompilerAdapterError> {
        self.freeze_modules_with_profile(epochs, ApplicationLinkProfile::Standard)
    }

    /// Explicit coordinator policy. Guest objects cannot choose their own
    /// capacity or producer entry ABI. Execution/publication authorities are
    /// still required when the request is executed.
    pub fn freeze_modules_with_profile(&self, epochs: &[u64], profile: ApplicationLinkProfile)
        -> Result<FrozenModuleLink, CompilerAdapterError> {
        self.next_epoch(self.epoch)?;
        if epochs.is_empty() || epochs.len() > 4096 {
            return Err(CompilerAdapterError::InvalidModuleDependency);
        }
        let mut dependencies = Vec::with_capacity(epochs.len());
        for (position, &epoch) in epochs.iter().enumerate() {
            let (receipt, bytes) = self.current_module(epoch)?;
            dependencies.push(FrozenDependency { position, receipt: receipt.clone(), bytes: bytes.to_vec() });
        }
        let linker = dependencies[0].receipt.linker_image.clone();
        let request = FrozenModuleLink { profile, expected_epoch: self.epoch, dependencies, linker };
        self.validate_dependencies(&request)?;
        Ok(request)
    }

    pub fn link_modules(&mut self, request: &FrozenModuleLink,
        execution: Option<&DeveloperExecutionAuthority>, publication: Option<&RebuildPublicationAuthority>)
        -> Result<u64, CompilerAdapterError> {
        execution.ok_or(CompilerAdapterError::ExecutionAuthorityRequired)?;
        publication.ok_or(CompilerAdapterError::PublicationAuthorityRequired)?;
        let modules = self.validate_dependencies(request)?;
        let output = run_application_ankald_for_publication(&request.linker.bytes, &modules, request.profile)
            .map_err(CompilerAdapterError::Link)?;
        self.publish_link(request, output, publication)
    }

    fn current_module(&self, epoch: u64) -> Result<(&RebuildReceipt, &[u8]), CompilerAdapterError> {
        let record = self.records.get(&epoch).ok_or(CompilerAdapterError::InvalidModuleDependency)?;
        let receipt = &record.receipt;
        if receipt.role != RebuildAdmissionRole::RelocatableModule {
            return Err(CompilerAdapterError::InvalidModuleDependency);
        }
        let source = sealed_bytes(&record.fabric, &record.placement, receipt.source_key)
            .ok_or(CompilerAdapterError::DependencyChanged)?;
        let length = receipt.effective_source.len();
        if receipt.epoch != epoch || receipt.context == 0 || receipt.context != record.context
            || receipt.process_slot != 0 || receipt.process_generation == 0
            || receipt.source_offset != 8 || receipt.target_profile != 2
            || source.get(..8) != Some((length as u64).to_le_bytes().as_slice())
            || source.get(8..8 + length) != Some(receipt.effective_source.as_slice())
            || source.get(8 + length..).is_none_or(|tail| tail.iter().any(|b| *b != 0))
            || sealed_bytes(&record.fabric, &record.placement, receipt.compiler_key)
                != Some(receipt.compiler_image.bytes.as_slice())
            || sealed_bytes(&record.fabric, &record.placement, receipt.profile_key)
                != Some(profile_bytes().as_slice())
            || !record.fabric.compiler_trace_safe(receipt.artifact_key.object) {
            return Err(CompilerAdapterError::DependencyChanged);
        }
        let bytes = self.artifact_bytes(epoch).ok_or(CompilerAdapterError::DependencyChanged)?;
        if bytes.len() as u64 != receipt.artifact_length {
            return Err(CompilerAdapterError::DependencyChanged);
        }
        Ok((receipt, bytes))
    }

    fn validate_dependencies(&self, request: &FrozenModuleLink)
        -> Result<Vec<ValidatedPointerModule>, CompilerAdapterError> {
        self.next_epoch(request.expected_epoch)?;
        if request.dependencies.is_empty() || request.dependencies.len() > 4096 {
            return Err(CompilerAdapterError::InvalidModuleDependency);
        }
        let mut modules = Vec::with_capacity(request.dependencies.len());
        for (position, dependency) in request.dependencies.iter().enumerate() {
            let (receipt, bytes) = self.current_module(dependency.receipt.epoch)?;
            if dependency.position != position || receipt != &dependency.receipt
                || bytes != dependency.bytes || receipt.linker_image != request.linker {
                return Err(CompilerAdapterError::DependencyChanged);
            }
            modules.push(ValidatedPointerModule::from_aom_with_limit(bytes, request.profile.module_limit())
                .map_err(|_| CompilerAdapterError::InvalidProtectedManifest)?);
        }
        Ok(modules)
    }

    fn publish_link(&mut self, request: &FrozenModuleLink, mut output: AnkaldOutput,
        publication: Option<&RebuildPublicationAuthority>) -> Result<u64, CompilerAdapterError> {
        publication.ok_or(CompilerAdapterError::PublicationAuthorityRequired)?;
        let epoch = self.next_epoch(request.expected_epoch)?;
        // Check current identities/receipts again after guest execution, while
        // exclusive store ownership still holds the same epoch reservation.
        let modules = self.validate_dependencies(request)?;
        validate_link_binding(request, &modules, &output)?;
        let reader = output.fabric.create_domain();
        let artifact_key = publish_read_only(&mut output.fabric, &mut output.placement,
            reader, "rebuilt-protected-link", &output.image.bytes)?;
        if output.input_keys.iter().map(|k| k.object).chain([
            output.linker_key.object, output.scratch_key.object, output.control_key.object])
            .any(|object| object == artifact_key.object) {
            return Err(CompilerAdapterError::PublicationRejected);
        }
        let dependencies = request.dependencies.iter().zip(&output.input_keys)
            .map(|(dependency, &transport_key)| LinkedModuleDependency {
                position: dependency.position, compiler_receipt: dependency.receipt.clone(),
                aom_bytes: dependency.bytes.clone(), transport_key,
            }).collect();
        let receipt = LinkedRebuildReceipt { profile: request.profile, epoch, role: RebuildAdmissionRole::LinkedImage,
            context: output.context, process_slot: output.process_slot,
            process_generation: output.process_generation, producer_domain: output.domain,
            artifact_key, artifact_permissions: Permissions::READ, image: output.image,
            linker_image: request.linker.clone(), linker_key: output.linker_key,
            staging_key: output.scratch_key, control_key: output.control_key, dependencies };
        // Single visibility decision, no fallible work or guest execution after it.
        self.linked_records.insert(epoch, PublishedLinkedRebuild { fabric: output.fabric,
            placement: output.placement, reader, context: output.context, receipt });
        self.epoch = epoch;
        Ok(epoch)
    }
}

fn validate_link_binding(request: &FrozenModuleLink, modules: &[ValidatedPointerModule],
    output: &AnkaldOutput) -> Result<(), CompilerAdapterError> {
    let reject = || CompilerAdapterError::BindingChanged;
    if output.link_profile != request.profile.wire()
        || output.context == 0 || output.process_slot != 0 || output.process_generation == 0
        || !output.fabric.domains.contains_key(&output.domain)
        || request.dependencies.iter().any(|d| d.receipt.context == output.context)
        || output.input_keys.len() != request.dependencies.len()
        || !output.fabric.compiler_trace_safe(output.scratch_key.object)
        || sealed_bytes(&output.fabric, &output.placement, output.linker_key)
            != Some(request.linker.bytes.as_slice()) {
        return Err(reject());
    }
    let mut distinct = std::collections::BTreeSet::new();
    for key in output.input_keys.iter().copied().chain([
        output.linker_key, output.scratch_key, output.control_key]) {
        if !distinct.insert(key.object) { return Err(reject()); }
    }
    for (dependency, &key) in request.dependencies.iter().zip(&output.input_keys) {
        if !exact_read_grant(&output.fabric, output.domain, key, dependency.bytes.len() as u64)
            || sealed_bytes(&output.fabric, &output.placement, key) != Some(dependency.bytes.as_slice()) {
            return Err(reject());
        }
    }
    for key in [output.scratch_key, output.control_key] {
        if output.fabric.objects.get(&key.object).is_none_or(|object|
            object.state != ObjectState::Active || object.generation != key.generation) {
            return Err(reject());
        }
    }
    let control = output.placement.allocated_extent(output.control_key.object).ok_or_else(reject)?;
    if output.fabric.objects[&output.control_key.object].size < 96
        || output.fabric.read_physical(control.base + 88, 8)
            != request.profile.wire().to_le_bytes().as_slice() {
        return Err(reject());
    }
    let scratch = &output.fabric.objects[&output.scratch_key.object];
    let extent = output.placement.allocated_extent(output.scratch_key.object).ok_or_else(reject)?;
    if output.image.bytes.len() as u64 > scratch.size
        || output.fabric.read_physical(extent.base, output.image.bytes.len() as u64) != output.image.bytes {
        return Err(reject());
    }
    validate_application_link_result(modules, &output.image, request.profile).map_err(CompilerAdapterError::Link)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::{prepared, tiny_aom};
    use super::super::super::ankald::{run_ankald, AnkaldError};
    use super::super::super::ankald_tests::{ankald_image, protected_test_modules};

    // The short ABI producers are publication-boundary fixtures, not CC2
    // lineage substitutes. The long p107 test covers the public compile API
    // using its real fixed-point witness. Linking here executes real ankald.
    pub(super) fn modules() -> (RebuildArtifactStore, RebuildPublicationAuthority) {
        let authority = RebuildPublicationAuthority::provision();
        let mut store = RebuildArtifactStore::new();
        for module in protected_test_modules() {
            let (output, mut binding) = prepared(module.bytes());
            binding.linker = ankald_image().clone();
            store.publish_as(store.epoch(), output, binding, Some(&authority),
                RebuildAdmissionRole::RelocatableModule).unwrap();
        }
        (store, authority)
    }

    pub(super) fn output(request: &FrozenModuleLink) -> AnkaldOutput {
        let modules: Vec<_> = request.dependencies.iter()
            .map(|d| ValidatedPointerModule::from_aom_with_limit(&d.bytes, request.profile.module_limit()).unwrap()).collect();
        run_application_ankald_for_publication(&request.linker.bytes, &modules, request.profile).unwrap()
    }

    pub(super) fn assert_read_only(fabric: &Fabric, key: LinkedArtifactKey) {
        for &domain in fabric.domains.keys() {
            for permission in [Permissions::WRITE, Permissions::EXECUTE, Permissions::SEAL] {
                assert!(fabric.find_authorizing_cap(domain, key.object, 0, 1, permission).is_none());
            }
        }
    }

    // Short executable modules isolate the loader/call/lifetime boundary.
    // The long acceptance separately compiles the actual C probes with CC2.
    fn executable_modules(escape: bool, one_past: bool) -> Vec<ValidatedPointerModule> {
        use crate::anka64::isa::{Asm64, R0, R1, R2, R4, R5, R12};
        use crate::anka64::ankald_tests::protected_test_aom;
        macro_rules! slot { ($asm:ident, $op:ident($($arg:expr),*)) => {
            $asm.$op($($arg),*); $asm.nop();
        }; }
        let mut caller = Asm64::new();
        slot!(caller, pframe(0)); slot!(caller, plocal(R0, 0));
        slot!(caller, movi(R12, 41)); slot!(caller, pwrite(R12, R0, 1));
        if one_past {
            slot!(caller, movi(R12, 1)); slot!(caller, padd(R0, R0, R12));
        }
        let call = caller.here() as u64 * 4;
        slot!(caller, call(0));
        if !escape { slot!(caller, plocal(R0, 0)); }
        slot!(caller, pread(R12, R0, 1));
        // Preserve the protected pair while preparing the typed write syscall.
        slot!(caller, pmov(R2, R0)); slot!(caller, movi(R0, crate::anka64::os::SYS_WRITE as i32));
        slot!(caller, movi(R1, 0)); slot!(caller, movi(R4, 1));
        slot!(caller, movi(R5, 0)); slot!(caller, trap(0));
        slot!(caller, movi(R0, 0)); slot!(caller, movi(R1, 42)); slot!(caller, trap(0));
        slot!(caller, punframe()); slot!(caller, ret());
        let mut callee = Asm64::new();
        slot!(callee, pframe(0));
        if escape { slot!(callee, plocal(R0, 0)); }
        slot!(callee, movi(R12, 42)); slot!(callee, pwrite(R12, R0, 1));
        if !escape { slot!(callee, movi(R0, 0)); }
        slot!(callee, punframe()); slot!(callee, ret());
        let module = |asm: Asm64, symbols: &[(&str, u64, u64, &[u64])], relocs: &[(u64,u64)]| {
            let code = asm.to_bytes();
            let metadata: Vec<u8> = [1345400887u64, 2, code.len() as u64, 1,
                0, code.len() as u64, 16, 1, 0, 1, 1, 1]
                .iter().flat_map(|w| w.to_le_bytes()).collect();
            let mut bytes = protected_test_aom(&code, &metadata, symbols, relocs);
            if escape {
                // Both declarations have the same char* return type.
                let parsed = crate::anka64::aom::AomModule::parse(&bytes).unwrap();
                let i = parsed.symbols.iter().position(|s| s.name == "helper").unwrap();
                let offset = parsed.header.symbol_offset as usize + i * 160 + 112;
                bytes[offset..offset+8].copy_from_slice(&1002u64.to_le_bytes());
            }
            ValidatedPointerModule::from_aom(&bytes).unwrap()
        };
        vec![module(caller, &[("main",1,0,&[]),("helper",2,0,&[1002])], &[(call,1)]),
            module(callee, &[("helper",1,0,&[1002])], &[])]
    }

    pub(super) fn executable_store(escape: bool, one_past: bool) -> (RebuildArtifactStore, LinkedRebuildReceipt) {
        let mut store = RebuildArtifactStore::new();
        let publication = RebuildPublicationAuthority::provision();
        for module in executable_modules(escape, one_past) {
            let (output, mut binding) = prepared(module.bytes());
            binding.linker = ankald_image().clone();
            store.publish_as(store.epoch(), output, binding, Some(&publication),
                RebuildAdmissionRole::RelocatableModule).unwrap();
        }
        let request = store.freeze_modules(&[1,2]).unwrap();
        let execution = DeveloperExecutionAuthority::provision();
        let epoch = store.link_modules(&request, Some(&execution), Some(&publication)).unwrap();
        let receipt = store.linked_receipt(epoch).unwrap().clone();
        (store, receipt)
    }

    #[test]
    fn p108_module_execution_requires_authority_and_preserves_publication() {
        let (mut store, receipt) = executable_store(false, false);
        let record = &store.linked_records[&3];
        let before = (record.fabric.objects.len(), record.fabric.domains.len(), record.placement.free_bytes());
        assert!(matches!(store.run_linked_application(&receipt, None),
            Err(CompilerAdapterError::ExecutionAuthorityRequired)));
        let record = &store.linked_records[&3];
        assert_eq!(before, (record.fabric.objects.len(), record.fabric.domains.len(), record.placement.free_bytes()));
        assert_read_only(&record.fabric, receipt.artifact_key);
        let execution = DeveloperExecutionAuthority::provision();
        // A second run must survive ordinary process teardown with unchanged
        // publication identity, epoch, bytes, and original READ-only grant.
        for _ in 0..2 {
            let report = store.run_linked_application(&receipt, Some(&execution)).unwrap();
            assert_eq!(report.child_result, crate::anka64::os::ProcessResult::Exited(42));
            assert_eq!(report.byte_output, [42]);
            assert_eq!(report.artifact.object, receipt.artifact_key.object);
            assert_eq!(report.artifact.generation, receipt.artifact_key.generation);
            assert_eq!(report.presented_code_permissions, Permissions::RX);
            assert_eq!(report.presented_literal_permissions, Some(Permissions::READ));
            assert!(report.process_slots_observed >= 2);
            assert_eq!(store.epoch(), 3);
            assert_eq!(store.linked_receipt(3), Some(&receipt));
            assert_eq!(store.linked_image(3), Some(&receipt.image));
            assert_read_only(&store.linked_records[&3].fabric, receipt.artifact_key);
        }
    }

    #[test]
    fn p108_module_execution_rejects_substituted_receipts_before_loading() {
        let (mut store, receipt) = executable_store(false, false);
        let execution = DeveloperExecutionAuthority::provision();
        let before = store.linked_records[&3].placement.free_bytes();
        for mutation in 0..10 {
            let mut changed = receipt.clone();
            match mutation {
                0 => changed.epoch = 1, // A module is not an executable publication.
                1 => changed.context += 1,
                2 => changed.artifact_key.generation.0 += 1,
                3 => changed.role = RebuildAdmissionRole::RelocatableModule,
                4 => changed.image.bytes[0] ^= 1,
                5 => changed.image.entry = 8,
                6 => changed.dependencies.swap(0,1),
                7 => changed.dependencies[0].compiler_receipt.effective_source.push(0),
                8 => changed.linker_image.bytes[0] ^= 1,
                _ => changed.artifact_permissions = Permissions::RX,
            }
            assert!(matches!(store.run_linked_application(&changed, Some(&execution)),
                Err(CompilerAdapterError::BindingChanged)), "mutation {mutation}");
        }
        let (_, foreign) = executable_store(false, false);
        assert_eq!(foreign.artifact_key, receipt.artifact_key);
        assert_eq!(foreign.image, receipt.image);
        assert_ne!(foreign.context, receipt.context);
        assert!(matches!(store.run_linked_application(&foreign, Some(&execution)),
            Err(CompilerAdapterError::BindingChanged)));
        assert_eq!(store.linked_records[&3].placement.free_bytes(), before);
        assert_eq!(store.epoch(), 3);
        assert_read_only(&store.linked_records[&3].fabric, receipt.artifact_key);
    }

    #[test]
    fn p108_module_execution_rechecks_live_objects_and_closed_image() {
        let (mut store, receipt) = executable_store(false, false);
        let execution = DeveloperExecutionAuthority::provision();
        for key in [receipt.artifact_key, receipt.linker_key, receipt.dependencies[0].transport_key] {
            store.linked_records.get_mut(&3).unwrap().fabric.objects.get_mut(&key.object).unwrap().generation.0 += 1;
            assert!(store.run_linked_application(&receipt, Some(&execution)).is_err());
            store.linked_records.get_mut(&3).unwrap().fabric.objects.get_mut(&key.object).unwrap().generation = key.generation;
        }
        let reader = store.linked_records[&3].reader;
        store.linked_records.get_mut(&3).unwrap().reader = DomainId(u64::MAX);
        assert!(matches!(store.run_linked_application(&receipt, Some(&execution)), Err(CompilerAdapterError::BindingChanged)));
        store.linked_records.get_mut(&3).unwrap().reader = reader;
        let key = receipt.dependencies[0].compiler_receipt.artifact_key;
        store.records.get_mut(&1).unwrap().fabric.objects.get_mut(&key.object).unwrap().generation.0 += 1;
        assert!(matches!(store.run_linked_application(&receipt, Some(&execution)), Err(CompilerAdapterError::DependencyChanged)));
        store.records.get_mut(&1).unwrap().fabric.objects.get_mut(&key.object).unwrap().generation = key.generation;
        let record = store.linked_records.get_mut(&3).unwrap();
        let base = record.placement.allocated_extent(receipt.artifact_key.object).unwrap().base;
        record.fabric.write_physical(base, &[receipt.image.bytes[0] ^ 1]);
        assert!(matches!(store.run_linked_application(&receipt, Some(&execution)), Err(CompilerAdapterError::BindingChanged)));
        store.linked_records.get_mut(&3).unwrap().fabric.write_physical(base, &receipt.image.bytes[..1]);
        // Even matching stored/supplied receipts cannot skip recomputation of
        // entry/closure/manifest obligations over the actual sealed bytes.
        for mutation in 0..3 {
            let mut invalid = receipt.clone();
            match mutation {
                0 => invalid.image.entry = 8,
                1 => invalid.image.code_size -= 8,
                _ => invalid.dependencies[0].position = 1,
            }
            store.linked_records.get_mut(&3).unwrap().receipt = invalid.clone();
            assert!(store.run_linked_application(&invalid, Some(&execution)).is_err());
        }
        store.linked_records.get_mut(&3).unwrap().receipt = receipt.clone();
        store.validate_linked_execution(&receipt).unwrap();
        assert_read_only(&store.linked_records[&3].fabric, receipt.artifact_key);
    }

    #[test]
    fn p108_module_execution_rejects_escaped_local_and_one_past_access() {
        let execution = DeveloperExecutionAuthority::provision();
        for (escape, one_past) in [(true,false),(false,true)] {
            let (mut store, receipt) = executable_store(escape, one_past);
            let report = store.run_linked_application(&receipt, Some(&execution)).unwrap();
            assert_eq!(report.child_result, crate::anka64::os::ProcessResult::ProtectionFault);
            assert!(report.byte_output.is_empty());
            assert_eq!(store.linked_image(3), Some(&receipt.image));
            assert_read_only(&store.linked_records[&3].fabric, receipt.artifact_key);
        }
    }

    #[test]
    fn p108_module_execution_placement_failure_keeps_receipt_and_allows_retry() {
        let (mut store, receipt) = executable_store(false, false);
        let execution = DeveloperExecutionAuthority::provision();
        let record = store.linked_records.get_mut(&3).unwrap();
        let filler = record.fabric.alloc_object("full execution pool", record.placement.free_bytes(), ObjectKind::Memory);
        record.placement.allocate_and_place_object(&mut record.fabric, filler).unwrap();
        assert!(matches!(store.run_linked_application(&receipt, Some(&execution)),
            Err(CompilerAdapterError::Run(DevelopmentRunError::Placement(_)))));
        assert_eq!(store.linked_receipt(3), Some(&receipt));
        assert_eq!(store.linked_image(3), Some(&receipt.image));
        assert_eq!(store.epoch(), 3);
        let record = store.linked_records.get_mut(&3).unwrap();
        assert_read_only(&record.fabric, receipt.artifact_key);
        assert!(record.fabric.rollback_unpublished_object(filler));
        record.placement.release_unplaced(&record.fabric, filler).unwrap();
        assert_eq!(store.run_linked_application(&receipt, Some(&execution)).unwrap().child_result,
            crate::anka64::os::ProcessResult::Exited(42));
    }

    #[test]
    fn p108_module_publication_keeps_admission_roles_separate() {
        let authority = RebuildPublicationAuthority::provision();
        let mut store = RebuildArtifactStore::new();
        let bytes = protected_test_modules()[0].bytes().to_vec();
        let (compiled, binding) = prepared(&bytes);
        assert!(matches!(store.publish(0, compiled, binding, Some(&authority)),
            Err(CompilerAdapterError::InvalidProtectedManifest)));
        assert_eq!(store.epoch(), 0);
        let (compiled, binding) = prepared(&tiny_aom());
        store.publish(0, compiled, binding, Some(&authority)).unwrap();
        assert!(matches!(store.freeze_modules(&[1]), Err(CompilerAdapterError::InvalidModuleDependency)));
        let (compiled, binding) = prepared(&tiny_aom());
        assert!(matches!(store.publish_as(1, compiled, binding, Some(&authority),
            RebuildAdmissionRole::RelocatableModule), Err(CompilerAdapterError::InvalidProtectedManifest)));
        let (store, _) = modules();
        for record in store.records.values() {
            assert_eq!(record.receipt.role, RebuildAdmissionRole::RelocatableModule);
            assert_read_only(&record.fabric, record.receipt.artifact_key);
        }
        assert!(matches!(store.freeze_modules(&[]), Err(CompilerAdapterError::InvalidModuleDependency)));
        assert!(matches!(store.freeze_modules(&vec![1; 4097]), Err(CompilerAdapterError::InvalidModuleDependency)));
    }

    #[test]
    fn p108_module_publication_binds_order_identity_tools_and_exact_image() {
        let (mut store, authority) = modules();
        let execution = DeveloperExecutionAuthority::provision();
        let request = store.freeze_modules(&[1, 2]).unwrap();
        assert_eq!(request.expected_epoch(), 2);
        assert_eq!(request.module_count(), 2);
        let epoch = store.link_modules(&request, Some(&execution), Some(&authority)).unwrap();
        assert_eq!(epoch, 3);
        let receipt = store.linked_receipt(epoch).unwrap();
        assert_eq!(receipt.role, RebuildAdmissionRole::LinkedImage);
        assert_eq!(receipt.artifact_permissions, Permissions::READ);
        assert_eq!(receipt.image.bytes.len(), 336);
        assert_eq!((receipt.image.code_size, receipt.image.lit_start, receipt.image.entry), (112, 112, 0));
        assert_eq!(receipt.linker_image, *ankald_image());
        assert_eq!(store.linked_image(epoch), Some(&receipt.image));
        assert_eq!(receipt.dependencies.len(), 2);
        // Equal bare object numbers in different Fabrics are deliberately normal.
        assert_eq!(receipt.dependencies[0].compiler_receipt.artifact_key,
            receipt.dependencies[1].compiler_receipt.artifact_key);
        assert_ne!(receipt.dependencies[0].compiler_receipt.context,
            receipt.dependencies[1].compiler_receipt.context);
        for (i, dependency) in receipt.dependencies.iter().enumerate() {
            assert_eq!(dependency.position, i);
            assert_eq!(dependency.compiler_receipt, request.dependencies[i].receipt);
            assert_eq!(dependency.aom_bytes, request.dependencies[i].bytes);
            assert_ne!(dependency.compiler_receipt.context, receipt.context);
            assert_ne!(dependency.transport_key.object, receipt.artifact_key.object);
        }
        let record = &store.linked_records[&epoch];
        assert_read_only(&record.fabric, receipt.artifact_key);
        assert!(store.receipt(epoch).is_none());
        assert!(store.artifact_bytes(epoch).is_none());
        assert!(matches!(store.freeze_modules(&[epoch]), Err(CompilerAdapterError::InvalidModuleDependency)));
    }

    #[test]
    fn p108_module_publication_rejects_frozen_dependency_substitution() {
        let (store, _) = modules();
        let request = store.freeze_modules(&[1, 2]).unwrap();
        for mutation in 0..12 {
            let mut changed = request.clone();
            match mutation {
                0 => changed.dependencies[0].receipt.context += 1,
                1 => changed.dependencies[0].receipt.artifact_key.generation.0 += 1,
                2 => changed.dependencies[0].position = 1,
                3 => changed.dependencies.swap(0, 1),
                4 => changed.dependencies[0].bytes[0] ^= 1,
                5 => changed.dependencies[0].receipt.effective_source.push(0),
                6 => changed.dependencies[0].receipt.compiler_image.bytes[0] ^= 1,
                7 => changed.dependencies[0].receipt.preprocessor_image.bytes[0] ^= 1,
                8 => changed.linker.bytes[0] ^= 1,
                9 => changed.dependencies[0].receipt.target_profile = 1,
                10 => changed.dependencies[0].receipt.role = RebuildAdmissionRole::ClosedTranslationUnit,
                _ => changed.dependencies[0].receipt.source_bundle = SourceBundle::new("/other.c", [
                    crate::anka64::source_bundle::SourceBundleMember::new("/other.c", b"other".to_vec()).unwrap()
                ]).unwrap(),
            }
            assert!(matches!(store.validate_dependencies(&changed), Err(CompilerAdapterError::DependencyChanged)),
                "accepted mutation {mutation}");
        }
        let (other, _) = modules();
        let foreign = other.freeze_modules(&[1, 2]).unwrap();
        assert_eq!(foreign.dependencies[0].bytes, request.dependencies[0].bytes);
        assert_eq!(foreign.dependencies[0].receipt.artifact_key, request.dependencies[0].receipt.artifact_key);
        assert!(matches!(store.validate_dependencies(&foreign), Err(CompilerAdapterError::DependencyChanged)));
        assert_eq!(store.epoch(), 2);
        assert!(store.linked_records.is_empty());
    }

    #[test]
    fn p108_module_publication_rechecks_current_sealed_dependencies() {
        let (mut store, _) = modules();
        let request = store.freeze_modules(&[1, 2]).unwrap();
        let receipt = store.receipt(1).unwrap().clone();
        for key in [receipt.artifact_key, receipt.compiler_key, receipt.source_key, receipt.profile_key] {
            store.records.get_mut(&1).unwrap().fabric.objects.get_mut(&key.object).unwrap().generation.0 += 1;
            assert!(matches!(store.validate_dependencies(&request), Err(CompilerAdapterError::DependencyChanged)));
            store.records.get_mut(&1).unwrap().fabric.objects.get_mut(&key.object).unwrap().generation = key.generation;
        }
        let reader = store.records[&1].reader;
        store.records.get_mut(&1).unwrap().reader = DomainId(u64::MAX);
        assert!(matches!(store.validate_dependencies(&request), Err(CompilerAdapterError::DependencyChanged)));
        store.records.get_mut(&1).unwrap().reader = reader;
        store.records.get_mut(&1).unwrap().context += 1;
        assert!(matches!(store.validate_dependencies(&request), Err(CompilerAdapterError::DependencyChanged)));
        store.records.get_mut(&1).unwrap().context = receipt.context;
        assert!(store.validate_dependencies(&request).is_ok());
    }

    #[test]
    fn p108_module_publication_requires_authorities_and_nonwrapping_reservation() {
        let (mut store, authority) = modules();
        let execution = DeveloperExecutionAuthority::provision();
        let request = store.freeze_modules(&[1, 2]).unwrap();
        assert!(matches!(store.link_modules(&request, None, Some(&authority)), Err(CompilerAdapterError::ExecutionAuthorityRequired)));
        assert!(matches!(store.link_modules(&request, Some(&execution), None), Err(CompilerAdapterError::PublicationAuthorityRequired)));
        assert_eq!(store.epoch(), 2);
        store.link_modules(&request, Some(&execution), Some(&authority)).unwrap();
        assert!(matches!(store.link_modules(&request, Some(&execution), Some(&authority)), Err(CompilerAdapterError::StaleEpoch)));
        assert!(store.linked_image(3).is_some());
        store.epoch = u64::MAX;
        assert!(matches!(store.freeze_modules(&[1, 2]), Err(CompilerAdapterError::EpochExhausted)));
        let mut exhausted = request; exhausted.expected_epoch = u64::MAX;
        assert!(matches!(store.link_modules(&exhausted, Some(&execution), Some(&authority)), Err(CompilerAdapterError::EpochExhausted)));
        assert_eq!(store.linked_records.len(), 1);
    }

    #[test]
    fn p108_module_publication_failure_preserves_prior_records_and_allows_retry() {
        let (mut store, authority) = modules();
        let execution = DeveloperExecutionAuthority::provision();
        let request = store.freeze_modules(&[1, 2]).unwrap();
        store.link_modules(&request, Some(&execution), Some(&authority)).unwrap();
        let prior = store.linked_receipt(3).unwrap().clone();
        let request = store.freeze_modules(&[1, 2]).unwrap();
        assert!(matches!(store.publish_link(&request, output(&request), None), Err(CompilerAdapterError::PublicationAuthorityRequired)));
        let mut full = output(&request);
        let filler = full.fabric.alloc_object("full pool", full.placement.free_bytes(), ObjectKind::Memory);
        full.placement.allocate_and_place_object(&mut full.fabric, filler).unwrap();
        assert!(matches!(store.publish_link(&request, full, Some(&authority)), Err(CompilerAdapterError::Placement(_))));
        assert_eq!(store.epoch(), 3);
        assert_eq!(store.records.len(), 2);
        assert_eq!(store.linked_records.len(), 1);
        assert!(store.linked_receipt(4).is_none());
        assert!(store.linked_image(4).is_none());
        assert_eq!(store.linked_receipt(3), Some(&prior));
        assert_eq!(store.linked_image(3), Some(&prior.image));
        assert_eq!(store.publish_link(&request, output(&request), Some(&authority)).unwrap(), 4);
        assert_eq!(store.linked_receipt(3), Some(&prior));
    }

    #[test]
    fn p108_module_publication_rejects_changed_actual_linker_binding() {
        let (mut store, authority) = modules();
        let request = store.freeze_modules(&[1, 2]).unwrap();
        for mutation in 0..9 {
            let mut changed = output(&request);
            match mutation {
                0 => changed.input_keys.swap(0, 1),
                1 => changed.linker_key.generation.0 += 1,
                2 => changed.image.bytes[0] ^= 1,
                3 => changed.context = request.dependencies[0].receipt.context,
                4 => changed.scratch_key = changed.input_keys[0],
                5 => changed.control_key.generation.0 += 1,
                6 => changed.process_generation = 0,
                _ => {
                    let transaction = changed.fabric.submit(MemoryRequest {
                        context: AccessContext { agent: AgentId(0), domain: changed.domain,
                            privilege: Privilege::User },
                        object: changed.scratch_key.object, offset: 0, width: Width::Byte,
                        length: 1, kind: if mutation == 7 { AccessKind::Read } else { AccessKind::Fetch },
                    }, None);
                    // A pending transaction prevents publication. A faulted
                    // attempt to execute staging also invalidates the trace.
                    if mutation == 8 {
                        while !changed.fabric.transaction(transaction).state.is_terminal() {
                            changed.fabric.advance(transaction);
                        }
                        assert_eq!(changed.fabric.transaction(transaction).state, TxState::Faulted);
                    }
                }
            }
            assert!(matches!(store.publish_link(&request, changed, Some(&authority)), Err(CompilerAdapterError::BindingChanged)),
                "accepted mutation {mutation}");
            assert_eq!(store.epoch(), 2);
            assert!(store.linked_records.is_empty());
        }
        // Dependency freshness is checked again even if execution already ended.
        let completed = output(&request);
        let key = store.receipt(1).unwrap().artifact_key;
        store.records.get_mut(&1).unwrap().fabric.revoke(key.object);
        assert!(matches!(store.publish_link(&request, completed, Some(&authority)), Err(CompilerAdapterError::DependencyChanged)));
        assert_eq!(store.epoch(), 2);
        assert!(store.linked_records.is_empty());
    }

    #[test]
    fn p108_module_publication_guest_link_failure_keeps_published_inputs() {
        let (mut store, authority) = modules();
        let execution = DeveloperExecutionAuthority::provision();
        let prior = store.receipt(1).unwrap().clone();
        let bytes = store.artifact_bytes(1).unwrap().to_vec();
        let request = store.freeze_modules(&[1]).unwrap();
        assert!(matches!(store.link_modules(&request, Some(&execution), Some(&authority)),
            Err(CompilerAdapterError::Link(AnkaldError::LinkerRejected(4)))));
        assert_eq!(store.epoch(), 2);
        assert_eq!(store.receipt(1), Some(&prior));
        assert_eq!(store.artifact_bytes(1), Some(bytes.as_slice()));
        assert!(store.linked_records.is_empty());
    }

    #[test]
    fn p108_module_publication_runner_rejects_modified_request_controls() {
        use crate::anka64::isa::{Asm64, R0, R1, R2};
        for offset in [0, 128] {
            let mut asm = Asm64::new();
            asm.movi(R2, 65536); asm.add(R2, R2, R2);
            asm.movi(R1, 0); asm.st(R1, R2, offset);
            asm.movi(R0, 0); asm.trap(0);
            let modules = protected_test_modules();
            assert_eq!(run_ankald(&asm.to_bytes(), &[modules[0].bytes()], "main"),
                Err(AnkaldError::LinkerStateChanged));
        }
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use super::tests::{modules, output, executable_store, assert_read_only};

    #[test]
    fn c4_receipt_large_profile_is_frozen_published_and_rechecked_before_execution() {
        let (mut store, prior) = executable_store(false, false);
        let execution = DeveloperExecutionAuthority::provision();
        let publication = RebuildPublicationAuthority::provision();
        assert_eq!(store.freeze_modules(&[1,2]).unwrap().profile(), ApplicationLinkProfile::Standard);
        let request = store.freeze_modules_with_profile(&[1,2], ApplicationLinkProfile::Large).unwrap();
        assert_eq!(request.profile(), ApplicationLinkProfile::Large);
        assert!(matches!(store.link_modules(&request, None, Some(&publication)),
            Err(CompilerAdapterError::ExecutionAuthorityRequired)));
        assert!(matches!(store.link_modules(&request, Some(&execution), None),
            Err(CompilerAdapterError::PublicationAuthorityRequired)));
        let epoch = store.link_modules(&request, Some(&execution), Some(&publication)).unwrap();
        let receipt = store.linked_receipt(epoch).unwrap().clone();
        assert_eq!(receipt.profile, ApplicationLinkProfile::Large);
        assert_eq!(receipt.image, prior.image, "policy changes no code or metadata bytes");
        let mut substituted = receipt.clone();
        substituted.profile = ApplicationLinkProfile::Standard;
        assert!(matches!(store.run_linked_application(&substituted, Some(&execution)),
            Err(CompilerAdapterError::BindingChanged)));
        let report = store.run_linked_application(&receipt, Some(&execution)).unwrap();
        assert_eq!(report.child_result, crate::anka64::os::ProcessResult::Exited(42));
        assert_eq!(report.byte_output, [42]);
        assert_eq!(store.linked_receipt(prior.epoch), Some(&prior));
        assert_read_only(&store.linked_records[&epoch].fabric, receipt.artifact_key);
        assert_eq!(store.freeze_modules(&[1,2]).unwrap().profile(), ApplicationLinkProfile::Standard);
    }

    #[test]
    fn c4_receipt_rejects_executed_profile_and_transport_substitution_without_commit() {
        let (mut store, authority) = modules();
        let request = store.freeze_modules_with_profile(&[1,2], ApplicationLinkProfile::Large).unwrap();
        for change_control in [false, true] {
            let mut completed = output(&request);
            if change_control {
                let at = completed.placement.allocated_extent(completed.control_key.object).unwrap().base;
                completed.fabric.write_physical(at + 88, &0u64.to_le_bytes());
            } else { completed.link_profile = ApplicationLinkProfile::Standard.wire(); }
            assert!(matches!(store.publish_link(&request, completed, Some(&authority)),
                Err(CompilerAdapterError::BindingChanged)));
            assert_eq!(store.epoch(), 2);
            assert!(store.linked_receipt(3).is_none());
            assert!(store.artifact_bytes(1).is_some());
            assert!(store.artifact_bytes(2).is_some());
        }
        assert_eq!(store.publish_link(&request, output(&request), Some(&authority)).unwrap(), 3);
    }
}
