//! Anka64 development artifact ingress and source registry (Phase 9.3h.1--9.3h.3).
//!
//! This module is the host-development bridge promised by the 9.3h.0 Kleis
//! contract.  It deliberately stops before execution:
//!
//!   developer authority -> host bytes -> Anka object -> PM placement
//!       -> initialize -> seal -> exact-generation registry entry
//!
//! Import authority, physical placement, and execution authority remain three
//! distinct things.  The loader never grants a Fabric capability and never
//! spawns a process.  A friendly registry name is only a development UI key.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use super::dev_compiler::{compile_c_with_ccb, DevelopmentCompileError};
use super::fabric::Fabric;
use super::placement::{PhysicalExtent, PhysicalPlacementManager, PlacementError};
use super::state::{Generation, ObjectId, ObjectKind, ObjectState};

/// Machine policy for the host development ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevelopmentMode {
    /// Explicit development mode.  A separately provisioned developer
    /// authority is still required for ingress.
    Development,
    /// No host artifact ingress, even if a developer authority token exists.
    Sealed,
}

/// Type-level witness that the human developer explicitly authorized ingress.
///
/// This is not a Fabric capability, is never presented to guest code, and has
/// no relation to PM placement or execution authority.  It is intentionally a
/// host-development token whose construction is an explicit developer action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeveloperIngressAuthority {
    _private: (),
}

impl DeveloperIngressAuthority {
    /// Explicitly provision developer ingress authority for a development
    /// session.  Possessing this token alone is insufficient on a sealed
    /// machine; `DevelopmentArtifactLoader` checks both conditions.
    pub fn provision() -> Self {
        Self { _private: () }
    }
}

/// Exact architectural identity of one registered development artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactKey {
    pub object: ObjectId,
    pub generation: Generation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevelopmentArtifactKind {
    /// Raw Anka64 bytecode imported from the host filesystem.
    Bytecode,
    /// C source compiled by the self-hosted CC_B in compile-only mode.
    CompiledC,
}

/// Registry metadata intentionally excludes the host pathname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevelopmentArtifact {
    pub key: ArtifactKey,
    /// Complete executable backing size stored in the Anka object.
    pub logical_size: u64,
    /// Executable code prefix length.
    pub code_size: u64,
    /// Zero when no literal segment exists.  Otherwise literals occupy
    /// `[lit_start, logical_size)` and must be mapped read-only at run time.
    pub lit_start: u64,
    pub kind: DevelopmentArtifactKind,
    /// Future Anka namespace path, e.g. `/system/services/net/arp`.
    /// This is non-authoritative metadata and never contains the host pathname.
    pub logical_path: Option<String>,
}

/// Friendly-name registry.  Names are UI references, never capabilities.
#[derive(Debug, Default)]
pub struct DevelopmentArtifactRegistry {
    entries: BTreeMap<String, DevelopmentArtifact>,
}

impl DevelopmentArtifactRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&DevelopmentArtifact> {
        self.entries.get(name)
    }

    pub fn contains_name(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    pub fn get_by_logical_path(&self, logical_path: &str) -> Option<&DevelopmentArtifact> {
        self.entries
            .values()
            .find(|artifact| artifact.logical_path.as_deref() == Some(logical_path))
    }

    pub fn contains_logical_path(&self, logical_path: &str) -> bool {
        self.get_by_logical_path(logical_path).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &DevelopmentArtifact)> {
        self.entries.iter().map(|(name, artifact)| (name.as_str(), artifact))
    }

    /// Resolve a friendly name to an exact current sealed artifact.
    ///
    /// This performs no authority grant.  It only validates that the registry
    /// still names the same ObjectId/generation incarnation that was published
    /// after sealing.
    pub fn resolve_current(
        &self,
        fabric: &Fabric,
        name: &str,
    ) -> Result<&DevelopmentArtifact, DevelopmentShellError> {
        let artifact = self.entries.get(name)
            .ok_or(DevelopmentShellError::ArtifactNotFound)?;
        Self::validate_current(fabric, artifact)
    }

    /// Resolve an absolute future-Anka logical path to the exact current
    /// sealed artifact.  The path is namespace metadata only; this lookup
    /// performs no authority grant.
    pub fn resolve_current_by_logical_path(
        &self,
        fabric: &Fabric,
        logical_path: &str,
    ) -> Result<&DevelopmentArtifact, DevelopmentShellError> {
        let artifact = self.get_by_logical_path(logical_path)
            .ok_or(DevelopmentShellError::ArtifactNotFound)?;
        Self::validate_current(fabric, artifact)
    }

    fn validate_current<'a>(
        fabric: &Fabric,
        artifact: &'a DevelopmentArtifact,
    ) -> Result<&'a DevelopmentArtifact, DevelopmentShellError> {
        let object = fabric.objects.get(&artifact.key.object)
            .ok_or(DevelopmentShellError::ArtifactObjectMissing)?;
        if object.generation != artifact.key.generation {
            return Err(DevelopmentShellError::StaleArtifactGeneration);
        }
        if object.state != ObjectState::Sealed {
            return Err(DevelopmentShellError::ArtifactNotSealed);
        }
        if object.kind != ObjectKind::Memory {
            return Err(DevelopmentShellError::ArtifactWrongObjectKind);
        }
        Ok(artifact)
    }

    fn publish(&mut self, name: String, artifact: DevelopmentArtifact) {
        let old = self.entries.insert(name, artifact);
        debug_assert!(old.is_none(), "artifact names are preflighted before publication");
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DevelopmentShellError {
    DevelopmentIngressDisabled,
    DeveloperAuthorityRequired,
    InvalidArtifactName,
    ArtifactNameAlreadyRegistered,
    InvalidUserspaceRoot,
    SourceOutsideUserspace,
    SourceMustBeC,
    NonUtf8LogicalPath,
    LogicalPathAlreadyRegistered,
    HostRead(io::ErrorKind),
    Compiler(DevelopmentCompileError),
    EmptyArtifact,
    ArtifactSizeOverflow,
    Placement(PlacementError),
    PhysicalExtentOutsideFabric,
    FabricInitializationRejected,
    ArtifactNotFound,
    ArtifactObjectMissing,
    StaleArtifactGeneration,
    ArtifactNotSealed,
    ArtifactWrongObjectKind,
}

/// Phase 9.3h.1--9.3h.3 host artifact loader, compiler bridge, and registry.
///
/// The loader owns no Fabric authority and no physical memory.  Fabric and PM
/// are borrowed explicitly for each import so the architectural ownership
/// boundaries remain visible in the API.
#[derive(Debug)]
pub struct DevelopmentArtifactLoader {
    mode: DevelopmentMode,
    registry: DevelopmentArtifactRegistry,
}

impl DevelopmentArtifactLoader {
    pub fn new(mode: DevelopmentMode) -> Self {
        Self {
            mode,
            registry: DevelopmentArtifactRegistry::new(),
        }
    }

    pub fn mode(&self) -> DevelopmentMode {
        self.mode
    }

    pub fn registry(&self) -> &DevelopmentArtifactRegistry {
        &self.registry
    }

    /// Import raw Anka64 bytecode from a host path.
    ///
    /// The host pathname is consumed only to obtain bytes.  It is not stored in
    /// the artifact registry and has no role in identity or authorization after
    /// a successful import.
    pub fn import_bytecode_file<P: AsRef<Path>>(
        &mut self,
        authority: Option<&DeveloperIngressAuthority>,
        fabric: &mut Fabric,
        placement: &mut PhysicalPlacementManager,
        name: &str,
        host_path: P,
    ) -> Result<ArtifactKey, DevelopmentShellError> {
        self.preflight_ingress(authority, name)?;

        // Host I/O occurs before any Anka/Fabric mutation.
        let bytes = fs::read(host_path)
            .map_err(|err| DevelopmentShellError::HostRead(err.kind()))?;
        self.import_artifact_bytes(
            fabric,
            placement,
            name,
            &bytes,
            DevelopmentArtifactKind::Bytecode,
            bytes.len() as u64,
            0,
            None,
        )
    }

    /// Compile one host C source file through the real self-hosted CC_B and
    /// register the resulting sealed executable artifact.
    ///
    /// `userspace_root` defines the host mirror of the future Anka namespace.
    /// For example:
    ///
    /// `userspace/system/services/net/arp.c` -> `/system/services/net/arp`
    ///
    /// The host pathname is consumed during this operation and is not stored.
    /// The logical path is non-authoritative registry metadata.
    pub fn compile_c_file<P: AsRef<Path>, R: AsRef<Path>>(
        &mut self,
        authority: Option<&DeveloperIngressAuthority>,
        fabric: &mut Fabric,
        placement: &mut PhysicalPlacementManager,
        name: &str,
        userspace_root: R,
        host_source: P,
        ccb_image: &[u8],
    ) -> Result<ArtifactKey, DevelopmentShellError> {
        self.preflight_ingress(authority, name)?;

        let (source_path, logical_path) = resolve_userspace_c_source(
            userspace_root.as_ref(),
            host_source.as_ref(),
        )?;
        if self.registry.contains_logical_path(&logical_path) {
            return Err(DevelopmentShellError::LogicalPathAlreadyRegistered);
        }

        // All host/source/compiler failures happen before the target Fabric is
        // mutated.  CC_B runs in a transient Anka machine in compile-only mode.
        let source = fs::read(&source_path)
            .map_err(|err| DevelopmentShellError::HostRead(err.kind()))?;
        let compiled = compile_c_with_ccb(ccb_image, &source)
            .map_err(DevelopmentShellError::Compiler)?;

        self.import_artifact_bytes(
            fabric,
            placement,
            name,
            &compiled.bytes,
            DevelopmentArtifactKind::CompiledC,
            compiled.code_size,
            compiled.lit_start,
            Some(logical_path),
        )
    }

    fn preflight_ingress(
        &self,
        authority: Option<&DeveloperIngressAuthority>,
        name: &str,
    ) -> Result<(), DevelopmentShellError> {
        if self.mode != DevelopmentMode::Development {
            return Err(DevelopmentShellError::DevelopmentIngressDisabled);
        }
        if authority.is_none() {
            return Err(DevelopmentShellError::DeveloperAuthorityRequired);
        }
        if name.trim().is_empty() {
            return Err(DevelopmentShellError::InvalidArtifactName);
        }
        if self.registry.contains_name(name) {
            return Err(DevelopmentShellError::ArtifactNameAlreadyRegistered);
        }
        Ok(())
    }

    fn import_artifact_bytes(
        &mut self,
        fabric: &mut Fabric,
        placement: &mut PhysicalPlacementManager,
        name: &str,
        bytes: &[u8],
        kind: DevelopmentArtifactKind,
        code_size: u64,
        lit_start: u64,
        logical_path: Option<String>,
    ) -> Result<ArtifactKey, DevelopmentShellError> {
        if bytes.is_empty() {
            return Err(DevelopmentShellError::EmptyArtifact);
        }
        let logical_size = u64::try_from(bytes.len())
            .map_err(|_| DevelopmentShellError::ArtifactSizeOverflow)?;

        // Object identity is allocated only after every host-side fallible step
        // has succeeded.  If composed placement fails, the fresh unpublished
        // allocation is rewound exactly rather than leaving an ObjectId hole.
        let object = fabric.alloc_object(
            &format!("dev-artifact:{name}"),
            logical_size,
            ObjectKind::Memory,
        );

        let extent = match placement.allocate_and_place_object(fabric, object) {
            Ok(extent) => extent,
            Err(err) => {
                let rolled_back = fabric.rollback_unpublished_object(object);
                assert!(rolled_back,
                    "fresh failed artifact object must be exactly rollbackable");
                return Err(DevelopmentShellError::Placement(err));
            }
        };

        // PM pools are required to lie inside Fabric RAM.  Fabric::place_object
        // intentionally does not impose that policy because older hostile tests
        // exercise commit-time physical-span faults.  The developer ingress is
        // stricter: reject such a pool before touching physical bytes.
        if !extent_fits_fabric(extent, fabric.mem_size()) {
            rollback_composed_unpublished(fabric, placement, object);
            return Err(DevelopmentShellError::PhysicalExtentOutsideFabric);
        }

        // zero_object_extent performs every fallible range/state check before
        // writing.  A false result therefore remains rollback-safe.
        if !fabric.zero_object_extent(object) {
            rollback_composed_unpublished(fabric, placement, object);
            return Err(DevelopmentShellError::FabricInitializationRejected);
        }

        // After the successful zero preflight, these operations cannot fail
        // without an internal invariant violation: the exact byte span equals
        // object.size, the object is still Active+placed, and this code is
        // single-threaded.  Treat such a violation as a bug instead of turning
        // a post-write state into a recoverable "transactional" failure.
        assert!(fabric.initialize_object(object, 0, bytes),
            "zeroed Active artifact must accept exact-size initialization");
        assert!(fabric.seal_object(object),
            "fresh initialized artifact must seal exactly once");

        let generation = fabric.objects.get(&object)
            .expect("sealed artifact object must still exist")
            .generation;
        let key = ArtifactKey { object, generation };
        self.registry.publish(
            name.to_string(),
            DevelopmentArtifact {
                key,
                logical_size,
                code_size,
                lit_start,
                kind,
                logical_path,
            },
        );
        Ok(key)
    }
}

/// Resolve a host C source under the mirrored `userspace/` root to the
/// corresponding future Anka logical install path.
///
/// This mapping carries no authority.  Canonicalization also prevents symlinks
/// inside the source tree from escaping the declared userspace root.
pub fn logical_install_path_for_c_source(
    userspace_root: &Path,
    host_source: &Path,
) -> Result<String, DevelopmentShellError> {
    resolve_userspace_c_source(userspace_root, host_source)
        .map(|(_, logical)| logical)
}

fn resolve_userspace_c_source(
    userspace_root: &Path,
    host_source: &Path,
) -> Result<(PathBuf, String), DevelopmentShellError> {
    let root = fs::canonicalize(userspace_root)
        .map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => DevelopmentShellError::InvalidUserspaceRoot,
            kind => DevelopmentShellError::HostRead(kind),
        })?;
    let source = fs::canonicalize(host_source)
        .map_err(|err| DevelopmentShellError::HostRead(err.kind()))?;

    let relative = source
        .strip_prefix(&root)
        .map_err(|_| DevelopmentShellError::SourceOutsideUserspace)?;
    if relative.extension().and_then(|ext| ext.to_str()) != Some("c") {
        return Err(DevelopmentShellError::SourceMustBeC);
    }

    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let text = part.to_str()
                    .ok_or(DevelopmentShellError::NonUtf8LogicalPath)?;
                parts.push(text.to_string());
            }
            _ => return Err(DevelopmentShellError::SourceOutsideUserspace),
        }
    }
    let last = parts.last_mut()
        .ok_or(DevelopmentShellError::SourceOutsideUserspace)?;
    if !last.ends_with(".c") {
        return Err(DevelopmentShellError::SourceMustBeC);
    }
    last.truncate(last.len() - 2);
    if last.is_empty() {
        return Err(DevelopmentShellError::SourceMustBeC);
    }

    Ok((source, format!("/{}", parts.join("/"))))
}

fn extent_fits_fabric(extent: PhysicalExtent, fabric_mem_size: usize) -> bool {
    let mem_size = match u64::try_from(fabric_mem_size) {
        Ok(size) => size,
        Err(_) => return false,
    };
    matches!(extent.end(), Some(end) if end <= mem_size)
}

fn rollback_composed_unpublished(
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    object: ObjectId,
) {
    // Remove Fabric identity/translation first so PM's checked teardown can
    // prove that the reservation is no longer translated.
    let fabric_rolled_back = fabric.rollback_unpublished_object(object);
    assert!(fabric_rolled_back,
        "fresh placed artifact must remain rollbackable before publication");
    placement.release_unplaced(fabric, object)
        .expect("fresh composed artifact reservation must release after Fabric rollback");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anka64::fabric::{request, AuthResult};
    use crate::anka64::state::{
        AccessKind, AgentId, FaultReason, Permissions, Width,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn authority() -> DeveloperIngressAuthority {
        DeveloperIngressAuthority::provision()
    }

    fn write_temp_artifact(tag: &str, bytes: &[u8]) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "anka64-{tag}-{}-{nonce}.anka",
            std::process::id(),
        ));
        fs::write(&path, bytes).expect("write temporary artifact");
        path
    }

    #[test]
    fn p93h1_development_mode_still_requires_explicit_authority() {
        let path = write_temp_artifact("no-authority", &[0x01, 0x02, 0x03, 0x04]);
        let mut fabric = Fabric::new(0x20000);
        let mut pm = PhysicalPlacementManager::new(0x4000, 0x10000).unwrap();
        let mut loader = DevelopmentArtifactLoader::new(DevelopmentMode::Development);
        let free_before = pm.free_extents().to_vec();

        assert_eq!(
            loader.import_bytecode_file(None, &mut fabric, &mut pm, "hello", &path),
            Err(DevelopmentShellError::DeveloperAuthorityRequired),
        );
        assert!(loader.registry().is_empty());
        assert!(fabric.objects.is_empty());
        assert_eq!(pm.free_extents(), free_before.as_slice());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn p93h1_sealed_mode_rejects_even_explicit_developer_authority() {
        let path = write_temp_artifact("sealed", &[0x11, 0x22]);
        let auth = authority();
        let mut fabric = Fabric::new(0x20000);
        let mut pm = PhysicalPlacementManager::new(0x4000, 0x10000).unwrap();
        let mut loader = DevelopmentArtifactLoader::new(DevelopmentMode::Sealed);

        assert_eq!(
            loader.import_bytecode_file(Some(&auth), &mut fabric, &mut pm, "hello", &path),
            Err(DevelopmentShellError::DevelopmentIngressDisabled),
        );
        assert!(loader.registry().is_empty());
        assert!(fabric.objects.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn p93h1_unreadable_host_path_is_side_effect_free() {
        let auth = authority();
        let mut fabric = Fabric::new(0x20000);
        let mut pm = PhysicalPlacementManager::new(0x4000, 0x10000).unwrap();
        let mut loader = DevelopmentArtifactLoader::new(DevelopmentMode::Development);
        let free_before = pm.free_extents().to_vec();
        let path = std::env::temp_dir().join("anka64-definitely-missing-artifact.anka");
        let _ = fs::remove_file(&path);

        assert!(matches!(
            loader.import_bytecode_file(Some(&auth), &mut fabric, &mut pm, "missing", &path),
            Err(DevelopmentShellError::HostRead(_))
        ));
        assert!(loader.registry().is_empty());
        assert!(fabric.objects.is_empty());
        assert_eq!(pm.free_extents(), free_before.as_slice());
    }

    #[test]
    fn p93h1_empty_artifact_is_rejected_before_object_allocation() {
        let path = write_temp_artifact("empty", &[]);
        let auth = authority();
        let mut fabric = Fabric::new(0x20000);
        let mut pm = PhysicalPlacementManager::new(0x4000, 0x10000).unwrap();
        let mut loader = DevelopmentArtifactLoader::new(DevelopmentMode::Development);

        assert_eq!(
            loader.import_bytecode_file(Some(&auth), &mut fabric, &mut pm, "empty", &path),
            Err(DevelopmentShellError::EmptyArtifact),
        );
        assert!(fabric.objects.is_empty());
        assert!(loader.registry().is_empty());
        let first = fabric.alloc_object("first-after-failed-empty-import", 1, ObjectKind::Memory);
        assert_eq!(first, ObjectId(0));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn p93h1_pm_exhaustion_rolls_back_object_identity_registry_and_allocator() {
        let path = write_temp_artifact("oom", &vec![0xA5; 0x2000]);
        let auth = authority();
        let mut fabric = Fabric::new(0x20000);
        let mut pm = PhysicalPlacementManager::new(0x4000, 0x1000).unwrap();
        let mut loader = DevelopmentArtifactLoader::new(DevelopmentMode::Development);
        let free_before = pm.free_extents().to_vec();

        assert_eq!(
            loader.import_bytecode_file(Some(&auth), &mut fabric, &mut pm, "too-big", &path),
            Err(DevelopmentShellError::Placement(PlacementError::OutOfMemory)),
        );
        assert!(loader.registry().is_empty());
        assert!(fabric.objects.is_empty());
        assert_eq!(pm.free_extents(), free_before.as_slice());
        assert_eq!(pm.allocated_count(), 0);

        // Exact rollback includes the fresh ObjectId allocator state.
        let first = fabric.alloc_object("first-after-oom", 1, ObjectKind::Memory);
        assert_eq!(first, ObjectId(0));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn p93h1_pm_pool_outside_fabric_rolls_back_composed_placement_exactly() {
        let path = write_temp_artifact("outside-fabric", &[0x10, 0x20, 0x30, 0x40]);
        let auth = authority();
        let mut fabric = Fabric::new(0x8000);
        let mut pm = PhysicalPlacementManager::new(0x10000, 0x4000).unwrap();
        let mut loader = DevelopmentArtifactLoader::new(DevelopmentMode::Development);
        let free_before = pm.free_extents().to_vec();

        assert_eq!(
            loader.import_bytecode_file(Some(&auth), &mut fabric, &mut pm, "outside", &path),
            Err(DevelopmentShellError::PhysicalExtentOutsideFabric),
        );
        assert!(fabric.objects.is_empty());
        assert!(loader.registry().is_empty());
        assert_eq!(pm.free_extents(), free_before.as_slice());
        assert_eq!(pm.allocated_count(), 0);
        let first = fabric.alloc_object("first-after-outside", 1, ObjectKind::Memory);
        assert_eq!(first, ObjectId(0));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn p93h1_success_registers_exact_post_seal_generation_without_host_path_identity() {
        let bytes = [0xCA, 0xFE, 0xBA, 0xBE, 0x42];
        let path = write_temp_artifact("success", &bytes);
        let auth = authority();
        let mut fabric = Fabric::new(0x20000);
        let mut pm = PhysicalPlacementManager::new(0x4000, 0x10000).unwrap();
        let mut loader = DevelopmentArtifactLoader::new(DevelopmentMode::Development);

        let key = loader.import_bytecode_file(
            Some(&auth), &mut fabric, &mut pm, "hello", &path,
        ).unwrap();
        let artifact = loader.registry().get("hello").unwrap();
        assert_eq!(artifact.key, key);
        assert_eq!(artifact.logical_size, bytes.len() as u64);
        assert_eq!(artifact.kind, DevelopmentArtifactKind::Bytecode);

        let obj = fabric.objects.get(&key.object).unwrap();
        assert_eq!(obj.state, ObjectState::Sealed);
        assert_eq!(obj.generation, key.generation);
        assert_eq!(key.generation, Generation(1), "seal must bump generation");
        let extent = pm.allocated_extent(key.object).unwrap();
        assert_eq!(fabric.physical_base(key.object), Some(extent.base));
        assert_eq!(fabric.read_physical(extent.base, bytes.len() as u64), &bytes[..]);

        // The host path is not registry identity: deleting it does not affect
        // exact-generation artifact resolution.
        fs::remove_file(&path).unwrap();
        assert_eq!(loader.registry().resolve_current(&fabric, "hello").unwrap().key, key);
    }

    #[test]
    fn p93h1_successful_import_creates_no_fabric_authority() {
        let path = write_temp_artifact("no-ambient-authority", &[0x01, 0x02, 0x03, 0x04]);
        let auth = authority();
        let mut fabric = Fabric::new(0x20000);
        let mut pm = PhysicalPlacementManager::new(0x4000, 0x10000).unwrap();
        let mut loader = DevelopmentArtifactLoader::new(DevelopmentMode::Development);
        let key = loader.import_bytecode_file(
            Some(&auth), &mut fabric, &mut pm, "evil-or-benign", &path,
        ).unwrap();

        let domain = fabric.create_domain();
        assert!(fabric.domains[&domain].capabilities.is_empty());
        let req = request(
            AgentId(0), domain, key.object, 0, Width::Byte, AccessKind::Fetch,
        );
        assert!(matches!(
            fabric.authorize(&req),
            AuthResult::Denied(FaultReason::NoCapability)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn p93h1_registry_rejects_stale_or_unsealed_incarnation() {
        let path = write_temp_artifact("stale", &[0x77, 0x88, 0x99]);
        let auth = authority();
        let mut fabric = Fabric::new(0x20000);
        let mut pm = PhysicalPlacementManager::new(0x4000, 0x10000).unwrap();
        let mut loader = DevelopmentArtifactLoader::new(DevelopmentMode::Development);
        let key = loader.import_bytecode_file(
            Some(&auth), &mut fabric, &mut pm, "artifact", &path,
        ).unwrap();

        // Hostile impossible-state witness: exact generation but no longer sealed.
        fabric.objects.get_mut(&key.object).unwrap().state = ObjectState::Active;
        assert_eq!(
            loader.registry().resolve_current(&fabric, "artifact"),
            Err(DevelopmentShellError::ArtifactNotSealed),
        );
        fabric.objects.get_mut(&key.object).unwrap().state = ObjectState::Sealed;

        fabric.revoke(key.object);
        assert_eq!(
            loader.registry().resolve_current(&fabric, "artifact"),
            Err(DevelopmentShellError::StaleArtifactGeneration),
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn p93h1_duplicate_registry_name_is_rejected_without_second_import() {
        let first_path = write_temp_artifact("dup-a", &[1, 2, 3]);
        let second_path = write_temp_artifact("dup-b", &[9, 8, 7, 6]);
        let auth = authority();
        let mut fabric = Fabric::new(0x20000);
        let mut pm = PhysicalPlacementManager::new(0x4000, 0x10000).unwrap();
        let mut loader = DevelopmentArtifactLoader::new(DevelopmentMode::Development);
        loader.import_bytecode_file(
            Some(&auth), &mut fabric, &mut pm, "same", &first_path,
        ).unwrap();
        let object_count = fabric.objects.len();
        let allocation_count = pm.allocated_count();
        let free_before = pm.free_extents().to_vec();

        assert_eq!(
            loader.import_bytecode_file(
                Some(&auth), &mut fabric, &mut pm, "same", &second_path,
            ),
            Err(DevelopmentShellError::ArtifactNameAlreadyRegistered),
        );
        assert_eq!(loader.registry().len(), 1);
        assert_eq!(fabric.objects.len(), object_count);
        assert_eq!(pm.allocated_count(), allocation_count);
        assert_eq!(pm.free_extents(), free_before.as_slice());
        let _ = fs::remove_file(first_path);
        let _ = fs::remove_file(second_path);
    }

    #[test]
    fn p93h1_friendly_name_is_not_a_capability() {
        let path = write_temp_artifact("name-not-cap", &[0xAA]);
        let auth = authority();
        let mut fabric = Fabric::new(0x20000);
        let mut pm = PhysicalPlacementManager::new(0x4000, 0x10000).unwrap();
        let mut loader = DevelopmentArtifactLoader::new(DevelopmentMode::Development);
        let key = loader.import_bytecode_file(
            Some(&auth), &mut fabric, &mut pm, "arp", &path,
        ).unwrap();

        assert!(loader.registry().contains_name("arp"));
        for domain in fabric.domains.values() {
            assert!(domain.capabilities.iter().all(|entry| entry.cap.object() != key.object));
            assert!(domain.device_authorities.iter().all(|entry| entry.object != key.object));
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn p93h1_rollback_primitive_refuses_published_or_non_latest_objects() {
        let mut fabric = Fabric::new(0x20000);
        let first = fabric.alloc_object("first", 0x1000, ObjectKind::Memory);
        let second = fabric.alloc_object("second", 0x1000, ObjectKind::Memory);
        assert!(!fabric.rollback_unpublished_object(first),
            "only the exact most-recent allocation may be rewound");

        let dom = fabric.create_domain();
        assert!(fabric.grant(
            dom, second, 0, 0x1000, Permissions::READ,
        ).is_some());
        assert!(!fabric.rollback_unpublished_object(second),
            "an object already published into authority may not be rewound");
    }

    #[test]
    fn p93h2_logical_path_mirrors_future_anka_namespace() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!(
            "anka64-userspace-map-{}-{nonce}", std::process::id()));
        let net = root.join("system/services/net");
        fs::create_dir_all(&net).unwrap();
        let arp = net.join("arp.c");
        fs::write(&arp, b"int main() { return 0; }").unwrap();

        assert_eq!(
            logical_install_path_for_c_source(&root, &arp).unwrap(),
            "/system/services/net/arp",
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p93h2_source_outside_userspace_is_rejected() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!(
            "anka64-userspace-root-{}-{nonce}", std::process::id()));
        let outside = std::env::temp_dir().join(format!(
            "anka64-outside-{}-{nonce}.c", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(&outside, b"int main() { return 0; }").unwrap();

        assert_eq!(
            logical_install_path_for_c_source(&root, &outside),
            Err(DevelopmentShellError::SourceOutsideUserspace),
        );
        fs::remove_file(outside).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p93h2_only_c_sources_map_into_logical_namespace() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!(
            "anka64-userspace-ext-{}-{nonce}", std::process::id()));
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let bytecode = bin.join("hello.anka");
        fs::write(&bytecode, [0u8; 4]).unwrap();

        assert_eq!(
            logical_install_path_for_c_source(&root, &bytecode),
            Err(DevelopmentShellError::SourceMustBeC),
        );
        fs::remove_dir_all(root).unwrap();
    }

}
