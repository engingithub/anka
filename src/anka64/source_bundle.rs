//! Phase 10.5 source bundles and include-only preprocessing transport.
//!
//! Source-bundle names are exact, non-authoritative lookup keys.  Host paths
//! may be used to ingest development bytes, but they are discarded before a
//! bundle exists.  The host does not parse C or expand includes.
//!
//! Include expansion is performed by the ordinary Anka userspace program
//! `userspace/system/compiler/ankapp.c`:
//!
//!   exact immutable bundle -> ankapp inside Anka -> exact effective source
//!
//! Bundle members and the manifest are mapped read-only.  `ankapp` receives
//! only RW output/workspace/result transport objects and creates no authority.
//! A preprocessing failure returns before Stage 3 is invoked, so no AOM can be
//! emitted or published from a failed expansion.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use super::dev_compiler::{
    compile_c_to_aom_stage3, CompiledAomModule, DevelopmentCompileError,
};
use super::fabric::Fabric;
use super::guest_compiler::SOURCE_SIZE;
use super::os::{BootError, BootGrant, BootImage, BootInfo, BootMap, Kernel};
use super::placement::{
    PhysicalPlacementManager, PlacementError, VirtualLayoutBuilder,
    PLACEMENT_PAGE_SIZE,
};
use super::state::{ObjectId, ObjectKind, ObjectState, Permissions};

/// Names are deliberately small enough for the bootstrap preprocessor to keep
/// bounded comparisons simple.  They are opaque exact keys, not filesystem
/// paths: no `.`/`..`, slash, case, or host-path normalization is performed.
pub const SOURCE_BUNDLE_NAME_MAX: usize = 127;
/// The first include-only implementation bound.  Active recursion deeper than
/// this is rejected before any Stage-3 compilation is attempted.
pub const INCLUDE_DEPTH_LIMIT: usize = 32;

const ANKAPP_MANIFEST_VADDR: u64 = 0x20000;
const ANKAPP_VIRTUAL_LIMIT: u64 = 0x80_0000;
const ANKAPP_RAM_SIZE: usize = 0x100_0000;
const ANKAPP_PM_BASE: u64 = 0x10000;
const ANKAPP_PM_SIZE: u64 = 0x700000;
const ANKAPP_STACK_SIZE: u64 = 0x4000;
const ANKAPP_TRAP_SIZE: u64 = PLACEMENT_PAGE_SIZE;
const ANKAPP_QUANTUM: usize = 5_000_000;
const ANKAPP_MAX_ROUNDS: usize = 200;

const MAN_MEMBER_COUNT: usize = 0;
const MAN_DESCRIPTOR_VADDR: usize = 8;
const MAN_ROOT_NAME_VADDR: usize = 16;
const MAN_ROOT_NAME_LEN: usize = 24;
const MAN_OUTPUT_VADDR: usize = 32;
const MAN_OUTPUT_CAPACITY: usize = 40;
const MAN_WORKSPACE_VADDR: usize = 48;
const MAN_WORKSPACE_CAPACITY: usize = 56;
const MAN_RESULT_VADDR: usize = 64;
const MAN_PREFIX_SIZE: usize = 128;
const MEMBER_DESCRIPTOR_SIZE: usize = 32;
const RESULT_SIZE: u64 = 16;
const RESULT_STATUS: u64 = 0;
const RESULT_OUTPUT_LEN: u64 = 8;
const WORKSPACE_SIZE: u64 = 8 + (INCLUDE_DEPTH_LIMIT as u64) * 8;
const EFFECTIVE_SOURCE_CAPACITY: u64 = SOURCE_SIZE as u64 - 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBundleMember {
    logical_name: String,
    bytes: Vec<u8>,
}

impl SourceBundleMember {
    pub fn new(logical_name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Result<Self, SourceBundleError> {
        let logical_name = logical_name.into();
        validate_logical_name(&logical_name)?;
        Ok(Self { logical_name, bytes: bytes.into() })
    }

    /// Development ingestion only.  The host pathname is consumed to obtain
    /// exact bytes and is not stored in the returned member.
    pub fn from_host_file<P: AsRef<Path>>(
        logical_name: impl Into<String>,
        host_path: P,
    ) -> Result<Self, SourceBundleError> {
        let logical_name = logical_name.into();
        validate_logical_name(&logical_name)?;
        let bytes = fs::read(host_path).map_err(|e| SourceBundleError::HostRead(e.kind()))?;
        Ok(Self { logical_name, bytes })
    }

    pub fn logical_name(&self) -> &str {
        &self.logical_name
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBundle {
    root_name: String,
    members: BTreeMap<String, SourceBundleMember>,
}

impl SourceBundle {
    pub fn new(
        root_name: impl Into<String>,
        members: impl IntoIterator<Item = SourceBundleMember>,
    ) -> Result<Self, SourceBundleError> {
        let root_name = root_name.into();
        validate_logical_name(&root_name)?;
        let mut by_name = BTreeMap::new();
        for member in members {
            let name = member.logical_name.clone();
            if by_name.insert(name.clone(), member).is_some() {
                return Err(SourceBundleError::DuplicateLogicalName(name));
            }
        }
        if by_name.is_empty() {
            return Err(SourceBundleError::EmptyBundle);
        }
        if !by_name.contains_key(&root_name) {
            return Err(SourceBundleError::RootNotFound(root_name));
        }
        Ok(Self { root_name, members: by_name })
    }

    pub fn root_name(&self) -> &str {
        &self.root_name
    }

    pub fn root(&self) -> &SourceBundleMember {
        self.members.get(&self.root_name).expect("validated bundle root remains present")
    }

    /// Exact-name lookup only.  There is no host path, cwd, `-I`, system
    /// include directory, or normalization fallback behind this operation.
    pub fn get(&self, logical_name: &str) -> Option<&SourceBundleMember> {
        self.members.get(logical_name)
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Deterministic canonical enumeration independent of construction order.
    pub fn members(&self) -> impl Iterator<Item = &SourceBundleMember> {
        self.members.values()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SourceBundleError {
    EmptyBundle,
    EmptyLogicalName,
    LogicalNameTooLong,
    LogicalNameNotRepresentable,
    DuplicateLogicalName(String),
    RootNotFound(String),
    HostRead(io::ErrorKind),
}

fn validate_logical_name(name: &str) -> Result<(), SourceBundleError> {
    if name.is_empty() {
        return Err(SourceBundleError::EmptyLogicalName);
    }
    if name.len() > SOURCE_BUNDLE_NAME_MAX {
        return Err(SourceBundleError::LogicalNameTooLong);
    }
    // Logical names are opaque exact bundle keys.  Restrict only the bytes the
    // first quoted-include syntax cannot represent unambiguously; do not apply
    // filesystem/path normalization semantics.
    if !name.bytes().all(|b| (33..=126).contains(&b) && b != b'"') {
        return Err(SourceBundleError::LogicalNameNotRepresentable);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreprocessedSource {
    pub bytes: Vec<u8>,
    /// Ordinary userspace closure witness: only ankapp runs; it cannot spawn
    /// or execute the source it produces.
    pub process_slots_observed: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnkaPreprocessError {
    EmptyPreprocessorImage,
    PreprocessorImageOverlapsManifest,
    SizeOverflow,
    VirtualLayout(PlacementError),
    Placement(PlacementError),
    PhysicalExtentOutsideFabric,
    InitializationRejected,
    Boot(BootError),
    PreprocessorDidNotExit,
    PreprocessorRejected(u64),
    InvalidResultGeometry,
    TransportObjectStateChanged,
    SourceMemberMutated,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SourceBundleCompileError {
    Preprocess(AnkaPreprocessError),
    Compile(DevelopmentCompileError),
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u64_physical(fabric: &Fabric, base: u64, offset: u64) -> u64 {
    let bytes = fabric.read_physical(base + offset, 8);
    u64::from_le_bytes(bytes.try_into().expect("eight-byte ankapp result read"))
}

fn word_backing_len(len: usize) -> Result<u64, AnkaPreprocessError> {
    let n = len.max(1).checked_add(7).ok_or(AnkaPreprocessError::SizeOverflow)? & !7usize;
    u64::try_from(n).map_err(|_| AnkaPreprocessError::SizeOverflow)
}

fn allocate_placed(
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    label: &str,
    size: u64,
) -> Result<ObjectId, AnkaPreprocessError> {
    let object = fabric.alloc_object(label, size, ObjectKind::Memory);
    match placement.allocate_and_place_object(fabric, object) {
        Ok(_) => Ok(object),
        Err(err) => {
            assert!(fabric.rollback_unpublished_object(object),
                "fresh failed ankapp transport object must rollback exactly");
            Err(AnkaPreprocessError::Placement(err))
        }
    }
}

fn initialize_exact(
    fabric: &mut Fabric,
    object: ObjectId,
    bytes: &[u8],
) -> Result<(), AnkaPreprocessError> {
    if !fabric.zero_object_extent(object) {
        return Err(AnkaPreprocessError::InitializationRejected);
    }
    if !bytes.is_empty() && !fabric.initialize_object(object, 0, bytes) {
        return Err(AnkaPreprocessError::InitializationRejected);
    }
    Ok(())
}

fn manifest_semantic_len(bundle: &SourceBundle) -> Result<usize, AnkaPreprocessError> {
    let descriptors = bundle.len().checked_mul(MEMBER_DESCRIPTOR_SIZE)
        .ok_or(AnkaPreprocessError::SizeOverflow)?;
    let names = bundle.members().try_fold(0usize, |acc, member| {
        acc.checked_add(member.logical_name().len()).ok_or(AnkaPreprocessError::SizeOverflow)
    })?;
    MAN_PREFIX_SIZE
        .checked_add(descriptors)
        .and_then(|x| x.checked_add(names))
        .and_then(|x| x.checked_add(bundle.root_name().len()))
        .ok_or(AnkaPreprocessError::SizeOverflow)
}

/// Run the real include-only preprocessor inside Anka.
///
/// The host constructs transport objects and exact logical-name metadata only.
/// It never examines C syntax or resolves an include operand.  The returned
/// bytes are the exact effective translation-unit source emitted by `ankapp`.
pub fn run_ankapp(
    preprocessor_image: &[u8],
    bundle: &SourceBundle,
) -> Result<PreprocessedSource, AnkaPreprocessError> {
    if preprocessor_image.is_empty() {
        return Err(AnkaPreprocessError::EmptyPreprocessorImage);
    }
    if preprocessor_image.len() as u64 > ANKAPP_MANIFEST_VADDR {
        return Err(AnkaPreprocessError::PreprocessorImageOverlapsManifest);
    }

    let manifest_len = manifest_semantic_len(bundle)?;
    let manifest_size = word_backing_len(manifest_len)?;
    let mut vlb = VirtualLayoutBuilder::after_image(
        ANKAPP_MANIFEST_VADDR,
        manifest_size,
        ANKAPP_VIRTUAL_LIMIT,
    ).map_err(AnkaPreprocessError::VirtualLayout)?;

    let mut member_maps = Vec::with_capacity(bundle.len());
    let mut member_backing = Vec::with_capacity(bundle.len());
    for member in bundle.members() {
        let backing = word_backing_len(member.bytes().len())?;
        member_backing.push(backing);
        member_maps.push(vlb.reserve(backing).map_err(AnkaPreprocessError::VirtualLayout)?);
    }
    let output_map = vlb.reserve(EFFECTIVE_SOURCE_CAPACITY)
        .map_err(AnkaPreprocessError::VirtualLayout)?;
    let workspace_map = vlb.reserve(WORKSPACE_SIZE)
        .map_err(AnkaPreprocessError::VirtualLayout)?;
    let result_map = vlb.reserve(RESULT_SIZE)
        .map_err(AnkaPreprocessError::VirtualLayout)?;
    let stack_map = vlb.reserve(ANKAPP_STACK_SIZE)
        .map_err(AnkaPreprocessError::VirtualLayout)?;
    let trap_map = vlb.reserve(ANKAPP_TRAP_SIZE)
        .map_err(AnkaPreprocessError::VirtualLayout)?;

    let mut manifest = vec![0u8; usize::try_from(manifest_size).map_err(|_| AnkaPreprocessError::SizeOverflow)?];
    let descriptor_vaddr = ANKAPP_MANIFEST_VADDR + MAN_PREFIX_SIZE as u64;
    let names_offset = MAN_PREFIX_SIZE
        .checked_add(bundle.len().checked_mul(MEMBER_DESCRIPTOR_SIZE)
            .ok_or(AnkaPreprocessError::SizeOverflow)?)
        .ok_or(AnkaPreprocessError::SizeOverflow)?;
    let mut name_cursor = names_offset;

    put_u64(&mut manifest, MAN_MEMBER_COUNT, bundle.len() as u64);
    put_u64(&mut manifest, MAN_DESCRIPTOR_VADDR, descriptor_vaddr);
    put_u64(&mut manifest, MAN_OUTPUT_VADDR, output_map.base);
    put_u64(&mut manifest, MAN_OUTPUT_CAPACITY, EFFECTIVE_SOURCE_CAPACITY);
    put_u64(&mut manifest, MAN_WORKSPACE_VADDR, workspace_map.base);
    put_u64(&mut manifest, MAN_WORKSPACE_CAPACITY, WORKSPACE_SIZE);
    put_u64(&mut manifest, MAN_RESULT_VADDR, result_map.base);

    for (index, (member, map)) in bundle.members().zip(member_maps.iter()).enumerate() {
        let desc = MAN_PREFIX_SIZE + index * MEMBER_DESCRIPTOR_SIZE;
        let name_vaddr = ANKAPP_MANIFEST_VADDR + name_cursor as u64;
        put_u64(&mut manifest, desc, map.base);
        put_u64(&mut manifest, desc + 8, member.bytes().len() as u64);
        put_u64(&mut manifest, desc + 16, name_vaddr);
        put_u64(&mut manifest, desc + 24, member.logical_name().len() as u64);
        let end = name_cursor + member.logical_name().len();
        manifest[name_cursor..end].copy_from_slice(member.logical_name().as_bytes());
        name_cursor = end;
    }
    let root_vaddr = ANKAPP_MANIFEST_VADDR + name_cursor as u64;
    let root_end = name_cursor + bundle.root_name().len();
    manifest[name_cursor..root_end].copy_from_slice(bundle.root_name().as_bytes());
    put_u64(&mut manifest, MAN_ROOT_NAME_VADDR, root_vaddr);
    put_u64(&mut manifest, MAN_ROOT_NAME_LEN, bundle.root_name().len() as u64);

    let mut fabric = Fabric::new(ANKAPP_RAM_SIZE);
    let mut placement = PhysicalPlacementManager::new(ANKAPP_PM_BASE, ANKAPP_PM_SIZE)
        .map_err(AnkaPreprocessError::Placement)?;

    let code_obj = allocate_placed(&mut fabric, &mut placement, "ankapp-code", preprocessor_image.len() as u64)?;
    let manifest_obj = allocate_placed(&mut fabric, &mut placement, "ankapp-manifest", manifest_size)?;
    let output_obj = allocate_placed(&mut fabric, &mut placement, "ankapp-output", EFFECTIVE_SOURCE_CAPACITY)?;
    let workspace_obj = allocate_placed(&mut fabric, &mut placement, "ankapp-workspace", WORKSPACE_SIZE)?;
    let result_obj = allocate_placed(&mut fabric, &mut placement, "ankapp-result", RESULT_SIZE)?;
    let mut member_objects = Vec::with_capacity(bundle.len());
    for (index, backing) in member_backing.iter().copied().enumerate() {
        member_objects.push(allocate_placed(
            &mut fabric,
            &mut placement,
            &format!("ankapp-source-{index}"),
            backing,
        )?);
    }

    let pool_end = placement.pool().end().ok_or(AnkaPreprocessError::PhysicalExtentOutsideFabric)?;
    let mem_size = u64::try_from(fabric.mem_size()).map_err(|_| AnkaPreprocessError::SizeOverflow)?;
    if pool_end > mem_size {
        return Err(AnkaPreprocessError::PhysicalExtentOutsideFabric);
    }
    for object in std::iter::once(code_obj)
        .chain(std::iter::once(manifest_obj))
        .chain(std::iter::once(output_obj))
        .chain(std::iter::once(workspace_obj))
        .chain(std::iter::once(result_obj))
        .chain(member_objects.iter().copied())
    {
        let extent = placement.allocated_extent(object)
            .ok_or(AnkaPreprocessError::PhysicalExtentOutsideFabric)?;
        if extent.end().map(|end| end <= mem_size) != Some(true) {
            return Err(AnkaPreprocessError::PhysicalExtentOutsideFabric);
        }
    }

    initialize_exact(&mut fabric, code_obj, preprocessor_image)?;
    assert!(fabric.seal_object(code_obj), "ankapp executable must seal exactly once");
    initialize_exact(&mut fabric, manifest_obj, &manifest)?;
    assert!(fabric.seal_object(manifest_obj), "source-bundle manifest must be immutable");
    initialize_exact(&mut fabric, output_obj, &[])?;
    initialize_exact(&mut fabric, workspace_obj, &[])?;
    initialize_exact(&mut fabric, result_obj, &[])?;
    for ((object, member), _backing) in member_objects.iter().copied()
        .zip(bundle.members())
        .zip(member_backing.iter())
    {
        initialize_exact(&mut fabric, object, member.bytes())?;
        assert!(fabric.seal_object(object), "source-bundle member must be immutable");
    }

    let manifest_phys = placement.allocated_extent(manifest_obj)
        .expect("placed manifest remains PM-owned").base;
    let output_phys = placement.allocated_extent(output_obj)
        .expect("placed output remains PM-owned").base;
    let result_phys = placement.allocated_extent(result_obj)
        .expect("placed result remains PM-owned").base;
    let member_phys: Vec<u64> = member_objects.iter().map(|object| {
        placement.allocated_extent(*object).expect("placed source remains PM-owned").base
    }).collect();

    let mut grants = vec![
        BootGrant { obj: manifest_obj, offset: 0, size: manifest_size, perms: Permissions::READ },
        BootGrant { obj: output_obj, offset: 0, size: EFFECTIVE_SOURCE_CAPACITY, perms: Permissions::RW },
        BootGrant { obj: workspace_obj, offset: 0, size: WORKSPACE_SIZE, perms: Permissions::RW },
        BootGrant { obj: result_obj, offset: 0, size: RESULT_SIZE, perms: Permissions::RW },
    ];
    let mut maps = vec![
        BootMap { vaddr: ANKAPP_MANIFEST_VADDR, size: manifest_size, obj: manifest_obj, obj_offset: 0 },
        BootMap { vaddr: output_map.base, size: EFFECTIVE_SOURCE_CAPACITY, obj: output_obj, obj_offset: 0 },
        BootMap { vaddr: workspace_map.base, size: WORKSPACE_SIZE, obj: workspace_obj, obj_offset: 0 },
        BootMap { vaddr: result_map.base, size: RESULT_SIZE, obj: result_obj, obj_offset: 0 },
    ];
    for (((object, map), backing), _member) in member_objects.iter()
        .zip(member_maps.iter())
        .zip(member_backing.iter())
        .zip(bundle.members())
    {
        grants.push(BootGrant { obj: *object, offset: 0, size: *backing, perms: Permissions::READ });
        maps.push(BootMap { vaddr: map.base, size: *backing, obj: *object, obj_offset: 0 });
    }

    let info = BootInfo {
        image: BootImage {
            obj: code_obj,
            code_offset: 0,
            code_size: preprocessor_image.len() as u64,
            entry: 0,
            lit_start: 0,
        },
        grants,
        maps,
        code_vaddr: 0,
        stack_vaddr: stack_map.base,
        stack_size: stack_map.size,
        trap_vaddr: trap_map.base,
    };

    let hwm = fabric.physical_high_watermark()
        .ok_or(AnkaPreprocessError::PhysicalExtentOutsideFabric)?;
    let kernel_base = pool_end.max(hwm);
    let dynamic = stack_map.size.checked_add(trap_map.size)
        .ok_or(AnkaPreprocessError::SizeOverflow)?;
    if kernel_base.checked_add(dynamic).filter(|end| *end <= mem_size).is_none() {
        return Err(AnkaPreprocessError::PhysicalExtentOutsideFabric);
    }

    let mut kernel = Kernel::new(fabric);
    kernel.next_phys = kernel_base;
    kernel.boot(&info).map_err(AnkaPreprocessError::Boot)?;
    kernel.run(ANKAPP_QUANTUM, ANKAPP_MAX_ROUNDS);

    let init = kernel.processes.get(0).ok_or(AnkaPreprocessError::PreprocessorDidNotExit)?;
    if !init.exited() {
        return Err(AnkaPreprocessError::PreprocessorDidNotExit);
    }
    let status = read_u64_physical(&kernel.fabric, result_phys, RESULT_STATUS);
    if init.exit_code != 0 || status != 0 {
        return Err(AnkaPreprocessError::PreprocessorRejected(
            if status != 0 { status } else { init.exit_code },
        ));
    }

    for object in [output_obj, workspace_obj, result_obj] {
        if kernel.fabric.objects.get(&object).map(|o| o.state) != Some(ObjectState::Active) {
            return Err(AnkaPreprocessError::TransportObjectStateChanged);
        }
    }
    if kernel.fabric.objects.get(&manifest_obj).map(|o| o.state) != Some(ObjectState::Sealed) {
        return Err(AnkaPreprocessError::TransportObjectStateChanged);
    }
    let manifest_now = kernel.fabric.read_physical(manifest_phys, manifest_size);
    if manifest_now != manifest.as_slice() {
        return Err(AnkaPreprocessError::TransportObjectStateChanged);
    }
    for (((phys, object), member), _backing) in member_phys.iter()
        .zip(member_objects.iter())
        .zip(bundle.members())
        .zip(member_backing.iter())
    {
        if kernel.fabric.objects.get(object).map(|o| o.state) != Some(ObjectState::Sealed) {
            return Err(AnkaPreprocessError::SourceMemberMutated);
        }
        let now = kernel.fabric.read_physical(*phys, member.bytes().len() as u64);
        if now != member.bytes() {
            return Err(AnkaPreprocessError::SourceMemberMutated);
        }
    }

    let output_len = read_u64_physical(&kernel.fabric, result_phys, RESULT_OUTPUT_LEN);
    if output_len > EFFECTIVE_SOURCE_CAPACITY {
        return Err(AnkaPreprocessError::InvalidResultGeometry);
    }
    let bytes = kernel.fabric.read_physical(output_phys, output_len).to_vec();
    Ok(PreprocessedSource {
        bytes,
        process_slots_observed: kernel.processes.len(),
    })
}

/// Phase-10.5 convenience path: run include preprocessing inside Anka, then
/// feed only the resulting exact bytes to the existing Stage-3 compiler.
/// Preprocessing failure returns before Stage 3 can emit an AOM.
pub fn compile_source_bundle_to_aom_stage3(
    preprocessor_image: &[u8],
    stage3_compiler_image: &[u8],
    bundle: &SourceBundle,
) -> Result<CompiledAomModule, SourceBundleCompileError> {
    let effective = run_ankapp(preprocessor_image, bundle)
        .map_err(SourceBundleCompileError::Preprocess)?;
    compile_c_to_aom_stage3(stage3_compiler_image, &effective.bytes)
        .map_err(SourceBundleCompileError::Compile)
}
