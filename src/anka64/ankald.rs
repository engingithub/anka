//! Phase 10.4 bootstrap harness for the ordinary userspace `ankald` linker.
//!
//! The linker itself lives in `userspace/system/compiler/ankald.c` and performs
//! all symbol resolution, layout, relocation, and entry selection inside Anka.
//! This Rust module is transport/publication plumbing only:
//!
//! 1. map exact sealed AOM bytes read-only,
//! 2. map a distinct scratch object read/write (never SEAL or EXECUTE),
//! 3. run the linker as an ordinary Anka process,
//! 4. read its non-authoritative result metadata,
//! 5. copy exactly `image_size` bytes into a fresh exact-size object and seal it.
//!
//! It deliberately does not parse symbols, resolve imports, apply relocations,
//! or select entry addresses on the host.

use super::fabric::Fabric;
use super::os::{BootError, BootGrant, BootImage, BootInfo, BootMap, Kernel};
use super::placement::{
    PhysicalPlacementManager, PlacementError, VirtualLayoutBuilder,
    PLACEMENT_PAGE_SIZE,
};
use super::state::{Generation, ObjectId, ObjectKind, ObjectState, Permissions};

pub const ANKALD_CONTROL_VADDR: u64 = 0x20000;
const ANKALD_VIRTUAL_LIMIT: u64 = 0x80_0000;
const ANKALD_RAM_SIZE: usize = 0x100_0000;
const ANKALD_PM_BASE: u64 = 0x10000;
const ANKALD_PM_SIZE: u64 = 0x700000;
const ANKALD_STACK_SIZE: u64 = 0x4000;
const ANKALD_TRAP_SIZE: u64 = PLACEMENT_PAGE_SIZE;
const ANKALD_QUANTUM: usize = 5_000_000;
const ANKALD_MAX_ROUNDS: usize = 200;

const CTRL_MODULE_COUNT: usize = 0;
const CTRL_DESCRIPTOR_VADDR: usize = 8;
const CTRL_OUTPUT_VADDR: usize = 16;
const CTRL_OUTPUT_CAPACITY: usize = 24;
const CTRL_ENTRY_VADDR: usize = 32;
const CTRL_ENTRY_LEN: usize = 40;
const CTRL_STATUS: u64 = 48;
const CTRL_CODE_SIZE: u64 = 56;
const CTRL_LIT_START: u64 = 64;
const CTRL_ENTRY: u64 = 72;
const CTRL_IMAGE_SIZE: u64 = 80;
const CTRL_PREFIX_SIZE: usize = 128;
const MODULE_DESCRIPTOR_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnkaldLinkedImage {
    pub bytes: Vec<u8>,
    pub code_size: u64,
    pub lit_start: u64,
    pub entry: u64,
    /// Ordinary userspace closure witness: ankald does not spawn linked output.
    pub process_slots_observed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkedArtifactKey {
    pub object: ObjectId,
    pub generation: Generation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedArtifact {
    pub key: LinkedArtifactKey,
    pub logical_size: u64,
    pub code_size: u64,
    pub lit_start: u64,
    pub entry: u64,
    pub code_permissions: Permissions,
    pub rodata_permissions: Option<Permissions>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnkaldError {
    EmptyLinkerImage,
    LinkerImageOverlapsControl,
    EmptyInput,
    EmptyModule(usize),
    EntryNameTooLong,
    SizeOverflow,
    VirtualLayout(PlacementError),
    Placement(PlacementError),
    PhysicalExtentOutsideFabric,
    InitializationRejected,
    Boot(BootError),
    LinkerDidNotExit,
    LinkerRejected(u64),
    InvalidResultGeometry,
    ScratchUnexpectedlySealed,
    LinkedOutputMutatedInput,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnkaldPublishError {
    EmptyImage,
    Placement(PlacementError),
    PhysicalExtentOutsideFabric,
    InitializationRejected,
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u64_physical(fabric: &Fabric, base: u64, offset: u64) -> u64 {
    let bytes = fabric.read_physical(base + offset, 8);
    u64::from_le_bytes(bytes.try_into().expect("eight-byte ankald control read"))
}

fn scratch_capacity(inputs: &[&[u8]]) -> Result<u64, AnkaldError> {
    // For structurally valid AOM v1, three times the sum of container sizes is
    // a conservative transport capacity without the host interpreting section
    // or symbol semantics.  The linker itself remains the authority for exact
    // layout and returns the exact image_size actually produced.
    let total = inputs.iter().try_fold(0u64, |acc, bytes| {
        let len = u64::try_from(bytes.len()).map_err(|_| AnkaldError::SizeOverflow)?;
        acc.checked_add(len).ok_or(AnkaldError::SizeOverflow)
    })?;
    total.checked_mul(3).ok_or(AnkaldError::SizeOverflow)
}

fn allocate_placed(
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    label: &str,
    size: u64,
) -> Result<ObjectId, AnkaldError> {
    let object = fabric.alloc_object(label, size, ObjectKind::Memory);
    match placement.allocate_and_place_object(fabric, object) {
        Ok(_) => Ok(object),
        Err(err) => {
            assert!(fabric.rollback_unpublished_object(object),
                "fresh failed ankald transport object must rollback exactly");
            Err(AnkaldError::Placement(err))
        }
    }
}

fn initialize_exact(
    fabric: &mut Fabric,
    object: ObjectId,
    bytes: &[u8],
) -> Result<(), AnkaldError> {
    if !fabric.zero_object_extent(object) {
        return Err(AnkaldError::InitializationRejected);
    }
    if !bytes.is_empty() && !fabric.initialize_object(object, 0, bytes) {
        return Err(AnkaldError::InitializationRejected);
    }
    Ok(())
}

/// Run the real userspace linker against an explicit ordered AOM byte sequence.
///
/// `linker_image` is the direct executable bootstrap image produced by
/// canonical CC_B from `userspace/system/compiler/ankald.c`.
pub fn run_ankald(
    linker_image: &[u8],
    inputs: &[&[u8]],
    entry_name: &str,
) -> Result<AnkaldLinkedImage, AnkaldError> {
    if linker_image.is_empty() {
        return Err(AnkaldError::EmptyLinkerImage);
    }
    if linker_image.len() as u64 > ANKALD_CONTROL_VADDR {
        return Err(AnkaldError::LinkerImageOverlapsControl);
    }
    if inputs.is_empty() {
        return Err(AnkaldError::EmptyInput);
    }
    for (index, bytes) in inputs.iter().enumerate() {
        if bytes.is_empty() {
            return Err(AnkaldError::EmptyModule(index));
        }
    }
    if entry_name.is_empty() || entry_name.len() > 63 {
        return Err(AnkaldError::EntryNameTooLong);
    }

    let descriptor_bytes = inputs.len()
        .checked_mul(MODULE_DESCRIPTOR_SIZE)
        .ok_or(AnkaldError::SizeOverflow)?;
    let entry_offset = CTRL_PREFIX_SIZE
        .checked_add(descriptor_bytes)
        .ok_or(AnkaldError::SizeOverflow)?;
    let control_len = entry_offset
        .checked_add(entry_name.len())
        .ok_or(AnkaldError::SizeOverflow)?;
    // The guest implements byte reads by loading the containing 64-bit word
    // (`rb()` in ankald.c).  Preserve the exact semantic entry length in the
    // control fields, but give the transport object/grant/map enough zeroed
    // tail bytes for the final word read to remain inside one object.
    let control_backing_len = control_len
        .checked_add(7)
        .ok_or(AnkaldError::SizeOverflow)?
        & !7usize;
    let control_size = u64::try_from(control_backing_len)
        .map_err(|_| AnkaldError::SizeOverflow)?;
    let scratch_size = scratch_capacity(inputs)?;
    if scratch_size == 0 {
        return Err(AnkaldError::SizeOverflow);
    }

    let mut vlb = VirtualLayoutBuilder::after_image(
        ANKALD_CONTROL_VADDR,
        control_size,
        ANKALD_VIRTUAL_LIMIT,
    ).map_err(AnkaldError::VirtualLayout)?;
    let mut input_maps = Vec::with_capacity(inputs.len());
    for bytes in inputs {
        input_maps.push(vlb.reserve(bytes.len() as u64)
            .map_err(AnkaldError::VirtualLayout)?);
    }
    let scratch_map = vlb.reserve(scratch_size).map_err(AnkaldError::VirtualLayout)?;
    let stack_map = vlb.reserve(ANKALD_STACK_SIZE).map_err(AnkaldError::VirtualLayout)?;
    let trap_map = vlb.reserve(ANKALD_TRAP_SIZE).map_err(AnkaldError::VirtualLayout)?;

    let mut fabric = Fabric::new(ANKALD_RAM_SIZE);
    let mut placement = PhysicalPlacementManager::new(ANKALD_PM_BASE, ANKALD_PM_SIZE)
        .map_err(AnkaldError::Placement)?;

    let linker_obj = allocate_placed(&mut fabric, &mut placement, "ankald-code", linker_image.len() as u64)?;
    let control_obj = allocate_placed(&mut fabric, &mut placement, "ankald-control", control_size)?;
    let scratch_obj = allocate_placed(&mut fabric, &mut placement, "ankald-scratch", scratch_size)?;
    let mut input_objects = Vec::with_capacity(inputs.len());
    for (index, bytes) in inputs.iter().enumerate() {
        input_objects.push(allocate_placed(
            &mut fabric,
            &mut placement,
            &format!("ankald-input-{index}"),
            bytes.len() as u64,
        )?);
    }

    let pool_end = placement.pool().end().ok_or(AnkaldError::PhysicalExtentOutsideFabric)?;
    let mem_size = u64::try_from(fabric.mem_size()).map_err(|_| AnkaldError::SizeOverflow)?;
    if pool_end > mem_size {
        return Err(AnkaldError::PhysicalExtentOutsideFabric);
    }
    for object in std::iter::once(linker_obj)
        .chain(std::iter::once(control_obj))
        .chain(std::iter::once(scratch_obj))
        .chain(input_objects.iter().copied())
    {
        let extent = placement.allocated_extent(object)
            .ok_or(AnkaldError::PhysicalExtentOutsideFabric)?;
        if extent.end().map(|end| end <= mem_size) != Some(true) {
            return Err(AnkaldError::PhysicalExtentOutsideFabric);
        }
    }

    initialize_exact(&mut fabric, linker_obj, linker_image)?;
    assert!(fabric.seal_object(linker_obj), "ankald executable must seal exactly once");
    initialize_exact(&mut fabric, scratch_obj, &[])?;
    for (object, bytes) in input_objects.iter().copied().zip(inputs.iter().copied()) {
        initialize_exact(&mut fabric, object, bytes)?;
        assert!(fabric.seal_object(object), "AOM input transport object must seal exactly once");
    }

    let mut control = vec![0u8; control_backing_len];
    put_u64(&mut control, CTRL_MODULE_COUNT, inputs.len() as u64);
    put_u64(&mut control, CTRL_DESCRIPTOR_VADDR,
        ANKALD_CONTROL_VADDR + CTRL_PREFIX_SIZE as u64);
    put_u64(&mut control, CTRL_OUTPUT_VADDR, scratch_map.base);
    put_u64(&mut control, CTRL_OUTPUT_CAPACITY, scratch_size);
    put_u64(&mut control, CTRL_ENTRY_VADDR,
        ANKALD_CONTROL_VADDR + entry_offset as u64);
    put_u64(&mut control, CTRL_ENTRY_LEN, entry_name.len() as u64);
    put_u64(&mut control, CTRL_STATUS as usize, u64::MAX);
    for (index, (map, bytes)) in input_maps.iter().zip(inputs.iter()).enumerate() {
        let base = CTRL_PREFIX_SIZE + index * MODULE_DESCRIPTOR_SIZE;
        put_u64(&mut control, base, map.base);
        put_u64(&mut control, base + 8, bytes.len() as u64);
    }
    control[entry_offset..entry_offset + entry_name.len()].copy_from_slice(entry_name.as_bytes());
    initialize_exact(&mut fabric, control_obj, &control)?;

    let control_phys = placement.allocated_extent(control_obj)
        .expect("placed ankald control remains PM-owned").base;
    let scratch_phys = placement.allocated_extent(scratch_obj)
        .expect("placed ankald scratch remains PM-owned").base;
    let input_phys: Vec<u64> = input_objects.iter().map(|object| {
        placement.allocated_extent(*object)
            .expect("placed ankald input remains PM-owned").base
    }).collect();

    let mut grants = vec![
        BootGrant {
            obj: control_obj,
            offset: 0,
            size: control_size,
            perms: Permissions::RW,
        },
        BootGrant {
            obj: scratch_obj,
            offset: 0,
            size: scratch_size,
            perms: Permissions::RW,
        },
    ];
    let mut maps = vec![
        BootMap {
            vaddr: ANKALD_CONTROL_VADDR,
            size: control_size,
            obj: control_obj,
            obj_offset: 0,
        },
        BootMap {
            vaddr: scratch_map.base,
            size: scratch_size,
            obj: scratch_obj,
            obj_offset: 0,
        },
    ];
    for ((object, map), bytes) in input_objects.iter().zip(input_maps.iter()).zip(inputs.iter()) {
        grants.push(BootGrant {
            obj: *object,
            offset: 0,
            size: bytes.len() as u64,
            perms: Permissions::READ,
        });
        maps.push(BootMap {
            vaddr: map.base,
            size: bytes.len() as u64,
            obj: *object,
            obj_offset: 0,
        });
    }

    let info = BootInfo {
        image: BootImage {
            obj: linker_obj,
            code_offset: 0,
            code_size: linker_image.len() as u64,
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
        .ok_or(AnkaldError::PhysicalExtentOutsideFabric)?;
    let kernel_base = pool_end.max(hwm);
    let dynamic = stack_map.size.checked_add(trap_map.size)
        .ok_or(AnkaldError::SizeOverflow)?;
    if kernel_base.checked_add(dynamic).filter(|end| *end <= mem_size).is_none() {
        return Err(AnkaldError::PhysicalExtentOutsideFabric);
    }

    let mut kernel = Kernel::new(fabric);
    kernel.next_phys = kernel_base;
    kernel.boot(&info).map_err(AnkaldError::Boot)?;
    kernel.run(ANKALD_QUANTUM, ANKALD_MAX_ROUNDS);

    let init = kernel.processes.get(0).ok_or(AnkaldError::LinkerDidNotExit)?;
    if !init.exited() {
        return Err(AnkaldError::LinkerDidNotExit);
    }
    let status = read_u64_physical(&kernel.fabric, control_phys, CTRL_STATUS);
    if init.exit_code != 0 || status != 0 {
        return Err(AnkaldError::LinkerRejected(if status != 0 { status } else { init.exit_code }));
    }

    let scratch_state = kernel.fabric.objects.get(&scratch_obj)
        .ok_or(AnkaldError::InvalidResultGeometry)?;
    if scratch_state.state != ObjectState::Active {
        return Err(AnkaldError::ScratchUnexpectedlySealed);
    }

    // Read-only AOM grants must have kept every exact input byte unchanged.
    for ((phys, original), object) in input_phys.iter().zip(inputs.iter()).zip(input_objects.iter()) {
        let now = kernel.fabric.read_physical(*phys, original.len() as u64);
        if now != *original {
            return Err(AnkaldError::LinkedOutputMutatedInput);
        }
        if kernel.fabric.objects.get(object).map(|o| o.state) != Some(ObjectState::Sealed) {
            return Err(AnkaldError::LinkedOutputMutatedInput);
        }
    }

    let code_size = read_u64_physical(&kernel.fabric, control_phys, CTRL_CODE_SIZE);
    let lit_start = read_u64_physical(&kernel.fabric, control_phys, CTRL_LIT_START);
    let entry = read_u64_physical(&kernel.fabric, control_phys, CTRL_ENTRY);
    let image_size = read_u64_physical(&kernel.fabric, control_phys, CTRL_IMAGE_SIZE);
    if code_size == 0 || code_size > image_size || image_size > scratch_size
        || entry >= code_size || entry & 7 != 0
        || (lit_start == 0 && image_size != code_size)
        || (lit_start != 0 && (lit_start < code_size || lit_start >= image_size))
    {
        return Err(AnkaldError::InvalidResultGeometry);
    }

    let image_len = usize::try_from(image_size).map_err(|_| AnkaldError::SizeOverflow)?;
    let bytes = kernel.fabric.read_physical(scratch_phys, image_len as u64).to_vec();
    Ok(AnkaldLinkedImage {
        bytes,
        code_size,
        lit_start,
        entry,
        process_slots_observed: kernel.processes.len(),
    })
}

/// Publish exact bytes produced by `run_ankald` into a caller-owned Fabric.
///
/// This step performs no linking.  It copies exactly the already-computed
/// `image.bytes` into a fresh exact-size object and seals that object.  No
/// capability or execution authority is granted by this function.
pub fn publish_linked_image(
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    label: &str,
    image: &AnkaldLinkedImage,
) -> Result<LinkedArtifact, AnkaldPublishError> {
    if image.bytes.is_empty() {
        return Err(AnkaldPublishError::EmptyImage);
    }
    let logical_size = u64::try_from(image.bytes.len())
        .map_err(|_| AnkaldPublishError::InitializationRejected)?;
    let object = fabric.alloc_object(label, logical_size, ObjectKind::Memory);
    let extent = match placement.allocate_and_place_object(fabric, object) {
        Ok(extent) => extent,
        Err(err) => {
            assert!(fabric.rollback_unpublished_object(object),
                "fresh failed linked artifact must rollback exactly");
            return Err(AnkaldPublishError::Placement(err));
        }
    };
    let mem_size = u64::try_from(fabric.mem_size())
        .map_err(|_| AnkaldPublishError::PhysicalExtentOutsideFabric)?;
    if extent.end().map(|end| end <= mem_size) != Some(true) {
        assert!(fabric.rollback_unpublished_object(object));
        placement.release_unplaced(fabric, object)
            .expect("failed linked artifact placement must release PM reservation");
        return Err(AnkaldPublishError::PhysicalExtentOutsideFabric);
    }
    if !fabric.zero_object_extent(object) || !fabric.initialize_object(object, 0, &image.bytes) {
        assert!(fabric.rollback_unpublished_object(object));
        placement.release_unplaced(fabric, object)
            .expect("failed linked artifact initialization must release PM reservation");
        return Err(AnkaldPublishError::InitializationRejected);
    }
    assert!(fabric.seal_object(object), "complete linked artifact must seal exactly once");
    let generation = fabric.objects.get(&object)
        .expect("sealed linked artifact remains present").generation;
    Ok(LinkedArtifact {
        key: LinkedArtifactKey { object, generation },
        logical_size,
        code_size: image.code_size,
        lit_start: image.lit_start,
        entry: image.entry,
        code_permissions: Permissions::RX,
        rodata_permissions: if image.lit_start == 0 { None } else { Some(Permissions::READ) },
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnkaldLinkPublishError {
    Link(AnkaldError),
    Publish(AnkaldPublishError),
}

/// Development/bootstrap convenience: execute the ordinary Anka linker first,
/// then publish its exact completed bytes into the caller-owned Fabric.
/// Link failure occurs before any mutation of the caller-owned Fabric/PM.
pub fn link_and_publish_with_ankald(
    linker_image: &[u8],
    inputs: &[&[u8]],
    entry_name: &str,
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    label: &str,
) -> Result<LinkedArtifact, AnkaldLinkPublishError> {
    let image = run_ankald(linker_image, inputs, entry_name)
        .map_err(AnkaldLinkPublishError::Link)?;
    publish_linked_image(fabric, placement, label, &image)
        .map_err(AnkaldLinkPublishError::Publish)
}
