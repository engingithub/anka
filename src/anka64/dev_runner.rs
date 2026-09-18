//! Anka64 development artifact execution bridge (Phase 9.3h.3).
//!
//! This module is deliberately narrower than a general host-side process
//! launcher.  The developer may explicitly authorize one run, but the bridge
//! does not execute the registered artifact directly:
//!
//!   DeveloperExecutionAuthority
//!     + exact current sealed ArtifactKey
//!     -> exact RX(code) / R(literals) authority presented to a tiny supervisor
//!     -> VLB-generated child layout
//!     -> ordinary guest SYS_SPAWN + SYS_WAIT
//!
//! The execution token is host-development policy, not a Fabric capability and
//! is never inherited by the child.  Ingress authority, placement, and execution
//! authority therefore remain distinct.

use super::dev_shell::{
    ArtifactKey, DevelopmentArtifact, DevelopmentArtifactRegistry, DevelopmentShellError,
};
use super::fabric::Fabric;
use super::isa::{Asm64, R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11};
use super::os::{
    BootError, BootGrant, BootImage, BootInfo, BootMap, Kernel, ProcessResult,
    SYS_EXIT, SYS_SPAWN, SYS_WAIT,
};
use super::placement::{
    PhysicalPlacementManager, PlacementError, VirtualLayoutBuilder,
    PLACEMENT_PAGE_SIZE,
};
use super::state::{ObjectId, ObjectKind, Permissions};

/// Explicit host-development authority to present a registered artifact to the
/// ordinary Anka spawn path.
///
/// This is intentionally a different type from `DeveloperIngressAuthority`.
/// Possessing permission to introduce bytes does not imply permission to run
/// them.  The token is never inserted into Fabric or exposed to guest code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeveloperExecutionAuthority {
    _private: (),
}

impl DeveloperExecutionAuthority {
    pub fn provision() -> Self {
        Self { _private: () }
    }
}

/// Virtual layout actually used for one process incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevelopmentProcessLayout {
    pub code_vaddr: u64,
    pub stack_vaddr: u64,
    pub stack_size: u64,
    pub trap_vaddr: u64,
}

/// Runtime policy for the one-shot Phase 9.3h.3 supervisor.
///
/// The defaults are intentionally modest and can be widened later for network
/// services without changing the authority model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevelopmentRunConfig {
    pub virtual_limit: u64,
    pub supervisor_stack_size: u64,
    pub child_stack_size: u64,
    pub quantum: usize,
    pub max_rounds: usize,
}

impl Default for DevelopmentRunConfig {
    fn default() -> Self {
        Self {
            virtual_limit: 0x20_0000,
            supervisor_stack_size: 0x4000,
            child_stack_size: 0x4000,
            quantum: 200_000,
            max_rounds: 10_000,
        }
    }
}

/// Observable result of one development-shell `run` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevelopmentRunReport {
    pub artifact: ArtifactKey,
    pub child_result: ProcessResult,
    pub byte_output: Vec<u8>,
    pub child_layout: DevelopmentProcessLayout,
    pub supervisor_layout: DevelopmentProcessLayout,
    pub artifact_parent_vaddr: u64,
    pub presented_code_permissions: Permissions,
    pub presented_literal_permissions: Option<Permissions>,
    /// A successful run must have created at least the supervisor and one child
    /// process slot.  The child is collected by SYS_WAIT before this report is
    /// returned.
    pub process_slots_observed: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DevelopmentRunError {
    DeveloperExecutionAuthorityRequired,
    Artifact(DevelopmentShellError),
    InvalidArtifactGeometry,
    ArtifactPlacementMissing,
    ArtifactPlacementMismatch,
    PhysicalPoolOutsideFabric,
    KernelPhysicalMemoryExhausted,
    VirtualLayout(PlacementError),
    Placement(PlacementError),
    FabricInitializationRejected,
    Boot(BootError),
    SupervisorDidNotExit,
    SupervisorFailed(ProcessResult),
    SpawnRejected,
    InvalidWaitTag(u64),
}

const SUPERVISOR_OBJECT_SIZE: u64 = PLACEMENT_PAGE_SIZE;
const CONTROL_OBJECT_SIZE: u64 = 64;
const CONTROL_LAYOUT_OFFSET: u64 = 24;
const TRAP_SIZE: u64 = PLACEMENT_PAGE_SIZE;
const MOVI_MAX: u64 = 0x1_FFFF;

#[derive(Debug)]
struct PreparedRun {
    artifact: DevelopmentArtifact,
    supervisor_obj: ObjectId,
    control_obj: ObjectId,
    boot_info: BootInfo,
    child_layout: DevelopmentProcessLayout,
    supervisor_layout: DevelopmentProcessLayout,
    artifact_parent_vaddr: u64,
    kernel_phys_base: u64,
}

/// Run a registered artifact by friendly name or absolute logical Anka path.
///
/// `selector = "hello"` resolves the friendly development name.
/// `selector = "/bin/hello"` resolves the future logical Anka path.
///
/// The target Fabric is borrowed rather than consumed.  Internally it is moved
/// into a one-shot Kernel, the tiny supervisor performs SYS_SPAWN/SYS_WAIT, all
/// transient supervisor state is reclaimed, and the Fabric is restored.  The
/// registered artifact and its PM placement survive the run.
pub fn run_registered_artifact(
    registry: &DevelopmentArtifactRegistry,
    authority: Option<&DeveloperExecutionAuthority>,
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    selector: &str,
) -> Result<DevelopmentRunReport, DevelopmentRunError> {
    run_registered_artifact_with_config(
        registry,
        authority,
        fabric,
        placement,
        selector,
        DevelopmentRunConfig::default(),
    )
}

pub fn run_registered_artifact_with_config(
    registry: &DevelopmentArtifactRegistry,
    authority: Option<&DeveloperExecutionAuthority>,
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    selector: &str,
    config: DevelopmentRunConfig,
) -> Result<DevelopmentRunReport, DevelopmentRunError> {
    let authority = authority
        .ok_or(DevelopmentRunError::DeveloperExecutionAuthorityRequired)?;

    let prepared = prepare_run(
        registry, authority, fabric, placement, selector, config,
    )?;
    execute_prepared_run(fabric, placement, prepared, config)
}

fn resolve_artifact<'a>(
    registry: &'a DevelopmentArtifactRegistry,
    fabric: &Fabric,
    selector: &str,
) -> Result<&'a DevelopmentArtifact, DevelopmentRunError> {
    let result = if selector.starts_with('/') {
        registry.resolve_current_by_logical_path(fabric, selector)
    } else {
        registry.resolve_current(fabric, selector)
    };
    result.map_err(DevelopmentRunError::Artifact)
}

fn validate_artifact_geometry(
    fabric: &Fabric,
    placement: &PhysicalPlacementManager,
    artifact: &DevelopmentArtifact,
) -> Result<(), DevelopmentRunError> {
    let object = fabric.objects.get(&artifact.key.object)
        .ok_or(DevelopmentRunError::Artifact(DevelopmentShellError::ArtifactObjectMissing))?;

    if object.size != artifact.logical_size
        || artifact.code_size == 0
        || artifact.code_size > artifact.logical_size
    {
        return Err(DevelopmentRunError::InvalidArtifactGeometry);
    }

    if artifact.lit_start == 0 {
        if artifact.code_size != artifact.logical_size {
            return Err(DevelopmentRunError::InvalidArtifactGeometry);
        }
    } else if artifact.lit_start < artifact.code_size
        || artifact.lit_start >= artifact.logical_size
    {
        return Err(DevelopmentRunError::InvalidArtifactGeometry);
    }

    let managed = placement.allocated_extent(artifact.key.object)
        .ok_or(DevelopmentRunError::ArtifactPlacementMissing)?;
    let fabric_base = fabric.physical_base(artifact.key.object)
        .ok_or(DevelopmentRunError::ArtifactPlacementMissing)?;
    if managed.base != fabric_base {
        return Err(DevelopmentRunError::ArtifactPlacementMismatch);
    }

    let mem_size = u64::try_from(fabric.mem_size())
        .map_err(|_| DevelopmentRunError::PhysicalPoolOutsideFabric)?;
    if managed.end().map(|end| end <= mem_size) != Some(true) {
        return Err(DevelopmentRunError::ArtifactPlacementMismatch);
    }

    Ok(())
}

fn prepare_run(
    registry: &DevelopmentArtifactRegistry,
    _authority: &DeveloperExecutionAuthority,
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    selector: &str,
    config: DevelopmentRunConfig,
) -> Result<PreparedRun, DevelopmentRunError> {
    let artifact = resolve_artifact(registry, fabric, selector)?.clone();
    validate_artifact_geometry(fabric, placement, &artifact)?;

    if config.supervisor_stack_size < PLACEMENT_PAGE_SIZE
        || config.child_stack_size < PLACEMENT_PAGE_SIZE
    {
        return Err(DevelopmentRunError::VirtualLayout(
            PlacementError::InvalidVirtualLayout,
        ));
    }

    // Child image -> stack -> trap.  `logical_size`, not merely `code_size`,
    // keeps the stack above a high two-ended literal segment.
    let mut child_vlb = VirtualLayoutBuilder::after_image(
        0,
        artifact.logical_size,
        config.virtual_limit,
    ).map_err(DevelopmentRunError::VirtualLayout)?;
    let child_stack = child_vlb.reserve(config.child_stack_size)
        .map_err(DevelopmentRunError::VirtualLayout)?;
    let child_trap = child_vlb.reserve(TRAP_SIZE)
        .map_err(DevelopmentRunError::VirtualLayout)?;
    let child_layout = DevelopmentProcessLayout {
        code_vaddr: 0,
        stack_vaddr: child_stack.base,
        stack_size: child_stack.size,
        trap_vaddr: child_trap.base,
    };

    // Supervisor image -> control -> artifact mapping -> stack -> trap.
    // Control comes first so its address remains a small immediate even when a
    // literal-bearing artifact preserves a large backing arena.
    let mut supervisor_vlb = VirtualLayoutBuilder::after_image(
        0,
        SUPERVISOR_OBJECT_SIZE,
        config.virtual_limit,
    ).map_err(DevelopmentRunError::VirtualLayout)?;
    let control_map = supervisor_vlb.reserve(CONTROL_OBJECT_SIZE)
        .map_err(DevelopmentRunError::VirtualLayout)?;
    let artifact_map = supervisor_vlb.reserve(artifact.logical_size)
        .map_err(DevelopmentRunError::VirtualLayout)?;
    let supervisor_stack = supervisor_vlb.reserve(config.supervisor_stack_size)
        .map_err(DevelopmentRunError::VirtualLayout)?;
    let supervisor_trap = supervisor_vlb.reserve(TRAP_SIZE)
        .map_err(DevelopmentRunError::VirtualLayout)?;
    let supervisor_layout = DevelopmentProcessLayout {
        code_vaddr: 0,
        stack_vaddr: supervisor_stack.base,
        stack_size: supervisor_stack.size,
        trap_vaddr: supervisor_trap.base,
    };

    if control_map.base > MOVI_MAX {
        return Err(DevelopmentRunError::VirtualLayout(
            PlacementError::InvalidVirtualLayout,
        ));
    }

    let pool_end = placement.pool().end()
        .ok_or(DevelopmentRunError::PhysicalPoolOutsideFabric)?;
    let mem_size = u64::try_from(fabric.mem_size())
        .map_err(|_| DevelopmentRunError::PhysicalPoolOutsideFabric)?;
    if pool_end > mem_size {
        return Err(DevelopmentRunError::PhysicalPoolOutsideFabric);
    }
    let fabric_hwm = fabric.physical_high_watermark()
        .ok_or(DevelopmentRunError::KernelPhysicalMemoryExhausted)?;
    let kernel_phys_base = pool_end.max(fabric_hwm);

    // Kernel-owned stack/trap extents deliberately begin above both the PM pool
    // and every already-placed Fabric object.  This preserves the 9.3g scope
    // boundary without assuming that PM owns every physical placement.
    let dynamic_required = supervisor_stack.size
        .checked_add(TRAP_SIZE)
        .and_then(|v| v.checked_add(child_stack.size))
        .and_then(|v| v.checked_add(TRAP_SIZE))
        .ok_or(DevelopmentRunError::KernelPhysicalMemoryExhausted)?;
    if kernel_phys_base.checked_add(dynamic_required)
        .filter(|end| *end <= mem_size)
        .is_none()
    {
        return Err(DevelopmentRunError::KernelPhysicalMemoryExhausted);
    }

    let supervisor_code = build_spawn_supervisor(control_map.base);
    if supervisor_code.len() as u64 > SUPERVISOR_OBJECT_SIZE {
        return Err(DevelopmentRunError::FabricInitializationRejected);
    }
    let control_bytes = build_control_block(
        artifact_map.base,
        &artifact,
        child_layout,
    );

    // Allocate both transient PM-managed objects before initializing either.
    // A failure on the second reservation can therefore roll back exact object
    // identity in reverse allocation order.
    let supervisor_obj = allocate_transient_object(
        fabric,
        placement,
        "dev-run-supervisor",
        SUPERVISOR_OBJECT_SIZE,
    )?;

    let control_obj = match allocate_transient_object(
        fabric,
        placement,
        "dev-run-control",
        CONTROL_OBJECT_SIZE,
    ) {
        Ok(obj) => obj,
        Err(err) => {
            rollback_active_transient(fabric, placement, supervisor_obj);
            return Err(err);
        }
    };

    if !fabric.zero_object_extent(supervisor_obj)
        || !fabric.zero_object_extent(control_obj)
    {
        rollback_active_transient(fabric, placement, control_obj);
        rollback_active_transient(fabric, placement, supervisor_obj);
        return Err(DevelopmentRunError::FabricInitializationRejected);
    }

    assert!(fabric.initialize_object(supervisor_obj, 0, &supervisor_code),
        "zeroed transient supervisor must accept exact in-bounds initialization");
    assert!(fabric.initialize_object(control_obj, 0, &control_bytes),
        "zeroed transient control object must accept exact in-bounds initialization");
    assert!(fabric.seal_object(supervisor_obj),
        "fresh development supervisor must seal once");
    assert!(fabric.seal_object(control_obj),
        "fresh development control object must seal once");

    let mut grants = vec![
        // DeveloperExecutionAuthority authorizes this exact ordinary Anka RX
        // presentation.  Boot is the trusted root for the one-shot supervisor;
        // the child still receives authority only by SYS_SPAWN derivation.
        BootGrant {
            obj: artifact.key.object,
            offset: 0,
            size: artifact.code_size,
            perms: Permissions::RX,
        },
        BootGrant {
            obj: control_obj,
            offset: 0,
            size: CONTROL_OBJECT_SIZE,
            perms: Permissions::READ,
        },
    ];
    if artifact.lit_start != 0 {
        grants.push(BootGrant {
            obj: artifact.key.object,
            offset: artifact.lit_start,
            size: artifact.logical_size - artifact.lit_start,
            perms: Permissions::READ,
        });
    }

    let boot_info = BootInfo {
        image: BootImage {
            obj: supervisor_obj,
            code_offset: 0,
            code_size: supervisor_code.len() as u64,
            entry: 0,
            lit_start: 0,
        },
        grants,
        maps: vec![
            BootMap {
                vaddr: control_map.base,
                size: CONTROL_OBJECT_SIZE,
                obj: control_obj,
                obj_offset: 0,
            },
            BootMap {
                vaddr: artifact_map.base,
                size: artifact.logical_size,
                obj: artifact.key.object,
                obj_offset: 0,
            },
        ],
        code_vaddr: supervisor_layout.code_vaddr,
        stack_vaddr: supervisor_layout.stack_vaddr,
        stack_size: supervisor_layout.stack_size,
        trap_vaddr: supervisor_layout.trap_vaddr,
    };

    Ok(PreparedRun {
        artifact,
        supervisor_obj,
        control_obj,
        boot_info,
        child_layout,
        supervisor_layout,
        artifact_parent_vaddr: artifact_map.base,
        kernel_phys_base,
    })
}

fn execute_prepared_run(
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    prepared: PreparedRun,
    config: DevelopmentRunConfig,
) -> Result<DevelopmentRunReport, DevelopmentRunError> {
    let PreparedRun {
        artifact,
        supervisor_obj,
        control_obj,
        boot_info,
        child_layout,
        supervisor_layout,
        artifact_parent_vaddr,
        kernel_phys_base,
    } = prepared;

    // Kernel owns Fabric while guest code executes.  A tiny placeholder keeps
    // the caller's borrow valid; `Kernel::into_fabric` restores the same machine
    // state after transient supervisor teardown.
    let owned_fabric = std::mem::replace(fabric, Fabric::new(0));
    let mut kernel = Kernel::new(owned_fabric);
    kernel.next_phys = kernel_phys_base;

    if let Err(err) = kernel.boot(&boot_info) {
        teardown_sealed_transient(&mut kernel.fabric, placement, control_obj);
        teardown_sealed_transient(&mut kernel.fabric, placement, supervisor_obj);
        *fabric = kernel.into_fabric();
        return Err(DevelopmentRunError::Boot(err));
    }

    kernel.run(config.quantum, config.max_rounds);

    if kernel.processes.is_empty() || !kernel.processes[0].exited() {
        if !kernel.processes.is_empty() {
            kernel.finish_process(0, ProcessResult::ProtectionFault);
            kernel.reclaim_process(0);
        }
        scrub_kernel_dynamic_region(&mut kernel, kernel_phys_base);
        teardown_sealed_transient(&mut kernel.fabric, placement, control_obj);
        teardown_sealed_transient(&mut kernel.fabric, placement, supervisor_obj);
        *fabric = kernel.into_fabric();
        return Err(DevelopmentRunError::SupervisorDidNotExit);
    }

    let supervisor_result = kernel.processes[0].result.clone()
        .expect("exited supervisor must have ProcessResult");
    if !matches!(supervisor_result, ProcessResult::Exited(_)) {
        kernel.reclaim_process(0);
        scrub_kernel_dynamic_region(&mut kernel, kernel_phys_base);
        teardown_sealed_transient(&mut kernel.fabric, placement, control_obj);
        teardown_sealed_transient(&mut kernel.fabric, placement, supervisor_obj);
        *fabric = kernel.into_fabric();
        return Err(DevelopmentRunError::SupervisorFailed(supervisor_result));
    }

    let wait_tag = kernel.processes[0].core.r[R9 as usize];
    let wait_detail = kernel.processes[0].core.r[R10 as usize];
    let child_result = match wait_tag {
        0 => ProcessResult::Exited(wait_detail),
        1 => ProcessResult::SupervisorFault,
        2 => ProcessResult::ProtectionFault,
        u64::MAX => {
            kernel.reclaim_process(0);
            scrub_kernel_dynamic_region(&mut kernel, kernel_phys_base);
            teardown_sealed_transient(&mut kernel.fabric, placement, control_obj);
            teardown_sealed_transient(&mut kernel.fabric, placement, supervisor_obj);
            *fabric = kernel.into_fabric();
            return Err(DevelopmentRunError::SpawnRejected);
        }
        other => {
            kernel.reclaim_process(0);
            scrub_kernel_dynamic_region(&mut kernel, kernel_phys_base);
            teardown_sealed_transient(&mut kernel.fabric, placement, control_obj);
            teardown_sealed_transient(&mut kernel.fabric, placement, supervisor_obj);
            *fabric = kernel.into_fabric();
            return Err(DevelopmentRunError::InvalidWaitTag(other));
        }
    };

    let process_slots_observed = kernel.processes.len();
    let byte_output = std::mem::take(&mut kernel.byte_output);

    // SYS_WAIT has already reclaimed the child.  Reclaim init explicitly so no
    // supervisor domain/capability survives the host development command.
    kernel.reclaim_process(0);
    scrub_kernel_dynamic_region(&mut kernel, kernel_phys_base);

    // The transient PM objects are not process-owned resources; remove them
    // after the supervisor domain has disappeared, then return their extents.
    teardown_sealed_transient(&mut kernel.fabric, placement, control_obj);
    teardown_sealed_transient(&mut kernel.fabric, placement, supervisor_obj);

    *fabric = kernel.into_fabric();

    Ok(DevelopmentRunReport {
        artifact: artifact.key,
        child_result,
        byte_output,
        child_layout,
        supervisor_layout,
        artifact_parent_vaddr,
        presented_code_permissions: Permissions::RX,
        presented_literal_permissions: if artifact.lit_start != 0 {
            Some(Permissions::READ)
        } else {
            None
        },
        process_slots_observed,
    })
}

fn build_spawn_supervisor(control_vaddr: u64) -> Vec<u8> {
    assert!(control_vaddr <= MOVI_MAX,
        "development control mapping must fit MOVI signed-positive range");

    let mut asm = Asm64::new();
    asm.movi(R11, control_vaddr as i32);
    asm.ld(R1, R11, 0);   // parent virtual address naming artifact
    asm.ld(R2, R11, 8);   // code_size
    asm.ld(R3, R11, 16);  // lit_start (0 if none)
    asm.movi(R4, 0);      // no extra child grants
    asm.movi(R5, 0);
    asm.movi(R6, 0);      // no extra child maps
    asm.movi(R7, 0);
    asm.lea(R8, R11, CONTROL_LAYOUT_OFFSET as i32); // explicit VLB SpawnLayout
    asm.movi(R0, SYS_SPAWN as i32);
    asm.trap(0);

    // SYS_SPAWN returns a lifecycle handle.  Waiting on that exact handle is
    // the constructive witness that execution still goes through normal Anka
    // lifecycle authority rather than a host-created child core.
    asm.mov(R9, R0);
    asm.mov(R1, R9);
    asm.movi(R0, SYS_WAIT as i32);
    asm.trap(0);

    // Preserve structured WAIT result for the host-side report, then exit the
    // transient supervisor normally with the child's detail as convenience.
    asm.mov(R9, R0);
    asm.mov(R10, R1);
    asm.mov(R1, R10);
    asm.movi(R0, SYS_EXIT as i32);
    asm.trap(0);
    asm.to_bytes()
}

fn build_control_block(
    artifact_parent_vaddr: u64,
    artifact: &DevelopmentArtifact,
    child_layout: DevelopmentProcessLayout,
) -> [u8; CONTROL_OBJECT_SIZE as usize] {
    let mut bytes = [0u8; CONTROL_OBJECT_SIZE as usize];
    let fields = [
        artifact_parent_vaddr,
        artifact.code_size,
        artifact.lit_start,
        child_layout.code_vaddr,
        child_layout.stack_vaddr,
        child_layout.stack_size,
        child_layout.trap_vaddr,
        0, // SpawnLayout reserved field
    ];
    for (i, value) in fields.iter().enumerate() {
        let start = i * 8;
        bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn allocate_transient_object(
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    label: &str,
    size: u64,
) -> Result<ObjectId, DevelopmentRunError> {
    let object = fabric.alloc_object(label, size, ObjectKind::Memory);
    let extent = match placement.allocate_and_place_object(fabric, object) {
        Ok(extent) => extent,
        Err(err) => {
            assert!(fabric.rollback_unpublished_object(object),
                "fresh failed development-run object must rollback exactly");
            return Err(DevelopmentRunError::Placement(err));
        }
    };

    let mem_size = u64::try_from(fabric.mem_size())
        .map_err(|_| DevelopmentRunError::PhysicalPoolOutsideFabric)?;
    if extent.end().map(|end| end <= mem_size) != Some(true) {
        rollback_active_transient(fabric, placement, object);
        return Err(DevelopmentRunError::PhysicalPoolOutsideFabric);
    }
    Ok(object)
}

fn rollback_active_transient(
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    object: ObjectId,
) {
    assert!(fabric.rollback_unpublished_object(object),
        "transient Active development object must remain unpublished during rollback");
    placement.release_unplaced(fabric, object)
        .expect("rolled-back transient object must release PM reservation");
}

fn teardown_sealed_transient(
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    object: ObjectId,
) {
    fabric.destroy_object(object);
    placement.release_unplaced(fabric, object)
        .expect("destroyed transient object must release PM reservation");
}

fn scrub_kernel_dynamic_region(kernel: &mut Kernel, base: u64) {
    if kernel.next_phys > base {
        kernel.fabric.zero_physical(base, kernel.next_phys - base);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anka64::dev_shell::{
        DevelopmentArtifactLoader, DevelopmentMode, DeveloperIngressAuthority,
    };
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_bytecode(tag: &str, exit_code: u64) -> std::path::PathBuf {
        let mut asm = crate::anka64::isa::Asm64::new();
        asm.movi(crate::anka64::isa::R1, exit_code as i32);
        asm.movi(crate::anka64::isa::R0, SYS_EXIT as i32);
        asm.trap(0);
        let bytes = asm.to_bytes();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "anka64-p93h3-{tag}-{}-{nonce}.anka", std::process::id()));
        fs::write(&path, bytes).unwrap();
        path
    }

    fn imported_exit_artifact(exit_code: u64) -> (
        DevelopmentArtifactLoader,
        Fabric,
        PhysicalPlacementManager,
        std::path::PathBuf,
    ) {
        let path = temp_bytecode("exit", exit_code);
        let ingress = DeveloperIngressAuthority::provision();
        let mut fabric = Fabric::new(0x400000);
        let mut placement = PhysicalPlacementManager::new(0x10000, 0x80000).unwrap();
        let mut loader = DevelopmentArtifactLoader::new(DevelopmentMode::Development);
        loader.import_bytecode_file(
            Some(&ingress), &mut fabric, &mut placement, "hello", &path,
        ).unwrap();
        (loader, fabric, placement, path)
    }

    #[test]
    fn p93h3_ingress_authority_is_not_execution_authority() {
        let (loader, mut fabric, mut placement, path) = imported_exit_artifact(42);
        let objects_before = fabric.objects.len();
        let allocations_before = placement.allocated_count();
        let domains_before = fabric.domains.len();

        assert_eq!(
            run_registered_artifact(
                loader.registry(), None, &mut fabric, &mut placement, "hello",
            ),
            Err(DevelopmentRunError::DeveloperExecutionAuthorityRequired),
        );
        assert_eq!(fabric.objects.len(), objects_before);
        assert_eq!(placement.allocated_count(), allocations_before);
        assert_eq!(fabric.domains.len(), domains_before);
        fs::remove_file(path).unwrap();
    }


    #[test]
    fn p93h3_authority_presentation_prepares_exact_rx_without_executing() {
        let (loader, mut fabric, mut placement, path) = imported_exit_artifact(42);
        let execution = DeveloperExecutionAuthority::provision();
        let artifact = loader.registry().get("hello").unwrap().clone();
        let allocations_before = placement.allocated_count();

        let prepared = prepare_run(
            loader.registry(),
            &execution,
            &mut fabric,
            &mut placement,
            "hello",
            DevelopmentRunConfig::default(),
        ).unwrap();

        assert!(fabric.domains.is_empty(),
            "authority presentation plan must not itself create a runnable domain");
        assert_eq!(prepared.artifact.key, artifact.key);
        assert!(prepared.boot_info.grants.iter().any(|g|
            g.obj == artifact.key.object
                && g.offset == 0
                && g.size == artifact.code_size
                && g.perms == Permissions::RX
        ));
        assert!(!prepared.boot_info.grants.iter().any(|g|
            g.obj == artifact.key.object && g.perms.contains(Permissions::WRITE)
        ));
        assert_eq!(placement.allocated_count(), allocations_before + 2,
            "preparation allocates only transient supervisor/control PM objects");

        teardown_sealed_transient(&mut fabric, &mut placement, prepared.control_obj);
        teardown_sealed_transient(&mut fabric, &mut placement, prepared.supervisor_obj);
        assert_eq!(placement.allocated_count(), allocations_before);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn p93h3_registered_bytecode_runs_through_vlb_and_sys_spawn() {
        let (loader, mut fabric, mut placement, path) = imported_exit_artifact(42);
        let execution = DeveloperExecutionAuthority::provision();
        let artifact_key = loader.registry().get("hello").unwrap().key;
        let artifact_extent = placement.allocated_extent(artifact_key.object).unwrap();
        let allocations_before = placement.allocated_count();

        let report = run_registered_artifact(
            loader.registry(), Some(&execution), &mut fabric, &mut placement, "hello",
        ).unwrap();

        assert_eq!(report.artifact, artifact_key);
        assert_eq!(report.child_result, ProcessResult::Exited(42));
        assert_eq!(report.presented_code_permissions, Permissions::RX);
        assert_eq!(report.presented_literal_permissions, None);
        assert!(report.process_slots_observed >= 2,
            "ordinary SYS_SPAWN must create a child process slot");
        assert_eq!(report.child_layout.code_vaddr, 0);
        assert!(report.child_layout.stack_vaddr >= PLACEMENT_PAGE_SIZE);
        assert!(fabric.domains.is_empty(),
            "transient supervisor authority must be removed after run");
        assert_eq!(placement.allocated_count(), allocations_before,
            "transient supervisor/control PM extents must be released");
        assert_eq!(placement.allocated_extent(artifact_key.object), Some(artifact_extent));
        assert_eq!(
            loader.registry().resolve_current(&fabric, "hello").unwrap().key,
            artifact_key,
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn p93h3_logical_path_selector_uses_same_exact_artifact() {
        // Raw bytecode has no logical path, so this witness first proves name
        // lookup is not silently treated as an absolute logical path.
        let (loader, mut fabric, mut placement, path) = imported_exit_artifact(7);
        let execution = DeveloperExecutionAuthority::provision();
        assert_eq!(
            run_registered_artifact(
                loader.registry(), Some(&execution), &mut fabric, &mut placement, "/bin/hello",
            ),
            Err(DevelopmentRunError::Artifact(DevelopmentShellError::ArtifactNotFound)),
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn p93h3_stale_artifact_is_rejected_before_authority_presentation() {
        let (loader, mut fabric, mut placement, path) = imported_exit_artifact(42);
        let execution = DeveloperExecutionAuthority::provision();
        let key = loader.registry().get("hello").unwrap().key;
        fabric.revoke(key.object);
        let allocations_before = placement.allocated_count();
        let objects_before = fabric.objects.len();

        assert_eq!(
            run_registered_artifact(
                loader.registry(), Some(&execution), &mut fabric, &mut placement, "hello",
            ),
            Err(DevelopmentRunError::Artifact(
                DevelopmentShellError::StaleArtifactGeneration,
            )),
        );
        assert_eq!(placement.allocated_count(), allocations_before);
        assert_eq!(fabric.objects.len(), objects_before);
        assert!(fabric.domains.is_empty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn p93h3_pm_fabric_disagreement_blocks_run_before_spawn() {
        let (loader, mut fabric, mut placement, path) = imported_exit_artifact(42);
        let execution = DeveloperExecutionAuthority::provision();
        let key = loader.registry().get("hello").unwrap().key;
        let old_extent = placement.allocated_extent(key.object).unwrap();
        let moved = old_extent.end().unwrap() + PLACEMENT_PAGE_SIZE;
        assert!(fabric.move_object(key.object, moved));

        assert_eq!(
            run_registered_artifact(
                loader.registry(), Some(&execution), &mut fabric, &mut placement, "hello",
            ),
            Err(DevelopmentRunError::ArtifactPlacementMismatch),
        );
        assert!(fabric.domains.is_empty());
        assert_eq!(placement.allocated_extent(key.object), Some(old_extent));
        fs::remove_file(path).unwrap();
    }
}
