//! Development-only CC_B compilation bridge (Phase 9.3h.2).
//!
//! This module deliberately gives `compile` different semantics from `run`.
//! A developer-authorized C source is compiled by the real self-hosted CC_B
//! inside a transient Anka64 machine supervised by ankad.  The compiler seals
//! its output, but in compile-only mode it does not SYS_EXEC that output.
//!
//! The returned bytes are a host-side development artifact representation of
//! that sealed output.  Importing them into the development registry is a
//! separate step and still creates no execution authority.

use super::ankad::{build_ankad_code, SUPERVISOR_COMPILER_VADDR};
use super::fabric::Fabric;
use super::cc;
use super::guest_compiler::{
    build_6b4_compiler, canonical_compiler_source, CCB_MODE_COMPILE_ONLY,
    LAYOUT_OUT, LAYOUT_SRC, LAYOUT_WS, OUTPUT_SIZE, SOURCE_SIZE,
    WS_FUNC_COUNT, WS_LIT_POS, WS_MODE, WS_OUT_POS, WS_SIZE,
};
use super::os::{BootError, BootGrant, BootImage, BootInfo, BootMap, Kernel};
use super::placement::{PhysicalPlacementManager, PlacementError};
use super::state::{ObjectId, ObjectKind, ObjectState, Permissions};
use super::isa::R10;

/// CC_B's relocatable code base inside the compiler child.
///
/// The compiler uses PC-relative calls/branches while its data ABI remains at
/// the canonical source/workspace/output virtual addresses.
pub const DEVELOPMENT_CCB_CODE_VADDR: u64 = 0x30000;

const DEVELOPMENT_COMPILER_RAM: usize = 0x1000000;
const DEVELOPMENT_PM_BASE: u64 = 0x10000;
const DEVELOPMENT_PM_SIZE: u64 = 0x700000;
const DEVELOPMENT_KERNEL_PHYS_BASE: u64 = 0x800000;
const ANKAD_OBJECT_SIZE: u64 = 0x2000;
const ANKAD_STACK_VADDR: u64 = 0x50000;
const ANKAD_STACK_SIZE: u64 = 0x4000;
const ANKAD_TRAP_VADDR: u64 = 0x54000;
const COMPILER_QUANTUM: usize = 5_000_000;
const COMPILER_MAX_ROUNDS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledCImage {
    /// Complete backing bytes required to reconstruct the executable image.
    /// With no literals this is exactly `code_size`.  With literals it keeps
    /// the fixed CC_B output arena so the literal segment remains at the same
    /// offset recorded by `lit_start`.
    pub bytes: Vec<u8>,
    pub code_size: u64,
    /// Zero means no literal segment.  Otherwise literals occupy
    /// `[lit_start, bytes.len())` and are read-only at execution time.
    pub lit_start: u64,
    pub function_count: u64,
    /// Closure witness for compile-only semantics.  CC_B itself is the only
    /// child ankad should create during a compile command.
    pub process_slots_observed: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DevelopmentCompileError {
    EmptyCompilerImage,
    CompilerImageTooLarge,
    SourceTooLarge,
    Placement(PlacementError),
    InitializationRejected,
    Boot(BootError),
    SupervisorDidNotExit,
    CompilerFault(u64),
    CompilerRejected(u64),
    OutputNotSealed,
    InvalidOutputGeometry,
    CompileCommandExecutedOutput,
    BootstrappedCompilerHasLiterals,
}

/// Compile one C translation unit through the real self-hosted CC_B.
///
/// This is intentionally a one-shot development bridge.  It uses ankad and
/// ordinary SYS_SPAWN/SYS_WAIT to construct the compiler process.  CC_B is
/// placed in compile-only mode through the workspace control word, so the
/// produced output is sealed but not executed.
pub fn compile_c_with_ccb(
    ccb_image: &[u8],
    source: &[u8],
) -> Result<CompiledCImage, DevelopmentCompileError> {
    compile_c_with_compiler_image(ccb_image, DEVELOPMENT_CCB_CODE_VADDR, source)
}

/// Compile one AC2 stage-1 translation unit through a CC_B-built AnkaCC2 image.
///
/// Phase 10.1 deliberately reuses the already-audited compiler process ABI:
/// source/workspace/output mappings are identical to CC_B, while the compiler
/// image itself is an ordinary sealed Anka executable produced by CC_B.  This
/// bridge does not grant execution authority to the produced program; the
/// compiler is forced into compile-only mode exactly like `compile_c_with_ccb`.
pub fn compile_c_with_ankacc2_stage1(
    compiler_image: &[u8],
    source: &[u8],
) -> Result<CompiledCImage, DevelopmentCompileError> {
    compile_c_with_compiler_image(
        compiler_image,
        DEVELOPMENT_CCB_CODE_VADDR,
        source,
    )
}

/// Bootstrap the self-hosted CC_B image from the Rust AST seed (CC_A).
///
/// This is development tooling, not a host C compiler shortcut: CC_A itself
/// runs as an ordinary Anka process under ankad and compiles the canonical C
/// source in compile-only mode.  The resulting sealed bytes are cached by the
/// interactive development shell and used for subsequent user-source builds.
pub fn bootstrap_development_ccb() -> Result<Vec<u8>, DevelopmentCompileError> {
    let compiler_prog = build_6b4_compiler();
    let cca_image = cc::compile(&compiler_prog).to_bytes();
    let canonical_source = canonical_compiler_source();
    let ccb = compile_c_with_compiler_image(&cca_image, 0, canonical_source.as_bytes())?;
    if ccb.lit_start != 0 {
        // The compiler image itself is intentionally code-only today.  If the
        // canonical compiler gains literals, its child-image grant/mapping
        // contract must be extended before silently treating them as RX code.
        return Err(DevelopmentCompileError::BootstrappedCompilerHasLiterals);
    }
    Ok(ccb.bytes)
}

fn compile_c_with_compiler_image(
    compiler_image: &[u8],
    compiler_code_vaddr: u64,
    source: &[u8],
) -> Result<CompiledCImage, DevelopmentCompileError> {
    if compiler_image.is_empty() {
        return Err(DevelopmentCompileError::EmptyCompilerImage);
    }
    if compiler_image.len() > 0x1FFFF {
        return Err(DevelopmentCompileError::CompilerImageTooLarge);
    }
    if source.len().saturating_add(8) > SOURCE_SIZE as usize {
        return Err(DevelopmentCompileError::SourceTooLarge);
    }

    let mut fabric = Fabric::new(DEVELOPMENT_COMPILER_RAM);
    let mut placement = PhysicalPlacementManager::new(
        DEVELOPMENT_PM_BASE,
        DEVELOPMENT_PM_SIZE,
    ).expect("fixed development compiler PM pool must be valid");

    let ankad_obj = allocate_placed(
        &mut fabric, &mut placement, "dev-ankad", ANKAD_OBJECT_SIZE,
    )?;
    let compiler_obj = allocate_placed(
        &mut fabric, &mut placement, "dev-compiler", compiler_image.len() as u64,
    )?;
    let source_obj = allocate_placed(
        &mut fabric, &mut placement, "dev-c-source", SOURCE_SIZE as u64,
    )?;
    let output_obj = allocate_placed(
        &mut fabric, &mut placement, "dev-c-output", OUTPUT_SIZE as u64,
    )?;
    let workspace_obj = allocate_placed(
        &mut fabric, &mut placement, "dev-c-workspace", WS_SIZE as u64,
    )?;

    for object in [ankad_obj, compiler_obj, source_obj, output_obj, workspace_obj] {
        if !fabric.zero_object_extent(object) {
            return Err(DevelopmentCompileError::InitializationRejected);
        }
    }

    if !fabric.initialize_object(compiler_obj, 0, compiler_image)
        || !fabric.seal_object(compiler_obj)
    {
        return Err(DevelopmentCompileError::InitializationRejected);
    }

    let source_len = source.len() as u64;
    if !fabric.initialize_object(source_obj, 0, &source_len.to_le_bytes())
        || !fabric.initialize_object(source_obj, 8, source)
    {
        return Err(DevelopmentCompileError::InitializationRejected);
    }

    // The Rust AST seed compiler (CC_A) historically relies on the harness to
    // initialize the downward-growing literal frontier.  Canonical CC_B also
    // initializes it itself, so doing this here is redundant for CC_B but
    // required for bootstrap symmetry with the long-standing supervised
    // compiler harness.
    let lit_pos_offset = (WS_LIT_POS - LAYOUT_WS) as u64;
    if !fabric.initialize_object(
        workspace_obj,
        lit_pos_offset,
        &(OUTPUT_SIZE as u64).to_le_bytes(),
    ) {
        return Err(DevelopmentCompileError::InitializationRejected);
    }

    // `compile` must not imply `run`.  Both the Rust AST seed compiler (CC_A)
    // and canonical self-hosted CC_B honor this workspace mode word.
    let mode_offset = (WS_MODE - LAYOUT_WS) as u64;
    if !fabric.initialize_object(
        workspace_obj,
        mode_offset,
        &CCB_MODE_COMPILE_ONLY.to_le_bytes(),
    ) {
        return Err(DevelopmentCompileError::InitializationRejected);
    }

    let ankad_code = build_ankad_code(compiler_image.len(), compiler_code_vaddr);
    if ankad_code.len() as u64 > ANKAD_OBJECT_SIZE
        || !fabric.initialize_object(ankad_obj, 0, &ankad_code)
        || !fabric.seal_object(ankad_obj)
    {
        return Err(DevelopmentCompileError::InitializationRejected);
    }

    let info = BootInfo {
        image: BootImage {
            obj: ankad_obj,
            code_offset: 0,
            code_size: ANKAD_OBJECT_SIZE,
            entry: 0,
            lit_start: 0,
        },
        grants: vec![
            BootGrant {
                obj: compiler_obj,
                offset: 0,
                size: compiler_image.len() as u64,
                perms: Permissions::RX,
            },
            BootGrant {
                obj: source_obj,
                offset: 0,
                size: SOURCE_SIZE as u64,
                perms: Permissions::READ,
            },
            BootGrant {
                obj: output_obj,
                offset: 0,
                size: OUTPUT_SIZE as u64,
                perms: Permissions::RWS,
            },
            BootGrant {
                obj: workspace_obj,
                offset: 0,
                size: WS_SIZE as u64,
                perms: Permissions::RW,
            },
        ],
        maps: vec![
            BootMap {
                vaddr: LAYOUT_SRC as u64,
                size: SOURCE_SIZE as u64,
                obj: source_obj,
                obj_offset: 0,
            },
            BootMap {
                vaddr: LAYOUT_WS as u64,
                size: WS_SIZE as u64,
                obj: workspace_obj,
                obj_offset: 0,
            },
            BootMap {
                vaddr: LAYOUT_OUT as u64,
                size: OUTPUT_SIZE as u64,
                obj: output_obj,
                obj_offset: 0,
            },
            BootMap {
                vaddr: SUPERVISOR_COMPILER_VADDR,
                size: compiler_image.len() as u64,
                obj: compiler_obj,
                obj_offset: 0,
            },
        ],
        code_vaddr: 0,
        stack_vaddr: ANKAD_STACK_VADDR,
        stack_size: ANKAD_STACK_SIZE,
        trap_vaddr: ANKAD_TRAP_VADDR,
    };

    let output_phys = placement
        .allocated_extent(output_obj)
        .expect("placed output must remain owned by PM")
        .base;
    let workspace_phys = placement
        .allocated_extent(workspace_obj)
        .expect("placed workspace must remain owned by PM")
        .base;

    let mut kernel = Kernel::new(fabric);
    kernel.next_phys = DEVELOPMENT_KERNEL_PHYS_BASE;
    kernel.boot(&info).map_err(DevelopmentCompileError::Boot)?;
    kernel.run(COMPILER_QUANTUM, COMPILER_MAX_ROUNDS);

    let init = kernel.processes.get(0)
        .ok_or(DevelopmentCompileError::SupervisorDidNotExit)?;
    if !init.exited() {
        return Err(DevelopmentCompileError::SupervisorDidNotExit);
    }

    let wait_tag = init.core.r[R10 as usize];
    if wait_tag != 0 {
        return Err(DevelopmentCompileError::CompilerFault(wait_tag));
    }

    let read_ws = |offset: u64| -> u64 {
        let bytes = kernel.fabric.read_physical(workspace_phys + offset, 8);
        u64::from_le_bytes(bytes.try_into().expect("workspace u64 read"))
    };

    let ws_error = read_ws(0x18);
    if ws_error != 0 {
        return Err(DevelopmentCompileError::CompilerRejected(ws_error));
    }
    if init.exit_code != 0 {
        return Err(DevelopmentCompileError::CompilerRejected(init.exit_code));
    }

    let output_object = kernel.fabric.objects.get(&output_obj)
        .ok_or(DevelopmentCompileError::OutputNotSealed)?;
    if output_object.state != ObjectState::Sealed {
        return Err(DevelopmentCompileError::OutputNotSealed);
    }

    let out_pos = read_ws((WS_OUT_POS - LAYOUT_WS) as u64);
    let function_count = read_ws((WS_FUNC_COUNT - LAYOUT_WS) as u64);
    let raw_lit_pos = read_ws((WS_LIT_POS - LAYOUT_WS) as u64);
    let output_limit = OUTPUT_SIZE as u64;

    if out_pos == 0 || out_pos > output_limit || raw_lit_pos > output_limit {
        return Err(DevelopmentCompileError::InvalidOutputGeometry);
    }

    let lit_start = if raw_lit_pos == output_limit {
        0
    } else {
        if raw_lit_pos < out_pos {
            return Err(DevelopmentCompileError::InvalidOutputGeometry);
        }
        raw_lit_pos
    };
    let image_size = if lit_start == 0 { out_pos } else { output_limit };
    let bytes = kernel.fabric.read_physical(output_phys, image_size).to_vec();

    // With compile-only mode ankad spawns exactly CC_B.  A third slot would be
    // evidence that the produced program was executed during `compile`.
    let process_slots_observed = kernel.processes.len();
    if process_slots_observed > 2 {
        return Err(DevelopmentCompileError::CompileCommandExecutedOutput);
    }

    Ok(CompiledCImage {
        bytes,
        code_size: out_pos,
        lit_start,
        function_count,
        process_slots_observed,
    })
}

fn allocate_placed(
    fabric: &mut Fabric,
    placement: &mut PhysicalPlacementManager,
    label: &str,
    size: u64,
) -> Result<ObjectId, DevelopmentCompileError> {
    let object = fabric.alloc_object(label, size, ObjectKind::Memory);
    placement
        .allocate_and_place_object(fabric, object)
        .map_err(DevelopmentCompileError::Placement)?;
    Ok(object)
}
