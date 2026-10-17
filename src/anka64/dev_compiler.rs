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

use super::ankad::{build_ankad_code_with_source};
use super::fabric::Fabric;
use super::cc;
use super::guest_compiler::{
    build_6b4_compiler, canonical_compiler_source, CCB_MODE_COMPILE_ONLY,
    LAYOUT_OUT, LAYOUT_SRC, LAYOUT_WS, OUTPUT_SIZE, SOURCE_SIZE, STACK_SIZE,
    WS_FUNC_COUNT, WS_LIT_POS, WS_MODE, WS_OUT_POS, WS_OUTPUT_LIMIT, WS_SIZE,
};
use super::guest_compiler::extended_compiler_source;
use super::os::{BootError, BootGrant, BootImage, BootInfo, BootMap, Kernel};
use super::placement::{PhysicalPlacementManager, PlacementError, VirtualLayoutBuilder, PLACEMENT_PAGE_SIZE};
use super::state::{ObjectId, ObjectKind, ObjectState, Permissions};
use super::isa::R10;

const DEVELOPMENT_COMPILER_RAM: usize = 0x1000000;
const DEVELOPMENT_PM_BASE: u64 = 0x10000;
const DEVELOPMENT_PM_SIZE: u64 = 0x700000;
const DEVELOPMENT_KERNEL_PHYS_BASE: u64 = 0x800000;
const ANKAD_OBJECT_SIZE: u64 = 0x2000;
const ANKAD_STACK_SIZE: u64 = 0x4000;
const CHILD_TRAP_SIZE: u64 = PLACEMENT_PAGE_SIZE;
const COMPILER_VIRTUAL_LIMIT: u64 = 0x1000000;
/// Bounded capacity policy for the extended bootstrap, independent of code
/// placement. Both processes reserve their suffixes from the actual sizes.
pub(crate) const DEVELOPMENT_COMPILER_OUTPUT_SIZE: u64 = 0x40000;
pub(crate) const DEVELOPMENT_COMPILER_SOURCE_SIZE:u64=0x10000;
const _: () = assert!(DEVELOPMENT_COMPILER_OUTPUT_SIZE >= OUTPUT_SIZE as u64);
const _: () = assert!(DEVELOPMENT_COMPILER_OUTPUT_SIZE % PLACEMENT_PAGE_SIZE == 0);
// Stage-3 bootstrap language-profile control word, checked by q47/q50.
// It changes parsing admission only; Fabric still authorizes every word access.
const WS_AC2_BOOTSTRAP_WORD_DEREF: u64 = 68480;
const COMPILER_QUANTUM: usize = 100_000;
const COMPILER_MAX_ROUNDS: usize = 10_000;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledAomModule {
    /// Exact sealed AOM bytes produced by AnkaCC2 stage 3.
    pub bytes: Vec<u8>,
    /// Compile-only closure witness: only the compiler child may run.
    pub process_slots_observed: usize,
}
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
    AdapterStateChanged,
    AdapterReadDenied,
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
    compile_c_with_compiler_image(
        ccb_image,
        false,
        source,
        OUTPUT_SIZE as u64,
    )
}

/// Compile through the Phase-10 bootstrap CC_B with a bounded larger arena
/// and size-driven virtual placement.  This is intentionally separate
/// from `compile_c_with_ccb`: the ordinary development shell retains the
/// historical 80 KiB CC_B artifact geometry.
pub fn compile_c_with_extended_ccb(
    ccb_image: &[u8],
    source: &[u8],
) -> Result<CompiledCImage, DevelopmentCompileError> {
    compile_c_with_compiler_image(
        ccb_image,
        false,
        source,
        DEVELOPMENT_COMPILER_OUTPUT_SIZE,
    )
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
        false,
        source,
        OUTPUT_SIZE as u64,
    )
}

/// Compile one AC2 stage-2 translation unit through the CC_B-built AnkaCC2
/// declarations/types/ABI compiler.
///
/// Phase 10.2 deliberately preserves the same supervised compiler ABI and
/// compile-only admission used by CC_B and stage 1.  The richer type system
/// therefore changes source semantics, not artifact or execution authority.
pub fn compile_c_with_ankacc2_stage2(
    compiler_image: &[u8],
    source: &[u8],
) -> Result<CompiledCImage, DevelopmentCompileError> {
    compile_c_with_compiler_image(
        compiler_image,
        false,
        source,
        OUTPUT_SIZE as u64,
    )
}


/// Compile one AC2 translation unit through the Phase 10.3 AOM-emitting
/// AnkaCC2 compiler.
///
/// The supervised process path is intentionally identical to the earlier
/// compiler stages.  The output object is sealed in compile-only mode, but its
/// bytes are an AOM module, not an executable image.  Successful object
/// emission therefore grants no execution authority.
pub fn compile_c_to_aom_stage3(
    compiler_image: &[u8],
    source: &[u8],
) -> Result<CompiledAomModule, DevelopmentCompileError> {
    let raw = compile_c_with_compiler_image(
        compiler_image,
        false,
        source,
        DEVELOPMENT_COMPILER_OUTPUT_SIZE,
    )?;
    Ok(CompiledAomModule {
        bytes: raw.bytes,
        process_slots_observed: raw.process_slots_observed,
    })
}

/// Compile the exact compiler-source translation unit using the already-earned
/// Phase-10.6 bootstrap word-address profile. Only the lineage harness calls
/// this entry point; ordinary AOM compilation keeps the profile disabled.
pub(crate) fn compile_bootstrap_aom_stage3(
    compiler_image: &[u8], source: &[u8],
    _authority: &super::dev_runner::DeveloperExecutionAuthority,
) -> Result<CompiledAomModule, DevelopmentCompileError> {
    let raw = compile_c_with_geometry(compiler_image, false, source,
        DEVELOPMENT_COMPILER_OUTPUT_SIZE, None, 1)?;
    Ok(CompiledAomModule { bytes: raw.bytes,
        process_slots_observed: raw.process_slots_observed })
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
    let ccb = compile_c_with_compiler_image(
        &cca_image,
        true,
        canonical_source.as_bytes(),
        OUTPUT_SIZE as u64,
    )?;
    if ccb.lit_start != 0 {
        // The compiler image itself is intentionally code-only today.  If the
        // canonical compiler gains literals, its child-image grant/mapping
        // contract must be extended before silently treating them as RX code.
        return Err(DevelopmentCompileError::BootstrappedCompilerHasLiterals);
    }
    Ok(ccb.bytes)
}

/// Bootstrap the output-limit-aware CC_B used only to build Phase 10.3's
/// larger AnkaCC2 compiler image.  The ordinary development-shell CC_B above
/// remains the exact Phase 9.3h fixed point and keeps its 80 KiB ABI.
pub fn bootstrap_extended_ccb() -> Result<Vec<u8>, DevelopmentCompileError> {
    let compiler_prog = build_6b4_compiler();
    let cca_image = cc::compile(&compiler_prog).to_bytes();
    let source = extended_compiler_source();
    let ccb = compile_c_with_compiler_image(
        &cca_image,
        true,
        source.as_bytes(),
        DEVELOPMENT_COMPILER_OUTPUT_SIZE,
    )?;
    if ccb.lit_start != 0 {
        return Err(DevelopmentCompileError::BootstrappedCompilerHasLiterals);
    }
    Ok(ccb.bytes)
}

/// Execute exact linked compiler bytes at the linker-selected entry. A separate control launcher
/// CALLs the linker-selected entry with RX(code)/R(literals) authority. The
/// linked artifact itself is never prefixed, patched, or otherwise mutated.
pub(crate) fn compile_bootstrap_aom_with_linked_compiler(
    image: &super::ankald::AnkaldLinkedImage,
    source: &[u8],
    _authority: &super::dev_runner::DeveloperExecutionAuthority,
) -> Result<CompiledAomModule, DevelopmentCompileError> {
    compile_linked_aom(image, source, 1)
}

/// Ordinary applications never receive the compiler's raw word-address exception.
pub(crate) fn compile_application_aom_with_linked_compiler(
    image: &super::ankald::AnkaldLinkedImage,
    source: &[u8],
    _authority: &super::dev_runner::DeveloperExecutionAuthority,
) -> Result<CompiledAomModule, DevelopmentCompileError> {
    compile_linked_aom(image, source, 0)
}

pub(crate) fn compile_protected_application_aom_with_linked_compiler(
    image:&super::ankald::AnkaldLinkedImage,source:&[u8],
    _authority:&super::dev_runner::DeveloperExecutionAuthority) -> Result<CompiledAomModule,DevelopmentCompileError> {
    compile_linked_aom(image,source,2)
}

fn compile_linked_aom(
    image: &super::ankald::AnkaldLinkedImage, source: &[u8], profile: u64,
) -> Result<CompiledAomModule, DevelopmentCompileError> {
    if image.code_size == 0 || image.code_size > image.bytes.len() as u64
        || image.entry >= image.code_size || image.entry % 8 != 0
        || (image.lit_start != 0 && (image.lit_start < image.code_size
            || image.lit_start >= image.bytes.len() as u64))
    {
        return Err(DevelopmentCompileError::InvalidOutputGeometry);
    }
    let raw = compile_c_with_geometry(&image.bytes, false, source,
        DEVELOPMENT_COMPILER_OUTPUT_SIZE, Some(image), profile)?;
    Ok(CompiledAomModule { bytes: raw.bytes,
        process_slots_observed: raw.process_slots_observed })
}

fn compile_c_with_compiler_image(
    compiler_image: &[u8],
    seed_at_zero: bool,
    source: &[u8],
    output_limit: u64,
) -> Result<CompiledCImage, DevelopmentCompileError> {
    compile_c_with_geometry(compiler_image, seed_at_zero, source, output_limit, None, 0)
}

fn compile_c_with_geometry(
    compiler_image: &[u8],
    seed_at_zero: bool,
    source: &[u8],
    output_limit: u64,
    linked: Option<&super::ankald::AnkaldLinkedImage>,
    compiler_profile: u64,
) -> Result<CompiledCImage, DevelopmentCompileError> {
    run_compiler(compiler_image, seed_at_zero, source, output_limit, linked,
        compiler_profile, false).map(|run| run.image)
}

struct CompilerRun {
    image: CompiledCImage,
    adapter: Option<super::compiler_adapter::CompilerOutput>,
}

pub(crate) fn compile_for_adapter(image: &super::ankald::AnkaldLinkedImage,
    source: &[u8]) -> Result<super::compiler_adapter::CompilerOutput, DevelopmentCompileError> {
    if image.code_size == 0 || image.code_size > image.bytes.len() as u64
        || image.entry >= image.code_size || image.entry % 8 != 0
        || (image.lit_start == 0 && image.code_size != image.bytes.len() as u64)
        || (image.lit_start != 0 && (image.lit_start < image.code_size
            || image.lit_start >= image.bytes.len() as u64)) {
        return Err(DevelopmentCompileError::InvalidOutputGeometry);
    }
    run_compiler(&image.bytes, false, source, DEVELOPMENT_COMPILER_OUTPUT_SIZE,
        Some(image), 2, true)?.adapter.ok_or(DevelopmentCompileError::AdapterStateChanged)
}

fn run_compiler(compiler_image: &[u8], seed_at_zero: bool, source: &[u8],
    output_limit: u64, linked: Option<&super::ankald::AnkaldLinkedImage>,
    compiler_profile: u64, strict_adapter: bool) -> Result<CompilerRun, DevelopmentCompileError> {
    if compiler_image.is_empty() {
        return Err(DevelopmentCompileError::EmptyCompilerImage);
    }
    if compiler_image.len() > DEVELOPMENT_COMPILER_OUTPUT_SIZE as usize {
        return Err(DevelopmentCompileError::CompilerImageTooLarge);
    }
    if source.len().saturating_add(8) > DEVELOPMENT_COMPILER_SOURCE_SIZE as usize || (seed_at_zero && source.len().saturating_add(8) > SOURCE_SIZE as usize) {
        return Err(DevelopmentCompileError::SourceTooLarge);
    }
    if output_limit < OUTPUT_SIZE as u64
        || output_limit & (PLACEMENT_PAGE_SIZE - 1) != 0
    {
        return Err(DevelopmentCompileError::InvalidOutputGeometry);
    }

    let source_size=if source.len()+8>SOURCE_SIZE as usize {
        ((source.len() as u64+8+PLACEMENT_PAGE_SIZE-1)/PLACEMENT_PAGE_SIZE)*PLACEMENT_PAGE_SIZE
    } else { SOURCE_SIZE as u64 };
    let layout = compiler_virtual_layout_with_source(compiler_image.len(), seed_at_zero, output_limit,source_size)?;

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
        &mut fabric, &mut placement, "dev-c-source", source_size,
    )?;
    let output_obj = allocate_placed(
        &mut fabric,
        &mut placement,
        "dev-c-output",
        output_limit,
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
    let compiler_generation = fabric.objects[&compiler_obj].generation;
    let workspace_generation = fabric.objects[&workspace_obj].generation;

    let source_len = source.len() as u64;
    if !fabric.initialize_object(source_obj, 0, &source_len.to_le_bytes())
        || !fabric.initialize_object(source_obj, 8, source)
    {
        return Err(DevelopmentCompileError::InitializationRejected);
    }

    if strict_adapter && !fabric.seal_object(source_obj) {
        return Err(DevelopmentCompileError::InitializationRejected);
    }
    let source_generation = fabric.objects[&source_obj].generation;
    let arena_before = fabric.objects[&output_obj].generation;
    if strict_adapter && arena_before.0.checked_add(1).is_none() {
        return Err(DevelopmentCompileError::AdapterStateChanged);
    }
    // Bind immutable configuration before launch. It is not mapped into the
    // compiler; mutable workspace controls are checked against this profile.
    let profile_key = if strict_adapter {
        let bytes = super::compiler_adapter::profile_bytes();
        let object = allocate_placed(&mut fabric, &mut placement, "rebuild-profile", bytes.len() as u64)?;
        if !fabric.zero_object_extent(object) || !fabric.initialize_object(object, 0, &bytes)
            || !fabric.seal_object(object) {
            return Err(DevelopmentCompileError::InitializationRejected);
        }
        Some(super::ankald::LinkedArtifactKey { object, generation: fabric.objects[&object].generation })
    } else { None };

    // The Rust AST seed compiler (CC_A) historically relies on the harness to
    // initialize the downward-growing literal frontier.  Canonical CC_B also
    // initializes it itself, so doing this here is redundant for CC_B but
    // required for bootstrap symmetry with the long-standing supervised
    // compiler harness.
    let lit_pos_offset = (WS_LIT_POS - LAYOUT_WS) as u64;
    if !fabric.initialize_object(
        workspace_obj,
        lit_pos_offset,
        &output_limit.to_le_bytes(),
    ) {
        return Err(DevelopmentCompileError::InitializationRejected);
    }

    // The compiler reads this per-invocation limit instead of baking the
    // development arena size into generated code.  Older direct harnesses may
    // leave the word zero and retain OUTPUT_SIZE compatibility.
    let output_limit_offset = (WS_OUTPUT_LIMIT - LAYOUT_WS) as u64;
    if !fabric.initialize_object(
        workspace_obj,
        output_limit_offset,
        &output_limit.to_le_bytes(),
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

    // Match the exact same language profile on CC2_0->CC2_1 and CC2_1->CC2_2.
    // Fresh workspace zeroing keeps the flag off on all ordinary compile paths.
    if !fabric.initialize_object(
        workspace_obj, WS_AC2_BOOTSTRAP_WORD_DEREF - LAYOUT_WS as u64,
        &compiler_profile.to_le_bytes(),
    ) {
        return Err(DevelopmentCompileError::InitializationRejected);
    }

    if strict_adapter || source_size>SOURCE_SIZE as u64 {
        for (at,value) in [(68488u64,layout.source_base),(68496,source_size-8)] {
            if !fabric.initialize_object(workspace_obj,at-LAYOUT_WS as u64,&value.to_le_bytes()) {
                return Err(DevelopmentCompileError::InitializationRejected);
            }
        }
    }
    let ankad_code = if let Some(image) = linked {
        // AOM main is an ordinary function: CALL must mint its return authority.
        // Keep the launcher in its own object, outside the compared artifacts.
        let mut launcher = super::isa::Asm64::new();
        let target = layout.child_code.checked_add(image.entry)
            .ok_or(DevelopmentCompileError::InvalidOutputGeometry)?;
        let word_offset = i32::try_from(target / 4)
            .map_err(|_| DevelopmentCompileError::InvalidOutputGeometry)?;
        if target % 8 != 0 || word_offset >= (1 << 19) {
            return Err(DevelopmentCompileError::InvalidOutputGeometry);
        }
        launcher.call(word_offset);
        launcher.mov(super::isa::R1, super::isa::R0);
        launcher.movi(super::isa::R0, super::os::SYS_EXIT as i32);
        launcher.trap(0);
        launcher.to_bytes()
    } else {
        build_ankad_code_with_source(
            compiler_image.len(), layout.parent_code, layout.child_code,
            output_limit, layout.child_stack, layout.child_trap, layout.source_base,source_size,
        )
    };
    if ankad_code.len() as u64 > ANKAD_OBJECT_SIZE
        || !fabric.initialize_object(ankad_obj, 0, &ankad_code)
        || !fabric.seal_object(ankad_obj)
    {
        return Err(DevelopmentCompileError::InitializationRejected);
    }

    let mut info = BootInfo {
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
                size: source_size,
                perms: Permissions::READ,
            },
            BootGrant {
                obj: output_obj,
                offset: 0,
                size: output_limit,
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
                vaddr: layout.source_base,
                size: source_size,
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
                size: output_limit,
                obj: output_obj,
                obj_offset: 0,
            },
            BootMap {
                vaddr: layout.parent_code,
                size: compiler_image.len() as u64,
                obj: compiler_obj,
                obj_offset: 0,
            },
        ],
        code_vaddr: 0,
        stack_vaddr: layout.parent_stack,
        stack_size: ANKAD_STACK_SIZE,
        trap_vaddr: layout.parent_trap,
    };

    if let Some(image) = linked {
        info.grants.retain(|grant| grant.obj != compiler_obj);
        info.grants.push(BootGrant { obj: compiler_obj, offset: 0,
            size: image.code_size, perms: Permissions::RX });
        if image.lit_start != 0 {
            info.grants.push(BootGrant { obj: compiler_obj, offset: image.lit_start,
                size: image.bytes.len() as u64 - image.lit_start, perms: Permissions::READ });
        }
        for map in &mut info.maps {
            if map.obj == compiler_obj { map.vaddr = layout.child_code; }
        }
        info.stack_vaddr = layout.child_stack;
        info.stack_size = STACK_SIZE as u64;
        info.trap_vaddr = layout.child_trap;
    }

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
    let owner = {
        let process = kernel.processes.first().ok_or(DevelopmentCompileError::SupervisorDidNotExit)?;
        (process.pid, process.generation, process.core.context_identity(), process.core.domain)
    };
    // Compiler machines have no devices or asynchronous transaction handles.
    // Bound retained diagnostic history without changing transaction execution.
    for _ in 0..COMPILER_MAX_ROUNDS {
        kernel.run(COMPILER_QUANTUM,1);
        if strict_adapter && !kernel.fabric.compiler_trace_safe(output_obj) {
            return Err(DevelopmentCompileError::CompileCommandExecutedOutput);
        }
        if kernel.processes.first().is_some_and(|p| p.exited()) {break;}
        assert!(kernel.fabric.discard_completed_compiler_trace());
    }

    let init = kernel.processes.get(0)
        .ok_or(DevelopmentCompileError::SupervisorDidNotExit)?;
    if !init.exited() {
        return Err(DevelopmentCompileError::SupervisorDidNotExit);
    }

    if linked.is_some() && !matches!(init.result, Some(super::os::ProcessResult::Exited(_))) {
        return Err(DevelopmentCompileError::CompilerFault(1));
    }
    let wait_tag = if linked.is_some() { 0 } else { init.core.r[R10 as usize] };
    if wait_tag != 0 {
        return Err(DevelopmentCompileError::CompilerFault(wait_tag));
    }

    let read_ws = |offset: u64| -> u64 {
        let bytes = kernel.fabric.read_physical(workspace_phys + offset, 8);
        u64::from_le_bytes(bytes.try_into().expect("workspace u64 read"))
    };

    let ws_error = read_ws(0x18);
    if ws_error != 0 {
        eprintln!("compiler source position={}",read_ws(0));
        let out_pos = read_ws((WS_OUT_POS - LAYOUT_WS) as u64);
        let lit_pos = read_ws((WS_LIT_POS - LAYOUT_WS) as u64);
        let function_count = read_ws((WS_FUNC_COUNT - LAYOUT_WS) as u64);
        eprintln!(
            "development compiler rejected source: error={} source_bytes={} out_pos={} lit_pos={} free_gap={} functions={} output_limit={}",
            ws_error,
            source.len(),
            out_pos,
            lit_pos,
            lit_pos.saturating_sub(out_pos),
            function_count,
            output_limit,
        );
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
    if strict_adapter {
        let source_object = kernel.fabric.objects.get(&source_obj)
            .ok_or(DevelopmentCompileError::AdapterStateChanged)?;
        let compiler_object = kernel.fabric.objects.get(&compiler_obj)
            .ok_or(DevelopmentCompileError::AdapterStateChanged)?;
        let workspace_object = kernel.fabric.objects.get(&workspace_obj)
            .ok_or(DevelopmentCompileError::AdapterStateChanged)?;
        if kernel.processes.len() != 1
            || owner != (init.pid, init.generation, init.core.context_identity(), init.core.domain)
            || !init.async_requests.is_empty() || init.io_wait.is_some()
            || compiler_object.state != ObjectState::Sealed || compiler_object.generation != compiler_generation
            || workspace_object.state != ObjectState::Active || workspace_object.generation != workspace_generation
            || source_object.state != ObjectState::Sealed || source_object.generation != source_generation
            || output_object.generation.0 != arena_before.0.checked_add(1).unwrap()
            || read_ws(0) != source_len || read_ws(8) != source_len
            || read_ws(16) != layout.source_base + 8
            || read_ws((WS_MODE-LAYOUT_WS) as u64) != CCB_MODE_COMPILE_ONLY
            || read_ws((WS_OUTPUT_LIMIT-LAYOUT_WS) as u64) != output_limit
            || read_ws(WS_AC2_BOOTSTRAP_WORD_DEREF-LAYOUT_WS as u64) != 2
            || read_ws(68488-LAYOUT_WS as u64) != layout.source_base
            || read_ws(68496-LAYOUT_WS as u64) != source_size-8
            || out_pos < super::aom::AOM_HEADER_SIZE || out_pos % 8 != 0
            || out_pos > raw_lit_pos || raw_lit_pos > output_limit {
            return Err(DevelopmentCompileError::AdapterStateChanged);
        }
    }
    if out_pos == 0 || out_pos > output_limit || raw_lit_pos > output_limit {
        return Err(DevelopmentCompileError::InvalidOutputGeometry);
    }

    // Protected AOM emission uses the downward frontier for private compiler
    // metadata scratch. Its complete serialized output is [0, out_pos),
    // including the manifest and symbol tables; scratch is not artifact bytes.
    let lit_start = if compiler_profile == 2 || raw_lit_pos == output_limit {
        0
    } else {
        if raw_lit_pos < out_pos {
            return Err(DevelopmentCompileError::InvalidOutputGeometry);
        }
        raw_lit_pos
    };
    let image_size = if lit_start == 0 { out_pos } else { output_limit };
    let mut adapter_output = None;
    let bytes = if strict_adapter {
        let arena_key = super::ankald::LinkedArtifactKey {
            object: output_obj, generation: output_object.generation,
        };
        let reader = kernel.fabric.create_domain();
        if kernel.fabric.grant(reader, output_obj, 0, out_pos, Permissions::READ).is_none() {
            return Err(DevelopmentCompileError::AdapterReadDenied);
        }
        let staged = super::compiler_adapter::copy_sealed_prefix(&mut kernel.fabric,
            reader, arena_key, out_pos)?;
        adapter_output = Some((arena_key, reader));
        staged
    } else {
        kernel.fabric.read_physical(output_phys, image_size).to_vec()
    };

    // With compile-only mode ankad spawns exactly CC_B.  A third slot would be
    // evidence that the produced program was executed during `compile`.
    let process_slots_observed = kernel.processes.len();
    if process_slots_observed > if linked.is_some() { 1 } else { 2 } {
        return Err(DevelopmentCompileError::CompileCommandExecutedOutput);
    }

    let adapter = adapter_output.map(|(arena_key, reader)| {
        let compiler_key = super::ankald::LinkedArtifactKey {
            object: compiler_obj, generation: compiler_generation,
        };
        super::compiler_adapter::CompilerOutput {
            bytes: bytes.clone(), fabric: kernel.fabric, placement, reader,
            compiler_key, arena_key, workspace_object: workspace_obj,
            source_key: super::ankald::LinkedArtifactKey { object: source_obj, generation: source_generation },
            profile_key: profile_key.expect("strict adapter binds profile before launch"),
            process_slot: 0, process_generation: u64::from(owner.1) + 1,
            context: owner.2, domain: owner.3, source_length: source_len,
        }
    });
    Ok(CompilerRun { image: CompiledCImage {
        bytes, code_size: out_pos, lit_start, function_count, process_slots_observed,
    }, adapter })
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

#[derive(Debug)]
struct CompilerVirtualLayout {
    source_base: u64,
    parent_code: u64,
    parent_stack: u64,
    parent_trap: u64,
    child_code: u64,
    child_stack: u64,
    child_trap: u64,
}

fn compiler_virtual_layout(
    compiler_len: usize, seed_at_zero: bool, output_size: u64,
) -> Result<CompilerVirtualLayout, DevelopmentCompileError> {
    compiler_virtual_layout_with_source(compiler_len,seed_at_zero,output_size,SOURCE_SIZE as u64)
}
fn compiler_virtual_layout_with_source(compiler_len:usize,seed_at_zero:bool,output_size:u64,source_size:u64)
    -> Result<CompilerVirtualLayout,DevelopmentCompileError> {
    let output_end = (LAYOUT_OUT as u64).checked_add(output_size)
        .ok_or(DevelopmentCompileError::InvalidOutputGeometry)?;
    // The occupied ABI prefix includes source, workspace, and the exact output
    // extent. Reserve every suffix through the existing virtual manager.
    let mut parent = VirtualLayoutBuilder::after_image(0, output_end, COMPILER_VIRTUAL_LIMIT)
        .map_err(DevelopmentCompileError::Placement)?;
    let source_base=if source_size>SOURCE_SIZE as u64 { parent.reserve(source_size)
        .map_err(DevelopmentCompileError::Placement)?.base } else { LAYOUT_SRC as u64 };
    let parent_code = parent.reserve(compiler_len as u64)
        .map_err(DevelopmentCompileError::Placement)?.base;
    let parent_stack = parent.reserve(ANKAD_STACK_SIZE)
        .map_err(DevelopmentCompileError::Placement)?.base;
    let parent_trap = parent.reserve(CHILD_TRAP_SIZE)
        .map_err(DevelopmentCompileError::Placement)?.base;
    let mut child = VirtualLayoutBuilder::after_image(0, output_end, COMPILER_VIRTUAL_LIMIT)
        .map_err(DevelopmentCompileError::Placement)?;
    if source_size>SOURCE_SIZE as u64 { child.reserve(source_size).map_err(DevelopmentCompileError::Placement)?; }
    // CC_A uses absolute code addresses and stays below the fixed source ABI.
    // CC_B/CC2 use relative control flow and can occupy an allocated suffix.
    let child_code = if seed_at_zero {
        if compiler_len as u64 > LAYOUT_SRC as u64 {
            return Err(DevelopmentCompileError::InvalidOutputGeometry);
        }
        0
    } else {
        child.reserve(compiler_len as u64)
            .map_err(DevelopmentCompileError::Placement)?.base
    };
    let child_stack = child.reserve(STACK_SIZE as u64)
        .map_err(DevelopmentCompileError::Placement)?.base;
    let child_trap = child.reserve(CHILD_TRAP_SIZE)
        .map_err(DevelopmentCompileError::Placement)?.base;
    Ok(CompilerVirtualLayout { source_base,parent_code, parent_stack, parent_trap,
        child_code, child_stack, child_trap })
}

#[cfg(test)]
mod virtual_layout_tests {
    use super::*;
    #[test]
    fn adapter_rejects_fetch_of_its_own_sealed_output_without_a_child() {
        use super::super::isa::{Asm64, R0, R1, R2};
        let mut asm = Asm64::new();
        asm.movi(R1, LAYOUT_OUT as i32); asm.movi(R2, 0); asm.st(R2, R1, 0);
        asm.movi(R0, super::super::os::SYS_SEAL as i32); asm.trap(0);
        let call_at = asm.to_bytes().len();
        asm.call(0); asm.movi(R0, 0); asm.ret();
        let length = asm.to_bytes().len();
        let layout = compiler_virtual_layout(length, false, DEVELOPMENT_COMPILER_OUTPUT_SIZE).unwrap();
        let target = LAYOUT_OUT as i64 - layout.child_code as i64 - call_at as i64;
        let mut call = Asm64::new(); call.call((target / 4) as i32);
        asm.words_mut()[call_at / 4] = call.words_mut()[0];
        let bytes = asm.to_bytes();
        let image = super::super::ankald::AnkaldLinkedImage {
            code_size: bytes.len() as u64, bytes, lit_start: 0, entry: 0, process_slots_observed: 1,
        };
        assert!(matches!(compile_for_adapter(&image, b"probe"),
            Err(DevelopmentCompileError::CompileCommandExecutedOutput)));
    }

    #[test]
    fn p106_bootstrap_profile_is_enabled_on_both_edges_but_not_ordinary_aom() {
        use super::super::isa::{Asm64, R0, R1, R2, R3};
        // A tiny guest compiler observes the control word through Fabric and
        // emits it as sealed output. No CC_B bootstrap is needed for this ABI
        // regression: exercise both real execution bridges directly.
        let mut asm = Asm64::new();
        asm.movi(R3, (WS_AC2_BOOTSTRAP_WORD_DEREF / 2) as i32);
        asm.add(R3, R3, R3);
        asm.ld(R2, R3, 0);
        asm.movi(R1, (LAYOUT_OUT / 2) as i32);
        asm.add(R1, R1, R1);
        asm.st(R2, R1, 0);
        asm.movi(R3, (WS_OUT_POS / 2) as i32);
        asm.add(R3, R3, R3);
        asm.movi(R2, 8);
        asm.st(R2, R3, 0);
        asm.movi(R0, super::super::os::SYS_SEAL as i32);
        asm.trap(0);
        asm.movi(R1, 0);
        asm.movi(R0, super::super::os::SYS_EXIT as i32);
        asm.trap(0);
        let bytes = asm.to_bytes();
        let authority = super::super::dev_runner::DeveloperExecutionAuthority::provision();
        let ordinary = compile_c_to_aom_stage3(&bytes, b"probe").unwrap();
        assert_eq!(ordinary.bytes, 0u64.to_le_bytes());
        let first_edge = compile_bootstrap_aom_stage3(&bytes, b"probe", &authority).unwrap();
        assert_eq!(first_edge.bytes, 1u64.to_le_bytes());
        let linked = super::super::ankald::AnkaldLinkedImage {
            code_size: bytes.len() as u64, bytes, lit_start: 0,
            entry: 0, process_slots_observed: 1,
        };
        let second_edge = compile_bootstrap_aom_with_linked_compiler(&linked, b"probe", &authority).unwrap();
        assert_eq!(second_edge.bytes, 1u64.to_le_bytes());
        let application = compile_application_aom_with_linked_compiler(&linked, b"probe", &authority).unwrap();
        assert_eq!(application.bytes, 0u64.to_le_bytes());
    }

    #[test]
    fn p106_linked_compiler_uses_nonzero_entry_and_protected_return() {
        use super::super::isa::{Asm64, R0, R1, R2, R3};
        let mut asm = Asm64::new();
        asm.halt(); asm.halt(); // Decoys at zero/four; linked entry is eight.
        asm.movi(R1, (LAYOUT_OUT / 2) as i32);
        asm.add(R1, R1, R1);
        asm.movi(R2, 42);
        asm.st(R2, R1, 0);
        asm.movi(R3, (WS_OUT_POS / 2) as i32);
        asm.add(R3, R3, R3);
        asm.movi(R2, 8);
        asm.st(R2, R3, 0);
        asm.movi(R0, 5); // SYS_SEAL(output)
        asm.trap(0);
        asm.movi(R0, 0);
        asm.ret(); // Must consume return authority minted by the launcher CALL.
        let bytes = asm.to_bytes();
        let image = super::super::ankald::AnkaldLinkedImage {
            code_size: bytes.len() as u64, bytes, lit_start: 0,
            entry: 8, process_slots_observed: 1,
        };
        let authority = super::super::dev_runner::DeveloperExecutionAuthority::provision();
        let result = compile_bootstrap_aom_with_linked_compiler(&image, b"probe", &authority).unwrap();
        assert_eq!(result.bytes, 42u64.to_le_bytes());
        assert_eq!(result.process_slots_observed, 1);
        let mut wrong_entry = image; wrong_entry.entry = 0;
        assert!(compile_bootstrap_aom_with_linked_compiler(&wrong_entry, b"probe", &authority).is_err());
    }

    #[test]
    fn protected_aom_transport_excludes_downward_compiler_scratch() {
        use super::super::isa::{Asm64,R0,R1,R2,R3};
        let mut asm=Asm64::new();
        asm.movi(R1,(LAYOUT_OUT/2) as i32);asm.add(R1,R1,R1);
        asm.movi(R2,42);asm.st(R2,R1,0);
        asm.movi(R3,(WS_OUT_POS/2) as i32);asm.add(R3,R3,R3);
        asm.movi(R2,8);asm.st(R2,R3,0);
        asm.movi(R3,(WS_LIT_POS/2) as i32);asm.add(R3,R3,R3);
        asm.movi(R2,131048);asm.add(R2,R2,R2);asm.st(R2,R3,0);
        asm.movi(R0,5);asm.trap(0);asm.movi(R0,0);asm.ret();
        let bytes=asm.to_bytes();
        let image=super::super::ankald::AnkaldLinkedImage{code_size:bytes.len() as u64,bytes,lit_start:0,entry:0,process_slots_observed:1};
        let authority=super::super::dev_runner::DeveloperExecutionAuthority::provision();
        let result=compile_protected_application_aom_with_linked_compiler(&image,b"probe",&authority).unwrap();
        assert_eq!(result.bytes,42u64.to_le_bytes());
    }

    #[test]
    fn extended_bootstrap_layout_separates_output_code_stack_and_trap() {
        let size = DEVELOPMENT_COMPILER_OUTPUT_SIZE;
        let layout = compiler_virtual_layout(114_688, false, size).unwrap();
        let output_end = LAYOUT_OUT as u64 + size;
        assert!(output_end <= layout.parent_code);
        assert!(layout.parent_code + 114_688 <= layout.parent_stack);
        assert!(layout.parent_stack + ANKAD_STACK_SIZE <= layout.parent_trap);
        assert!(output_end <= layout.child_code);
        assert!(layout.child_code + 114_688 <= layout.child_stack);
        assert!(layout.child_stack + STACK_SIZE as u64 <= layout.child_trap);
    }
    #[test]
    fn enlarged_exact_source_is_disjoint_from_compiler_and_output() {
        let layout=compiler_virtual_layout_with_source(180_000,false,DEVELOPMENT_COMPILER_OUTPUT_SIZE,DEVELOPMENT_COMPILER_SOURCE_SIZE).unwrap();
        assert!(layout.source_base>=LAYOUT_OUT as u64+DEVELOPMENT_COMPILER_OUTPUT_SIZE);
        assert!(layout.source_base+DEVELOPMENT_COMPILER_SOURCE_SIZE<=layout.parent_code);
        assert!(layout.source_base+DEVELOPMENT_COMPILER_SOURCE_SIZE<=layout.child_code);
    }
    #[test]
    fn seed_layout_keeps_absolute_code_below_source_and_stack_above_output() {
        let layout = compiler_virtual_layout(0x6000, true, DEVELOPMENT_COMPILER_OUTPUT_SIZE).unwrap();
        assert_eq!(layout.child_code, 0);
        assert!(layout.child_stack >= LAYOUT_OUT as u64 + DEVELOPMENT_COMPILER_OUTPUT_SIZE);
        assert!(compiler_virtual_layout(LAYOUT_SRC as usize + 1, true, OUTPUT_SIZE as u64).is_err());
    }
}
