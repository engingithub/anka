//! Ankad — the Anka supervisor program.
//!
//! Builds the machine code for the supervisor process that spawns
//! a compiler, waits for it, and exits with the structured result.
//!
//! This is the single source of truth for the supervisor assembly.
//! Both `run_supervised_compiler` (test helper) and
//! `build_compiler_system_image` (production image builder) use it.

use crate::anka64::isa::*;
use crate::anka64::os::{SYS_SPAWN, SYS_WAIT, SYS_EXIT};
use crate::anka64::guest_compiler::{OUTPUT_SIZE, LAYOUT_OUT, STACK_SIZE};
use crate::anka64::placement::PLACEMENT_PAGE_SIZE;

/// Where ankad maps the compiler object in its own address space.
/// SYS_SPAWN.R1 is always this value regardless of whether the
/// compiler is CC_A (child code_vaddr=0) or CC_B (child code_vaddr=0x30000).
pub const SUPERVISOR_COMPILER_VADDR: u64 = 0x30000;

/// Build the ankad supervisor machine code.
///
/// The resulting program:
/// 1. Constructs SpawnGrant, SpawnMap, and SpawnLayout descriptors
///    on the stack via SP-relative addressing.
/// 2. Calls SYS_SPAWN with R1 = SUPERVISOR_COMPILER_VADDR.
/// 3. Calls SYS_WAIT on the child handle.
/// 4. Preserves the WAIT tag in R10 (survives exit).
/// 5. Calls SYS_EXIT(detail) to propagate the compiler's result.
///
/// Parameters:
/// - `compiler_len`: byte length of the compiler code (must fit MOVI).
/// - `child_code_vaddr`: where the child's code is placed in the
///   child's virtual space. 0 for CC_A, 0x30000 for CC_B.
///   Only affects SpawnLayout.code_vaddr.
pub fn build_ankad_code(compiler_len: usize, child_code_vaddr: u64) -> Vec<u8> {
    build_ankad_code_with_output_size(
        compiler_len,
        child_code_vaddr,
        OUTPUT_SIZE as u64,
    )
}

/// Build ankad with an explicit compiler output arena size.
///
/// The development compiler bridge uses this entry point so physical extent
/// sizing and child virtual placement are driven by the actual arena granted
/// for that invocation rather than by the historical OUTPUT_SIZE constant.
pub fn build_ankad_code_with_output_size(
    compiler_len: usize,
    child_code_vaddr: u64,
    output_size: u64,
) -> Vec<u8> {
    assert!(compiler_len <= 0x1FFFF,
        "compiler_len {compiler_len:#x} exceeds MOVI range (max 0x1FFFF)");
    assert!(child_code_vaddr % 2 == 0,
        "child_code_vaddr {child_code_vaddr:#x} must be even (halved for MOVI)");
    assert!((child_code_vaddr / 2) <= 0x1FFFF,
        "child_code_vaddr/2 {:#x} exceeds MOVI range (max 0x1FFFF)",
        child_code_vaddr / 2);

    // Layout-derived constants for assembly.  All values are loaded
    // via MOVI(half) + ADD(R,R,R) so half must fit in 18-bit signed.
    const HALF_LAYOUT_OUT: i32 = (LAYOUT_OUT / 2) as i32;
    const TRAP_SIZE: u64 = PLACEMENT_PAGE_SIZE;
    assert!(output_size != 0 && output_size & (PLACEMENT_PAGE_SIZE - 1) == 0,
        "compiler output arena must be non-zero and page-aligned");
    let layout_stack = (LAYOUT_OUT as u64)
        .checked_add(output_size)
        .expect("compiler output virtual range overflow");
    let trap_vaddr = layout_stack
        .checked_add(STACK_SIZE as u64)
        .expect("compiler stack virtual range overflow");
    let trap_end = trap_vaddr
        .checked_add(TRAP_SIZE)
        .expect("compiler trap virtual range overflow");
    if child_code_vaddr != 0 {
        assert!(trap_end <= child_code_vaddr,
            "compiler output/stack/trap layout overlaps child compiler code");
    }
    assert!(output_size % 2 == 0);
    assert!(layout_stack % 2 == 0);
    assert!(trap_vaddr % 2 == 0);
    assert!((output_size / 2) <= 0x1FFFF);
    assert!((layout_stack / 2) <= 0x1FFFF);
    assert!((trap_vaddr / 2) <= 0x1FFFF);
    let half_output_size = (output_size / 2) as i32;
    let half_layout_stack = (layout_stack / 2) as i32;
    let half_trap = (trap_vaddr / 2) as i32;

    let mut asm = Asm64::new();

    // ── Phase 1: base addresses ──
    asm.subi(R4, SP, 0x300);          // grant_base
    asm.subi(R6, SP, 0x200);          // map_base
    asm.subi(R8, SP, 0x100);          // layout_base
    asm.movi(R9, 0);                  // zero constant

    // ── Phase 2a: Grant[0] — source = R ──
    // [parent_vaddr, offset, size, perms, reserved]
    asm.movi(R3, 0x07000);
    asm.st(R3, R4, 0);               // parent_vaddr = 0x07000
    asm.st(R9, R4, 8);               // offset = 0
    asm.movi(R3, 0x5000);
    asm.st(R3, R4, 16);              // size = SOURCE_SIZE
    asm.movi(R3, 1);
    asm.st(R3, R4, 24);              // perms = READ
    asm.st(R9, R4, 32);              // reserved = 0

    // ── Phase 2b: Grant[1] — output = RWS ──
    asm.movi(R3, HALF_LAYOUT_OUT);
    asm.add(R3, R3, R3);             // R3 = LAYOUT_OUT
    asm.st(R3, R4, 40);              // parent_vaddr
    asm.st(R9, R4, 48);              // offset = 0
    asm.movi(R3, half_output_size);
    asm.add(R3, R3, R3);             // R3 = OUTPUT_SIZE
    asm.st(R3, R4, 56);              // size = OUTPUT_SIZE
    asm.movi(R3, 0x13);
    asm.st(R3, R4, 64);              // perms = RWS
    asm.st(R9, R4, 72);              // reserved = 0

    // ── Phase 2c: Grant[2] — workspace = RW ──
    asm.movi(R3, 0x6000);
    asm.add(R3, R3, R3);             // R3 = 0x0C000
    asm.st(R3, R4, 80);              // parent_vaddr
    asm.st(R9, R4, 88);              // offset = 0
    asm.movi(R3, 0x6000);
    asm.st(R3, R4, 96);              // size = WS_SIZE
    asm.movi(R3, 3);
    asm.st(R3, R4, 104);             // perms = RW
    asm.st(R9, R4, 112);             // reserved = 0

    // ── Phase 2d: Map[0] — source (identity mapping) ──
    // [child_vaddr, parent_vaddr, offset, size, reserved]
    asm.movi(R3, 0x07000);
    asm.st(R3, R6, 0);               // child_vaddr = 0x07000
    asm.st(R3, R6, 8);               // parent_vaddr = 0x07000
    asm.st(R9, R6, 16);              // offset = 0
    asm.movi(R3, 0x5000);
    asm.st(R3, R6, 24);              // size = SOURCE_SIZE
    asm.st(R9, R6, 32);              // reserved = 0

    // ── Phase 2e: Map[1] — workspace (identity mapping) ──
    asm.movi(R3, 0x6000);
    asm.add(R3, R3, R3);             // R3 = 0x0C000
    asm.st(R3, R6, 40);              // child_vaddr
    asm.st(R3, R6, 48);              // parent_vaddr
    asm.st(R9, R6, 56);              // offset = 0
    asm.movi(R3, 0x6000);
    asm.st(R3, R6, 64);              // size = WS_SIZE
    asm.st(R9, R6, 72);              // reserved = 0

    // ── Phase 2f: Map[2] — output (identity mapping) ──
    asm.movi(R3, HALF_LAYOUT_OUT);
    asm.add(R3, R3, R3);             // R3 = LAYOUT_OUT
    asm.st(R3, R6, 80);              // child_vaddr
    asm.st(R3, R6, 88);              // parent_vaddr
    asm.st(R9, R6, 96);              // offset = 0
    asm.movi(R3, half_output_size);
    asm.add(R3, R3, R3);             // R3 = OUTPUT_SIZE
    asm.st(R3, R6, 104);             // size = OUTPUT_SIZE
    asm.st(R9, R6, 112);             // reserved = 0

    // ── Phase 2g: SpawnLayout ──
    // [code_vaddr, stack_vaddr, stack_size, trap_vaddr, reserved]
    let half_code = (child_code_vaddr / 2) as i32;
    asm.movi(R3, half_code);
    asm.add(R3, R3, R3);             // R3 = child_code_vaddr
    asm.st(R3, R8, 0);               // code_vaddr
    asm.movi(R3, half_layout_stack);
    asm.add(R3, R3, R3);             // R3 = LAYOUT_STACK
    asm.st(R3, R8, 8);               // stack_vaddr
    asm.movi(R3, STACK_SIZE as i32);
    asm.st(R3, R8, 16);              // stack_size
    asm.movi(R3, half_trap);
    asm.add(R3, R3, R3);             // R3 = LAYOUT_STACK + STACK_SIZE
    asm.st(R3, R8, 24);              // trap_vaddr
    asm.st(R9, R8, 32);              // reserved = 0

    // ── Phase 3: SYS_SPAWN(R1-R8) ──
    // R1 = SUPERVISOR_COMPILER_VADDR (parent mapping), always 0x30000
    asm.movi(R1, 0x18000);
    asm.add(R1, R1, R1);             // R1 = 0x30000
    asm.movi(R2, compiler_len as i32); // R2 = code_size (fits MOVI)
    asm.movi(R3, 0);                 // R3 = lit_start = 0
    asm.movi(R5, 3);                 // R5 = grant_count
    asm.movi(R7, 3);                 // R7 = map_count
    // R4 = grant_base, R6 = map_base, R8 = layout_base (already set)
    asm.movi(R0, SYS_SPAWN as i32);
    asm.trap(0);

    // ── Phase 4: SYS_WAIT ──
    asm.mov(R9, R0);                 // R9 = handle
    asm.mov(R1, R9);
    asm.movi(R0, SYS_WAIT as i32);
    asm.trap(0);
    // R0 = tag, R1 = detail

    // ── Phase 5: preserve tag, exit with detail ──
    // MOV R10, R0 preserves the WAIT tag for host inspection.
    // SYS_EXIT(R1) propagates the compiler's result as ankad's exit code.
    asm.mov(R10, R0);                // R10 = wait tag (survives exit)
    asm.movi(R0, SYS_EXIT as i32);
    asm.trap(0);

    asm.to_bytes()
}
