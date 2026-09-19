//! Phase 10.1 executable witnesses for the CC_B-built AnkaCC2 stage-1
//! lexer/parser/compiler core.
//!
//! The compiler itself is real Anka userspace C:
//! `userspace/system/compiler/ankacc2_stage1.c`.
//!
//! Stage 10.1 intentionally emits the existing direct executable form.  AOM,
//! separate translation units, richer declarations/types, and the static
//! linker remain later Phase 10 boundaries.

use std::sync::OnceLock;

use super::dev_compiler::{
    bootstrap_development_ccb, compile_c_with_ankacc2_stage1,
    compile_c_with_ccb, CompiledCImage, DevelopmentCompileError,
};
use super::fabric::Fabric;
use super::os::{BootImage, BootInfo, Kernel, ProcessResult};
use super::state::{ObjectKind};

const CODE_PHYS: u64 = 0x1_0000;
const STACK_VADDR: u64 = 0x2_0000;
const STACK_SIZE: u64 = 0x4000;
const TRAP_VADDR: u64 = 0x2_4000;
const RAM_SIZE: usize = 0x40_0000;

const ERR_LEX: u64 = 1;
const ERR_IDENT_TOO_LONG: u64 = 2;
const ERR_INTEGER_WIDTH: u64 = 3;
const ERR_PARSE: u64 = 4;
const ERR_DUPLICATE_FUNCTION: u64 = 5;
const ERR_MISSING_MAIN: u64 = 6;
const ERR_UNRESOLVED_FUNCTION: u64 = 7;

fn stage1_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/compiler/ankacc2_stage1.c"
    ))
}

fn ccb_image() -> &'static Vec<u8> {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        bootstrap_development_ccb()
            .expect("phase 10.1 must bootstrap canonical CC_B")
    })
}

fn stage1_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(ccb_image(), stage1_source())
            .expect("CC_B must compile the real AnkaCC2 stage-1 source")
    })
}

fn compile_ac2(source: &str) -> Result<CompiledCImage, DevelopmentCompileError> {
    compile_c_with_ankacc2_stage1(&stage1_image().bytes, source.as_bytes())
}

fn run_image(image: &CompiledCImage) -> ProcessResult {
    assert_eq!(image.lit_start, 0,
        "phase 10.1 stage-1 output is a direct code-only executable");
    assert!(image.code_size > 0);
    assert!(image.code_size < STACK_VADDR,
        "stage-1 output must not overlap the test stack");

    let mut fabric = Fabric::new(RAM_SIZE);
    let code = fabric.alloc_object(
        "p101-direct-executable",
        image.bytes.len() as u64,
        ObjectKind::Memory,
    );
    assert!(fabric.place_object(code, CODE_PHYS));
    assert!(fabric.initialize_object(code, 0, &image.bytes));
    assert!(fabric.seal_object(code));

    let boot = BootInfo {
        image: BootImage {
            obj: code,
            code_offset: 0,
            code_size: image.code_size,
            entry: 0,
            lit_start: 0,
        },
        grants: vec![],
        maps: vec![],
        code_vaddr: 0,
        stack_vaddr: STACK_VADDR,
        stack_size: STACK_SIZE,
        trap_vaddr: TRAP_VADDR,
    };

    let mut kernel = Kernel::new(fabric);
    kernel.boot(&boot).expect("stage-1 output boot");
    kernel.run(200_000, 100);
    kernel.processes[0].result.clone()
        .expect("stage-1 output must terminate")
}

fn assert_rejected(source: &str, expected: u64) {
    assert_eq!(
        compile_ac2(source),
        Err(DevelopmentCompileError::CompilerRejected(expected)),
    );
}

#[test]
fn p101_ccb_builds_real_ankacc2_stage1() {
    let image = stage1_image();
    assert!(image.code_size > 0);
    assert_eq!(image.lit_start, 0,
        "stage-1 compiler source intentionally contains no literals");
    assert_eq!(image.process_slots_observed, 2,
        "CC_B compile-only mode must not execute AnkaCC2 while building it");
}

#[test]
fn p101_sixty_three_byte_c_identifier_compiles_and_executes() {
    let name = format!("A_{}", "x".repeat(61));
    assert_eq!(name.len(), 63);
    let source = format!(
        "int {name}(){{return 42;}} int main(){{return {name}();}}"
    );
    let image = compile_ac2(&source).expect("63-byte C identifier must compile");
    assert_eq!(run_image(&image), ProcessResult::Exited(42));
}

#[test]
fn p101_sixty_four_byte_identifier_is_rejected_stably() {
    let name = format!("A_{}", "x".repeat(62));
    assert_eq!(name.len(), 64);
    let source = format!("int {name}(){{return 1;}} int main(){{return 0;}}");
    assert_rejected(&source, ERR_IDENT_TOO_LONG);
}

#[test]
fn p101_full_width_hex_literal_is_preserved_and_executes() {
    let image = compile_ac2("int main(){return 0xffffffffffffffff;}")
        .expect("full-width hexadecimal token must compile");
    assert_eq!(run_image(&image), ProcessResult::Exited(u64::MAX));
}

#[test]
fn p101_full_width_decimal_literal_is_preserved_and_executes() {
    let image = compile_ac2("int main(){return 18446744073709551615;}")
        .expect("full-width decimal token must compile");
    assert_eq!(run_image(&image), ProcessResult::Exited(u64::MAX));
}

#[test]
fn p101_integer_magnitude_above_u64_is_rejected() {
    assert_rejected(
        "int main(){return 0x10000000000000000;}",
        ERR_INTEGER_WIDTH,
    );
    assert_rejected(
        "int main(){return 18446744073709551616;}",
        ERR_INTEGER_WIDTH,
    );
}

#[test]
fn p101_leading_zeroes_do_not_fake_literal_width() {
    let image = compile_ac2(
        "int main(){return 0000000000000000000018446744073709551615;}"
    ).expect("literal width is magnitude, not spelling length");
    assert_eq!(run_image(&image), ProcessResult::Exited(u64::MAX));

    let image = compile_ac2(
        "int main(){return 0x00000000000000000000ffffffffffffffff;}"
    ).expect("hex leading zeroes do not exceed the 64-bit magnitude");
    assert_eq!(run_image(&image), ProcessResult::Exited(u64::MAX));
}

#[test]
fn p101_stage1_grammar_is_deliberately_narrow() {
    assert_rejected("int main(int x){return x;}", ERR_PARSE);
    assert_rejected("int main(){return 1+2;}", ERR_LEX);
}

#[test]
fn p101_duplicate_missing_and_unresolved_functions_have_stable_diagnostics() {
    assert_rejected(
        "int main(){return 1;} int main(){return 2;}",
        ERR_DUPLICATE_FUNCTION,
    );
    assert_rejected("int helper(){return 1;}", ERR_MISSING_MAIN);
    assert_rejected(
        "int main(){return missing_function();}",
        ERR_UNRESOLVED_FUNCTION,
    );
}
