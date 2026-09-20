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
    compile_c_with_ankacc2_stage2, compile_c_with_ccb, CompiledCImage,
    DevelopmentCompileError,
};
use super::fabric::Fabric;
use super::guest_compiler::{OUTPUT_SIZE, SOURCE_SIZE};
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
const ERR_TYPE: u64 = 9;
const ERR_DECL: u64 = 10;
const ERR_SIGNATURE: u64 = 11;
const ERR_ABI: u64 = 12;
const ERR_LAYOUT: u64 = 13;
const ERR_GLOBAL_DATA: u64 = 14;

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


fn stage2_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/compiler/ankacc2_stage2.c"
    ))
}

fn stage2_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(ccb_image(), stage2_source())
            .expect("CC_B must compile the real AnkaCC2 stage-2 source")
    })
}

fn compile_ac2_v2(source: &str) -> Result<CompiledCImage, DevelopmentCompileError> {
    compile_c_with_ankacc2_stage2(&stage2_image().bytes, source.as_bytes())
}

fn assert_v2_rejected(source: &str, expected: u64) {
    assert_eq!(
        compile_ac2_v2(source),
        Err(DevelopmentCompileError::CompilerRejected(expected)),
    );
}

#[test]
fn p102_ccb_builds_real_ankacc2_stage2() {
    let image = stage2_image();
    let source_bytes = stage2_source().len() as u64;
    let source_payload_limit = SOURCE_SIZE as u64 - 8;
    let source_headroom_bytes = source_payload_limit
        .checked_sub(source_bytes)
        .expect("stage-2 compiler source must fit in CC_B's length-prefixed source arena");
    let output_limit = OUTPUT_SIZE as u64;

    assert!(image.code_size > 0);
    assert!(image.code_size <= output_limit,
        "stage-2 compiler code must fit in CC_B's output arena");
    assert!(image.lit_start == 0
            || (image.code_size <= image.lit_start && image.lit_start <= output_limit),
        "stage-2 compiler output geometry must be ordered and in bounds");

    let literal_bytes = if image.lit_start == 0 {
        0
    } else {
        output_limit - image.lit_start
    };
    let occupied_bytes = image.code_size + literal_bytes;
    let free_gap_bytes = if image.lit_start == 0 {
        output_limit - image.code_size
    } else {
        image.lit_start - image.code_size
    };

    println!(
        "p102 Stage-2 CC_B geometry: source_bytes={} source_headroom_bytes={} code_bytes={} literal_bytes={} occupied_bytes={} free_gap_bytes={} output_limit={}",
        source_bytes,
        source_headroom_bytes,
        image.code_size,
        literal_bytes,
        occupied_bytes,
        free_gap_bytes,
        output_limit,
    );

    assert_eq!(occupied_bytes + free_gap_bytes, output_limit,
        "measured Stage-2 output must account for the complete CC_B arena");
    assert_eq!(image.bytes.len() as u64, image.code_size,
        "stage-2 bootstrap artifact is currently code-only");
    assert_eq!(image.lit_start, 0,
        "stage-2 compiler remains a direct code-only bootstrap artifact");
    assert_eq!(image.process_slots_observed, 2,
        "building stage 2 must remain compile-only");
}

#[test]
fn p102_prototype_and_four_register_argument_abi_execute() {
    let source = concat!(
        "int add(int a,int b,int c,int d);",
        "int add(int a,int b,int c,int d){return a+b+c+d;}",
        "int main(){return add(10,20,5,7);}"
    );
    let image = compile_ac2_v2(source).expect("compatible prototype and 4-arg definition");
    assert_eq!(run_image(&image), ProcessResult::Exited(42));
}

#[test]
fn p102_pointer_and_array_parameter_decay_execute() {
    let source = concat!(
        "int first(int a[]);",
        "int first(int a[]){return *a;}",
        "int main(){int x=42;return first(&x);}"
    );
    let image = compile_ac2_v2(source).expect("array parameter must decay to int pointer");
    assert_eq!(run_image(&image), ProcessResult::Exited(42));
}

#[test]
fn p102_typedef_and_enum_constants_participate_in_typed_calls() {
    let source = concat!(
        "typedef int word;",
        "enum color{red=40,green,blue};",
        "word id(word x);",
        "word id(word x){return x;}",
        "int main(){return id(green+1);}"
    );
    let image = compile_ac2_v2(source).expect("typedef and enum metadata must feed type checking");
    assert_eq!(run_image(&image), ProcessResult::Exited(42));
}

#[test]
fn p102_struct_layout_and_array_extent_are_word_aligned() {
    let source = concat!(
        "struct pair{char c;int x;};",
        "int main(){struct pair p;int a[3];return sizeof(struct pair)+sizeof(int[3]);}"
    );
    let image = compile_ac2_v2(source).expect("struct and array layout must compile");
    assert_eq!(run_image(&image), ProcessResult::Exited(40));
}

#[test]
fn p102_char_size_is_one_byte_while_scalar_abi_remains_word_return() {
    let image = compile_ac2_v2("int main(){char c=42;return c+sizeof(char)-1;}")
        .expect("char object and sizeof(char) must compile");
    assert_eq!(run_image(&image), ProcessResult::Exited(42));
}

#[test]
fn p102_prototype_mismatch_is_rejected_stably() {
    assert_v2_rejected(
        "int f(int x);int f(char x){return x;}int main(){return 0;}",
        ERR_SIGNATURE,
    );
}

#[test]
fn p102_abi_rejects_more_than_four_register_arguments_and_struct_by_value() {
    assert_v2_rejected(
        "int f(int a,int b,int c,int d,int e);int main(){return 0;}",
        ERR_ABI,
    );
    assert_v2_rejected(
        "struct pair{int x;int y;};int f(struct pair p);int main(){return 0;}",
        ERR_ABI,
    );
}

#[test]
fn p102_invalid_object_layout_is_rejected_stably() {
    assert_v2_rejected(
        "struct node{struct node next;};int main(){return 0;}",
        ERR_LAYOUT,
    );
    assert_v2_rejected(
        "int main(){int a[0];return 0;}",
        ERR_TYPE,
    );
}

#[test]
fn p102_mutable_file_scope_data_remains_outside_direct_backend() {
    assert_v2_rejected("int counter;int main(){return 0;}", ERR_GLOBAL_DATA);
}

#[test]
fn p102_called_prototype_must_resolve_to_a_definition() {
    assert_v2_rejected(
        "int f(int x);int main(){return f(42);}",
        ERR_UNRESOLVED_FUNCTION,
    );
}

#[test]
fn p102_void_object_and_unknown_typedef_are_type_errors() {
    assert_v2_rejected("int main(){void x;return 0;}", ERR_TYPE);
    assert_v2_rejected("mystery main(){return 0;}", ERR_DECL);
}
