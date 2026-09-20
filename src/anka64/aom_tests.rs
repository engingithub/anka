//! Phase 10.3 executable witnesses for AOM v1 object emission.
//!
//! AnkaCC2 stage 3 is still bootstrapped by the real CC_B compiler, but its
//! compile-only output is now an Anka Object Module rather than a runnable
//! image.  These tests deliberately stop before static linking: 10.4 owns the
//! first transformation from AOM modules to a linked executable artifact.

use std::sync::OnceLock;

use super::aom::{
    AomError, AomModule, AOM_BINDING_EXPORT, AOM_BINDING_IMPORT,
    AOM_HEADER_SIZE, AOM_RELOC_CALL_PC20, AOM_SECTION_CODE,
};
use super::dev_compiler::{
    bootstrap_extended_ccb, compile_c_to_aom_stage3, compile_c_with_extended_ccb,
    CompiledAomModule, CompiledCImage, DevelopmentCompileError,
    DEVELOPMENT_COMPILER_OUTPUT_SIZE,
};

use super::guest_compiler::SOURCE_SIZE;

const ERR_AOM: u64 = 15;
const ERR_AOM_SIGNATURE: u64 = 16;

fn stage3_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/compiler/ankacc2_stage3.c"
    ))
}

fn ccb_image() -> &'static Vec<u8> {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        bootstrap_extended_ccb()
            .expect("phase 10.3 must bootstrap the extended real CC_B")
    })
}

fn stage3_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_extended_ccb(ccb_image(), stage3_source())
            .expect("CC_B must compile the real AnkaCC2 stage-3 source")
    })
}

fn compile_aom(source: &str) -> Result<CompiledAomModule, DevelopmentCompileError> {
    compile_c_to_aom_stage3(&stage3_image().bytes, source.as_bytes())
}

fn module(source: &str) -> AomModule {
    let object = compile_aom(source).expect("AC2 translation unit must emit AOM");
    assert_eq!(object.process_slots_observed, 2,
        "AOM emission is compile-only and must not execute produced bytes");
    AomModule::parse(&object.bytes).expect("AnkaCC2 must emit structurally valid AOM v1")
}

#[test]
fn p103_ccb_builds_real_ankacc2_stage3() {
    let image = stage3_image();
    let source_bytes = stage3_source().len() as u64;
    let source_payload_limit = SOURCE_SIZE as u64 - 8;
    let source_headroom_bytes = source_payload_limit
        .checked_sub(source_bytes)
        .expect("stage-3 compiler source must fit in CC_B's length-prefixed source arena");
    let output_limit = DEVELOPMENT_COMPILER_OUTPUT_SIZE;

    assert!(image.code_size > 0);
    assert!(image.code_size <= output_limit,
        "stage-3 compiler code must fit in the derived development compiler arena");
    assert_eq!(image.lit_start, 0,
        "stage-3 compiler bootstrap artifact remains code-only");
    let free_gap_bytes = output_limit - image.code_size;

    println!(
        "p103 Stage-3 CC_B geometry: source_bytes={} source_headroom_bytes={} code_bytes={} free_gap_bytes={} output_limit={}",
        source_bytes,
        source_headroom_bytes,
        image.code_size,
        free_gap_bytes,
        output_limit,
    );

    assert_eq!(image.process_slots_observed, 2,
        "building stage 3 must remain compile-only");
}

#[test]
fn p103_single_translation_unit_emits_export_without_main_requirement() {
    let aom = module("int answer(){return 42;}");
    assert_eq!(aom.header.code_offset, AOM_HEADER_SIZE);
    assert!(aom.header.code_size > 0);
    assert!(aom.rodata.is_empty());
    assert_eq!(aom.symbols.len(), 1);
    let answer = aom.symbol("answer").expect("answer export");
    assert_eq!(answer.binding, AOM_BINDING_EXPORT);
    assert_eq!(answer.section, AOM_SECTION_CODE);
    assert_eq!(answer.return_type, 1);
    assert!(answer.parameter_types.is_empty());
    assert!(aom.relocations.is_empty());
}

#[test]
fn p103_separate_caller_translation_unit_emits_import_and_typed_relocation() {
    let caller = module(
        "int addone(int x);int main(){return addone(41);}"
    );
    let main = caller.symbol("main").expect("main export");
    let addone = caller.symbol("addone").expect("addone import");
    assert_eq!(main.binding, AOM_BINDING_EXPORT);
    assert_eq!(addone.binding, AOM_BINDING_IMPORT);
    assert_eq!(addone.return_type, 1);
    assert_eq!(addone.parameter_types, vec![1]);
    assert_eq!(caller.relocations.len(), 1);
    let relocation = &caller.relocations[0];
    assert_eq!(relocation.kind, AOM_RELOC_CALL_PC20);
    assert_eq!(relocation.width, 8);
    assert_eq!(relocation.section, AOM_SECTION_CODE);
    assert_eq!(caller.symbols[relocation.symbol_index as usize].name, "addone");
}

#[test]
fn p103_separate_callee_translation_unit_is_independently_valid() {
    let callee = module("int addone(int x){return x+1;}");
    let addone = callee.symbol("addone").expect("addone export");
    assert_eq!(addone.binding, AOM_BINDING_EXPORT);
    assert_eq!(addone.parameter_types, vec![1]);
    assert!(callee.relocations.is_empty());
    assert!(callee.symbol("main").is_none(),
        "AOM translation units do not require a distinguished main symbol");
}

#[test]
fn p103_forward_definition_is_patched_locally_not_imported() {
    let aom = module(
        "int id(int x);int main(){return id(42);}int id(int x){return x;}"
    );
    assert_eq!(aom.symbol("id").expect("id export").binding, AOM_BINDING_EXPORT);
    assert!(aom.relocations.is_empty(),
        "same-module forward calls remain local PC-relative calls");
}

#[test]
fn p103_uncalled_prototype_does_not_become_required_import() {
    let aom = module("int unused(int x);int live(){return 1;}");
    assert!(aom.symbol("unused").is_none());
    assert_eq!(aom.symbol("live").expect("live export").binding, AOM_BINDING_EXPORT);
    assert!(aom.relocations.is_empty());
}

#[test]
fn p103_symbol_records_preserve_ac2_signature_types() {
    let aom = module(
        "char narrow(char x){return x;}int ptr(int *p){return *p;}"
    );
    let narrow = aom.symbol("narrow").expect("narrow export");
    assert_eq!(narrow.return_type, 2);
    assert_eq!(narrow.parameter_types, vec![2]);
    let ptr = aom.symbol("ptr").expect("ptr export");
    assert_eq!(ptr.return_type, 1);
    assert_eq!(ptr.parameter_types, vec![1001]);
}

#[test]
fn p103_prototype_only_module_with_no_code_is_rejected() {
    assert_eq!(
        compile_aom("int external(int x);"),
        Err(DevelopmentCompileError::CompilerRejected(ERR_AOM)),
    );
}

#[test]
fn p103_public_signature_rejects_translation_unit_local_struct_identity() {
    assert_eq!(
        compile_aom(
            "struct item{int x;};int expose(struct item *p){return 0;}"
        ),
        Err(DevelopmentCompileError::CompilerRejected(ERR_AOM_SIGNATURE)),
    );
}

#[test]
fn p103_parser_rejects_unknown_version_and_bad_relocation_bounds() {
    let object = compile_aom(
        "int ext(int x);int main(){return ext(1);}"
    ).expect("valid object before mutation");

    let mut bad_version = object.bytes.clone();
    bad_version[8..16].copy_from_slice(&2u64.to_le_bytes());
    assert_eq!(AomModule::parse(&bad_version), Err(AomError::UnsupportedVersion(2)));

    let parsed = AomModule::parse(&object.bytes).expect("valid object");
    let mut bad_relocation = object.bytes.clone();
    let relocation_offset = parsed.header.relocation_offset as usize;
    bad_relocation[relocation_offset + 8..relocation_offset + 16]
        .copy_from_slice(&parsed.header.code_size.to_le_bytes());
    assert_eq!(AomModule::parse(&bad_relocation), Err(AomError::BadRelocation));
}

#[test]
fn p103_object_emission_is_not_an_execution_artifact() {
    let object = compile_aom("int main(){return 42;}")
        .expect("AOM emission");
    assert_eq!(&object.bytes[..8], b"ANKAOM1\0");
    assert_ne!(&object.bytes[..8], &[0u8; 8]);
    assert_eq!(object.process_slots_observed, 2,
        "compiler output was not spawned or executed while producing AOM");
}
