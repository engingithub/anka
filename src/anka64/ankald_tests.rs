//! Phase 10.4 executable witnesses for the userspace `ankald` linker.

use std::sync::OnceLock;

use super::aom::{AomModule, AOM_RELOC_CALL_PC20};
use super::ankald::{
    link_and_publish_with_ankald, publish_linked_image, run_ankald,
    AnkaldError, AnkaldLinkPublishError,
};
use super::dev_compiler::{
    bootstrap_development_ccb, bootstrap_extended_ccb,
    compile_c_to_aom_stage3, compile_c_with_ccb, compile_c_with_extended_ccb,
    CompiledAomModule, CompiledCImage,
};
use super::fabric::Fabric;
use super::placement::PhysicalPlacementManager;
use super::state::{ObjectState, Permissions};

fn stage3_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/compiler/ankacc2_stage3.c"
    ))
}

fn ankald_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/compiler/ankald.c"
    ))
}

fn canonical_ccb() -> &'static Vec<u8> {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        bootstrap_development_ccb().expect("Phase 10.4 must bootstrap canonical CC_B")
    })
}

fn extended_ccb() -> &'static Vec<u8> {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        bootstrap_extended_ccb().expect("Phase 10.4 must bootstrap extended CC_B")
    })
}

fn stage3_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_extended_ccb(extended_ccb(), stage3_source())
            .expect("extended CC_B must compile the real AnkaCC2 stage-3 source")
    })
}

fn ankald_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(canonical_ccb(), ankald_source())
            .expect("canonical CC_B must compile the Phase 10.4 bootstrap ankald source")
    })
}

fn compile_aom(source: &str) -> CompiledAomModule {
    compile_c_to_aom_stage3(&stage3_image().bytes, source.as_bytes())
        .expect("AC2 translation unit must emit AOM")
}

fn caller_and_callee() -> (CompiledAomModule, CompiledAomModule) {
    (
        compile_aom("int addone(int x);int main(){return addone(41);}"),
        compile_aom("int addone(int x){return x+1;}"),
    )
}

fn sign_extend_22(value: u32) -> i64 {
    let raw = i64::from(value & 0x003f_ffff);
    if raw & (1 << 21) != 0 { raw - (1 << 22) } else { raw }
}

fn add_rodata(module: &[u8], data: &[u8]) -> Vec<u8> {
    let parsed = AomModule::parse(module).expect("base module must be valid AOM");
    assert!(parsed.rodata.is_empty());
    assert_eq!(data.len() % 8, 0, "test rodata keeps AOM table alignment simple");
    let insert = parsed.header.rodata_offset as usize;
    let mut out = Vec::with_capacity(module.len() + data.len());
    out.extend_from_slice(&module[..insert]);
    out.extend_from_slice(data);
    out.extend_from_slice(&module[insert..]);
    let delta = data.len() as u64;
    let total = parsed.header.total_size + delta;
    let symbol = parsed.header.symbol_offset + delta;
    let reloc = parsed.header.relocation_offset + delta;
    out[24..32].copy_from_slice(&total.to_le_bytes());
    out[64..72].copy_from_slice(&delta.to_le_bytes());
    out[80..88].copy_from_slice(&symbol.to_le_bytes());
    out[96..104].copy_from_slice(&reloc.to_le_bytes());
    AomModule::parse(&out).expect("test mutation must remain valid AOM");
    out
}

#[test]
fn p104_ccb_builds_real_userspace_ankald() {
    let image = ankald_image();
    assert!(image.code_size > 0);
    assert_eq!(image.lit_start, 0, "bootstrap ankald is code-only");
    assert_eq!(image.bytes.len() as u64, image.code_size);
    assert_eq!(image.process_slots_observed, 2,
        "compiling ankald remains compile-only");
}

#[test]
fn p104_real_stage3_modules_link_inside_anka_and_patch_exact_call() {
    let (caller, callee) = caller_and_callee();
    let caller_parsed = AomModule::parse(&caller.bytes).unwrap();
    let callee_parsed = AomModule::parse(&callee.bytes).unwrap();
    let linked = run_ankald(&ankald_image().bytes, &[&caller.bytes, &callee.bytes], "main").unwrap();

    assert_eq!(linked.process_slots_observed, 1,
        "ankald is the only process and never executes its linked output");
    assert_eq!(linked.lit_start, 0);
    assert_eq!(linked.bytes.len() as u64, linked.code_size);
    assert_eq!(linked.entry, caller_parsed.symbol("main").unwrap().value);

    let relocation = &caller_parsed.relocations[0];
    assert_eq!(relocation.kind, AOM_RELOC_CALL_PC20);
    let patch = relocation.offset as usize;
    let word = u32::from_le_bytes(linked.bytes[patch..patch + 4].try_into().unwrap());
    let pad = u32::from_le_bytes(linked.bytes[patch + 4..patch + 8].try_into().unwrap());
    assert_eq!(word >> 26, 50);
    assert_eq!(pad >> 26, 63);
    let disp = sign_extend_22(word);
    let resolved = i128::from(relocation.offset) + i128::from(disp) * 4;
    let caller_code = caller_parsed.header.code_size;
    let callee_base = (caller_code + callee_parsed.header.code_align - 1)
        & !(callee_parsed.header.code_align - 1);
    let expected = callee_base + callee_parsed.symbol("addone").unwrap().value;
    assert_eq!(resolved, i128::from(expected));
}

#[test]
fn p104_ordered_inputs_are_semantic_and_both_directions_link() {
    let (caller, callee) = caller_and_callee();
    let forward = run_ankald(&ankald_image().bytes, &[&caller.bytes, &callee.bytes], "main").unwrap();
    let backward = run_ankald(&ankald_image().bytes, &[&callee.bytes, &caller.bytes], "main").unwrap();
    assert_ne!(forward.entry, backward.entry);
    assert_ne!(forward.bytes, backward.bytes);
}

#[test]
fn p104_same_inputs_and_entry_are_byte_deterministic() {
    let (caller, callee) = caller_and_callee();
    let first = run_ankald(&ankald_image().bytes, &[&caller.bytes, &callee.bytes], "main").unwrap();
    let second = run_ankald(&ankald_image().bytes, &[&caller.bytes, &callee.bytes], "main").unwrap();
    assert_eq!(first, second);
}

#[test]
fn p104_unresolved_required_import_is_rejected() {
    let (caller, _) = caller_and_callee();
    assert_eq!(
        run_ankald(&ankald_image().bytes, &[&caller.bytes], "main"),
        Err(AnkaldError::LinkerRejected(4)),
    );
}

#[test]
fn p104_duplicate_strong_definition_is_rejected() {
    let a = compile_aom("int same(){return 1;}");
    let b = compile_aom("int same(){return 2;}");
    assert_eq!(
        run_ankald(&ankald_image().bytes, &[&a.bytes, &b.bytes], "same"),
        Err(AnkaldError::LinkerRejected(3)),
    );
}

#[test]
fn p104_import_export_signature_must_match_exactly() {
    let caller = compile_aom("int ext(int x);int main(){return ext(1);}");
    let callee = compile_aom("int ext(char x){return x;}");
    assert_eq!(
        run_ankald(&ankald_image().bytes, &[&caller.bytes, &callee.bytes], "main"),
        Err(AnkaldError::LinkerRejected(5)),
    );
}

#[test]
fn p104_nonzero_relocation_addend_is_rejected() {
    let (caller, callee) = caller_and_callee();
    let parsed = AomModule::parse(&caller.bytes).unwrap();
    let mut mutated = caller.bytes.clone();
    let addend = parsed.header.relocation_offset as usize + 40;
    mutated[addend..addend + 8].copy_from_slice(&1u64.to_le_bytes());
    assert_eq!(
        run_ankald(&ankald_image().bytes, &[&mutated, &callee.bytes], "main"),
        Err(AnkaldError::LinkerRejected(6)),
    );
}

#[test]
fn p104_aom_headers_are_not_copied_into_linked_image() {
    let (_, callee) = caller_and_callee();
    let parsed = AomModule::parse(&callee.bytes).unwrap();
    let linked = run_ankald(&ankald_image().bytes, &[&callee.bytes], "addone").unwrap();
    assert_eq!(&linked.bytes[..8], &parsed.code[..8]);
    assert_ne!(&linked.bytes[..8], b"ANKAOM1\0");
}

#[test]
fn p104_optional_rodata_is_separated_from_executable_prefix() {
    let (_, callee) = caller_and_callee();
    let rodata = [11u8, 22, 33, 44, 55, 66, 77, 88];
    let module = add_rodata(&callee.bytes, &rodata);
    let linked = run_ankald(&ankald_image().bytes, &[&module], "addone").unwrap();
    assert!(linked.lit_start >= linked.code_size);
    assert_eq!(&linked.bytes[linked.lit_start as usize..], &rodata);
}

#[test]
fn p104_successful_publication_is_exact_sealed_and_grants_no_authority() {
    let (caller, callee) = caller_and_callee();
    let linked = run_ankald(&ankald_image().bytes, &[&caller.bytes, &callee.bytes], "main").unwrap();
    let mut fabric = Fabric::new(0x400000);
    let mut placement = PhysicalPlacementManager::new(0x10000, 0x100000).unwrap();
    let domains_before = fabric.domains.len();

    let artifact = publish_linked_image(&mut fabric, &mut placement, "ankald-linked", &linked).unwrap();
    let object = fabric.objects.get(&artifact.key.object).unwrap();
    assert_eq!(object.state, ObjectState::Sealed);
    assert_eq!(object.generation, artifact.key.generation);
    assert_eq!(object.size, linked.bytes.len() as u64);
    assert_eq!(artifact.logical_size, linked.bytes.len() as u64);
    assert_eq!(artifact.code_size, linked.code_size);
    assert_eq!(artifact.entry, linked.entry);
    assert_eq!(artifact.code_permissions, Permissions::RX);
    assert_eq!(fabric.domains.len(), domains_before,
        "publication mints no capability/execution authority");
}

#[test]
fn p104_failed_link_does_not_mutate_target_fabric_or_placement() {
    let (caller, _) = caller_and_callee();
    let mut fabric = Fabric::new(0x400000);
    let mut placement = PhysicalPlacementManager::new(0x10000, 0x100000).unwrap();
    let objects_before = fabric.objects.len();
    let allocations_before = placement.allocated_count();
    assert_eq!(
        link_and_publish_with_ankald(
            &ankald_image().bytes,
            &[&caller.bytes],
            "main",
            &mut fabric,
            &mut placement,
            "must-not-publish",
        ),
        Err(AnkaldLinkPublishError::Link(AnkaldError::LinkerRejected(4))),
    );
    assert_eq!(fabric.objects.len(), objects_before);
    assert_eq!(placement.allocated_count(), allocations_before);
}
