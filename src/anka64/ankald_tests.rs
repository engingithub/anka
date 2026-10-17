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

pub(crate) fn ankald_image() -> &'static CompiledCImage {
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

// Small hand-assembled inputs exercise the real guest linker without a CC2
// bootstrap. The separate p107 acceptance covers exact self-hosted production.
pub(crate) fn protected_test_aom(code: &[u8], metadata: &[u8],
    symbols: &[(&str, u64, u64, &[u64])], relocations: &[(u64, u64)]) -> Vec<u8> {
    let rodata = 112 + code.len() as u64;
    let syms = rodata + metadata.len() as u64;
    let relocs = syms + symbols.len() as u64 * 160;
    let total = relocs + relocations.len() as u64 * 48;
    let mut bytes = b"ANKAOM1\0".to_vec();
    for word in [1, 112, total, 112, code.len() as u64, 8, rodata,
        metadata.len() as u64, 8, syms, symbols.len() as u64, relocs, relocations.len() as u64] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(code);
    bytes.extend_from_slice(metadata);
    for &(name, binding, value, params) in symbols {
        bytes.extend_from_slice(&(name.len() as u64).to_le_bytes());
        let mut storage = [0; 64]; storage[..name.len()].copy_from_slice(name.as_bytes());
        bytes.extend_from_slice(&storage);
        for word in [binding, 1, if binding == 1 { 1 } else { 0 }, value, 0, 1, params.len() as u64] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        for i in 0..4 { bytes.extend_from_slice(&params.get(i).copied().unwrap_or(0).to_le_bytes()); }
    }
    for &(offset, symbol) in relocations {
        for word in [1, offset, 8, 1, symbol, 0] { bytes.extend_from_slice(&word.to_le_bytes()); }
    }
    bytes
}

pub(crate) fn protected_test_modules() -> Vec<super::pointer_frames::ValidatedPointerModule> {
    use super::isa::Asm64;
    use super::pointer_frames::ValidatedPointerModule;
    let mut caller = Asm64::new();
    caller.pframe(1); caller.nop(); caller.call(0); caller.nop();
    caller.call(6); caller.nop(); caller.punframe(); caller.nop(); caller.ret(); caller.nop();
    caller.pframe(0); caller.nop(); caller.plocal(8, 0); caller.nop();
    caller.punframe(); caller.nop(); caller.ret(); caller.nop();
    let metadata: Vec<u8> = [1345400887u64, 2, 72, 2,
        40, 72, 16, 1, 0, 16, 16, 3, 0, 40, 16, 1, 0, 4, 1, 1]
        .iter().flat_map(|w| w.to_le_bytes()).collect();
    let caller = protected_test_aom(&caller.to_bytes(), &metadata,
        &[("tail", 1, 40, &[1]), ("touch", 2, 0, &[1002, 1]), ("main", 1, 0, &[])], &[(8, 1)]);
    let mut callee = Asm64::new();
    callee.pframe(0); callee.nop(); callee.call(0); callee.nop(); callee.plocal(8, 0); callee.nop();
    callee.punframe(); callee.nop(); callee.ret(); callee.nop();
    let metadata: Vec<u8> = [1345400887u64, 2, 40, 1, 0, 40, 16, 1, 0, 16, 16, 3]
        .iter().flat_map(|w| w.to_le_bytes()).collect();
    let callee = protected_test_aom(&callee.to_bytes(), &metadata,
        &[("touch", 1, 0, &[1002, 1]), ("tail", 2, 0, &[1])], &[(8, 1)]);
    vec![ValidatedPointerModule::from_aom(&caller).unwrap(), ValidatedPointerModule::from_aom(&callee).unwrap()]
}

fn set_word(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset+8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn p108_protected_link_merges_frames_and_resolves_both_call_directions() {
    use super::ankald::run_protected_ankald;
    use super::pointer_frames::ValidatedPointerProgram;
    let inputs = protected_test_modules();
    let image = run_protected_ankald(&ankald_image().bytes, &inputs).unwrap();
    assert_eq!((image.code_size, image.lit_start, image.entry, image.bytes.len()), (112, 112, 0, 336));
    let program = ValidatedPointerProgram::from_image(&image.bytes[..112], &image.bytes[112..]).unwrap().unwrap();
    assert_eq!(program.frames.iter().map(|f| f.entry).collect::<Vec<_>>(), [40, 0, 72]);
    assert_eq!(program.frames[2].locals, inputs[1].frames()[0].locals);
    let word = |pc| u32::from_le_bytes(image.bytes[pc..pc+4].try_into().unwrap());
    assert_eq!(word(72), (44 << 26) | 2);
    assert_eq!(8 + sign_extend_22(word(8)) * 4, 72);
    assert_eq!(80 + sign_extend_22(word(80)) * 4, 40);
    assert_eq!(&image.bytes[16..24], &inputs[0].module().code[16..24]);
    assert_eq!(&image.bytes[88..96], &inputs[1].module().code[16..24]);
    assert_eq!(image, run_protected_ankald(&ankald_image().bytes, &inputs).unwrap());
}

#[test]
fn p108_protected_link_rejects_unresolved_duplicate_and_wrong_signature() {
    use super::ankald::run_protected_ankald;
    use super::pointer_frames::ValidatedPointerModule;
    let inputs = protected_test_modules();
    assert_eq!(run_protected_ankald(&ankald_image().bytes, &inputs[..1]), Err(AnkaldError::LinkerRejected(4)));
    let mut duplicate = inputs.clone(); duplicate.push(inputs[1].clone());
    assert_eq!(run_protected_ankald(&ankald_image().bytes, &duplicate), Err(AnkaldError::LinkerRejected(3)));
    let mut changed = inputs[1].bytes().to_vec();
    set_word(&mut changed, inputs[1].module().header.symbol_offset as usize + 112, 2);
    let wrong = vec![inputs[0].clone(), ValidatedPointerModule::from_aom(&changed).unwrap()];
    assert_eq!(run_protected_ankald(&ankald_image().bytes, &wrong), Err(AnkaldError::LinkerRejected(5)));
}

#[test]
fn p108_protected_link_rejects_mixed_profiles_and_changed_entry_contract() {
    use super::ankald::run_protected_ankald;
    use super::pointer_frames::ValidatedPointerModule;
    let inputs = protected_test_modules();
    let mut legacy = inputs[1].bytes().to_vec();
    set_word(&mut legacy, 112, (63u64 << 26) | (63u64 << 58));
    assert_eq!(run_ankald(&ankald_image().bytes, &[inputs[0].bytes(), &legacy], "main"), Err(AnkaldError::LinkerRejected(9)));
    assert_eq!(run_protected_ankald(&ankald_image().bytes, &[inputs[1].clone(), inputs[0].clone()]), Err(AnkaldError::LinkerRejected(8)));
    assert_eq!(run_ankald(&ankald_image().bytes, &[inputs[0].bytes(), inputs[1].bytes()], "tail"), Err(AnkaldError::LinkerRejected(8)));
    for (offset, value) in [(112, 2), (120, 1)] {
        let mut changed = inputs[0].bytes().to_vec();
        let symbol = inputs[0].module().header.symbol_offset as usize + 2 * 160;
        set_word(&mut changed, symbol + offset, value);
        if offset == 120 { set_word(&mut changed, symbol + 128, 1); }
        let wrong = vec![ValidatedPointerModule::from_aom(&changed).unwrap(), inputs[1].clone()];
        assert_eq!(run_protected_ankald(&ankald_image().bytes, &wrong), Err(AnkaldError::LinkerRejected(8)));
    }
}

#[test]
fn p108_protected_link_guest_rejects_bad_frame_and_relocation_slots() {
    let inputs = protected_test_modules();
    let caller = inputs[0].module();
    let reloc = caller.header.relocation_offset as usize;
    let rodata = caller.header.rodata_offset as usize;
    for (offset, value) in [(112, (44u64 << 26) | (63u64 << 58)),
        (rodata + 24, 1), (rodata + 32, 8), (reloc + 8, 0), (reloc + 40, 1),
        (112 + 8, (50u64 << 26) | 1 | (63u64 << 58)),
        (112 + 16, (50u64 << 26) | 1 | (63u64 << 58)), (112 + 8, 50u64 << 26)] {
        let mut bad = inputs[0].bytes().to_vec(); set_word(&mut bad, offset, value);
        assert_eq!(run_ankald(&ankald_image().bytes, &[&bad, inputs[1].bytes()], "main"),
            Err(AnkaldError::LinkerRejected(9)), "offset={offset} value={value}");
    }
    let mut duplicate = inputs[0].bytes().to_vec();
    duplicate.extend_from_slice(&inputs[0].bytes()[reloc..reloc+48]);
    let total = duplicate.len() as u64;
    set_word(&mut duplicate, 24, total); set_word(&mut duplicate, 104, 2);
    assert_eq!(run_ankald(&ankald_image().bytes, &[&duplicate, inputs[1].bytes()], "main"), Err(AnkaldError::LinkerRejected(9)));
    let mut missing = inputs[0].bytes()[..reloc].to_vec();
    set_word(&mut missing, 24, reloc as u64); set_word(&mut missing, 104, 0);
    assert_eq!(run_ankald(&ankald_image().bytes, &[&missing, inputs[1].bytes()], "main"), Err(AnkaldError::LinkerRejected(9)));
    let mut large_tag = inputs[0].bytes().to_vec();
    set_word(&mut large_tag, caller.header.symbol_offset as usize + 112, 1 << 62);
    assert_eq!(run_ankald(&ankald_image().bytes, &[&large_tag, inputs[1].bytes()], "main"), Err(AnkaldError::LinkerRejected(2)));
}

#[test]
fn p108_protected_link_checks_every_guest_patch_and_metadata_field() {
    use super::ankald::{run_protected_ankald, validate_protected_link_result};
    let inputs = protected_test_modules();
    let image = run_protected_ankald(&ankald_image().bytes, &inputs).unwrap();
    for (pc, word) in [(8, (50u32 << 26) | 8), // valid frame, wrong imported function
        (16, (50u32 << 26) | 0x3ffffc), // changed internal CALL, still valid code
        (88, (45u32 << 26) | (6 << 22)), // legal PLOCAL with changed destination
        (76, (63u32 << 26) | 1)] { // noncanonical padding
        let mut changed = image.clone();
        changed.bytes[pc..pc+4].copy_from_slice(&word.to_le_bytes());
        assert_eq!(validate_protected_link_result(&inputs, &changed), Err(AnkaldError::InvalidProtectedResult));
    }
    for (offset, value) in [(112 + 32 + 16, 32), (112 + 32 + 32 + 24, 1)] {
        let mut changed = image.clone(); set_word(&mut changed.bytes, offset, value);
        assert_eq!(validate_protected_link_result(&inputs, &changed), Err(AnkaldError::InvalidProtectedResult));
    }
    let mut changed = image.clone(); changed.bytes.push(0);
    assert_eq!(validate_protected_link_result(&inputs, &changed), Err(AnkaldError::InvalidProtectedResult));
    let mut changed = image.clone(); changed.entry = 40;
    assert_eq!(validate_protected_link_result(&inputs, &changed), Err(AnkaldError::InvalidProtectedResult));
}

#[test]
fn p108_protected_link_limits_frames_and_combined_image_before_execution() {
    use super::ankald::run_protected_ankald;
    use super::pointer_frames::ValidatedPointerModule;
    let inputs = protected_test_modules();
    assert_eq!(run_protected_ankald(&[], &vec![inputs[0].clone(); 2049]), Err(AnkaldError::InvalidProtectedLayout));
    let size = (1024 * 1024 / 5) & !7usize;
    let mut code: Vec<u8> = std::iter::repeat_n((63u32 << 26).to_le_bytes(), size / 4).flatten().collect();
    code[..4].copy_from_slice(&(44u32 << 26).to_le_bytes());
    code[size-16..size-12].copy_from_slice(&(46u32 << 26).to_le_bytes());
    let mut ending = super::isa::Asm64::new(); ending.ret();
    code[size-8..size-4].copy_from_slice(&ending.to_bytes());
    let metadata: Vec<u8> = [1345400887u64, 2, size as u64, 1, 0, size as u64, 16, 0]
        .iter().flat_map(|w| w.to_le_bytes()).collect();
    let bytes = protected_test_aom(&code, &metadata, &[("main", 1, 0, &[])], &[]);
    let module = ValidatedPointerModule::from_aom(&bytes).unwrap();
    assert!(5 * size <= 1024 * 1024);
    assert_eq!(run_protected_ankald(&[], &vec![module; 5]), Err(AnkaldError::InvalidProtectedLayout));
}

#[test]
fn p108_protected_link_preserves_legacy_rodata_and_entry_behavior() {
    use super::isa::Asm64;
    let mut asm = Asm64::new(); asm.movi(0, 42); asm.nop(); asm.ret(); asm.nop();
    let code = asm.to_bytes();
    let rodata = 123u64.to_le_bytes();
    let aom = protected_test_aom(&code, &rodata, &[("entry", 1, 0, &[])], &[]);
    let image = run_ankald(&ankald_image().bytes, &[&aom], "entry").unwrap();
    assert_eq!(image.code_size, code.len() as u64);
    assert_eq!(image.entry, 0);
    assert_eq!(&image.bytes[..code.len()], code);
    assert_eq!(&image.bytes[code.len()..], rodata);
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
