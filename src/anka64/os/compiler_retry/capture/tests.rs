use super::*;
use super::super::tests::{budget, client, machine, quiet, release};
use crate::anka64::aom::*;
use crate::anka64::compiler_adapter::resources::COMPILER_RESOURCE_MAGIC;

// Canonical single-frame AOM. Optional unresolved import requires module role.
pub(crate) fn aom(import: bool, slots: usize) -> Vec<u8> {
    let mut a = Asm64::new();
    a.pframe(0); a.nop();
    if import { a.call(0); a.nop(); }
    for _ in 0..slots { a.nop(); a.nop(); }
    a.punframe(); a.nop(); a.ret(); a.nop();
    let code = a.to_bytes();
    let metadata: Vec<u8> = [1345400887u64, 2, code.len() as u64, 1,
        0, code.len() as u64, 16, 0].into_iter().flat_map(u64::to_le_bytes).collect();
    let symbols = 1 + u64::from(import);
    let rodata = AOM_HEADER_SIZE + code.len() as u64;
    let symbol_start = rodata + metadata.len() as u64;
    let relocation_start = symbol_start + symbols * AOM_SYMBOL_SIZE;
    let total = relocation_start + u64::from(import) * AOM_RELOCATION_SIZE;
    let mut bytes = AOM_MAGIC.to_vec();
    for word in [1, AOM_HEADER_SIZE, total, AOM_HEADER_SIZE, code.len() as u64,
        8, rodata, metadata.len() as u64, 8, symbol_start, symbols,
        relocation_start, u64::from(import)] { bytes.extend(word.to_le_bytes()); }
    bytes.extend(code); bytes.extend(metadata);
    for index in 0..symbols {
        let name = if index == 0 { b"main" } else { b"help" };
        bytes.extend(4u64.to_le_bytes());
        bytes.extend(name); bytes.extend([0; 60]);
        for word in [if index == 0 { AOM_BINDING_EXPORT } else { AOM_BINDING_IMPORT },
            AOM_SYMBOL_FUNCTION, if index == 0 { AOM_SECTION_CODE } else { AOM_SECTION_UNDEFINED },
            0, 0, 1, 0, 0, 0, 0, 0] { bytes.extend(word.to_le_bytes()); }
    }
    if import {
        for word in [AOM_SECTION_CODE, 8, 8, AOM_RELOC_CALL_PC20, 1, 0] {
            bytes.extend(word.to_le_bytes());
        }
    }
    ValidatedPointerModule::from_aom_with_limit(&bytes, bytes.len() as u64).unwrap();
    bytes
}

pub(crate) fn report(used: u64) -> [u64; 16] {
    [COMPILER_RESOURCE_MAGIC, 2, 10, 1, 0, 0, 0, used, 73, 0, 21, 22, 23, 24, 25, 0]
}

pub(crate) fn prepared(k: &mut Kernel, bytes: &[u8], mut reply: [u64; 16], exit: u64)
    -> CompilerOutputAttempt
{
    let capacity = 16384;
    if reply[7] == 0 { reply[7] = bytes.len() as u64; }
    let key = client(k, capacity, reply, exit, SYS_EXIT);
    let attempt = k.bind_compiler_output_attempt(key, budget(10, capacity)).unwrap();
    // Distinct nonzero tail must never be included in the private candidate.
    let mut arena = vec![0xa5; capacity as usize];
    arena[..bytes.len()].copy_from_slice(bytes);
    for (index, chunk) in arena.chunks(4096).enumerate() {
        let pointer = k.fabric.scoped_pointers.add_heap_pointer(
            attempt.output, attempt.owner, (index * 4096) as i64).unwrap();
        k.fabric.write_heap_bytes(attempt.owner, attempt.agent, pointer, chunk).unwrap();
    }
    attempt
}

pub(crate) fn captured<'k>(k: &'k mut Kernel, attempt: &mut CompilerOutputAttempt,
    role: RebuildAdmissionRole) -> CapturedCompilerOutput<'k>
{
    match k.run_compiler_capture_slice(attempt, 2000, role).unwrap() {
        CompilerCaptureSlice::Captured(output) => output,
        _ => panic!("fixture must reach authenticated exit in one bounded slice"),
    }
}

#[test]
fn c25_capture_three_chunks_exact_tail_and_charge_until_discard() {
    let mut k = machine();
    let bytes = aom(false, 1100);
    assert!(bytes.len() > 8192 && bytes.len() < 12288);
    let mut attempt = prepared(&mut k, &bytes, report(0), 0);
    let account = k.fabric.scoped_pointers.heap_account(attempt.owner).unwrap();
    let before = k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    let output = captured(&mut k, &mut attempt, RebuildAdmissionRole::ClosedTranslationUnit);
    assert_eq!(output.bytes(), bytes);
    assert_eq!(output.role(), RebuildAdmissionRole::ClosedTranslationUnit);
    assert_eq!(output.context().output_capacity(), 16384);
    assert!(output.kernel.fabric.scoped_pointers.account_reserved_bytes(account).unwrap() > before);
    assert_eq!(output.kernel.processes[attempt.owner.process.slot].state, ProcessState::Running);
    drop(output);
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(), before);
    assert_eq!(k.processes[attempt.owner.process.slot].state, ProcessState::Zombie);
    assert!(k.fabric.read_heap_bytes(attempt.owner, attempt.agent, attempt.output, &mut [0; 8]).is_err());
    quiet(&mut k);
    assert!(k.fabric.compiler_heap_owner_released(attempt.owner));
}

#[test]
fn c25_capture_import_requires_module_role_and_never_linked_image_role() {
    let bytes = aom(true, 1);
    for role in [RebuildAdmissionRole::ClosedTranslationUnit, RebuildAdmissionRole::LinkedImage] {
        let mut k = machine();
        let mut attempt = prepared(&mut k, &bytes, report(0), 0);
        assert!(matches!(k.run_compiler_capture_slice(&mut attempt, 2000, role),
            Err(CompilerCaptureError::Admission)));
        quiet(&mut k);
        assert!(k.fabric.compiler_heap_owner_released(attempt.owner));
    }
    let mut k = machine();
    let mut attempt = prepared(&mut k, &bytes, report(0), 0);
    let output = captured(&mut k, &mut attempt, RebuildAdmissionRole::RelocatableModule);
    assert_eq!(output.bytes(), bytes);
}

#[test]
fn c25_capture_rejects_partial_prefix_and_extra_arena_tail() {
    let bytes = aom(false, 1100);
    for used in [bytes.len() as u64 - 8, bytes.len() as u64 + 8] {
        let mut k = machine();
        let mut attempt = prepared(&mut k, &bytes, report(used), 0);
        assert!(matches!(k.run_compiler_capture_slice(&mut attempt, 2000,
            RebuildAdmissionRole::RelocatableModule), Err(CompilerCaptureError::Admission)));
        quiet(&mut k);
        assert!(k.fabric.compiler_heap_owner_released(attempt.owner));
    }
}

#[test]
fn c25_capture_failure_after_copy_preserves_other_client_and_refunds_only_stage() {
    let mut k = machine();
    let good = aom(false, 4);
    let other = prepared(&mut k, &good, report(0), 0);
    let mut bad = good.clone();
    *bad.last_mut().unwrap() = 1; // Invalid unused parameter signature word.
    let mut attempt = prepared(&mut k, &bad, report(0), 0);
    let account = k.fabric.scoped_pointers.heap_account(attempt.owner).unwrap();
    let before = k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    assert!(matches!(k.run_compiler_capture_slice(&mut attempt, 2000,
        RebuildAdmissionRole::RelocatableModule), Err(CompilerCaptureError::Admission)));
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(), before);
    let mut actual = vec![0; good.len()];
    k.fabric.read_heap_bytes(other.owner, other.agent, other.output, &mut actual).unwrap();
    assert_eq!(actual, good);
    assert_eq!(k.processes[other.owner.process.slot].state, ProcessState::Running);
}

#[test]
fn c25_capture_needs_real_zero_exit_and_matching_frozen_reply() {
    let bytes = aom(false, 1);
    for case in 0..3 {
        let mut k = machine();
        let mut words = report(0);
        if case == 1 { words[2] += 1; }
        if case == 2 { words[10] += 1; }
        let mut attempt = prepared(&mut k, &bytes, words, u64::from(case == 0));
        assert!(matches!(k.run_compiler_capture_slice(&mut attempt, 2000,
            RebuildAdmissionRole::RelocatableModule), Err(CompilerCaptureError::Runtime(_))));
        assert_eq!(k.processes[attempt.owner.process.slot].state, ProcessState::Zombie);
    }
}

#[test]
fn c25_capture_rejects_foreign_or_interior_output() {
    for foreign in [false, true] {
        let mut k = machine();
        let bytes = aom(false, 1);
        let other = prepared(&mut k, &bytes, report(0), 0);
        let mut attempt = prepared(&mut k, &bytes, report(0), 0);
        attempt.output = if foreign { other.output } else {
            k.fabric.scoped_pointers.add_heap_pointer(attempt.output, attempt.owner, 8).unwrap()
        };
        assert!(matches!(k.run_compiler_capture_slice(&mut attempt, 2000,
            RebuildAdmissionRole::RelocatableModule), Err(CompilerCaptureError::Runtime(_))));
        assert_eq!(k.processes[other.owner.process.slot].state, ProcessState::Running);
    }
}

#[test]
fn c25_capture_quota_denial_does_not_return_unaccounted_bytes() {
    let mut k = machine();
    let bytes = aom(false, 1100);
    let mut attempt = prepared(&mut k, &bytes, report(0), 0);
    let account = k.fabric.scoped_pointers.heap_account(attempt.owner).unwrap();
    let held = k.fabric.scoped_pointers.reserve_heap(account, 850000,
        k.fabric.scoped_pointers.revision()).unwrap();
    assert!(matches!(k.run_compiler_capture_slice(&mut attempt, 2000,
        RebuildAdmissionRole::RelocatableModule), Err(CompilerCaptureError::Runtime(CompilerRuntimeError::Heap(_)))));
    // This unexposed reservation is still an exact cancellable obligation.
    k.fabric.scoped_pointers.abort_heap(held).unwrap();
    quiet(&mut k);
    assert!(k.fabric.compiler_heap_owner_released(attempt.owner));
}

#[test]
fn c25_capture_capacity_reply_still_requires_actual_cleanup_for_retry() {
    let mut k = machine();
    let mut words = report(0);
    words[4] = 1; words[5] = 3; words[6] = 16385;
    let key = client(&mut k, 16384, words, 0, SYS_EXIT);
    let mut attempt = k.bind_compiler_output_attempt(key, budget(10, 16384)).unwrap();
    let mut pending = match k.run_compiler_capture_slice(&mut attempt, 2000,
        RebuildAdmissionRole::RelocatableModule).unwrap() {
        CompilerCaptureSlice::AwaitingCleanup(pending) => pending,
        _ => panic!("capacity must not yield captured bytes"),
    };
    assert!(attempt.budget.is_none());
    assert!(release(&mut k, &mut pending).context().output_capacity() > 16384);
}

#[test]
fn c25_capture_preflight_bounds_repeated_frame_scan_before_parsing() {
    let bytes = aom(false, 1);
    let mut hostile = bytes.clone();
    let metadata = u64::from_le_bytes(bytes[56..64].try_into().unwrap()) as usize;
    // One frame claiming more code than exists is rejected without allocations.
    hostile[metadata + 40..metadata + 48].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(bounded_manifest(&hostile).is_none());
    assert!(bounded_manifest(&bytes).is_some());
}

#[test]
fn c26_capture_budget_rejects_geometry_and_arithmetic_overflow() {
    assert_eq!(capture_charge(262152, 524288), Some(8392960));
    assert_eq!(capture_charge(262152, 1048576), Some(8392960));
    for (used, capacity) in [(104,4096), (262153,524288), (262152,262144),
        (1u64 << 59,1u64 << 59), (112,u64::MAX)] {
        assert_eq!(capture_charge(used,capacity), None);
    }
}

#[test]
fn c27_capture_full_guest_pool_still_allows_charged_host_capture_and_preserves_peer() {
    let mut k=machine();let bytes=aom(false,1100);
    let mut a=prepared(&mut k,&bytes,report(0),0);
    let b=prepared(&mut k,&bytes,report(0),0);
    let ba=k.fabric.scoped_pointers.heap_account(b.owner).unwrap();
    let b_before=k.fabric.scoped_pointers.account_reserved_bytes(ba).unwrap();
    let (_,ca)=k.compiler_candidate_account().unwrap();
    let a_account=k.fabric.scoped_pointers.heap_account(a.owner).unwrap();
    let a_before=k.fabric.scoped_pointers.account_reserved_bytes(a_account).unwrap();
    assert_eq!(a_before,20480);assert_eq!(b_before,20480);
    // Occupy every remaining guest page with unrelated exact reservations.
    let n=1024*1024-20480;
    let bp=k.fabric.scoped_pointers.reserve_heap(ba,n,k.fabric.scoped_pointers.revision()).unwrap();
    let cp=k.fabric.scoped_pointers.reserve_heap(ca,n,k.fabric.scoped_pointers.revision()).unwrap();
    let b_extent=k.fabric.scoped_pointers.reserved_extents(bp).unwrap();
    let output=captured(&mut k,&mut a,RebuildAdmissionRole::ClosedTranslationUnit);
    assert_eq!(output.bytes(),bytes);
    assert!(output.kernel.fabric.scoped_pointers.account_reserved_bytes(a_account).unwrap()>a_before);
    assert_eq!(output.kernel.fabric.scoped_pointers.reserved_extents(bp).unwrap(),b_extent);
    drop(output);
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(a_account).unwrap(),a_before);
    k.fabric.scoped_pointers.abort_heap(bp).unwrap();k.fabric.scoped_pointers.abort_heap(cp).unwrap();
    let mut actual=vec![0;bytes.len()];
    for (i,chunk) in actual.chunks_mut(4096).enumerate() {
        let p=k.fabric.scoped_pointers.add_heap_pointer(b.output,b.owner,(i*4096) as i64).unwrap();
        k.fabric.read_heap_bytes(b.owner,b.agent,p,chunk).unwrap();
    }
    assert_eq!(actual,bytes);assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(ba).unwrap(),b_before);
    assert_eq!(k.processes[b.owner.process.slot].state,ProcessState::Running);
    quiet(&mut k);assert!(k.fabric.compiler_heap_owner_released(a.owner));
}

pub(crate) fn typed_aom() -> Vec<u8> {
    fn word(v:&mut Vec<u8>,x:u64){v.extend(x.to_le_bytes());}
    fn name(v:&mut Vec<u8>,s:&str){let mut b=[0;64];b[..s.len()].copy_from_slice(s.as_bytes());v.extend(b);}
    let mut bytes=aom(true,1);let parsed=AomModule::parse(&bytes).unwrap();
    let mut tail=b"ANKATY1\0".to_vec();for n in [1,0,1,2]{word(&mut tail,n);}
    name(&mut tail,"Node");for _ in 0..6{word(&mut tail,0);}
    for (name_text,binding,kind,depth,tag) in [("main",1,1,0,""),("help",2,4,1,"Node")] {
        name(&mut tail,name_text);word(&mut tail,binding);word(&mut tail,0);
        word(&mut tail,kind);word(&mut tail,depth);name(&mut tail,tag);tail.extend([0;320]);
    }
    let n=tail.len() as u64;tail[16..24].copy_from_slice(&n.to_le_bytes());
    let at=parsed.header.symbol_offset as usize+160+112;
    bytes[at..at+8].copy_from_slice(&1004u64.to_le_bytes());bytes.extend(tail);
    let n=bytes.len() as u64;bytes[8..16].copy_from_slice(&2u64.to_le_bytes());bytes[24..32].copy_from_slice(&n.to_le_bytes());
    ValidatedPointerModule::from_aom(&bytes).unwrap();bytes
}

#[test]
fn c35_capture_charges_and_retains_the_exact_typed_trailer() {
    let mut k=machine();let bytes=typed_aom();
    let mut a=prepared(&mut k,&bytes,report(0),0);
    let account=k.fabric.scoped_pointers.heap_account(a.owner).unwrap();
    let before=k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    let output=captured(&mut k,&mut a,RebuildAdmissionRole::RelocatableModule);
    assert_eq!(output.bytes(),bytes);
    assert!(output.kernel.fabric.scoped_pointers.account_reserved_bytes(account).unwrap()>before);
    assert!(!AomModule::parse(output.bytes()).unwrap().interface.is_empty());
    drop(output);assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(),before);
}
