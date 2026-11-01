use super::*;
use super::super::capture::tests::{aom, captured, prepared, report};
use super::super::tests::{machine, quiet};

fn retained(k: &mut Kernel, slots: usize) -> (CompilerCandidateHandle, CompilerOutputAttempt, Vec<u8>) {
    let bytes = aom(false, slots);
    let mut attempt = prepared(k, &bytes, report(0), 0);
    let handle = captured(k, &mut attempt, RebuildAdmissionRole::RelocatableModule).retain().unwrap();
    (handle, attempt, bytes)
}

fn ready(k: &mut Kernel, handle: &CompilerCandidateHandle) {
    for _ in 0..2000 {
        if k.poll_compiler_candidate(handle).unwrap() { return; }
    }
    panic!("candidate remained blocked after bounded cleanup");
}

#[test]
fn c25_retained_bytes_and_charge_survive_exact_producer_cleanup() {
    let mut k = machine();
    let (handle, attempt, bytes) = retained(&mut k, 1100);
    assert_ne!(handle.custodian, attempt.owner);
    assert!(k.compiler_candidate(&handle).unwrap().is_none());
    assert!(!k.poll_compiler_candidate(&handle).unwrap());
    let account = k.fabric.scoped_pointers.heap_account(handle.custodian).unwrap();
    let held = k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    assert!(held >= bytes.len() as u64);
    ready(&mut k, &handle);
    let view = k.compiler_candidate(&handle).unwrap().unwrap();
    assert_eq!(view.bytes, bytes);
    assert_eq!(view.producer, attempt.owner);
    assert_eq!(view.context.output_capacity(), 16384);
    assert_eq!(view.role, RebuildAdmissionRole::RelocatableModule);
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(), held);
    assert!(k.fabric.read_heap_bytes(attempt.owner, attempt.agent, attempt.output, &mut [0;8]).is_err());
    k.discard_compiler_candidate(&handle).unwrap();
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(), 0);
    assert!(matches!(k.compiler_candidate(&handle), Err(CompilerCandidateError::Unknown)));
}

#[test]
fn c25_retained_a_cleanup_c_reuse_preserves_b_and_candidate() {
    let mut k = machine();
    let bytes = aom(false, 1);
    let mut a = prepared(&mut k, &bytes, report(0), 0);
    let old_extent = k.fabric.diagnostic_heap_extents(a.owner)[0];
    let b = prepared(&mut k, &bytes, report(0), 0);
    let b_account = k.fabric.scoped_pointers.heap_account(b.owner).unwrap();
    let b_charge = k.fabric.scoped_pointers.account_reserved_bytes(b_account).unwrap();
    let handle = captured(&mut k, &mut a, RebuildAdmissionRole::ClosedTranslationUnit).retain().unwrap();
    ready(&mut k, &handle);
    let c = prepared(&mut k, &bytes, report(0), 0);
    assert!(k.fabric.diagnostic_heap_extents(c.owner).iter().any(|e| e.base == old_extent.base));
    assert!(k.fabric.authenticate_heap_token(c.owner, c.agent, a.output).is_err());
    assert_eq!(k.compiler_candidate(&handle).unwrap().unwrap().bytes, bytes);
    let mut actual = vec![0; bytes.len()];
    k.fabric.read_heap_bytes(b.owner, b.agent, b.output, &mut actual).unwrap();
    assert_eq!(actual, bytes);
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(b_account).unwrap(), b_charge);
    assert_eq!(k.processes[b.owner.process.slot].state, ProcessState::Running);
}

#[test]
fn c25_retained_cancel_before_ready_refunds_only_candidate() {
    let mut k = machine();
    let (handle, attempt, _) = retained(&mut k, 1);
    let source_account = k.fabric.scoped_pointers.heap_account(attempt.owner).unwrap();
    let source_charge = k.fabric.scoped_pointers.account_reserved_bytes(source_account).unwrap();
    k.discard_compiler_candidate(&handle).unwrap();
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(source_account).unwrap(), source_charge);
    assert!(!k.fabric.compiler_heap_owner_released(attempt.owner));
    quiet(&mut k);
    assert!(k.fabric.compiler_heap_owner_released(attempt.owner));
}

#[test]
fn c25_retained_quota_denial_preserves_previous_candidate() {
    let mut k = machine();
    let (old, _, bytes) = retained(&mut k, 1);
    ready(&mut k, &old);
    let account = k.fabric.scoped_pointers.heap_account(old.custodian).unwrap();
    let held = k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    let filler = k.fabric.scoped_pointers.reserve_heap(account, 1024*1024-held,
        k.fabric.scoped_pointers.revision()).unwrap();
    let mut attempt = prepared(&mut k, &bytes, report(0), 0);
    let result = captured(&mut k, &mut attempt, RebuildAdmissionRole::RelocatableModule).retain();
    assert!(matches!(result, Err(CompilerCandidateError::Heap(_))));
    assert_eq!(k.compiler_candidate(&old).unwrap().unwrap().bytes, bytes);
    assert_eq!(k.compiler_candidates.records.len(), 1);
    k.fabric.scoped_pointers.abort_heap(filler).unwrap();
    quiet(&mut k);
    assert!(k.fabric.compiler_heap_owner_released(attempt.owner));
}

#[test]
fn c25_retained_wrong_kernel_and_old_handle_cannot_select_new_candidate() {
    let mut a = machine();
    let mut b = machine();
    let (ha, _, _) = retained(&mut a, 1);
    let (hb, _, expected) = retained(&mut b, 1);
    assert!(matches!(b.poll_compiler_candidate(&ha), Err(CompilerCandidateError::Unknown)));
    assert!(matches!(b.discard_compiler_candidate(&ha), Err(CompilerCandidateError::Unknown)));
    ready(&mut b, &hb);
    assert_eq!(b.compiler_candidate(&hb).unwrap().unwrap().bytes, expected);
    a.discard_compiler_candidate(&ha).unwrap();
    quiet(&mut a);
    let (next, _, _) = retained(&mut a, 1);
    assert_ne!(ha.reservation.incarnation(), next.reservation.incarnation());
    assert!(matches!(a.poll_compiler_candidate(&ha), Err(CompilerCandidateError::Unknown)));
}

#[test]
fn c25_retained_service_shutdown_cancels_payload_before_account_teardown() {
    let mut k = machine();
    let (handle, _, _) = retained(&mut k, 1);
    let account = k.fabric.scoped_pointers.heap_account(handle.custodian).unwrap();
    k.stop_heap_service();
    assert!(k.compiler_candidates.records.is_empty());
    assert!(k.heap_service.is_none());
    assert!(k.fabric.scoped_pointers.account_reserved_bytes(account).is_err());
    assert!(matches!(k.compiler_candidate(&handle), Err(CompilerCandidateError::Unknown)));
}

#[test]
fn c25_retained_custodian_death_destroys_candidates_before_owner_closure() {
    let mut k = machine();
    let (handle, _, _) = retained(&mut k, 1);
    let account = k.fabric.scoped_pointers.heap_account(handle.custodian).unwrap();
    k.finish_process(handle.custodian.process.slot, ProcessResult::ProtectionFault);
    assert!(k.compiler_candidates.records.is_empty());
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(), 0);
    assert!(matches!(k.compiler_candidate(&handle), Err(CompilerCandidateError::Unknown)));
}

#[test]
fn c25_retained_unconsumed_work_on_other_producer_region_blocks_readiness() {
    let mut k = machine();
    let bytes = aom(false, 1);
    let mut attempt = prepared(&mut k, &bytes, report(0), 0);
    let account = k.fabric.scoped_pointers.heap_account(attempt.owner).unwrap();
    let reservation = k.fabric.scoped_pointers.reserve_heap(account, 4096,
        k.fabric.scoped_pointers.revision()).unwrap();
    let object = k.fabric.attach_private_heap(reservation, attempt.owner,
        k.fabric.scoped_pointers.revision()).unwrap();
    let init = k.fabric.private_heap_initialization(reservation, attempt.owner, object,
        k.fabric.scoped_pointers.revision()).unwrap();
    let init = k.fabric.initialize_private_heap_chunk(init, attempt.owner, 4096,
        k.fabric.scoped_pointers.revision()).unwrap();
    let current = CurrentHeapProcess::from_processes(&k.processes, attempt.owner.process).unwrap();
    let extra = k.fabric.publish_compiler_region(&current, init, 2, &[], &[]).unwrap().pointer;
    let ticket = k.register_heap_cpu_read(attempt.owner.process, Some(extra), 1,
        k.fabric.scoped_pointers.revision()).unwrap();
    let handle = captured(&mut k, &mut attempt, RebuildAdmissionRole::RelocatableModule).retain().unwrap();
    for _ in 0..100 {
        assert!(!k.poll_compiler_candidate(&handle).unwrap());
        assert!(k.compiler_candidate(&handle).unwrap().is_none());
    }
    k.fabric.cancel_heap_cpu_work(ticket).unwrap();
    k.fabric.finish_heap_cpu_work(ticket).unwrap();
    ready(&mut k, &handle);
    assert_eq!(k.compiler_candidate(&handle).unwrap().unwrap().bytes, bytes);
}
