//! End-to-end trusted supervisor/role/lease recovery, not guest malloc/free.
use super::*;
use crate::anka64::scoped_pointers::heap::{CleanupLease, CleanupWorker};

fn worker(k: &mut Kernel) -> (ProcessKey, CleanupWorker) {
    let key = process(k);
    let w = no_alloc(|| k.enroll_cleanup_worker(key, k.fabric.scoped_pointers.revision())).unwrap();
    (key, w)
}
fn claim(
    k: &mut Kernel,
    key: ProcessKey,
    w: CleanupWorker,
    a: App,
) -> Result<CleanupLease, HeapError> {
    no_alloc(|| {
        k.claim_heap_cleanup(
            key,
            w,
            a.reservation,
            a.owner,
            a.object,
            k.fabric.scoped_pointers.revision(),
        )
    })
}
fn close(k: &mut Kernel, a: App) {
    no_alloc(|| {
        k.fabric
            .close_attached_heap(a.reservation, a.owner, a.object)
    })
    .unwrap();
}
fn revoke(k: &mut Kernel, a: App, lease: CleanupLease) -> Result<(), HeapError> {
    no_alloc(|| k.revoke_heap_cleanup(lease, a.owner, a.object))
}
fn recover(k: &mut Kernel, a: App, lease: CleanupLease) -> Result<(), HeapError> {
    no_alloc(|| k.recover_heap_cleanup(lease, a.owner, a.object))
}
fn fence(k: &mut Kernel, w: CleanupWorker) {
    no_alloc(|| k.fence_cleanup_worker(w)).unwrap();
}
fn auth(k: &mut Kernel, key: ProcessKey, a: App, lease: CleanupLease) -> Result<(), HeapError> {
    no_alloc(|| k.authenticate_heap_cleanup(key, lease, a.owner, a.object))
}
fn ready(k: &mut Kernel, key: ProcessKey, a: App, lease: CleanupLease) -> bool {
    no_alloc(|| k.heap_cleanup_ready(key, lease, a.owner, a.object)).unwrap()
}

#[test]
fn a236_runtime_recovery_preserves_dirty_backing_tags_initialization_and_all_charges() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 31, false);
    let b = allocation(&mut k, 64, false);
    let (key, w) = worker(&mut k);
    let (new_key, new_w) = worker(&mut k);
    k.fabric.memory.fill(0xa9);
    k.fabric
        .private_heap
        .as_mut()
        .unwrap()
        .shadow
        .fill(Some(a.pointer));
    let a_row = row(&k.fabric, a.object);
    let b_row = row(&k.fabric, b.object);
    close(&mut k, a);
    let lease = claim(&mut k, key, w, a).unwrap();
    let before = snapshot(&k.fabric);
    let charged = k.fabric.scoped_pointers.total_reserved_bytes();
    revoke(&mut k, a, lease).unwrap();
    fence(&mut k, w);
    recover(&mut k, a, lease).unwrap();
    assert_only_registry_changed(before, &k.fabric);
    assert_eq!(row(&k.fabric, a.object), a_row);
    assert_eq!(row(&k.fabric, b.object), b_row);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), charged);
    let fresh = claim(&mut k, new_key, new_w, a).unwrap();
    auth(&mut k, new_key, a, fresh).unwrap();
    assert!(ready(&mut k, new_key, a, fresh)); // drained does not mean initialized/free
    rejects(&mut k, HeapError::Busy, |k| {
        no_alloc(|| k.fabric.scoped_pointers.abort_heap(a.reservation))
    });
    assert!(
        k.fabric
            .private_heap_initialization(
                a.reservation,
                a.owner,
                a.object,
                k.fabric.scoped_pointers.revision()
            )
            .is_err()
    );
}

#[test]
fn a236_runtime_reassignment_preserves_old_worker_application_work_and_other_client() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 64, true);
    let b = allocation(&mut k, 64, true);
    let w =
        no_alloc(|| k.enroll_cleanup_worker(a.key, k.fabric.scoped_pointers.revision())).unwrap();
    let (new_key, new_w) = worker(&mut k);
    let ta = write(&mut k, a, 0, &[77]).unwrap();
    let tb = write(&mut k, b, 0, &[88]).unwrap();
    close(&mut k, a);
    let lease = claim(&mut k, a.key, w, a).unwrap();
    let records = format!("{:?}", work(&k));
    fence(&mut k, w);
    revoke(&mut k, a, lease).unwrap();
    recover(&mut k, a, lease).unwrap();
    assert_eq!(format!("{:?}", work(&k)), records);
    // The removed role is not the submitting application's identity.
    no_alloc(|| k.remove_cleanup_worker(w)).unwrap();
    let replacement = claim(&mut k, new_key, new_w, a).unwrap();
    assert!(!ready(&mut k, new_key, a, replacement));
    no_alloc(|| k.fabric.execute_heap_cpu_work(tb)).unwrap();
    no_alloc(|| k.fabric.finish_heap_cpu_work(tb)).unwrap();
    validate(&mut k, ta).unwrap();
    no_alloc(|| k.fabric.execute_heap_cpu_work(ta)).unwrap();
    no_alloc(|| k.fabric.finish_heap_cpu_work(ta)).unwrap();
    assert!(ready(&mut k, new_key, a, replacement));
    assert_eq!(
        k.fabric.memory[row(&k.fabric, a.object).extents.physical.base as usize],
        77
    );
    assert_eq!(
        k.fabric.memory[row(&k.fabric, b.object).extents.physical.base as usize],
        88
    );
}

#[test]
fn a236_runtime_worker_death_is_not_a_fence_but_exact_cleanup_survives_domain_death() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, false);
    let (key, w) = worker(&mut k);
    close(&mut k, a);
    let lease = claim(&mut k, key, w, a).unwrap();
    k.processes[key.slot].state = ProcessState::Zombie;
    let core = &k.processes[key.slot].core;
    let (agent, domain) = (core.agent, core.domain);
    k.fabric.agents.remove(&agent);
    k.fabric.destroy_domain(domain);
    revoke(&mut k, a, lease).unwrap();
    rejects(&mut k, HeapError::Worker, |k| recover(k, a, lease));
    fence(&mut k, w);
    recover(&mut k, a, lease).unwrap();
    no_alloc(|| k.remove_cleanup_worker(w)).unwrap();
    assert!(
        k.fabric
            .scoped_pointers
            .reserved_extents(a.reservation)
            .is_ok()
    );
}

#[test]
fn a236_runtime_process_slot_reuse_cannot_impersonate_the_retained_worker() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, false);
    let (old_key, old) = worker(&mut k);
    close(&mut k, a);
    let lease = claim(&mut k, old_key, old, a).unwrap();
    k.processes[old_key.slot].generation += 1;
    let key = ProcessKey {
        generation: old_key.generation + 1,
        ..old_key
    };
    rejects(&mut k, HeapError::Worker, |k| auth(k, key, a, lease));
    let new =
        no_alloc(|| k.enroll_cleanup_worker(key, k.fabric.scoped_pointers.revision())).unwrap();
    fence(&mut k, old);
    revoke(&mut k, a, lease).unwrap();
    recover(&mut k, a, lease).unwrap();
    no_alloc(|| k.remove_cleanup_worker(old)).unwrap();
    let new_lease = claim(&mut k, key, new, a).unwrap();
    auth(&mut k, key, a, new_lease).unwrap();
    rejects(&mut k, HeapError::Worker, |k| revoke(k, a, lease));
    rejects(&mut k, HeapError::Worker, |k| recover(k, a, lease));
}

#[test]
fn a236_runtime_recovery_authenticates_owner_and_actual_object_before_mutation() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, false);
    let b = allocation(&mut k, 64, false);
    let (key, w) = worker(&mut k);
    close(&mut k, a);
    let lease = claim(&mut k, key, w, a).unwrap();
    for (bad, error) in [
        (
            App {
                object: b.object,
                ..a
            },
            HeapError::StaleReservation,
        ),
        (
            App {
                owner: b.owner,
                ..a
            },
            HeapError::Owner,
        ),
    ] {
        rejects(&mut k, error, |k| revoke(k, bad, lease));
    }
    fence(&mut k, w);
    revoke(&mut k, a, lease).unwrap();
    for (bad, error) in [
        (
            App {
                object: b.object,
                ..a
            },
            HeapError::StaleReservation,
        ),
        (
            App {
                owner: b.owner,
                ..a
            },
            HeapError::Owner,
        ),
    ] {
        rejects(&mut k, error, |k| recover(k, bad, lease));
    }
    recover(&mut k, a, lease).unwrap();
}

#[test]
fn a236_runtime_changed_custody_cannot_be_recovered_or_dropped() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, false);
    let (key, w) = worker(&mut k);
    close(&mut k, a);
    let lease = claim(&mut k, key, w, a).unwrap();
    fence(&mut k, w);
    revoke(&mut k, a, lease).unwrap();
    let original = row(&k.fabric, a.object);
    k.fabric
        .private_heap
        .as_mut()
        .unwrap()
        .rows
        .iter_mut()
        .flatten()
        .find(|r| r.object == a.object)
        .unwrap()
        .extents
        .physical
        .base += 4096;
    rejects(&mut k, HeapError::StaleReservation, |k| {
        recover(k, a, lease)
    });
    rejects(&mut k, HeapError::Busy, |k| {
        no_alloc(|| k.remove_cleanup_worker(w))
    });
    *k.fabric
        .private_heap
        .as_mut()
        .unwrap()
        .rows
        .iter_mut()
        .flatten()
        .find(|r| r.object == a.object)
        .unwrap() = original;
    recover(&mut k, a, lease).unwrap();
}

#[test]
fn a236_runtime_full_census_rejects_foreign_orphan_source_before_reassignment() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, false);
    let b = allocation(&mut k, 64, true);
    let (key, w) = worker(&mut k);
    let t = read(&mut k, b, 0, 1).unwrap();
    close(&mut k, a);
    let lease = claim(&mut k, key, w, a).unwrap();
    let record = work_mut(&mut k).records[0].take();
    // Fencing is allowed even though backend integrity cannot be established.
    revoke(&mut k, a, lease).unwrap();
    fence(&mut k, w);
    rejects(&mut k, HeapError::StaleWork, |k| recover(k, a, lease));
    work_mut(&mut k).records[0] = record;
    recover(&mut k, a, lease).unwrap();
    validate(&mut k, t).unwrap();
}

fn legacy_conflict(k: &mut Kernel, key: ProcessKey) -> usize {
    let core = &k.processes[key.slot].core;
    let (agent, domain) = (core.agent, core.domain);
    let object = k
        .fabric
        .alloc_object("legacy pending", 64, ObjectKind::Memory);
    assert!(k.fabric.place_object(object, 0x1000));
    k.fabric
        .grant(domain, object, 0, 16, Permissions::RW)
        .unwrap();
    let mut req = request(agent, domain, object, 0, Width::Byte, AccessKind::Write);
    req.length = 16;
    let tx = k.fabric.submit(req, Some(vec![9; 16]));
    k.fabric.advance(tx);
    k.fabric.advance(tx);
    assert_eq!(k.fabric.transactions[tx].state, TxState::Prepared);
    k.fabric.transactions[tx].physical_address = Some(0x1ff8); // hostile bypass fixture
    tx
}

#[test]
fn a236_runtime_legacy_conflict_blocks_recovery_but_not_per_job_revocation() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, false);
    let (key, w) = worker(&mut k);
    close(&mut k, a);
    let lease = claim(&mut k, key, w, a).unwrap();
    let tx = legacy_conflict(&mut k, key);
    revoke(&mut k, a, lease).unwrap();
    fence(&mut k, w);
    rejects(&mut k, HeapError::Busy, |k| recover(k, a, lease));
    let bytes = k.fabric.memory.clone();
    k.fabric.advance(tx);
    assert_eq!(k.fabric.transactions[tx].state, TxState::Faulted);
    assert_eq!(k.fabric.memory, bytes);
    recover(&mut k, a, lease).unwrap();
}

#[test]
fn a236_runtime_saturated_revision_never_replaces_current_exclusion_checks() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, false);
    let (key, w) = worker(&mut k);
    let (next_key, next_w) = worker(&mut k);
    close(&mut k, a);
    let lease = claim(&mut k, key, w, a).unwrap();
    fixture::set_revision(&mut k.fabric.scoped_pointers, u64::MAX);
    assert!(ready(&mut k, key, a, lease));
    let tx = legacy_conflict(&mut k, key);
    fence(&mut k, w);
    revoke(&mut k, a, lease).unwrap();
    rejects(&mut k, HeapError::Busy, |k| recover(k, a, lease));
    assert_eq!(k.fabric.scoped_pointers.revision(), u64::MAX);
    k.fabric.advance(tx);
    recover(&mut k, a, lease).unwrap();
    assert_eq!(k.fabric.scoped_pointers.revision(), u64::MAX);
    rejects(&mut k, HeapError::StaleRevision, |k| {
        claim(k, next_key, next_w, a)
    });
}

#[test]
fn a236_runtime_recovery_does_not_consume_completed_application_tickets() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    let (key, w) = worker(&mut k);
    let (next_key, next_w) = worker(&mut k);
    let t = read(&mut k, a, 0, 1).unwrap();
    no_alloc(|| k.fabric.execute_heap_cpu_work(t)).unwrap();
    close(&mut k, a);
    let lease = claim(&mut k, key, w, a).unwrap();
    fence(&mut k, w);
    revoke(&mut k, a, lease).unwrap();
    recover(&mut k, a, lease).unwrap();
    let before = snapshot(&k.fabric);
    rejects(&mut k, HeapError::Lease, |k| recover(k, a, lease));
    assert_eq!(snapshot(&k.fabric), before);
    let replacement = claim(&mut k, next_key, next_w, a).unwrap();
    assert!(!ready(&mut k, next_key, a, replacement));
    assert_eq!(
        no_alloc(|| k.fabric.heap_work_census(a.reservation, a.owner, a.object))
            .unwrap()
            .cpu,
        1
    );
    assert_eq!(
        no_alloc(|| k.fabric.finish_heap_cpu_work(t)).unwrap(),
        HeapWorkOutcome::Committed
    );
    assert!(ready(&mut k, next_key, a, replacement));
}

#[test]
fn a236_runtime_recovered_job_still_requires_a_current_replacement_worker() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, false);
    let (key, w) = worker(&mut k);
    let (next_key, next_w) = worker(&mut k);
    close(&mut k, a);
    let lease = claim(&mut k, key, w, a).unwrap();
    fence(&mut k, w);
    revoke(&mut k, a, lease).unwrap();
    recover(&mut k, a, lease).unwrap();
    k.processes[next_key.slot].state = ProcessState::Zombie;
    rejects(&mut k, HeapError::Worker, |k| claim(k, next_key, next_w, a));
    k.processes[next_key.slot].state = ProcessState::Running;
    let replacement = claim(&mut k, next_key, next_w, a).unwrap();
    auth(&mut k, next_key, a, replacement).unwrap();
}

#[test]
fn a236_runtime_worker_row_churn_without_cpu_backend_keeps_fixed_storage_and_backing() {
    let mut k = Kernel::new(
        Fabric::with_private_heap_and_workers(0x10000, limits(), profile(), 1).unwrap(),
    );
    let a = allocation(&mut k, 64, false);
    let key = process(&mut k);
    close(&mut k, a);
    let fixed = k.fabric.scoped_pointers.fixed_metadata_bytes();
    let charges = k.fabric.scoped_pointers.total_reserved_bytes();
    let before = snapshot(&k.fabric);
    let mut old = None;
    for _ in 0..16 {
        let w =
            no_alloc(|| k.enroll_cleanup_worker(key, k.fabric.scoped_pointers.revision())).unwrap();
        let lease = claim(&mut k, key, w, a).unwrap();
        if let Some(prior) = old {
            rejects(&mut k, HeapError::Worker, |k| revoke(k, a, prior));
            rejects(&mut k, HeapError::Worker, |k| recover(k, a, prior));
        }
        revoke(&mut k, a, lease).unwrap();
        fence(&mut k, w);
        recover(&mut k, a, lease).unwrap();
        no_alloc(|| k.remove_cleanup_worker(w)).unwrap();
        old = Some(lease);
    }
    assert_eq!(k.fabric.scoped_pointers.fixed_metadata_bytes(), fixed);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), charges);
    assert_only_registry_changed(before, &k.fabric);
}
