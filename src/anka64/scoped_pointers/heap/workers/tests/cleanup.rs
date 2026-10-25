//! Registry transition witnesses; actual byte/tag effects are tested in Fabric.
use super::*;

fn start(
    t: &mut ScopedPointers,
) -> (
    AllocationOwner,
    HeapReservation,
    CleanupLease,
    HeapCleanupStatus,
) {
    let w = enroll(t, 0);
    let (owner, r) = queued(t);
    let lease = claim(t, w, owner, r);
    let plan = t
        .prepare_heap_retirement(lease, identity(0), owner)
        .unwrap();
    no_alloc(|| t.commit_heap_retirement(plan));
    let plan = t
        .prepare_heap_scrub_begin(lease, identity(0), owner)
        .unwrap();
    let status = no_alloc(|| t.commit_heap_scrub(plan));
    (owner, r, lease, status)
}
fn chunk(
    t: &mut ScopedPointers,
    owner: AllocationOwner,
    status: HeapCleanupStatus,
    amount: u64,
) -> Result<HeapCleanupStatus, HeapError> {
    let plan = t.prepare_heap_scrub_chunk(status, identity(0), owner, amount)?;
    Ok(t.commit_heap_scrub(plan))
}
fn release(
    t: &mut ScopedPointers,
    owner: AllocationOwner,
    status: HeapCleanupStatus,
) -> Result<(), HeapError> {
    let plan = t.prepare_heap_release(status, identity(0), owner)?;
    t.commit_heap_release(plan);
    Ok(())
}

#[test]
fn a238_registry_refunds_payload_once_and_preserves_fixed_charges_and_generation() {
    let mut t = registry(1);
    let (owner, r, _, status) = start(&mut t);
    let fixed = t.fixed_metadata_bytes();
    let status = no_alloc(|| chunk(&mut t, owner, status, 4096)).unwrap();
    assert_eq!(t.total_reserved_bytes(), fixed + 4096);
    assert_eq!(t.account(r.owner).unwrap().reserved, 4096);
    no_alloc(|| release(&mut t, owner, status)).unwrap();
    assert_eq!(t.total_reserved_bytes(), fixed);
    assert_eq!(t.account(r.owner).unwrap().reserved, 0);
    assert_eq!(t.slots[r.slot].generation, r.generation);
    assert_eq!(t.slots[r.slot].state, SlotState::Free);
    assert_eq!(t.slots[r.slot].record, Record::Empty);
    assert!(t.heap.cleanup.iter().all(Option::is_none));
    rejects(&mut t, HeapError::StaleReservation, |t| {
        release(t, owner, status)
    });
    let next = no_alloc(|| t.reserve_heap(r.owner, 31, t.revision())).unwrap();
    assert_eq!(next.slot, r.slot);
    assert_eq!(next.generation, r.generation + 1);
    assert_ne!(next.job, r.job);
}

#[test]
fn a238_registry_release_rejects_missing_virtual_custody_without_returning_physical() {
    let mut t = registry(1);
    let (owner, r, _, status) = start(&mut t);
    let status = no_alloc(|| chunk(&mut t, owner, status, 4096)).unwrap();
    let physical = format!("{:?}", t.heap.placement.as_ref().unwrap().physical);
    t.heap.placement.as_mut().unwrap().virtual_arenas[r.owner.index]
        .bind_owner(Some(r.owner.serial + 1));
    rejects(&mut t, HeapError::StaleReservation, |t| {
        release(t, owner, status)
    });
    assert_eq!(
        format!("{:?}", t.heap.placement.as_ref().unwrap().physical),
        physical
    );
    t.heap.placement.as_mut().unwrap().virtual_arenas[r.owner.index]
        .bind_owner(Some(r.owner.serial));
    no_alloc(|| release(&mut t, owner, status)).unwrap();
}

#[test]
fn a238_registry_versions_and_sequences_exhaust_without_partial_progress() {
    for sequence in [false, true] {
        let mut t = registry(1);
        let (owner, r, lease, _) = start(&mut t);
        let index = t.reservation_record(r).unwrap().cleanup;
        if sequence {
            t.heap.cleanup[index].as_mut().unwrap().sequence = u64::MAX;
        } else {
            t.heap.cleanup[index].as_mut().unwrap().version = u64::MAX;
        }
        let status = HeapCleanupStatus {
            lease,
            job: t.heap.cleanup[index].unwrap(),
        };
        rejects(&mut t, HeapError::Capacity(Resource::Identity), |t| {
            chunk(t, owner, status, 4096)
        });
        assert_eq!(
            t.heap.cleanup[index].unwrap().progress,
            HeapScrubProgress::Scrubbing(0)
        );
    }
}

#[test]
fn a238_registry_release_works_at_last_version_sequence_and_common_revision() {
    let mut t = registry(1);
    let (owner, r, lease, _) = start(&mut t);
    let index = t.reservation_record(r).unwrap().cleanup;
    t.heap.cleanup[index].as_mut().unwrap().version = u64::MAX - 1;
    t.heap.cleanup[index].as_mut().unwrap().sequence = u64::MAX - 1;
    let status = HeapCleanupStatus {
        lease,
        job: t.heap.cleanup[index].unwrap(),
    };
    t.heap.revision = u64::MAX;
    let clean = no_alloc(|| chunk(&mut t, owner, status, 4096)).unwrap();
    assert_eq!(clean.version(), u64::MAX);
    assert_eq!(clean.job.sequence, u64::MAX);
    no_alloc(|| release(&mut t, owner, clean)).unwrap();
    assert_eq!(t.revision(), u64::MAX);
    assert_eq!(t.total_reserved_bytes(), t.fixed_metadata_bytes());
    rejects(&mut t, HeapError::Capacity(Resource::Identity), |t| {
        t.reserve_heap(r.owner, 31, t.revision())
    });
}

#[test]
fn a238_registry_last_slot_generation_returns_backing_but_never_reuses_slot() {
    let mut t = registry(1);
    t.slots[0].generation = u32::MAX - 1;
    let (owner, r, _, status) = start(&mut t);
    let extents = t.reserved_extents(r).unwrap();
    let clean = no_alloc(|| chunk(&mut t, owner, status, 4096)).unwrap();
    no_alloc(|| release(&mut t, owner, clean)).unwrap();
    assert_eq!(t.slots[r.slot].state, SlotState::Exhausted);
    let next = no_alloc(|| t.reserve_heap(r.owner, 31, t.revision())).unwrap();
    assert_ne!(next.slot, r.slot);
    assert_eq!(t.reserved_extents(next).unwrap(), extents);
}

#[test]
fn a238_registry_recovery_invalidates_clean_receipt_and_keeps_sequence_and_charges() {
    let mut t = registry(2);
    let (owner, r, lease, status) = start(&mut t);
    let replacement = enroll(&mut t, 1);
    let clean = no_alloc(|| chunk(&mut t, owner, status, 4096)).unwrap();
    let charge = t.total_reserved_bytes();
    let index = t.reservation_record(r).unwrap().cleanup;
    let prior = t.heap.cleanup[index].unwrap();
    let plan = t.prepare_heap_worker_revoke(lease, owner).unwrap();
    no_alloc(|| t.commit_heap_worker_recovery(plan));
    no_alloc(|| t.fence_cleanup_worker_record(lease.worker)).unwrap();
    let plan = t.prepare_heap_worker_recovery(lease, owner).unwrap();
    no_alloc(|| t.commit_heap_worker_recovery(plan));
    let recovered = t.heap.cleanup[index].unwrap();
    assert_eq!(recovered.progress, HeapScrubProgress::Pending);
    assert_eq!(recovered.sequence, prior.sequence);
    assert_eq!(recovered.version, prior.version + 1);
    assert_eq!(t.total_reserved_bytes(), charge);
    let plan = t
        .prepare_heap_worker_claim(replacement, identity(1), r, owner, t.revision())
        .unwrap();
    let fresh = no_alloc(|| t.commit_heap_worker_claim(plan));
    assert_eq!(fresh.epoch, lease.epoch + 1);
    rejects(&mut t, HeapError::Worker, |t| release(t, owner, clean));
}

#[test]
fn a238_registry_owner_and_worker_rows_release_only_after_last_obligation() {
    let mut t = registry(1);
    let (owner, r, lease, status) = start(&mut t);
    let clean = no_alloc(|| chunk(&mut t, owner, status, 4096)).unwrap();
    no_alloc(|| t.close_owner(r.owner)).unwrap();
    rejects(&mut t, HeapError::Busy, |t| t.release_owner(r.owner));
    no_alloc(|| release(&mut t, owner, clean)).unwrap();
    no_alloc(|| t.release_owner(r.owner)).unwrap();
    no_alloc(|| t.fence_cleanup_worker_record(lease.worker)).unwrap();
    no_alloc(|| t.remove_cleanup_worker_record(lease.worker)).unwrap();
    assert_eq!(t.total_reserved_bytes(), t.fixed_metadata_bytes());
    assert!(t.heap.accounts.iter().all(Option::is_none));
    assert!(t.heap.workers.iter().all(Option::is_none));
}
