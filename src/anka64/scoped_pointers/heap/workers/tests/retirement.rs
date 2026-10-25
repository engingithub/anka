use super::*;

fn retire(
    t: &mut ScopedPointers,
    lease: CleanupLease,
    owner: AllocationOwner,
) -> Result<(), HeapError> {
    let plan = t.prepare_heap_retirement(lease, identity(0), owner)?;
    t.commit_heap_retirement(plan);
    Ok(())
}

#[test]
fn a237_retirement_preserves_identity_job_lease_custody_and_all_charges() {
    let mut t = registry(1);
    let w = enroll(&mut t, 0);
    let (owner, r) = queued(&mut t);
    let lease = claim(&mut t, w, owner, r);
    let record = t.reservation_record(r).unwrap();
    let job = t.heap.cleanup[record.cleanup];
    let account = *t.account(r.owner).unwrap();
    let placement = format!("{:?}", t.heap.placement);
    let identities = (t.heap.next_job, t.heap.next_owner, t.heap.next_worker);
    let charges = (t.fixed_metadata_bytes(), t.total_reserved_bytes());
    let revision = t.revision();
    no_alloc(|| retire(&mut t, lease, owner)).unwrap();
    assert_eq!(t.slots[r.slot].state, SlotState::Retired);
    assert_eq!(t.slots[r.slot].generation, r.generation);
    assert_eq!(t.reservation_record(r), Ok(record));
    assert_eq!(t.heap.cleanup[record.cleanup], job);
    assert_eq!(*t.account(r.owner).unwrap(), account);
    assert_eq!(format!("{:?}", t.heap.placement), placement);
    assert_eq!(
        (t.heap.next_job, t.heap.next_owner, t.heap.next_worker),
        identities
    );
    assert_eq!(
        (t.fixed_metadata_bytes(), t.total_reserved_bytes()),
        charges
    );
    assert_eq!(t.revision(), revision + 1);
}

#[test]
fn a237_duplicate_closure_and_owner_death_never_reopen_retired_allocation() {
    let mut t = registry(1);
    let w = enroll(&mut t, 0);
    let (owner, r) = queued(&mut t);
    let lease = claim(&mut t, w, owner, r);
    no_alloc(|| retire(&mut t, lease, owner)).unwrap();
    for closed in [false, true] {
        if closed {
            no_alloc(|| t.close_owner(r.owner)).unwrap();
        }
        let before = format!("{t:?}");
        no_alloc(|| {
            let plan = t.prepare_attached_heap_closure(r, owner).unwrap();
            assert_eq!(
                t.commit_attached_heap_closure(plan),
                HeapCloseOutcome::AlreadyRetired
            );
        });
        assert_eq!(format!("{t:?}"), before);
        rejects(&mut t, HeapError::Lease, |t| retire(t, lease, owner));
        rejects(&mut t, HeapError::Busy, |t| t.abort_heap(r));
    }
    rejects(&mut t, HeapError::Busy, |t| t.release_owner(r.owner));
}

#[test]
fn a237_retired_slot_and_extents_remain_unavailable_to_new_reservations() {
    let mut t = registry(1);
    let w = enroll(&mut t, 0);
    let (owner, r) = queued(&mut t);
    let extents = t.reserved_extents(r).unwrap();
    let lease = claim(&mut t, w, owner, r);
    no_alloc(|| retire(&mut t, lease, owner)).unwrap();
    let next = no_alloc(|| t.reserve_heap(r.owner, 31, t.revision())).unwrap();
    assert_ne!(next.slot, r.slot);
    let other = t.reserved_extents(next).unwrap();
    assert_ne!(extents.physical, other.physical);
    assert_ne!(extents.virtual_extent, other.virtual_extent);
    assert_eq!(t.reserved_extents(r), Ok(extents));
    assert!(t.is_heap_pointer(super::super::super::cell_test_support::token(r, 0)));
}

#[test]
fn a237_retirement_needs_no_remaining_generation_lease_version_or_revision_headroom() {
    let mut t = registry(1);
    t.slots[0].generation = u32::MAX - 1;
    let w = enroll(&mut t, 0);
    let (owner, r) = queued(&mut t);
    assert_eq!(r.generation, u32::MAX);
    let index = t.reservation_record(r).unwrap().cleanup;
    t.heap.cleanup[index].as_mut().unwrap().lease = JobLease::Unowned {
        epoch: u64::MAX - 1,
    };
    let lease = claim(&mut t, w, owner, r);
    t.heap.cleanup[index].as_mut().unwrap().version = u64::MAX;
    t.heap.revision = u64::MAX;
    no_alloc(|| retire(&mut t, lease, owner)).unwrap();
    assert_eq!(t.revision(), u64::MAX);
    assert_eq!(t.slots[r.slot].state, SlotState::Retired);
    assert_eq!(t.slots[r.slot].generation, u32::MAX);
    assert_eq!(t.heap.cleanup[index].unwrap().version, u64::MAX);
    assert_eq!(
        t.heap.cleanup[index].unwrap().lease,
        JobLease::Held {
            epoch: u64::MAX,
            worker: w
        }
    );
}

#[test]
fn a237_retired_worker_failure_requires_explicit_fencing_and_recovery() {
    let mut t = registry(1);
    let w = enroll(&mut t, 0);
    let (owner, r) = queued(&mut t);
    let lease = claim(&mut t, w, owner, r);
    no_alloc(|| retire(&mut t, lease, owner)).unwrap();
    rejects(&mut t, HeapError::Lease, |t| {
        t.prepare_heap_worker_claim(w, identity(0), r, owner, t.revision())
    });
    rejects(&mut t, HeapError::Lease, |t| t.prepare_heap_worker_recovery(lease, owner));
    let plan = t.prepare_heap_worker_revoke(lease, owner).unwrap();
    no_alloc(|| t.commit_heap_worker_recovery(plan));
    rejects(&mut t, HeapError::Worker, |t| t.prepare_heap_worker_recovery(lease, owner));
    no_alloc(|| t.fence_cleanup_worker_record(w)).unwrap();
    rejects(&mut t, HeapError::Busy, |t| t.remove_cleanup_worker_record(w));
    let plan = t.prepare_heap_worker_recovery(lease, owner).unwrap();
    no_alloc(|| t.commit_heap_worker_recovery(plan));
    no_alloc(|| t.remove_cleanup_worker_record(w)).unwrap();
    assert_eq!(t.slots[r.slot].state, SlotState::Retired);
    assert!(t.reserved_extents(r).is_ok());
}

#[test]
fn a237_wrong_epoch_revoking_and_fenced_leases_cannot_retire() {
    let mut t = registry(1);
    let w = enroll(&mut t, 0);
    let (owner, r) = queued(&mut t);
    let lease = claim(&mut t, w, owner, r);
    rejects(&mut t, HeapError::Lease, |t| {
        retire(t, CleanupLease { epoch: 0, ..lease }, owner)
    });
    let plan = t.prepare_heap_worker_revoke(lease, owner).unwrap();
    no_alloc(|| t.commit_heap_worker_recovery(plan));
    rejects(&mut t, HeapError::Lease, |t| retire(t, lease, owner));
    no_alloc(|| t.fence_cleanup_worker_record(w)).unwrap();
    rejects(&mut t, HeapError::Worker, |t| retire(t, lease, owner));
}
