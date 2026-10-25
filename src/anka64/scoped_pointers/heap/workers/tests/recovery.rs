use super::*;

fn revoke(
    t: &mut ScopedPointers,
    lease: CleanupLease,
    owner: AllocationOwner,
) -> Result<(), HeapError> {
    let plan = t.prepare_heap_worker_revoke(lease, owner)?;
    t.commit_heap_worker_recovery(plan);
    Ok(())
}
fn recover(
    t: &mut ScopedPointers,
    lease: CleanupLease,
    owner: AllocationOwner,
) -> Result<(), HeapError> {
    let plan = t.prepare_heap_worker_recovery(lease, owner)?;
    t.commit_heap_worker_recovery(plan);
    Ok(())
}
fn extra_job(
    t: &mut ScopedPointers,
    owner: AllocationOwner,
    account: OwnerAccount,
) -> HeapReservation {
    let r = t.reserve_heap(account, 64, t.revision()).unwrap();
    let p = t.prepare_heap_attachment(r, owner, t.revision()).unwrap();
    t.commit_heap_attachment(p);
    let p = t.prepare_attached_heap_closure(r, owner).unwrap();
    t.commit_attached_heap_closure(p);
    r
}
fn reclaim(
    t: &mut ScopedPointers,
    w: CleanupWorker,
    id: CleanupWorkerIdentity,
    r: HeapReservation,
    owner: AllocationOwner,
) -> Result<CleanupLease, HeapError> {
    let p = t.prepare_heap_worker_claim(w, id, r, owner, t.revision())?;
    Ok(t.commit_heap_worker_claim(p))
}

#[test]
fn a236_recovery_preserves_custody_pending_charges_and_epoch_until_reclaim() {
    let mut t = registry(2);
    let old = enroll(&mut t, 0);
    let new = enroll(&mut t, 1);
    let (owner, r) = queued(&mut t);
    let lease = claim(&mut t, old, owner, r);
    let record = t.reservation_record(r).unwrap();
    let placement = format!("{:?}", t.heap.placement);
    let account = *t.account(r.owner).unwrap();
    let charges = t.total_reserved_bytes();
    let fixed = t.fixed_metadata_bytes();
    let identities = (t.heap.next_worker, t.heap.next_owner, t.heap.next_job);
    let before = t.revision();
    no_alloc(|| revoke(&mut t, lease, owner)).unwrap();
    assert_eq!(t.revision(), before + 1);
    assert_eq!(t.heap.cleanup[record.cleanup].unwrap().version, 0);
    no_alloc(|| t.fence_cleanup_worker_record(old)).unwrap();
    no_alloc(|| recover(&mut t, lease, owner)).unwrap();
    let job = t.heap.cleanup[record.cleanup].unwrap();
    assert!(job.queued);
    assert_eq!(job.lease, JobLease::Unowned { epoch: lease.epoch });
    assert_eq!(job.version, 1);
    assert_eq!(t.slots[r.slot].state, SlotState::Closing);
    assert_eq!(t.reservation_record(r).unwrap(), record);
    assert_eq!(format!("{:?}", t.heap.placement), placement);
    assert_eq!(*t.account(r.owner).unwrap(), account);
    assert_eq!(
        (t.total_reserved_bytes(), t.fixed_metadata_bytes()),
        (charges, fixed)
    );
    assert_eq!(
        (t.heap.next_worker, t.heap.next_owner, t.heap.next_job),
        identities
    );
    let replacement = no_alloc(|| reclaim(&mut t, new, identity(1), r, owner)).unwrap();
    assert_eq!(replacement.epoch, lease.epoch + 1);
    assert_eq!(t.heap.cleanup[record.cleanup].unwrap().version, 1);
    // Even replacing the worker in a copied stale receipt cannot erase its epoch.
    rejects(&mut t, HeapError::Lease, |t| {
        t.prepare_heap_worker_lease(
            CleanupLease {
                worker: new,
                ..lease
            },
            identity(1),
            owner,
        )
    });
}

#[test]
fn a236_revocation_is_per_job_and_claim_never_skips_revoking_state() {
    let mut t = registry(2);
    let w = enroll(&mut t, 0);
    let other = enroll(&mut t, 1);
    let (owner, a) = queued(&mut t);
    let b = extra_job(&mut t, owner, a.owner);
    let la = claim(&mut t, w, owner, a);
    let lb = claim(&mut t, w, owner, b);
    let b_job = t.heap.cleanup[t.reservation_record(b).unwrap().cleanup];
    no_alloc(|| revoke(&mut t, la, owner)).unwrap();
    assert_eq!(t.worker(w).unwrap().state, WorkerState::Active);
    rejects(&mut t, HeapError::Lease, |t| {
        t.prepare_heap_worker_lease(la, identity(0), owner)
    });
    assert!(t.prepare_heap_worker_lease(lb, identity(0), owner).is_ok());
    assert_eq!(
        t.heap.cleanup[t.reservation_record(b).unwrap().cleanup],
        b_job
    );
    rejects(&mut t, HeapError::Lease, |t| {
        reclaim(t, other, identity(1), a, owner)
    });
}

#[test]
fn a236_recovery_requires_both_exact_revocation_and_global_worker_fence() {
    let mut t = registry(1);
    let w = enroll(&mut t, 0);
    let (owner, r) = queued(&mut t);
    let lease = claim(&mut t, w, owner, r);
    rejects(&mut t, HeapError::Lease, |t| recover(t, lease, owner));
    no_alloc(|| revoke(&mut t, lease, owner)).unwrap();
    rejects(&mut t, HeapError::Worker, |t| recover(t, lease, owner));
    no_alloc(|| t.fence_cleanup_worker_record(w)).unwrap();
    no_alloc(|| recover(&mut t, lease, owner)).unwrap();
    rejects(&mut t, HeapError::Lease, |t| recover(t, lease, owner));
    rejects(&mut t, HeapError::Lease, |t| revoke(t, lease, owner));
}

#[test]
fn a236_recovery_rejects_wrong_owner_worker_epoch_and_reservation() {
    let mut t = registry(2);
    let w = enroll(&mut t, 0);
    let other = enroll(&mut t, 1);
    let (owner, r) = queued(&mut t);
    let lease = claim(&mut t, w, owner, r);
    for bad in [
        CleanupLease { epoch: 0, ..lease },
        CleanupLease { epoch: 2, ..lease },
        CleanupLease {
            worker: other,
            ..lease
        },
    ] {
        rejects(&mut t, HeapError::Lease, |t| revoke(t, bad, owner));
    }
    no_alloc(|| t.fence_cleanup_worker_record(w)).unwrap();
    no_alloc(|| revoke(&mut t, lease, owner)).unwrap();
    for bad in [
        CleanupLease { epoch: 0, ..lease },
        CleanupLease { epoch: 2, ..lease },
        CleanupLease {
            worker: other,
            ..lease
        },
    ] {
        rejects(&mut t, HeapError::Lease, |t| recover(t, bad, owner));
    }
    let bad = CleanupLease {
        worker: CleanupWorker {
            serial: w.serial + 20,
            ..w
        },
        ..lease
    };
    rejects(&mut t, HeapError::Worker, |t| recover(t, bad, owner));
    for bad_r in [
        HeapReservation {
            job: r.job + 1,
            ..r
        },
        HeapReservation {
            generation: r.generation + 1,
            ..r
        },
        HeapReservation {
            slot: usize::MAX,
            ..r
        },
    ] {
        rejects(&mut t, HeapError::StaleReservation, |t| {
            recover(
                t,
                CleanupLease {
                    reservation: bad_r,
                    ..lease
                },
                owner,
            )
        });
    }
    rejects(&mut t, HeapError::Owner, |t| {
        recover(
            t,
            lease,
            AllocationOwner {
                context: owner.context + 1,
                ..owner
            },
        )
    });
}

#[test]
fn a236_recovery_version_exhaustion_retains_quarantine_but_never_blocks_revocation() {
    for version in [u64::MAX - 1, u64::MAX] {
        let mut t = registry(1);
        let w = enroll(&mut t, 0);
        let (owner, r) = queued(&mut t);
        let lease = claim(&mut t, w, owner, r);
        let index = t.reservation_record(r).unwrap().cleanup;
        t.heap.cleanup[index].as_mut().unwrap().version = version;
        no_alloc(|| revoke(&mut t, lease, owner)).unwrap();
        no_alloc(|| t.fence_cleanup_worker_record(w)).unwrap();
        if version == u64::MAX {
            rejects(&mut t, HeapError::Capacity(Resource::Identity), |t| {
                recover(t, lease, owner)
            });
            assert_eq!(
                t.heap.cleanup[index].unwrap().lease,
                JobLease::Revoking {
                    epoch: 1,
                    worker: w
                }
            );
        } else {
            no_alloc(|| recover(&mut t, lease, owner)).unwrap();
        }
        assert_eq!(t.heap.cleanup[index].unwrap().version, u64::MAX);
        assert!(t.heap.cleanup[index].unwrap().queued);
        assert!(t.reserved_extents(r).is_ok());
    }
}

#[test]
fn a236_exhausted_lease_epoch_is_not_reset_by_recovery() {
    let mut t = registry(2);
    let w = enroll(&mut t, 0);
    let replacement = enroll(&mut t, 1);
    let (owner, r) = queued(&mut t);
    let index = t.reservation_record(r).unwrap().cleanup;
    t.heap.cleanup[index].as_mut().unwrap().lease = JobLease::Unowned {
        epoch: u64::MAX - 1,
    };
    let lease = claim(&mut t, w, owner, r);
    assert_eq!(lease.epoch, u64::MAX);
    no_alloc(|| t.fence_cleanup_worker_record(w)).unwrap();
    no_alloc(|| revoke(&mut t, lease, owner)).unwrap();
    no_alloc(|| recover(&mut t, lease, owner)).unwrap();
    rejects(&mut t, HeapError::Capacity(Resource::Identity), |t| {
        reclaim(t, replacement, identity(1), r, owner)
    });
    assert_eq!(
        t.heap.cleanup[index].unwrap().lease,
        JobLease::Unowned { epoch: u64::MAX }
    );
}

#[test]
fn a236_saturated_revision_allows_cleanup_but_not_fresh_claims() {
    let mut t = registry(2);
    let w = enroll(&mut t, 0);
    let replacement = enroll(&mut t, 1);
    let (owner, r) = queued(&mut t);
    let lease = claim(&mut t, w, owner, r);
    t.heap.revision = u64::MAX;
    no_alloc(|| t.fence_cleanup_worker_record(w)).unwrap();
    no_alloc(|| revoke(&mut t, lease, owner)).unwrap();
    no_alloc(|| recover(&mut t, lease, owner)).unwrap();
    no_alloc(|| t.remove_cleanup_worker_record(w)).unwrap();
    assert_eq!(t.revision(), u64::MAX);
    rejects(&mut t, HeapError::StaleRevision, |t| {
        reclaim(t, replacement, identity(1), r, owner)
    });
}

#[test]
fn a236_worker_removal_waits_for_every_held_and_revoking_job() {
    let mut t = registry(1);
    let w = enroll(&mut t, 0);
    let (owner, a) = queued(&mut t);
    let b = extra_job(&mut t, owner, a.owner);
    let la = claim(&mut t, w, owner, a);
    let lb = claim(&mut t, w, owner, b);
    no_alloc(|| t.fence_cleanup_worker_record(w)).unwrap();
    no_alloc(|| revoke(&mut t, la, owner)).unwrap();
    rejects(&mut t, HeapError::Busy, |t| {
        t.remove_cleanup_worker_record(w)
    });
    no_alloc(|| recover(&mut t, la, owner)).unwrap();
    rejects(&mut t, HeapError::Busy, |t| {
        t.remove_cleanup_worker_record(w)
    });
    no_alloc(|| revoke(&mut t, lb, owner)).unwrap();
    rejects(&mut t, HeapError::Busy, |t| {
        t.remove_cleanup_worker_record(w)
    });
    no_alloc(|| recover(&mut t, lb, owner)).unwrap();
    no_alloc(|| t.remove_cleanup_worker_record(w)).unwrap();
    let new = enroll(&mut t, 0);
    assert_eq!(w.row, new.row);
    assert!(new.serial > w.serial);
    rejects(&mut t, HeapError::Worker, |t| revoke(t, la, owner));
    rejects(&mut t, HeapError::Worker, |t| recover(t, lb, owner));
}

#[test]
fn a236_recovery_does_not_reset_exhausted_worker_issuance() {
    let mut t = registry(1);
    let w = enroll(&mut t, 0);
    let (owner, r) = queued(&mut t);
    let lease = claim(&mut t, w, owner, r);
    t.heap.next_worker = u64::MAX;
    no_alloc(|| t.fence_cleanup_worker_record(w)).unwrap();
    no_alloc(|| revoke(&mut t, lease, owner)).unwrap();
    no_alloc(|| recover(&mut t, lease, owner)).unwrap();
    no_alloc(|| t.remove_cleanup_worker_record(w)).unwrap();
    rejects(&mut t, HeapError::Capacity(Resource::Identity), |t| {
        t.enroll_cleanup_worker_record(identity(1), t.revision())
    });
    assert_eq!(t.heap.next_worker, u64::MAX);
}
