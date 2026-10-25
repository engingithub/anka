use super::*;
mod recovery;
mod retirement;
mod cleanup;
use crate::anka64::placement::{PhysicalExtent, VirtualExtent};

fn limits() -> RegistryLimits {
    RegistryLimits {
        slots: 4,
        scopes: 2,
        owners: 2,
        cleanup: 4,
        global_bytes: 1 << 20,
    }
}
fn placement() -> HeapPlacementLimits {
    HeapPlacementLimits {
        physical_pool: PhysicalExtent {
            base: 0x2000,
            size: 0x4000,
        },
        physical_claims: 4,
        virtual_window: VirtualExtent {
            base: 0x10000,
            size: 0x8000,
        },
        per_owner_claims: 4,
    }
}
fn registry(capacity: usize) -> ScopedPointers {
    ScopedPointers::with_heap_placement_and_workers(limits(), placement(), capacity).unwrap()
}
fn identity(slot: usize) -> CleanupWorkerIdentity {
    CleanupWorkerIdentity {
        process: ProcessKey {
            slot,
            generation: 0,
        },
        context: 100 + slot as u64,
        domain: DomainId(slot as u64),
    }
}
fn enroll(t: &mut ScopedPointers, slot: usize) -> CleanupWorker {
    no_alloc(|| t.enroll_cleanup_worker_record(identity(slot), t.revision())).unwrap()
}
fn queued(t: &mut ScopedPointers) -> (AllocationOwner, HeapReservation) {
    let owner = AllocationOwner {
        process: ProcessKey {
            slot: 20,
            generation: 0,
        },
        context: 200,
        domain: DomainId(20),
    };
    let a = t.admit_owner(owner, 0x4000).unwrap();
    let r = t.reserve_heap(a, 31, t.revision()).unwrap();
    let p = t.prepare_heap_attachment(r, owner, t.revision()).unwrap();
    t.commit_heap_attachment(p);
    let p = t.prepare_attached_heap_closure(r, owner).unwrap();
    t.commit_attached_heap_closure(p);
    (owner, r)
}
fn claim(
    t: &mut ScopedPointers,
    w: CleanupWorker,
    owner: AllocationOwner,
    r: HeapReservation,
) -> CleanupLease {
    no_alloc(|| {
        let p = t
            .prepare_heap_worker_claim(w, identity(0), r, owner, t.revision())
            .unwrap();
        t.commit_heap_worker_claim(p)
    })
}
fn rejects<T: std::fmt::Debug>(
    t: &mut ScopedPointers,
    error: HeapError,
    op: impl FnOnce(&mut ScopedPointers) -> Result<T, HeapError>,
) {
    let before = format!("{t:?}");
    assert_eq!(no_alloc(|| op(t)).unwrap_err(), error);
    assert_eq!(format!("{t:?}"), before);
}

#[test]
fn a235a_worker_storage_is_precharged_by_actual_capacity() {
    let plain = ScopedPointers::with_heap_placement(limits(), placement()).unwrap();
    let t = registry(3);
    let retained = t.heap.workers.capacity() * size_of::<Option<WorkerRecord>>();
    assert_eq!(t.heap.workers.len(), 3);
    assert_eq!(
        t.fixed_metadata_bytes(),
        plain.fixed_metadata_bytes() + retained as u64
    );
    let fixed = t.fixed_metadata_bytes();
    let tight = RegistryLimits {
        global_bytes: fixed,
        ..limits()
    };
    let mut exact = ScopedPointers::with_heap_placement_and_workers(tight, placement(), 3).unwrap();
    let before = exact.fixed_metadata_bytes();
    let w = enroll(&mut exact, 0);
    no_alloc(|| exact.fence_cleanup_worker_record(w)).unwrap();
    no_alloc(|| exact.remove_cleanup_worker_record(w)).unwrap();
    assert_eq!(exact.fixed_metadata_bytes(), before);
    assert_eq!(exact.total_reserved_bytes(), before);
    assert!(matches!(
        ScopedPointers::with_heap_placement_and_workers(
            RegistryLimits {
                global_bytes: fixed - 1,
                ..limits()
            },
            placement(),
            3
        ),
        Err(HeapError::Capacity(Resource::GlobalBytes))
    ));
    assert!(matches!(
        ScopedPointers::with_heap_placement_and_workers(limits(), placement(), usize::MAX),
        Err(HeapError::Configuration)
    ));
}

#[test]
fn a235a_enrollment_is_bounded_unique_and_separate_from_owner_accounts() {
    let mut zero = registry(0);
    rejects(&mut zero, HeapError::Capacity(Resource::Workers), |t| {
        t.enroll_cleanup_worker_record(identity(0), t.revision())
    });
    let mut t = registry(1);
    let w = enroll(&mut t, 0);
    assert!(t.heap.accounts.iter().all(Option::is_none));
    assert_eq!(w.row, 1);
    assert_eq!(w.serial, 1);
    rejects(&mut t, HeapError::Worker, |t| {
        t.enroll_cleanup_worker_record(
            CleanupWorkerIdentity {
                context: 999,
                ..identity(0)
            },
            t.revision(),
        )
    });
    rejects(&mut t, HeapError::Worker, |t| {
        t.enroll_cleanup_worker_record(
            CleanupWorkerIdentity {
                context: 0,
                ..identity(1)
            },
            t.revision(),
        )
    });
    rejects(&mut t, HeapError::Capacity(Resource::Workers), |t| {
        t.enroll_cleanup_worker_record(identity(1), t.revision())
    });
    no_alloc(|| t.fence_cleanup_worker_record(w)).unwrap();
    // A retained fenced incarnation is still not available for re-enrollment.
    rejects(&mut t, HeapError::Worker, |t| {
        t.enroll_cleanup_worker_record(identity(0), t.revision())
    });
}

#[test]
fn a235a_worker_handles_never_resurrect_after_directory_row_reuse() {
    let mut t = registry(1);
    let old = enroll(&mut t, 0);
    rejects(&mut t, HeapError::Worker, |t| {
        t.remove_cleanup_worker_record(old)
    });
    no_alloc(|| t.fence_cleanup_worker_record(old)).unwrap();
    no_alloc(|| t.remove_cleanup_worker_record(old)).unwrap();
    let new = enroll(&mut t, 0);
    assert_eq!(old.row, new.row);
    assert!(new.serial > old.serial);
    for stale in [
        old,
        CleanupWorker { row: 0, ..new },
        CleanupWorker {
            row: u32::MAX,
            ..new
        },
        CleanupWorker { serial: 0, ..new },
    ] {
        rejects(&mut t, HeapError::Worker, |t| {
            t.fence_cleanup_worker_record(stale)
        });
        assert_eq!(t.current_worker(stale, identity(0)), Err(HeapError::Worker));
    }
    assert_eq!(t.current_worker(new, identity(0)), Ok(()));
}

#[test]
fn a235a_identity_and_revision_exhaustion_never_wrap_or_drop_roles() {
    let mut t = registry(2);
    t.heap.next_worker = u64::MAX - 1;
    let last = enroll(&mut t, 0);
    assert_eq!(last.serial, u64::MAX - 1);
    rejects(&mut t, HeapError::Capacity(Resource::Identity), |t| {
        t.enroll_cleanup_worker_record(identity(1), t.revision())
    });
    t.heap.next_worker = 0; // hostile internal-state fixture
    rejects(&mut t, HeapError::Capacity(Resource::Identity), |t| {
        t.enroll_cleanup_worker_record(identity(1), t.revision())
    });
    t.heap.revision = u64::MAX;
    rejects(&mut t, HeapError::StaleRevision, |t| {
        t.enroll_cleanup_worker_record(identity(1), t.revision())
    });
    no_alloc(|| t.fence_cleanup_worker_record(last)).unwrap();
    no_alloc(|| t.remove_cleanup_worker_record(last)).unwrap();
    assert_eq!(t.revision(), u64::MAX);
    assert_eq!(t.heap.next_worker, 0); // cleanup never resets the issuance fence
}

#[test]
fn a235a_claim_keeps_the_pending_row_extents_account_and_backing_charge() {
    let mut t = registry(2);
    let w = enroll(&mut t, 0);
    let (owner, r) = queued(&mut t);
    let record = t.reservation_record(r).unwrap();
    let placement = format!("{:?}", t.heap.placement);
    let account = *t.account(r.owner).unwrap();
    let charged = t.total_reserved_bytes();
    let rev = t.revision();
    let lease = claim(&mut t, w, owner, r);
    assert_eq!(lease.epoch, 1);
    assert_eq!(t.revision(), rev + 1);
    assert_eq!(t.reservation_record(r).unwrap(), record);
    assert_eq!(
        t.heap.cleanup[record.cleanup].unwrap(),
        CleanupRecord {
            reservation: r,
            queued: true,
            lease: JobLease::Held {
                epoch: 1,
                worker: w
            },
            version: 0,
            sequence: 0,
            progress: workers::HeapScrubProgress::Pending,
        }
    );
    assert_eq!(t.total_reserved_bytes(), charged);
    assert_eq!(*t.account(r.owner).unwrap(), account);
    assert_eq!(format!("{:?}", t.heap.placement), placement);
    rejects(&mut t, HeapError::Lease, |t| {
        t.prepare_heap_worker_claim(w, identity(0), r, owner, t.revision())
    });
    assert!(
        t.prepare_heap_worker_lease(lease, identity(0), owner)
            .is_ok()
    );
    assert_eq!(t.abort_heap(r), Err(HeapError::Busy));
}

#[test]
fn a235a_lease_checks_every_identity_epoch_and_reservation_component() {
    let mut t = registry(2);
    let w = enroll(&mut t, 0);
    let other = enroll(&mut t, 1);
    let (owner, r) = queued(&mut t);
    let lease = claim(&mut t, w, owner, r);
    for bad in [
        identity(1),
        CleanupWorkerIdentity {
            context: 999,
            ..identity(0)
        },
        CleanupWorkerIdentity {
            domain: DomainId(999),
            ..identity(0)
        },
        CleanupWorkerIdentity {
            process: ProcessKey {
                slot: 0,
                generation: 1,
            },
            ..identity(0)
        },
    ] {
        rejects(&mut t, HeapError::Worker, |t| {
            t.prepare_heap_worker_lease(lease, bad, owner)
        });
    }
    for bad in [
        CleanupLease { epoch: 0, ..lease },
        CleanupLease { epoch: 2, ..lease },
        CleanupLease {
            worker: other,
            ..lease
        },
    ] {
        let id = if bad.worker == other {
            identity(1)
        } else {
            identity(0)
        };
        rejects(&mut t, HeapError::Lease, |t| {
            t.prepare_heap_worker_lease(bad, id, owner)
        });
    }
    for bad in [
        HeapReservation {
            slot: usize::MAX,
            ..r
        },
        HeapReservation {
            job: r.job + 1,
            ..r
        },
        HeapReservation {
            generation: r.generation + 1,
            ..r
        },
    ] {
        rejects(&mut t, HeapError::StaleReservation, |t| {
            t.prepare_heap_worker_lease(
                CleanupLease {
                    reservation: bad,
                    ..lease
                },
                identity(0),
                owner,
            )
        });
    }
}

#[test]
fn a235a_last_lease_epoch_is_valid_but_exhaustion_and_stale_plans_reject() {
    let mut t = registry(1);
    let w = enroll(&mut t, 0);
    let (owner, r) = queued(&mut t);
    let index = t.reservation_record(r).unwrap().cleanup;
    t.heap.cleanup[index].as_mut().unwrap().lease = JobLease::Unowned { epoch: u64::MAX };
    rejects(&mut t, HeapError::Capacity(Resource::Identity), |t| {
        t.prepare_heap_worker_claim(w, identity(0), r, owner, t.revision())
    });
    t.heap.cleanup[index].as_mut().unwrap().lease = JobLease::Unowned {
        epoch: u64::MAX - 1,
    };
    let stale = t.revision() - 1;
    rejects(&mut t, HeapError::StaleRevision, |t| {
        t.prepare_heap_worker_claim(w, identity(0), r, owner, stale)
    });
    t.heap.revision = u64::MAX - 1;
    let lease = claim(&mut t, w, owner, r);
    assert_eq!(lease.epoch, u64::MAX);
    assert_eq!(t.revision(), u64::MAX);
    assert!(
        t.prepare_heap_worker_lease(lease, identity(0), owner)
            .is_ok()
    );
    rejects(&mut t, HeapError::StaleRevision, |t| {
        t.prepare_heap_worker_claim(w, identity(0), r, owner, t.revision())
    });
    no_alloc(|| t.fence_cleanup_worker_record(w)).unwrap();
    assert_eq!(t.revision(), u64::MAX);
    rejects(&mut t, HeapError::Worker, |t| {
        t.prepare_heap_worker_lease(lease, identity(0), owner)
    });
    rejects(&mut t, HeapError::Busy, |t| {
        t.remove_cleanup_worker_record(w)
    });
}

#[test]
fn a235a_revoking_and_fenced_jobs_cannot_be_reclaimed_by_another_worker() {
    let mut t = registry(2);
    let w = enroll(&mut t, 0);
    let other = enroll(&mut t, 1);
    let (owner, r) = queued(&mut t);
    let lease = claim(&mut t, w, owner, r);
    let index = t.reservation_record(r).unwrap().cleanup;
    // Later recovery must not accidentally treat Revoking as Unowned.
    t.heap.cleanup[index].as_mut().unwrap().lease = JobLease::Revoking {
        epoch: lease.epoch,
        worker: w,
    };
    rejects(&mut t, HeapError::Lease, |t| {
        t.prepare_heap_worker_lease(lease, identity(0), owner)
    });
    no_alloc(|| t.fence_cleanup_worker_record(w)).unwrap();
    rejects(&mut t, HeapError::Lease, |t| {
        t.prepare_heap_worker_claim(other, identity(1), r, owner, t.revision())
    });
    rejects(&mut t, HeapError::Busy, |t| {
        t.remove_cleanup_worker_record(w)
    });
}

#[test]
fn a235a_claim_rejects_broken_queue_custody_and_placement_without_mutation() {
    let mut t = registry(1);
    let w = enroll(&mut t, 0);
    let (owner, r) = queued(&mut t);
    let index = t.reservation_record(r).unwrap().cleanup;
    t.heap.cleanup[index].as_mut().unwrap().queued = false;
    rejects(&mut t, HeapError::Configuration, |t| {
        t.prepare_heap_worker_claim(w, identity(0), r, owner, t.revision())
    });
    t.heap.cleanup[index].as_mut().unwrap().queued = true;
    let Record::Heap(record) = &mut t.slots[r.slot].record else {
        unreachable!()
    };
    record.extents.as_mut().unwrap().physical.base += 4096;
    let before = format!("{t:?}");
    assert!(
        no_alloc(|| t.prepare_heap_worker_claim(w, identity(0), r, owner, t.revision())).is_err()
    );
    assert_eq!(format!("{t:?}"), before);
}
