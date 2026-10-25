use super::*;
use crate::anka64::placement::{PhysicalExtent, VirtualExtent};

fn setup() -> (
    ScopedPointers,
    AllocationOwner,
    OwnerAccount,
    HeapReservation,
) {
    let mut t = ScopedPointers::with_heap_placement(
        RegistryLimits {
            slots: 4,
            scopes: 2,
            owners: 2,
            cleanup: 2,
            global_bytes: 1 << 20,
        },
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
        },
    )
    .unwrap();
    let owner = AllocationOwner {
        process: ProcessKey {
            slot: 0,
            generation: 0,
        },
        context: 1,
        domain: DomainId(0),
    };
    let account = t.admit_owner(owner, 0x4000).unwrap();
    let r = t.reserve_heap(account, 31, t.revision()).unwrap();
    let plan = t.prepare_heap_attachment(r, owner, t.revision()).unwrap();
    t.commit_heap_attachment(plan);
    (t, owner, account, r)
}

fn close(t: &mut ScopedPointers, owner: AllocationOwner, r: HeapReservation) -> HeapCloseOutcome {
    no_alloc(|| {
        let plan = t.prepare_attached_heap_closure(r, owner).unwrap();
        t.commit_attached_heap_closure(plan)
    })
}

fn rejects(t: &ScopedPointers, owner: AllocationOwner, r: HeapReservation, error: HeapError) {
    let before = format!("{t:?}");
    assert_eq!(
        no_alloc(|| t.prepare_attached_heap_closure(r, owner)).unwrap_err(),
        error
    );
    assert_eq!(format!("{t:?}"), before);
}

#[test]
fn a234_registry_close_queues_exact_job_once_and_retains_all_custody() {
    let (mut t, owner, account, r) = setup();
    let other = t.reserve_heap(account, 1, t.revision()).unwrap();
    let record = t.reservation_record(r).unwrap();
    let other_record = t.reservation_record(other).unwrap();
    let placement = format!("{:?}", t.heap.placement);
    let charged = t.total_reserved_bytes();
    let account_before = *t.account(account).unwrap();
    let ids = (t.heap.next_owner, t.heap.next_job);
    let rev = t.revision();
    assert_eq!(close(&mut t, owner, r), HeapCloseOutcome::Closed);
    assert_eq!(t.revision(), rev + 1);
    assert_eq!(t.slots[r.slot].state, SlotState::Closing);
    assert_eq!(t.reservation_record(r).unwrap(), record);
    assert_eq!(
        t.heap.cleanup[record.cleanup],
        Some(CleanupRecord {
            reservation: r,
            queued: true,
            lease: workers::JobLease::EMPTY,
            version: 0,
            sequence: 0,
            progress: workers::HeapScrubProgress::Pending,
        })
    );
    assert_eq!(t.slots[other.slot].state, SlotState::Reserved);
    assert_eq!(t.reservation_record(other).unwrap(), other_record);
    assert!(!t.heap.cleanup[other_record.cleanup].unwrap().queued);
    assert_eq!(*t.account(account).unwrap(), account_before);
    assert_eq!(t.total_reserved_bytes(), charged);
    assert_eq!(format!("{:?}", t.heap.placement), placement);
    assert_eq!((t.heap.next_owner, t.heap.next_job), ids);
    let before = format!("{t:?}");
    assert_eq!(close(&mut t, owner, r), HeapCloseOutcome::AlreadyClosing);
    assert_eq!(format!("{t:?}"), before);
    assert_eq!(no_alloc(|| t.abort_heap(r)), Err(HeapError::Busy));
}

#[test]
fn a234_registry_full_queue_and_exhausted_counters_do_not_block_closure() {
    for revision in [u64::MAX - 1, u64::MAX] {
        let (mut t, owner, account, r) = setup();
        let _other = t.reserve_heap(account, 1, t.revision()).unwrap();
        assert!(t.heap.cleanup.iter().all(Option::is_some));
        t.heap.revision = revision;
        t.heap.next_owner = u64::MAX;
        t.heap.next_job = u64::MAX;
        let charged = t.total_reserved_bytes();
        assert_eq!(close(&mut t, owner, r), HeapCloseOutcome::Closed);
        assert_eq!(t.revision(), u64::MAX);
        assert_eq!((t.heap.next_owner, t.heap.next_job), (u64::MAX, u64::MAX));
        assert_eq!(t.total_reserved_bytes(), charged);
        assert_eq!(close(&mut t, owner, r), HeapCloseOutcome::AlreadyClosing);
        assert_eq!(no_alloc(|| t.close_owner(account)), Ok(1));
        assert_eq!(close(&mut t, owner, r), HeapCloseOutcome::AlreadyClosing);
        assert_eq!(t.revision(), u64::MAX);
        assert_eq!(no_alloc(|| t.release_owner(account)), Err(HeapError::Busy));
    }
}

#[test]
fn a234_registry_stale_and_never_attached_reservations_cannot_select_a_job() {
    let (mut t, owner, account, r) = setup();
    let private = t.reserve_heap(account, 1, t.revision()).unwrap();
    rejects(&t, owner, private, HeapError::Busy);
    for bad in [
        HeapReservation {
            slot: usize::MAX,
            ..r
        },
        HeapReservation {
            generation: r.generation + 1,
            ..r
        },
        HeapReservation {
            job: r.job + 1,
            ..r
        },
        HeapReservation {
            slot: private.slot,
            ..r
        },
    ] {
        rejects(&t, owner, bad, HeapError::StaleReservation);
    }
    rejects(
        &t,
        owner,
        HeapReservation {
            owner: OwnerAccount {
                serial: account.serial + 1,
                ..account
            },
            ..r
        },
        HeapError::Owner,
    );
    no_alloc(|| t.abort_heap(private)).unwrap();
    rejects(&t, owner, private, HeapError::StaleReservation);
    assert_eq!(close(&mut t, owner, r), HeapCloseOutcome::Closed);
}

#[test]
fn a234_registry_rechecks_cleanup_index_job_and_both_claims_before_closure() {
    for mode in 0..5 {
        let (mut t, owner, account, r) = setup();
        let other = t.reserve_heap(account, 1, t.revision()).unwrap();
        let record = t.reservation_record(r).unwrap();
        if mode == 0 {
            t.heap.cleanup[record.cleanup] = None;
        } else if mode == 1 {
            t.heap.cleanup[record.cleanup].as_mut().unwrap().reservation = other;
        } else {
            let Record::Heap(record) = &mut t.slots[r.slot].record else {
                unreachable!()
            };
            match mode {
                2 => record.cleanup = usize::MAX,
                3 => record.extents.as_mut().unwrap().physical.base += 4096,
                _ => record.extents.as_mut().unwrap().virtual_extent.base += 4096,
            }
        }
        rejects(&t, owner, r, HeapError::StaleReservation);
    }
}

#[test]
fn a234_registry_inconsistent_stage_queue_and_accounting_fail_without_mutation() {
    for mode in 0..7 {
        let (mut t, owner, account, r) = setup();
        let record = t.reservation_record(r).unwrap();
        match mode {
            0 => t.heap.cleanup[record.cleanup].as_mut().unwrap().queued = true,
            1 => t.slots[r.slot].state = SlotState::Closing,
            2 => t.slots[r.slot].state = SlotState::Live,
            3 => {
                let Record::Heap(record) = &mut t.slots[r.slot].record else {
                    unreachable!()
                };
                record.published = true;
            }
            4 => t.heap.accounts[account.index].as_mut().unwrap().closed = true,
            5 => t.heap.accounts[account.index].as_mut().unwrap().reserved = 0,
            _ => t.heap.reserved_bytes = 0,
        }
        rejects(&t, owner, r, HeapError::Configuration);
    }
}
