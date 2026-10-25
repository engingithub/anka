use super::*;
use crate::anka64::placement::{PhysicalExtent, VirtualExtent};

fn attached() -> (
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
            cleanup: 4,
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

fn rejects(t: &ScopedPointers, owner: AllocationOwner, r: HeapReservation, error: HeapError) {
    let before = format!("{t:?}");
    assert_eq!(
        no_alloc(|| t.prepare_heap_initialization(r, owner, t.revision())).unwrap_err(),
        error
    );
    assert_eq!(format!("{t:?}"), before);
}

#[test]
fn a232_registry_terminal_revision_fences_init_but_allows_owner_close() {
    let (mut t, owner, account, r) = attached();
    let charged = t.total_reserved_bytes();
    t.heap.revision = u64::MAX - 1;
    let plan = no_alloc(|| t.prepare_heap_initialization(r, owner, t.revision())).unwrap();
    no_alloc(|| t.commit_heap_initialization(plan));
    assert_eq!(t.revision(), u64::MAX);
    rejects(&t, owner, r, HeapError::Capacity(Resource::Identity));
    assert_eq!(no_alloc(|| t.close_owner(account)), Ok(1));
    assert_eq!(t.revision(), u64::MAX);
    assert_eq!(t.total_reserved_bytes(), charged);
    assert_eq!(no_alloc(|| t.abort_heap(r)), Err(HeapError::Busy));
}

#[test]
fn a232_registry_excludes_live_closing_queued_and_published_lifetimes() {
    for mode in 0..4 {
        let (mut t, owner, _, r) = attached();
        let record = t.reservation_record(r).unwrap();
        match mode {
            0 => t.slots[r.slot].state = SlotState::Live,
            1 => t.slots[r.slot].state = SlotState::Closing,
            2 => t.heap.cleanup[record.cleanup].as_mut().unwrap().queued = true,
            _ => {
                let Record::Heap(record) = &mut t.slots[r.slot].record else {
                    unreachable!()
                };
                record.published = true;
            }
        }
        rejects(&t, owner, r, HeapError::Busy);
    }
}

#[test]
fn a232_registry_rechecks_cleanup_binding_and_both_extent_claims() {
    for mode in 0..3 {
        let (mut t, owner, account, r) = attached();
        let other = t.reserve_heap(account, 31, t.revision()).unwrap();
        let record = t.reservation_record(r).unwrap();
        if mode == 0 {
            t.heap.cleanup[record.cleanup].as_mut().unwrap().reservation = other;
        } else {
            let Record::Heap(record) = &mut t.slots[r.slot].record else {
                unreachable!()
            };
            let extents = record.extents.as_mut().unwrap();
            if mode == 1 {
                extents.physical.base += 4096;
            } else {
                extents.virtual_extent.base += 4096;
            }
        }
        rejects(&t, owner, r, HeapError::StaleReservation);
    }
}
