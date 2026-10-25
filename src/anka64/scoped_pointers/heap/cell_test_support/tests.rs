use super::*;
use crate::anka64::placement::{PhysicalExtent, VirtualExtent};
use crate::anka64::scoped_pointers::PointerError;

fn setup() -> (
    ScopedPointers,
    AllocationOwner,
    OwnerAccount,
    HeapReservation,
    ScopedPointer,
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
    let a = t.admit_owner(owner, 0x4000).unwrap();
    let r = t.reserve_heap(a, 31, t.revision()).unwrap();
    let plan = t.prepare_heap_attachment(r, owner, t.revision()).unwrap();
    t.commit_heap_attachment(plan);
    let p = activate(&mut t, r);
    (t, owner, a, r, p)
}

#[test]
fn a233_registry_authenticates_cleanup_identity_and_both_manager_claims() {
    for mode in 0..4 {
        let (mut t, owner, a, r, p) = setup();
        let other = t.reserve_heap(a, 31, t.revision()).unwrap();
        let record = t.reservation_record(r).unwrap();
        match mode {
            0 => t.heap.cleanup[record.cleanup].as_mut().unwrap().queued = true,
            1 => t.heap.cleanup[record.cleanup].as_mut().unwrap().reservation = other,
            _ => {
                let Record::Heap(record) = &mut t.slots[r.slot].record else {
                    unreachable!()
                };
                let e = record.extents.as_mut().unwrap();
                if mode == 2 {
                    e.physical.base += 4096;
                } else {
                    e.virtual_extent.base += 4096;
                }
            }
        }
        let before = format!("{t:?}");
        assert_eq!(
            no_alloc(|| t.prepare_heap_pointer(p, owner)).unwrap_err(),
            HeapError::StaleReservation
        );
        assert_eq!(format!("{t:?}"), before);
    }
}

#[test]
fn a233_registry_rejects_partial_publication_and_stale_slot_generation() {
    for mode in 0..4 {
        let (mut t, owner, _, r, p) = setup();
        if mode == 0 {
            t.slots[r.slot].state = SlotState::Reserved;
        } else if mode == 1 {
            t.slots[r.slot].generation += 1;
        } else {
            let Record::Heap(record) = &mut t.slots[r.slot].record else {
                unreachable!()
            };
            if mode == 2 {
                record.published = false;
            } else {
                record.ever_attached = false;
            }
        }
        assert_eq!(
            no_alloc(|| t.prepare_heap_pointer(p, owner)).unwrap_err(),
            HeapError::Pointer(PointerError::Stale)
        );
    }
}
