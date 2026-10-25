use super::*;
use crate::anka64::scoped_pointers::PointerError;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

// Thread-local measurement avoids counting other tests/harness threads. Tracking
// is enabled only around the actual operation, never its snapshot/diagnostics.
struct CountAlloc;
thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
fn allocation() {
    let _ = TRACK.try_with(|t| {
        if t.get() {
            let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        }
    });
}
unsafe impl GlobalAlloc for CountAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocation();
        unsafe { System.realloc(p, layout, size) }
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: CountAlloc = CountAlloc;

fn no_alloc<T>(f: impl FnOnce() -> T) -> T {
    struct Stop;
    impl Drop for Stop {
        fn drop(&mut self) {
            TRACK.with(|t| t.set(false));
        }
    }
    ALLOCATIONS.with(|n| n.set(0));
    TRACK.with(|t| {
        assert!(!t.replace(true));
    });
    let stop = Stop;
    let result = f();
    drop(stop);
    assert_eq!(
        ALLOCATIONS.with(Cell::get),
        0,
        "operation allocated host storage"
    );
    result
}

fn owner(n: usize, generation: u32) -> AllocationOwner {
    AllocationOwner {
        process: ProcessKey {
            slot: n,
            generation,
        },
        context: 100 + n as u64,
        domain: DomainId(7 + n as u64),
    }
}
fn limits(slots: usize, owners: usize, cleanup: usize) -> RegistryLimits {
    RegistryLimits {
        slots,
        scopes: slots,
        owners,
        cleanup,
        global_bytes: u64::MAX,
    }
}
fn profile(pc: usize, vc: usize, physical_pages: u64, virtual_pages: u64) -> HeapPlacementLimits {
    HeapPlacementLimits {
        physical_pool: PhysicalExtent {
            base: 0x1000,
            size: 4096 * physical_pages,
        },
        physical_claims: pc,
        virtual_window: VirtualExtent {
            base: 0x10000,
            size: 4096 * virtual_pages,
        },
        per_owner_claims: vc,
    }
}
fn table(l: RegistryLimits, p: HeapPlacementLimits, budget: u64) -> ScopedPointers {
    let mut t = ScopedPointers::with_heap_placement(l, p).unwrap();
    t.heap.limit = t.fixed_metadata_bytes().checked_add(budget).unwrap();
    t
}
fn reserve(t: &mut ScopedPointers, a: OwnerAccount, n: u64) -> HeapReservation {
    t.reserve_heap(a, n, t.revision()).unwrap()
}
fn unchanged<T: std::fmt::Debug + PartialEq>(
    t: &mut ScopedPointers,
    error: HeapError,
    f: impl FnOnce(&mut ScopedPointers) -> Result<T, HeapError>,
) {
    let before = format!("{t:?}");
    let fixed = t.fixed_metadata_bytes();
    assert_eq!(f(t), Err(error));
    assert_eq!(format!("{t:?}"), before);
    assert_eq!(t.fixed_metadata_bytes(), fixed);
}
fn placement(t: &ScopedPointers) -> &HeapPlacement {
    t.heap.placement.as_ref().unwrap()
}

/// Independent complete row census plus full sorted partition reconstruction.
fn census(t: &ScopedPointers) {
    let p = placement(t);
    p.physical.audit_reservations();
    let mut global = 0;
    let mut claims = 0;
    for (i, account) in t.heap.accounts.iter().enumerate() {
        p.virtual_arenas[i].audit_reservations();
        if let Some(account) = account {
            let mut charge = 0;
            let mut owner_claims = 0;
            for (slot_index, s) in t.slots.iter().enumerate() {
                if let Record::Heap(record) = s.record {
                    if record.owner != account.token {
                        continue;
                    }
                    let job = t.heap.cleanup[record.cleanup].unwrap();
                    let key = job.reservation.key();
                    assert_eq!(key.owner, account.token.serial);
                    assert_eq!(key.slot as usize, slot_index + 1);
                    assert_eq!(key.generation, s.generation);
                    assert_eq!(job.queued, s.state == SlotState::Closing);
                    let e = record.extents.unwrap();
                    assert_eq!(e.physical.size, record.rounded);
                    assert_eq!(e.virtual_extent.size, record.rounded);
                    assert_eq!(t.reserved_extents(job.reservation), Ok(e));
                    assert!(record.logical > 0 && record.logical <= record.rounded);
                    charge += record.rounded;
                    owner_claims += 1;
                }
            }
            assert_eq!(charge, account.reserved);
            assert!(charge <= account.limit);
            assert_eq!(p.virtual_arenas[i].reservation_count(), owner_claims);
            global += charge;
            claims += owner_claims;
        } else {
            assert_eq!(p.virtual_arenas[i].reservation_count(), 0);
        }
    }
    assert_eq!(global, t.heap.reserved_bytes);
    assert_eq!(claims, p.physical.reservation_count());
    assert_eq!(claims, t.heap.cleanup.iter().flatten().count());
    assert_eq!(
        claims,
        t.slots
            .iter()
            .filter(|s| matches!(s.record, Record::Heap(_)))
            .count()
    );
    assert!(t.total_reserved_bytes() <= t.heap.limit);
}

#[test]
fn a22_complete_reservation_commits_once_with_exact_four_record_identity() {
    let mut t = table(limits(4, 2, 4), profile(4, 3, 12, 6), 65536);
    let a = t.admit_owner(owner(0, 0), 32768).unwrap();
    let revision = t.revision();
    let r = reserve(&mut t, a, 4097);
    assert_eq!(t.revision(), revision + 1);
    assert_eq!(r.generation, 1);
    assert_eq!(r.job, 1);
    assert_eq!(
        t.reserved_extents(r),
        Ok(HeapExtents {
            physical: PhysicalExtent {
                base: 0x1000,
                size: 8192
            },
            virtual_extent: VirtualExtent {
                base: 0x10000,
                size: 8192
            }
        })
    );
    assert_eq!(t.account_reserved_bytes(a), Ok(8192));
    let pointer = ScopedPointer {
        slot: r.slot,
        generation: r.generation,
        position: 0,
    };
    assert_eq!(t.resolve(pointer, 7, 1, false), Err(PointerError::Stale));
    assert_eq!(t.backing(pointer), None);
    census(&t);
}

#[test]
fn a22_capacity_denials_stutter_every_manager_record_and_counter() {
    let cases = [
        (
            limits(4, 1, 4),
            profile(0, 4, 8, 8),
            32768,
            32768,
            HeapError::PhysicalPlacement(PlacementError::ReservationCapacity),
        ),
        (
            limits(4, 1, 4),
            profile(4, 0, 8, 8),
            32768,
            32768,
            HeapError::VirtualPlacement(PlacementError::ReservationCapacity),
        ),
        (
            limits(0, 1, 4),
            profile(4, 4, 8, 8),
            32768,
            32768,
            HeapError::Capacity(Resource::Slots),
        ),
        (
            limits(4, 1, 0),
            profile(4, 4, 8, 8),
            32768,
            32768,
            HeapError::Capacity(Resource::Cleanup),
        ),
        (
            limits(4, 1, 4),
            profile(4, 4, 8, 8),
            4095,
            32768,
            HeapError::Capacity(Resource::GlobalBytes),
        ),
        (
            limits(4, 1, 4),
            profile(4, 4, 8, 8),
            32768,
            4095,
            HeapError::Capacity(Resource::OwnerBytes),
        ),
    ];
    for (l, p, budget, quota, error) in cases {
        let mut t = table(l, p, budget);
        let a = t.admit_owner(owner(0, 0), quota).unwrap();
        unchanged(&mut t, error, |t| t.reserve_heap(a, 1, t.revision()));
        census(&t);
    }
}

#[test]
fn a22_full_claim_tables_reject_with_free_bytes_then_reuse_the_same_capacity() {
    for physical_first in [true, false] {
        let p = if physical_first {
            profile(1, 4, 8, 8)
        } else {
            profile(4, 1, 8, 8)
        };
        let mut t = table(limits(4, 1, 4), p, 32768);
        let a = t.admit_owner(owner(0, 0), 32768).unwrap();
        let r = reserve(&mut t, a, 1);
        let fixed = t.fixed_metadata_bytes();
        assert!(placement(&t).physical.free_bytes() >= 4096);
        let error = if physical_first {
            HeapError::PhysicalPlacement(PlacementError::ReservationCapacity)
        } else {
            HeapError::VirtualPlacement(PlacementError::ReservationCapacity)
        };
        unchanged(&mut t, error, |t| {
            no_alloc(|| t.reserve_heap(a, 1, t.revision()))
        });
        no_alloc(|| t.abort_heap(r)).unwrap();
        let next = no_alloc(|| reserve(&mut t, a, 1));
        assert_eq!(next.slot, r.slot);
        assert!(next.generation > r.generation && next.job > r.job);
        assert_eq!(t.fixed_metadata_bytes(), fixed);
        census(&t);
    }
}

#[test]
fn a22_late_virtual_exhaustion_leaves_physical_preflight_uncommitted() {
    let mut t = table(limits(4, 1, 4), profile(4, 4, 8, 1), 32768);
    let a = t.admit_owner(owner(0, 0), 32768).unwrap();
    let r = reserve(&mut t, a, 1);
    unchanged(
        &mut t,
        HeapError::VirtualPlacement(PlacementError::OutOfMemory),
        |t| t.reserve_heap(a, 1, t.revision()),
    );
    assert_eq!(placement(&t).physical.reservation_count(), 1);
    t.abort_heap(r).unwrap();
    census(&t);
}

#[test]
fn a22_physical_exhaustion_preserves_virtual_and_metadata_capacity() {
    let mut t = table(limits(4, 1, 4), profile(4, 4, 1, 8), 32768);
    let a = t.admit_owner(owner(0, 0), 32768).unwrap();
    reserve(&mut t, a, 1);
    unchanged(
        &mut t,
        HeapError::PhysicalPlacement(PlacementError::OutOfMemory),
        |t| t.reserve_heap(a, 1, t.revision()),
    );
    census(&t);
}

#[test]
fn a22_invalid_sizes_and_closed_owner_do_not_advance_identity() {
    let mut t = table(limits(4, 1, 4), profile(4, 4, 8, 8), 32768);
    let a = t.admit_owner(owner(0, 0), 32768).unwrap();
    for size in [0, i64::MAX as u64 + 1, u64::MAX] {
        unchanged(&mut t, HeapError::Size, |t| {
            t.reserve_heap(a, size, t.revision())
        });
    }
    t.close_owner(a).unwrap();
    unchanged(&mut t, HeapError::Closed, |t| {
        t.reserve_heap(a, 1, t.revision())
    });
    census(&t);
}

#[test]
fn a22_two_clients_share_revision_and_global_budget() {
    let mut t = table(limits(4, 2, 4), profile(4, 4, 8, 8), 4096);
    let a = t.admit_owner(owner(0, 0), 8192).unwrap();
    let b = t.admit_owner(owner(1, 0), 8192).unwrap();
    let revision = t.revision();
    let r = t.reserve_heap(a, 1, revision).unwrap();
    unchanged(&mut t, HeapError::StaleRevision, |t| {
        t.reserve_heap(b, 1, revision)
    });
    unchanged(&mut t, HeapError::Capacity(Resource::GlobalBytes), |t| {
        t.reserve_heap(b, 1, t.revision())
    });
    t.abort_heap(r).unwrap();
    let next = reserve(&mut t, b, 1);
    assert_eq!(t.reserved_extents(next).unwrap().physical.base, 0x1000);
    assert!(next.generation > r.generation && next.job > r.job);
    assert_eq!(t.account_reserved_bytes(a), Ok(0));
    census(&t);
}

#[test]
fn a22_local_slots_and_scope_mutations_share_the_admission_boundary() {
    let mut t = table(limits(1, 1, 1), profile(1, 1, 4, 4), 16384);
    let a = t.admit_owner(owner(0, 0), 16384).unwrap();
    let revision = t.revision();
    let scope = t.enter_scope().unwrap();
    unchanged(&mut t, HeapError::StaleRevision, |t| {
        t.reserve_heap(a, 1, revision)
    });
    let local = t.register(scope, 7, 0x8000, 16, true).unwrap();
    unchanged(&mut t, HeapError::Capacity(Resource::Slots), |t| {
        t.reserve_heap(a, 1, t.revision())
    });
    t.leave_scope(scope).unwrap();
    let r = reserve(&mut t, a, 1);
    assert!(r.generation > local.generation);
    assert_eq!(t.resolve(local, 7, 1, false), Err(PointerError::Stale));
    census(&t);
}

#[test]
fn a22_all_four_neighbor_cases_recover_both_arenas_in_every_free_order() {
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let order = [a, b, c, d];
                    if (0..4).any(|i| order[i + 1..].contains(&order[i])) {
                        continue;
                    }
                    let mut t = table(limits(4, 1, 4), profile(4, 4, 8, 8), 32768);
                    let owner = t.admit_owner(owner(0, 0), 32768).unwrap();
                    let records = [
                        reserve(&mut t, owner, 1),
                        reserve(&mut t, owner, 1),
                        reserve(&mut t, owner, 1),
                        reserve(&mut t, owner, 1),
                    ];
                    for index in order {
                        t.abort_heap(records[index]).unwrap();
                        census(&t);
                    }
                    assert_eq!(
                        placement(&t).physical.free_extents(),
                        &[PhysicalExtent {
                            base: 4096,
                            size: 32768
                        }]
                    );
                    let r = reserve(&mut t, owner, 32768);
                    assert_eq!(
                        t.reserved_extents(r).unwrap().virtual_extent,
                        VirtualExtent {
                            base: 65536,
                            size: 32768
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn a22_fragmented_total_does_not_satisfy_a_contiguous_request() {
    for physical_first in [true, false] {
        let mut t = table(
            limits(4, 1, 4),
            profile(4, 4, if physical_first { 8 } else { 32 }, 8),
            131072,
        );
        let a = t.admit_owner(owner(0, 0), 131072).unwrap();
        let r = [
            reserve(&mut t, a, 8192),
            reserve(&mut t, a, 8192),
            reserve(&mut t, a, 8192),
            reserve(&mut t, a, 8192),
        ];
        t.abort_heap(r[0]).unwrap();
        t.abort_heap(r[2]).unwrap();
        let error = if physical_first {
            HeapError::PhysicalPlacement(PlacementError::OutOfMemory)
        } else {
            HeapError::VirtualPlacement(PlacementError::OutOfMemory)
        };
        unchanged(&mut t, error, |t| t.reserve_heap(a, 12288, t.revision()));
        census(&t);
        t.abort_heap(r[1]).unwrap();
        t.abort_heap(r[3]).unwrap();
        reserve(&mut t, a, 32768);
        census(&t);
    }
}

#[test]
fn a22_owner_death_cancels_only_its_private_reservations() {
    let mut t = table(limits(6, 2, 6), profile(6, 3, 16, 8), 65536);
    let a = t.admit_owner(owner(0, 0), 32768).unwrap();
    let b = t.admit_owner(owner(1, 0), 32768).unwrap();
    let ra = reserve(&mut t, a, 4097);
    let rb = reserve(&mut t, b, 8193);
    let old_b = t.reserved_extents(rb).unwrap();
    assert_eq!(t.close_owner(a), Ok(1));
    unchanged(&mut t, HeapError::Busy, |t| t.release_owner(a));
    let charged = t.total_reserved_bytes();
    t.abort_heap(ra).unwrap();
    assert_eq!(t.total_reserved_bytes(), charged - 8192);
    assert_eq!(t.reserved_extents(rb), Ok(old_b));
    assert_eq!(t.account_reserved_bytes(b), Ok(12288));
    t.release_owner(a).unwrap();
    let c = t.admit_owner(owner(0, 1), 32768).unwrap();
    assert_ne!(a.serial, c.serial);
    assert_eq!(a.index, c.index);
    unchanged(&mut t, HeapError::Owner, |t| {
        t.reserve_heap(a, 1, t.revision())
    });
    let rc = reserve(&mut t, c, 4097);
    assert_eq!(t.reserved_extents(rc).unwrap().physical.base, 4096);
    assert_eq!(t.reserved_extents(rb), Ok(old_b));
    census(&t);
}

#[test]
fn a22_cancel_rejects_foreign_stale_and_duplicate_keys() {
    let mut t = table(limits(4, 2, 4), profile(4, 4, 8, 8), 32768);
    let a = t.admit_owner(owner(0, 0), 32768).unwrap();
    let b = t.admit_owner(owner(1, 0), 32768).unwrap();
    let r = reserve(&mut t, a, 1);
    for bad in [
        HeapReservation { owner: b, ..r },
        HeapReservation {
            slot: r.slot + 1,
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
    ] {
        unchanged(&mut t, HeapError::StaleReservation, |t| t.abort_heap(bad));
    }
    t.abort_heap(r).unwrap();
    unchanged(&mut t, HeapError::StaleReservation, |t| t.abort_heap(r));
    let next = reserve(&mut t, a, 1);
    assert!(next.generation > r.generation && next.job > r.job);
    unchanged(&mut t, HeapError::StaleReservation, |t| t.abort_heap(r));
    census(&t);
}

#[test]
fn a22_late_virtual_binding_failure_cannot_half_return_physical_extent() {
    let mut t = table(limits(4, 1, 4), profile(4, 4, 8, 8), 32768);
    let a = t.admit_owner(owner(0, 0), 32768).unwrap();
    let first = reserve(&mut t, a, 1);
    let second = reserve(&mut t, a, 1);
    let good = t.reservation_record(first).unwrap();
    let mut bad = good;
    bad.extents.as_mut().unwrap().virtual_extent =
        t.reserved_extents(second).unwrap().virtual_extent;
    t.slots[first.slot].record = Record::Heap(bad);
    unchanged(
        &mut t,
        HeapError::VirtualPlacement(PlacementError::ReservationMismatch),
        |t| t.abort_heap(first),
    );
    assert_eq!(
        placement(&t).physical.reservation_extent(first.key()),
        Some(good.extents.unwrap().physical)
    );
    t.slots[first.slot].record = Record::Heap(good);
    t.abort_heap(first).unwrap();
    census(&t);
}

#[test]
fn a22_sticky_attachment_and_publication_require_later_retirement() {
    let mut t = table(limits(2, 1, 2), profile(2, 2, 4, 4), 16384);
    let a = t.admit_owner(owner(0, 0), 16384).unwrap();
    let r = reserve(&mut t, a, 1);
    let mut record = t.reservation_record(r).unwrap();
    record.ever_attached = true;
    t.slots[r.slot].record = Record::Heap(record);
    unchanged(&mut t, HeapError::Busy, |t| t.abort_heap(r));
    t.close_owner(a).unwrap();
    unchanged(&mut t, HeapError::Busy, |t| t.abort_heap(r));
    record.ever_attached = false;
    record.published = true;
    t.slots[r.slot].record = Record::Heap(record);
    unchanged(&mut t, HeapError::Busy, |t| t.abort_heap(r));
    census(&t);
}

#[test]
fn a22_terminal_revision_and_last_generation_do_not_strand_cancellation() {
    let mut t = table(limits(1, 1, 1), profile(1, 1, 4, 4), 16384);
    let a = t.admit_owner(owner(0, 0), 16384).unwrap();
    t.slots[0].generation = u32::MAX - 1;
    t.heap.next_job = u64::MAX - 1;
    t.heap.revision = u64::MAX - 1;
    let r = reserve(&mut t, a, 1);
    assert_eq!(r.generation, u32::MAX);
    assert_eq!(t.revision(), u64::MAX);
    t.close_owner(a).unwrap();
    no_alloc(|| t.abort_heap(r)).unwrap();
    assert_eq!(t.slots[0].state, SlotState::Exhausted);
    assert_eq!(t.slots[0].generation, u32::MAX);
    assert_eq!(t.heap.next_job, u64::MAX);
    assert_eq!(t.revision(), u64::MAX);
    no_alloc(|| t.release_owner(a)).unwrap();
    census(&t);
}

#[test]
fn a22_exhausted_generation_blocks_admission_after_full_extent_recovery() {
    let mut t = table(limits(1, 1, 1), profile(1, 1, 4, 4), 16384);
    let a = t.admit_owner(owner(0, 0), 16384).unwrap();
    t.slots[0].generation = u32::MAX - 1;
    let r = reserve(&mut t, a, 1);
    no_alloc(|| t.abort_heap(r)).unwrap();
    assert_eq!(t.slots[0].state, SlotState::Exhausted);
    assert_eq!(placement(&t).physical.free_bytes(), 16384);
    assert!(t.revision() < u64::MAX && t.heap.next_job < u64::MAX);
    unchanged(&mut t, HeapError::Capacity(Resource::Slots), |t| {
        t.reserve_heap(a, 1, t.revision())
    });
    unchanged(&mut t, HeapError::StaleReservation, |t| t.abort_heap(r));
    census(&t);
}

#[test]
fn a22_bounded_profile_rejects_legacy_object_and_monotonic_bypasses() {
    let mut t = table(limits(2, 1, 2), profile(2, 2, 4, 4), 16384);
    let p = t.heap.placement.as_mut().unwrap();
    assert_eq!(
        p.physical.allocate(crate::anka64::state::ObjectId(1), 1),
        Err(PlacementError::WrongMode)
    );
    assert_eq!(
        p.virtual_arenas[0].reserve(1),
        Err(PlacementError::WrongMode)
    );
    census(&t);
}

#[test]
fn a22_construction_charges_retained_tables_and_scratch_before_admission() {
    let l = limits(4, 2, 4);
    let p = profile(4, 3, 16, 8);
    let plain = ScopedPointers::with_limits(l).unwrap();
    let t = ScopedPointers::with_heap_placement(l, p).unwrap();
    let fixed = t.fixed_metadata_bytes();
    let owned = placement(&t);
    assert_eq!(
        fixed,
        plain.fixed_metadata_bytes() + owned.retained_bytes().unwrap()
    );
    assert!(owned.retained_bytes().unwrap() >= HeapPlacement::minimum_bytes(p, 2).unwrap());
    let exact = RegistryLimits {
        global_bytes: fixed,
        ..l
    };
    let mut zero = ScopedPointers::with_heap_placement(exact, p).unwrap();
    let a = zero.admit_owner(owner(0, 0), 32768).unwrap();
    unchanged(&mut zero, HeapError::Capacity(Resource::GlobalBytes), |t| {
        t.reserve_heap(a, 1, t.revision())
    });
    assert!(matches!(
        ScopedPointers::with_heap_placement(
            RegistryLimits {
                global_bytes: fixed - 1,
                ..l
            },
            p
        ),
        Err(HeapError::Capacity(Resource::GlobalBytes))
    ));
    eprintln!(
        "A2.2 sizes: registry={} slot={} account={} cleanup={} virtual descriptor={} scratch={}; fixed={} placement={}",
        size_of::<ScopedPointers>(),
        size_of::<Slot>(),
        size_of::<Option<Account>>(),
        size_of::<Option<CleanupRecord>>(),
        size_of::<VirtualLayoutBuilder>(),
        HeapPlacement::scratch_bytes(),
        fixed,
        owned.retained_bytes().unwrap()
    );
}

#[test]
fn a22_invalid_configuration_and_extent_geometry_fail_before_use() {
    let l = limits(4, 2, 4);
    let good = profile(4, 4, 8, 8);
    for pool in [
        PhysicalExtent {
            base: 1,
            size: 4096,
        },
        PhysicalExtent {
            base: 4096,
            size: 0,
        },
        PhysicalExtent {
            base: u64::MAX - 4095,
            size: 4096,
        },
    ] {
        assert!(
            ScopedPointers::with_heap_placement(
                l,
                HeapPlacementLimits {
                    physical_pool: pool,
                    ..good
                }
            )
            .is_err()
        );
    }
    for window in [
        VirtualExtent {
            base: 1,
            size: 4096,
        },
        VirtualExtent {
            base: 4096,
            size: 0,
        },
        VirtualExtent {
            base: u64::MAX - 4095,
            size: 4096,
        },
    ] {
        assert!(
            ScopedPointers::with_heap_placement(
                l,
                HeapPlacementLimits {
                    virtual_window: window,
                    ..good
                }
            )
            .is_err()
        );
        assert!(
            ScopedPointers::with_heap_placement(
                limits(0, 0, 0),
                HeapPlacementLimits {
                    virtual_window: window,
                    ..good
                }
            )
            .is_err()
        );
    }
    assert!(
        ScopedPointers::with_heap_placement(
            l,
            HeapPlacementLimits {
                physical_claims: usize::MAX,
                ..good
            }
        )
        .is_err()
    );
}

#[test]
fn a22_steady_state_reserve_cancel_owner_reuse_and_failures_allocate_nothing() {
    let mut t = table(limits(4, 2, 4), profile(4, 2, 8, 4), 32768);
    no_alloc(|| {
        let a = t.admit_owner(owner(0, 0), 16384).unwrap();
        let b = t.admit_owner(owner(1, 0), 16384).unwrap();
        let ra = reserve(&mut t, a, 4097);
        let rb = reserve(&mut t, b, 1);
        assert!(t.reserve_heap(a, 12288, t.revision()).is_err());
        t.close_owner(a).unwrap();
        t.abort_heap(ra).unwrap();
        t.release_owner(a).unwrap();
        let c = t.admit_owner(owner(0, 1), 16384).unwrap();
        let rc = reserve(&mut t, c, 8192);
        t.abort_heap(rb).unwrap();
        t.abort_heap(rc).unwrap();
        t.close_owner(b).unwrap();
        t.release_owner(b).unwrap();
        t.close_owner(c).unwrap();
        t.release_owner(c).unwrap();
    });
    census(&t);
}

#[test]
fn a22_2048_interleaved_churn_cycles_recover_extents_and_keep_capacity_and_history() {
    let mut t = table(limits(8, 2, 6), profile(6, 3, 32, 16), 131072);
    let a = t.admit_owner(owner(0, 0), 65536).unwrap();
    let b = t.admit_owner(owner(1, 0), 65536).unwrap();
    let scope = t.enter_scope().unwrap();
    let local = t.register(scope, 7, 0x8000, 16, true).unwrap();
    let fixed = t.fixed_metadata_bytes();
    let capacity_bytes = placement(&t).retained_bytes().unwrap();
    let mut stale = None;
    for i in 0..2048 {
        let sizes = [1, 4096, 4097, 12287];
        let ra = no_alloc(|| reserve(&mut t, a, sizes[i % 4]));
        let rb = no_alloc(|| reserve(&mut t, b, sizes[(i + 1) % 4]));
        let rc = no_alloc(|| reserve(&mut t, a, sizes[(i + 2) % 4]));
        if let Some(old) = stale {
            assert_ne!(ra, old);
            unchanged(&mut t, HeapError::StaleReservation, |t| t.abort_heap(old));
        }
        let stable_b = t.reserved_extents(rb).unwrap();
        for r in if i % 2 == 0 { [ra, rc] } else { [rc, ra] } {
            no_alloc(|| t.abort_heap(r)).unwrap();
            assert_eq!(t.reserved_extents(rb), Ok(stable_b));
            census(&t);
        }
        no_alloc(|| t.abort_heap(rb)).unwrap();
        assert_eq!(t.heap.reserved_bytes, 0);
        assert_eq!(
            placement(&t).physical.free_extents(),
            &[PhysicalExtent {
                base: 4096,
                size: 131072
            }]
        );
        assert_eq!(t.fixed_metadata_bytes(), fixed);
        assert_eq!(placement(&t).retained_bytes().unwrap(), capacity_bytes);
        assert!(t.resolve(local, 7, 1, false).is_ok());
        census(&t);
        stale = Some(ra);
    }
    let all = reserve(&mut t, a, 65536);
    assert_eq!(
        t.reserved_extents(all).unwrap().virtual_extent,
        VirtualExtent {
            base: 65536,
            size: 65536
        }
    );
    t.abort_heap(all).unwrap();
    t.leave_scope(scope).unwrap();
    census(&t);
}
