use super::*;
use crate::anka64::scoped_pointers::PointerError;

fn owner(slot: usize, generation: u32) -> AllocationOwner {
    AllocationOwner {
        process: ProcessKey { slot, generation },
        context: slot as u64 + 100,
        domain: DomainId(slot as u64 + 7),
    }
}

fn table(slots: usize, owners: usize, cleanup: usize, payload_budget: u64) -> ScopedPointers {
    let mut t = ScopedPointers::with_limits(RegistryLimits {
        slots,
        scopes: slots,
        owners,
        cleanup,
        global_bytes: u64::MAX,
    })
    .unwrap();
    t.heap.limit = t
        .fixed_metadata_bytes()
        .checked_add(payload_budget)
        .unwrap();
    t
}

fn reserve(t: &mut ScopedPointers, a: OwnerAccount, n: u64) -> HeapReservation {
    t.reserve_heap(a, n, t.revision()).unwrap()
}

fn unchanged<T: std::fmt::Debug + PartialEq>(
    t: &mut ScopedPointers,
    expected: Result<T, HeapError>,
    action: impl FnOnce(&mut ScopedPointers) -> Result<T, HeapError>,
) {
    let before = format!("{t:?}");
    assert_eq!(action(t), expected);
    assert_eq!(format!("{t:?}"), before);
}

/// Test fixture ONLY: stand in for the later, fully checked publication commit.
/// This intentionally cannot be called by any production runtime path. Even
/// this token cannot resolve through the local-only access/Fabric path in A2.1.
fn published(t: &mut ScopedPointers, r: HeapReservation) -> ScopedPointer {
    let mut record = t.reservation_record(r).unwrap();
    assert!(!t.account(r.owner).unwrap().closed);
    assert_eq!(t.slots[r.slot].state, SlotState::Reserved);
    record.published = true;
    t.slots[r.slot].record = Record::Heap(record);
    t.slots[r.slot].state = SlotState::Live;
    t.heap.advance();
    ScopedPointer {
        slot: r.slot,
        generation: r.generation,
        position: 0,
    }
}

/// Independent census of every current row, including local/retired slots.
fn census(t: &ScopedPointers) {
    let mut sum = 0;
    for account in t.heap.accounts.iter().flatten() {
        let expected: u64 = t
            .slots
            .iter()
            .filter_map(|s| match s.record {
                Record::Heap(r) if r.owner == account.token => Some(r.rounded),
                _ => None,
            })
            .sum();
        assert_eq!(account.reserved, expected);
        assert!(account.reserved <= account.limit);
        sum += expected;
    }
    let mut records = 0;
    for (i, slot) in t.slots.iter().enumerate() {
        if let Record::Heap(r) = slot.record {
            records += 1;
            t.account(r.owner).unwrap();
            assert!(matches!(
                slot.state,
                SlotState::Reserved | SlotState::Live | SlotState::Closing | SlotState::Retired
            ));
            let job = t.heap.cleanup[r.cleanup].unwrap();
            assert_eq!(
                (
                    job.reservation.slot,
                    job.reservation.generation,
                    job.reservation.owner
                ),
                (i, slot.generation, r.owner)
            );
            assert_eq!(job.queued, matches!(slot.state, SlotState::Closing | SlotState::Retired));
            assert_eq!(t.reservation_record(job.reservation), Ok(r));
        }
    }
    assert_eq!(records, t.heap.cleanup.iter().flatten().count());
    assert_eq!(sum, t.heap.reserved_bytes);
    assert!(t.total_reserved_bytes() <= t.heap.limit);
}

#[test]
fn a21_fixed_metadata_measures_all_retained_tables_and_survives_release() {
    let mut t = table(3, 1, 2, 8192);
    let bytes = size_of::<ScopedPointers>()
        + t.slots.capacity() * size_of::<Slot>()
        + t.scopes.capacity() * size_of::<Option<super::super::ScopeRecord>>()
        + t.heap.accounts.capacity() * size_of::<Option<Account>>()
        + t.heap.cleanup.capacity() * size_of::<Option<CleanupRecord>>();
    assert_eq!(t.fixed_metadata_bytes(), bytes as u64);
    let a = t.admit_owner(owner(0, 0), 8192).unwrap();
    let r = reserve(&mut t, a, 1);
    assert_eq!(t.total_reserved_bytes(), bytes as u64 + 4096);
    t.abort_heap(r).unwrap();
    t.close_owner(a).unwrap();
    t.release_owner(a).unwrap();
    assert_eq!(t.total_reserved_bytes(), bytes as u64);
    census(&t);
    eprintln!(
        "A2.1 layout: registry={} slot={} scope={} account={} cleanup={}; fixed={}",
        size_of::<ScopedPointers>(),
        size_of::<Slot>(),
        size_of::<Option<super::super::ScopeRecord>>(),
        size_of::<Option<Account>>(),
        size_of::<Option<CleanupRecord>>(),
        bytes
    );
}

#[test]
fn a21_configuration_rejects_unfunded_or_unencodable_directory() {
    let limits = RegistryLimits {
        slots: 1,
        scopes: 1,
        owners: 1,
        cleanup: 1,
        global_bytes: 0,
    };
    assert_eq!(
        ScopedPointers::with_limits(limits),
        Err(HeapError::Capacity(Resource::GlobalBytes))
    );
    if usize::BITS > 32 {
        assert_eq!(
            ScopedPointers::with_limits(RegistryLimits {
                slots: u32::MAX as usize + 1,
                global_bytes: u64::MAX,
                ..limits
            }),
            Err(HeapError::Configuration)
        );
    }
}

#[test]
fn a21_budget_race_uses_one_current_revision_for_all_clients() {
    let mut t = table(4, 2, 4, 4096);
    let a = t.admit_owner(owner(0, 0), 8192).unwrap();
    let b = t.admit_owner(owner(1, 0), 8192).unwrap();
    let snapshot = t.revision();
    let r = t.reserve_heap(a, 1, snapshot).unwrap();
    unchanged(&mut t, Err(HeapError::StaleRevision), |t| {
        t.reserve_heap(b, 1, snapshot)
    });
    unchanged(
        &mut t,
        Err(HeapError::Capacity(Resource::GlobalBytes)),
        |t| t.reserve_heap(b, 1, t.revision()),
    );
    t.abort_heap(r).unwrap();
    reserve(&mut t, b, 4096);
    assert_eq!(t.account_reserved_bytes(a), Ok(0));
    assert_eq!(t.account_reserved_bytes(b), Ok(4096));
    census(&t);
}

#[test]
fn a21_independent_owner_budget_and_rounding_are_atomic() {
    let mut t = table(4, 2, 4, 32768);
    let a = t.admit_owner(owner(0, 0), 4096).unwrap();
    let b = t.admit_owner(owner(1, 0), 8192).unwrap();
    unchanged(
        &mut t,
        Err(HeapError::Capacity(Resource::OwnerBytes)),
        |t| t.reserve_heap(a, 4097, t.revision()),
    );
    reserve(&mut t, a, 1);
    reserve(&mut t, b, 4097);
    assert_eq!(t.account_reserved_bytes(a), Ok(4096));
    assert_eq!(t.account_reserved_bytes(b), Ok(8192));
    census(&t);
}

#[test]
fn a21_size_failures_do_not_consume_identity_or_cleanup() {
    let mut t = table(1, 1, 1, u64::MAX / 2);
    let a = t.admit_owner(owner(0, 0), u64::MAX).unwrap();
    for n in [0, i64::MAX as u64 + 1, u64::MAX] {
        unchanged(&mut t, Err(HeapError::Size), |t| {
            t.reserve_heap(a, n, t.revision())
        });
    }
    census(&t);
}

#[test]
fn a21_cleanup_exhaustion_leaves_free_identity_and_ledger_unchanged() {
    let mut t = table(4, 1, 1, 32768);
    let a = t.admit_owner(owner(0, 0), 32768).unwrap();
    let first = reserve(&mut t, a, 16);
    unchanged(&mut t, Err(HeapError::Capacity(Resource::Cleanup)), |t| {
        t.reserve_heap(a, 16, t.revision())
    });
    assert_eq!(
        t.slots
            .iter()
            .filter(|s| s.state == SlotState::Free)
            .count(),
        3
    );
    t.abort_heap(first).unwrap();
    let second = reserve(&mut t, a, 16);
    assert_eq!(second.slot, first.slot);
    assert!(second.generation > first.generation && second.job > first.job);
    unchanged(&mut t, Err(HeapError::StaleReservation), |t| {
        t.abort_heap(first)
    });
    census(&t);
}

#[test]
fn a21_heap_and_local_share_slots_generations_and_capacity() {
    let mut t = table(1, 1, 1, 8192);
    let a = t.admit_owner(owner(0, 0), 8192).unwrap();
    let scope = t.enter_scope().unwrap();
    let local = t.register(scope, 7, 0x8000, 16, true).unwrap();
    unchanged(&mut t, Err(HeapError::Capacity(Resource::Slots)), |t| {
        t.reserve_heap(a, 16, t.revision())
    });
    t.leave_scope(scope).unwrap();
    let r = reserve(&mut t, a, 16);
    assert_eq!(r.slot, local.slot);
    assert!(r.generation > local.generation);
    assert_eq!(t.resolve(local, 7, 1, false), Err(PointerError::Stale));
    t.abort_heap(r).unwrap();
    let scope = t.enter_scope().unwrap();
    let next = t.register(scope, 7, 0x8000, 16, true).unwrap();
    assert_eq!(next.slot, r.slot);
    assert!(next.generation > r.generation);
    unchanged(&mut t, Err(HeapError::StaleReservation), |t| {
        t.abort_heap(r)
    });
    census(&t);
}

#[test]
fn a21_local_scope_changes_invalidate_stale_heap_admission_snapshot() {
    let mut t = table(4, 1, 2, 8192);
    let a = t.admit_owner(owner(0, 0), 8192).unwrap();
    let revision = t.revision();
    t.enter_scope().unwrap();
    unchanged(&mut t, Err(HeapError::StaleRevision), |t| {
        t.reserve_heap(a, 16, revision)
    });
}

#[test]
fn a21_reserved_heap_never_resolves_as_local_authority() {
    let mut t = table(2, 1, 2, 8192);
    let a = t.admit_owner(owner(0, 0), 8192).unwrap();
    let r = reserve(&mut t, a, 16);
    let counterfeit = ScopedPointer {
        slot: r.slot,
        generation: r.generation,
        position: 0,
    };
    assert_eq!(
        t.resolve(counterfeit, 7, 1, false),
        Err(PointerError::Stale)
    );
    let p = published(&mut t, r);
    // Even fixture-only live metadata cannot bypass missing heap publication.
    assert_eq!(t.resolve(p, 7, 1, false), Err(PointerError::Stale));
    assert_eq!(t.backing(p), None);
    unchanged(&mut t, Err(HeapError::Busy), |t| t.abort_heap(r));
}

#[test]
fn a21_independent_heap_close_preserves_local_and_newer_heap() {
    let mut t = table(5, 1, 3, 16384);
    let a = t.admit_owner(owner(0, 0), 16384).unwrap();
    let scope = t.enter_scope().unwrap();
    let local = t.register(scope, 7, 0x8000, 16, true).unwrap();
    let r1 = reserve(&mut t, a, 1);
    let p1 = published(&mut t, r1);
    let r2 = reserve(&mut t, a, 4097);
    let p2 = published(&mut t, r2);
    t.close_heap(a, p1).unwrap();
    assert_eq!(t.slots[p1.slot].state, SlotState::Closing);
    assert_eq!(t.slots[p2.slot].state, SlotState::Live);
    assert_eq!(t.resolve(local, 7, 16, true), Ok(0x8000));
    assert_eq!(t.account_reserved_bytes(a), Ok(12288));
    t.leave_scope(scope).unwrap();
    assert_eq!(t.slots[p2.slot].state, SlotState::Live);
    t.close_heap(a, p2).unwrap();
    census(&t);
}

#[test]
fn a21_invalid_free_is_side_effect_free_for_every_class_owner_and_position() {
    let mut t = table(4, 2, 3, 16384);
    let a = t.admit_owner(owner(0, 0), 8192).unwrap();
    let b = t.admit_owner(owner(1, 0), 8192).unwrap();
    let r = reserve(&mut t, a, 32);
    let p = published(&mut t, r);
    let scope = t.enter_scope().unwrap();
    let local = t.register(scope, 7, 0x8000, 16, true).unwrap();
    unchanged(&mut t, Err(HeapError::InvalidFree), |t| t.close_heap(b, p));
    for bad in [
        local,
        ScopedPointer { position: 1, ..p },
        ScopedPointer {
            generation: p.generation + 1,
            ..p
        },
        ScopedPointer { slot: 99, ..p },
    ] {
        unchanged(&mut t, Err(HeapError::InvalidFree), |t| {
            t.close_heap(a, bad)
        });
    }
    t.close_heap(a, p).unwrap();
    unchanged(&mut t, Err(HeapError::InvalidFree), |t| t.close_heap(a, p));
    census(&t);
}

#[test]
fn a21_full_queue_owner_death_retains_every_charge_and_foreign_record() {
    let mut t = table(3, 3, 3, 16384);
    let a = t.admit_owner(owner(0, 0), 8192).unwrap();
    let b = t.admit_owner(owner(1, 0), 8192).unwrap();
    let empty = t.admit_owner(owner(2, 0), 8192).unwrap();
    let r1 = reserve(&mut t, a, 1);
    let p1 = published(&mut t, r1);
    let r2 = reserve(&mut t, a, 1); // private staging is fenced as well
    let foreign = reserve(&mut t, b, 1);
    let before_foreign = t.slots[foreign.slot];
    t.close_heap(a, p1).unwrap(); // already queued
    let total = t.total_reserved_bytes();
    assert_eq!(t.close_owner(a), Ok(1));
    assert_eq!(t.close_owner(a), Ok(0));
    assert_eq!(t.close_owner(empty), Ok(0));
    assert_eq!(t.slots[foreign.slot], before_foreign);
    assert_eq!(t.total_reserved_bytes(), total);
    assert_eq!(
        t.heap.cleanup.iter().flatten().filter(|j| j.queued).count(),
        2
    );
    unchanged(&mut t, Err(HeapError::Closed), |t| {
        t.reserve_heap(a, 1, t.revision())
    });
    unchanged(&mut t, Err(HeapError::Busy), |t| t.release_owner(a));
    t.abort_heap(r2).unwrap(); // only the never-published reservation can cancel
    unchanged(&mut t, Err(HeapError::Busy), |t| t.abort_heap(r1));
    t.release_owner(empty).unwrap();
    census(&t);
}

#[test]
fn a21_owner_incarnations_and_retained_account_capacity_do_not_alias() {
    let mut t = table(4, 2, 4, 16384);
    let a = t.admit_owner(owner(0, 0), 8192).unwrap();
    let r = reserve(&mut t, a, 1);
    t.close_owner(a).unwrap();
    let b = t.admit_owner(owner(0, 1), 8192).unwrap();
    reserve(&mut t, b, 1);
    unchanged(&mut t, Err(HeapError::Capacity(Resource::Owners)), |t| {
        t.admit_owner(owner(1, 0), 8192)
    });
    unchanged(&mut t, Err(HeapError::Busy), |t| t.release_owner(a));
    t.abort_heap(r).unwrap();
    t.release_owner(a).unwrap();
    let c = t.admit_owner(owner(1, 0), 8192).unwrap();
    assert_eq!(c.index, a.index);
    assert_ne!(c.serial, a.serial);
    unchanged(&mut t, Err(HeapError::Owner), |t| t.close_owner(a));
    assert_eq!(t.account_reserved_bytes(b), Ok(4096));
    census(&t);
}

#[test]
fn a21_owner_binding_rejects_duplicate_process_with_changed_context_or_domain() {
    let mut t = table(4, 3, 4, 16384);
    let key = owner(0, 0);
    t.admit_owner(key, 8192).unwrap();
    for bad in [
        key,
        AllocationOwner {
            context: key.context + 1,
            ..key
        },
        AllocationOwner {
            domain: DomainId(999),
            ..key
        },
        AllocationOwner {
            context: 0,
            ..owner(1, 0)
        },
    ] {
        unchanged(&mut t, Err(HeapError::Owner), |t| t.admit_owner(bad, 8192));
    }
}

#[test]
fn a21_exhausted_generation_is_a_fixed_tombstone_across_classes() {
    let mut t = table(2, 1, 2, 8192);
    let a = t.admit_owner(owner(0, 0), 8192).unwrap();
    t.slots[0].generation = u32::MAX - 1;
    let last = reserve(&mut t, a, 1);
    assert_eq!(last.generation, u32::MAX);
    t.abort_heap(last).unwrap();
    assert_eq!(t.slots[0].state, SlotState::Exhausted);
    let scope = t.enter_scope().unwrap();
    let local = t.register(scope, 7, 0x8000, 16, true).unwrap();
    assert_eq!(local.slot, 1);
    unchanged(&mut t, Err(HeapError::Capacity(Resource::Slots)), |t| {
        t.reserve_heap(a, 1, t.revision())
    });
    assert_eq!(t.slots.len(), 2);
    census(&t);
}

#[test]
fn a21_identity_and_revision_exhaustion_cannot_block_registered_death() {
    let mut t = table(3, 2, 3, 16384);
    let a = t.admit_owner(owner(0, 0), 8192).unwrap();
    let r = reserve(&mut t, a, 1);
    t.heap.next_job = u64::MAX;
    unchanged(&mut t, Err(HeapError::Capacity(Resource::Identity)), |t| {
        t.reserve_heap(a, 1, t.revision())
    });
    t.heap.next_owner = u64::MAX;
    unchanged(&mut t, Err(HeapError::Capacity(Resource::Identity)), |t| {
        t.admit_owner(owner(1, 0), 4096)
    });
    t.heap.revision = u64::MAX;
    assert_eq!(t.close_owner(a), Ok(1));
    t.abort_heap(r).unwrap();
    t.release_owner(a).unwrap();
    assert_eq!(t.revision(), u64::MAX);
    assert_eq!(t.heap.next_job, u64::MAX);
    assert_eq!(t.total_reserved_bytes(), t.fixed_metadata_bytes());
    census(&t);
}

#[test]
fn a21_arbitrary_order_staging_churn_has_constant_capacity_and_exact_refunds() {
    let mut t = table(6, 2, 4, 65536);
    let a = t.admit_owner(owner(0, 0), 32768).unwrap();
    let b = t.admit_owner(owner(1, 0), 32768).unwrap();
    let capacities = (
        t.slots.capacity(),
        t.scopes.capacity(),
        t.heap.accounts.capacity(),
        t.heap.cleanup.capacity(),
    );
    let fixed = t.fixed_metadata_bytes();
    let mut old = None;
    for cycle in 0..2048 {
        let scope = t.enter_scope_for(100).unwrap();
        let local = t.register(scope, 7, 0x8000, 16, true).unwrap();
        let x = reserve(&mut t, a, 1 + cycle % 9000);
        let y = reserve(&mut t, b, 4097);
        let z = reserve(&mut t, a, 16);
        if let Some(stale) = old {
            unchanged(&mut t, Err(HeapError::StaleReservation), |t| {
                t.abort_heap(stale)
            });
        }
        for r in [y, x, z] {
            t.abort_heap(r).unwrap();
            census(&t);
        }
        assert_eq!(t.resolve(local, 7, 16, true), Ok(0x8000));
        t.leave_scope(scope).unwrap();
        assert_eq!(t.total_reserved_bytes(), fixed);
        assert_eq!(
            (
                t.slots.capacity(),
                t.scopes.capacity(),
                t.heap.accounts.capacity(),
                t.heap.cleanup.capacity()
            ),
            capacities
        );
        old = Some(x);
    }
}

#[test]
fn a21_cleanup_identity_rejects_wrong_job_account_and_reused_slot() {
    let mut t = table(2, 2, 2, 16384);
    let a = t.admit_owner(owner(0, 0), 8192).unwrap();
    let b = t.admit_owner(owner(1, 0), 8192).unwrap();
    let r = reserve(&mut t, a, 16);
    for wrong in [
        HeapReservation {
            job: r.job + 1,
            ..r
        },
        HeapReservation { owner: b, ..r },
        HeapReservation {
            generation: r.generation + 1,
            ..r
        },
        HeapReservation { slot: 99, ..r },
    ] {
        unchanged(&mut t, Err(HeapError::StaleReservation), |t| {
            t.abort_heap(wrong)
        });
    }
    let wrong_account = OwnerAccount {
        serial: a.serial + 10,
        ..a
    };
    unchanged(&mut t, Err(HeapError::Owner), |t| {
        t.close_owner(wrong_account)
    });
    t.abort_heap(r).unwrap();
    reserve(&mut t, b, 16);
    unchanged(&mut t, Err(HeapError::StaleReservation), |t| {
        t.abort_heap(r)
    });
    census(&t);
}
