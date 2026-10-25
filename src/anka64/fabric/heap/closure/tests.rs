use super::super::tests::{
    add_owner, assert_only_registry_changed, attach, bare, reserve, row, snapshot,
};
use super::*;
use crate::anka64::fabric::{AuthResult, request};
use crate::anka64::scoped_pointers::{
    PointerError,
    heap::{OwnerAccount, cell_test_support as fixture, no_alloc},
};
use crate::anka64::state::*;

const CPU: AgentId = AgentId(10);

fn setup() -> (
    Fabric,
    AllocationOwner,
    OwnerAccount,
    HeapReservation,
    ObjectId,
) {
    let mut f = bare();
    let (owner, account) = add_owner(&mut f, 0);
    let r = reserve(&mut f, account, 64);
    let id = attach(&mut f, owner, r);
    (f, owner, account, r, id)
}

fn observe(
    f: &Fabric,
    owner: AllocationOwner,
    r: HeapReservation,
    id: ObjectId,
) -> HeapInitialization {
    no_alloc(|| f.private_heap_initialization(r, owner, id, f.scoped_pointers.revision())).unwrap()
}

fn initialize(
    f: &mut Fabric,
    owner: AllocationOwner,
    progress: HeapInitialization,
    n: u64,
) -> HeapInitialization {
    no_alloc(|| f.initialize_private_heap_chunk(progress, owner, n, f.scoped_pointers.revision()))
        .unwrap()
}

// Explicit conditional-live fixture only. Production publication is not enabled.
fn activate(
    f: &mut Fabric,
    owner: AllocationOwner,
    r: HeapReservation,
    id: ObjectId,
) -> ScopedPointer {
    let progress = observe(f, owner, r, id);
    let progress = initialize(f, owner, progress, 4096);
    assert!(progress.is_complete());
    fixture::activate(&mut f.scoped_pointers, r)
}

fn close(
    f: &mut Fabric,
    owner: AllocationOwner,
    r: HeapReservation,
    id: ObjectId,
) -> HeapCloseOutcome {
    no_alloc(|| f.close_attached_heap(r, owner, id)).unwrap()
}

fn rejects<T: std::fmt::Debug>(
    f: &mut Fabric,
    error: HeapError,
    op: impl FnOnce(&mut Fabric) -> Result<T, HeapError>,
) {
    let before = snapshot(f);
    assert_eq!(no_alloc(|| op(f)).unwrap_err(), error);
    assert_eq!(snapshot(f), before);
}

#[test]
fn a234_private_close_preserves_dirty_partial_and_complete_backing() {
    for mode in 0..4 {
        let (mut f, owner, account, r, id) = setup();
        f.memory.fill(0xa5); // arbitrary pre-existing bytes, including padding
        f.private_heap
            .as_mut()
            .unwrap()
            .shadow
            .fill(Some(fixture::token(r, 0)));
        let mut progress = observe(&f, owner, r, id);
        if mode == 1 {
            progress = initialize(&mut f, owner, progress, 16);
        } else if mode >= 2 {
            progress = initialize(&mut f, owner, progress, 4096);
            if mode == 3 {
                progress = f
                    .write_private_heap(progress, owner, 7, &[0x55], f.scoped_pointers.revision())
                    .unwrap();
            }
        }
        let before = snapshot(&f);
        let held = f.scoped_pointers.reserved_extents(r).unwrap();
        let charged = f.scoped_pointers.total_reserved_bytes();
        let rev = f.scoped_pointers.revision();
        assert_eq!(close(&mut f, owner, r, id), HeapCloseOutcome::Closed);
        assert_only_registry_changed(before, &f);
        assert_eq!(f.scoped_pointers.revision(), rev + 1);
        assert_eq!(f.scoped_pointers.reserved_extents(r).unwrap(), held);
        assert_eq!(f.scoped_pointers.total_reserved_bytes(), charged);
        assert_eq!(
            f.scoped_pointers.account_reserved_bytes(account).unwrap(),
            4096
        );
        rejects(&mut f, HeapError::Busy, |f| {
            f.private_heap_initialization(r, owner, id, f.scoped_pointers.revision())
        });
        rejects(&mut f, HeapError::Busy, |f| {
            f.initialize_private_heap_chunk(progress, owner, 16, f.scoped_pointers.revision())
        });
        rejects(&mut f, HeapError::Busy, |f| {
            f.write_private_heap(progress, owner, 0, &[1], f.scoped_pointers.revision())
        });
        rejects(&mut f, HeapError::Busy, |f| {
            f.validate_private_heap_initialization(progress, owner, f.scoped_pointers.revision())
        });
        rejects(&mut f, HeapError::Busy, |f| f.scoped_pointers.abort_heap(r));
    }
}

#[test]
fn a234_duplicate_and_owner_close_ordering_are_idempotent_after_domain_removal() {
    for owner_first in [false, true] {
        let (mut f, owner, account, r, id) = setup();
        if owner_first {
            assert_eq!(no_alloc(|| f.scoped_pointers.close_owner(account)), Ok(1));
        } else {
            assert_eq!(close(&mut f, owner, r, id), HeapCloseOutcome::Closed);
            assert_eq!(no_alloc(|| f.scoped_pointers.close_owner(account)), Ok(0));
        }
        f.destroy_domain(owner.domain);
        let before = snapshot(&f);
        assert_eq!(
            close(&mut f, owner, r, id),
            HeapCloseOutcome::AlreadyClosing
        );
        assert_eq!(snapshot(&f), before);
        rejects(&mut f, HeapError::Busy, |f| {
            f.scoped_pointers.release_owner(account)
        });
        rejects(&mut f, HeapError::Busy, |f| f.scoped_pointers.abort_heap(r));
    }
}

#[test]
fn a234_first_close_uses_retained_identity_without_live_domain_or_cpu() {
    let (mut f, owner, _, r, id) = setup();
    f.destroy_domain(owner.domain);
    let before = snapshot(&f);
    assert_eq!(close(&mut f, owner, r, id), HeapCloseOutcome::Closed);
    assert_only_registry_changed(before, &f);
}

#[test]
fn a234_wrong_owner_incarnation_context_domain_and_object_do_not_close() {
    let (mut f, owner, account, r, id) = setup();
    let other = reserve(&mut f, account, 64);
    let other_id = attach(&mut f, owner, other);
    let mut bad_owners = [owner; 4];
    bad_owners[0].process.slot += 1;
    bad_owners[1].process.generation += 1;
    bad_owners[2].context += 1;
    bad_owners[3].domain = DomainId(owner.domain.0 + 1);
    for already_closed in [false, true] {
        if already_closed {
            assert_eq!(close(&mut f, owner, r, id), HeapCloseOutcome::Closed);
        }
        for bad in bad_owners {
            rejects(&mut f, HeapError::Owner, |f| {
                f.close_attached_heap(r, bad, id)
            });
        }
        for (reservation, object) in [(r, other_id), (other, id), (r, ObjectId(u64::MAX))] {
            rejects(&mut f, HeapError::StaleReservation, |f| {
                f.close_attached_heap(reservation, owner, object)
            });
        }
    }
    assert_eq!(observe(&f, owner, other, other_id).initialized_bytes(), 0);
}

#[test]
fn a234_missing_or_substituted_fabric_custody_preserves_registry_and_job() {
    for mode in 0..10 {
        let (mut f, owner, account, r, id) = setup();
        let other = reserve(&mut f, account, 64);
        let other_id = attach(&mut f, owner, other);
        let other_row = row(&f, other_id);
        let heap = f.private_heap.as_mut().unwrap();
        let slot = heap
            .rows
            .iter()
            .position(|row| row.is_some_and(|r| r.object == id))
            .unwrap();
        if mode == 0 {
            heap.rows[slot] = None;
        } else if mode == 9 {
            heap.object_id_floor = id.0;
        } else {
            let row = heap.rows[slot].as_mut().unwrap();
            match mode {
                1 => row.reservation = other,
                2 => row.owner.context += 1,
                3 => row.object = other_id,
                4 => row.object_generation = Generation(1),
                5 => row.logical += 1,
                6 => row.extents.physical = other_row.extents.physical,
                7 => row.extents.virtual_extent = other_row.extents.virtual_extent,
                _ => row.planned_rights = Permissions::READ,
            }
        }
        rejects(&mut f, HeapError::StaleReservation, |f| {
            f.close_attached_heap(r, owner, id)
        });
    }
}

#[test]
fn a234_live_source_aliases_fail_without_erasing_copies_or_shadow() {
    let (mut f, owner, account, r, id) = setup();
    f.register_agent(CPU, AgentKind::Cpu(CoreId(0)), owner.domain);
    let source = activate(&mut f, owner, r, id);
    let other = reserve(&mut f, account, 64);
    let other_id = attach(&mut f, owner, other);
    let dest = activate(&mut f, owner, other, other_id);
    let copied_token = fixture::at(source, 64); // one-past token, valid for transport
    no_alloc(|| f.store_heap_pointer_cell(owner, CPU, dest, Some(copied_token))).unwrap();
    assert_eq!(
        no_alloc(|| f.load_heap_pointer_cell(owner, CPU, dest)).unwrap(),
        Some(copied_token)
    );
    let before = snapshot(&f);
    assert_eq!(close(&mut f, owner, r, id), HeapCloseOutcome::Closed);
    assert_only_registry_changed(before, &f);
    for old in [source, copied_token] {
        rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
            f.store_heap_pointer_cell(owner, CPU, dest, Some(old))
        });
    }
    rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
        f.load_heap_pointer_cell(owner, CPU, dest)
    });
    // The destination still belongs to a live sibling; replacing the dead
    // source reference by canonical null needs no cleanup of that source.
    no_alloc(|| f.store_heap_pointer_cell(owner, CPU, dest, None)).unwrap();
    assert_eq!(
        no_alloc(|| f.load_heap_pointer_cell(owner, CPU, dest)).unwrap(),
        None
    );
}

#[test]
fn a234_live_destination_closure_fences_all_cell_and_scalar_paths() {
    let (mut f, owner, _, r, id) = setup();
    f.register_agent(CPU, AgentKind::Cpu(CoreId(0)), owner.domain);
    let p = activate(&mut f, owner, r, id);
    no_alloc(|| f.store_heap_pointer_cell(owner, CPU, p, Some(p))).unwrap();
    let before = snapshot(&f);
    assert_eq!(close(&mut f, owner, r, id), HeapCloseOutcome::Closed);
    assert_only_registry_changed(before, &f);
    rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
        f.load_heap_pointer_cell(owner, CPU, p)
    });
    rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
        f.store_heap_pointer_cell(owner, CPU, p, None)
    });
    rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
        f.write_heap_bytes(owner, CPU, p, &[0])
    });
    let before = snapshot(&f);
    assert_eq!(
        close(&mut f, owner, r, id),
        HeapCloseOutcome::AlreadyClosing
    );
    assert_eq!(snapshot(&f), before);
}

#[test]
fn a234_independent_owner_and_same_owner_sibling_keep_their_backing() {
    let (mut f, a, aa, ra, ia) = setup();
    let (b, ab) = add_owner(&mut f, 1);
    let rb = reserve(&mut f, ab, 64);
    let ib = attach(&mut f, b, rb);
    let sibling = reserve(&mut f, aa, 64);
    let sibling_id = attach(&mut f, a, sibling);
    assert_eq!(
        row(&f, ia).extents.virtual_extent,
        row(&f, ib).extents.virtual_extent
    );
    assert_ne!(row(&f, ia).extents.physical, row(&f, ib).extents.physical);
    let pb = observe(&f, b, rb, ib);
    let ps = observe(&f, a, sibling, sibling_id);
    let old_rev = f.scoped_pointers.revision();
    let before = snapshot(&f);
    assert_eq!(close(&mut f, a, ra, ia), HeapCloseOutcome::Closed);
    assert_only_registry_changed(before, &f);
    rejects(&mut f, HeapError::StaleRevision, |f| {
        f.initialize_private_heap_chunk(pb, b, 4096, old_rev)
    });
    assert!(initialize(&mut f, b, pb, 4096).is_complete());
    assert!(initialize(&mut f, a, ps, 4096).is_complete());
    assert_eq!(f.scoped_pointers.account_reserved_bytes(aa).unwrap(), 8192);
    assert_eq!(f.scoped_pointers.account_reserved_bytes(ab).unwrap(), 4096);
    // A's admission remains open. Its closed allocation's physical claim is
    // still held, so the new reservation cannot reuse that backing yet.
    let next = reserve(&mut f, aa, 1);
    assert_ne!(
        f.scoped_pointers.reserved_extents(next).unwrap().physical,
        row(&f, ia).extents.physical
    );
}

#[test]
fn a234_pending_cpu_dma_and_atomic_work_does_not_block_admission_closure() {
    for agent in [AgentKind::Cpu(CoreId(0)), AgentKind::Dma] {
        for access in [AccessKind::Read, AccessKind::Write, AccessKind::Atomic] {
            let (mut f, owner, _, r, id) = setup();
            f.register_agent(CPU, agent, owner.domain);
            let legacy = f.alloc_object("old work", 16, ObjectKind::Memory);
            assert!(f.place_object(legacy, 0));
            f.grant(
                owner.domain,
                legacy,
                0,
                16,
                Permissions(Permissions::RW.0 | Permissions::ATOMIC.0),
            )
            .unwrap();
            let mut req = request(CPU, owner.domain, legacy, 0, Width::Byte, access);
            req.length = 16;
            let tx = f.submit(req, Some(vec![1; 16]));
            f.advance(tx);
            f.advance(tx);
            assert_eq!(f.transactions[tx].state, TxState::Prepared);
            // Fault injection represents a delayed conflicting legacy request.
            // This is not a newly authorized heap DMA or a drainage receipt.
            f.transactions[tx].physical_address = Some(0x1ff8);
            assert!(!f.heap_pool_is_private());
            let before = snapshot(&f);
            assert_eq!(close(&mut f, owner, r, id), HeapCloseOutcome::Closed);
            assert_only_registry_changed(before, &f);
            assert_eq!(f.transactions[tx].state, TxState::Prepared);
            rejects(&mut f, HeapError::Busy, |f| f.scoped_pointers.abort_heap(r));
            let bytes = f.memory.clone();
            f.advance(tx); // existing legacy precommit gate still rejects it
            assert_eq!(f.transactions[tx].state, TxState::Faulted);
            assert_eq!(f.memory, bytes);
            assert_eq!(row(&f, id).reservation, r);
            assert!(f.scoped_pointers.reserved_extents(r).is_ok());
        }
    }
}

#[test]
fn a234_terminal_revision_object_ids_and_init_version_still_allow_close() {
    let (mut f, owner, _, r, id) = setup();
    fixture::set_revision(&mut f.scoped_pointers, u64::MAX);
    f.next_object_id = u64::MAX;
    f.private_heap
        .as_mut()
        .unwrap()
        .rows
        .iter_mut()
        .flatten()
        .find(|row| row.object == id)
        .unwrap()
        .initialization_version = u64::MAX;
    let before = snapshot(&f);
    assert_eq!(close(&mut f, owner, r, id), HeapCloseOutcome::Closed);
    assert_only_registry_changed(before, &f);
    assert_eq!(f.scoped_pointers.revision(), u64::MAX);
    let before = snapshot(&f);
    assert_eq!(
        close(&mut f, owner, r, id),
        HeapCloseOutcome::AlreadyClosing
    );
    assert_eq!(snapshot(&f), before);
}

#[test]
fn a234_never_attached_and_reused_reservations_cannot_close_a_new_lifetime() {
    let mut f = bare();
    let (owner, account) = add_owner(&mut f, 0);
    let old = reserve(&mut f, account, 64);
    rejects(&mut f, HeapError::Busy, |f| {
        f.close_attached_heap(old, owner, ObjectId(0))
    });
    no_alloc(|| f.scoped_pointers.abort_heap(old)).unwrap();
    let fresh = reserve(&mut f, account, 64);
    let id = attach(&mut f, owner, fresh);
    rejects(&mut f, HeapError::StaleReservation, |f| {
        f.close_attached_heap(old, owner, id)
    });
    assert_eq!(close(&mut f, owner, fresh, id), HeapCloseOutcome::Closed);
}

#[test]
fn a234_closing_storage_remains_excluded_from_legacy_grants_and_reuse() {
    let (mut f, owner, _, r, id) = setup();
    assert_eq!(close(&mut f, owner, r, id), HeapCloseOutcome::Closed);
    let before = snapshot(&f);
    no_alloc(|| {
        assert!(f.grant(owner.domain, id, 0, 64, Permissions::RW).is_none());
        assert!(f.physical_base(id).is_none());
        assert!(f.translate(id, 0).is_none());
        assert!(!f.place_object(id, 0));
        assert!(!f.initialize_object(id, 0, &[1]));
        assert!(!f.zero_object_extent(id));
        assert!(!f.rollback_unpublished_object(id));
        f.revoke(id);
        f.destroy_object(id);
        assert!(f.try_read_physical(0x2000, 1).is_none());
        assert!(matches!(
            f.authorize(&request(
                CPU,
                owner.domain,
                id,
                0,
                Width::Byte,
                AccessKind::Read
            )),
            AuthResult::Denied(_)
        ));
    });
    assert_eq!(snapshot(&f), before);
}
