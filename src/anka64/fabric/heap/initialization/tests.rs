use super::super::tests::{add_owner, attach, bare, reserve, row, snapshot};
use super::*;
use crate::anka64::fabric::{AuthResult, request};
use crate::anka64::scoped_pointers::heap::{OwnerAccount, no_alloc};
use crate::anka64::state::*;

fn observe(
    f: &Fabric,
    r: HeapReservation,
    owner: AllocationOwner,
    id: ObjectId,
) -> HeapInitialization {
    no_alloc(|| f.private_heap_initialization(r, owner, id, f.scoped_pointers.revision())).unwrap()
}

fn chunk(
    f: &mut Fabric,
    receipt: HeapInitialization,
    owner: AllocationOwner,
    amount: u64,
) -> HeapInitialization {
    let revision = f.scoped_pointers.revision();
    no_alloc(|| f.initialize_private_heap_chunk(receipt, owner, amount, revision)).unwrap()
}

fn write(
    f: &mut Fabric,
    receipt: HeapInitialization,
    owner: AllocationOwner,
    offset: u64,
    bytes: &[u8],
) -> HeapInitialization {
    let revision = f.scoped_pointers.revision();
    no_alloc(|| f.write_private_heap(receipt, owner, offset, bytes, revision)).unwrap()
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

fn old_token() -> ScopedPointer {
    let mut old = ScopedPointers::new(1);
    let scope = old.enter_scope().unwrap();
    old.register(scope, 0, 0, 16, true).unwrap()
}

fn dirty_pool(f: &mut Fabric, byte: u8) {
    // Model residual contents before any scrub. No production mutation bypass.
    let heap = f.private_heap.as_mut().unwrap();
    f.memory[heap.pool.base as usize..heap.end() as usize].fill(byte);
    heap.shadow.fill(Some(old_token()));
}

fn fixture(
    size: u64,
) -> (
    Fabric,
    AllocationOwner,
    OwnerAccount,
    HeapReservation,
    ObjectId,
    HeapInitialization,
) {
    let mut f = bare();
    let (owner, account) = add_owner(&mut f, 0);
    let r = reserve(&mut f, account, size);
    dirty_pool(&mut f, 0xa5);
    let id = attach(&mut f, owner, r);
    let receipt = observe(&f, r, owner, id);
    (f, owner, account, r, id, receipt)
}

#[test]
fn a232_two_chunks_clear_full_backing_padding_and_tags_without_publication() {
    for old in [0, 0x11, 0xa5, 0xff] {
        let (mut f, owner, account, r, id, receipt) = fixture(31);
        dirty_pool(&mut f, old);
        let bound = row(&f, id);
        let base = bound.extents.physical.base as usize;
        let end = bound.extents.physical.end().unwrap() as usize;
        let bytes = f.memory.clone();
        let tags = f.private_heap.as_ref().unwrap().shadow.clone();
        let fixed = f.scoped_pointers.fixed_metadata_bytes();
        let charged = f.scoped_pointers.total_reserved_bytes();
        let revision = f.scoped_pointers.revision();
        let next_object = f.next_object_id;
        assert_eq!((receipt.initialized_bytes(), receipt.version()), (0, 0));
        assert!(!receipt.is_complete());
        rejects(&mut f, HeapError::Busy, |f| {
            f.validate_private_heap_initialization(receipt, owner, revision)
        });

        let first = chunk(&mut f, receipt, owner, 16);
        assert_eq!((first.initialized_bytes(), first.version()), (16, 1));
        assert_eq!(f.scoped_pointers.revision(), revision + 1);
        assert!(f.memory[base..base + 16].iter().all(|b| *b == 0));
        assert_eq!(&f.memory[base + 16..], &bytes[base + 16..]);
        assert!(f.private_heap.as_ref().unwrap().shadow[0].is_none());
        assert_eq!(&f.private_heap.as_ref().unwrap().shadow[1..], &tags[1..]);
        let revision = f.scoped_pointers.revision();
        rejects(&mut f, HeapError::Busy, |f| {
            f.validate_private_heap_initialization(first, owner, revision)
        });

        let complete = chunk(&mut f, first, owner, 4080);
        assert_eq!(
            (
                complete.initialized_bytes(),
                complete.rounded_bytes(),
                complete.version()
            ),
            (4096, 4096, 2)
        );
        assert!(complete.is_complete());
        assert!(f.memory[base..end].iter().all(|b| *b == 0));
        assert_eq!(&f.memory[..base], &bytes[..base]);
        assert_eq!(&f.memory[end..], &bytes[end..]);
        assert!(
            f.private_heap.as_ref().unwrap().shadow[..256]
                .iter()
                .all(Option::is_none)
        );
        assert_eq!(
            &f.private_heap.as_ref().unwrap().shadow[256..],
            &tags[256..]
        );
        let before = snapshot(&f);
        assert_eq!(
            no_alloc(|| f.validate_private_heap_initialization(
                complete,
                owner,
                f.scoped_pointers.revision()
            )),
            Ok(())
        );
        assert_eq!(snapshot(&f), before);
        assert_eq!(f.scoped_pointers.fixed_metadata_bytes(), fixed);
        assert_eq!(f.scoped_pointers.total_reserved_bytes(), charged);
        assert_eq!(
            f.scoped_pointers.account_reserved_bytes(account).unwrap(),
            4096
        );
        assert_eq!(
            f.scoped_pointers.reserved_extents(r).unwrap(),
            bound.extents
        );
        assert_eq!(f.next_object_id, next_object);
        assert_eq!(row(&f, id).reservation, r);
        assert!(f.objects.is_empty());
        assert!(f.placement.is_empty());
        assert!(f.domains[&owner.domain].capabilities.is_empty());
        assert!(f.translate(id, 0).is_none());
        assert!(f.try_read_physical(base as u64, 31).is_none());
        assert!(f.grant(owner.domain, id, 0, 31, Permissions::RW).is_none());
        assert!(matches!(
            f.authorize(&request(
                AgentId(0),
                owner.domain,
                id,
                0,
                Width::Byte,
                AccessKind::Read
            )),
            AuthResult::Denied(_)
        ));
        assert_eq!(
            no_alloc(|| f.scoped_pointers.abort_heap(r)),
            Err(HeapError::Busy)
        );
    }
}

#[test]
fn a232_page_bounded_progress_covers_multiple_pages_and_tail_padding() {
    let (mut f, owner, _, _, id, receipt) = fixture(4097);
    let start = row(&f, id).extents.physical.base as usize;
    let first = chunk(&mut f, receipt, owner, 4096);
    assert!(!first.is_complete());
    assert_eq!(first.rounded_bytes(), 8192);
    assert!(
        f.memory[start + 4096..start + 8192]
            .iter()
            .all(|b| *b == 0xa5)
    );
    let complete = chunk(&mut f, first, owner, 4096);
    assert!(complete.is_complete());
    assert!(f.memory[start..start + 8192].iter().all(|b| *b == 0));
    let revision = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::Size, |f| {
        f.initialize_private_heap_chunk(complete, owner, 16, revision)
    });
}

#[test]
fn a232_rejects_zero_unaligned_oversized_and_skipped_prefix_chunks() {
    let (mut f, owner, _, _, _, receipt) = fixture(31);
    for n in [0, 1, 15, 17, 4097, 4112, u64::MAX] {
        let revision = f.scoped_pointers.revision();
        rejects(&mut f, HeapError::Size, |f| {
            f.initialize_private_heap_chunk(receipt, owner, n, revision)
        });
    }
    let partial = chunk(&mut f, receipt, owner, 16);
    let revision = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::Size, |f| {
        f.initialize_private_heap_chunk(partial, owner, 4096, revision)
    });
    let mut forged = partial;
    forged.row.initialized_bytes = 4080;
    rejects(&mut f, HeapError::StaleInitialization, |f| {
        f.initialize_private_heap_chunk(forged, owner, 16, revision)
    });
    forged = partial;
    forged.row.initialized_bytes = 4096;
    rejects(&mut f, HeapError::StaleInitialization, |f| {
        f.validate_private_heap_initialization(forged, owner, revision)
    });
}

#[test]
fn a232_replayed_progress_and_stale_shared_revision_preserve_all_state() {
    let (mut f, owner, _, r, id, receipt) = fixture(31);
    let old_revision = f.scoped_pointers.revision();
    let next = chunk(&mut f, receipt, owner, 16);
    rejects(&mut f, HeapError::StaleRevision, |f| {
        f.initialize_private_heap_chunk(next, owner, 16, old_revision)
    });
    let revision = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::StaleInitialization, |f| {
        f.initialize_private_heap_chunk(receipt, owner, 16, revision)
    });
    rejects(&mut f, HeapError::StaleInitialization, |f| {
        f.write_private_heap(receipt, owner, 0, &[1], revision)
    });
    assert_eq!(observe(&f, r, owner, id), next);
}

#[test]
fn a232_owner_context_incarnation_domain_and_closed_owner_are_rechecked() {
    let (mut f, owner, account, _, _, receipt) = fixture(31);
    let (other, _) = add_owner(&mut f, 1);
    for wrong in [
        other,
        AllocationOwner {
            context: owner.context + 1,
            ..owner
        },
        AllocationOwner {
            domain: other.domain,
            ..owner
        },
        AllocationOwner {
            process: ProcessKey {
                generation: 1,
                ..owner.process
            },
            ..owner
        },
    ] {
        let revision = f.scoped_pointers.revision();
        rejects(&mut f, HeapError::Owner, |f| {
            f.initialize_private_heap_chunk(receipt, wrong, 16, revision)
        });
        rejects(&mut f, HeapError::Owner, |f| {
            f.write_private_heap(receipt, wrong, 0, &[1], revision)
        });
    }
    let complete = chunk(&mut f, receipt, owner, 4096);
    let charged = f.scoped_pointers.total_reserved_bytes();
    assert_eq!(no_alloc(|| f.scoped_pointers.close_owner(account)), Ok(1));
    let revision = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::Closed, |f| {
        f.validate_private_heap_initialization(complete, owner, revision)
    });
    rejects(&mut f, HeapError::Closed, |f| {
        f.write_private_heap(complete, owner, 0, &[1], revision)
    });
    assert_eq!(f.scoped_pointers.total_reserved_bytes(), charged);
}

#[test]
fn a232_missing_domain_blocks_observation_and_initialization() {
    let (mut f, owner, _, r, id, receipt) = fixture(31);
    f.destroy_domain(owner.domain);
    let revision = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::Owner, |f| {
        f.private_heap_initialization(r, owner, id, revision)
    });
    rejects(&mut f, HeapError::Owner, |f| {
        f.initialize_private_heap_chunk(receipt, owner, 16, revision)
    });
}

#[test]
fn a232_snapshots_bind_reservation_object_generation_and_exact_geometry() {
    let (mut f, owner, account, _, _, receipt) = fixture(31);
    let other = reserve(&mut f, account, 32);
    let other_id = attach(&mut f, owner, other);
    let other_receipt = observe(&f, other, owner, other_id);
    let mut substitutions = [receipt; 9];
    substitutions[0].row.reservation = other;
    substitutions[1].row.object = other_id;
    substitutions[2].row.object_generation = Generation(1);
    substitutions[3].row.logical += 1;
    substitutions[4].row.extents.physical = other_receipt.row.extents.physical;
    substitutions[5].row.extents.virtual_extent = other_receipt.row.extents.virtual_extent;
    substitutions[6].row.extents.physical.size *= 2;
    substitutions[7].row.initialization_version += 1;
    substitutions[8].row.planned_rights = Permissions::READ;
    for forged in substitutions {
        let revision = f.scoped_pointers.revision();
        rejects(&mut f, HeapError::StaleInitialization, |f| {
            f.initialize_private_heap_chunk(forged, owner, 16, revision)
        });
    }
}

#[test]
fn a232_unattached_cancelled_and_reused_reservations_cannot_initialize() {
    let mut f = bare();
    let (owner, account) = add_owner(&mut f, 0);
    let old = reserve(&mut f, account, 31);
    let revision = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::Busy, |f| {
        f.private_heap_initialization(old, owner, ObjectId(0), revision)
    });
    f.scoped_pointers.abort_heap(old).unwrap();
    let fresh = reserve(&mut f, account, 31);
    let id = attach(&mut f, owner, fresh);
    let revision = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::StaleReservation, |f| {
        f.private_heap_initialization(old, owner, id, revision)
    });
    assert_eq!(observe(&f, fresh, owner, id).initialized_bytes(), 0);
}

#[test]
fn a232_trusted_write_clears_overlap_resets_prefix_and_invalidates_receipts() {
    let (mut f, owner, _, r, id, receipt) = fixture(31);
    let base = row(&f, id).extents.physical.base as usize;
    let tags = f.private_heap.as_ref().unwrap().shadow.clone();
    let dirty = write(&mut f, receipt, owner, 15, &[1, 2]);
    assert_eq!(&f.memory[base + 15..base + 17], &[1, 2]);
    assert!(
        f.private_heap.as_ref().unwrap().shadow[..2]
            .iter()
            .all(Option::is_none)
    );
    assert_eq!(&f.private_heap.as_ref().unwrap().shadow[2..], &tags[2..]);
    assert_eq!((dirty.initialized_bytes(), dirty.version()), (0, 1));
    let partial = chunk(&mut f, dirty, owner, 16);
    let dirty = write(&mut f, partial, owner, 4095, &[0x7f]);
    assert_eq!((dirty.initialized_bytes(), dirty.version()), (0, 3));
    let complete = chunk(&mut f, dirty, owner, 4096);
    let dirty = write(&mut f, complete, owner, 31, &[0]);
    assert!(!dirty.is_complete());
    let revision = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::StaleInitialization, |f| {
        f.validate_private_heap_initialization(complete, owner, revision)
    });
    let complete_again = chunk(&mut f, dirty, owner, 4096);
    assert!(complete_again.is_complete());
    let revision = f.scoped_pointers.revision();
    // Bytes/cursor can be identical again, but the old version stays invalid.
    rejects(&mut f, HeapError::StaleInitialization, |f| {
        f.validate_private_heap_initialization(complete, owner, revision)
    });
    assert_eq!(observe(&f, r, owner, id), complete_again);
}

#[test]
fn a232_rejected_trusted_writes_preserve_existing_completed_prefix() {
    let (mut f, owner, _, _, _, receipt) = fixture(31);
    let complete = chunk(&mut f, receipt, owner, 4096);
    for (offset, length) in [(0, 0), (0, 4097), (4095, 2), (4096, 1), (u64::MAX, 1)] {
        let data = vec![0x55; length];
        let revision = f.scoped_pointers.revision();
        rejects(&mut f, HeapError::Size, |f| {
            f.write_private_heap(complete, owner, offset, &data, revision)
        });
        assert_eq!(
            f.validate_private_heap_initialization(complete, owner, revision),
            Ok(())
        );
    }
}

#[test]
fn a232_version_exhaustion_never_wraps_or_blocks_owner_closure() {
    let (mut f, owner, account, r, id, _) = fixture(31);
    let slot = f
        .scoped_pointers
        .prepare_heap_initialization(r, owner, f.scoped_pointers.revision())
        .unwrap()
        .slot();
    f.private_heap.as_mut().unwrap().rows[slot]
        .as_mut()
        .unwrap()
        .initialization_version = u64::MAX - 1;
    let boundary = observe(&f, r, owner, id);
    let last = chunk(&mut f, boundary, owner, 16);
    assert_eq!(last.version(), u64::MAX);
    let revision = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::Capacity(Resource::Identity), |f| {
        f.initialize_private_heap_chunk(last, owner, 16, revision)
    });
    rejects(&mut f, HeapError::Capacity(Resource::Identity), |f| {
        f.write_private_heap(last, owner, 0, &[1], revision)
    });
    let charged = f.scoped_pointers.total_reserved_bytes();
    assert_eq!(no_alloc(|| f.scoped_pointers.close_owner(account)), Ok(1));
    assert_eq!(f.scoped_pointers.total_reserved_bytes(), charged);
}

#[test]
fn a232_interleaved_owners_preserve_bytes_tags_progress_and_charges() {
    let (mut f, a, account_a, _, id_a, receipt_a) = fixture(31);
    let (b, account_b) = add_owner(&mut f, 1);
    let rb = reserve(&mut f, account_b, 31);
    let id_b = attach(&mut f, b, rb);
    let receipt_b = observe(&f, rb, b, id_b);
    assert_eq!(
        receipt_a.row.extents.virtual_extent,
        receipt_b.row.extents.virtual_extent
    );
    let b_base = receipt_b.row.extents.physical.base as usize;
    let b_end = receipt_b.row.extents.physical.end().unwrap() as usize;
    let b_bytes = f.memory[b_base..b_end].to_vec();
    let b_tags = f.private_heap.as_ref().unwrap().shadow[256..512].to_vec();
    let revision = f.scoped_pointers.revision();
    let partial_a = chunk(&mut f, receipt_a, a, 16);
    assert_eq!(&f.memory[b_base..b_end], &b_bytes);
    assert_eq!(&f.private_heap.as_ref().unwrap().shadow[256..512], &b_tags);
    assert_eq!(row(&f, id_b), receipt_b.row);
    rejects(&mut f, HeapError::StaleRevision, |f| {
        f.initialize_private_heap_chunk(receipt_b, b, 16, revision)
    });
    let partial_b = chunk(&mut f, receipt_b, b, 16);
    assert_eq!(row(&f, id_a), partial_a.row);
    let charged = f.scoped_pointers.total_reserved_bytes();
    f.scoped_pointers.close_owner(account_a).unwrap();
    let complete_b = chunk(&mut f, partial_b, b, 4080);
    assert!(complete_b.is_complete());
    assert_eq!(row(&f, id_a), partial_a.row);
    assert_eq!(
        f.scoped_pointers.account_reserved_bytes(account_a).unwrap(),
        4096
    );
    assert_eq!(
        f.scoped_pointers.account_reserved_bytes(account_b).unwrap(),
        4096
    );
    assert_eq!(f.scoped_pointers.total_reserved_bytes(), charged);
}

#[test]
fn a232_outstanding_cpu_dma_and_legacy_tag_paths_block_every_mutation() {
    for kind in [AgentKind::Cpu(CoreId(0)), AgentKind::Dma] {
        for access in [AccessKind::Read, AccessKind::Write, AccessKind::Atomic] {
            let (mut f, owner, _, _, _, receipt) = fixture(31);
            f.register_agent(AgentId(0), kind, owner.domain);
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
            let mut req = request(AgentId(0), owner.domain, legacy, 0, Width::Byte, access);
            req.length = 16;
            let tx = f.submit(
                req,
                if access == AccessKind::Read {
                    None
                } else {
                    Some(vec![0x77; 16])
                },
            );
            f.advance(tx);
            f.advance(tx);
            assert_eq!(f.transactions[tx].state, TxState::Prepared);
            f.transactions[tx].physical_address = Some(0x1ff8);
            let revision = f.scoped_pointers.revision();
            rejects(&mut f, HeapError::Busy, |f| {
                f.initialize_private_heap_chunk(receipt, owner, 16, revision)
            });
            rejects(&mut f, HeapError::Busy, |f| {
                f.write_private_heap(receipt, owner, 0, &[1], revision)
            });
            f.advance(tx);
            assert_eq!(f.transactions[tx].state, TxState::Faulted);
            // A stale legacy pointer-cell entry is a separate exclusion path.
            f.pointer_cells
                .insert((legacy, Generation(0), 0x2000), old_token());
            rejects(&mut f, HeapError::Busy, |f| {
                f.initialize_private_heap_chunk(receipt, owner, 16, revision)
            });
            f.pointer_cells.clear();
            assert_eq!(chunk(&mut f, receipt, owner, 16).initialized_bytes(), 16);
        }
    }
}

#[test]
fn a232_late_storage_and_placement_failures_do_not_partially_scrub() {
    let (mut f, owner, _, _, _, receipt) = fixture(31);
    let revision = f.scoped_pointers.revision();
    let memory = std::mem::take(&mut f.memory);
    rejects(&mut f, HeapError::Configuration, |f| {
        f.initialize_private_heap_chunk(receipt, owner, 16, revision)
    });
    f.memory = memory;
    let shadow = std::mem::take(&mut f.private_heap.as_mut().unwrap().shadow);
    rejects(&mut f, HeapError::Configuration, |f| {
        f.initialize_private_heap_chunk(receipt, owner, 16, revision)
    });
    f.private_heap.as_mut().unwrap().shadow = shadow;
    let legacy = f.alloc_object("late overlap", 16, ObjectKind::Memory);
    f.placement
        .insert(legacy, receipt.row.extents.physical.base);
    rejects(&mut f, HeapError::Busy, |f| {
        f.initialize_private_heap_chunk(receipt, owner, 16, revision)
    });
    f.placement.remove(&legacy);
    assert_eq!(chunk(&mut f, receipt, owner, 16).initialized_bytes(), 16);
}

#[test]
fn a232_raw_pool_writers_cannot_dirty_a_completed_allocation() {
    let (mut f, owner, _, _, id, receipt) = fixture(31);
    let complete = chunk(&mut f, receipt, owner, 4096);
    let base = complete.row.extents.physical.base;
    let before = snapshot(&f);
    assert!(!f.try_write_physical(base - 1, &[1, 2]));
    assert!(!f.initialize_object(id, 0, &[1]));
    assert!(!f.zero_object_extent(id));
    f.zero_physical(base, 4096);
    assert_eq!(snapshot(&f), before);
    assert_eq!(
        f.validate_private_heap_initialization(complete, owner, f.scoped_pointers.revision()),
        Ok(())
    );
}
