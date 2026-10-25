//! Positive cases use an explicitly synthetic published checkpoint. Real
//! reserve/attach/initialize code runs first; production publication stays off.
use super::super::tests::{add_owner, attach, bare, reserve, row, snapshot};
use super::*;
use crate::anka64::fabric::{AuthResult, request};
use crate::anka64::scoped_pointers::{
    Scope,
    heap::{OwnerAccount, cell_test_support as fixture, no_alloc},
};
use crate::anka64::state::*;

const CPU: AgentId = AgentId(10);

fn live(
    f: &mut Fabric,
    owner: AllocationOwner,
    account: OwnerAccount,
    size: u64,
) -> (HeapReservation, ObjectId, ScopedPointer) {
    let r = reserve(f, account, size);
    let id = attach(f, owner, r);
    let mut progress = f
        .private_heap_initialization(r, owner, id, f.scoped_pointers.revision())
        .unwrap();
    while !progress.is_complete() {
        let amount = (progress.rounded_bytes() - progress.initialized_bytes()).min(4096);
        progress = no_alloc(|| {
            f.initialize_private_heap_chunk(progress, owner, amount, f.scoped_pointers.revision())
        })
        .unwrap();
    }
    f.validate_private_heap_initialization(progress, owner, f.scoped_pointers.revision())
        .unwrap();
    let pointer = fixture::activate(&mut f.scoped_pointers, r);
    (r, id, pointer)
}

fn setup(
    size: u64,
) -> (
    Fabric,
    AllocationOwner,
    OwnerAccount,
    HeapReservation,
    ObjectId,
    ScopedPointer,
) {
    let mut f = bare();
    let (owner, account) = add_owner(&mut f, 0);
    f.register_agent(CPU, AgentKind::Cpu(CoreId(0)), owner.domain);
    let (r, id, pointer) = live(&mut f, owner, account, size);
    (f, owner, account, r, id, pointer)
}

fn local(f: &mut Fabric, owner: AllocationOwner, context: u64) -> (Scope, ObjectId, ScopedPointer) {
    let id = f.alloc_object("local source", 64, ObjectKind::Memory);
    assert!(f.place_object(id, 0));
    f.grant(owner.domain, id, 0, 64, Permissions::RW).unwrap();
    let scope = f.scoped_pointers.enter_scope_for(context).unwrap();
    let mut req = request(CPU, owner.domain, id, 0, Width::Byte, AccessKind::Read);
    req.length = 32;
    let p = f.register_scoped_pointer(scope, req, 0x8000, true).unwrap();
    (scope, id, p)
}

fn store(f: &mut Fabric, owner: AllocationOwner, dst: ScopedPointer, value: Option<ScopedPointer>) {
    no_alloc(|| f.store_heap_pointer_cell(owner, CPU, dst, value)).unwrap();
}
fn load(f: &mut Fabric, owner: AllocationOwner, src: ScopedPointer) -> Option<ScopedPointer> {
    no_alloc(|| f.load_heap_pointer_cell(owner, CPU, src)).unwrap()
}
fn write(f: &mut Fabric, owner: AllocationOwner, dst: ScopedPointer, bytes: &[u8]) {
    no_alloc(|| f.write_heap_bytes(owner, CPU, dst, bytes)).unwrap();
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
fn cell_bytes(f: &Fabric, id: ObjectId, offset: usize) -> [u8; 16] {
    let base = row(f, id).extents.physical.base as usize + offset;
    f.memory[base..base + 16].try_into().unwrap()
}

#[test]
fn a233_private_and_initialized_lifetimes_reject_every_live_cell_path() {
    let mut f = bare();
    let (owner, a) = add_owner(&mut f, 0);
    f.register_agent(CPU, AgentKind::Cpu(CoreId(0)), owner.domain);
    let r = reserve(&mut f, a, 32);
    let id = attach(&mut f, owner, r);
    let forged = fixture::token(r, 0);
    let progress = f
        .private_heap_initialization(r, owner, id, f.scoped_pointers.revision())
        .unwrap();
    for initialized in [false, true] {
        if initialized {
            f.initialize_private_heap_chunk(progress, owner, 4096, f.scoped_pointers.revision())
                .unwrap();
        }
        rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
            f.store_heap_pointer_cell(owner, CPU, forged, None)
        });
        rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
            f.load_heap_pointer_cell(owner, CPU, forged)
        });
        rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
            f.write_heap_bytes(owner, CPU, forged, &[0])
        });
    }
    assert!(f.objects.is_empty() && f.placement.is_empty());
}

#[test]
fn a233_live_fixture_transports_exact_heap_and_null_without_allocation_or_recharge() {
    let (mut f, owner, a, _, id, p) = setup(64);
    let (_, _, other) = live(&mut f, owner, a, 31);
    let next = f.next_object_id;
    let revision = f.scoped_pointers.revision();
    let charged = f.scoped_pointers.total_reserved_bytes();
    let fixed = f.scoped_pointers.fixed_metadata_bytes();
    assert_eq!(load(&mut f, owner, p), None);
    store(&mut f, owner, p, Some(other));
    assert_eq!(cell_bytes(&f, id, 0), pointer_bytes(Some(other)));
    assert_eq!(load(&mut f, owner, p), Some(other));
    let alias = p;
    store(&mut f, owner, alias, None);
    assert_eq!(cell_bytes(&f, id, 0), [0; 16]);
    assert_eq!(load(&mut f, owner, p), None);
    // Self-references are authenticated before the coherent overwrite too.
    store(&mut f, owner, p, Some(p));
    assert_eq!(load(&mut f, owner, alias), Some(p));
    assert_eq!(f.next_object_id, next);
    assert_eq!(f.scoped_pointers.revision(), revision);
    assert_eq!(f.scoped_pointers.total_reserved_bytes(), charged);
    assert_eq!(f.scoped_pointers.fixed_metadata_bytes(), fixed);
    assert!(f.pointer_cells.is_empty()); // no legacy growing shadow
    assert!(f.transactions.is_empty() && f.fault_log.is_empty());
    assert!(f.domains[&owner.domain].capabilities.is_empty());
}

#[test]
fn a233_roundtrip_transports_one_past_but_never_dereferences_it() {
    let (mut f, owner, a, _, _, p) = setup(32);
    let (_, _, other) = live(&mut f, owner, a, 31);
    let end = fixture::at(other, 31);
    store(&mut f, owner, p, Some(end));
    assert_eq!(load(&mut f, owner, p), Some(end));
    rejects(&mut f, HeapError::Pointer(PointerError::Bounds), |f| {
        f.load_heap_pointer_cell(owner, CPU, end)
    });
    rejects(&mut f, HeapError::Pointer(PointerError::Bounds), |f| {
        f.write_heap_bytes(owner, CPU, end, &[1])
    });
    rejects(&mut f, HeapError::Pointer(PointerError::Bounds), |f| {
        f.store_heap_pointer_cell(owner, CPU, p, Some(fixture::at(other, 32)))
    });
    assert_eq!(load(&mut f, owner, p), Some(end));
}

#[test]
fn a233_logical_bounds_alignment_and_overflow_preserve_destination() {
    let (mut f, owner, _, _, _, p) = setup(31);
    store(&mut f, owner, p, Some(p));
    for position in [16, 31, 32, 4096, u64::MAX] {
        let dst = fixture::at(p, position);
        rejects(&mut f, HeapError::Pointer(PointerError::Bounds), |f| {
            f.store_heap_pointer_cell(owner, CPU, dst, None)
        });
        rejects(&mut f, HeapError::Pointer(PointerError::Bounds), |f| {
            f.load_heap_pointer_cell(owner, CPU, dst)
        });
    }
    rejects(&mut f, HeapError::Size, |f| {
        f.store_heap_pointer_cell(owner, CPU, fixture::at(p, 1), None)
    });
    rejects(&mut f, HeapError::Pointer(PointerError::Bounds), |f| {
        f.write_heap_bytes(owner, CPU, fixture::at(p, 30), &[1, 2])
    });
    rejects(&mut f, HeapError::Pointer(PointerError::Bounds), |f| {
        f.write_heap_bytes(owner, CPU, p, &[])
    });
    assert_eq!(load(&mut f, owner, p), Some(p));
    write(&mut f, owner, fixture::at(p, 30), &[9]);
    assert_eq!(load(&mut f, owner, p), Some(p));
}

#[test]
fn a233_equal_scalar_bytes_clear_kind_and_cannot_recreate_it() {
    let (mut f, owner, _, _, id, p) = setup(64);
    store(&mut f, owner, p, Some(p));
    let bytes = cell_bytes(&f, id, 0);
    write(&mut f, owner, fixture::at(p, 15), &bytes[15..]);
    assert_eq!(cell_bytes(&f, id, 0), bytes);
    rejects(&mut f, HeapError::MissingKind, |f| {
        f.load_heap_pointer_cell(owner, CPU, p)
    });
    write(&mut f, owner, p, &bytes);
    rejects(&mut f, HeapError::MissingKind, |f| {
        f.load_heap_pointer_cell(owner, CPU, p)
    });
    write(&mut f, owner, p, &[0; 16]);
    assert_eq!(load(&mut f, owner, p), None);
    let mut noncanonical = [0; 16];
    noncanonical[8] = 1;
    write(&mut f, owner, p, &noncanonical);
    rejects(&mut f, HeapError::MissingKind, |f| {
        f.load_heap_pointer_cell(owner, CPU, p)
    });
}

#[test]
fn a233_scalar_cross_cell_write_clears_all_and_only_overlapping_tags() {
    let (mut f, owner, _, _, id, p) = setup(64);
    for offset in [0, 16, 32, 48] {
        store(&mut f, owner, fixture::at(p, offset), Some(p));
    }
    let prior = f.memory.clone();
    write(&mut f, owner, fixture::at(p, 15), &[0x33; 18]);
    for offset in [0, 16, 32] {
        rejects(&mut f, HeapError::MissingKind, |f| {
            f.load_heap_pointer_cell(owner, CPU, fixture::at(p, offset))
        });
    }
    assert_eq!(load(&mut f, owner, fixture::at(p, 48)), Some(p));
    let base = row(&f, id).extents.physical.base as usize;
    assert_eq!(&f.memory[..base + 15], &prior[..base + 15]);
    assert_eq!(&f.memory[base + 33..], &prior[base + 33..]);
}

#[test]
fn a233_mismatched_payload_and_tag_never_falls_back_to_null() {
    let (mut f, owner, _, _, id, p) = setup(64);
    let base = row(&f, id).extents.physical.base as usize;
    for byte in [0, 8] {
        store(&mut f, owner, p, Some(p));
        f.memory[base + byte] ^= 1; // trusted-state fault injection, not a guest writer
        rejects(&mut f, HeapError::MissingKind, |f| {
            f.load_heap_pointer_cell(owner, CPU, p)
        });
    }
    f.memory[base..base + 16].fill(0);
    rejects(&mut f, HeapError::MissingKind, |f| {
        f.load_heap_pointer_cell(owner, CPU, p)
    });
    store(&mut f, owner, p, None);
    assert_eq!(load(&mut f, owner, p), None);
}

#[test]
fn a233_closing_source_invalidates_stored_and_cached_copies_without_erasure() {
    let (mut f, owner, a, _, id, p) = setup(64);
    let (_, _, other) = live(&mut f, owner, a, 31);
    store(&mut f, owner, p, Some(other));
    let cached = load(&mut f, owner, p).unwrap();
    let bytes = cell_bytes(&f, id, 0);
    let tags = f.private_heap.as_ref().unwrap().shadow.clone();
    let charged = f.scoped_pointers.total_reserved_bytes();
    assert_eq!(no_alloc(|| f.scoped_pointers.close_heap(a, other)), Ok(()));
    assert_eq!(cell_bytes(&f, id, 0), bytes);
    assert_eq!(f.private_heap.as_ref().unwrap().shadow, tags);
    rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
        f.load_heap_pointer_cell(owner, CPU, p)
    });
    rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
        f.store_heap_pointer_cell(owner, CPU, fixture::at(p, 16), Some(cached))
    });
    assert_eq!(f.scoped_pointers.total_reserved_bytes(), charged);
    store(&mut f, owner, p, None); // clearing a stale reference needs no old source authority
    assert_eq!(load(&mut f, owner, p), None);
}

#[test]
fn a233_destination_close_and_owner_death_fence_all_paths() {
    for whole_owner in [false, true] {
        let (mut f, owner, a, r, _, p) = setup(64);
        store(&mut f, owner, p, Some(p));
        if whole_owner {
            f.scoped_pointers.close_owner(a).unwrap();
        } else {
            f.scoped_pointers.close_heap(a, p).unwrap();
        }
        rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
            f.load_heap_pointer_cell(owner, CPU, p)
        });
        rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
            f.store_heap_pointer_cell(owner, CPU, p, None)
        });
        rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
            f.write_heap_bytes(owner, CPU, p, &[0])
        });
        assert_eq!(
            no_alloc(|| f.scoped_pointers.abort_heap(r)),
            Err(HeapError::Busy)
        );
    }
}

#[test]
fn a233_owner_incarnation_context_domain_and_cpu_identity_are_rechecked() {
    let (mut f, owner, _, _, _, p) = setup(64);
    let (other, _) = add_owner(&mut f, 1);
    for wrong in [
        other,
        AllocationOwner {
            context: owner.context + 1,
            ..owner
        },
        AllocationOwner {
            process: ProcessKey {
                generation: 1,
                ..owner.process
            },
            ..owner
        },
        AllocationOwner {
            domain: other.domain,
            ..owner
        },
    ] {
        rejects(&mut f, HeapError::Owner, |f| {
            f.store_heap_pointer_cell(wrong, CPU, p, None)
        });
        rejects(&mut f, HeapError::Owner, |f| {
            f.load_heap_pointer_cell(wrong, CPU, p)
        });
    }
    for kind in [None, Some(AgentKind::Dma), Some(AgentKind::Cpu(CoreId(1)))] {
        f.agents.remove(&CPU);
        if let Some(kind) = kind {
            f.register_agent(
                CPU,
                kind,
                if matches!(kind, AgentKind::Cpu(_)) {
                    other.domain
                } else {
                    owner.domain
                },
            );
        }
        rejects(&mut f, HeapError::Owner, |f| {
            f.store_heap_pointer_cell(owner, CPU, p, None)
        });
        rejects(&mut f, HeapError::Owner, |f| {
            f.load_heap_pointer_cell(owner, CPU, p)
        });
        rejects(&mut f, HeapError::Owner, |f| {
            f.write_heap_bytes(owner, CPU, p, &[1])
        });
    }
    f.register_agent(CPU, AgentKind::Cpu(CoreId(0)), owner.domain);
    f.destroy_domain(owner.domain);
    rejects(&mut f, HeapError::Owner, |f| {
        f.load_heap_pointer_cell(owner, CPU, p)
    });
}

#[test]
fn a233_independent_owners_share_numeric_addresses_but_not_cells_or_sources() {
    let (mut f, a, aa, _, ia, pa) = setup(64);
    let (b, ab) = add_owner(&mut f, 1);
    let cpu_b = AgentId(11);
    f.register_agent(cpu_b, AgentKind::Cpu(CoreId(1)), b.domain);
    let (_, ib, pb) = live(&mut f, b, ab, 64);
    assert_eq!(
        row(&f, ia).extents.virtual_extent,
        row(&f, ib).extents.virtual_extent
    );
    assert_ne!(row(&f, ia).extents.physical, row(&f, ib).extents.physical);
    store(&mut f, a, pa, Some(pa));
    no_alloc(|| f.store_heap_pointer_cell(b, cpu_b, pb, Some(pb))).unwrap();
    let bytes_b = cell_bytes(&f, ib, 0);
    rejects(&mut f, HeapError::Owner, |f| {
        f.store_heap_pointer_cell(a, CPU, pa, Some(pb))
    });
    rejects(&mut f, HeapError::Owner, |f| {
        f.load_heap_pointer_cell(a, CPU, pb)
    });
    f.scoped_pointers.close_owner(aa).unwrap();
    assert_eq!(
        no_alloc(|| f.load_heap_pointer_cell(b, cpu_b, pb)),
        Ok(Some(pb))
    );
    assert_eq!(cell_bytes(&f, ib, 0), bytes_b);
    assert_eq!(f.scoped_pointers.account_reserved_bytes(aa).unwrap(), 4096);
    assert_eq!(f.scoped_pointers.account_reserved_bytes(ab).unwrap(), 4096);
}

#[test]
fn a233_local_pointer_roundtrip_rejects_scope_exit_and_slot_reuse() {
    let (mut f, owner, _, _, _, p) = setup(64);
    let (scope, object, local_p) = local(&mut f, owner, owner.context);
    let end = f.scoped_pointers.add(local_p, owner.domain.0, 32).unwrap();
    store(&mut f, owner, p, Some(end));
    assert_eq!(load(&mut f, owner, p), Some(end));
    f.retire_pointer_frame(scope, &[local_p]).unwrap();
    rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
        f.load_heap_pointer_cell(owner, CPU, p)
    });
    let next = f.scoped_pointers.enter_scope_for(owner.context).unwrap();
    let mut req = request(CPU, owner.domain, object, 0, Width::Byte, AccessKind::Read);
    req.length = 32;
    let fresh = f.register_scoped_pointer(next, req, 0x8000, true).unwrap();
    assert_ne!(fresh.words(), local_p.words());
    rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
        f.store_heap_pointer_cell(owner, CPU, p, Some(local_p))
    });
    store(&mut f, owner, p, Some(fresh));
    assert_eq!(load(&mut f, owner, p), Some(fresh));
}

#[test]
fn a233_local_source_requires_current_context_backing_and_read_authority() {
    for mode in 0..3 {
        let (mut f, owner, _, _, _, p) = setup(64);
        let (_, object, source) = local(
            &mut f,
            owner,
            if mode == 0 {
                owner.context + 1
            } else {
                owner.context
            },
        );
        if mode != 0 {
            store(&mut f, owner, p, Some(source));
            assert_eq!(load(&mut f, owner, p), Some(source));
        }
        if mode == 1 {
            f.revoke(object);
        }
        if mode == 2 {
            f.domains
                .get_mut(&owner.domain)
                .unwrap()
                .capabilities
                .clear();
        }
        let error = match mode {
            0 => PointerError::InvalidScope,
            1 => PointerError::Stale,
            _ => PointerError::Rights,
        };
        rejects(&mut f, HeapError::Pointer(error), |f| {
            f.store_heap_pointer_cell(owner, CPU, p, Some(source))
        });
        if mode == 0 {
            assert_eq!(load(&mut f, owner, p), None);
        } else {
            rejects(&mut f, HeapError::Pointer(error), |f| {
                f.load_heap_pointer_cell(owner, CPU, p)
            });
        }
    }
}

#[test]
fn a233_private_source_and_stale_reused_reservation_cannot_gain_kind() {
    let (mut f, owner, a, _, _, p) = setup(64);
    let old = reserve(&mut f, a, 31);
    let stale = fixture::token(old, 0);
    f.scoped_pointers.abort_heap(old).unwrap();
    let next = reserve(&mut f, a, 31);
    attach(&mut f, owner, next);
    rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
        f.store_heap_pointer_cell(owner, CPU, p, Some(stale))
    });
    rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
        f.store_heap_pointer_cell(owner, CPU, p, Some(fixture::token(next, 0)))
    });
    assert_eq!(load(&mut f, owner, p), None);
}

#[test]
fn a233_storage_mismatch_rights_and_late_bounds_fail_without_mutation() {
    let (mut f, owner, _, r, id, p) = setup(64);
    let slot = f
        .scoped_pointers
        .prepare_heap_pointer(p, owner)
        .unwrap()
        .slot();
    let good = row(&f, id);
    for mode in 0..6 {
        let mut bad = good;
        let error = match mode {
            0 => {
                bad.logical += 1;
                HeapError::StaleReservation
            }
            1 => {
                bad.extents.physical.base += 4096;
                HeapError::StaleReservation
            }
            2 => {
                bad.object_generation = Generation(1);
                HeapError::StaleReservation
            }
            3 => {
                bad.planned_rights = Permissions::RWX;
                HeapError::Pointer(PointerError::Rights)
            }
            4 => {
                bad.initialized_bytes = 16;
                HeapError::Busy
            }
            _ => {
                bad.extents.virtual_extent.base += 4096;
                HeapError::StaleReservation
            }
        };
        f.private_heap.as_mut().unwrap().rows[slot] = Some(bad);
        rejects(&mut f, error, |f| {
            f.store_heap_pointer_cell(owner, CPU, p, None)
        });
    }
    f.private_heap.as_mut().unwrap().rows[slot] = Some(good);
    let shadow = std::mem::take(&mut f.private_heap.as_mut().unwrap().shadow);
    rejects(&mut f, HeapError::Configuration, |f| {
        f.store_heap_pointer_cell(owner, CPU, p, None)
    });
    f.private_heap.as_mut().unwrap().shadow = shadow;
    let memory = std::mem::take(&mut f.memory);
    rejects(&mut f, HeapError::Configuration, |f| {
        f.store_heap_pointer_cell(owner, CPU, p, None)
    });
    f.memory = memory;
    assert_eq!(row(&f, id).reservation, r);
    store(&mut f, owner, p, Some(p));
}

#[test]
fn a233_legacy_dma_atomic_and_raw_paths_cannot_access_heap_cells() {
    let (mut f, owner, _, _, id, p) = setup(64);
    store(&mut f, owner, p, Some(p));
    let base = row(&f, id).extents.physical.base;
    let before = snapshot(&f);
    assert!(f.grant(owner.domain, id, 0, 64, Permissions::RW).is_none());
    assert!(!f.try_write_physical(base, &[0; 16]));
    assert!(f.try_read_physical(base, 16).is_none());
    f.zero_physical(base, 16);
    for kind in [AccessKind::Read, AccessKind::Write, AccessKind::Atomic] {
        assert!(matches!(
            f.authorize(&request(CPU, owner.domain, id, 0, Width::Double, kind)),
            AuthResult::Denied(_)
        ));
    }
    assert_eq!(snapshot(&f), before);
    assert_eq!(load(&mut f, owner, p), Some(p));
}

#[test]
fn a233_pending_legacy_work_blocks_access_until_terminal() {
    let (mut f, owner, _, _, _, p) = setup(64);
    store(&mut f, owner, p, Some(p));
    let obj = f.alloc_object("other work", 16, ObjectKind::Memory);
    assert!(f.place_object(obj, 0));
    f.grant(owner.domain, obj, 0, 16, Permissions::RW).unwrap();
    let mut req = request(CPU, owner.domain, obj, 0, Width::Byte, AccessKind::Write);
    req.length = 16;
    let tx = f.submit(req, Some(vec![1; 16]));
    f.advance(tx);
    f.advance(tx);
    assert_eq!(f.transactions[tx].state, TxState::Prepared);
    f.transactions[tx].physical_address = Some(0x1ff8);
    rejects(&mut f, HeapError::Busy, |f| {
        f.store_heap_pointer_cell(owner, CPU, p, None)
    });
    rejects(&mut f, HeapError::Busy, |f| {
        f.load_heap_pointer_cell(owner, CPU, p)
    });
    rejects(&mut f, HeapError::Busy, |f| {
        f.write_heap_bytes(owner, CPU, p, &[0])
    });
    f.advance(tx);
    assert_eq!(f.transactions[tx].state, TxState::Faulted);
    assert_eq!(load(&mut f, owner, p), Some(p));
}

#[test]
fn a233_live_access_needs_no_new_ledger_revision_or_identity() {
    let (mut f, owner, a, _, _, p) = setup(64);
    fixture::set_revision(&mut f.scoped_pointers, u64::MAX);
    f.next_object_id = u64::MAX;
    store(&mut f, owner, p, Some(p));
    assert_eq!(load(&mut f, owner, p), Some(p));
    write(&mut f, owner, fixture::at(p, 16), &[1]);
    assert_eq!(f.scoped_pointers.revision(), u64::MAX);
    assert_eq!(no_alloc(|| f.scoped_pointers.close_owner(a)), Ok(1));
    rejects(&mut f, HeapError::Pointer(PointerError::Stale), |f| {
        f.load_heap_pointer_cell(owner, CPU, p)
    });
}

#[test]
fn a233_full_preallocated_shadow_and_exhausted_owner_quota_do_not_block_stores() {
    let (mut f, owner, account, _, _, p) = setup(0x4000);
    let charged = f.scoped_pointers.total_reserved_bytes();
    let revision = f.scoped_pointers.revision();
    assert_eq!(
        no_alloc(|| f.scoped_pointers.reserve_heap(account, 1, revision)),
        Err(HeapError::Capacity(Resource::OwnerBytes))
    );
    // Fill every configured shadow cell without inserting a map entry, growing
    // metadata, spending another identity or charging pointer payload twice.
    for offset in (0..0x4000).step_by(16) {
        store(&mut f, owner, fixture::at(p, offset), Some(p));
    }
    assert!(
        f.private_heap
            .as_ref()
            .unwrap()
            .shadow
            .iter()
            .all(|tag| *tag == Some(p))
    );
    assert_eq!(load(&mut f, owner, fixture::at(p, 0x3ff0)), Some(p));
    assert_eq!(f.scoped_pointers.total_reserved_bytes(), charged);
    assert_eq!(f.scoped_pointers.revision(), revision);
    assert!(f.pointer_cells.is_empty() && f.transactions.is_empty());
}

#[test]
fn a233_scalar_write_chunk_limit_is_independent_of_allocation_size() {
    let (mut f, owner, _, _, id, p) = setup(8192);
    store(&mut f, owner, p, Some(p));
    let oversized = vec![0xaa; 4097];
    rejects(&mut f, HeapError::Pointer(PointerError::Bounds), |f| {
        f.write_heap_bytes(owner, CPU, p, &oversized)
    });
    assert_eq!(load(&mut f, owner, p), Some(p));
    write(&mut f, owner, p, &[0xaa; 4096]);
    let base = row(&f, id).extents.physical.base as usize;
    assert!(f.memory[base..base + 4096].iter().all(|b| *b == 0xaa));
    assert!(f.memory[base + 4096..base + 8192].iter().all(|b| *b == 0));
    rejects(&mut f, HeapError::MissingKind, |f| {
        f.load_heap_pointer_cell(owner, CPU, p)
    });
}
