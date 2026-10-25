use super::*;
use crate::anka64::fabric::{AuthResult, request};
use crate::anka64::scoped_pointers::heap::{OwnerAccount, no_alloc};
use crate::anka64::state::*;

pub(super) fn limits() -> RegistryLimits {
    RegistryLimits {
        slots: 8,
        scopes: 4,
        owners: 4,
        cleanup: 8,
        global_bytes: 1 << 20,
    }
}
pub(super) fn profile() -> HeapPlacementLimits {
    HeapPlacementLimits {
        physical_pool: PhysicalExtent {
            base: 0x2000,
            size: 0x4000,
        },
        physical_claims: 8,
        virtual_window: VirtualExtent {
            base: 0x10000,
            size: 0x8000,
        },
        per_owner_claims: 8,
    }
}
pub(super) fn bare() -> Fabric {
    Fabric::with_private_heap(0x10000, limits(), profile()).unwrap()
}
pub(super) fn add_owner(f: &mut Fabric, slot: usize) -> (AllocationOwner, OwnerAccount) {
    let domain = f.create_domain();
    let owner = AllocationOwner {
        process: ProcessKey {
            slot,
            generation: 0,
        },
        context: 100 + slot as u64,
        domain,
    };
    let account = f.scoped_pointers.admit_owner(owner, 0x4000).unwrap();
    (owner, account)
}
pub(super) fn reserve(f: &mut Fabric, account: OwnerAccount, size: u64) -> HeapReservation {
    no_alloc(|| {
        f.scoped_pointers
            .reserve_heap(account, size, f.scoped_pointers.revision())
    })
    .unwrap()
}
pub(super) fn attach(f: &mut Fabric, owner: AllocationOwner, r: HeapReservation) -> ObjectId {
    let rev = f.scoped_pointers.revision();
    no_alloc(|| f.attach_private_heap(r, owner, rev)).unwrap()
}
pub(super) fn row(f: &Fabric, id: ObjectId) -> PrivateHeapRow {
    *f.private_heap
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .flatten()
        .find(|r| r.object == id)
        .unwrap()
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    registry: String,
    heap: String,
    bytes: Vec<u8>,
    legacy: String,
    domains: String,
    agents: String,
    transactions: String,
    faults: String,
    counters: (u64, u64, u64, u64),
}
pub(super) fn snapshot(f: &Fabric) -> Snapshot {
    Snapshot {
        registry: format!("{:?}", f.scoped_pointers),
        heap: format!("{:?}", f.private_heap),
        bytes: f.memory.clone(),
        legacy: format!(
            "{:?} {:?} {:?} {:?}",
            f.objects
                .iter()
                .map(|(id, o)| (*id, o.generation, o.size, o.state, o.kind, &o.name))
                .collect::<Vec<_>>(),
            f.placement,
            f.pointer_cells,
            f.pointer_stack_objects
        ),
        domains: format!(
            "{:?}",
            f.domains
                .iter()
                .map(|(id, d)| (*id, &d.capabilities, &d.device_authorities))
                .collect::<Vec<_>>()
        ),
        agents: format!(
            "{:?}",
            f.agents
                .iter()
                .map(|(id, a)| (*id, a.kind, a.domain))
                .collect::<Vec<_>>()
        ),
        transactions: format!(
            "{:?}",
            f.transactions
                .iter()
                .map(|t| (
                    t.id,
                    t.request,
                    t.state,
                    t.auth_generation,
                    t.physical_address,
                    &t.write_data,
                    &t.read_data
                ))
                .collect::<Vec<_>>()
        ),
        faults: format!("{:?}", f.fault_log),
        counters: (
            f.next_object_id,
            f.next_domain_id,
            f.next_tx_id,
            f.next_authority_id,
        ),
    }
}
pub(super) fn assert_only_registry_changed(mut before: Snapshot, f: &Fabric) {
    let after = snapshot(f);
    before.registry = after.registry.clone();
    assert_eq!(after, before);
}
pub(super) fn assert_only_heap_and_registry_changed(mut before: Snapshot, f: &Fabric) {
    let after = snapshot(f);
    before.registry = after.registry.clone();
    before.heap = after.heap.clone();
    assert_eq!(after, before);
}
fn rejects(
    f: &mut Fabric,
    error: HeapError,
    op: impl FnOnce(&mut Fabric) -> Result<ObjectId, HeapError>,
) {
    let before = snapshot(f);
    assert_eq!(no_alloc(|| op(f)), Err(error));
    assert_eq!(snapshot(f), before);
}

#[test]
fn a231_fixed_storage_charges_actual_rows_shadow_and_scratch_once() {
    let baseline = ScopedPointers::with_heap_placement(limits(), profile()).unwrap();
    let f = bare();
    let heap = f.private_heap.as_ref().unwrap();
    assert_eq!(heap.rows.len(), limits().slots);
    assert_eq!(
        heap.shadow.len(),
        profile().physical_pool.size as usize / 16
    );
    assert!(heap.rows.iter().all(Option::is_none));
    assert!(heap.shadow.iter().all(Option::is_none));
    let added = size_of::<Option<HeapFabric>>()
        + heap.rows.capacity() * size_of::<Option<PrivateHeapRow>>()
        + heap.shadow.capacity() * size_of::<Option<ScopedPointer>>()
        + size_of::<HeapAttachmentPlan>()
        + size_of::<PrivateHeapRow>()
        + initialization::scratch_bytes().unwrap() as usize
        + cells::scratch_bytes().unwrap() as usize
        + closure::scratch_bytes().unwrap() as usize
        + workers::scratch_bytes().unwrap() as usize;
    let fixed = f.scoped_pointers.fixed_metadata_bytes();
    assert_eq!(fixed, baseline.fixed_metadata_bytes() + added as u64);
    assert_eq!(f.scoped_pointers.total_reserved_bytes(), fixed);
    let tight = RegistryLimits {
        global_bytes: fixed,
        ..limits()
    };
    let mut full = Fabric::with_private_heap(0x10000, tight, profile()).unwrap();
    let (_, owner) = add_owner(&mut full, 0);
    let before = snapshot(&full);
    assert_eq!(
        no_alloc(|| full
            .scoped_pointers
            .reserve_heap(owner, 1, full.scoped_pointers.revision())),
        Err(HeapError::Capacity(Resource::GlobalBytes))
    );
    assert_eq!(snapshot(&full), before);
    assert!(matches!(
        Fabric::with_private_heap(
            0x10000,
            RegistryLimits {
                global_bytes: fixed - 1,
                ..limits()
            },
            profile()
        ),
        Err(HeapError::Capacity(Resource::GlobalBytes))
    ));
}

#[test]
fn a231_invalid_configuration_cannot_construct_an_exposed_service() {
    assert!(Fabric::with_private_heap(0x5000, limits(), profile()).is_err());
    for pool in [
        PhysicalExtent {
            base: 0x2001,
            size: 4096,
        },
        PhysicalExtent {
            base: 0x2000,
            size: 0,
        },
        PhysicalExtent {
            base: u64::MAX - 4095,
            size: 4096,
        },
    ] {
        assert!(
            Fabric::with_private_heap(
                0x10000,
                limits(),
                HeapPlacementLimits {
                    physical_pool: pool,
                    ..profile()
                }
            )
            .is_err()
        );
    }
    assert!(
        Fabric::with_private_heap(
            0x10000,
            RegistryLimits {
                global_bytes: 0,
                ..limits()
            },
            profile()
        )
        .is_err()
    );
    assert!(HeapFabric::footprint(usize::MAX, 0).is_err());
    assert!(HeapFabric::footprint(0, usize::MAX).is_err());
}

#[test]
fn a231_attach_preserves_payload_tags_epoch_quota_and_exact_custody() {
    let mut f = bare();
    let (owner, account) = add_owner(&mut f, 0);
    let r = reserve(&mut f, account, 31);
    let extents = f.scoped_pointers.reserved_extents(r).unwrap();
    let generation_before = format!("{r:?}");
    let fixed = f.scoped_pointers.fixed_metadata_bytes();
    let charged = f.scoped_pointers.total_reserved_bytes();
    let rev = f.scoped_pointers.revision();
    // Model residual contents without exposing a bootstrap bypass in the API.
    f.memory[extents.physical.base as usize..extents.physical.end().unwrap() as usize].fill(0xa5);
    let mut source = ScopedPointers::new(1);
    let scope = source.enter_scope().unwrap();
    let token = source.register(scope, 0, 0, 16, true).unwrap();
    f.private_heap.as_mut().unwrap().shadow[0] = Some(token);
    let bytes = f.memory.clone();
    let tags = f.private_heap.as_ref().unwrap().shadow.clone();
    let id = attach(&mut f, owner, r);
    assert_eq!(id, ObjectId(0));
    let bound = row(&f, id);
    assert_eq!(bound.reservation, r);
    assert_eq!(format!("{:?}", bound.reservation), generation_before);
    assert_eq!(bound.owner, owner);
    assert_eq!(bound.extents, extents);
    assert_eq!(bound.logical, 31);
    assert_eq!(bound.planned_rights, Permissions::RW);
    assert_eq!(
        (bound.initialized_bytes, bound.initialization_version),
        (0, 0)
    );
    assert_eq!(f.scoped_pointers.revision(), rev + 1);
    assert_eq!(f.scoped_pointers.fixed_metadata_bytes(), fixed);
    assert_eq!(f.scoped_pointers.total_reserved_bytes(), charged);
    assert_eq!(f.scoped_pointers.reserved_extents(r).unwrap(), extents);
    assert_eq!(f.memory, bytes);
    assert_eq!(f.private_heap.as_ref().unwrap().shadow, tags);
    assert!(f.objects.is_empty());
    assert!(f.placement.is_empty());
    assert!(f.domains[&owner.domain].capabilities.is_empty());
    assert_eq!(
        no_alloc(|| f.scoped_pointers.abort_heap(r)),
        Err(HeapError::Busy)
    );
}

#[test]
fn a231_stale_revision_owner_context_incarnation_and_domain_fail_atomically() {
    let mut f = bare();
    let (owner, a) = add_owner(&mut f, 0);
    let (other, _) = add_owner(&mut f, 1);
    let r = reserve(&mut f, a, 1);
    let rev = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::StaleRevision, |f| {
        f.attach_private_heap(r, owner, rev - 1)
    });
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
        rejects(&mut f, HeapError::Owner, |f| {
            f.attach_private_heap(r, wrong, rev)
        });
    }
    f.scoped_pointers.close_owner(a).unwrap();
    let rev = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::Closed, |f| {
        f.attach_private_heap(r, owner, rev)
    });
}

#[test]
fn a231_stale_cancelled_reservation_cannot_attach_reused_slot() {
    let mut f = bare();
    let (owner, a) = add_owner(&mut f, 0);
    let old = reserve(&mut f, a, 1);
    f.scoped_pointers.abort_heap(old).unwrap();
    let fresh = reserve(&mut f, a, 1);
    assert_ne!(old, fresh);
    let rev = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::StaleReservation, |f| {
        f.attach_private_heap(old, owner, rev)
    });
    attach(&mut f, owner, fresh);
}

#[test]
fn a231_duplicate_attach_cannot_consume_identity_or_recharge() {
    let mut f = bare();
    let (owner, a) = add_owner(&mut f, 0);
    let r = reserve(&mut f, a, 1);
    attach(&mut f, owner, r);
    let rev = f.scoped_pointers.revision();
    rejects(&mut f, HeapError::Busy, |f| {
        f.attach_private_heap(r, owner, rev)
    });
}

#[test]
fn a231_object_exhaustion_is_fallible_and_never_wraps() {
    let mut f = bare();
    let (owner, a) = add_owner(&mut f, 0);
    let r = reserve(&mut f, a, 1);
    let rev = f.scoped_pointers.revision();
    f.next_object_id = u64::MAX;
    rejects(&mut f, HeapError::Capacity(Resource::Identity), |f| {
        f.attach_private_heap(r, owner, rev)
    });
    assert!(
        f.try_alloc_object("exhausted", 1, ObjectKind::Memory)
            .is_none()
    );
    f.next_object_id = u64::MAX - 1; // boundary forcing is test-only
    assert_eq!(attach(&mut f, owner, r), ObjectId(u64::MAX - 1));
    assert_eq!(f.next_object_id, u64::MAX);
    assert!(
        f.try_alloc_object("still exhausted", 1, ObjectKind::Memory)
            .is_none()
    );
}

#[test]
fn a231_legacy_and_heap_share_identity_without_rewinding_attached_ids() {
    let mut f = bare();
    let (owner, a) = add_owner(&mut f, 0);
    assert_eq!(
        f.alloc_object("legacy before", 16, ObjectKind::Memory),
        ObjectId(0)
    );
    let r = reserve(&mut f, a, 1);
    let heap = attach(&mut f, owner, r);
    assert_eq!(heap, ObjectId(1));
    let after = f.alloc_object("legacy after", 16, ObjectKind::Memory);
    assert_eq!(after, ObjectId(2));
    assert!(f.rollback_unpublished_object(after));
    assert!(!f.rollback_unpublished_object(heap));
    f.destroy_object(heap);
    assert_eq!(f.next_object_id, 2);
    assert_eq!(row(&f, heap).reservation, r);
    assert_eq!(
        f.alloc_object("replacement staging", 16, ObjectKind::Memory),
        after
    );
    f.next_object_id = 1;
    assert!(
        f.try_alloc_object("must not overwrite", 16, ObjectKind::Memory)
            .is_none()
    );
    assert_eq!(row(&f, heap).reservation, r);
}

#[test]
fn a231_two_owners_share_virtual_numbers_without_sharing_backing_or_cleanup() {
    let mut f = bare();
    let (oa, a) = add_owner(&mut f, 0);
    let (ob, b) = add_owner(&mut f, 1);
    let ra = reserve(&mut f, a, 31);
    let rb = reserve(&mut f, b, 32);
    let ia = attach(&mut f, oa, ra);
    let ib = attach(&mut f, ob, rb);
    let before_b = row(&f, ib);
    assert_eq!(
        row(&f, ia).extents.virtual_extent,
        before_b.extents.virtual_extent
    );
    assert_ne!(row(&f, ia).extents.physical, before_b.extents.physical);
    let charged = f.scoped_pointers.total_reserved_bytes();
    assert_eq!(no_alloc(|| f.scoped_pointers.close_owner(a)), Ok(1));
    assert_eq!(
        no_alloc(|| f.scoped_pointers.abort_heap(ra)),
        Err(HeapError::Busy)
    );
    assert_eq!(f.scoped_pointers.total_reserved_bytes(), charged);
    assert_eq!(row(&f, ib), before_b);
    let next = reserve(&mut f, b, 1);
    attach(&mut f, ob, next);
    assert_eq!(row(&f, ib), before_b);
    assert_eq!(f.scoped_pointers.account_reserved_bytes(a).unwrap(), 4096);
    assert_eq!(f.scoped_pointers.account_reserved_bytes(b).unwrap(), 8192);
}

#[test]
fn a231_entire_pool_is_excluded_even_before_first_heap_reservation() {
    let mut f = bare();
    let pool = profile().physical_pool;
    assert_eq!(f.physical_high_watermark(), pool.end());
    let obj = f.alloc_object("legacy", 32, ObjectKind::Memory);
    assert!(f.place_object(obj, 0));
    for base in [pool.base - 16, pool.base, pool.end().unwrap() - 16] {
        assert!(!no_alloc(|| f.place_object(obj, base)));
        assert!(!no_alloc(|| f.move_object(obj, base)));
        assert_eq!(f.physical_base(obj), Some(0));
    }
    assert!(f.move_object(obj, pool.end().unwrap()));
}

#[test]
fn a231_private_object_has_no_legacy_grant_translation_or_lifecycle_bypass() {
    let mut f = bare();
    let (owner, a) = add_owner(&mut f, 0);
    let r = reserve(&mut f, a, 31);
    let id = attach(&mut f, owner, r);
    let before = snapshot(&f);
    assert!(f.grant(owner.domain, id, 0, 31, Permissions::RW).is_none());
    assert!(
        f.grant_with_authority_id(owner.domain, id, 0, 31, Permissions::RW, AuthorityId(4))
            .is_none()
    );
    assert!(f.physical_base(id).is_none());
    assert!(f.translate(id, 0).is_none());
    assert!(!f.place_object(id, 0));
    assert!(!f.initialize_object(id, 0, &[1]));
    assert!(!f.zero_object_extent(id));
    assert!(!f.seal_object(id));
    f.revoke(id);
    f.destroy_object(id);
    assert!(!f.rollback_unpublished_object(id));
    let req = request(
        AgentId(0),
        owner.domain,
        id,
        0,
        Width::Byte,
        AccessKind::Read,
    );
    assert!(matches!(f.authorize(&req), AuthResult::Denied(_)));
    assert_eq!(snapshot(&f), before);
}

#[test]
fn a231_raw_read_write_zero_and_cross_boundary_spans_are_fail_closed() {
    let mut f = bare();
    f.memory.fill(0xa5);
    for (base, n) in [(0x2000, 1), (0x1fff, 2), (0x5fff, 2), (u64::MAX, 2)] {
        let before = snapshot(&f);
        assert!(f.try_read_physical(base, n).is_none());
        assert!(!no_alloc(|| f.try_write_physical(base, &[1, 2])));
        no_alloc(|| f.zero_physical(base, n));
        assert_eq!(snapshot(&f), before);
    }
    assert!(f.try_write_physical(0x6000, &[3, 4]));
    assert_eq!(f.try_read_physical(0x6000, 2), Some(&[3, 4][..]));
    assert_eq!(f.try_read_physical(0x2000, 0), Some(&[][..]));
}

#[test]
fn a231_late_legacy_overlap_and_missing_domain_preserve_the_reservation() {
    let mut f = bare();
    let (owner, a) = add_owner(&mut f, 0);
    let r = reserve(&mut f, a, 1);
    let rev = f.scoped_pointers.revision();
    let legacy = f.alloc_object("fault injected mapping", 4096, ObjectKind::Memory);
    f.placement.insert(legacy, 0x2000); // trusted-state fault injection
    rejects(&mut f, HeapError::Busy, |f| {
        f.attach_private_heap(r, owner, rev)
    });
    f.placement.remove(&legacy);
    f.destroy_domain(owner.domain);
    rejects(&mut f, HeapError::Owner, |f| {
        f.attach_private_heap(r, owner, rev)
    });
}

#[test]
fn a231_outstanding_cpu_and_dma_work_blocks_attach_until_terminal() {
    for kind in [AgentKind::Cpu(CoreId(0)), AgentKind::Dma] {
        let mut f = bare();
        let (owner, a) = add_owner(&mut f, 0);
        let r = reserve(&mut f, a, 1);
        f.register_agent(AgentId(0), kind, owner.domain);
        let legacy = f.alloc_object("other work", 16, ObjectKind::Memory);
        assert!(f.place_object(legacy, 0));
        f.grant(owner.domain, legacy, 0, 16, Permissions::RW)
            .unwrap();
        let mut req = request(
            AgentId(0),
            owner.domain,
            legacy,
            0,
            Width::Byte,
            AccessKind::Write,
        );
        req.length = 16;
        let i = f.submit(req, Some(vec![1; 16]));
        f.advance(i);
        f.advance(i);
        assert_eq!(f.transactions[i].state, TxState::Prepared);
        f.transactions[i].physical_address = Some(0x1ff8); // delayed overlapping operation
        let rev = f.scoped_pointers.revision();
        rejects(&mut f, HeapError::Busy, |f| {
            f.attach_private_heap(r, owner, rev)
        });
        let bytes = f.memory.clone();
        f.advance(i);
        assert_eq!(f.transactions[i].state, TxState::Faulted);
        assert_eq!(f.memory, bytes);
        attach(&mut f, owner, r);
    }
}

#[test]
fn a231_shadow_index_is_bounded_and_injective_for_every_configured_cell() {
    let f = bare();
    let h = f.private_heap.as_ref().unwrap();
    for index in 0..h.shadow.len() {
        let p = h.pool.base + index as u64 * 16;
        assert_eq!(h.shadow_index(p), Some(index));
        assert_eq!(h.shadow_index(p + 1), None);
    }
    assert_eq!(h.shadow_index(h.pool.base - 16), None);
    assert_eq!(h.shadow_index(h.end()), None);
    assert_eq!(h.shadow_index(u64::MAX), None);
}

#[test]
fn a231_rejected_metadata_row_conflict_does_not_set_sticky_attachment() {
    let mut f = bare();
    let (owner, a) = add_owner(&mut f, 0);
    let ra = reserve(&mut f, a, 1);
    let ia = attach(&mut f, owner, ra);
    let rb = reserve(&mut f, a, 1);
    let rev = f.scoped_pointers.revision();
    let slot = f
        .scoped_pointers
        .prepare_heap_attachment(rb, owner, rev)
        .unwrap()
        .slot();
    f.private_heap.as_mut().unwrap().rows[slot] = Some(row(&f, ia));
    rejects(&mut f, HeapError::Busy, |f| {
        f.attach_private_heap(rb, owner, rev)
    });
    f.private_heap.as_mut().unwrap().rows[slot] = None;
    assert_eq!(no_alloc(|| f.scoped_pointers.abort_heap(rb)), Ok(()));
}

#[test]
fn a231_legacy_profile_keeps_bootstrap_access_and_checked_identity_failure() {
    let mut f = Fabric::new(4096);
    assert!(f.private_heap.is_none());
    f.write_physical(0, &[9, 8]);
    assert_eq!(f.read_physical(0, 2), &[9, 8]);
    let first = f.alloc_object("first", 16, ObjectKind::Memory);
    assert_eq!(first, ObjectId(0));
    f.next_object_id = 0;
    assert!(
        f.try_alloc_object("collision", 16, ObjectKind::Memory)
            .is_none()
    );
    assert_eq!(f.objects[&first].name, "first");
    f.next_object_id = u64::MAX;
    assert!(
        f.try_alloc_object("exhausted", 16, ObjectKind::Memory)
            .is_none()
    );
    assert_eq!(f.next_object_id, u64::MAX);
}
