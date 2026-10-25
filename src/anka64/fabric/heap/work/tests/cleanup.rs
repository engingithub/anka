//! Full trusted cleanup-to-reuse acceptance. Live accesses still use the
//! explicit test-only publication fixture; these are not C malloc/free tests.
use super::*;
use crate::anka64::fabric::HeapCleanupSnapshot;
use crate::anka64::scoped_pointers::heap::{CleanupLease, CleanupWorker, HeapCloseOutcome};

fn worker(k: &mut Kernel) -> (ProcessKey, CleanupWorker) {
    let key = process(k);
    let role =
        no_alloc(|| k.enroll_cleanup_worker(key, k.fabric.scoped_pointers.revision())).unwrap();
    (key, role)
}
fn retire(k: &mut Kernel, a: App, key: ProcessKey, role: CleanupWorker) -> CleanupLease {
    no_alloc(|| {
        k.fabric
            .close_attached_heap(a.reservation, a.owner, a.object)
            .unwrap();
        let lease = k
            .claim_heap_cleanup(
                key,
                role,
                a.reservation,
                a.owner,
                a.object,
                k.fabric.scoped_pointers.revision(),
            )
            .unwrap();
        k.retire_heap_authority(key, lease, a.owner, a.object)
            .unwrap();
        lease
    })
}
fn begin(
    k: &mut Kernel,
    a: App,
    key: ProcessKey,
    lease: CleanupLease,
) -> Result<HeapCleanupSnapshot, HeapError> {
    no_alloc(|| k.begin_heap_scrub(key, lease, a.owner, a.object))
}
fn chunk(
    k: &mut Kernel,
    key: ProcessKey,
    s: HeapCleanupSnapshot,
    n: u64,
) -> Result<HeapCleanupSnapshot, HeapError> {
    no_alloc(|| k.scrub_heap_chunk(key, s, n))
}
fn complete(k: &mut Kernel, key: ProcessKey, mut s: HeapCleanupSnapshot) -> HeapCleanupSnapshot {
    while !s.is_complete() {
        let n = (s.rounded_bytes() - s.completed_bytes()).min(4096);
        s = chunk(k, key, s, n).unwrap();
    }
    s
}
fn release(k: &mut Kernel, key: ProcessKey, s: HeapCleanupSnapshot) -> Result<(), HeapError> {
    no_alloc(|| k.release_clean_heap(key, s))
}
fn rejected<T: std::fmt::Debug>(
    k: &mut Kernel,
    op: impl FnOnce(&mut Kernel) -> Result<T, HeapError>,
) {
    let before = snapshot(&k.fabric);
    assert!(op(k).is_err());
    assert_eq!(snapshot(&k.fabric), before);
}
fn fill(k: &mut Kernel, a: App, value: u8) {
    let r = row(&k.fabric, a.object);
    let lo = r.extents.physical.base as usize;
    let hi = lo + r.extents.physical.size as usize;
    k.fabric.memory[lo..hi].fill(value);
    let h = k.fabric.private_heap.as_mut().unwrap();
    let start = ((r.extents.physical.base - h.pool.base) / 16) as usize;
    h.shadow[start..start + (r.extents.physical.size / 16) as usize].fill(Some(a.pointer));
}

#[test]
fn a238_cleanup_zeroes_full_rounded_backing_and_tags_then_refunds_exactly_once() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 4097, false);
    let (key, role) = worker(&mut k);
    fill(&mut k, a, 0xa7);
    let r = row(&k.fabric, a.object);
    let fixed = k.fabric.scoped_pointers.fixed_metadata_bytes();
    let lease = retire(&mut k, a, key, role);
    let s = begin(&mut k, a, key, lease).unwrap();
    let first = chunk(&mut k, key, s, 4096).unwrap();
    let lo = r.extents.physical.base as usize;
    assert!(k.fabric.memory[lo..lo + 4096].iter().all(|b| *b == 0));
    assert!(
        k.fabric.memory[lo + 4096..lo + 8192]
            .iter()
            .all(|b| *b == 0xa7)
    );
    assert_eq!(
        k.fabric.scoped_pointers.total_reserved_bytes(),
        fixed + 8192
    );
    rejects(&mut k, HeapError::Busy, |k| release(k, key, first));
    let clean = chunk(&mut k, key, first, 4096).unwrap();
    assert!(clean.is_complete());
    assert_eq!(clean.completed_bytes(), 8192);
    assert!(k.fabric.memory[lo..lo + 8192].iter().all(|b| *b == 0));
    let h = k.fabric.private_heap.as_ref().unwrap();
    let start = ((r.extents.physical.base - h.pool.base) / 16) as usize;
    assert!(h.shadow[start..start + 512].iter().all(Option::is_none));
    release(&mut k, key, clean).unwrap();
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), fixed);
    assert!(
        k.fabric
            .private_heap
            .as_ref()
            .unwrap()
            .rows
            .iter()
            .all(Option::is_none)
    );
    rejected(&mut k, |k| release(k, key, clean));
    assert!(
        k.fabric
            .scoped_pointers
            .reserved_extents(a.reservation)
            .is_err()
    );
}

#[test]
fn a238_a_exhausts_and_exits_c_reuses_clean_backing_while_b_work_stays_correct() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 8192, true);
    let b = allocation(&mut k, 8192, true);
    let (key, role) = worker(&mut k);
    let ta = write(&mut k, a, 9, &[0xde, 0xad]).unwrap();
    let tb = write(&mut k, b, 7, &[65, 0, 255, 66]).unwrap();
    rejected(&mut k, |k| {
        no_alloc(|| {
            k.fabric.scoped_pointers.reserve_heap(
                a.account,
                8193,
                k.fabric.scoped_pointers.revision(),
            )
        })
    });
    no_alloc(|| k.fabric.execute_heap_cpu_work(ta)).unwrap();
    no_alloc(|| k.fabric.finish_heap_cpu_work(ta)).unwrap();
    let old = row(&k.fabric, a.object);
    let b_row = row(&k.fabric, b.object);
    let lease = retire(&mut k, a, key, role);
    k.processes[a.key.slot].state = ProcessState::Zombie;
    no_alloc(|| k.fabric.scoped_pointers.close_owner(a.account)).unwrap();
    let requests = format!("{:?}", work(&k));
    let start = begin(&mut k, a, key, lease).unwrap();
    let clean = complete(&mut k, key, start);
    release(&mut k, key, clean).unwrap();
    no_alloc(|| k.fabric.scoped_pointers.release_owner(a.account)).unwrap();
    assert_eq!(format!("{:?}", work(&k)), requests);
    let lo = old.extents.physical.base as usize;
    assert!(k.fabric.memory[lo..lo + 8192].iter().all(|b| *b == 0));
    let c = allocation(&mut k, 8192, true);
    assert_eq!(
        row(&k.fabric, c.object).extents.physical,
        old.extents.physical
    );
    assert_ne!(c.pointer.words()[0], a.pointer.words()[0]);
    assert_ne!(c.object, a.object);
    assert_eq!(row(&k.fabric, b.object), b_row);
    rejected(&mut k, |k| {
        no_alloc(|| {
            k.fabric
                .scoped_pointers
                .prepare_heap_pointer(a.pointer, a.owner)
        })
    });
    rejected(&mut k, |k| {
        no_alloc(|| {
            k.fabric
                .scoped_pointers
                .prepare_heap_pointer(a.pointer, c.owner)
        })
    });
    no_alloc(|| k.fabric.execute_heap_cpu_work(tb)).unwrap();
    no_alloc(|| k.fabric.finish_heap_cpu_work(tb)).unwrap();
    let bbase = b_row.extents.physical.base as usize;
    assert_eq!(&k.fabric.memory[bbase + 7..bbase + 11], &[65, 0, 255, 66]);
    assert!(read(&mut k, c, 0, 1).is_ok());
}

#[test]
fn a238_chunks_reject_stale_receipts_invalid_spans_and_duplicates_atomically() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 4097, false);
    let (key, role) = worker(&mut k);
    let lease = retire(&mut k, a, key, role);
    let start = begin(&mut k, a, key, lease).unwrap();
    for n in [0, 1, 17, 4097, 8192, u64::MAX] {
        rejects(&mut k, HeapError::Size, |k| chunk(k, key, start, n));
    }
    let first = chunk(&mut k, key, start, 16).unwrap();
    rejects(&mut k, HeapError::StaleCleanup, |k| {
        chunk(k, key, start, 16)
    });
    rejected(&mut k, |k| release(k, key, start));
    rejects(&mut k, HeapError::Busy, |k| begin(k, a, key, lease));
    let clean = complete(&mut k, key, first);
    rejects(&mut k, HeapError::Busy, |k| chunk(k, key, clean, 16));
    let before = snapshot(&k.fabric);
    assert_eq!(
        no_alloc(|| k
            .fabric
            .close_attached_heap(a.reservation, a.owner, a.object)),
        Ok(HeapCloseOutcome::AlreadyRetired)
    );
    assert_eq!(snapshot(&k.fabric), before);
    release(&mut k, key, clean).unwrap();
}

#[test]
fn a238_worker_failure_restarts_retired_partial_and_clean_jobs_and_rejects_old_receipts() {
    for chunks in 0..3 {
        let mut k = machine(0, 0);
        let a = allocation(&mut k, 4097, false);
        let (key, role) = worker(&mut k);
        let (new_key, new_role) = worker(&mut k);
        let lease = retire(&mut k, a, key, role);
        let mut old = None;
        if chunks > 0 {
            let s = begin(&mut k, a, key, lease).unwrap();
            old = Some(if chunks == 1 {
                chunk(&mut k, key, s, 4096).unwrap()
            } else {
                complete(&mut k, key, s)
            });
        }
        let charge = k.fabric.scoped_pointers.total_reserved_bytes();
        no_alloc(|| k.revoke_heap_cleanup(lease, a.owner, a.object)).unwrap();
        rejects(&mut k, HeapError::Worker, |k| {
            no_alloc(|| k.recover_heap_cleanup(lease, a.owner, a.object))
        });
        no_alloc(|| k.fence_cleanup_worker(role)).unwrap();
        no_alloc(|| k.recover_heap_cleanup(lease, a.owner, a.object)).unwrap();
        assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), charge);
        let fresh = no_alloc(|| {
            k.claim_heap_cleanup(
                new_key,
                new_role,
                a.reservation,
                a.owner,
                a.object,
                k.fabric.scoped_pointers.revision(),
            )
        })
        .unwrap();
        if let Some(old) = old {
            rejected(&mut k, |k| chunk(k, key, old, 16));
            rejected(&mut k, |k| release(k, new_key, old));
        }
        let restart = begin(&mut k, a, new_key, fresh).unwrap();
        assert_eq!(restart.completed_bytes(), 0);
        let clean = complete(&mut k, new_key, restart);
        release(&mut k, new_key, clean).unwrap();
        no_alloc(|| k.remove_cleanup_worker(role)).unwrap();
    }
}

#[test]
fn a238_new_process_mapping_blocks_each_cleanup_effect_and_final_release() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 31, false);
    let other = process(&mut k);
    let (key, role) = worker(&mut k);
    let lease = retire(&mut k, a, key, role);
    let start = begin(&mut k, a, key, lease).unwrap();
    k.processes[other.slot].core.address_map.add(0, 0, a.object);
    rejects(&mut k, HeapError::Busy, |k| chunk(k, key, start, 4096));
    k.processes[other.slot].core.address_map = crate::anka64::core::AddressMap::new();
    let clean = complete(&mut k, key, start);
    k.processes[other.slot].state = ProcessState::Zombie;
    k.processes[other.slot]
        .core
        .address_map
        .add(0, 16, a.object);
    rejects(&mut k, HeapError::Busy, |k| release(k, key, clean));
    k.processes[other.slot].core.address_map = crate::anka64::core::AddressMap::new();
    release(&mut k, key, clean).unwrap();
}

#[test]
fn a238_new_legacy_grant_blocks_chunk_and_release_without_refund() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 31, false);
    let (key, role) = worker(&mut k);
    let lease = retire(&mut k, a, key, role);
    let start = begin(&mut k, a, key, lease).unwrap();
    k.fabric
        .domains
        .get_mut(&a.owner.domain)
        .unwrap()
        .capabilities
        .push(CapabilityEntry {
            cap: Capability64::new(a.object, Generation(0), 0, 1, Permissions::RW),
            authority_id: None,
        });
    rejects(&mut k, HeapError::Busy, |k| chunk(k, key, start, 4096));
    k.fabric
        .domains
        .get_mut(&a.owner.domain)
        .unwrap()
        .capabilities
        .clear();
    let clean = complete(&mut k, key, start);
    k.fabric
        .pointer_stack_objects
        .insert(a.object, (a.owner.context, a.owner.domain));
    rejects(&mut k, HeapError::Busy, |k| release(k, key, clean));
    k.fabric.pointer_stack_objects.remove(&a.object);
    release(&mut k, key, clean).unwrap();
}

#[test]
fn a238_foreign_orphan_work_blocks_scrub_and_release_until_repaired() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 31, false);
    let b = allocation(&mut k, 31, true);
    let (key, role) = worker(&mut k);
    let lease = retire(&mut k, a, key, role);
    let start = begin(&mut k, a, key, lease).unwrap();
    let ticket = read(&mut k, b, 0, 1).unwrap();
    let record = work_mut(&mut k).records[0].take();
    rejects(&mut k, HeapError::StaleWork, |k| chunk(k, key, start, 4096));
    work_mut(&mut k).records[0] = record;
    let clean = complete(&mut k, key, start);
    work_mut(&mut k).records[0] = None;
    rejects(&mut k, HeapError::StaleWork, |k| release(k, key, clean));
    work_mut(&mut k).records[0] = record;
    release(&mut k, key, clean).unwrap();
    validate(&mut k, ticket).unwrap();
}

#[test]
fn a238_worker_process_incarnation_is_rechecked_for_chunk_and_release() {
    for at_release in [false, true] {
        let mut k = machine(0, 0);
        let a = allocation(&mut k, 31, false);
        let (key, role) = worker(&mut k);
        let lease = retire(&mut k, a, key, role);
        let start = begin(&mut k, a, key, lease).unwrap();
        let s = if at_release {
            complete(&mut k, key, start)
        } else {
            start
        };
        k.processes[key.slot].generation += 1;
        if at_release {
            rejects(&mut k, HeapError::Worker, |k| release(k, key, s));
        } else {
            rejects(&mut k, HeapError::Worker, |k| chunk(k, key, s, 4096));
        }
    }
}

#[test]
fn a238_old_private_initialization_and_application_writers_cannot_dirty_clean_custody() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 31, false);
    let old = k
        .fabric
        .private_heap_initialization(
            a.reservation,
            a.owner,
            a.object,
            k.fabric.scoped_pointers.revision(),
        )
        .unwrap();
    let (key, role) = worker(&mut k);
    let lease = retire(&mut k, a, key, role);
    let start = begin(&mut k, a, key, lease).unwrap();
    let clean = complete(&mut k, key, start);
    rejected(&mut k, |k| {
        no_alloc(|| {
            k.fabric
                .write_private_heap(old, a.owner, 0, &[99], k.fabric.scoped_pointers.revision())
        })
    });
    let agent = k.processes[a.key.slot].core.agent;
    rejected(&mut k, |k| {
        no_alloc(|| k.fabric.write_heap_bytes(a.owner, agent, a.pointer, &[99]))
    });
    release(&mut k, key, clean).unwrap();
}

#[test]
fn a238_bounded_repeated_reuse_keeps_table_capacities_and_fixed_charge_constant() {
    let mut k = machine(0, 0);
    let mut a = allocation(&mut k, 31, false);
    let (key, role) = worker(&mut k);
    let fixed = k.fabric.scoped_pointers.fixed_metadata_bytes();
    let capacity = k
        .fabric
        .private_heap
        .as_ref()
        .map(|h| (h.rows.capacity(), h.shadow.capacity()));
    for _ in 0..32 {
        fill(&mut k, a, 0xad);
        let lease = retire(&mut k, a, key, role);
        let start = begin(&mut k, a, key, lease).unwrap();
        let clean = complete(&mut k, key, start);
        let extents = row(&k.fabric, a.object).extents;
        release(&mut k, key, clean).unwrap();
        assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), fixed);
        assert_eq!(
            k.fabric
                .private_heap
                .as_ref()
                .map(|h| (h.rows.capacity(), h.shadow.capacity())),
            capacity
        );
        let reservation = reserve(&mut k.fabric, a.account, 31);
        let object = attach(&mut k.fabric, a.owner, reservation);
        assert_eq!(row(&k.fabric, object).extents, extents);
        assert!(object.0 > a.object.0);
        let fresh = fixture::token(reservation, 0);
        assert_ne!(fresh.words()[0], a.pointer.words()[0]);
        rejected(&mut k, |k| release(k, key, clean));
        a = App {
            reservation,
            object,
            pointer: fresh,
            ..a
        };
    }
}

#[test]
fn a238_arbitrary_release_order_coalesces_the_pool_and_virtual_holes() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 31, false);
    let r2 = reserve(&mut k.fabric, a.account, 31);
    let r3 = reserve(&mut k.fabric, a.account, 31);
    let b = App {
        reservation: r2,
        object: attach(&mut k.fabric, a.owner, r2),
        pointer: fixture::token(r2, 0),
        ..a
    };
    let c = App {
        reservation: r3,
        object: attach(&mut k.fabric, a.owner, r3),
        pointer: fixture::token(r3, 0),
        ..a
    };
    let (key, role) = worker(&mut k);
    for app in [b, a, c] {
        let lease = retire(&mut k, app, key, role);
        let start = begin(&mut k, app, key, lease).unwrap();
        let clean = complete(&mut k, key, start);
        release(&mut k, key, clean).unwrap();
    }
    let full = reserve(&mut k.fabric, a.account, 0x4000);
    assert_eq!(
        k.fabric
            .scoped_pointers
            .reserved_extents(full)
            .unwrap()
            .physical,
        profile().physical_pool
    );
}

#[test]
fn a238_fresh_allocation_requires_its_own_initialization_despite_clean_backing() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 31, false);
    let (key, role) = worker(&mut k);
    let lease = retire(&mut k, a, key, role);
    let start = begin(&mut k, a, key, lease).unwrap();
    let clean = complete(&mut k, key, start);
    release(&mut k, key, clean).unwrap();
    let reservation = reserve(&mut k.fabric, a.account, 31);
    let object = attach(&mut k.fabric, a.owner, reservation);
    let init = k
        .fabric
        .private_heap_initialization(
            reservation,
            a.owner,
            object,
            k.fabric.scoped_pointers.revision(),
        )
        .unwrap();
    assert_eq!(init.initialized_bytes(), 0);
    assert!(!init.is_complete());
    rejected(&mut k, |k| release(k, key, clean));
    rejected(&mut k, |k| {
        no_alloc(|| {
            k.fabric.validate_private_heap_initialization(
                init,
                a.owner,
                k.fabric.scoped_pointers.revision(),
            )
        })
    });
}
