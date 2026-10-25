use super::super::tests::{
    add_owner, assert_only_registry_changed, attach, limits, profile, reserve, row, snapshot,
};
use super::*;
use crate::anka64::core::Anka64Core;
use crate::anka64::fabric::{AuthResult, request};
use crate::anka64::os::{Kernel, ProcessState};
use crate::anka64::scoped_pointers::heap::{OwnerAccount, cell_test_support as fixture, no_alloc};
use crate::anka64::state::*;

#[derive(Clone, Copy)]
struct Job {
    owner: AllocationOwner,
    account: OwnerAccount,
    reservation: HeapReservation,
    object: ObjectId,
}

fn machine(capacity: usize) -> Kernel {
    Kernel::new(
        Fabric::with_private_heap_and_workers(0x10000, limits(), profile(), capacity).unwrap(),
    )
}
fn process(k: &mut Kernel) -> ProcessKey {
    let domain = k.fabric.create_domain();
    let agent = AgentId(100 + k.processes.len() as u64);
    k.fabric
        .register_agent(agent, AgentKind::Cpu(CoreId(0)), domain);
    k.spawn(Anka64Core::new(agent, domain))
}
fn enroll(k: &mut Kernel, key: ProcessKey) -> CleanupWorker {
    no_alloc(|| k.enroll_cleanup_worker(key, k.fabric.scoped_pointers.revision())).unwrap()
}
fn job(k: &mut Kernel, slot: usize, close: bool) -> Job {
    let (owner, account) = add_owner(&mut k.fabric, slot);
    let reservation = reserve(&mut k.fabric, account, 64);
    let object = attach(&mut k.fabric, owner, reservation);
    if close {
        no_alloc(|| k.fabric.close_attached_heap(reservation, owner, object)).unwrap();
    }
    Job {
        owner,
        account,
        reservation,
        object,
    }
}
fn claim(
    k: &mut Kernel,
    key: ProcessKey,
    w: CleanupWorker,
    job: Job,
) -> Result<CleanupLease, HeapError> {
    no_alloc(|| {
        k.claim_heap_cleanup(
            key,
            w,
            job.reservation,
            job.owner,
            job.object,
            k.fabric.scoped_pointers.revision(),
        )
    })
}
fn auth(k: &mut Kernel, key: ProcessKey, lease: CleanupLease, job: Job) -> Result<(), HeapError> {
    no_alloc(|| k.authenticate_heap_cleanup(key, lease, job.owner, job.object))
}
fn rejects<T: std::fmt::Debug>(
    k: &mut Kernel,
    error: HeapError,
    op: impl FnOnce(&mut Kernel) -> Result<T, HeapError>,
) {
    let before = snapshot(&k.fabric);
    assert_eq!(op(k).unwrap_err(), error);
    assert_eq!(snapshot(&k.fabric), before);
}

#[test]
fn a235a_runtime_enrollment_requires_current_running_process_and_explicit_role() {
    let mut k = machine(2);
    let key = process(&mut k);
    let other = process(&mut k);
    let j = job(&mut k, 20, true);
    for bad in [
        ProcessKey {
            slot: usize::MAX,
            ..key
        },
        ProcessKey {
            generation: 1,
            ..key
        },
    ] {
        rejects(&mut k, HeapError::Worker, |k| {
            no_alloc(|| k.enroll_cleanup_worker(bad, k.fabric.scoped_pointers.revision()))
        });
    }
    for state in [
        ProcessState::Zombie,
        ProcessState::Free,
        ProcessState::Retired,
    ] {
        k.processes[key.slot].state = state;
        rejects(&mut k, HeapError::Worker, |k| {
            no_alloc(|| k.enroll_cleanup_worker(key, k.fabric.scoped_pointers.revision()))
        });
    }
    k.processes[key.slot].state = ProcessState::Running;
    let w = enroll(&mut k, key);
    rejects(&mut k, HeapError::Worker, |k| claim(k, other, w, j));
    assert!(claim(&mut k, key, w, j).is_ok());
    // The application owner's account is not consulted for role issuance.
    assert_eq!(
        k.fabric
            .scoped_pointers
            .account_reserved_bytes(j.account)
            .unwrap(),
        4096
    );
}

#[test]
fn a235a_runtime_enrollment_requires_current_domain_and_registered_cpu() {
    for mode in 0..5 {
        let mut k = machine(1);
        let key = process(&mut k);
        let agent = k.processes[key.slot].core.agent;
        let domain = k.processes[key.slot].core.domain;
        match mode {
            0 => {
                k.fabric.agents.remove(&agent);
            }
            1 => {
                k.fabric.agents.get_mut(&agent).unwrap().kind = AgentKind::Network;
            }
            2 => {
                k.fabric.agents.get_mut(&agent).unwrap().domain = DomainId(999);
            }
            3 => {
                k.fabric.destroy_domain(domain);
            }
            _ => {
                k.fabric.agents.get_mut(&agent).unwrap().id = AgentId(999);
            }
        }
        rejects(&mut k, HeapError::Worker, |k| {
            no_alloc(|| k.enroll_cleanup_worker(key, k.fabric.scoped_pointers.revision()))
        });
    }
}

#[test]
fn a235a_fabric_constructor_charges_workers_and_scratch_before_exposure() {
    let plain = machine(0);
    let k = machine(3);
    assert!(
        k.fabric.scoped_pointers.fixed_metadata_bytes()
            > plain.fabric.scoped_pointers.fixed_metadata_bytes()
    );
    let fixed = k.fabric.scoped_pointers.fixed_metadata_bytes();
    assert!(
        Fabric::with_private_heap_and_workers(
            0x10000,
            RegistryLimits {
                global_bytes: fixed,
                ..limits()
            },
            profile(),
            3
        )
        .is_ok()
    );
    assert!(matches!(
        Fabric::with_private_heap_and_workers(
            0x10000,
            RegistryLimits {
                global_bytes: fixed - 1,
                ..limits()
            },
            profile(),
            3
        ),
        Err(HeapError::Capacity(Resource::GlobalBytes))
    ));
    let mut zero = machine(0);
    let key = process(&mut zero);
    rejects(&mut zero, HeapError::Capacity(Resource::Workers), |k| {
        no_alloc(|| k.enroll_cleanup_worker(key, k.fabric.scoped_pointers.revision()))
    });
}

#[test]
fn a235a_claim_preserves_dirty_backing_tags_custody_and_charges() {
    let mut k = machine(1);
    let key = process(&mut k);
    let w = enroll(&mut k, key);
    let j = job(&mut k, 20, true);
    k.fabric.memory.fill(0xa5);
    k.fabric
        .private_heap
        .as_mut()
        .unwrap()
        .shadow
        .fill(Some(fixture::token(j.reservation, 0)));
    let before = snapshot(&k.fabric);
    let extents = k
        .fabric
        .scoped_pointers
        .reserved_extents(j.reservation)
        .unwrap();
    let charged = k.fabric.scoped_pointers.total_reserved_bytes();
    let lease = claim(&mut k, key, w, j).unwrap();
    assert_only_registry_changed(before, &k.fabric);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), charged);
    assert_eq!(
        k.fabric
            .scoped_pointers
            .reserved_extents(j.reservation)
            .unwrap(),
        extents
    );
    let before = snapshot(&k.fabric);
    auth(&mut k, key, lease, j).unwrap();
    assert_eq!(snapshot(&k.fabric), before);
    rejects(&mut k, HeapError::Lease, |k| claim(k, key, w, j));
    rejects(&mut k, HeapError::Busy, |k| {
        no_alloc(|| k.fabric.scoped_pointers.abort_heap(j.reservation))
    });
}

#[test]
fn a235a_claim_requires_attached_closing_queued_job_not_merely_a_reservation() {
    let mut k = machine(1);
    let key = process(&mut k);
    let w = enroll(&mut k, key);
    let (owner, account) = add_owner(&mut k.fabric, 20);
    let r = reserve(&mut k.fabric, account, 64);
    let mut j = Job {
        owner,
        account,
        reservation: r,
        object: ObjectId(0),
    };
    rejects(&mut k, HeapError::Busy, |k| claim(k, key, w, j));
    j.object = attach(&mut k.fabric, owner, r);
    rejects(&mut k, HeapError::Busy, |k| claim(k, key, w, j));
    // Conditional-live fixture only; production publication is still disabled.
    fixture::activate(&mut k.fabric.scoped_pointers, r);
    rejects(&mut k, HeapError::Busy, |k| claim(k, key, w, j));
    k.fabric.close_attached_heap(r, owner, j.object).unwrap();
    assert!(claim(&mut k, key, w, j).is_ok());
}

#[test]
fn a235a_exact_custody_is_rechecked_before_claim_and_every_lease_use() {
    for claimed in [false, true] {
        for mode in 0..10 {
            let mut k = machine(1);
            let key = process(&mut k);
            let w = enroll(&mut k, key);
            let j = job(&mut k, 20, true);
            let other = job(&mut k, 21, false);
            let lease = claimed.then(|| claim(&mut k, key, w, j).unwrap());
            let mut request = j;
            if mode == 8 {
                request.owner.context += 1;
            } else if mode == 9 {
                request.object = other.object;
            } else {
                let rows = &mut k.fabric.private_heap.as_mut().unwrap().rows;
                let held = rows
                    .iter_mut()
                    .flatten()
                    .find(|r| r.object == j.object)
                    .unwrap();
                match mode {
                    0 => held.reservation = other.reservation,
                    1 => held.owner = other.owner,
                    2 => held.logical += 1,
                    3 => held.object_generation = Generation(1),
                    4 => held.object = ObjectId(u64::MAX),
                    5 => held.extents.physical.base += 4096,
                    6 => held.extents.virtual_extent.base += 4096,
                    _ => held.planned_rights = Permissions::READ,
                }
            }
            let error = if mode == 8 {
                HeapError::Owner
            } else {
                HeapError::StaleReservation
            };
            rejects(&mut k, error, |k| match lease {
                Some(lease) => auth(k, key, lease, request),
                None => claim(k, key, w, request).map(|_| ()),
            });
        }
    }
}

#[test]
fn a235a_worker_death_reincarnation_context_and_domain_changes_reject_old_lease() {
    for mode in 0..7 {
        let mut k = machine(1);
        let key = process(&mut k);
        let w = enroll(&mut k, key);
        let j = job(&mut k, 20, true);
        let lease = claim(&mut k, key, w, j).unwrap();
        let core = &mut k.processes[key.slot].core;
        let agent = core.agent;
        let domain = core.domain;
        match mode {
            0 => k.processes[key.slot].state = ProcessState::Zombie,
            1 => k.processes[key.slot].generation += 1,
            2 => *core = Anka64Core::new(agent, domain),
            3 => core.domain = k.fabric.create_domain(),
            4 => {
                k.fabric.destroy_domain(domain);
            }
            5 => {
                k.fabric.agents.remove(&agent);
            }
            _ => k.fabric.agents.get_mut(&agent).unwrap().kind = AgentKind::Network,
        }
        rejects(&mut k, HeapError::Worker, |k| auth(k, key, lease, j));
        if mode == 1 {
            rejects(&mut k, HeapError::Worker, |k| {
                auth(
                    k,
                    ProcessKey {
                        generation: 1,
                        ..key
                    },
                    lease,
                    j,
                )
            });
        }
        // Supervisor fencing still works with no live matching process/CPU.
        let before = snapshot(&k.fabric);
        no_alloc(|| k.fence_cleanup_worker(w)).unwrap();
        assert_only_registry_changed(before, &k.fabric);
        rejects(&mut k, HeapError::Busy, |k| {
            no_alloc(|| k.remove_cleanup_worker(w))
        });
    }
}

#[test]
fn a235a_worker_role_can_migrate_to_a_current_cpu_in_the_same_domain() {
    let mut k = machine(1);
    let key = process(&mut k);
    let w = enroll(&mut k, key);
    let j = job(&mut k, 20, true);
    let lease = claim(&mut k, key, w, j).unwrap();
    let domain = k.processes[key.slot].core.domain;
    k.fabric
        .register_agent(AgentId(999), AgentKind::Cpu(CoreId(1)), domain);
    k.processes[key.slot].core.agent = AgentId(999);
    auth(&mut k, key, lease, j).unwrap();
    k.fabric.agents.get_mut(&AgentId(999)).unwrap().domain = DomainId(999);
    rejects(&mut k, HeapError::Worker, |k| auth(k, key, lease, j));
}

#[test]
fn a235a_global_fence_invalidates_all_copied_leases_and_preserves_other_worker() {
    let mut k = machine(2);
    let a = process(&mut k);
    let b = process(&mut k);
    let wa = enroll(&mut k, a);
    let wb = enroll(&mut k, b);
    let ja = job(&mut k, 20, true);
    let ja2 = job(&mut k, 21, true);
    let jb = job(&mut k, 22, true);
    let la = claim(&mut k, a, wa, ja).unwrap();
    let copy = la;
    let la2 = claim(&mut k, a, wa, ja2).unwrap();
    let lb = claim(&mut k, b, wb, jb).unwrap();
    fixture::set_revision(&mut k.fabric.scoped_pointers, u64::MAX);
    let charged = k.fabric.scoped_pointers.total_reserved_bytes();
    let before = snapshot(&k.fabric);
    no_alloc(|| k.fence_cleanup_worker(wa)).unwrap();
    assert_only_registry_changed(before, &k.fabric);
    for (lease, j) in [(la, ja), (copy, ja), (la2, ja2)] {
        rejects(&mut k, HeapError::Worker, |k| auth(k, a, lease, j));
    }
    auth(&mut k, b, lb, jb).unwrap();
    rejects(&mut k, HeapError::Worker, |k| {
        no_alloc(|| k.fence_cleanup_worker(wa))
    });
    rejects(&mut k, HeapError::Busy, |k| {
        no_alloc(|| k.remove_cleanup_worker(wa))
    });
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), charged);
    assert_eq!(k.fabric.scoped_pointers.revision(), u64::MAX);
}

#[test]
fn a235a_owner_exit_and_duplicate_close_preserve_worker_lease() {
    let mut k = machine(1);
    let key = process(&mut k);
    let w = enroll(&mut k, key);
    let j = job(&mut k, 20, false);
    no_alloc(|| k.fabric.scoped_pointers.close_owner(j.account)).unwrap();
    k.fabric.destroy_domain(j.owner.domain);
    let lease = claim(&mut k, key, w, j).unwrap();
    let before = snapshot(&k.fabric);
    assert_eq!(
        no_alloc(|| k
            .fabric
            .close_attached_heap(j.reservation, j.owner, j.object))
        .unwrap(),
        crate::anka64::scoped_pointers::heap::HeapCloseOutcome::AlreadyClosing
    );
    no_alloc(|| k.fabric.scoped_pointers.close_owner(j.account)).unwrap();
    auth(&mut k, key, lease, j).unwrap();
    assert_eq!(snapshot(&k.fabric), before);
}

#[test]
fn a235a_claim_does_not_misreport_pending_legacy_work_as_drained() {
    let mut k = machine(1);
    let key = process(&mut k);
    let w = enroll(&mut k, key);
    let j = job(&mut k, 20, true);
    let agent = k.processes[key.slot].core.agent;
    let domain = k.processes[key.slot].core.domain;
    let legacy = k.fabric.alloc_object("pending", 64, ObjectKind::Memory);
    assert!(k.fabric.place_object(legacy, 0x1000));
    k.fabric
        .grant(domain, legacy, 0, 16, Permissions::RW)
        .unwrap();
    let mut req = request(agent, domain, legacy, 0, Width::Byte, AccessKind::Write);
    req.length = 16;
    let tx = k.fabric.submit(req, Some(vec![1; 16]));
    k.fabric.advance(tx);
    k.fabric.advance(tx);
    assert_eq!(k.fabric.transactions[tx].state, TxState::Prepared);
    // Fault injection only: a conflict never becomes proof of safe reclamation.
    k.fabric.transactions[tx].physical_address = Some(0x1ff8);
    assert!(!k.fabric.heap_pool_is_private());
    let before = snapshot(&k.fabric);
    let lease = claim(&mut k, key, w, j).unwrap();
    assert_only_registry_changed(before, &k.fabric);
    auth(&mut k, key, lease, j).unwrap();
    assert_eq!(k.fabric.transactions[tx].state, TxState::Prepared);
    assert!(
        k.fabric
            .scoped_pointers
            .reserved_extents(j.reservation)
            .is_ok()
    );
    rejects(&mut k, HeapError::Busy, |k| {
        no_alloc(|| k.fabric.scoped_pointers.abort_heap(j.reservation))
    });
}

#[test]
fn a235a_claim_and_fence_grant_no_payload_or_raw_object_authority() {
    let mut k = machine(1);
    let key = process(&mut k);
    let w = enroll(&mut k, key);
    let j = job(&mut k, 20, true);
    let lease = claim(&mut k, key, w, j).unwrap();
    auth(&mut k, key, lease, j).unwrap();
    let domain = k.processes[key.slot].core.domain;
    let agent = k.processes[key.slot].core.agent;
    for fenced in [false, true] {
        if fenced {
            no_alloc(|| k.fence_cleanup_worker(w)).unwrap();
        }
        let before = snapshot(&k.fabric);
        no_alloc(|| {
            assert!(
                k.fabric
                    .grant(domain, j.object, 0, 1, Permissions::RW)
                    .is_none()
            );
            assert!(!k.fabric.initialize_object(j.object, 0, &[1]));
            assert!(!k.fabric.zero_object_extent(j.object));
            assert!(!k.fabric.place_object(j.object, 0));
            assert!(
                k.fabric
                    .try_read_physical(row(&k.fabric, j.object).extents.physical.base, 1)
                    .is_none()
            );
            assert!(matches!(
                k.fabric.authorize(&request(
                    agent,
                    domain,
                    j.object,
                    0,
                    Width::Byte,
                    AccessKind::Read
                )),
                AuthResult::Denied(_)
            ));
        });
        assert_eq!(snapshot(&k.fabric), before);
    }
}
