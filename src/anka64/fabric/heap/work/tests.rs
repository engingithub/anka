//! Real reserve/attach/initialize operations precede a TEST-ONLY publication
//! fixture. These are backend-admission witnesses, not guest malloc/I/O proofs.
mod runtime;
mod recovery;
mod retirement;
mod cleanup;
use super::super::tests::{
    assert_only_heap_and_registry_changed, assert_only_registry_changed, attach, limits, profile,
    reserve, row, snapshot,
};
use super::*;
use crate::anka64::core::Anka64Core;
use crate::anka64::fabric::{AuthResult, request};
use crate::anka64::os::{Kernel, ProcessState};
use crate::anka64::scoped_pointers::{
    PointerError,
    heap::{OwnerAccount, cell_test_support as fixture, no_alloc},
};
use crate::anka64::state::*;

#[derive(Clone, Copy)]
struct App {
    key: ProcessKey,
    owner: AllocationOwner,
    account: OwnerAccount,
    reservation: HeapReservation,
    object: ObjectId,
    pointer: ScopedPointer,
}

fn machine(tickets: usize, requests: usize) -> Kernel {
    Kernel::new(
        Fabric::with_private_heap_cpu_work(
            0x10000,
            limits(),
            profile(),
            2,
            HeapWorkLimits { tickets, requests },
        )
        .unwrap(),
    )
}
fn process(k: &mut Kernel) -> ProcessKey {
    let domain = k.fabric.create_domain();
    let agent = AgentId(100 + k.processes.len() as u64);
    k.fabric
        .register_agent(agent, AgentKind::Cpu(CoreId(0)), domain);
    k.spawn(Anka64Core::new(agent, domain))
}
fn allocation(k: &mut Kernel, size: u64, publish: bool) -> App {
    let key = process(k);
    let core = &k.processes[key.slot].core;
    let owner = AllocationOwner {
        process: key,
        context: core.context_identity(),
        domain: core.domain,
    };
    let account = k.fabric.scoped_pointers.admit_owner(owner, 0x4000).unwrap();
    let reservation = reserve(&mut k.fabric, account, size);
    let object = attach(&mut k.fabric, owner, reservation);
    let pointer = if publish {
        let mut init = k
            .fabric
            .private_heap_initialization(
                reservation,
                owner,
                object,
                k.fabric.scoped_pointers.revision(),
            )
            .unwrap();
        while !init.is_complete() {
            let amount = (init.rounded_bytes() - init.initialized_bytes()).min(4096);
            init = k
                .fabric
                .initialize_private_heap_chunk(
                    init,
                    owner,
                    amount,
                    k.fabric.scoped_pointers.revision(),
                )
                .unwrap();
        }
        fixture::activate(&mut k.fabric.scoped_pointers, reservation)
    } else {
        fixture::token(reservation, 0)
    };
    App {
        key,
        owner,
        account,
        reservation,
        object,
        pointer,
    }
}
fn read(k: &mut Kernel, a: App, position: u64, length: u64) -> Result<HeapWorkTicket, HeapError> {
    no_alloc(|| {
        k.register_heap_cpu_read(
            a.key,
            Some(fixture::at(a.pointer, position)),
            length,
            k.fabric.scoped_pointers.revision(),
        )
    })
}
fn write(k: &mut Kernel, a: App, position: u64, data: &[u8]) -> Result<HeapWorkTicket, HeapError> {
    no_alloc(|| {
        k.register_heap_cpu_write(
            a.key,
            Some(fixture::at(a.pointer, position)),
            data,
            k.fabric.scoped_pointers.revision(),
        )
    })
}
fn work(k: &Kernel) -> &HeapCpuWork {
    k.fabric
        .private_heap
        .as_ref()
        .unwrap()
        .work
        .as_ref()
        .unwrap()
}
fn work_mut(k: &mut Kernel) -> &mut HeapCpuWork {
    k.fabric
        .private_heap
        .as_mut()
        .unwrap()
        .work
        .as_mut()
        .unwrap()
}
fn validate(k: &mut Kernel, t: HeapWorkTicket) -> Result<(), HeapError> {
    no_alloc(|| k.fabric.validate_heap_work_ticket(t))
}
fn rejects<T: std::fmt::Debug>(
    k: &mut Kernel,
    error: HeapError,
    f: impl FnOnce(&mut Kernel) -> Result<T, HeapError>,
) {
    let before = snapshot(&k.fabric);
    assert_eq!(f(k).unwrap_err(), error);
    assert_eq!(snapshot(&k.fabric), before);
}

#[test]
fn a235b_fixed_storage_charges_both_actual_tables_payloads_and_scratch_once() {
    let plain = Fabric::with_private_heap_and_workers(0x10000, limits(), profile(), 2).unwrap();
    let k = machine(3, 4);
    let w = work(&k);
    let added = w.records.capacity() * size_of::<Option<WorkRecord>>()
        + w.sources.capacity() * size_of::<CpuSourceSlot>()
        + size_of::<Admission>()
        + size_of::<WorkBinding>()
        + size_of::<WorkRecord>()
        + super::runtime::scratch_bytes().unwrap() as usize;
    assert_eq!(w.records.len(), 3);
    assert_eq!(w.sources.len(), 4);
    assert_eq!(
        k.fabric.scoped_pointers.fixed_metadata_bytes(),
        plain.scoped_pointers.fixed_metadata_bytes() + added as u64
    );
    assert!(size_of::<CpuSourceSlot>() >= MAX_CPU_BYTES);
    let fixed = k.fabric.scoped_pointers.fixed_metadata_bytes();
    let tight = RegistryLimits {
        global_bytes: fixed,
        ..limits()
    };
    assert!(
        Fabric::with_private_heap_cpu_work(
            0x10000,
            tight,
            profile(),
            2,
            HeapWorkLimits {
                tickets: 3,
                requests: 4
            }
        )
        .is_ok()
    );
    assert!(matches!(
        Fabric::with_private_heap_cpu_work(
            0x10000,
            RegistryLimits {
                global_bytes: fixed - 1,
                ..limits()
            },
            profile(),
            2,
            HeapWorkLimits {
                tickets: 3,
                requests: 4
            }
        ),
        Err(HeapError::Capacity(Resource::GlobalBytes))
    ));
    for bad in [
        HeapWorkLimits {
            tickets: usize::MAX,
            requests: 0,
        },
        HeapWorkLimits {
            tickets: 0,
            requests: usize::MAX,
        },
    ] {
        assert!(matches!(
            Fabric::with_private_heap_cpu_work(0x10000, limits(), profile(), 0, bad),
            Err(HeapError::Configuration)
        ));
    }
}

#[test]
fn a235b_profile_is_explicit_and_zero_capacity_is_nonadmitting() {
    let mut old = Kernel::new(
        Fabric::with_private_heap_and_workers(0x10000, limits(), profile(), 0).unwrap(),
    );
    let a = allocation(&mut old, 64, true);
    rejects(&mut old, HeapError::Configuration, |k| read(k, a, 0, 1));
    for (tickets, requests, error) in [
        (0, 1, Resource::WorkTickets),
        (1, 0, Resource::BackendRequests),
    ] {
        let mut k = machine(tickets, requests);
        let a = allocation(&mut k, 64, true);
        rejects(&mut k, HeapError::Capacity(error), |k| read(k, a, 0, 1));
    }
}

#[test]
fn a235b_registration_pins_exact_cpu_source_and_preserves_application_storage() {
    let mut k = machine(3, 3);
    let a = allocation(&mut k, 64, true);
    k.fabric.memory.fill(0xa5);
    k.fabric
        .private_heap
        .as_mut()
        .unwrap()
        .shadow
        .fill(Some(a.pointer));
    let before = snapshot(&k.fabric);
    let charge = k.fabric.scoped_pointers.total_reserved_bytes();
    let revision = k.fabric.scoped_pointers.revision();
    let t = write(&mut k, a, 7, &[65, 0, 255, 66]).unwrap();
    assert_only_heap_and_registry_changed(before, &k.fabric);
    assert_eq!(k.fabric.scoped_pointers.revision(), revision + 1);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), charge);
    let record = work(&k).checked_record(t).unwrap();
    assert_eq!(
        t,
        HeapWorkTicket {
            row: 1,
            operation: 1
        }
    );
    assert_eq!(
        record.source,
        CpuSourceKey {
            index: 0,
            generation: 0,
            request: 0
        }
    );
    let source = work(&k).sources[0].request.as_ref().unwrap();
    assert_eq!(source.pin, t);
    assert_eq!(source.binding, record.binding);
    assert_eq!(source.binding.reservation, a.reservation);
    assert_eq!(source.binding.owner, a.owner);
    assert_eq!(source.binding.object, a.object);
    assert_eq!(source.binding.offset, 7);
    assert_eq!(source.binding.length, 4);
    assert_eq!(source.binding.access, CpuAccess::Write);
    assert_eq!(&source.payload[..4], &[65, 0, 255, 66]);
    assert!(source.payload[4..].iter().all(|b| *b == 0));
    let before = snapshot(&k.fabric);
    validate(&mut k, t).unwrap();
    assert_eq!(snapshot(&k.fabric), before);
}

#[test]
fn a235b_write_input_is_owned_and_read_has_no_early_payload_effect() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 64, true);
    let mut input = [1, 2, 3];
    let first = write(&mut k, a, 0, &input).unwrap();
    input.fill(99);
    let second = read(&mut k, a, 0, 3).unwrap();
    assert_eq!(
        &work(&k).sources[0].request.as_ref().unwrap().payload[..3],
        &[1, 2, 3]
    );
    let source = work(&k).sources[1].request.as_ref().unwrap();
    assert_eq!(source.binding.access, CpuAccess::Read);
    assert!(source.payload.iter().all(|b| *b == 0));
    assert_ne!(first.operation, second.operation);
    assert_ne!(
        work(&k).checked_record(first).unwrap().source.request,
        work(&k).checked_record(second).unwrap().source.request
    );
    let base = row(&k.fabric, a.object).extents.physical.base as usize;
    assert_eq!(&k.fabric.memory[base..base + 3], &[0, 0, 0]);
}

#[test]
fn a235b_full_ledger_rejection_leaves_free_backend_slot_and_existing_pin_untouched() {
    let mut k = machine(1, 2);
    let a = allocation(&mut k, 64, true);
    let t = read(&mut k, a, 0, 1).unwrap();
    rejects(&mut k, HeapError::Capacity(Resource::WorkTickets), |k| {
        write(k, a, 1, &[7])
    });
    assert!(work(&k).sources[1].request.is_none());
    assert_eq!(work(&k).sources[1].next_generation, Some(0));
    validate(&mut k, t).unwrap();
}

#[test]
fn a235b_full_backend_rejection_does_not_insert_a_best_effort_ticket() {
    let mut k = machine(3, 2);
    let a = allocation(&mut k, 64, true);
    let b = allocation(&mut k, 64, true);
    let independent = read(&mut k, b, 0, 1).unwrap();
    let t = read(&mut k, a, 0, 1).unwrap();
    rejects(
        &mut k,
        HeapError::Capacity(Resource::BackendRequests),
        |k| write(k, a, 1, &[7]),
    );
    assert!(work(&k).records[2].is_none());
    assert_eq!(work(&k).next_operation, 3);
    validate(&mut k, t).unwrap();
    validate(&mut k, independent).unwrap();
}

#[test]
fn a235b_denied_admission_does_not_burn_ids_and_retry_uses_first_available_pair() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 64, true);
    let rev = k.fabric.scoped_pointers.revision();
    rejects(&mut k, HeapError::StaleRevision, |k| {
        no_alloc(|| k.register_heap_cpu_read(a.key, Some(a.pointer), 1, rev - 1))
    });
    rejects(&mut k, HeapError::Pointer(PointerError::Bounds), |k| {
        read(k, a, 64, 1)
    });
    let t = read(&mut k, a, 63, 1).unwrap();
    assert_eq!(
        t,
        HeapWorkTicket {
            row: 1,
            operation: 1
        }
    );
    assert_eq!(work(&k).checked_record(t).unwrap().source.request, 0);
}

#[test]
fn a235b_missing_kind_empty_oversized_padding_and_wrapping_spans_reject_atomically() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 4097, true);
    rejects(&mut k, HeapError::MissingKind, |k| {
        no_alloc(|| k.register_heap_cpu_read(a.key, None, 1, k.fabric.scoped_pointers.revision()))
    });
    for (offset, length) in [
        (0, 0),
        (0, 4097),
        (4097, 1),
        (4096, 2),
        (u64::MAX, 1),
        (1, u64::MAX),
    ] {
        rejects(&mut k, HeapError::Pointer(PointerError::Bounds), |k| {
            read(k, a, offset, length)
        });
    }
    rejects(&mut k, HeapError::Pointer(PointerError::Bounds), |k| {
        write(k, a, 0, &[])
    });
    let too_big = [1; 4097];
    rejects(&mut k, HeapError::Pointer(PointerError::Bounds), |k| {
        write(k, a, 0, &too_big)
    });
    let full = [7; 4096];
    assert!(write(&mut k, a, 0, &full).is_ok());
    assert!(read(&mut k, a, 4096, 1).is_ok());
}

#[test]
fn a235b_private_initialized_unpublished_and_incomplete_live_allocations_reject() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 64, false);
    rejects(&mut k, HeapError::Pointer(PointerError::Stale), |k| {
        read(k, a, 0, 1)
    });
    let init = k
        .fabric
        .private_heap_initialization(
            a.reservation,
            a.owner,
            a.object,
            k.fabric.scoped_pointers.revision(),
        )
        .unwrap();
    k.fabric
        .initialize_private_heap_chunk(init, a.owner, 4096, k.fabric.scoped_pointers.revision())
        .unwrap();
    rejects(&mut k, HeapError::Pointer(PointerError::Stale), |k| {
        read(k, a, 0, 1)
    });
    fixture::activate(&mut k.fabric.scoped_pointers, a.reservation);
    let held = k
        .fabric
        .private_heap
        .as_mut()
        .unwrap()
        .rows
        .iter_mut()
        .flatten()
        .find(|r| r.object == a.object)
        .unwrap();
    held.initialized_bytes = 16; // hostile conditional-live fixture
    rejects(&mut k, HeapError::Busy, |k| read(k, a, 0, 1));
}

#[test]
fn a235b_current_process_context_domain_cpu_and_incarnation_are_required() {
    for mode in 0..8 {
        let mut k = machine(2, 2);
        let a = allocation(&mut k, 64, true);
        let t = read(&mut k, a, 0, 1).unwrap();
        let core = &mut k.processes[a.key.slot].core;
        let agent = core.agent;
        let domain = core.domain;
        match mode {
            0 => k.processes[a.key.slot].state = ProcessState::Zombie,
            1 => k.processes[a.key.slot].generation += 1,
            2 => *core = Anka64Core::new(agent, domain),
            3 => {
                k.fabric.destroy_domain(domain);
            }
            4 => {
                k.fabric.agents.remove(&agent);
            }
            5 => k.fabric.agents.get_mut(&agent).unwrap().kind = AgentKind::Network,
            6 => k.fabric.agents.get_mut(&agent).unwrap().domain = DomainId(999),
            _ => k.fabric.agents.get_mut(&agent).unwrap().id = AgentId(999),
        }
        rejects(&mut k, HeapError::Owner, |k| write(k, a, 1, &[9]));
        if mode == 1 {
            let reincarnated = App {
                key: ProcessKey {
                    generation: 1,
                    ..a.key
                },
                ..a
            };
            rejects(&mut k, HeapError::Owner, |k| read(k, reincarnated, 0, 1));
        }
        // Retained records do not depend on owner/agent liveness to be observed.
        validate(&mut k, t).unwrap();
    }
}

#[test]
fn a235b_other_clients_and_local_pointer_tokens_cannot_select_a_heap() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 64, true);
    let b = allocation(&mut k, 64, true);
    rejects(&mut k, HeapError::Owner, |k| {
        no_alloc(|| {
            k.register_heap_cpu_read(
                b.key,
                Some(a.pointer),
                1,
                k.fabric.scoped_pointers.revision(),
            )
        })
    });
    let object = k.fabric.alloc_object("local", 32, ObjectKind::Memory);
    assert!(k.fabric.place_object(object, 0));
    k.fabric
        .grant(a.owner.domain, object, 0, 32, Permissions::RW)
        .unwrap();
    let scope = k
        .fabric
        .scoped_pointers
        .enter_scope_for(a.owner.context)
        .unwrap();
    let agent = k.processes[a.key.slot].core.agent;
    let mut req = request(
        agent,
        a.owner.domain,
        object,
        0,
        Width::Byte,
        AccessKind::Read,
    );
    req.length = 16;
    let local = k
        .fabric
        .register_scoped_pointer(scope, req, 0x8000, true)
        .unwrap();
    rejects(&mut k, HeapError::Pointer(PointerError::Stale), |k| {
        no_alloc(|| {
            k.register_heap_cpu_read(a.key, Some(local), 1, k.fabric.scoped_pointers.revision())
        })
    });
}

#[test]
fn a235b_exact_custody_rights_and_legacy_exclusion_precede_pair_commit() {
    for mode in 0..5 {
        let mut k = machine(1, 1);
        let a = allocation(&mut k, 64, true);
        let held = k
            .fabric
            .private_heap
            .as_mut()
            .unwrap()
            .rows
            .iter_mut()
            .flatten()
            .find(|r| r.object == a.object)
            .unwrap();
        match mode {
            0 => held.logical += 1,
            1 => held.object_generation = Generation(1),
            2 => held.planned_rights = Permissions::READ,
            3 => held.extents.virtual_extent.base += 4096,
            _ => {
                k.fabric.placement.insert(ObjectId(999), 0x2000);
            }
        }
        let error = match mode {
            2 => HeapError::Pointer(PointerError::Rights),
            4 => HeapError::Busy,
            _ => HeapError::StaleReservation,
        };
        rejects(&mut k, error, |k| read(k, a, 0, 1));
    }
}

#[test]
fn a235b_owner_closure_keeps_pins_and_charges_while_another_client_continues() {
    let mut k = machine(4, 4);
    let a = allocation(&mut k, 64, true);
    let b = allocation(&mut k, 64, true);
    let ta = write(&mut k, a, 0, &[9]).unwrap();
    let tb = read(&mut k, b, 0, 1).unwrap();
    let b_before = work(&k).checked_record(tb).unwrap();
    let charged = k.fabric.scoped_pointers.total_reserved_bytes();
    let before = snapshot(&k.fabric);
    no_alloc(|| k.fabric.scoped_pointers.close_owner(a.account)).unwrap();
    assert_only_registry_changed(before, &k.fabric);
    rejects(&mut k, HeapError::Pointer(PointerError::Stale), |k| {
        read(k, a, 0, 1)
    });
    assert!(write(&mut k, b, 1, &[8]).is_ok());
    validate(&mut k, ta).unwrap();
    validate(&mut k, tb).unwrap();
    assert_eq!(work(&k).checked_record(tb).unwrap(), b_before);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), charged);
    rejects(&mut k, HeapError::Busy, |k| {
        no_alloc(|| k.fabric.scoped_pointers.abort_heap(a.reservation))
    });
}

#[test]
fn a235b_cleanup_claim_and_worker_fence_do_not_consume_application_requests() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 64, true);
    let application_role = k
        .enroll_cleanup_worker(a.key, k.fabric.scoped_pointers.revision())
        .unwrap();
    let worker_key = process(&mut k);
    let worker = k
        .enroll_cleanup_worker(worker_key, k.fabric.scoped_pointers.revision())
        .unwrap();
    let ticket = write(&mut k, a, 0, &[7]).unwrap();
    // Ordinary CPU work binds the application account, not an optional cleanup
    // role of the same process. Removing that unreferenced role keeps the work.
    no_alloc(|| k.fence_cleanup_worker(application_role)).unwrap();
    no_alloc(|| k.remove_cleanup_worker(application_role)).unwrap();
    validate(&mut k, ticket).unwrap();
    no_alloc(|| {
        k.fabric
            .close_attached_heap(a.reservation, a.owner, a.object)
    })
    .unwrap();
    let before = snapshot(&k.fabric);
    let lease = no_alloc(|| {
        k.claim_heap_cleanup(
            worker_key,
            worker,
            a.reservation,
            a.owner,
            a.object,
            k.fabric.scoped_pointers.revision(),
        )
    })
    .unwrap();
    assert_only_registry_changed(before, &k.fabric);
    no_alloc(|| k.fence_cleanup_worker(worker)).unwrap();
    rejects(&mut k, HeapError::Worker, |k| {
        no_alloc(|| k.authenticate_heap_cleanup(worker_key, lease, a.owner, a.object))
    });
    validate(&mut k, ticket).unwrap();
    assert_eq!(work(&k).records.iter().flatten().count(), 1);
    assert_eq!(
        work(&k)
            .sources
            .iter()
            .filter(|s| s.request.is_some())
            .count(),
        1
    );
}

#[test]
fn a235b_tickets_require_exact_row_and_fresh_operation_not_numeric_notifications() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 64, true);
    let first = read(&mut k, a, 0, 1).unwrap();
    let second = read(&mut k, a, 1, 1).unwrap();
    for bad in [
        HeapWorkTicket { row: 0, ..first },
        HeapWorkTicket {
            row: u32::MAX,
            ..first
        },
        HeapWorkTicket {
            operation: 0,
            ..first
        },
        HeapWorkTicket {
            operation: second.operation,
            ..first
        },
    ] {
        rejects(&mut k, HeapError::StaleWork, |k| validate(k, bad));
    }
    validate(&mut k, first).unwrap();
    validate(&mut k, second).unwrap();
}

#[test]
fn a235b_source_tuple_pin_and_binding_mismatches_reject_without_releasing_any_row() {
    for mode in 0..12 {
        let mut k = machine(2, 2);
        let a = allocation(&mut k, 64, true);
        let t = read(&mut k, a, 0, 1).unwrap();
        let slot = &mut work_mut(&mut k).sources[0];
        let source = slot.request.as_mut().unwrap();
        match mode {
            0 => source.key.index = 1,
            1 => source.key.generation = 1,
            2 => source.key.request = 1,
            3 => source.pin.operation += 1,
            4 => source.pin.row = 2,
            5 => source.binding.agent = AgentId(999),
            6 => source.binding.offset = 1,
            7 => source.binding.length = 2,
            8 => source.binding.access = CpuAccess::Write,
            9 => source.binding.owner.context += 1,
            10 => source.binding.object_generation = Generation(1),
            _ => slot.next_generation = Some(9),
        }
        rejects(&mut k, HeapError::StaleWork, |k| validate(k, t));
        rejects(&mut k, HeapError::StaleWork, |k| read(k, a, 1, 1));
    }
}

#[test]
fn a235b_orphan_backend_or_missing_pin_is_not_free_capacity() {
    for erase_ledger in [false, true] {
        let mut k = machine(2, 2);
        let a = allocation(&mut k, 64, true);
        let t = read(&mut k, a, 0, 1).unwrap();
        if erase_ledger {
            work_mut(&mut k).records[0] = None;
        } else {
            work_mut(&mut k).sources[0].request = None;
        }
        rejects(&mut k, HeapError::StaleWork, |k| validate(k, t));
        rejects(&mut k, HeapError::StaleWork, |k| read(k, a, 1, 1));
    }
}

#[test]
fn a235b_retained_ticket_rechecks_actual_fabric_custody_after_closure() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    let t = read(&mut k, a, 0, 1).unwrap();
    k.fabric
        .close_attached_heap(a.reservation, a.owner, a.object)
        .unwrap();
    k.fabric
        .private_heap
        .as_mut()
        .unwrap()
        .rows
        .iter_mut()
        .flatten()
        .find(|r| r.object == a.object)
        .unwrap()
        .extents
        .physical
        .base += 4096;
    rejects(&mut k, HeapError::StaleReservation, |k| validate(k, t));
}

#[test]
fn a235b_operation_and_common_revision_exhaustion_preserve_last_registered_request() {
    for counter in [true, false] {
        let mut k = machine(2, 2);
        let a = allocation(&mut k, 64, true);
        if counter {
            work_mut(&mut k).next_operation = u64::MAX - 1;
        } else {
            fixture::set_revision(&mut k.fabric.scoped_pointers, u64::MAX - 1);
        }
        let t = read(&mut k, a, 0, 1).unwrap();
        let error = if counter {
            HeapError::Capacity(Resource::Identity)
        } else {
            HeapError::StaleRevision
        };
        rejects(&mut k, error, |k| read(k, a, 1, 1));
        validate(&mut k, t).unwrap();
        no_alloc(|| {
            k.fabric
                .close_attached_heap(a.reservation, a.owner, a.object)
        })
        .unwrap();
        validate(&mut k, t).unwrap();
    }
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    work_mut(&mut k).next_operation = 0;
    rejects(&mut k, HeapError::Capacity(Resource::Identity), |k| {
        read(k, a, 0, 1)
    });
}

#[test]
fn a235b_backend_request_and_source_generations_never_wrap() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 64, true);
    work_mut(&mut k).next_request = Some(u64::MAX);
    work_mut(&mut k).sources[0].next_generation = Some(u64::MAX);
    let t = read(&mut k, a, 0, 1).unwrap();
    let source = work(&k).checked_record(t).unwrap().source;
    assert_eq!(source.generation, u64::MAX);
    assert_eq!(source.request, u64::MAX);
    assert_eq!(work(&k).sources[0].next_generation, None);
    assert_eq!(work(&k).next_request, None);
    rejects(&mut k, HeapError::Capacity(Resource::Identity), |k| {
        read(k, a, 1, 1)
    });
    validate(&mut k, t).unwrap();
    let mut retired = machine(1, 1);
    let a = allocation(&mut retired, 64, true);
    work_mut(&mut retired).sources[0].next_generation = None;
    rejects(
        &mut retired,
        HeapError::Capacity(Resource::BackendRequests),
        |k| read(k, a, 0, 1),
    );
}

#[test]
fn a235b_request_registration_does_not_grant_raw_heap_access_or_legacy_pipeline_entry() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    let t = write(&mut k, a, 0, &[9]).unwrap();
    let agent = k.processes[a.key.slot].core.agent;
    let before = snapshot(&k.fabric);
    no_alloc(|| {
        assert!(
            k.fabric
                .grant(a.owner.domain, a.object, 0, 1, Permissions::RW)
                .is_none()
        );
        assert!(!k.fabric.initialize_object(a.object, 0, &[3]));
        assert!(!k.fabric.zero_object_extent(a.object));
        assert!(!k.fabric.place_object(a.object, 0));
        assert!(matches!(
            k.fabric.authorize(&request(
                agent,
                a.owner.domain,
                a.object,
                0,
                Width::Byte,
                AccessKind::Write
            )),
            AuthResult::Denied(_)
        ));
    });
    assert_eq!(snapshot(&k.fabric), before);
    assert!(k.fabric.transactions.is_empty());
    validate(&mut k, t).unwrap();
}
