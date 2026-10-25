//! Real Kernel/Fabric checks; live applications use the existing TEST-ONLY
//! publication fixture. This is not guest malloc/free or hardware DMA proof.
use super::*;
use crate::anka64::core::AddressMap;
use crate::anka64::scoped_pointers::heap::{CleanupLease, CleanupWorker, HeapCloseOutcome};

fn worker(k: &mut Kernel) -> (ProcessKey, CleanupWorker) {
    let key = process(k);
    let role =
        no_alloc(|| k.enroll_cleanup_worker(key, k.fabric.scoped_pointers.revision())).unwrap();
    (key, role)
}
fn close_and_claim(k: &mut Kernel, a: App, key: ProcessKey, role: CleanupWorker) -> CleanupLease {
    no_alloc(|| {
        k.fabric
            .close_attached_heap(a.reservation, a.owner, a.object)
            .unwrap();
        k.claim_heap_cleanup(
            key,
            role,
            a.reservation,
            a.owner,
            a.object,
            k.fabric.scoped_pointers.revision(),
        )
    })
    .unwrap()
}
fn retire(k: &mut Kernel, a: App, key: ProcessKey, lease: CleanupLease) -> Result<(), HeapError> {
    no_alloc(|| k.retire_heap_authority(key, lease, a.owner, a.object))
}
fn armed(k: &mut Kernel, a: App) -> (ProcessKey, CleanupLease) {
    let (key, role) = worker(k);
    (key, close_and_claim(k, a, key, role))
}

#[test]
fn a237_runtime_retirement_keeps_dirty_bytes_tags_rows_and_initialization_history() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 31, false);
    let b = allocation(&mut k, 64, false);
    let (key, lease) = armed(&mut k, a);
    k.fabric.memory.fill(0xa9);
    k.fabric
        .private_heap
        .as_mut()
        .unwrap()
        .shadow
        .fill(Some(a.pointer));
    let before = snapshot(&k.fabric);
    let charges = k.fabric.scoped_pointers.total_reserved_bytes();
    let rows = (row(&k.fabric, a.object), row(&k.fabric, b.object));
    retire(&mut k, a, key, lease).unwrap();
    assert_only_registry_changed(before, &k.fabric);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), charges);
    assert_eq!((row(&k.fabric, a.object), row(&k.fabric, b.object)), rows);
    rejects(&mut k, HeapError::Busy, |k| {
        no_alloc(|| k.fabric.scoped_pointers.abort_heap(a.reservation))
    });
    rejects(&mut k, HeapError::Lease, |k| retire(k, a, key, lease));
}

#[test]
fn a237_runtime_prepared_committed_and_cancelled_work_all_block_until_consumed() {
    for state in 0..3 {
        let mut k = machine(1, 1);
        let a = allocation(&mut k, 64, true);
        let ticket = write(&mut k, a, 0, &[65, 0, 255, 66]).unwrap();
        let (key, lease) = armed(&mut k, a);
        if state == 1 {
            no_alloc(|| k.fabric.execute_heap_cpu_work(ticket)).unwrap();
        }
        if state == 2 {
            no_alloc(|| k.fabric.cancel_heap_cpu_work(ticket)).unwrap();
        }
        rejects(&mut k, HeapError::Busy, |k| retire(k, a, key, lease));
        if state == 0 {
            no_alloc(|| k.fabric.execute_heap_cpu_work(ticket)).unwrap();
        }
        no_alloc(|| k.fabric.finish_heap_cpu_work(ticket)).unwrap();
        retire(&mut k, a, key, lease).unwrap();
        let base = row(&k.fabric, a.object).extents.physical.base as usize;
        assert_eq!(
            &k.fabric.memory[base..base + 4],
            if state == 2 {
                &[0, 0, 0, 0]
            } else {
                &[65, 0, 255, 66]
            }
        );
        rejects(&mut k, HeapError::StaleWork, |k| {
            no_alloc(|| k.fabric.execute_heap_cpu_work(ticket))
        });
    }
}

#[test]
fn a237_runtime_retiring_a_preserves_b_pending_work_and_live_access() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    let b = allocation(&mut k, 64, true);
    let ticket = write(&mut k, b, 7, &[88]).unwrap();
    let (key, lease) = armed(&mut k, a);
    let requests = format!("{:?}", work(&k));
    retire(&mut k, a, key, lease).unwrap();
    assert_eq!(format!("{:?}", work(&k)), requests);
    validate(&mut k, ticket).unwrap();
    no_alloc(|| k.fabric.execute_heap_cpu_work(ticket)).unwrap();
    no_alloc(|| k.fabric.finish_heap_cpu_work(ticket)).unwrap();
    assert_eq!(
        k.fabric.memory[row(&k.fabric, b.object).extents.physical.base as usize + 7],
        88
    );
    assert!(read(&mut k, b, 7, 1).is_ok());
    rejects(&mut k, HeapError::Pointer(PointerError::Stale), |k| {
        read(k, a, 0, 1)
    });
}

#[test]
fn a237_runtime_register_saved_event_and_heap_cell_aliases_reject_without_erasure() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    let agent = k.processes[a.key.slot].core.agent;
    no_alloc(|| {
        k.fabric
            .store_heap_pointer_cell(a.owner, agent, a.pointer, Some(a.pointer))
    })
    .unwrap();
    k.processes[a.key.slot]
        .core
        .install_pointer(4, Some(a.pointer))
        .unwrap();
    k.processes[a.key.slot].core.enter_event(EventFrame {
        return_pc: 16,
        return_privilege: Privilege::User,
        interrupts_were_enabled: true,
        cause: EventCause::Syscall,
    });
    let core = format!("{:?}", k.processes[a.key.slot].core);
    let (key, lease) = armed(&mut k, a);
    let before = snapshot(&k.fabric);
    retire(&mut k, a, key, lease).unwrap();
    assert_only_registry_changed(before, &k.fabric);
    assert_eq!(format!("{:?}", k.processes[a.key.slot].core), core);
    assert_eq!(k.processes[a.key.slot].core.event_return(), Some(16));
    assert_eq!(&k.processes[a.key.slot].core.r[4..6], &a.pointer.words());
    for pair in [0, 4, 10] {
        k.processes[a.key.slot]
            .core
            .install_pointer(pair, Some(a.pointer))
            .unwrap();
        rejects(&mut k, HeapError::Pointer(PointerError::Stale), |k| {
            read(k, a, 0, 1)
        });
    }
    rejects(&mut k, HeapError::Pointer(PointerError::Stale), |k| {
        no_alloc(|| k.fabric.load_heap_pointer_cell(a.owner, agent, a.pointer))
    });
    rejects(&mut k, HeapError::Pointer(PointerError::Stale), |k| {
        no_alloc(|| k.fabric.write_heap_bytes(a.owner, agent, a.pointer, &[7]))
    });
}

#[test]
fn a237_runtime_inactive_local_backing_record_still_blocks_retirement() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, false);
    let (key, lease) = armed(&mut k, a);
    let scope = k
        .fabric
        .scoped_pointers
        .enter_scope_for(a.owner.context)
        .unwrap();
    let local = k
        .fabric
        .scoped_pointers
        .register(scope, a.owner.domain.0, 0x10000, 16, true)
        .unwrap();
    k.fabric.scoped_pointers.bind_backing(
        local,
        crate::anka64::scoped_pointers::PointerBacking {
            object: a.object,
            generation: Generation(99),
            offset: 0,
        },
    );
    rejects(&mut k, HeapError::Busy, |k| retire(k, a, key, lease));
    no_alloc(|| k.fabric.scoped_pointers.leave_scope(scope)).unwrap();
    rejects(&mut k, HeapError::Busy, |k| retire(k, a, key, lease));
    assert!(no_alloc(|| k.fabric.scoped_pointers.take_backing(local)).is_some());
    retire(&mut k, a, key, lease).unwrap();
}

#[test]
fn a237_runtime_retained_process_resources_cannot_claim_private_heap_object() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, false);
    let other = process(&mut k);
    let (key, lease) = armed(&mut k, a);
    let extent = crate::anka64::placement::PhysicalExtent {
        base: 0,
        size: 4096,
    };
    k.processes[other.slot].resources = Some(crate::anka64::os::OwnedResources {
        domain: a.owner.domain,
        stack_obj: a.object,
        trap_obj: ObjectId(999),
        stack_extent: extent,
        trap_extent: extent,
    });
    k.processes[other.slot].state = ProcessState::Zombie;
    rejects(&mut k, HeapError::Busy, |k| retire(k, a, key, lease));
    k.processes[other.slot].resources = None;
    retire(&mut k, a, key, lease).unwrap();
}

#[test]
fn a237_runtime_worker_must_have_current_process_context_domain_and_cpu() {
    for mode in 0..7 {
        let mut k = machine(0, 0);
        let a = allocation(&mut k, 64, false);
        let (key, lease) = armed(&mut k, a);
        let core = &mut k.processes[key.slot].core;
        let (agent, domain) = (core.agent, core.domain);
        match mode {
            0 => k.processes[key.slot].state = ProcessState::Zombie,
            1 => k.processes[key.slot].generation += 1,
            2 => *core = Anka64Core::new(agent, domain),
            3 => {
                k.fabric.domains.remove(&domain);
            }
            4 => {
                k.fabric.agents.remove(&agent);
            }
            5 => k.fabric.agents.get_mut(&agent).unwrap().kind = AgentKind::Dma,
            _ => k.fabric.agents.get_mut(&agent).unwrap().domain = DomainId(999),
        }
        rejects(&mut k, HeapError::Worker, |k| retire(k, a, key, lease));
    }
}

#[test]
fn a237_runtime_checks_all_process_maps_including_dead_empty_and_overflowing_entries() {
    for (state, base, size) in [
        (ProcessState::Running, 0, 16),
        (ProcessState::Zombie, 0, 0),
        (ProcessState::Zombie, u64::MAX, u64::MAX),
    ] {
        let mut k = machine(0, 0);
        let a = allocation(&mut k, 64, false);
        let other = process(&mut k);
        let (key, lease) = armed(&mut k, a);
        k.processes[other.slot].state = state;
        k.processes[other.slot]
            .core
            .address_map
            .add_at(base, size, a.object, u64::MAX);
        rejects(&mut k, HeapError::Busy, |k| retire(k, a, key, lease));
        k.processes[other.slot].core.address_map = AddressMap::new();
        retire(&mut k, a, key, lease).unwrap();
    }
}

#[test]
fn a237_runtime_checks_all_retained_process_capability_slots_without_resolution_filters() {
    for device in [false, true] {
        let mut k = machine(0, 0);
        let a = allocation(&mut k, 64, false);
        let other = process(&mut k);
        let (key, lease) = armed(&mut k, a);
        let mut table = CapabilityTable::new();
        table.slots_mut()[15].state = if device {
            CapabilitySlotState::Device {
                object: a.object,
                object_generation: Generation(99),
                rights: DeviceRights::SUBMIT_READ,
                authority_id: AuthorityId(99),
                delegation_id: None,
            }
        } else {
            CapabilitySlotState::Memory {
                object: a.object,
                object_generation: Generation(99),
                offset: u64::MAX,
                length: 0,
                perms: Permissions::READ,
                authority_id: AuthorityId(99),
                delegation_id: None,
            }
        };
        k.processes[other.slot].cap_table = Some(table);
        k.processes[other.slot].state = ProcessState::Zombie;
        rejects(&mut k, HeapError::Busy, |k| retire(k, a, key, lease));
        k.processes[other.slot].cap_table = None;
        retire(&mut k, a, key, lease).unwrap();
    }
}

#[test]
fn a237_runtime_legacy_domain_grants_and_device_authority_block_retirement() {
    for device in [false, true] {
        let mut k = machine(0, 0);
        let a = allocation(&mut k, 64, false);
        let (key, lease) = armed(&mut k, a);
        let domain = k.fabric.create_domain();
        let d = k.fabric.domains.get_mut(&domain).unwrap();
        if device {
            d.device_authorities.push(DeviceAuthorityEntry {
                object: a.object,
                generation: Generation(99),
                rights: DeviceRights::SUBMIT_READ,
                authority_id: AuthorityId(99),
            });
        } else {
            d.capabilities.push(CapabilityEntry {
                cap: Capability64::new(a.object, Generation(99), u64::MAX, 0, Permissions::READ),
                authority_id: None,
            });
        }
        rejects(&mut k, HeapError::Busy, |k| retire(k, a, key, lease));
        k.fabric.domains.remove(&domain);
        retire(&mut k, a, key, lease).unwrap();
    }
}

#[test]
fn a237_runtime_legacy_object_placement_and_stack_registration_are_not_silently_removed() {
    for mode in 0..3 {
        let mut k = machine(0, 0);
        let a = allocation(&mut k, 64, false);
        let (key, lease) = armed(&mut k, a);
        match mode {
            0 => {
                let id = k
                    .fabric
                    .alloc_object("hostile collision", 1, ObjectKind::Memory);
                let value = k.fabric.objects.remove(&id).unwrap();
                k.fabric.objects.insert(a.object, value);
            }
            1 => {
                k.fabric.placement.insert(a.object, 0);
            }
            _ => {
                k.fabric
                    .pointer_stack_objects
                    .insert(a.object, (a.owner.context, a.owner.domain));
            }
        }
        rejects(&mut k, HeapError::Busy, |k| retire(k, a, key, lease));
    }
}

#[test]
fn a237_runtime_foreign_orphan_or_malformed_work_blocks_even_zero_selected_census() {
    for orphan in [false, true] {
        let mut k = machine(1, 1);
        let a = allocation(&mut k, 64, false);
        let b = allocation(&mut k, 64, true);
        let ticket = read(&mut k, b, 0, 1).unwrap();
        let (key, lease) = armed(&mut k, a);
        let record = work(&k).records[0];
        if orphan {
            work_mut(&mut k).records[0] = None;
        } else {
            work_mut(&mut k).records[0]
                .as_mut()
                .unwrap()
                .binding
                .logical += 1;
        }
        rejects(&mut k, HeapError::StaleWork, |k| retire(k, a, key, lease));
        work_mut(&mut k).records[0] = record;
        retire(&mut k, a, key, lease).unwrap();
        validate(&mut k, ticket).unwrap();
    }
}

#[test]
fn a237_runtime_custody_object_and_owner_are_rechecked_before_retirement() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, false);
    let b = allocation(&mut k, 64, false);
    let (key, lease) = armed(&mut k, a);
    rejects(&mut k, HeapError::Owner, |k| {
        retire(
            k,
            App {
                owner: b.owner,
                ..a
            },
            key,
            lease,
        )
    });
    rejects(&mut k, HeapError::StaleReservation, |k| {
        retire(
            k,
            App {
                object: b.object,
                ..a
            },
            key,
            lease,
        )
    });
    let heap = k.fabric.private_heap.as_mut().unwrap();
    let held = heap
        .rows
        .iter_mut()
        .flatten()
        .find(|r| r.object == a.object)
        .unwrap();
    held.logical += 1;
    rejects(&mut k, HeapError::StaleReservation, |k| {
        retire(k, a, key, lease)
    });
}

#[test]
fn a237_runtime_owner_death_and_duplicate_close_do_not_reopen_or_refund_retired_job() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, false);
    let (key, lease) = armed(&mut k, a);
    k.processes[a.key.slot].state = ProcessState::Zombie;
    no_alloc(|| k.fabric.scoped_pointers.close_owner(a.account)).unwrap();
    k.fabric.domains.remove(&a.owner.domain);
    retire(&mut k, a, key, lease).unwrap();
    let before = snapshot(&k.fabric);
    assert_eq!(
        no_alloc(|| k
            .fabric
            .close_attached_heap(a.reservation, a.owner, a.object)),
        Ok(HeapCloseOutcome::AlreadyRetired)
    );
    assert_eq!(snapshot(&k.fabric), before);
    rejects(&mut k, HeapError::Busy, |k| {
        no_alloc(|| k.fabric.scoped_pointers.release_owner(a.account))
    });
}

#[test]
fn a237_runtime_retirement_rechecks_legacy_conflicts_after_ready_at_revision_max() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, false);
    let (key, lease) = armed(&mut k, a);
    fixture::set_revision(&mut k.fabric.scoped_pointers, u64::MAX);
    assert!(no_alloc(|| k.heap_cleanup_ready(key, lease, a.owner, a.object)).unwrap());
    let core = &k.processes[key.slot].core;
    let (agent, domain) = (core.agent, core.domain);
    let object = k
        .fabric
        .alloc_object("legacy pending", 64, ObjectKind::Memory);
    assert!(k.fabric.place_object(object, 0x1000));
    k.fabric
        .grant(domain, object, 0, 16, Permissions::RW)
        .unwrap();
    let mut req = request(agent, domain, object, 0, Width::Byte, AccessKind::Write);
    req.length = 16;
    let tx = k.fabric.submit(req, Some(vec![9; 16]));
    k.fabric.advance(tx);
    k.fabric.advance(tx);
    assert_eq!(k.fabric.transactions[tx].state, TxState::Prepared);
    k.fabric.transactions[tx].physical_address = Some(0x1ff8);
    rejects(&mut k, HeapError::Busy, |k| retire(k, a, key, lease));
    k.fabric.advance(tx);
    assert_eq!(k.fabric.transactions[tx].state, TxState::Faulted);
    retire(&mut k, a, key, lease).unwrap();
    assert_eq!(k.fabric.scoped_pointers.revision(), u64::MAX);
}
