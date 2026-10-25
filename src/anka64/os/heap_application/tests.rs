use super::*;
use crate::anka64::fabric::HeapWorkLimits;
use crate::anka64::placement::VirtualExtent;
use crate::anka64::scoped_pointers::heap::{HeapPlacementLimits, RegistryLimits};

fn machine() -> Kernel {
    let fabric = Fabric::with_private_heap_cpu_work(
        0x10000,
        RegistryLimits {
            slots: 32,
            scopes: 32,
            owners: 8,
            cleanup: 16,
            global_bytes: 0x100000,
        },
        HeapPlacementLimits {
            physical_pool: PhysicalExtent {
                base: 0x2000,
                size: 0x4000,
            },
            physical_claims: 16,
            virtual_window: VirtualExtent {
                base: 0x10000,
                size: 0x8000,
            },
            per_owner_claims: 16,
        },
        1,
        HeapWorkLimits {
            tickets: 4,
            requests: 4,
        },
    )
    .unwrap();
    let mut kernel = Kernel::new(fabric);
    kernel.enable_heap_service(8192).unwrap();
    kernel
}
fn client(k: &mut Kernel) -> ProcessKey {
    let domain = k.fabric.create_domain();
    let agent = AgentId(200 + k.processes.len() as u64);
    k.fabric
        .register_agent(agent, AgentKind::Cpu(CoreId(0)), domain);
    let mut core = Anka64Core::new(agent, domain);
    core.enable_protected_context().unwrap();
    k.spawn(core)
}
fn trap(k: &mut Kernel, key: ProcessKey, number: u64, n: u64, p: Option<ScopedPointer>) {
    let core = &mut k.processes[key.slot].core;
    for r in 0..6 {
        core.write_register(r, 0);
    }
    core.write_register(0, number);
    core.write_register(1, n);
    if number == SYS_FREE {
        core.install_pointer(2, p).unwrap();
    }
    core.enter_event(EventFrame {
        return_pc: 0,
        return_privilege: Privilege::User,
        interrupts_were_enabled: false,
        cause: EventCause::Syscall,
    });
    core.halted = true;
}
fn malloc(k: &mut Kernel, key: ProcessKey, n: u64) -> (Option<ScopedPointer>, u64) {
    trap(k, key, SYS_MALLOC, n, None);
    let (w, t) = k.processes[key.slot]
        .core
        .protected_syscall_image()
        .unwrap();
    k.handle_malloc(key.slot, w, t);
    assert_eq!(k.processes[key.slot].state, ProcessState::Running);
    // Capture the returned pair through a real protected event image.
    let status = k.processes[key.slot].core.r[2];
    k.processes[key.slot].core.enter_event(EventFrame {
        return_pc: 0,
        return_privilege: Privilege::User,
        interrupts_were_enabled: false,
        cause: EventCause::Syscall,
    });
    let (_, kinds) = k.processes[key.slot]
        .core
        .protected_syscall_image()
        .unwrap();
    k.processes[key.slot].core.event_return().unwrap();
    (kinds[0], status)
}
fn free(k: &mut Kernel, key: ProcessKey, p: Option<ScopedPointer>) {
    trap(k, key, SYS_FREE, 0, p);
    let (w, t) = k.processes[key.slot]
        .core
        .protected_syscall_image()
        .unwrap();
    k.handle_free(key.slot, w, t);
}
fn drain(k: &mut Kernel) {
    for _ in 0..1000 {
        if !k.advance_heap_cleanup() {
            return;
        }
    }
    panic!("cleanup did not become quiet");
}
fn owner(k: &Kernel, key: ProcessKey) -> AllocationOwner {
    k.processes[key.slot].core.heap_owner().unwrap()
}
fn read(k: &Kernel, key: ProcessKey, p: ScopedPointer, n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    k.fabric
        .read_heap_bytes(owner(k, key), k.processes[key.slot].core.agent, p, &mut b)
        .unwrap();
    b
}

#[test]
fn a3_malloc_zero_invalid_and_capacity_results_are_canonical_and_uncharged() {
    let mut k = machine();
    let a = client(&mut k);
    let baseline = k.fabric.scoped_pointers.total_reserved_bytes();
    for (n, status) in [(0, 0), (u64::MAX, 2), (i64::MAX as u64, 1)] {
        assert_eq!(malloc(&mut k, a, n), (None, status));
        assert_eq!(k.processes[a.slot].core.r[..2], [0, 0]);
        assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), baseline);
    }
    free(&mut k, a, None);
    assert_eq!(k.processes[a.slot].core.r[..2], [0, 0]);
}
#[test]
fn a3_actual_publication_zeroes_and_cpu_operations_transport_heap_pointers() {
    let mut k = machine();
    let a = client(&mut k);
    let p = malloc(&mut k, a, 32).0.unwrap();
    assert_eq!(read(&k, a, p, 32), vec![0; 32]);
    let (core, fabric) = (&mut k.processes[a.slot].core, &mut k.fabric);
    core.install_pointer(4, Some(p)).unwrap();
    core.pointer_move(fabric, 6, 4).unwrap();
    core.pointer_add(fabric, 6, 6, 7).unwrap();
    core.pointer_write(fabric, 6, Width::Byte, vec![255])
        .unwrap();
    assert_eq!(
        core.pointer_read(fabric, 6, Width::Byte).unwrap(),
        vec![255]
    );
    assert_eq!(read(&k, a, p, 8), vec![0, 0, 0, 0, 0, 0, 0, 255]);
}
#[test]
fn a3_free_closes_aliases_waits_for_terminal_work_then_refunds() {
    let mut k = machine();
    let a = client(&mut k);
    let p = malloc(&mut k, a, 16).0.unwrap();
    let ticket = k
        .register_heap_cpu_read(a, Some(p), 1, k.fabric.scoped_pointers.revision())
        .unwrap();
    let charged = k.fabric.scoped_pointers.total_reserved_bytes();
    free(&mut k, a, Some(p));
    assert!(k.processes[a.slot].heap_free_wait.is_some());
    assert!(!k.processes[a.slot].is_schedulable());
    assert!(
        k.fabric
            .authenticate_heap_token(owner(&k, a), k.processes[a.slot].core.agent, p)
            .is_err()
    );
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), charged);
    k.fabric.cancel_heap_cpu_work(ticket).unwrap();
    k.fabric.finish_heap_cpu_work(ticket).unwrap();
    drain(&mut k);
    assert!(k.processes[a.slot].heap_free_wait.is_none());
    assert_eq!(k.processes[a.slot].core.r[..2], [0, 0]);
    assert_eq!(
        k.fabric.scoped_pointers.total_reserved_bytes(),
        k.fabric.scoped_pointers.fixed_metadata_bytes()
    );
}

#[test]
fn a3_free_returns_capacity_only_after_scrub_and_release() {
    let mut k = machine();
    let a = client(&mut k);
    let p = malloc(&mut k, a, 16).0.unwrap();
    free(&mut k, a, Some(p)); // closes and retires, but does not acknowledge
    assert!(k.processes[a.slot].heap_free_wait.is_some());
    assert!(k.advance_heap_cleanup()); // begin
    assert!(k.processes[a.slot].heap_free_wait.is_some());
    assert!(k.advance_heap_cleanup()); // one page scrub
    assert!(k.processes[a.slot].heap_free_wait.is_some());
    assert!(k.advance_heap_cleanup()); // exact release + reply
    assert!(k.processes[a.slot].heap_free_wait.is_none());
    assert_eq!(
        k.fabric.scoped_pointers.total_reserved_bytes(),
        k.fabric.scoped_pointers.fixed_metadata_bytes()
    );
}
#[test]
fn a3_death_and_reuse_preserve_other_client_and_reject_old_event_alias() {
    let mut k = machine();
    let a = client(&mut k);
    let b = client(&mut k);
    let pa = malloc(&mut k, a, 8192).0.unwrap();
    let pb = malloc(&mut k, b, 4096).0.unwrap();
    k.fabric
        .write_heap_bytes(
            owner(&k, b),
            k.processes[b.slot].core.agent,
            pb,
            &[65, 0, 255, 66],
        )
        .unwrap();
    assert_eq!(malloc(&mut k, a, 1), (None, 1));
    k.processes[a.slot]
        .core
        .install_pointer(4, Some(pa))
        .unwrap();
    k.processes[a.slot].core.enter_event(EventFrame {
        return_pc: 0,
        return_privilege: Privilege::User,
        interrupts_were_enabled: false,
        cause: EventCause::TimerInterrupt,
    });
    k.finish_process(a.slot, ProcessResult::Exited(0));
    drain(&mut k);
    let c = client(&mut k);
    let pc = malloc(&mut k, c, 8192).0.unwrap();
    assert_ne!(pc.words()[0], pa.words()[0]);
    assert_eq!(read(&k, c, pc, 16), vec![0; 16]);
    assert_eq!(read(&k, b, pb, 4), vec![65, 0, 255, 66]);
    k.processes[a.slot].core.event_return().unwrap();
    assert!(
        k.processes[a.slot]
            .core
            .pointer_read(&mut k.fabric, 4, Width::Byte)
            .is_err()
    );
}
#[test]
fn a3_invalid_free_faults_and_process_death_closes_its_remaining_allocations() {
    for interior in [false, true] {
        let mut k = machine();
        let a = client(&mut k);
        let b = client(&mut k);
        let p = malloc(&mut k, a, 16).0.unwrap();
        let bad = if interior {
            k.fabric
                .scoped_pointers
                .add_heap_pointer(p, owner(&k, a), 1)
                .unwrap()
        } else {
            p
        };
        free(&mut k, if interior { a } else { b }, Some(bad));
        assert_eq!(
            k.processes[if interior { a.slot } else { b.slot }].result,
            Some(ProcessResult::ProtectionFault)
        );
        if !interior {
            assert_eq!(read(&k, a, p, 1), vec![0]);
        } else {
            drain(&mut k);
            assert_eq!(
                k.fabric.scoped_pointers.total_reserved_bytes(),
                k.fabric.scoped_pointers.fixed_metadata_bytes()
            );
        }
    }
}
#[test]
fn a3_heap_cells_reauthenticate_copies_after_free_and_scalar_overwrite() {
    let mut k = machine();
    let a = client(&mut k);
    let p = malloc(&mut k, a, 16).0.unwrap();
    let cell = malloc(&mut k, a, 16).0.unwrap();
    let o = owner(&k, a);
    let agent = k.processes[a.slot].core.agent;
    k.fabric
        .store_heap_pointer_cell(o, agent, cell, Some(p))
        .unwrap();
    assert_eq!(
        k.fabric.load_heap_pointer_cell(o, agent, cell).unwrap(),
        Some(p)
    );
    free(&mut k, a, Some(p));
    drain(&mut k);
    assert!(k.fabric.load_heap_pointer_cell(o, agent, cell).is_err());
    k.fabric.write_heap_bytes(o, agent, cell, &[0; 16]).unwrap();
    assert_eq!(
        k.fabric.load_heap_pointer_cell(o, agent, cell).unwrap(),
        None
    );
}
#[test]
fn a3_result_permits_reject_replay_changed_event_and_scalar_overlay() {
    let mut k = machine();
    let a = client(&mut k);
    trap(&mut k, a, SYS_MALLOC, 0, None);
    let o = owner(&k, a);
    let permit = k.processes[a.slot].core.prepare_heap_event(o).unwrap();
    k.processes[a.slot]
        .core
        .commit_heap_event(permit, None, 0, true);
    assert!(!k.processes[a.slot].core.valid_heap_event(permit, o));
    k.processes[a.slot].core.event_return().unwrap();
    trap(&mut k, a, SYS_MALLOC, 0, None);
    assert!(!k.processes[a.slot].core.valid_heap_event(permit, o));
    k.processes[a.slot].core.write_syscall_result(0, 9);
    assert!(k.processes[a.slot].core.prepare_heap_event(o).is_err());
}
#[test]
fn a3_malformed_malloc_never_reserves_and_same_domain_other_process_cannot_read() {
    let mut k = machine();
    let a = client(&mut k);
    let b = client(&mut k);
    let p = malloc(&mut k, a, 16).0.unwrap();
    let wrong = AllocationOwner {
        process: b,
        ..owner(&k, a)
    };
    assert!(
        k.fabric
            .authenticate_heap_token(wrong, k.processes[a.slot].core.agent, p)
            .is_err()
    );
    let baseline = k.fabric.scoped_pointers.total_reserved_bytes();
    trap(&mut k, b, SYS_MALLOC, 16, None);
    let (mut w, t) = k.processes[b.slot].core.protected_syscall_image().unwrap();
    w[5] = 1;
    k.handle_malloc(b.slot, w, t);
    assert_eq!(
        k.processes[b.slot].result,
        Some(ProcessResult::ProtectionFault)
    );
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), baseline);
}
#[test]
fn a3_free_wait_cannot_return_into_a_replaced_syscall_image() {
    let mut k = machine();
    let a = client(&mut k);
    let p = malloc(&mut k, a, 16).0.unwrap();
    let ticket = k
        .register_heap_cpu_read(a, Some(p), 1, k.fabric.scoped_pointers.revision())
        .unwrap();
    free(&mut k, a, Some(p));
    k.processes[a.slot].core.event_return().unwrap();
    trap(&mut k, a, SYS_MALLOC, 0, None);
    k.fabric.cancel_heap_cpu_work(ticket).unwrap();
    k.fabric.finish_heap_cpu_work(ticket).unwrap();
    drain(&mut k);
    assert_eq!(
        k.processes[a.slot].result,
        Some(ProcessResult::ProtectionFault)
    );
}

#[test]
fn a3_publication_rechecks_initialization_and_event_without_partial_visibility() {
    let mut k = machine();
    let a = client(&mut k);
    let o = owner(&k, a);
    let account = k.fabric.scoped_pointers.admit_owner(o, 8192).unwrap();
    let reservation = k
        .fabric
        .scoped_pointers
        .reserve_heap(account, 16, k.fabric.scoped_pointers.revision())
        .unwrap();
    let object = k
        .fabric
        .attach_private_heap(reservation, o, k.fabric.scoped_pointers.revision())
        .unwrap();
    let initial = k
        .fabric
        .private_heap_initialization(reservation, o, object, k.fabric.scoped_pointers.revision())
        .unwrap();
    trap(&mut k, a, SYS_MALLOC, 16, None);
    let permit = k.processes[a.slot].core.prepare_heap_event(o).unwrap();
    assert!(
        k.fabric
            .publish_heap_reply(&mut k.processes[a.slot].core, o, permit, initial)
            .is_err()
    );
    assert!(k.processes[a.slot].core.valid_heap_event(permit, o));
    let complete = k
        .fabric
        .initialize_private_heap_chunk(initial, o, 4096, k.fabric.scoped_pointers.revision())
        .unwrap();
    let dirty = k
        .fabric
        .write_private_heap(complete, o, 0, &[99], k.fabric.scoped_pointers.revision())
        .unwrap();
    assert!(
        k.fabric
            .publish_heap_reply(&mut k.processes[a.slot].core, o, permit, complete)
            .is_err()
    );
    assert!(k.processes[a.slot].core.valid_heap_event(permit, o));
    let current = k
        .fabric
        .initialize_private_heap_chunk(dirty, o, 4096, k.fabric.scoped_pointers.revision())
        .unwrap();
    k.processes[a.slot].core.event_return().unwrap();
    trap(&mut k, a, SYS_MALLOC, 16, None);
    assert!(
        k.fabric
            .publish_heap_reply(&mut k.processes[a.slot].core, o, permit, current)
            .is_err()
    );
    let fresh = k.processes[a.slot].core.prepare_heap_event(o).unwrap();
    k.fabric
        .publish_heap_reply(&mut k.processes[a.slot].core, o, fresh, current)
        .unwrap();
    let (words, kinds) = k.processes[a.slot].core.protected_syscall_image().unwrap();
    assert_eq!(&words[2..4], &[0, 0]);
    let p = kinds[0].unwrap();
    assert_eq!(read(&k, a, p, 16), vec![0; 16]);
    assert!(
        k.fabric
            .publish_heap_reply(&mut k.processes[a.slot].core, o, fresh, current)
            .is_err()
    );
}

#[test]
fn a3_publication_rejects_legacy_authority_and_leaves_the_event_pending() {
    let mut k = machine();
    let a = client(&mut k);
    let o = owner(&k, a);
    let account = k.fabric.scoped_pointers.admit_owner(o, 8192).unwrap();
    let reservation = k
        .fabric
        .scoped_pointers
        .reserve_heap(account, 16, k.fabric.scoped_pointers.revision())
        .unwrap();
    let object = k
        .fabric
        .attach_private_heap(reservation, o, k.fabric.scoped_pointers.revision())
        .unwrap();
    let initial = k
        .fabric
        .private_heap_initialization(reservation, o, object, k.fabric.scoped_pointers.revision())
        .unwrap();
    let complete = k
        .fabric
        .initialize_private_heap_chunk(initial, o, 4096, k.fabric.scoped_pointers.revision())
        .unwrap();
    trap(&mut k, a, SYS_MALLOC, 16, None);
    let permit = k.processes[a.slot].core.prepare_heap_event(o).unwrap();
    k.processes[a.slot].core.address_map.add(0x9000, 16, object);
    assert!(
        k.fabric
            .publish_heap_reply(&mut k.processes[a.slot].core, o, permit, complete)
            .is_err()
    );
    assert!(k.processes[a.slot].core.valid_heap_event(permit, o));
    assert_eq!(
        k.processes[a.slot]
            .core
            .protected_syscall_image()
            .unwrap()
            .1[0],
        None
    );
    assert_eq!(
        k.fabric.scoped_pointers.account_reserved_bytes(account),
        Ok(4096)
    );
}
