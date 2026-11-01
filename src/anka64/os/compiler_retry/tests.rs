use super::*;
use crate::anka64::compiler_adapter::resources::{
    COMPILER_RESOURCE_MAGIC, CompilerResourceBindings, OutputGrowthSupport, OutputRetryPolicy,
};
use crate::anka64::fabric::HeapWorkLimits;
use crate::anka64::guest_compiler::{install_trap_handler, seal_code_object};
use crate::anka64::placement::{PhysicalExtent, VirtualExtent};
use crate::anka64::pointer_frames::{FrameManifest, ValidatedPointerProgram};
use crate::anka64::scoped_pointers::heap::{HeapPlacementLimits, RegistryLimits};

pub(super) fn machine() -> Kernel {
    let f = Fabric::with_private_heap_cpu_work(
        4 * 1024 * 1024,
        RegistryLimits {
            slots: 64,
            scopes: 32,
            owners: 16,
            cleanup: 32,
            global_bytes: 64 * 1024 * 1024,
        },
        HeapPlacementLimits {
            physical_pool: PhysicalExtent {
                base: 0x100000,
                size: 0x200000,
            },
            physical_claims: 32,
            virtual_window: VirtualExtent {
                base: 0x40000000,
                size: 0x200000,
            },
            per_owner_claims: 16,
        },
        1,
        HeapWorkLimits {
            tickets: 8,
            requests: 8,
        },
    )
    .unwrap();
    let mut k = Kernel::new(f);
    k.enable_heap_service(1024 * 1024).unwrap();
    k
}

pub(super) fn budget(job: u64, capacity: u64) -> OutputRetryBudget {
    let c = CompilerReplyContext::new(
        job,
        1,
        CompilerResourceBindings {
            source: 21,
            tools: 22,
            profile: 23,
            dependencies: 24,
            plan: 25,
        },
        73,
        capacity,
        OutputGrowthSupport::CompilerOutput,
    )
    .unwrap();
    OutputRetryPolicy::new(1024 * 1024, 3, 10000)
        .unwrap()
        .start(c)
        .unwrap()
}

fn words(job: u64, attempt: u64, minimum: u64) -> [u64; 16] {
    [
        COMPILER_RESOURCE_MAGIC,
        2,
        job,
        attempt,
        1,
        3,
        minimum,
        0,
        73,
        0,
        21,
        22,
        23,
        24,
        25,
        0,
    ]
}

pub(super) fn imm(a: &mut Asm64, r: u8, n: u64) {
    let scratch = if r == R12 { R11 } else { R12 };
    a.movi(r, 0);
    a.movi(scratch, 8);
    for b in n.to_be_bytes() {
        a.shl(r, r, scratch);
        a.addi(r, r, b as i32);
    }
}

fn alloc_code(a: &mut Asm64, n: u64) {
    a.movi(R0, SYS_MALLOC as i32);
    imm(a, R1, n);
    for r in R2..=R5 {
        a.movi(r, 0);
    }
    a.trap(0);
}

/// This is a real Anka ISA transport producer, not a C compiler. It allocates
/// both buffers via guest SYS_MALLOC and writes the report via protected PWRITE.
pub(super) fn client(k: &mut Kernel, capacity: u64, report: [u64; 16], exit: u64, syscall: u64) -> ProcessKey {
    let mut a = Asm64::new();
    a.pframe(0);
    alloc_code(&mut a, capacity);
    a.pmov(R8, R0);
    alloc_code(&mut a, 128);
    a.pmov(R2, R0);
    a.pmov(R4, R8);
    a.movi(R0, 0);
    a.movi(R1, 0);
    let entry = a.here() as u64 * 4;
    a.pmov(R6, R2);
    for (i, word) in report.into_iter().enumerate() {
        imm(&mut a, R12, word);
        a.pwrite(R12, R6, 8);
        if i != 15 {
            a.movi(R10, 8);
            a.padd(R6, R6, R10);
        }
    }
    imm(&mut a, R0, syscall);
    imm(&mut a, R1, exit);
    a.trap(0);
    let frame_exit = a.here() as u64 * 4;
    a.punframe();
    a.ret();
    let code = a.to_bytes();
    assert!(code.len() < 4080);
    let domain = k.fabric.create_domain();
    let agent = AgentId(100 + k.processes.len() as u64);
    k.fabric
        .register_agent(agent, AgentKind::Cpu(CoreId(0)), domain);
    let text = k
        .fabric
        .alloc_object("compiler-runtime-probe", 4096, ObjectKind::Memory);
    let physical = (k.processes.len() as u64) * 8192;
    k.fabric.place_object(text, physical);
    k.fabric.write_physical(physical, &code);
    install_trap_handler(&mut k.fabric, physical, 4096);
    seal_code_object(&mut k.fabric, text, domain);
    let mut core = Anka64Core::new(agent, domain);
    core.address_map.add(0, 4096, text);
    core.trap_vector = 4080;
    let stack = k
        .fabric
        .alloc_object("compiler-runtime-stack", 4096, ObjectKind::Memory);
    k.fabric.place_object(stack, physical + 4096);
    k.fabric.grant(domain, stack, 0, 4096, Permissions::RW);
    core.address_map.add(0x10000, 4096, stack);
    let program = ValidatedPointerProgram::validate(
        &code,
        vec![FrameManifest {
            entry: 0,
            end: code.len() as u64,
            size: 16,
            exits: vec![frame_exit],
            locals: vec![],
        }],
    )
    .unwrap();
    core.admit_pointer_program(&mut k.fabric, program, 0, 0x10000, 0x11000)
        .unwrap();
    let key = k.spawn(core);
    for _ in 0..300 {
        if k.processes[key.slot].core.pc == entry
            && k.processes[key.slot].core.privilege == Privilege::User
        {
            assert_eq!(k.processes[key.slot].state, ProcessState::Running);
            return key;
        }
        assert!(!k.run_process_with_exit_stop(key.slot, 1, true));
        assert_eq!(k.processes[key.slot].state, ProcessState::Running);
    }
    panic!("guest allocation setup did not finish");
}

pub(super) fn run(
    k: &mut Kernel,
    a: &mut CompilerOutputAttempt,
) -> Result<CompilerRetryPending, CompilerRuntimeError> {
    for _ in 0..20 {
        match k.run_compiler_retry_slice(a, 100)? {
            CompilerSlice::Running => (),
            CompilerSlice::AwaitingCleanup(p) => return Ok(p),
        }
    }
    panic!("bounded producer did not finish");
}

pub(super) fn release(k: &mut Kernel, p: &mut CompilerRetryPending) -> OutputRetryBudget {
    for _ in 0..2000 {
        if let Some(b) = k.poll_compiler_retry(p).unwrap() {
            return b;
        }
    }
    panic!("cleanup did not complete");
}

pub(super) fn quiet(k: &mut Kernel) {
    for _ in 0..2000 {
        if !k.advance_heap_cleanup() {
            return;
        }
    }
    panic!("cleanup loop");
}

#[test]
fn c22_real_malloc_pwrite_exit_cleanup_and_fresh_budget_cross_old_capacity() {
    let mut k = machine();
    let key = client(
        &mut k,
        256 * 1024,
        words(10, 1, 256 * 1024 + 1),
        0,
        SYS_EXIT,
    );
    let mut a = k
        .bind_compiler_output_attempt(key, budget(10, 256 * 1024))
        .unwrap();
    let old = a.output;
    let owner = a.owner;
    let held = k.fabric.scoped_pointers.total_reserved_bytes();
    let mut p = run(&mut k, &mut a).unwrap();
    assert_eq!(k.processes[key.slot].result, Some(ProcessResult::Exited(0)));
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), held);
    assert!(!k.fabric.compiler_heap_owner_released(owner));
    assert!(
        k.fabric
            .authenticate_heap_token(owner, a.agent, old)
            .is_err()
    );
    let next = release(&mut k, &mut p);
    assert_eq!(next.context().output_capacity(), 512 * 1024);
    assert!(next.spent_work() > 0);
    assert_eq!(next.remaining_retries(), 2);
    assert!(k.fabric.compiler_heap_owner_released(owner));
    assert!(k.fabric.scoped_pointers.total_reserved_bytes() < held);
    assert_eq!(
        k.poll_compiler_retry(&mut p).unwrap_err(),
        CompilerRuntimeError::Completed
    );
    let c = client(
        &mut k,
        512 * 1024,
        words(10, 2, 512 * 1024 + 1),
        0,
        SYS_EXIT,
    );
    let newer = k.bind_compiler_output_attempt(c, next).unwrap();
    assert_ne!(newer.owner, owner);
    assert!(
        k.fabric
            .authenticate_heap_token(newer.owner, newer.agent, old)
            .is_err()
    );
}

#[test]
fn c22_binding_rejects_scalar_forgery_foreign_token_and_wrong_extent() {
    for case in 0..4 {
        let mut k = machine();
        let a = client(&mut k, 4096, words(10, 1, 4097), 0, SYS_EXIT);
        match case {
            0 => {
                let word = k.processes[a.slot].core.r[4];
                k.processes[a.slot].core.write_register(4, word);
            }
            1 => {
                let b = client(&mut k, 4096, words(20, 1, 4097), 0, SYS_EXIT);
                let foreign = k.processes[b.slot]
                    .core
                    .authenticated_pointer(&k.fabric, R4)
                    .unwrap();
                k.processes[a.slot]
                    .core
                    .install_pointer(R4, foreign)
                    .unwrap();
            }
            2 => {
                let p = k.processes[a.slot]
                    .core
                    .authenticated_pointer(&k.fabric, R4)
                    .unwrap();
                k.processes[a.slot].core.install_pointer(R2, p).unwrap();
            }
            _ => (),
        }
        let held = k.fabric.scoped_pointers.total_reserved_bytes();
        assert!(
            k.bind_compiler_output_attempt(a, budget(10, if case == 3 { 8192 } else { 4096 }))
                .is_err()
        );
        assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), held);
    }
}

#[test]
fn c22_binding_rejects_interior_and_stale_process() {
    let mut k = machine();
    let key = client(&mut k, 4096, words(10, 1, 4097), 0, SYS_EXIT);
    let owner = k.processes[key.slot].core.heap_owner().unwrap();
    let token = k.processes[key.slot]
        .core
        .authenticated_pointer(&k.fabric, R4)
        .unwrap()
        .unwrap();
    let interior = k
        .fabric
        .scoped_pointers
        .add_heap_pointer(token, owner, 1)
        .unwrap();
    k.processes[key.slot]
        .core
        .install_pointer(R4, Some(interior))
        .unwrap();
    assert!(
        k.bind_compiler_output_attempt(key, budget(10, 4096))
            .is_err()
    );
    let stale = ProcessKey {
        generation: key.generation + 1,
        ..key
    };
    assert_eq!(
        k.bind_compiler_output_attempt(stale, budget(10, 4096))
            .unwrap_err(),
        CompilerRuntimeError::Process
    );
}

#[test]
fn c22_frozen_reply_fields_are_checked_after_real_execution() {
    for field in [0, 1, 2, 3, 10, 11, 12, 13, 14, 15] {
        let mut k = machine();
        let mut report = words(10, 1, 4097);
        report[field] ^= 1;
        let key = client(&mut k, 4096, report, 0, SYS_EXIT);
        let mut a = k
            .bind_compiler_output_attempt(key, budget(10, 4096))
            .unwrap();
        assert!(matches!(
            run(&mut k, &mut a),
            Err(CompilerRuntimeError::Resource(_))
        ));
        assert_eq!(k.processes[key.slot].state, ProcessState::Zombie);
        quiet(&mut k);
        assert!(k.fabric.compiler_heap_owner_released(a.owner));
    }
}

#[test]
fn c22_terminal_source_representation_success_and_legacy_reports_never_retry() {
    for status in [0, 2, 3, 8] {
        let mut k = machine();
        let mut report = words(10, 1, 4097);
        report[4] = status;
        report[5] = 0;
        report[6] = 0;
        if status == 0 {
            report[7] = 112;
        } else {
            report[9] = 8;
        }
        let key = client(&mut k, 4096, report, 0, SYS_EXIT);
        let mut a = k
            .bind_compiler_output_attempt(key, budget(10, 4096))
            .unwrap();
        assert!(run(&mut k, &mut a).is_err());
        assert_eq!(k.processes[key.slot].state, ProcessState::Zombie);
        quiet(&mut k);
        assert!(k.fabric.compiler_heap_owner_released(a.owner));
    }
}

#[test]
fn c22_nonzero_exit_and_forbidden_exec_are_terminal() {
    for (code, syscall) in [(7, SYS_EXIT), (0, SYS_EXEC), (0, SYS_DEV_SUBMIT)] {
        let mut k = machine();
        let key = client(&mut k, 4096, words(10, 1, 4097), code, syscall);
        let mut a = k
            .bind_compiler_output_attempt(key, budget(10, 4096))
            .unwrap();
        assert_eq!(
            run(&mut k, &mut a).unwrap_err(),
            CompilerRuntimeError::ExecutionFailure
        );
        assert_eq!(k.processes.len(), 2); // cleanup worker + producer; no child execution.
        quiet(&mut k);
        assert!(k.fabric.compiler_heap_owner_released(a.owner));
    }
}

#[test]
fn c22_work_denial_retires_owner_without_executing_or_refunding() {
    let mut k = machine();
    let key = client(&mut k, 4096, words(10, 1, 4097), 0, SYS_EXIT);
    let c = budget(10, 4096).context();
    let b = OutputRetryPolicy::new(8192, 1, 1)
        .unwrap()
        .start(c)
        .unwrap();
    let mut a = k.bind_compiler_output_attempt(key, b).unwrap();
    let pc = k.processes[key.slot].core.pc;
    let held = k.fabric.scoped_pointers.total_reserved_bytes();
    assert!(matches!(
        k.run_compiler_retry_slice(&mut a, 2),
        Err(CompilerRuntimeError::Resource(
            CompilerResourceError::WorkBudgetDenied
        ))
    ));
    assert_eq!(k.processes[key.slot].core.pc, pc);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), held);
    quiet(&mut k);
    assert!(k.fabric.compiler_heap_owner_released(a.owner));
}

#[test]
fn c22_registered_output_work_blocks_reply_snapshot_even_after_terminal_effect() {
    for terminal in [false, true] {
        let mut k = machine();
        let key = client(&mut k, 4096, words(10, 1, 4097), 0, SYS_EXIT);
        let mut a = k
            .bind_compiler_output_attempt(key, budget(10, 4096))
            .unwrap();
        let t = k
            .register_heap_cpu_read(key, Some(a.output), 1, k.fabric.scoped_pointers.revision())
            .unwrap();
        if terminal {
            k.fabric.execute_heap_cpu_work(t).unwrap();
        }
        assert!(matches!(
            run(&mut k, &mut a),
            Err(CompilerRuntimeError::Heap(HeapError::Busy))
        ));
        quiet(&mut k);
        assert!(!k.fabric.compiler_heap_owner_released(a.owner));
        if !terminal {
            k.fabric.cancel_heap_cpu_work(t).unwrap();
        }
        k.fabric.finish_heap_cpu_work(t).unwrap();
        quiet(&mut k);
        assert!(k.fabric.compiler_heap_owner_released(a.owner));
    }
}

#[test]
fn c22_independent_b_survives_a_cleanup_and_c_reuses_clean_backing() {
    let mut k = machine();
    let ka = client(&mut k, 4096, words(10, 1, 4097), 0, SYS_EXIT);
    let mut a = k
        .bind_compiler_output_attempt(ka, budget(10, 4096))
        .unwrap();
    let old_extent = k.fabric.diagnostic_heap_extents(a.owner)[0];
    k.fabric
        .write_heap_bytes(a.owner, a.agent, a.output, &[0xa5; 32])
        .unwrap();
    let kb = client(&mut k, 4096, words(20, 1, 4097), 0, SYS_EXIT);
    let b = k
        .bind_compiler_output_attempt(kb, budget(20, 4096))
        .unwrap();
    k.fabric
        .write_heap_bytes(b.owner, b.agent, b.output, &[0x5a; 32])
        .unwrap();
    let b_account = k.fabric.scoped_pointers.heap_account(b.owner).unwrap();
    let b_held = k
        .fabric
        .scoped_pointers
        .account_reserved_bytes(b_account)
        .unwrap();
    let mut pending = run(&mut k, &mut a).unwrap();
    let next = release(&mut k, &mut pending);
    let kc = client(&mut k, 8192, words(10, 2, 8193), 0, SYS_EXIT);
    let c = k.bind_compiler_output_attempt(kc, next).unwrap();
    assert!(
        k.fabric
            .diagnostic_heap_extents(c.owner)
            .iter()
            .any(|e| e.base == old_extent.base)
    );
    let mut data = [9; 32];
    k.fabric
        .read_heap_bytes(c.owner, c.agent, c.output, &mut data)
        .unwrap();
    assert_eq!(data, [0; 32]);
    k.fabric
        .read_heap_bytes(b.owner, b.agent, b.output, &mut data)
        .unwrap();
    assert_eq!(data, [0x5a; 32]);
    assert_eq!(
        k.fabric
            .scoped_pointers
            .account_reserved_bytes(b_account)
            .unwrap(),
        b_held
    );
    assert!(
        k.fabric
            .authenticate_heap_token(c.owner, c.agent, a.output)
            .is_err()
    );
    assert_eq!(k.processes[kb.slot].state, ProcessState::Running);
}

#[test]
fn c22_owner_change_between_slices_is_rejected_before_execution() {
    let mut k = machine();
    let key = client(&mut k, 4096, words(10, 1, 4097), 0, SYS_EXIT);
    let mut a = k
        .bind_compiler_output_attempt(key, budget(10, 4096))
        .unwrap();
    let pc = k.processes[key.slot].core.pc;
    k.processes[key.slot].generation += 1;
    assert_eq!(
        k.run_compiler_retry_slice(&mut a, 100).unwrap_err(),
        CompilerRuntimeError::Process
    );
    assert_eq!(k.processes[key.slot].core.pc, pc);
    assert_eq!(a.budget.as_ref().unwrap().spent_work(), 0);
}

#[test]
fn c22_budget_denial_cleans_up_but_does_not_yield_next_budget() {
    let mut k = machine();
    let key = client(&mut k, 4096, words(10, 1, 1024 * 1024 + 1), 0, SYS_EXIT);
    let mut a = k
        .bind_compiler_output_attempt(key, budget(10, 4096))
        .unwrap();
    assert_eq!(
        run(&mut k, &mut a).unwrap_err(),
        CompilerRuntimeError::Resource(CompilerResourceError::CapacityBudgetDenied)
    );
    quiet(&mut k);
    assert!(k.fabric.compiler_heap_owner_released(a.owner));
}
