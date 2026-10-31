use super::super::tests::{imm, machine, quiet, release, run};
use super::*;
use crate::anka64::compiler_adapter::resources::{
    COMPILER_RESOURCE_MAGIC, CompilerResourceBindings, OutputGrowthSupport, OutputRetryPolicy,
};
use crate::anka64::guest_compiler::{install_trap_handler, seal_code_object};
use crate::anka64::pointer_frames::{FrameManifest, ValidatedPointerProgram};

fn budget(job: u64, capacity: u64, length: u64) -> OutputRetryBudget {
    OutputRetryPolicy::new(1024 * 1024, 3, 10000)
        .unwrap()
        .start(
            CompilerReplyContext::new(
                job,
                1,
                CompilerResourceBindings {
                    source: 21,
                    tools: 22,
                    profile: 23,
                    dependencies: 24,
                    plan: 25,
                },
                length,
                capacity,
                OutputGrowthSupport::CompilerOutput,
            )
            .unwrap(),
        )
        .unwrap()
}

/// An admitted ISA transport probe, NOT a migrated CC2 compiler. Entry is
/// deliberately not executed before the loader installs its protected pairs.
fn client(k: &mut Kernel, job: u64, attempt: u64, capacity: u64) -> ProcessKey {
    let mut a = Asm64::new();
    a.pframe(0);
    a.pload(R4, R0, 160); // source pointer in immutable request
    a.pload(R8, R0, 416); // output pointer
    a.pread(R12, R4, 8);
    a.pwrite(R12, R8, 8); // observe actual source bytes, including zero padding
    a.pload(R4, R0, 544); // request's authentic self-reference
    a.pload(R6, R4, 672); // reply through that self-reference
    let report = [
        COMPILER_RESOURCE_MAGIC,
        2,
        job,
        attempt,
        1,
        3,
        capacity + 1,
        0,
        3,
        0,
        21,
        22,
        23,
        24,
        25,
        0,
    ];
    for (i, word) in report.into_iter().enumerate() {
        imm(&mut a, R12, word);
        a.pwrite(R12, R6, 8);
        if i != 15 {
            a.movi(R10, 8);
            a.padd(R6, R6, R10);
        }
    }
    imm(&mut a, R0, SYS_EXIT);
    a.movi(R1, 0);
    a.trap(0);
    let exit = a.here() as u64 * 4;
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
        .alloc_object("compiler-loader-probe", 4096, ObjectKind::Memory);
    let physical = k.processes.len() as u64 * 8192;
    k.fabric.place_object(text, physical);
    k.fabric.write_physical(physical, &code);
    install_trap_handler(&mut k.fabric, physical, 4096);
    seal_code_object(&mut k.fabric, text, domain);
    let mut core = Anka64Core::new(agent, domain);
    core.address_map.add(0, 4096, text);
    core.trap_vector = 4080;
    let stack = k
        .fabric
        .alloc_object("compiler-loader-stack", 4096, ObjectKind::Memory);
    k.fabric.place_object(stack, physical + 4096);
    k.fabric.grant(domain, stack, 0, 4096, Permissions::RW);
    core.address_map.add(0x10000, 4096, stack);
    let program = ValidatedPointerProgram::validate(
        &code,
        vec![FrameManifest {
            entry: 0,
            end: code.len() as u64,
            size: 16,
            exits: vec![exit],
            locals: vec![],
        }],
    )
    .unwrap();
    core.admit_pointer_program(&mut k.fabric, program, 0, 0x10000, 0x11000)
        .unwrap();
    k.spawn(core)
}

fn request(k: &Kernel, key: ProcessKey) -> ScopedPointer {
    k.processes[key.slot]
        .core
        .authenticated_pointer(&k.fabric, R0)
        .unwrap()
        .unwrap()
}

fn at(k: &Kernel, a: &CompilerOutputAttempt, p: ScopedPointer, offset: u64) -> ScopedPointer {
    k.fabric
        .scoped_pointers
        .add_heap_pointer(p, a.owner, offset as i64)
        .unwrap()
}

fn region(
    k: &mut Kernel,
    a: &CompilerOutputAttempt,
    q: ScopedPointer,
    index: u64,
) -> ScopedPointer {
    let cell = at(k, a, q, 160 + index * 128);
    k.fabric
        .load_heap_pointer_cell(a.owner, a.agent, cell)
        .unwrap()
        .unwrap()
}

fn bytes(k: &Kernel, a: &CompilerOutputAttempt, p: ScopedPointer, n: u64) -> Vec<u8> {
    let mut data = vec![0; n as usize];
    k.fabric
        .read_heap_bytes(a.owner, a.agent, p, &mut data)
        .unwrap();
    data
}

#[test]
fn c23_exact_five_region_directory_and_authentic_self_reference() {
    let mut k = machine();
    let key = client(&mut k, 10, 1, 4096);
    let a = k
        .load_compiler_request(key, budget(10, 4096, 3), b"abc")
        .unwrap();
    let q = request(&k, key);
    let b = bytes(&k, &a, q, 768);
    let words: Vec<u64> = b
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect();
    let account = k.fabric.scoped_pointers.heap_account(a.owner).unwrap();
    assert_eq!(
        &words[..16],
        &[
            COMPILER_RESOURCE_MAGIC,
            2,
            128,
            10,
            1,
            account.serial(),
            21,
            22,
            23,
            24,
            25,
            5,
            128,
            768,
            128,
            0
        ]
    );
    let mut objects = std::collections::BTreeSet::new();
    let mut incarnations = std::collections::BTreeSet::new();
    let mut bases = std::collections::BTreeSet::new();
    for (i, (role, rights, length, valid)) in [
        (1, 1, 8, 3),
        (2, 3, WORKSPACE, 0),
        (3, 3, 4096, 0),
        (15, 1, 768, 768),
        (16, 3, 128, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let w = &words[16 + i * 16..32 + i * 16];
        let p = region(&mut k, &a, q, i as u64);
        assert_eq!(w[0..2], [role, rights]);
        assert_eq!(
            w[2],
            k.fabric
                .heap_object_for_pointer(a.owner, a.agent, p)
                .unwrap()
                .0
        );
        assert_eq!(w[3], 0);
        assert_eq!(w[4..6], p.words());
        assert_eq!(w[6..10], [length, valid, 1, length]);
        assert!(w[10] >= 0x40000000);
        assert!(w[11] >= length && w[11] % 4096 == 0);
        assert_eq!(w[12], account.serial());
        assert_ne!(w[13], 0);
        assert_eq!(w[14..16], [0, 0]);
        assert!(objects.insert(w[2]));
        assert!(incarnations.insert(w[13]));
        assert!(bases.insert(w[10]));
    }
    assert_eq!(region(&mut k, &a, q, 2), a.output);
    assert_eq!(region(&mut k, &a, q, 3), q);
    assert_eq!(region(&mut k, &a, q, 4), a.reply);
    let source = region(&mut k, &a, q, 0);
    assert_eq!(bytes(&k, &a, source, 8), b"abc\0\0\0\0\0");
    assert!(bytes(&k, &a, a.output, 4096).iter().all(|&b| b == 0));
    assert!(bytes(&k, &a, a.reply, 128).iter().all(|&b| b == 0));
}

#[test]
fn c23_guest_uses_loaded_cells_then_real_exit_cleanup_and_reload() {
    let mut k = machine();
    let key = client(&mut k, 10, 1, 4096);
    let mut a = k
        .load_compiler_request(key, budget(10, 4096, 3), b"abc")
        .unwrap();
    let old = request(&k, key);
    // Run through the real PFRAME/PLOAD/PREAD/PWRITE instructions before exit.
    for _ in 0..5 {
        assert!(!k.run_process_with_exit_stop(key.slot, 1, true));
    }
    assert_eq!(bytes(&k, &a, a.output, 8), b"abc\0\0\0\0\0");
    let held = k.fabric.scoped_pointers.total_reserved_bytes();
    let mut pending = run(&mut k, &mut a).unwrap();
    assert_eq!(k.processes[key.slot].result, Some(ProcessResult::Exited(0)));
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), held);
    assert!(
        k.fabric
            .authenticate_heap_token(a.owner, a.agent, old)
            .is_err()
    );
    let next = release(&mut k, &mut pending);
    assert_eq!(next.context().output_capacity(), 8192);
    assert!(k.fabric.compiler_heap_owner_released(a.owner));
    let b = client(&mut k, 10, 2, 8192);
    let mut second = k.load_compiler_request(b, next, b"abc").unwrap();
    assert!(
        k.fabric
            .authenticate_heap_token(second.owner, second.agent, old)
            .is_err()
    );
    let mut pending = run(&mut k, &mut second).unwrap();
    assert_eq!(
        release(&mut k, &mut pending).context().output_capacity(),
        16384
    );
}

#[test]
fn c23_read_only_source_and_request_reject_every_write_path() {
    let mut k = machine();
    let key = client(&mut k, 10, 1, 4096);
    let a = k
        .load_compiler_request(key, budget(10, 4096, 3), b"abc")
        .unwrap();
    let q = request(&k, key);
    let source = region(&mut k, &a, q, 0);
    for p in [source, q] {
        let before = bytes(&k, &a, p, 8);
        assert!(
            k.fabric
                .write_heap_bytes(a.owner, a.agent, p, &[42])
                .is_err()
        );
        assert!(
            k.fabric
                .store_heap_pointer_cell(a.owner, a.agent, p, Some(a.output))
                .is_err()
        );
        assert!(
            k.processes[key.slot]
                .core
                .syscall_write_span(&k.fabric, p, 0)
                .is_err()
        );
        assert!(
            k.processes[key.slot]
                .core
                .syscall_write_span(&k.fabric, p, 1)
                .is_err()
        );
        assert!(
            k.processes[key.slot]
                .core
                .syscall_read_span(&k.fabric, p, 8)
                .is_ok()
        );
        let current = CurrentHeapProcess::from_processes(&k.processes, key).unwrap();
        assert!(
            k.fabric
                .register_heap_cpu_write(
                    &current,
                    Some(p),
                    &[42],
                    k.fabric.scoped_pointers.revision()
                )
                .is_err()
        );
        let ticket = k
            .fabric
            .register_heap_cpu_read(&current, Some(p), 8, k.fabric.scoped_pointers.revision())
            .unwrap();
        k.fabric.cancel_heap_cpu_work(ticket).unwrap();
        k.fabric.finish_heap_cpu_work(ticket).unwrap();
        assert_eq!(bytes(&k, &a, p, 8), before);
    }
    k.fabric
        .write_heap_bytes(a.owner, a.agent, a.output, &[42])
        .unwrap();
    assert_eq!(bytes(&k, &a, a.output, 1), [42]);
}

#[test]
fn c23_raw_request_copy_cannot_copy_protected_kind() {
    let mut k = machine();
    let key = client(&mut k, 10, 1, 4096);
    let a = k
        .load_compiler_request(key, budget(10, 4096, 3), b"abc")
        .unwrap();
    let q = request(&k, key);
    let image = bytes(&k, &a, q, 768);
    k.fabric
        .write_heap_bytes(a.owner, a.agent, a.output, &image)
        .unwrap();
    let forged_cell = at(&k, &a, a.output, 160);
    assert!(
        k.fabric
            .load_heap_pointer_cell(a.owner, a.agent, forged_cell)
            .is_err()
    );
    assert!(
        k.fabric
            .load_heap_pointer_cell(a.owner, a.agent, at(&k, &a, q, 160))
            .unwrap()
            .is_some()
    );
}

#[test]
fn c23_bad_source_and_started_entry_reject_before_owner_admission() {
    let mut k = machine();
    for started in [false, true] {
        let key = client(&mut k, 10, 1, 4096);
        if started {
            assert!(!k.run_process_with_exit_stop(key.slot, 1, true));
        }
        let owner = k.compiler_owner(key).unwrap();
        let before = k.fabric.scoped_pointers.total_reserved_bytes();
        assert!(
            k.load_compiler_request(key, budget(10, 4096, if started { 3 } else { 4 }), b"abc")
                .is_err()
        );
        assert!(k.fabric.scoped_pointers.heap_account(owner).is_none());
        assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), before);
    }
}

#[test]
fn c23_partial_allocation_failure_is_fenced_and_cleaned_without_disturbing_peer() {
    let mut k = machine();
    let b = client(&mut k, 20, 1, 4096);
    let mut peer = k
        .load_compiler_request(b, budget(20, 4096, 3), b"abc")
        .unwrap();
    let peer_request = request(&k, b);
    let peer_image = bytes(&k, &peer, peer_request, 768);
    let a = client(&mut k, 10, 1, 1024 * 1024);
    let owner = k.compiler_owner(a).unwrap();
    let before = k.fabric.scoped_pointers.total_reserved_bytes();
    assert!(
        k.load_compiler_request(a, budget(10, 1024 * 1024, 3), b"abc")
            .is_err()
    );
    assert_eq!(
        k.processes[a.slot].result,
        Some(ProcessResult::ProtectionFault)
    );
    assert!(k.fabric.scoped_pointers.total_reserved_bytes() > before);
    assert!(!k.fabric.compiler_heap_owner_released(owner));
    quiet(&mut k);
    assert!(k.fabric.compiler_heap_owner_released(owner));
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), before);
    assert_eq!(bytes(&k, &peer, peer_request, 768), peer_image);
    let mut pending = run(&mut k, &mut peer).unwrap();
    assert_eq!(
        release(&mut k, &mut pending).context().output_capacity(),
        8192
    );
}

#[test]
fn c23_second_load_cannot_replace_live_request_or_change_charges() {
    let mut k = machine();
    let key = client(&mut k, 10, 1, 4096);
    let a = k
        .load_compiler_request(key, budget(10, 4096, 3), b"abc")
        .unwrap();
    let q = request(&k, key);
    let image = bytes(&k, &a, q, 768);
    let before = k.fabric.scoped_pointers.total_reserved_bytes();
    assert!(
        k.load_compiler_request(key, budget(11, 4096, 3), b"xyz")
            .is_err()
    );
    assert_eq!(request(&k, key), q);
    assert_eq!(bytes(&k, &a, q, 768), image);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), before);
    assert_eq!(k.processes[key.slot].state, ProcessState::Running);
}

#[test]
fn c23_empty_and_limit_source_preserve_exact_bytes_and_bound() {
    for length in [0, SOURCE_LIMIT, SOURCE_LIMIT + 1] {
        let mut k = machine();
        let key = client(&mut k, 10, 1, 4096);
        let source = vec![0x5a; length];
        let result = k.load_compiler_request(key, budget(10, 4096, length as u64), &source);
        if length > SOURCE_LIMIT {
            assert!(result.is_err());
            continue;
        }
        let a = result.unwrap();
        let q = request(&k, key);
        let p = region(&mut k, &a, q, 0);
        if length == 0 {
            assert_eq!(bytes(&k, &a, p, 8), [0; 8]);
        } else {
            for offset in (0..length).step_by(4096) {
                assert_eq!(
                    bytes(
                        &k,
                        &a,
                        at(&k, &a, p, offset as u64),
                        (length - offset).min(4096) as u64
                    ),
                    source[offset..(offset + 4096).min(length)]
                );
            }
        }
    }
}
