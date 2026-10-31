//! Cheap entry-frame regressions: real loader, registry and machine transitions;
//! hand-assembled probes are not evidence of guest CC2 compilation or lineage.
use super::*;
use crate::anka64::core::StepResult;
use crate::anka64::fabric::HeapWorkLimits;
use crate::anka64::isa::Asm64;
use crate::anka64::placement::{PhysicalExtent, VirtualExtent};
use crate::anka64::scoped_pointers::{PointerError, heap::{HeapPlacementLimits, RegistryLimits}};

fn former_small_fabric() -> Fabric {
    Fabric::with_private_heap_cpu_work(0x1000000,
        RegistryLimits { slots: 64, scopes: 32, owners: 16, cleanup: 32,
            global_bytes: 0x1000000 },
        HeapPlacementLimits {
            physical_pool: PhysicalExtent { base: 0x800000, size: 0x600000 },
            physical_claims: 32,
            virtual_window: VirtualExtent { base: 0x40000000, size: 0x600000 },
            per_owner_claims: 16,
        }, 1, HeapWorkLimits { tickets: 8, requests: 8 }).unwrap()
}

#[test]
fn p108_producer_output_capture_crosses_read_boundaries_without_widening_fabric() {
    let (image, _) = probe();
    let (mut k, key) = machine(&image);
    let attempt = k.load_compiler_request(key, budget(b"x", 16384), b"x").unwrap();
    let expected: Vec<u8> = (0..16384).map(|i| ((i * 37 + i / 4096) % 251) as u8).collect();
    for (index, chunk) in expected.chunks(4096).enumerate() {
        let pointer = k.fabric.scoped_pointers.add_heap_pointer(
            attempt.output, attempt.owner, (index * 4096) as i64).unwrap();
        k.fabric.write_heap_bytes(attempt.owner, attempt.agent, pointer, chunk).unwrap();
    }
    assert!(k.fabric.read_heap_bytes(attempt.owner, attempt.agent,
        attempt.output, &mut [0; 4097]).is_err(), "per-read limit remains enforced");
    for used in [0, 4095, 4096, 4097, 8192, 8872, 16384] {
        assert_eq!(read_producer_output(&k, &attempt, used).unwrap(), expected[..used as usize]);
    }
    assert!(read_producer_output(&k, &attempt, 16385).is_err(),
        "chunking must not expose bytes beyond the allocation");
}

#[test]
fn p108_producer_output_capture_rejects_retired_owner_even_for_empty_output() {
    let (image, _) = probe();
    let (mut k, key) = machine(&image);
    let attempt = k.load_compiler_request(key, budget(b"x", 16384), b"x").unwrap();
    k.finish_process(key.slot, ProcessResult::Exited(0));
    for used in [0, 1, 4097, 8872] {
        assert!(read_producer_output(&k, &attempt, used).is_err());
    }
}

fn probe() -> (AnkaldLinkedImage, u64) {
    let mut a = Asm64::new();
    a.pframe(0); a.nop();
    a.plocal(R4, 0); a.nop(); a.pstore(R0, R4, 0); a.nop();
    a.plocal(R6, 1); a.nop(); a.pstore(R2, R6, 0); a.nop();
    let call = a.here(); a.call(0); a.nop();
    a.plocal(R4, 0); a.nop(); a.pload(R0, R4, 0); a.nop();
    a.plocal(R6, 1); a.nop(); a.pload(R2, R6, 0); a.nop();
    a.punframe(); a.nop();
    let stop = a.here() as u64 * 4; a.ret(); a.nop();
    let child = a.here();
    a.pframe(1); a.nop();
    a.movi(R0, 0); a.nop(); a.movi(R2, 0); a.nop();
    a.punframe(); a.nop(); a.ret(); a.nop();
    let mut code = a.to_bytes();
    code[call as usize*4..call as usize*4+4].copy_from_slice(&((50u32 << 26) | (child-call) as u32).to_le_bytes());
    let len = code.len() as u64;
    let mut words = vec![1345400887, 2, len, 2];
    // Native metadata inspection reports 174 entry locals; the larger 588-local
    // nested frame also exercises live parent storage and saved pointer pairs.
    for (entry, end, size, count) in [(0, child as u64*4, 2144, 174),
        (child as u64*4, len, 8192, 588)] {
        words.extend([entry, end, size, count]);
        words.extend([0, 16, 16, 3, 16, 16, 16, 3]);
        for i in 2..count { words.extend([32+(i-2)*8, 8, 8, 1]); }
    }
    code.extend(words.iter().flat_map(|word: &u64| word.to_le_bytes()));
    (AnkaldLinkedImage { bytes: code, code_size: len, lit_start: len,
        entry: 0, process_slots_observed: 1 }, stop)
}

#[test]
fn p108_producer_entry_old_fixture_exhausts_before_any_frame_write() {
    let (image, _) = probe();
    let (mut k, key) = machine_with_fabric(&image, former_small_fabric());
    let _attempt = k.load_compiler_request(key, budget(b"x", 4096), b"x").unwrap();
    assert!(k.fabric.scoped_pointers.preflight_frame(59).is_ok());
    assert_eq!(k.fabric.scoped_pointers.preflight_frame(60), Err(PointerError::Exhausted));
    let dirty = vec![0xa7; 2144];
    k.fabric.write_physical(0x300000-2144, &dirty);
    let registry = format!("{:?}", k.fabric.scoped_pointers);
    let registers = k.processes[key.slot].core.r;
    assert!(matches!(k.processes[key.slot].core.step(&mut k.fabric),
        StepResult::Fault(f) if f.pc == Some(0) && f.reason == FaultReason::ControlFlowViolation));
    assert_eq!(k.processes[key.slot].core.r, registers);
    assert_eq!(format!("{:?}", k.fabric.scoped_pointers), registry);
    assert_eq!(k.fabric.read_physical(0x300000-2144, 2144), dirty);
}

#[test]
fn p108_producer_entry_application_profile_runs_nested_frames_and_preserves_arguments() {
    let (image, stop) = probe();
    let (mut k, key) = machine(&image);
    let attempt = k.load_compiler_request(key, budget(b"x", 4096), b"x").unwrap();
    let request = k.processes[key.slot].core.authenticated_pointer(&k.fabric, R0).unwrap();
    let reply = k.processes[key.slot].core.authenticated_pointer(&k.fabric, R2).unwrap();
    assert!(k.fabric.scoped_pointers.preflight_frame(4091).is_ok());
    for _ in 0..64 {
        if k.processes[key.slot].core.pc == stop { break; }
        assert!(matches!(k.processes[key.slot].core.step(&mut k.fabric), StepResult::Continue));
    }
    assert_eq!(k.processes[key.slot].core.pc, stop);
    assert_eq!(k.processes[key.slot].core.authenticated_pointer(&k.fabric, R0).unwrap(), request);
    assert_eq!(k.processes[key.slot].core.authenticated_pointer(&k.fabric, R2).unwrap(), reply);
    assert!(k.fabric.scoped_pointers.preflight_frame(4091).is_ok(), "both frames retired");
    let mut byte = [9];
    k.fabric.read_heap_bytes(attempt.owner, attempt.agent, attempt.output, &mut byte).unwrap();
    assert_eq!(byte, [0]);
}

fn trace_request(k: &Kernel, key: ProcessKey) -> MemoryRequest {
    let core = &k.processes[key.slot].core;
    let (object, offset) = core.address_map.resolve(0).unwrap();
    MemoryRequest {
        context: AccessContext { agent: core.agent, domain: core.domain,
            privilege: Privilege::User },
        object, offset, width: Width::Word,
        length: 4, kind: AccessKind::Fetch,
    }
}

#[test]
fn p108_producer_trace_collection_preserves_every_instruction_and_heap_arguments() {
    let run = |collect: bool| {
        let (image, stop) = probe();
        let (mut k, key) = machine(&image);
        let attempt = k.load_compiler_request(key, budget(b"x", 4096), b"x").unwrap();
        let request = k.processes[key.slot].core.authenticated_pointer(&k.fabric, R0).unwrap();
        let reply = k.processes[key.slot].core.authenticated_pointer(&k.fabric, R2).unwrap();
        let mut states = Vec::new();
        if collect { assert!(collect_producer_trace(&mut k)); }
        for _ in 0..64 {
            if k.processes[key.slot].core.pc == stop { break; }
            assert!(matches!(k.processes[key.slot].core.step(&mut k.fabric), StepResult::Continue));
            states.push((k.processes[key.slot].core.pc, k.processes[key.slot].core.r));
            if collect { assert!(collect_producer_trace(&mut k)); }
        }
        assert_eq!(k.processes[key.slot].core.pc, stop);
        assert_eq!(k.processes[key.slot].core.authenticated_pointer(&k.fabric, R0).unwrap(), request);
        assert_eq!(k.processes[key.slot].core.authenticated_pointer(&k.fabric, R2).unwrap(), reply);
        assert!(k.fabric.scoped_pointers.preflight_frame(4091).is_ok());
        let mut byte = [9];
        k.fabric.read_heap_bytes(attempt.owner, attempt.agent, attempt.output, &mut byte).unwrap();
        assert_eq!(byte, [0]);
        // A new record starts at index zero only when all diagnostic history
        // was actually released. Identity still advances independently.
        let request = trace_request(&k, key);
        let index = k.fabric.submit(request, None);
        assert_eq!(index == 0, collect);
        assert!(k.fabric.transaction(index).id.0 > 0);
        states
    };
    assert_eq!(run(false), run(true));
}

#[test]
fn p108_producer_trace_collection_refuses_live_work_and_non_cpu_agents() {
    let (image, _) = probe();
    let (mut k, key) = machine(&image);
    assert!(collect_producer_trace(&mut k));
    let request = trace_request(&k, key);
    let index = k.fabric.submit(request, None);
    let id = k.fabric.transaction(index).id;
    for state in [TxState::Requested, TxState::Authorized, TxState::Prepared] {
        assert_eq!(k.fabric.transaction(index).state, state);
        assert!(!collect_producer_trace(&mut k));
        assert_eq!(k.fabric.transaction(index).id, id);
        k.fabric.advance(index);
    }
    assert_eq!(k.fabric.transaction(index).state, TxState::Committed);
    k.fabric.register_agent(AgentId(999), AgentKind::Dma, request.context.domain);
    assert!(!collect_producer_trace(&mut k));
    assert_eq!(k.fabric.transaction(index).id, id);
    k.fabric.agents.remove(&AgentId(999));
    assert!(collect_producer_trace(&mut k));
    let next = k.fabric.submit(request, None);
    assert_eq!(next, 0);
    assert!(k.fabric.transaction(next).id.0 > id.0);
}
