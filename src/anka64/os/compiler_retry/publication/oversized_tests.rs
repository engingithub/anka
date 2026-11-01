//! Fast boundary witnesses use ISA transport and a constructed valid AOM.
//! The separate ignored guest-compiler witness establishes actual C production.
use super::*;
use crate::anka64::fabric::HeapWorkLimits;
use crate::anka64::placement::{PhysicalExtent, VirtualExtent};
use crate::anka64::scoped_pointers::heap::{HeapPlacementLimits, RegistryLimits};
use crate::anka64::pointer_frames::{PointerModuleError, ValidatedPointerModule};
use super::super::super::capture::{CompilerCaptureError, CompilerCaptureSlice};

fn large_machine(owner_limit: u64) -> Kernel {
    let fabric = Fabric::with_private_heap_cpu_work(32 * 1024 * 1024,
        RegistryLimits { slots: 128, scopes: 64, owners: 16, cleanup: 64,
            global_bytes: 64 * 1024 * 1024 },
        HeapPlacementLimits {
            physical_pool: PhysicalExtent { base: 0x100000, size: 16 * 1024 * 1024 },
            physical_claims: 64,
            virtual_window: VirtualExtent { base: 0x40000000, size: 16 * 1024 * 1024 },
            per_owner_claims: 32,
        }, 1, HeapWorkLimits { tickets: 8, requests: 8 }).unwrap();
    let mut k = Kernel::new(fabric);
    k.enable_heap_service(owner_limit).unwrap();
    k
}
fn large_aom() -> Vec<u8> {
    let bytes = aom(false, 33000);
    assert!(bytes.len() > 262144 && bytes.len() < 524288);
    bytes
}
fn read_all(k: &Kernel, epoch: u64, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    for (i, chunk) in bytes.chunks_mut(4096).enumerate() {
        k.read_compiler_publication(epoch, (i * 4096) as u64, chunk).unwrap();
    }
    bytes
}

#[test]
fn c26_oversized_publication_exact_bytes_independent_capacities_and_read_only() {
    let bytes = large_aom();
    // The legacy API still applies its own bound; no global cap was raised.
    assert!(matches!(ValidatedPointerModule::from_aom(&bytes), Err(PointerModuleError::Capacity)));
    assert!(matches!(ValidatedPointerModule::from_aom_with_limit(&bytes, bytes.len() as u64 - 1),
        Err(PointerModuleError::Capacity)));
    let mut k = large_machine(16 * 1024 * 1024);
    for (index, capacity) in [524288, 1048576].into_iter().enumerate() {
        let (mut a, inputs, _) = setup_bytes(&mut k, bytes.clone(), capacity);
        freeze(&mut k, &mut a, &inputs);
        let h = retain(&mut k, &mut a);
        ready(&mut k, &h);
        let epoch = publish(&mut k, &h).unwrap();
        assert_eq!(epoch, index as u64 + 1);
        let receipt = k.compiler_publication_receipt(epoch).unwrap();
        assert_eq!(receipt.length, bytes.len() as u64);
        assert_eq!(receipt.context.output_capacity(), capacity);
        assert_eq!(receipt.permissions, Permissions::READ);
        assert_eq!(read_all(&k, epoch, bytes.len()), bytes);
        assert_eq!(read_all(&k, 1, bytes.len()), bytes);
        let record = &k.compiler_publications.records[&epoch];
        let (owner, pointer) = (record.job.key.custodian, record.pointer);
        let agent = k.processes[owner.process.slot].core.agent;
        assert!(k.fabric.write_heap_bytes(owner, agent, pointer, &[1]).is_err());
        assert!(k.read_compiler_publication(epoch, bytes.len() as u64, &mut [0]).is_err());
        assert!(k.read_compiler_publication(epoch, 0, &mut [0; 4097]).is_err());
    }
}

#[test]
fn c26_oversized_capture_quota_denial_preserves_previous_publication() {
    let mut k = large_machine(1024 * 1024);
    let (mut first, inputs, bytes) = setup(&mut k);
    freeze(&mut k, &mut first, &inputs);
    let h = retain(&mut k, &mut first); ready(&mut k, &h); publish(&mut k, &h).unwrap();
    let (mut denied, inputs, _) = setup_bytes(&mut k, large_aom(), 524288);
    freeze(&mut k, &mut denied, &inputs);
    assert!(matches!(k.run_compiler_capture_slice(&mut denied, 2000,
        RebuildAdmissionRole::RelocatableModule),
        Err(CompilerCaptureError::Runtime(CompilerRuntimeError::Heap(_)))));
    assert_eq!(k.compiler_publication_epoch(), 1);
    assert_eq!(read_all(&k, 1, bytes.len()), bytes);
    assert_eq!(k.processes[denied.owner.process.slot].state, ProcessState::Zombie);
}

#[test]
fn c26_oversized_capture_still_validates_last_symbol_and_refunds_stage() {
    let mut k = large_machine(16 * 1024 * 1024);
    let mut bytes = large_aom();
    *bytes.last_mut().unwrap() = 1; // Invalid unused signature, beyond 256 KiB.
    let (mut a, inputs, _) = setup_bytes(&mut k, bytes, 524288);
    freeze(&mut k, &mut a, &inputs);
    let account = k.fabric.scoped_pointers.heap_account(a.owner).unwrap();
    let before = k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    assert!(matches!(k.run_compiler_capture_slice(&mut a, 2000,
        RebuildAdmissionRole::RelocatableModule), Err(CompilerCaptureError::Admission)));
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(), before);
    assert_eq!(k.compiler_publication_epoch(), 0);
}

#[test]
fn c26_oversized_capture_does_not_admit_linked_image_role() {
    let mut k = large_machine(16 * 1024 * 1024);
    let (mut a, _, _) = setup_bytes(&mut k, large_aom(), 524288);
    assert!(matches!(k.run_compiler_capture_slice(&mut a, 2000,
        RebuildAdmissionRole::LinkedImage), Err(CompilerCaptureError::Admission)));
}

#[test]
fn c26_oversized_closed_capture_excludes_unused_arena_tail() {
    let mut k = large_machine(16 * 1024 * 1024);
    let bytes = large_aom();
    let (mut a, _, _) = setup_bytes(&mut k, bytes.clone(), 524288);
    let tail = k.fabric.scoped_pointers.add_heap_pointer(a.output, a.owner, bytes.len() as i64).unwrap();
    k.fabric.write_heap_bytes(a.owner, a.agent, tail, &[0xa5; 8]).unwrap();
    match k.run_compiler_capture_slice(&mut a, 2000, RebuildAdmissionRole::ClosedTranslationUnit).unwrap() {
        CompilerCaptureSlice::Captured(capture) => assert_eq!(capture.bytes(), bytes),
        _ => panic!("expected exact closed AOM capture"),
    };
}
