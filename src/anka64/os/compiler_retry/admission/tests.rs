use super::*;
use crate::anka64::fabric::HeapWorkLimits;
use crate::anka64::placement::{PhysicalExtent,VirtualExtent};
use crate::anka64::scoped_pointers::heap::{RegistryLimits,HeapPlacementLimits};
use crate::anka64::isa::Asm64;
fn kernel(limit:u64)->Kernel {
    let f=Fabric::with_private_heap_cpu_work(0x1000000,
        RegistryLimits{slots:4096,scopes:4096,owners:16,cleanup:64,global_bytes:0x4000000},
        HeapPlacementLimits{physical_pool:PhysicalExtent{base:0x800000,size:0x400000},physical_claims:64,
            virtual_window:VirtualExtent{base:0x40000000,size:0x400000},per_owner_claims:16},
        1,HeapWorkLimits{tickets:8,requests:8}).unwrap();
    let mut k=Kernel::new(f);k.enable_heap_service(limit).unwrap();k
}
fn image()->AnkaldLinkedImage {
    let mut a=Asm64::new();a.pframe(0);a.punframe();a.ret();let mut bytes=a.to_bytes();
    for w in [1345400887u64,2,12,1,0,12,16,0] {bytes.extend_from_slice(&w.to_le_bytes());}
    AnkaldLinkedImage{bytes,code_size:12,lit_start:12,entry:0,process_slots_observed:1}
}
fn configured(slots:usize)->Kernel {
    let mut k=kernel(0x3000000);k.configure_compiler_admission(&image(),0x10000,slots,
        Some(&DeveloperExecutionAuthority::provision())).unwrap();k
}
#[test]
fn c2_admission_quota_denial_precedes_objects_and_processes() {
    let mut k=kernel(0x100000);let objects=k.fabric.objects.len();let processes=k.processes.len();
    let held=k.fabric.scoped_pointers.total_reserved_bytes();
    assert!(matches!(k.configure_compiler_admission(&image(),0x10000,1,
        Some(&DeveloperExecutionAuthority::provision())),Err(CompilerAdmissionError::Heap(_))));
    assert_eq!(k.fabric.objects.len(),objects);assert_eq!(k.processes.len(),processes);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),held);
}
#[test]
fn c2_admission_overlap_rolls_back_without_scrubbing_peer() {
    let mut k=kernel(0x3000000);let o=k.fabric.alloc_object("peer",4096,ObjectKind::Memory);
    assert!(k.fabric.place_object(o,0x10000));assert!(k.fabric.initialize_object(o,0,&[91;16]));
    let count=k.fabric.objects.len();let held=k.fabric.scoped_pointers.total_reserved_bytes();
    assert!(k.configure_compiler_admission(&image(),0x10000,1,
        Some(&DeveloperExecutionAuthority::provision())).is_err());
    assert_eq!(k.fabric.read_physical(0x10000,16),&[91;16]);assert_eq!(k.fabric.objects.len(),count);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),held);
}
#[test]
fn c2_admission_a_retirement_c_reuse_preserves_b_and_retains_arena_charge() {
    let mut k=configured(2);let auth=DeveloperExecutionAuthority::provision();
    let a=k.admit_compiler_process(Some(&auth)).unwrap();let b=k.admit_compiler_process(Some(&auth)).unwrap();
    let arena=k.compiler_admission.as_ref().unwrap();
    let old=arena.slots[0].object.unwrap();let at=arena.slots[0].base;let bp=arena.slots[1].base;
    k.fabric.write_physical(at,&[55;16]);k.fabric.write_physical(bp,&[77;16]);
    let held=k.fabric.scoped_pointers.total_reserved_bytes();
    assert!(matches!(k.retire_admitted_compiler(a),Err(CompilerAdmissionError::Busy)));
    k.finish_process(a.slot,ProcessResult::Exited(0));k.retire_admitted_compiler(a).unwrap();
    assert!(!k.fabric.objects.contains_key(&old));
    let c=k.admit_compiler_process(Some(&auth)).unwrap();
    assert_eq!(a.slot,c.slot);assert_ne!(a.generation,c.generation);
    assert_eq!(k.fabric.read_physical(at,16),&[0;16]);assert_eq!(k.fabric.read_physical(bp,16),&[77;16]);
    assert_eq!(k.processes[b.slot].state,ProcessState::Running);
    assert!(matches!(k.retire_admitted_compiler(a),Err(CompilerAdmissionError::Stale)));
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),held);
}
#[test]
fn c2_admission_capacity_and_authority_fail_without_touching_live_peer() {
    let mut k=configured(1);let auth=DeveloperExecutionAuthority::provision();
    assert!(matches!(k.admit_compiler_process(None),Err(CompilerAdmissionError::Authority)));
    let a=k.admit_compiler_process(Some(&auth)).unwrap();let count=k.fabric.objects.len();
    assert!(matches!(k.admit_compiler_process(Some(&auth)),Err(CompilerAdmissionError::Busy)));
    assert_eq!(k.fabric.objects.len(),count);assert_eq!(k.processes[a.slot].state,ProcessState::Running);
    assert!(matches!(k.configure_compiler_admission(&image(),0x500000,1,Some(&auth)),Err(CompilerAdmissionError::Configured)));
}
#[test]
fn c2_admission_bad_metadata_refunds_before_publication() {
    let mut k=kernel(0x3000000);let mut bad=image();*bad.bytes.last_mut().unwrap()=255;
    let held=k.fabric.scoped_pointers.total_reserved_bytes();let n=k.fabric.objects.len();
    assert!(k.configure_compiler_admission(&bad,0x10000,1,Some(&DeveloperExecutionAuthority::provision())).is_err());
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),held);assert_eq!(k.fabric.objects.len(),n);
}
#[test]
fn c2_admission_generic_scheduler_cannot_bypass_compile_only_route() {
    let mut k=configured(1);let a=k.admit_compiler_process(Some(&DeveloperExecutionAuthority::provision())).unwrap();
    k.run_process_with_exit_stop(a.slot,1,false);
    assert_eq!(k.processes[a.slot].result,Some(ProcessResult::ProtectionFault));
}
#[test]
fn c2_admission_recursive_execution_has_a_finite_metadata_boundary() {
    let mut k=kernel(0x3000000);let mut a=Asm64::new();
    a.pframe(0);a.call(-1);a.punframe();a.ret();let mut bytes=a.to_bytes();
    for w in [1345400887u64,2,16,1,0,16,16,0] {bytes.extend_from_slice(&w.to_le_bytes());}
    let recursive=AnkaldLinkedImage{bytes,code_size:16,lit_start:16,entry:0,process_slots_observed:1};
    let auth=DeveloperExecutionAuthority::provision();
    k.configure_compiler_admission(&recursive,0x10000,1,Some(&auth)).unwrap();
    let p=k.admit_compiler_process(Some(&auth)).unwrap();
    k.run_process_with_exit_stop(p.slot,256,true);
    if !k.processes[p.slot].exited() {k.run_process_with_exit_stop(p.slot,1,true);}
    assert_eq!(k.processes[p.slot].result,Some(ProcessResult::ProtectionFault));
    k.retire_admitted_compiler(p).unwrap();
}
#[test]
fn c2_admission_owner_cleanup_must_finish_before_stack_reuse() {
    let mut k=configured(1);let auth=DeveloperExecutionAuthority::provision();
    let p=k.admit_compiler_process(Some(&auth)).unwrap();
    let budget=super::super::tests::budget(1,4096);
    // Loader binds actual private-heap regions to this process incarnation.
    let attempt=k.load_compiler_request(p,budget,&[32;73]).unwrap();
    k.finish_process(p.slot,ProcessResult::Exited(0));
    assert!(matches!(k.retire_admitted_compiler(p),Err(CompilerAdmissionError::Busy)));
    super::super::tests::quiet(&mut k);
    assert!(k.fabric.compiler_heap_owner_released(attempt.owner));
    k.retire_admitted_compiler(p).unwrap();
}
