use super::*;
use super::super::tests::{machine,quiet};
use super::super::loader::tests::{budget,client_report};
use crate::anka64::scoped_pointers::heap::Resource;

fn source(k:&mut Kernel, bytes:&[u8]) -> CompilerInputHandle {
    k.ingest_compiler_input(CompilerInputRole::EffectiveSource,bytes).unwrap()
}
fn read<'a>(k:&'a Kernel,h:&CompilerInputHandle) -> &'a [u8] {
    k.compiler_input(h,CompilerInputRole::EffectiveSource).unwrap()
}
fn load(k:&mut Kernel,h:&CompilerInputHandle,job:u64) -> CompilerOutputAttempt {
    let n=read(k,h).len() as u64;
    let key=client_report(k,job,1,4096,None);
    k.load_compiler_request_from_input(key,budget(job,4096,n),h).unwrap()
}
fn source_bytes(k:&Kernel,a:&CompilerOutputAttempt) -> [u8;8] {
    let mut bytes=[0;8];k.fabric.read_heap_bytes(a.owner,a.agent,a.loaded_source.unwrap(),&mut bytes).unwrap();bytes
}

#[test]
fn c28_ingress_copies_exact_bytes_before_caller_mutates_and_checks_role() {
    let mut k=machine();let before=k.fabric.scoped_pointers.total_reserved_bytes();
    let mut bytes=b"a\0\xff".to_vec();let h=source(&mut k,&bytes);bytes.fill(0x55);
    assert_eq!(read(&k,&h),b"a\0\xff");
    assert!(k.fabric.scoped_pointers.total_reserved_bytes()>before);
    assert_eq!(k.compiler_input(&h,CompilerInputRole::Tool),Err(CompilerInputError::Role));
    k.discard_compiler_input(&h).unwrap();assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),before);
}

#[test]
fn c28_ingress_tool_is_shared_immutable_storage_without_recharging_borrows() {
    let mut k=machine();let h=k.ingest_compiler_input(CompilerInputRole::Tool,b"tool").unwrap();
    let held=k.fabric.scoped_pointers.total_reserved_bytes();
    let first=k.compiler_input(&h,CompilerInputRole::Tool).unwrap().as_ptr();
    for _ in 0..16 {
        let bytes=k.compiler_input(&h,CompilerInputRole::Tool).unwrap();assert_eq!(bytes,b"tool");assert_eq!(bytes.as_ptr(),first);
    }
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),held);
    assert_eq!(k.compiler_inputs.records.len(),1);
}

#[test]
fn c28_ingress_enforces_current_source_and_tool_boundaries_without_allocating() {
    let mut k=machine();let empty=source(&mut k,&[]);assert_eq!(read(&k,&empty),b"");
    let max=source(&mut k,&vec![7;super::super::loader::SOURCE_LIMIT]);
    assert_eq!(read(&k,&max).len(),65528);
    let held=k.fabric.scoped_pointers.total_reserved_bytes();
    assert!(matches!(k.ingest_compiler_input(CompilerInputRole::EffectiveSource,&vec![0;65529]),Err(CompilerInputError::Size)));
    assert!(matches!(k.ingest_compiler_input(CompilerInputRole::Tool,&[]),Err(CompilerInputError::Size)));
    assert!(matches!(k.ingest_compiler_input(CompilerInputRole::Tool,&vec![0;1024*1024+1]),Err(CompilerInputError::Size)));
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),held);
}

#[test]
fn c28_ingress_quota_denial_preserves_existing_input_and_all_charges() {
    let mut k=machine();let old=source(&mut k,b"old");let (_,account)=k.compiler_candidate_account().unwrap();
    let held=k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    let filler=k.fabric.scoped_pointers.reserve_host_storage(account,1024*1024-held,k.fabric.scoped_pointers.revision()).unwrap();
    let total=k.fabric.scoped_pointers.total_reserved_bytes();
    assert!(matches!(k.ingest_compiler_input(CompilerInputRole::EffectiveSource,b"new"),
        Err(CompilerInputError::Heap(HeapError::Capacity(Resource::OwnerBytes)))));
    assert_eq!(read(&k,&old),b"old");assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),total);
    k.fabric.scoped_pointers.release_host_storage(filler).unwrap();let new=source(&mut k,b"new");assert_eq!(read(&k,&new),b"new");
}

#[test]
fn c28_ingress_failure_after_copy_drops_only_new_storage_before_refund() {
    let mut k=machine();let old=source(&mut k,b"old");let held=k.fabric.scoped_pointers.total_reserved_bytes();
    k.compiler_inputs.fail_after_copy=true;
    assert!(matches!(k.ingest_compiler_input(CompilerInputRole::EffectiveSource,b"failed"),Err(CompilerInputError::Storage)));
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),held);assert_eq!(k.compiler_inputs.records.len(),1);
    assert_eq!(read(&k,&old),b"old");k.compiler_inputs.fail_after_copy=false;
    let next=source(&mut k,b"next");assert_eq!(read(&k,&next),b"next");
}

#[test]
fn c28_ingress_stale_and_foreign_handles_cannot_select_or_refund_new_input() {
    let mut k=machine();let mut other=machine();let a=source(&mut k,b"a");let b=source(&mut other,b"b");
    assert_eq!(other.discard_compiler_input(&a),Err(CompilerInputError::Unknown));assert_eq!(read(&other,&b),b"b");
    k.discard_compiler_input(&a).unwrap();let c=source(&mut k,b"c");let held=k.fabric.scoped_pointers.total_reserved_bytes();
    assert_eq!(k.discard_compiler_input(&a),Err(CompilerInputError::Unknown));
    assert_eq!(k.compiler_input(&a,CompilerInputRole::EffectiveSource),Err(CompilerInputError::Unknown));
    assert_eq!(read(&k,&c),b"c");assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),held);
}

#[test]
fn c28_ingress_real_loader_copies_source_and_survives_input_discard() {
    let mut k=machine();let h=source(&mut k,b"abc");let a=load(&mut k,&h,10);
    assert_eq!(source_bytes(&k,&a),*b"abc\0\0\0\0\0");
    let account=k.fabric.scoped_pointers.heap_account(a.owner).unwrap();let held=k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    k.discard_compiler_input(&h).unwrap();assert_eq!(source_bytes(&k,&a),*b"abc\0\0\0\0\0");
    for _ in 0..5 {assert!(!k.run_process_with_exit_stop(a.owner.process.slot,1,true));}
    let mut bytes=[0;8];k.fabric.read_heap_bytes(a.owner,a.agent,a.output,&mut bytes).unwrap();assert_eq!(bytes,*b"abc\0\0\0\0\0");
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(),held);
}

#[test]
fn c28_ingress_loader_rejects_role_and_length_before_producer_heap_admission() {
    let mut k=machine();let h=source(&mut k,b"abc");let tool=k.ingest_compiler_input(CompilerInputRole::Tool,b"abc").unwrap();
    let key=client_report(&mut k,10,1,4096,None);let owner=k.compiler_owner(key).unwrap();
    assert!(matches!(k.load_compiler_request_from_input(key,budget(10,4096,4),&h),Err(CompilerInputError::Size)));
    assert!(matches!(k.load_compiler_request_from_input(key,budget(10,4096,3),&tool),Err(CompilerInputError::Role)));
    assert!(k.fabric.scoped_pointers.heap_account(owner).is_none());assert_eq!(read(&k,&h),b"abc");
}

#[test]
fn c28_ingress_partial_loader_failure_restores_input_for_fresh_attempt() {
    let mut k=machine();let h=source(&mut k,b"abc");let (_,account)=k.compiler_candidate_account().unwrap();
    let held=k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    // Exhaust real backing through ordinary reservations, without changing
    // HeapService's private policy. Leave enough for the source page, but not
    // the following 24-KiB workspace, so this exercises partial-load cleanup.
    assert!((4096..24576).contains(&held));
    let custodian_filler=k.fabric.scoped_pointers.reserve_heap(account,1024*1024-held,
        k.fabric.scoped_pointers.revision()).unwrap();
    let peer=client_report(&mut k,99,1,4096,None);
    let peer_account=k.compiler_heap_account(peer).unwrap();
    let peer_filler=k.fabric.scoped_pointers.reserve_heap(peer_account,1024*1024,
        k.fabric.scoped_pointers.revision()).unwrap();
    let key=client_report(&mut k,10,1,4096,None);let owner=k.compiler_owner(key).unwrap();
    assert!(matches!(k.load_compiler_request_from_input(key,budget(10,4096,3),&h),
        Err(CompilerInputError::Runtime(CompilerRuntimeError::Heap(HeapError::PhysicalPlacement(_))))));
    assert_eq!(k.fabric.diagnostic_heap_extents(owner).len(),1,"source was attached before workspace denial");
    assert_eq!(read(&k,&h),b"abc");
    k.fabric.scoped_pointers.abort_heap(custodian_filler).unwrap();
    k.fabric.scoped_pointers.abort_heap(peer_filler).unwrap();
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(),held);
    assert_eq!(k.processes[peer.slot].state,ProcessState::Running);
    quiet(&mut k);assert!(k.fabric.compiler_heap_owner_released(owner));
    let b=load(&mut k,&h,11);assert_eq!(source_bytes(&k,&b),*b"abc\0\0\0\0\0");
}

#[test]
fn c28_ingress_producer_exit_preserves_input_but_custodian_death_destroys_it() {
    let mut k=machine();let h=source(&mut k,b"abc");let a=load(&mut k,&h,10);
    k.finish_process(a.owner.process.slot,ProcessResult::Exited(0));quiet(&mut k);assert_eq!(read(&k,&h),b"abc");
    let custodian=h.custodian;k.finish_process(custodian.process.slot,ProcessResult::ProtectionFault);
    assert_eq!(k.compiler_input(&h,CompilerInputRole::EffectiveSource),Err(CompilerInputError::Unknown));
    assert!(k.compiler_inputs.records.is_empty());
}

#[test]
fn c28_ingress_service_shutdown_refunds_all_input_storage() {
    let mut k=machine();let fixed=k.fabric.scoped_pointers.fixed_metadata_bytes();
    let a=source(&mut k,b"abc");let _b=k.ingest_compiler_input(CompilerInputRole::Tool,b"code").unwrap();
    k.stop_heap_service();assert!(k.compiler_inputs.records.is_empty());
    assert!(k.compiler_input(&a,CompilerInputRole::EffectiveSource).is_err());
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),fixed);
}

#[test]
fn c28_ingress_a_cleanup_c_reuse_preserves_b_source_and_stale_a_rejection() {
    let mut k=machine();let ha=source(&mut k,b"aaa");let hb=source(&mut k,b"bbb");
    let a=load(&mut k,&ha,10);let b=load(&mut k,&hb,11);
    let old=a.loaded_source.unwrap();let old_extents=k.fabric.diagnostic_heap_extents(a.owner);
    let account=k.fabric.scoped_pointers.heap_account(b.owner).unwrap();let held=k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    k.finish_process(a.owner.process.slot,ProcessResult::Exited(0));quiet(&mut k);k.discard_compiler_input(&ha).unwrap();
    let hc=source(&mut k,b"ccc");let c=load(&mut k,&hc,12);
    assert!(k.fabric.diagnostic_heap_extents(c.owner).iter().any(|e|old_extents.iter().any(|old|old.base==e.base)));
    assert!(k.fabric.authenticate_heap_token(c.owner,c.agent,old).is_err());
    assert_eq!(source_bytes(&k,&b),*b"bbb\0\0\0\0\0");assert_eq!(source_bytes(&k,&c),*b"ccc\0\0\0\0\0");
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(),held);
    assert_eq!(k.processes[b.owner.process.slot].state,ProcessState::Running);
    assert_eq!(read(&k,&hb),b"bbb");assert!(k.compiler_input(&ha,CompilerInputRole::EffectiveSource).is_err());
}

#[test]
fn c32_directory_ingress_remains_charged_across_failed_legacy_load_and_real_cleanup() {
    use crate::anka64::compiler_adapter::resources::growth::workspace::WorkspaceDirectory;
    let mut k=machine();let old=source(&mut k,b"peer B");
    let bytes=vec![b' ';70001];let h=k.ingest_compiler_directory_source(&bytes).unwrap();
    let key=client_report(&mut k,10,1,4096,None);
    let held=k.fabric.scoped_pointers.total_reserved_bytes();
    assert!(k.load_compiler_request_from_input(key,budget(10,4096,70001),&h).is_err());
    assert_eq!(read(&k,&h),bytes);assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),held);
    let d=WorkspaceDirectory::new([128,256,64,64,16,128,128],1<<20).unwrap();
    let mut a=k.load_compiler_input_with_workspace(key,budget(10,4096,70001),&h,d).unwrap();
    let mut pending=super::super::tests::run(&mut k,&mut a).unwrap();
    let _next=super::super::tests::release(&mut k,&mut pending);
    assert_eq!(read(&k,&h),bytes);assert_eq!(read(&k,&old),b"peer B");
    k.discard_compiler_input(&h).unwrap();assert_eq!(read(&k,&old),b"peer B");
}

#[test]
fn c32_directory_ingress_limit_and_quota_denial_do_not_damage_peer() {
    use crate::anka64::compiler_adapter::resources::growth::workspace::DIRECTORY_SOURCE_LIMIT;
    let mut k=machine();let old=source(&mut k,b"B");
    let (_,account)=k.compiler_candidate_account().unwrap();
    let used=k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    let filler=k.fabric.scoped_pointers.reserve_host_storage(account,1024*1024-used,
        k.fabric.scoped_pointers.revision()).unwrap();
    let held=k.fabric.scoped_pointers.total_reserved_bytes();
    assert!(matches!(k.ingest_compiler_directory_source(&vec![0;DIRECTORY_SOURCE_LIMIT+1]),Err(CompilerInputError::Size)));
    assert!(matches!(k.ingest_compiler_directory_source(&vec![0;70001]),
        Err(CompilerInputError::Heap(HeapError::Capacity(Resource::OwnerBytes)))));
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),held);assert_eq!(read(&k,&old),b"B");
    k.fabric.scoped_pointers.release_host_storage(filler).unwrap();
    let h=k.ingest_compiler_directory_source(&vec![0;70001]).unwrap();assert_eq!(read(&k,&h).len(),70001);
}
