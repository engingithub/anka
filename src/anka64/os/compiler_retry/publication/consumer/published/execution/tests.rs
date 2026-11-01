use super::*;
use super::super::tests::{fixture_bytes,link};
use super::super::super::tests::charge;
use crate::anka64::os::compiler_retry::capture::tests::aom;
use crate::anka64::os::ProcessResult;

fn fixture()->(Kernel,u64,u64) {
    // Real protected machine code and real guest linking, without rebuilding
    // CC2 in each fast test. The real producer witness covers that upstream leg.
    // Ordinary C main returns; selected startup must CALL it and exit with R0.
    let mut bytes=aom(false,1);
    let mut instruction=crate::anka64::isa::Asm64::new();
    instruction.movi(0,42);instruction.nop();
    bytes[120..128].copy_from_slice(&instruction.to_bytes());
    let(mut k,m)=fixture_bytes(bytes);
    let e=link(&mut k,m).publish(m,Some(&RebuildPublicationAuthority::provision())).unwrap();
    (k,m,e)
}
fn config()->DevelopmentRunConfig {
    DevelopmentRunConfig {quantum:2000,max_rounds:32,..DevelopmentRunConfig::default()}
}
#[test]
fn c4_execution_runs_current_receipt_via_spawn_wait_without_widening_publication() {
    let(mut k,m,e)=fixture();let before=charge(&k);
    let auth=DeveloperExecutionAuthority::provision();
    let result=k.run_linked_compiler_publication(e,Some(&auth),config()).unwrap();
    assert_eq!(result.publication_epoch,e);assert_eq!(result.profile,ApplicationLinkProfile::Standard);
    assert_eq!(result.execution().child_result,ProcessResult::Exited(42));
    assert!(result.execution().process_slots_observed>=2);
    assert_eq!(result.execution().presented_code_permissions,Permissions::RX);
    assert_eq!(result.execution().presented_literal_permissions,Some(Permissions::READ));
    assert_eq!(charge(result.kernel),before+REPORT_CHARGE);
    drop(result);
    assert_eq!(k.compiler_publication_epoch(),e);assert_eq!(charge(&k),before);
    assert!(k.compiler_publication_receipt(m).is_some());
    assert_eq!(k.linked_compiler_receipt(e).unwrap().permissions,Permissions::READ);
    let r=&k.compiler_publications.links[&e];
    let agent=k.processes[r.owner.process.slot].core.agent;
    assert!(k.fabric.write_heap_bytes(r.owner,agent,r.pointer,&[1]).is_err());
}
#[test]
fn c4_execution_requires_separate_authority_and_rejects_module_epoch() {
    let(mut k,m,e)=fixture();let before=charge(&k);
    assert!(matches!(k.run_linked_compiler_publication(e,None,config()),Err(CompilerLinkError::Authority)));
    assert!(k.run_linked_compiler_publication(m,Some(&DeveloperExecutionAuthority::provision()),config()).is_err());
    assert_eq!(charge(&k),before);assert_eq!(k.compiler_publication_epoch(),e);
    assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn c4_execution_revoked_dependency_blocks_existing_linked_receipt() {
    let(mut k,m,e)=fixture();let before=charge(&k);
    let key=k.compiler_publications.records[&m].job.inputs[1].key;
    let owner=k.compiler_candidate_custodian().unwrap();
    k.fabric.domains.get_mut(&owner.domain).unwrap().capabilities.retain(|c|c.cap.object()!=key.object);
    assert!(k.run_linked_compiler_publication(e,Some(&DeveloperExecutionAuthority::provision()),config()).is_err());
    assert_eq!(charge(&k),before);assert_eq!(k.compiler_publication_epoch(),e);
}
#[test]
fn c4_execution_rechecks_exact_heap_bytes_before_loading() {
    let(mut k,_,e)=fixture();let before=charge(&k);
    // Trusted-state fault injection: no guest can edit this retained record.
    k.compiler_publications.links.get_mut(&e).unwrap().image.as_mut().unwrap().bytes[8]^=1;
    assert!(k.run_linked_compiler_publication(e,Some(&DeveloperExecutionAuthority::provision()),config()).is_err());
    assert_eq!(charge(&k),before);assert_eq!(k.compiler_publication_epoch(),e);
}
#[test]
fn c4_execution_discarded_receipt_cannot_authorize_another_run() {
    let(mut k,m,e)=fixture();let auth=RebuildPublicationAuthority::provision();
    k.discard_linked_compiler_publication(e,Some(&auth)).unwrap();
    assert!(k.run_linked_compiler_publication(e,Some(&DeveloperExecutionAuthority::provision()),config()).is_err());
    assert!(k.compiler_publication_receipt(m).is_some());assert_eq!(k.compiler_publication_epoch(),e);
}
#[test]
fn c4_execution_rejects_zero_or_excess_dispatch_without_changing_receipt() {
    let(mut k,_,e)=fixture();let before=charge(&k);
    for (quantum,max_rounds) in [(0,1),(1,0),(200001,1),(1,10001)] {
        let c=DevelopmentRunConfig {quantum,max_rounds,..config()};
        assert!(matches!(k.run_linked_compiler_publication(e,Some(&DeveloperExecutionAuthority::provision()),c),Err(CompilerLinkError::Binding)));
    }
    assert_eq!(charge(&k),before);assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn c4_execution_timeout_preserves_publication_and_allows_fresh_run() {
    let(mut k,_,e)=fixture();let before=charge(&k);let auth=DeveloperExecutionAuthority::provision();
    let tiny=DevelopmentRunConfig {quantum:1,max_rounds:1,..config()};
    assert!(matches!(k.run_linked_compiler_publication(e,Some(&auth),tiny),
        Err(CompilerLinkError::Run(dev_runner::DevelopmentRunError::SupervisorDidNotExit))));
    assert_eq!(charge(&k),before);assert_eq!(k.compiler_publication_epoch(),e);
    let run=k.run_linked_compiler_publication(e,Some(&auth),config()).unwrap();
    assert_eq!(run.execution().child_result,ProcessResult::Exited(42));
}

#[test]
fn c4_execution_entry_ret_without_call_authority_faults_and_keeps_receipt() {
    // Do not "fix" the positive fixture by granting an invented return token.
    // The former fixture is now a required hostile execution witness.
    let(mut k,m)=fixture_bytes(aom(false,1));
    let e=link(&mut k,m).publish(m,Some(&RebuildPublicationAuthority::provision())).unwrap();
    let before=charge(&k);
    let image=k.linked_compiler_receipt(e).unwrap().image.clone();
    let mut fabric=Fabric::with_application_heap(0x1000000).unwrap();
    let mut placement=PhysicalPlacementManager::new(0x10000,0x700000).unwrap();
    let artifact=ankald::publish_linked_image(&mut fabric,&mut placement,"direct-entry",&image).unwrap();
    let mut registry=DevelopmentArtifactRegistry::new();
    registry.register_linked_application(&fabric,&artifact).unwrap();
    // The direct process-entry API does not implicitly opt into C startup.
    let run=dev_runner::run_registered_artifact_with_config(&registry,
        Some(&DeveloperExecutionAuthority::provision()),&mut fabric,&mut placement,
        "rebuilt-application",config()).unwrap();
    assert_eq!(run.child_result,ProcessResult::ProtectionFault);
    assert!(run.byte_output.is_empty());
    assert_eq!(k.compiler_publication_epoch(),e);assert_eq!(charge(&k),before);
    assert_eq!(k.linked_compiler_receipt(e).unwrap().permissions,Permissions::READ);
}

#[test]
fn c4_execution_explicit_sys_exit_remains_valid_under_c_startup() {
    let mut bytes=aom(false,3);let mut a=crate::anka64::isa::Asm64::new();
    a.movi(1,73);a.nop();a.movi(0,crate::anka64::os::SYS_EXIT as i32);a.nop();a.trap(0);a.nop();
    bytes[120..144].copy_from_slice(&a.to_bytes());
    let(mut k,m)=fixture_bytes(bytes);
    let e=link(&mut k,m).publish(m,Some(&RebuildPublicationAuthority::provision())).unwrap();
    let run=k.run_linked_compiler_publication(e,Some(&DeveloperExecutionAuthority::provision()),config()).unwrap();
    assert_eq!(run.execution().child_result,ProcessResult::Exited(73));
    drop(run);
    assert!(k.linked_compiler_receipt(e).is_ok());
}

#[test]
fn c2_run_charge_checks_stack_geometry_and_includes_all_machine_capacity() {
    let c=config();assert_eq!(machine_charge(128,c).unwrap(),96*1024*1024+32*128);
    for (stack,virtual_limit) in [(0,0x200000),(65537,0x200000),(16384,0),(16384,0x1000001)] {
        let bad=DevelopmentRunConfig{child_stack_size:stack,virtual_limit,..c};
        assert!(machine_charge(128,bad).is_err());
    }
    assert!(machine_charge(0,c).is_err());assert!(machine_charge(0x200001,c).is_err());
}
#[test]
fn c2_run_quota_denial_keeps_receipt_and_refunds_report_reservation() {
    let(mut k,m,e)=fixture();let before=charge(&k);
    let(_,account)=k.compiler_candidate_account().unwrap();
    let filler=k.fabric.scoped_pointers.reserve_host_storage(account,
        256*1024*1024-before-REPORT_CHARGE,k.fabric.scoped_pointers.revision()).unwrap();
    let held=charge(&k);
    assert!(matches!(k.run_linked_compiler_publication(e,Some(&DeveloperExecutionAuthority::provision()),config()),
        Err(CompilerLinkError::Heap(HeapError::Capacity(_)))));
    assert_eq!(charge(&k),held);assert!(k.compiler_publication_receipt(m).is_some());
    assert!(k.linked_compiler_receipt(e).is_ok());
    k.fabric.scoped_pointers.release_host_storage(filler).unwrap();assert_eq!(charge(&k),before);
}
#[test]
fn c2_run_report_holds_only_its_output_charge_until_drop() {
    let(mut k,_,e)=fixture();let before=charge(&k);
    let run=k.run_linked_compiler_publication(e,Some(&DeveloperExecutionAuthority::provision()),config()).unwrap();
    assert_eq!(charge(run.kernel),before+REPORT_CHARGE);
    assert_eq!(run.execution().byte_output.capacity(),OUTPUT_BYTES);
    assert_eq!(run.execution().child_result,ProcessResult::Exited(42));
    drop(run);assert_eq!(charge(&k),before);assert!(k.linked_compiler_receipt(e).is_ok());
}

#[test]
fn c5_http_input_requires_separate_authorities_before_charging() {
    let(mut k,_,e)=fixture();let before=charge(&k);
    let execution=DeveloperExecutionAuthority::provision();let input=DeveloperInputAuthority::provision();
    assert!(matches!(k.run_linked_compiler_publication_with_input(e,Some(&execution),None,b"x",config()),Err(CompilerLinkError::Authority)));
    assert!(matches!(k.run_linked_compiler_publication_with_input(e,None,Some(&input),b"x",config()),Err(CompilerLinkError::Authority)));
    assert_eq!(charge(&k),before);assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn c5_http_input_oversize_and_wrong_receipt_preserve_publications() {
    let(mut k,m,e)=fixture();let before=charge(&k);
    let execution=DeveloperExecutionAuthority::provision();let input=DeveloperInputAuthority::provision();
    assert!(matches!(k.run_linked_compiler_publication_with_input(e,Some(&execution),Some(&input),&vec![0;INPUT_BYTES+1],config()),Err(CompilerLinkError::Binding)));
    assert!(k.run_linked_compiler_publication_with_input(m,Some(&execution),Some(&input),b"",config()).is_err());
    assert_eq!(charge(&k),before);assert!(k.compiler_publication_receipt(m).is_some());
}
#[test]
fn c5_http_input_copy_peak_requires_additional_quota() {
    let(mut k,_,e)=fixture();let before=charge(&k);
    let bytes=k.linked_compiler_receipt(e).unwrap().image.bytes.len();
    let base=machine_charge(bytes,config()).unwrap();
    let(_,account)=k.compiler_candidate_account().unwrap();
    let filler=k.fabric.scoped_pointers.reserve_host_storage(account,
        256*1024*1024-before-REPORT_CHARGE-base,k.fabric.scoped_pointers.revision()).unwrap();
    let held=charge(&k);
    assert!(matches!(k.run_linked_compiler_publication_with_input(e,Some(&DeveloperExecutionAuthority::provision()),
        Some(&DeveloperInputAuthority::provision()),b"x",config()),Err(CompilerLinkError::Heap(HeapError::Capacity(_)))));
    assert_eq!(charge(&k),held);assert!(k.linked_compiler_receipt(e).is_ok());
    k.fabric.scoped_pointers.release_host_storage(filler).unwrap();assert_eq!(charge(&k),before);
}
#[test]
fn c5_http_input_is_released_with_machine_not_with_report() {
    let(mut k,_,e)=fixture();let before=charge(&k);
    for bytes in [&b"first"[..],&b""[..],&b"second"[..]] {
        let r=k.run_linked_compiler_publication_with_input(e,Some(&DeveloperExecutionAuthority::provision()),
            Some(&DeveloperInputAuthority::provision()),bytes,config()).unwrap();
        assert_eq!(r.execution().child_result,ProcessResult::Exited(42));
        assert_eq!(charge(r.kernel),before+REPORT_CHARGE);
        drop(r);assert_eq!(charge(&k),before);
    }
}
#[test]
fn c5_http_input_failed_startup_refunds_both_machine_and_input() {
    let(mut k,_,e)=fixture();let before=charge(&k);
    let tiny=DevelopmentRunConfig{quantum:1,max_rounds:1,..config()};
    assert!(k.run_linked_compiler_publication_with_input(e,Some(&DeveloperExecutionAuthority::provision()),
        Some(&DeveloperInputAuthority::provision()),b"x",tiny).is_err());
    assert_eq!(charge(&k),before);assert!(k.linked_compiler_receipt(e).is_ok());
}
