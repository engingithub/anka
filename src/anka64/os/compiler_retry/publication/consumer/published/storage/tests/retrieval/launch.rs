use super::*;
use super::super::super::launch::{LaunchPolicy,tests::Policy as ExecutePolicy};
use crate::anka64::{dev_runner::DevelopmentRunConfig,os::ProcessResult};
use std::sync::Mutex;
fn config()->DevelopmentRunConfig {DevelopmentRunConfig{quantum:2000,max_rounds:32,..Default::default()}}
fn returning()->(Kernel,u64,Temp,ArtifactStore,ReadPolicy) {returning_with_padding(1)}
fn returning_with_padding(slots:usize)->(Kernel,u64,Temp,ArtifactStore,ReadPolicy) {
    let mut bytes=aom(false,slots);let mut asm=crate::anka64::isa::Asm64::new();asm.movi(0,42);asm.nop();
    bytes[120..128].copy_from_slice(&asm.to_bytes());
    let(mut k,m)=fixture_bytes(bytes);
    let epoch=link(&mut k,m).publish(m,Some(&RebuildPublicationAuthority::provision())).unwrap();
    let(t,mut s)=store();k.persist_linked_compiler_publication(epoch,&mut s,caller(),91,7,&mut Policy::default()).unwrap();
    let bytes=fs::read(t.0.join("artifact.bytes")).unwrap();
    let r=k.linked_compiler_receipt(epoch).unwrap();let d=[dependency()];let manifest=Envelope::new(r.image,r.profile,identity(),&d).unwrap().manifest;
    (k,epoch,t,s,ReadPolicy{manifest,bytes,valid:true,inspections:0,checks:0,deny_after:None,dependencies:true,revoke_after_validate:false,panic_validate:false})
}
#[test]
fn sr110_live_kernel_launches_stored_bytes_and_retains_charge_until_drop() {
    let(mut k,e,t,mut s,mut p)=returning();let before=charge(&k);let record=fs::read(t.0.join("artifact.record")).unwrap();
    let policy=Mutex::new(ExecutePolicy::new(p.manifest,p.bytes.clone(),7));
    let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    let run=view.launch(&policy,0,config()).unwrap();assert_eq!(run.execution().child_result,ProcessResult::Exited(42));
    assert!(run.execution().process_slots_observed>=2);assert_eq!(run.execution().presented_code_permissions,Permissions::RX);
    assert!(charge(run.test_kernel())>before+p.manifest.size);assert_eq!(run.test_kernel().stored_launch_revision(),1);
    assert_eq!(run.test_kernel().compiler_publication_epoch(),e);drop(run);
    assert_eq!(charge(&k),before);assert_eq!(fs::read(t.0.join("artifact.record")).unwrap(),record);
    assert_eq!(fs::read(t.0.join("artifact.bytes")).unwrap(),p.bytes);assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn sr110_live_kernel_default_policy_denies_without_consuming_admission() {
    struct Deny;impl LaunchPolicy for Deny {}
    let(mut k,e,_t,mut s,mut p)=returning();let before=charge(&k);
    let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    assert!(view.launch(&Mutex::new(Deny),0,config()).is_err());
    assert_eq!(k.stored_launch_revision(),0);assert_eq!(charge(&k),before);assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn sr110_live_kernel_a_replay_denied_b_preserved_c_has_fresh_identity() {
    let(mut k,e,_t,mut s,mut p)=returning();let(_,account)=k.compiler_candidate_account().unwrap();
    let peer=k.fabric.scoped_pointers.reserve_host_storage(account,4096,k.fabric.scoped_pointers.revision()).unwrap();
    let before=charge(&k);let owner=k.compiler_candidate_custodian().unwrap();
    let peer_state=k.processes[owner.process.slot].state;
    let policy=Mutex::new(ExecutePolicy::new(p.manifest,p.bytes.clone(),7));
    let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    let run=view.launch(&policy,0,config()).unwrap();let a=run.id();drop(run);
    let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    assert!(view.launch(&policy,1,config()).is_err());assert_eq!(k.stored_launch_revision(),1);
    policy.lock().unwrap().challenge=8;
    let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    assert!(view.launch(&policy,0,config()).is_err()); // saved revision cannot consume C
    let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    let c=view.launch(&policy,1,config()).unwrap();assert_eq!(c.execution().child_result,ProcessResult::Exited(42));
    assert_eq!(a.boot,c.id().boot);assert!(c.id().serial>a.serial);drop(c);
    assert_eq!(k.stored_launch_revision(),2);assert_eq!(charge(&k),before);assert_eq!(k.compiler_candidate_custodian().unwrap(),owner);
    assert_eq!(k.processes[owner.process.slot].state,peer_state);
    assert_eq!(k.fabric.scoped_pointers.check_host_storage(peer,owner,k.fabric.scoped_pointers.revision()).unwrap(),4096);
    assert!(k.linked_compiler_receipt(e).is_ok());k.fabric.scoped_pointers.release_host_storage(peer).unwrap();
}
#[test]
fn sr110_live_kernel_commit_revocation_stale_time_and_unwind_refund() {
    let(mut k,e,_t,mut s,mut p)=returning();let before=charge(&k);
    for case in 0..3 {
        let mut policy=ExecutePolicy::new(p.manifest,p.bytes.clone(),7);
        match case {0=>policy.revoke_on_execute=true,1=>policy.advance_clock=true,_=>policy.panic_execute=true}
        let policy=Mutex::new(policy);
        let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||assert!(view.launch(&policy,0,config()).is_err())));
        assert_eq!(result.is_err(),case==2);assert_eq!(charge(&k),before);assert_eq!(k.stored_launch_revision(),0);
    }
    assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn sr110_live_kernel_expired_or_exhausted_original_budget_cannot_reset() {
    let(mut k,_,_t,mut s,mut p)=returning();let before=charge(&k);
    let policy=Mutex::new(ExecutePolicy::new(p.manifest,p.bytes.clone(),7));
    for expired in [true,false] {
        let limits=if expired {read_limits()}else{RetrievalLimits{work:8000,..read_limits()}};
        let mut view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),limits,&mut p).unwrap();
        // Deterministic trusted fault injection for time; the work case uses
        // the ACTUAL original low-budget retrieval, not a replacement budget.
        if expired {view.budget.as_mut().unwrap().expire_for_test();}
        assert!(view.launch(&policy,0,config()).is_err());
        assert_eq!(k.stored_launch_revision(),0);assert_eq!(charge(&k),before);
    }
}
#[test]
fn sr110_live_kernel_quota_and_stale_owner_deny_without_peer_effect() {
    let(mut k,e,_t,mut s,mut p)=returning();let before=charge(&k);let(_,account)=k.compiler_candidate_account().unwrap();
    let peer=k.fabric.scoped_pointers.reserve_host_storage(account,200*1024*1024-before,k.fabric.scoped_pointers.revision()).unwrap();
    let policy=Mutex::new(ExecutePolicy::new(p.manifest,p.bytes.clone(),7));
    let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    assert!(view.launch(&policy,0,config()).is_err());assert_eq!(charge(&k),200*1024*1024);
    k.fabric.scoped_pointers.release_host_storage(peer).unwrap();
    let mut view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    view.owner.context+=1;assert!(view.launch(&policy,0,config()).is_err());
    assert_eq!(charge(&k),before);assert_eq!(k.stored_launch_revision(),0);assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn sr110_live_kernel_run_timeout_keeps_consumed_challenge_and_allows_fresh_c() {
    // Each AOM padding slot contributes two straight-line instructions. After
    // replacing the first pair with MOVI/NOP, main still needs over 500 steps.
    // A 64-round run can stage/admit the child but cannot finish this image;
    // the normal 64,000-round budget can run the SAME stored image to completion.
    let(mut k,_,_t,mut s,mut p)=returning_with_padding(256);let before=charge(&k);
    let policy=Mutex::new(ExecutePolicy::new(p.manifest,p.bytes.clone(),7));

    // Pre-admission exhaustion must NOT consume the challenge or revision.
    let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    match view.launch(&policy,0,DevelopmentRunConfig{quantum:1,max_rounds:1,..config()}) {
        Err(error)=>assert_eq!(error,"StoredAdmissionRejected"),
        Ok(_)=>panic!("one-round startup unexpectedly completed"),
    }
    assert_eq!(k.stored_launch_revision(),0);assert_eq!(charge(&k),before);

    // A: admission succeeds; execution subsequently exhausts the finite budget.
    let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    match view.launch(&policy,0,DevelopmentRunConfig{quantum:1,max_rounds:64,..config()}) {
        Err(error)=>assert_eq!(error,"SupervisorDidNotExit"),
        Ok(_)=>panic!("padded image unexpectedly completed in 64 rounds"),
    }
    assert_eq!(k.stored_launch_revision(),1);assert_eq!(charge(&k),before);

    // A's consumed challenge stays consumed after timeout and cleanup.
    let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    match view.launch(&policy,1,config()) {
        Err(error)=>assert_eq!(error,"T1 execute admission denied"),
        Ok(_)=>panic!("timed-out admission challenge was replayed"),
    }
    assert_eq!(k.stored_launch_revision(),1);assert_eq!(charge(&k),before);

    // C: a fresh challenge launches the unchanged image with sufficient work.
    policy.lock().unwrap().challenge=8;
    let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    let run=view.launch(&policy,1,config()).unwrap();assert_eq!(run.execution().child_result,ProcessResult::Exited(42));drop(run);
    assert_eq!(k.stored_launch_revision(),2);assert_eq!(charge(&k),before);
}
