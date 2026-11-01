use super::*;
use super::super::capture::tests::{aom,captured};
use super::super::loader::tests::{budget,client_report};
use super::super::tests::{machine,quiet};
use crate::anka64::aom::AOM_MAGIC;
use crate::anka64::compiler_adapter::resources::COMPILER_RESOURCE_MAGIC;

fn sealed(k: &mut Kernel, bytes: &[u8]) -> LinkedArtifactKey {
    let owner = k.compiler_candidate_custodian().unwrap();
    let object = k.fabric.alloc_object("publication-input",bytes.len() as u64,ObjectKind::Memory);
    k.fabric.place_object(object,0x40000+object.0*4096);
    assert!(k.fabric.initialize_object(object,0,bytes));
    assert!(k.fabric.seal_object(object));
    assert!(k.fabric.grant(owner.domain,object,0,bytes.len() as u64,Permissions::READ).is_some());
    LinkedArtifactKey { object, generation:k.fabric.objects[&object].generation }
}

// Real loader/ISA transport, not a C compiler or self-host lineage witness.
pub(crate) fn setup(k: &mut Kernel) -> (CompilerOutputAttempt,PublicationInputs,Vec<u8>) {
    let bytes = aom(false,1);
    let report = [COMPILER_RESOURCE_MAGIC,2,10,1,0,0,0,bytes.len() as u64,8,0,21,22,23,24,25,0];
    let key = client_report(k,10,1,16384,Some(report));
    let b = budget(10,16384,8);
    let plan: Vec<u8> = b.publication_plan_words().into_iter().flat_map(u64::to_le_bytes).collect();
    let attempt = k.load_compiler_request(key,b,&AOM_MAGIC).unwrap();
    k.fabric.write_heap_bytes(attempt.owner,attempt.agent,attempt.output,&bytes).unwrap();
    let (_,object,generation,_,_) = k.processes[key.slot].core.compiler_publication_entry(&k.fabric).unwrap();
    let compiler = LinkedArtifactKey { object,generation };
    let owner = k.compiler_candidate_custodian().unwrap();
    assert!(k.fabric.grant(owner.domain,object,0,k.fabric.objects[&object].size,Permissions::READ).is_some());
    let inputs = PublicationInputs { bundle:sealed(k,b"frozen bundle"), source:sealed(k,&AOM_MAGIC),
        compiler, preprocessor:sealed(k,b"selected preprocessor"), linker:sealed(k,b"selected linker"),
        profile:sealed(k,&publication_profile()), plan:sealed(k,&plan),
        dependencies:vec![sealed(k,b"first dependency"),sealed(k,b"second dependency")] };
    (attempt,inputs,bytes)
}
fn freeze(k:&mut Kernel, a:&mut CompilerOutputAttempt,i:&PublicationInputs) -> PublicationKey {
    k.freeze_compiler_publication(a,i,RebuildAdmissionRole::RelocatableModule,
        k.compiler_publication_epoch(),Some(&RebuildPublicationAuthority::provision())).unwrap()
}
fn retain(k:&mut Kernel,a:&mut CompilerOutputAttempt) -> CompilerCandidateHandle {
    captured(k,a,RebuildAdmissionRole::RelocatableModule).retain().unwrap()
}
fn ready(k:&mut Kernel,h:&CompilerCandidateHandle) {
    for _ in 0..2000 { if k.poll_compiler_candidate(h).unwrap() { return; } }
    panic!("cleanup did not release producer");
}
fn publish(k:&mut Kernel,h:&CompilerCandidateHandle) -> Result<u64,PublicationError> {
    k.publish_compiler_candidate(h,k.compiler_publication_epoch(),Some(&RebuildPublicationAuthority::provision()))
}

#[test]
fn c25_publication_atomically_exposes_exact_read_only_artifact_and_receipt() {
    let mut k=machine();let(mut a,i,bytes)=setup(&mut k);let job=freeze(&mut k,&mut a,&i);
    let h=retain(&mut k,&mut a);assert!(k.compiler_publication_receipt(1).is_none());ready(&mut k,&h);
    // A real executed tool necessarily fails the output-only no-FETCH policy.
    // Its terminal fetches must not disqualify immutable provenance inputs.
    assert!(k.fabric.compiler_provenance_quiescent());
    assert!(!k.fabric.compiler_trace_safe(i.compiler.object));
    let custodian=k.compiler_candidate_custodian().unwrap();
    assert_eq!(sealed_length(&k.fabric,custodian.domain,i.compiler),
        Ok(k.fabric.objects[&i.compiler.object].size));
    assert_eq!(publish(&mut k,&h),Ok(1));
    let r=k.compiler_publication_receipt(1).unwrap();
    assert_eq!((r.epoch,r.abi,r.source_offset,r.length),(1,2,0,bytes.len() as u64));
    assert_eq!(r.permissions,Permissions::READ);assert!(r.heap_generation>0);
    assert_eq!(r.producer,a.owner);assert_eq!(r.context.output_capacity(),16384);
    assert_eq!(r.role,RebuildAdmissionRole::RelocatableModule);assert!(!r.admission.is_empty());
    assert_eq!(r.inputs.len(),9);assert_eq!(r.inputs[7].key,i.dependencies[0]);assert_eq!(r.inputs[8].key,i.dependencies[1]);
    assert_eq!(r.inputs[1].bytes,AOM_MAGIC);
    let mut actual=vec![0;bytes.len()];k.read_compiler_publication(1,0,&mut actual).unwrap();assert_eq!(actual,bytes);
    let p=&k.compiler_publications.records[&1];let(owner,pointer)=(p.job.key.custodian,p.pointer);
    let agent=k.processes[owner.process.slot].core.agent;
    assert!(k.fabric.write_heap_bytes(owner,agent,pointer,&[0]).is_err());
    assert!(k.compiler_candidate(&h).is_err());assert!(k.cancel_compiler_publication(job).is_err());
    assert!(k.read_compiler_publication(1,bytes.len() as u64,&mut [0]).is_err());
    assert!(k.read_compiler_publication(1,0,&mut [0;4097]).is_err());
}

#[test]
fn c25_publication_rejects_success_without_preexecution_provenance() {
    let mut k=machine();let(mut a,_,_)=setup(&mut k);let h=retain(&mut k,&mut a);ready(&mut k,&h);
    assert_eq!(publish(&mut k,&h),Err(PublicationError::Binding));
    assert_eq!(k.compiler_publication_epoch(),0);assert!(k.compiler_candidate(&h).unwrap().is_some());
}

#[test]
fn c25_publication_freeze_checks_actual_source_compiler_profile_and_plan() {
    for field in 0..4 {
        let mut k=machine();let(mut a,mut i,_)=setup(&mut k);let wrong=sealed(&mut k,b"wrong");
        match field {0=>i.source=wrong,1=>i.compiler=wrong,2=>i.profile=wrong,_=>i.plan=wrong};
        assert!(matches!(k.freeze_compiler_publication(&mut a,&i,RebuildAdmissionRole::RelocatableModule,0,
            Some(&RebuildPublicationAuthority::provision())),Err(PublicationError::Binding)));
        assert!(a.publication.is_none());assert!(k.compiler_publications.jobs.is_empty());
    }
}

#[test]
fn c25_publication_requires_current_authority_and_exact_owner_release() {
    let mut k=machine();let(mut a,i,_)=setup(&mut k);
    assert_eq!(k.freeze_compiler_publication(&mut a,&i,RebuildAdmissionRole::RelocatableModule,0,None),Err(PublicationError::Authority));
    freeze(&mut k,&mut a,&i);let h=retain(&mut k,&mut a);
    assert_eq!(publish(&mut k,&h),Err(PublicationError::NotReady));ready(&mut k,&h);
    assert_eq!(k.publish_compiler_candidate(&h,0,None),Err(PublicationError::Authority));
    assert_eq!(publish(&mut k,&h),Ok(1));
}

#[test]
fn c25_publication_rechecks_every_sealed_dependency_and_tool_byte() {
    for index in 0..9 {
        let mut k=machine();let(mut a,i,_)=setup(&mut k);freeze(&mut k,&mut a,&i);
        let h=retain(&mut k,&mut a);ready(&mut k,&h);
        let key=i.keys().nth(index).unwrap();let at=k.fabric.translate(key.object,0).unwrap();
        let old=k.fabric.read_physical(at,1)[0];k.fabric.write_physical(at,&[old^1]);
        assert_eq!(publish(&mut k,&h),Err(PublicationError::Binding));
        assert_eq!(k.compiler_publication_epoch(),0);assert!(k.compiler_publication_receipt(1).is_none());
        k.fabric.write_physical(at,&[old]);assert_eq!(publish(&mut k,&h),Ok(1));
    }
}

#[test]
fn c25_publication_revoked_read_grant_blocks_commit() {
    let mut k=machine();let(mut a,i,_)=setup(&mut k);let job=freeze(&mut k,&mut a,&i);
    let h=retain(&mut k,&mut a);ready(&mut k,&h);
    k.fabric.domains.get_mut(&job.custodian.domain).unwrap().capabilities.clear();
    assert_eq!(publish(&mut k,&h),Err(PublicationError::Binding));
    assert_eq!(k.compiler_publication_epoch(),0);
}

#[test]
fn c25_publication_stale_and_exhausted_epochs_preserve_prior_record() {
    let mut k=machine();let(mut a,i,bytes)=setup(&mut k);freeze(&mut k,&mut a,&i);
    let h=retain(&mut k,&mut a);ready(&mut k,&h);publish(&mut k,&h).unwrap();
    let(mut b,j,_)=setup(&mut k);freeze(&mut k,&mut b,&j);let next=retain(&mut k,&mut b);ready(&mut k,&next);
    assert_eq!(k.publish_compiler_candidate(&next,0,Some(&RebuildPublicationAuthority::provision())),Err(PublicationError::Epoch));
    k.compiler_publications.epoch=u64::MAX;
    assert_eq!(publish(&mut k,&next),Err(PublicationError::Exhausted));
    let mut actual=vec![0;bytes.len()];k.read_compiler_publication(1,0,&mut actual).unwrap();assert_eq!(actual,bytes);
}

#[test]
fn c25_publication_artifact_quota_denial_preserves_candidate_and_can_retry() {
    let mut k=machine();let(mut a,i,bytes)=setup(&mut k);let job=freeze(&mut k,&mut a,&i);
    let h=retain(&mut k,&mut a);ready(&mut k,&h);
    let account=k.fabric.scoped_pointers.heap_account(job.custodian).unwrap();
    let held=k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    let filler=k.fabric.scoped_pointers.reserve_heap(account,1024*1024-held,k.fabric.scoped_pointers.revision()).unwrap();
    assert!(matches!(publish(&mut k,&h),Err(PublicationError::Heap(_))));
    assert_eq!(k.compiler_candidate(&h).unwrap().unwrap().bytes,bytes);
    k.fabric.scoped_pointers.abort_heap(filler).unwrap();assert_eq!(publish(&mut k,&h),Ok(1));
}

#[test]
fn c25_publication_failure_after_sealing_keeps_epoch_and_cleanup_obligation() {
    let mut k=machine();let(mut a,i,_)=setup(&mut k);let job=freeze(&mut k,&mut a,&i);
    let h=retain(&mut k,&mut a);ready(&mut k,&h);
    let account=k.fabric.scoped_pointers.heap_account(job.custodian).unwrap();
    let held=k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    k.compiler_publications.fail_before_commit=true;
    assert_eq!(publish(&mut k,&h),Err(PublicationError::Storage));
    assert_eq!(k.compiler_publication_epoch(),0);assert!(k.compiler_publication_receipt(1).is_none());
    assert!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap()>held);
    assert!(k.compiler_candidate(&h).unwrap().is_some());quiet(&mut k);
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(),held);
    k.compiler_publications.fail_before_commit=false;assert_eq!(publish(&mut k,&h),Ok(1));
}

#[test]
fn c25_publication_cancelled_or_late_freeze_cannot_authorize_candidate() {
    let mut k=machine();let(mut a,i,_)=setup(&mut k);let job=freeze(&mut k,&mut a,&i);
    k.cancel_compiler_publication(job).unwrap();let h=retain(&mut k,&mut a);ready(&mut k,&h);
    assert_eq!(publish(&mut k,&h),Err(PublicationError::Binding));
    assert!(k.freeze_compiler_publication(&mut a,&i,RebuildAdmissionRole::RelocatableModule,0,
        Some(&RebuildPublicationAuthority::provision())).is_err());
}

#[test]
fn c25_publication_shutdown_releases_artifact_and_receipt_charges() {
    let mut k=machine();let(mut a,i,_)=setup(&mut k);let job=freeze(&mut k,&mut a,&i);
    let h=retain(&mut k,&mut a);ready(&mut k,&h);publish(&mut k,&h).unwrap();
    let account=k.fabric.scoped_pointers.heap_account(job.custodian).unwrap();
    assert!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap()>0);
    k.stop_heap_service();assert!(k.compiler_publications.records.is_empty());
    assert!(k.fabric.scoped_pointers.heap_account(job.custodian).is_none());
    assert!(k.compiler_publication_receipt(1).is_none());
}
