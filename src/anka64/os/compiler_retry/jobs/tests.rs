use super::*;
use super::super::publication::tests::setup;
use super::super::tests::{machine,quiet};
use super::super::loader::tests::{budget,client_report};
use crate::anka64::aom::AOM_MAGIC;
use crate::anka64::pointer_frames::ValidatedPointerProgram;

fn sealed(k:&mut Kernel,bytes:&[u8])->LinkedArtifactKey {
    let c=k.compiler_candidate_custodian().unwrap();
    let o=k.fabric.alloc_object("job-plan",bytes.len() as u64,ObjectKind::Memory);
    k.fabric.place_object(o,0x40000+o.0*4096);
    assert!(k.fabric.initialize_object(o,0,bytes));assert!(k.fabric.seal_object(o));
    k.fabric.grant(c.domain,o,0,bytes.len() as u64,Permissions::READ).unwrap();
    LinkedArtifactKey {object:o,generation:k.fabric.objects[&o].generation}
}
fn capacity(k:&mut Kernel)->(CompilerOutputAttempt,PublicationInputs,ValidatedPointerProgram) {
    let (unused,mut inputs,_)=setup(k);
    k.finish_process(unused.owner.process.slot,ProcessResult::Exited(0));quiet(k);
    let key=client_report(k,10,1,16384,None);
    let a=k.load_compiler_request(key,budget(10,16384,8),&AOM_MAGIC).unwrap();
    let (program,object,generation,_,_)=k.processes[key.slot].core.compiler_publication_entry(&k.fabric).unwrap();
    let program=program.clone();inputs.compiler=LinkedArtifactKey {object,generation};
    let c=k.compiler_candidate_custodian().unwrap();
    k.fabric.grant(c.domain,object,0,k.fabric.objects[&object].size,Permissions::READ).unwrap();
    (a,inputs,program)
}
fn wait(k:&mut Kernel,h:&CompilerJobHandle,auth:&RebuildPublicationAuthority)->CompilerJobProgress {
    for _ in 0..2000 {
        let p=k.advance_compiler_job(h,2000,Some(auth)).unwrap();
        if p!=CompilerJobProgress::Running {return p;}
    }panic!("bounded job must finish or release a retry")
}
fn resumed_process(k:&mut Kernel,code:LinkedArtifactKey,program:ValidatedPointerProgram)->ProcessKey {
    let domain=k.fabric.create_domain();let agent=AgentId(500+k.processes.len() as u64);
    k.fabric.register_agent(agent,AgentKind::Cpu(CoreId(0)),domain);
    k.fabric.grant(domain,code.object,0,4096,Permissions::RX).unwrap();
    let stack=k.fabric.alloc_object("job-fresh-stack",4096,ObjectKind::Memory);
    k.fabric.place_object(stack,0x30000+k.processes.len() as u64*4096);
    k.fabric.grant(domain,stack,0,4096,Permissions::RW).unwrap();
    let mut core=Anka64Core::new(agent,domain);core.address_map.add(0,4096,code.object);
    core.address_map.add(0x10000,4096,stack);core.trap_vector=4080;
    core.admit_pointer_program(&mut k.fabric,program,0,0x10000,0x11000).unwrap();k.spawn(core)
}
#[test]
fn c5_job_success_retains_receipt_after_job_disposal() {
    let mut k=machine();let(a,i,bytes)=setup(&mut k);let owner=a.owner;
    let auth=RebuildPublicationAuthority::provision();
    let h=k.begin_compiler_job(a,i,&AOM_MAGIC,Some(&auth)).unwrap();
    assert_eq!(wait(&mut k,&h,&auth),CompilerJobProgress::Published(1));
    assert!(k.fabric.compiler_heap_owner_released(owner));
    assert!(k.compiler_jobs.records[&h.reservation.incarnation()].source.is_none());
    assert_eq!(k.advance_compiler_job(&h,1,Some(&auth)).unwrap(),CompilerJobProgress::Published(1));
    k.cancel_compiler_job(&h).unwrap();assert!(k.compiler_job_status(&h).is_err());
    let mut out=vec![0;bytes.len()];k.read_compiler_publication(1,0,&mut out).unwrap();assert_eq!(out,bytes);
}
#[test]
fn c5_job_cancel_preserves_independent_peer() {
    let mut k=machine();let(a,ia,_)=setup(&mut k);let owner=a.owner;
    let auth=RebuildPublicationAuthority::provision();let a=k.begin_compiler_job(a,ia,&AOM_MAGIC,Some(&auth)).unwrap();
    let(b,ib,_)=setup(&mut k);let peer=b.owner;
    let b=k.begin_compiler_job(b,ib,&AOM_MAGIC,Some(&auth)).unwrap();
    k.cancel_compiler_job(&a).unwrap();quiet(&mut k);
    assert!(k.fabric.compiler_heap_owner_released(owner));assert!(!k.fabric.compiler_heap_owner_released(peer));
    assert_eq!(wait(&mut k,&b,&auth),CompilerJobProgress::Published(1));
    k.cancel_compiler_job(&b).unwrap();
}
#[test]
fn c5_job_source_substitution_rejected_before_execution() {
    let mut k=machine();let(a,i,_)=setup(&mut k);let owner=a.owner;
    assert!(k.begin_compiler_job(a,i,b"substituted",Some(&RebuildPublicationAuthority::provision())).is_err());
    quiet(&mut k);assert!(k.fabric.compiler_heap_owner_released(owner));
    assert!(k.compiler_jobs.records.is_empty());assert_eq!(k.compiler_publication_epoch(),0);
}
#[test]
fn c5_job_retry_keeps_pin_source_and_exact_budget_until_resume() {
    let mut k=machine();let(a,i,program)=capacity(&mut k);let code=i.compiler;let owner=a.owner;
    let auth=RebuildPublicationAuthority::provision();let h=k.begin_compiler_job(a,i,&AOM_MAGIC,Some(&auth)).unwrap();
    assert!(k.compiler_job_retry_plan(&h).is_err());
    assert_eq!(wait(&mut k,&h,&auth),CompilerJobProgress::NeedsProcess);
    assert!(k.fabric.compiler_heap_owner_released(owner));
    let (words,directory)=k.compiler_job_retry_plan(&h).unwrap();assert!(directory.is_none());
    assert_eq!(words[4],2);assert_eq!(words[19],2);assert_eq!(words[20],2000);
    let pin=k.compiler_jobs.records[&h.reservation.incarnation()].pin.unwrap();
    k.recheck_compiler_job_pin(pin,Some(&AOM_MAGIC)).unwrap();
    let bytes:Vec<u8>=words.into_iter().flat_map(u64::to_le_bytes).collect();let plan=sealed(&mut k,&bytes);
    let fresh=resumed_process(&mut k,code,program);
    k.resume_compiler_job(&h,fresh,plan,Some(&auth)).unwrap();
    assert_eq!(k.compiler_job_status(&h).unwrap(),CompilerJobProgress::Running);
    assert!(k.recheck_compiler_job_pin(pin,None).is_err());
    assert!(k.resume_compiler_job(&h,fresh,plan,Some(&auth)).is_err());
    k.cancel_compiler_job(&h).unwrap();quiet(&mut k);
}
#[test]
fn c5_job_changed_provenance_cannot_cross_retry_gap() {
    let mut k=machine();let(a,i,program)=capacity(&mut k);let code=i.compiler;let source=i.source;
    let auth=RebuildPublicationAuthority::provision();let h=k.begin_compiler_job(a,i,&AOM_MAGIC,Some(&auth)).unwrap();
    assert_eq!(wait(&mut k,&h,&auth),CompilerJobProgress::NeedsProcess);
    let(w,_)=k.compiler_job_retry_plan(&h).unwrap();let plan=sealed(&mut k,&w.into_iter().flat_map(u64::to_le_bytes).collect::<Vec<_>>());
    let fresh=resumed_process(&mut k,code,program);
    let at=k.fabric.translate(source.object,0).unwrap();k.fabric.write_physical(at,b"X");
    assert!(k.resume_compiler_job(&h,fresh,plan,Some(&auth)).is_err());
    assert_eq!(k.processes[fresh.slot].core.pc,0);assert_eq!(k.compiler_publication_epoch(),0);
    k.cancel_compiler_job(&h).unwrap();k.finish_process(fresh.slot,ProcessResult::Exited(0));quiet(&mut k);
}
#[test]
fn c5_job_bad_next_plan_closes_attempt_without_publishing() {
    let mut k=machine();let(a,i,program)=capacity(&mut k);let code=i.compiler;let old_plan=i.plan;
    let auth=RebuildPublicationAuthority::provision();let h=k.begin_compiler_job(a,i,&AOM_MAGIC,Some(&auth)).unwrap();
    assert_eq!(wait(&mut k,&h,&auth),CompilerJobProgress::NeedsProcess);
    let fresh=resumed_process(&mut k,code,program);
    assert!(k.resume_compiler_job(&h,fresh,old_plan,Some(&auth)).is_err());
    assert_eq!(k.compiler_job_status(&h).unwrap(),CompilerJobProgress::Closed);
    assert_eq!(k.compiler_publication_epoch(),0);k.cancel_compiler_job(&h).unwrap();quiet(&mut k);
}
#[test]
fn c5_job_foreign_kernel_and_disposed_handle_rejected() {
    let mut k=machine();let(a,i,_)=setup(&mut k);let auth=RebuildPublicationAuthority::provision();
    let h=k.begin_compiler_job(a,i,&AOM_MAGIC,Some(&auth)).unwrap();let other=machine();
    assert!(other.compiler_job_status(&h).is_err());k.cancel_compiler_job(&h).unwrap();
    assert!(k.cancel_compiler_job(&h).is_err());
}
#[test]
fn c5_job_shutdown_cancels_running_and_waiting_jobs() {
    let mut k=machine();let(a,i,_)=capacity(&mut k);let auth=RebuildPublicationAuthority::provision();
    let h=k.begin_compiler_job(a,i,&AOM_MAGIC,Some(&auth)).unwrap();
    assert_eq!(wait(&mut k,&h,&auth),CompilerJobProgress::NeedsProcess);
    let(b,i,_)=setup(&mut k);let b=k.begin_compiler_job(b,i,&AOM_MAGIC,Some(&auth)).unwrap();
    k.stop_heap_service();assert!(k.compiler_jobs.records.is_empty());
    assert!(k.compiler_job_status(&h).is_err());assert!(k.compiler_job_status(&b).is_err());
}
#[test]
fn c5_job_missing_authority_does_not_run_or_publish() {
    let mut k=machine();let(a,i,_)=setup(&mut k);let owner=a.owner;
    assert!(matches!(k.begin_compiler_job(a,i,&AOM_MAGIC,None),Err(CompilerJobError::Authority)));
    quiet(&mut k);assert!(k.fabric.compiler_heap_owner_released(owner));assert_eq!(k.compiler_publication_epoch(),0);
}
#[test]
fn c5_job_resume_cannot_consume_an_independent_loaded_peer() {
    let mut k=machine();let(a,i,_)=capacity(&mut k);let plan=i.plan;
    let auth=RebuildPublicationAuthority::provision();let h=k.begin_compiler_job(a,i,&AOM_MAGIC,Some(&auth)).unwrap();
    assert_eq!(wait(&mut k,&h,&auth),CompilerJobProgress::NeedsProcess);
    let(peer,_,_)=setup(&mut k);let owner=peer.owner;
    assert!(k.resume_compiler_job(&h,owner.process,plan,Some(&auth)).is_err());
    assert_eq!(k.compiler_job_status(&h).unwrap(),CompilerJobProgress::NeedsProcess);
    assert_eq!(k.processes[owner.process.slot].core.pc,0);
    k.fabric.authenticate_heap_token(owner,peer.agent,peer.output).unwrap();
    k.cancel_compiler_job(&h).unwrap();k.finish_process(owner.process.slot,ProcessResult::Exited(0));quiet(&mut k);
}
#[test]
fn c5_job_quota_denial_does_not_take_peer_custody_or_publish() {
    let mut k=machine();let(a,i,_)=setup(&mut k);let auth=RebuildPublicationAuthority::provision();
    let h=k.begin_compiler_job(a,i,&AOM_MAGIC,Some(&auth)).unwrap();
    let(b,bi,_)=setup(&mut k);let denied=b.owner;
    let(_,account)=k.compiler_candidate_account().unwrap();
    let held=k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    let block=k.fabric.scoped_pointers.reserve_host_storage(account,(1<<20)-held,
        k.fabric.scoped_pointers.revision()).unwrap();
    assert!(k.begin_compiler_job(b,bi,&AOM_MAGIC,Some(&auth)).is_err());
    assert_eq!(k.compiler_job_status(&h).unwrap(),CompilerJobProgress::Running);
    assert_eq!(k.compiler_publication_epoch(),0);
    k.fabric.scoped_pointers.release_host_storage(block).unwrap();quiet(&mut k);
    assert!(k.fabric.compiler_heap_owner_released(denied));
    assert_eq!(wait(&mut k,&h,&auth),CompilerJobProgress::Published(1));k.cancel_compiler_job(&h).unwrap();
}

#[test]
fn c5_job_admitted_source_ingress_keeps_both_copy_charges_and_restores_handle() {
    let mut k=machine();let(a,i,_)=setup(&mut k);let auth=RebuildPublicationAuthority::provision();
    let source=k.ingest_compiler_directory_source(&AOM_MAGIC).unwrap();
    let h=k.begin_compiler_job_from_input(a,i,&source,Some(&auth)).unwrap();
    assert_eq!(k.compiler_input(&source,super::super::inputs::CompilerInputRole::EffectiveSource).unwrap(),AOM_MAGIC);
    k.discard_compiler_input(&source).unwrap();
    assert_eq!(wait(&mut k,&h,&auth),CompilerJobProgress::Published(1));k.cancel_compiler_job(&h).unwrap();
}
