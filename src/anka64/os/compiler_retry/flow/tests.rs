use super::*;
use super::super::publication::tests::setup;
use super::super::tests::{machine,quiet};

#[test]
fn c25_flow_success_captures_cleans_and_publishes_once() {
    let mut k=machine();let(a,inputs,bytes)=setup(&mut k);
    let owner=a.owner;let token=a.output;let agent=a.agent;
    let auth=RebuildPublicationAuthority::provision();
    let mut flow=k.begin_compiler_publication_flow(a,&inputs,
        RebuildAdmissionRole::RelocatableModule,0,Some(&auth)).unwrap();
    let mut published=None;
    for _ in 0..2000 {
        match k.advance_compiler_publication_flow(&mut flow,2000,Some(&auth)).unwrap() {
            CompilerFlowProgress::Pending=>{},
            CompilerFlowProgress::Published(epoch)=>{published=Some(epoch);break},
            CompilerFlowProgress::Retry(_)=>panic!("adequate probe must not retry"),
        }
    }
    assert_eq!(published,Some(1));assert!(k.fabric.compiler_heap_owner_released(owner));
    assert!(k.fabric.authenticate_heap_token(owner,agent,token).is_err());
    let mut actual=vec![0;bytes.len()];k.read_compiler_publication(1,0,&mut actual).unwrap();
    assert_eq!(actual,bytes);
    assert!(matches!(k.advance_compiler_publication_flow(&mut flow,2000,Some(&auth)),Err(CompilerFlowError::Completed)));
    assert!(matches!(k.cancel_compiler_publication_flow(&mut flow),Err(CompilerFlowError::Completed)));
    assert!(k.compiler_publication_receipt(1).is_some());
}

#[test]
fn c25_flow_cancellation_releases_only_its_owner_and_frozen_storage() {
    let mut k=machine();let(a,inputs,_)=setup(&mut k);let owner=a.owner;
    let auth=RebuildPublicationAuthority::provision();
    let mut flow=k.begin_compiler_publication_flow(a,&inputs,
        RebuildAdmissionRole::RelocatableModule,0,Some(&auth)).unwrap();
    let(b,_,_)=setup(&mut k);let account=k.fabric.scoped_pointers.heap_account(b.owner).unwrap();
    let charge=k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    k.cancel_compiler_publication_flow(&mut flow).unwrap();quiet(&mut k);
    assert!(k.fabric.compiler_heap_owner_released(owner));
    assert!(k.fabric.authenticate_heap_token(b.owner,b.agent,b.output).is_ok());
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(),charge);
    assert_eq!(k.compiler_publication_epoch(),0);
}

#[test]
fn c25_flow_commit_authority_failure_closes_without_publication() {
    let mut k=machine();let(a,inputs,_)=setup(&mut k);let owner=a.owner;
    let auth=RebuildPublicationAuthority::provision();
    let mut flow=k.begin_compiler_publication_flow(a,&inputs,
        RebuildAdmissionRole::RelocatableModule,0,Some(&auth)).unwrap();
    let mut rejected=false;
    for _ in 0..2000 {
        match k.advance_compiler_publication_flow(&mut flow,2000,None) {
            Ok(CompilerFlowProgress::Pending)=>{},
            Err(CompilerFlowError::Publication(PublicationError::Authority))=>{rejected=true;break},
            _=>panic!("must reject missing commit authority"),
        }
    }
    assert!(rejected);quiet(&mut k);
    assert!(k.fabric.compiler_heap_owner_released(owner));
    assert_eq!(k.compiler_publication_epoch(),0);
    let owner=k.compiler_candidate_custodian().unwrap();
    let account=k.fabric.scoped_pointers.heap_account(owner).unwrap();
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(),0);
}

fn finish(k:&mut Kernel,flow:&mut CompilerPublicationFlow,auth:&RebuildPublicationAuthority) -> u64 {
    for _ in 0..2000 {
        match k.advance_compiler_publication_flow(flow,2000,Some(auth)).unwrap() {
            CompilerFlowProgress::Pending=>{},CompilerFlowProgress::Published(e)=>return e,
            CompilerFlowProgress::Retry(_)=>panic!("adequate probe unexpectedly retried"),
        }
    }
    panic!("publication did not complete");
}

#[test]
fn c25_flow_peer_commit_revalidates_epoch_without_overwriting_prior_record() {
    let mut k=machine();let(a,ia,bytes)=setup(&mut k);let(b,ib,_)=setup(&mut k);
    let auth=RebuildPublicationAuthority::provision();
    let mut a=k.begin_compiler_publication_flow(a,&ia,RebuildAdmissionRole::RelocatableModule,0,Some(&auth)).unwrap();
    let mut b=k.begin_compiler_publication_flow(b,&ib,RebuildAdmissionRole::RelocatableModule,0,Some(&auth)).unwrap();
    assert!(matches!(k.advance_compiler_publication_flow(&mut b,2000,Some(&auth)).unwrap(),CompilerFlowProgress::Pending));
    assert_eq!(finish(&mut k,&mut a,&auth),1);assert_eq!(finish(&mut k,&mut b,&auth),2);
    assert_ne!(k.compiler_publication_receipt(1).unwrap().object,k.compiler_publication_receipt(2).unwrap().object);
    for epoch in [1,2] {let mut actual=vec![0;bytes.len()];k.read_compiler_publication(epoch,0,&mut actual).unwrap();assert_eq!(actual,bytes);}
}

#[test]
fn c25_flow_epoch_refresh_cannot_hide_changed_provenance_or_missing_authority() {
    for revoke in [false,true] {
        let mut k=machine();let(a,ia,bytes)=setup(&mut k);let(b,ib,_)=setup(&mut k);
        let auth=RebuildPublicationAuthority::provision();
        let mut a=k.begin_compiler_publication_flow(a,&ia,RebuildAdmissionRole::RelocatableModule,0,Some(&auth)).unwrap();
        let mut b=k.begin_compiler_publication_flow(b,&ib,RebuildAdmissionRole::RelocatableModule,0,Some(&auth)).unwrap();
        assert_eq!(finish(&mut k,&mut a,&auth),1);
        if !revoke {let at=k.fabric.translate(ib.source.object,0).unwrap();k.fabric.write_physical(at,&[0]);}
        let mut rejected=false;
        for _ in 0..2000 {
            match k.advance_compiler_publication_flow(&mut b,2000,if revoke {None}else{Some(&auth)}) {
                Ok(CompilerFlowProgress::Pending)=>{},
                Err(CompilerFlowError::Publication(e))=>{
                    assert_eq!(e,if revoke {PublicationError::Authority}else{PublicationError::Binding});rejected=true;break},
                _=>panic!("refresh must reject changed evidence or absent authority"),
            }
        }
        assert!(rejected);assert_eq!(k.compiler_publication_epoch(),1);
        let mut actual=vec![0;bytes.len()];k.read_compiler_publication(1,0,&mut actual).unwrap();assert_eq!(actual,bytes);
    }
}

#[test]
fn c25_flow_capacity_reply_returns_original_budget_only_after_real_cleanup() {
    use super::super::loader::tests::{budget,client_report};
    use crate::anka64::ankald::LinkedArtifactKey;
    use crate::anka64::aom::AOM_MAGIC;
    let mut k=machine();let(unused,mut inputs,_)=setup(&mut k);
    k.finish_process(unused.owner.process.slot,ProcessResult::Exited(0));quiet(&mut k);
    let key=client_report(&mut k,10,1,16384,None);
    let a=k.load_compiler_request(key,budget(10,16384,8),&AOM_MAGIC).unwrap();
    let owner=a.owner;let token=a.output;let agent=a.agent;
    let(_,object,generation,_,_)=k.processes[key.slot].core.compiler_publication_entry(&k.fabric).unwrap();
    inputs.compiler=LinkedArtifactKey {object,generation};
    let custodian=k.compiler_candidate_custodian().unwrap();
    k.fabric.grant(custodian.domain,object,0,k.fabric.objects[&object].size,Permissions::READ).unwrap();
    let auth=RebuildPublicationAuthority::provision();
    let mut flow=k.begin_compiler_publication_flow(a,&inputs,RebuildAdmissionRole::RelocatableModule,0,Some(&auth)).unwrap();
    assert!(matches!(k.advance_compiler_publication_flow(&mut flow,2000,Some(&auth)).unwrap(),CompilerFlowProgress::Pending));
    assert!(!k.fabric.compiler_heap_owner_released(owner));
    let mut retry=None;
    for _ in 0..2000 {
        match k.advance_compiler_publication_flow(&mut flow,2000,Some(&auth)).unwrap() {
            CompilerFlowProgress::Pending=>{},CompilerFlowProgress::Retry(budget)=>{retry=Some(budget);break},
            CompilerFlowProgress::Published(_)=>panic!("capacity reply must not publish"),
        }
    }
    let retry=retry.expect("actual cleanup should release next budget");
    assert!(k.fabric.compiler_heap_owner_released(owner));
    assert!(k.fabric.authenticate_heap_token(owner,agent,token).is_err());
    assert!(retry.context().output_capacity()>16384);assert_eq!(retry.spent_work(),2000);
    assert_eq!(retry.remaining_retries(),2);assert_eq!(retry.context().request_header(0)[4],2);
    assert_eq!(k.compiler_publication_epoch(),0);
    assert!(matches!(k.advance_compiler_publication_flow(&mut flow,2000,Some(&auth)),Err(CompilerFlowError::Completed)));
}
