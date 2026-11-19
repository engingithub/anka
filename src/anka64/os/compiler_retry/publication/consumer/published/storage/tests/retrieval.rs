use super::*;
use crate::anka64::authority_persistence::artifact::retrieval::{RetrievalLimits,RetrievalPolicy,StoredEnvelope};
use std::time::Duration;
fn read_limits()->RetrievalLimits {RetrievalLimits{max_bytes:2*1024*1024,work:20000,timeout:Duration::from_secs(10)}}
struct ReadPolicy {
    manifest:Manifest,bytes:Vec<u8>,valid:bool,inspections:usize,checks:usize,
    deny_after:Option<usize>,dependencies:bool,revoke_after_validate:bool,panic_validate:bool,
}
impl Evidence for ReadPolicy {
    fn authorize(&mut self,s:Scope)->Verdict {
        self.checks+=1;
        if self.valid && s.manifest==self.manifest && s.caller==caller() && s.action==Action::Read
            && !self.deny_after.is_some_and(|n|self.checks>n) {Verdict::Valid}else{Verdict::Invalid}
    }
    fn inspect(&mut self,r:&mut dyn Read)->Result<Manifest,StoreError> {
        self.inspections+=1;let mut chunk=[0u8;4096];let mut offset=0;
        loop {let n=r.read(&mut chunk).map_err(|_|StoreError::CorruptRecord)?;if n==0 {break}
            if self.bytes.get(offset..offset+n)!=Some(&chunk[..n]) {return Err(StoreError::CorruptRecord)}offset+=n;}
        if offset!=self.bytes.len() {return Err(StoreError::CorruptRecord)}Ok(self.manifest)
    }
}
impl RetrievalPolicy for ReadPolicy {
    fn validate_retrieved(&mut self,s:Scope,e:StoredEnvelope<'_>)->Verdict {
        assert_eq!(s.action,Action::Read);
        if self.panic_validate {panic!("injected private retrieval validator failure")}
        if self.revoke_after_validate {self.valid=false;}
        if !self.dependencies || e.manifest()!=self.manifest || e.dependency_count()!=1
            || e.dependency(0).map(|d|(d.anchor,d.installation,d.artifact,d.generation,d.provenance))!=Some((10,20,800,2,804))
            || e.image()!=&self.bytes[176..] {Verdict::Invalid}else{Verdict::Valid}
    }
}
fn exported()->(Kernel,u64,Temp,ArtifactStore,ReadPolicy) {
    let(mut k,_,e)=fixture();let(t,mut s)=store();
    k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut Policy::default()).unwrap();
    let bytes=fs::read(t.0.join("artifact.bytes")).unwrap();let receipt=k.linked_compiler_receipt(e).unwrap();let d=[dependency()];
    let m=Envelope::new(receipt.image,receipt.profile,identity(),&d).unwrap().manifest;
    let p=ReadPolicy{manifest:m,bytes,valid:true,inspections:0,checks:0,deny_after:None,dependencies:true,revoke_after_validate:false,panic_validate:false};
    (k,e,t,s,p)
}
#[test]
fn sr110_kernel_retrieves_actual_cs110_export_with_charge_until_drop() {
    let(mut k,e,_t,mut s,mut p)=exported();let before=charge(&k);let usage=s.usage().unwrap();let expected=k.linked_compiler_receipt(e).unwrap().image.clone();
    {
        let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
        assert!(charge(view.test_kernel())>=before+p.manifest.size+32768);
        let image=view.envelope().unwrap();assert_eq!(image.image(),expected.bytes.as_slice());assert_eq!(image.entry(),expected.entry);
        assert_eq!(image.code_size(),expected.code_size);assert_eq!(image.literal_start(),expected.lit_start);
        assert_eq!(view.test_kernel().compiler_publication_epoch(),e);assert_eq!(p.inspections,1);
    }
    assert_eq!(charge(&k),before);assert_eq!(s.usage().unwrap(),usage);assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn sr110_kernel_quota_denial_precedes_file_or_policy_access() {
    let(mut k,e,_t,mut s,mut p)=exported();let before=charge(&k);let(_,account)=k.compiler_candidate_account().unwrap();
    let filler=k.fabric.scoped_pointers.reserve_host_storage(account,256*1024*1024-before,k.fabric.scoped_pointers.revision()).unwrap();
    assert!(matches!(k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p),Err(CompilerStorageError::Publication(CompilerLinkError::Heap(_)))));
    assert_eq!(p.checks,0);assert_eq!(p.inspections,0);k.fabric.scoped_pointers.release_host_storage(filler).unwrap();
    assert_eq!(charge(&k),before);assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn sr110_kernel_midread_revocation_refunds_only_private_staging() {
    let(mut k,e,t,mut s,mut p)=exported();let before=charge(&k);let head=fs::read(t.0.join("artifact.record")).unwrap();p.deny_after=Some(3);
    assert!(k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).is_err());
    assert_eq!(charge(&k),before);assert_eq!(k.compiler_publication_epoch(),e);assert_eq!(fs::read(t.0.join("artifact.record")).unwrap(),head);
    p.deny_after=None;drop(k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap());assert_eq!(charge(&k),before);
}
#[test]
fn sr110_kernel_independent_dependency_denial_and_final_revocation_refund() {
    let(mut k,e,_t,mut s,mut p)=exported();let before=charge(&k);p.dependencies=false;
    assert!(k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).is_err());assert_eq!(charge(&k),before);
    p.dependencies=true;p.revoke_after_validate=true;
    assert!(k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).is_err());assert_eq!(charge(&k),before);assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn sr110_kernel_validator_unwind_refunds_and_preserves_publication() {
    let(mut k,e,_t,mut s,mut p)=exported();let before=charge(&k);p.panic_validate=true;
    let failed=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p);
    }));assert!(failed.is_err());assert_eq!(charge(&k),before);assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn sr110_kernel_work_exhaustion_then_fresh_retrieval_preserves_peer_charge() {
    let(mut k,e,_t,mut s,mut p)=exported();let(_,account)=k.compiler_candidate_account().unwrap();
    let peer=k.fabric.scoped_pointers.reserve_host_storage(account,4096,k.fabric.scoped_pointers.revision()).unwrap();let before=charge(&k);
    assert!(k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),RetrievalLimits{work:1,..read_limits()},&mut p).is_err());
    assert_eq!(charge(&k),before);drop(k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap());
    assert_eq!(charge(&k),before);assert!(k.linked_compiler_receipt(e).is_ok());k.fabric.scoped_pointers.release_host_storage(peer).unwrap();
}
#[test]
fn sr110_kernel_reopen_reads_same_bytes_without_recompiling() {
    let(mut k,e,t,s,mut p)=exported();drop(s);let mut s=ArtifactStore::open(&t.0,10,20,2,limits()).unwrap();let before=charge(&k);
    let view=k.retrieve_stored_compiler_image(&mut s,p.manifest,caller(),read_limits(),&mut p).unwrap();
    assert_eq!(view.envelope().unwrap().image(),&p.bytes[176..]);drop(view);assert_eq!(charge(&k),before);assert_eq!(k.compiler_publication_epoch(),e);
}

mod launch;

mod restart;
