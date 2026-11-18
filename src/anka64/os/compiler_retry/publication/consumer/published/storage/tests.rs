use super::*;
use super::super::tests::{fixture_bytes,link};
use super::super::super::tests::charge;
use crate::anka64::authority_persistence::artifact::{Action,Limits};
use crate::anka64::os::compiler_retry::capture::tests::aom;
use std::{fs,path::PathBuf,sync::atomic::{AtomicU64,Ordering}};
static SERIAL:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {fn new()->Self {
    Self(std::env::temp_dir().join(format!("anka-cs110-{}-{}-{}",std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),SERIAL.fetch_add(1,Ordering::Relaxed))))
}}
impl Drop for Temp {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn identity()->PersistentLinkIdentity {PersistentLinkIdentity{anchor:10,installation:20,artifact:900,generation:3,image:901,metadata:902,dependencies:903,provenance:904}}
fn dependency()->PersistentDependency {PersistentDependency{anchor:10,installation:20,artifact:800,generation:2,provenance:804}}
fn caller()->Caller {Caller{owner:30,incarnation:4}}
fn limits()->Limits {Limits{max_payload:2*1024*1024,window:257,owner_bytes:4*1024*1024,total_bytes:8*1024*1024,other_bytes:1000,work:20000}}
fn store()->(Temp,ArtifactStore) {
    let t=Temp::new();let s=ArtifactStore::create(&t.0,10,20,1,limits(),Selection{revision:7,artifact:0,generation:0}).unwrap();(t,s)
}
fn fixture()->(Kernel,u64,u64) {
    let(mut k,m)=fixture_bytes(aom(false,1));
    let e=link(&mut k,m).publish(m,Some(&RebuildPublicationAuthority::provision())).unwrap();(k,m,e)
}
struct Policy {valid:bool,foreign:bool,uploads:usize,deny_after:Option<usize>}
impl Default for Policy {fn default()->Self {Self{valid:true,foreign:false,uploads:0,deny_after:None}}}
impl CompilerStoragePolicy for Policy {
    fn bind_link(&mut self,r:&LinkedCompilerReceipt<'_>,c:Caller)->Result<PersistentLinkIdentity,StoreError> {
        if r.role!=RebuildAdmissionRole::LinkedImage || r.permissions!=Permissions::READ || c!=caller() {return Err(StoreError::Authority)}
        Ok(identity())
    }
    fn bind_module(&mut self,r:&CompilerPublicationReceipt<'_>,bytes:&[u8],i:usize)->Result<PersistentDependency,StoreError> {
        if r.length!=bytes.len() as u64 || i!=0 {return Err(StoreError::Authority)}
        let mut d=dependency();if self.foreign {d.installation+=1;}Ok(d)
    }
    fn current_binding(&mut self,m:Manifest,d:&[PersistentDependency])->Verdict {
        if self.valid && m.artifact==identity().artifact && d==[dependency()] {Verdict::Valid}else{Verdict::Invalid}
    }
    fn authorize(&mut self,s:Scope)->Verdict {
        if s.action==Action::Upload {self.uploads+=1;}
        if s.caller!=caller() || self.deny_after.is_some_and(|n|self.uploads>n) {Verdict::Invalid}else{Verdict::Valid}
    }
}
fn word(bytes:&[u8],i:usize)->u64 {u64::from_le_bytes(bytes[8+i*8..16+i*8].try_into().unwrap())}
#[test]
fn cs110_live_publication_streams_exact_geometry_dependencies_and_image() {
    let(mut k,_,e)=fixture();let(t,mut s)=store();let before=charge(&k);let mut p=Policy::default();
    let selection=k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut p).unwrap();
    assert_eq!(selection,Selection{revision:8,artifact:900,generation:3});
    assert_eq!(charge(&k),before);assert_eq!(k.compiler_publication_epoch(),e);
    let bytes=fs::read(t.0.join("artifact.bytes")).unwrap();let receipt=k.linked_compiler_receipt(e).unwrap();
    assert_eq!(&bytes[..8],b"ANKACS01");assert_eq!(word(&bytes,0),1);assert_eq!(word(&bytes,1),2);assert_eq!(word(&bytes,2),1);
    assert_eq!(word(&bytes,7),receipt.image.code_size);assert_eq!(word(&bytes,8),receipt.image.lit_start);
    assert_eq!(word(&bytes,9),receipt.image.entry);assert_eq!(word(&bytes,11),1);
    assert_eq!(&bytes[136+40..],receipt.image.bytes.as_slice());
    assert_eq!(u64::from_le_bytes(bytes[152..160].try_into().unwrap()),800);
    assert_eq!(receipt.permissions,Permissions::READ);
}
#[test]
fn cs110_reopen_exact_retry_keeps_one_effect_and_rejects_changed_request() {
    let(mut k,_,e)=fixture();let(t,mut s)=store();let mut p=Policy::default();
    let first=k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut p).unwrap();
    let usage=s.usage().unwrap();drop(s);
    let mut s=ArtifactStore::open(&t.0,10,20,2,limits()).unwrap();
    assert_eq!(k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut p).unwrap(),first);
    assert!(k.persist_linked_compiler_publication(e,&mut s,caller(),92,7,&mut p).is_err());
    assert_eq!(s.usage().unwrap(),usage);
    p.valid=false;assert!(k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut p).is_err());
}
#[test]
fn cs110_partial_revocation_keeps_stage_charge_and_resumes_exact_prefix() {
    let(mut k,_,e)=fixture();let(t,mut s)=store();let before=charge(&k);
    let mut p=Policy{deny_after:Some(4),..Policy::default()};
    assert!(k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut p).is_err());
    assert_eq!(charge(&k),before);assert!(s.usage().unwrap().candidate>0);
    assert_eq!(fs::metadata(t.0.join("artifact.bytes")).unwrap().len(),257);
    drop(s);let mut s=ArtifactStore::open(&t.0,10,20,2,limits()).unwrap();p.deny_after=None;
    assert_eq!(k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut p).unwrap().revision,8);
    assert_eq!(charge(&k),before);
}
#[test]
fn cs110_default_policy_foreign_mapping_and_module_role_leave_store_empty() {
    struct Deny;impl CompilerStoragePolicy for Deny {}
    let(mut k,m,e)=fixture();let(t,mut s)=store();let before=charge(&k);let usage=s.usage().unwrap();
    assert!(k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut Deny).is_err());
    let mut p=Policy{foreign:true,..Policy::default()};
    assert!(k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut p).is_err());
    assert!(k.persist_linked_compiler_publication(m,&mut s,caller(),91,7,&mut p).is_err());
    assert_eq!(s.usage().unwrap(),usage);assert_eq!(charge(&k),before);assert!(!t.0.join("artifact.bytes").exists());
}
#[test]
fn cs110_changed_heap_image_and_revoked_dependency_reject_before_storage() {
    let(mut k,m,e)=fixture();let(_t,mut s)=store();let before=charge(&k);let usage=s.usage().unwrap();let mut p=Policy::default();
    k.compiler_publications.links.get_mut(&e).unwrap().image.as_mut().unwrap().bytes[8]^=1;
    assert!(k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut p).is_err());
    k.compiler_publications.links.get_mut(&e).unwrap().image.as_mut().unwrap().bytes[8]^=1;
    let key=k.compiler_publications.records[&m].job.inputs[1].key;let owner=k.compiler_candidate_custodian().unwrap();
    k.fabric.domains.get_mut(&owner.domain).unwrap().capabilities.retain(|c|c.cap.object()!=key.object);
    assert!(k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut p).is_err());
    assert_eq!(s.usage().unwrap(),usage);assert_eq!(charge(&k),before);
}
#[test]
fn cs110_store_quota_denial_preserves_live_publication_and_refunds_scratch() {
    let(mut k,_,e)=fixture();let t=Temp::new();let mut l=limits();l.max_payload=1;l.window=1;
    let mut s=ArtifactStore::create(&t.0,10,20,1,l,Selection{revision:7,artifact:0,generation:0}).unwrap();
    let before=charge(&k);let mut p=Policy::default();let usage=s.usage().unwrap();
    assert!(matches!(k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut p),Err(CompilerStorageError::Store(StoreError::Capacity))));
    assert_eq!(s.usage().unwrap(),usage);assert_eq!(charge(&k),before);assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn cs110_validator_rejects_changed_payload_truncation_and_tail() {
    let(mut k,_,e)=fixture();let r=k.linked_compiler_receipt(e).unwrap();let d=[dependency()];
    let envelope=Envelope::new(r.image,r.profile,identity(),&d).unwrap();let mut bytes=vec![0;envelope.manifest.size as usize];
    envelope.copy(0,&mut bytes).unwrap();let mut p=Policy::default();let mut proof=Proof{envelope,policy:&mut p};
    assert!(proof.inspect(&mut &bytes[..]).is_ok());
    bytes[136+40]^=1;assert!(proof.inspect(&mut &bytes[..]).is_err());bytes[136+40]^=1;
    assert!(proof.inspect(&mut &bytes[..bytes.len()-1]).is_err());bytes.push(0);
    assert!(proof.inspect(&mut &bytes[..]).is_err());
}
#[test]
fn cs110_envelope_rejects_geometry_and_namespace_and_encodes_large_profile() {
    let(mut k,_,e)=fixture();let mut image=k.linked_compiler_receipt(e).unwrap().image.clone();let d=[dependency()];
    let envelope=Envelope::new(&image,ApplicationLinkProfile::Large,identity(),&d).unwrap();assert_eq!(envelope.manifest.profile,2);drop(envelope);
    image.entry=image.code_size;assert!(Envelope::new(&image,ApplicationLinkProfile::Standard,identity(),&d).is_err());
    image.entry=0;let mut foreign=d;foreign[0].anchor+=1;
    assert!(Envelope::new(&image,ApplicationLinkProfile::Standard,identity(),&foreign).is_err());
    assert!(Envelope::new(&image,ApplicationLinkProfile::Standard,identity(),&[]).is_err());
}
#[test]
fn cs110_policy_unwind_refunds_export_scratch_without_touching_backend() {
    struct Panic;
    impl CompilerStoragePolicy for Panic {
        fn bind_module(&mut self,_:&CompilerPublicationReceipt<'_>,_:&[u8],_:usize)->Result<PersistentDependency,StoreError> {Ok(dependency())}
        fn bind_link(&mut self,_:&LinkedCompilerReceipt<'_>,_:Caller)->Result<PersistentLinkIdentity,StoreError> {panic!("injected mapping failure")}
    }
    let(mut k,_,e)=fixture();let(_t,mut s)=store();let before=charge(&k);let usage=s.usage().unwrap();
    let failed=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _=k.persist_linked_compiler_publication(e,&mut s,caller(),91,7,&mut Panic);
    }));
    assert!(failed.is_err());assert_eq!(charge(&k),before);assert_eq!(s.usage().unwrap(),usage);
    assert!(k.linked_compiler_receipt(e).is_ok());
}
