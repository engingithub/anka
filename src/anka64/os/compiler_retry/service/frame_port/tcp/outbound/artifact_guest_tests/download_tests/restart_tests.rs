//! RR110 real acceptance: compile once, persist pump A and target B, destroy
//! compiler/lineage, then independently restart file service and guest realm.
use super::*;
use crate::anka64::authority_persistence::{DurableRecord,file_backend::FileRecord};
use crate::anka64::os::compiler_retry::publication::consumer::stored_restart::{Authority,RestartGuest,tests::{Policy as BootPolicy,request}};
struct BootstrapExport {manifest:Option<store::Manifest>}
impl CompilerStoragePolicy for BootstrapExport {
    fn bind_link(&mut self,_:&LinkedCompilerReceipt<'_>,c:store::Caller)->Result<PersistentLinkIdentity,ap::Error>{
        if c!=caller(){return Err(ap::Error::Authority)}
        Ok(PersistentLinkIdentity{anchor:10,installation:20,artifact:1900,generation:3,image:1901,metadata:1902,dependencies:1903,provenance:1904})
    }
    fn bind_module(&mut self,r:&CompilerPublicationReceipt<'_>,b:&[u8],i:usize)->Result<PersistentDependency,ap::Error>{
        if i!=0 || r.length!=b.len()as u64{return Err(ap::Error::Authority)}
        Ok(PersistentDependency{anchor:10,installation:20,artifact:800,generation:2,provenance:804})
    }
    fn current_binding(&mut self,m:store::Manifest,d:&[PersistentDependency])->ap::Verdict{
        if m.artifact!=1900 || d!=[PersistentDependency{anchor:10,installation:20,artifact:800,generation:2,provenance:804}]
            || self.manifest.is_some_and(|old|old!=m){return ap::Verdict::Invalid}
        self.manifest=Some(m);ap::Verdict::Valid
    }
    fn authorize(&mut self,s:store::Scope)->ap::Verdict{
        if Some(s.manifest)==self.manifest && s.caller==caller(){ap::Verdict::Valid}else{ap::Verdict::Invalid}
    }
}
#[test]
#[ignore="real CC2 -> persisted bootstrap -> independent guest/service restart -> socket/NIC/file -> T1 launch; release only"]
fn rr110_real_cc2_independent_restart_and_stored_launch(){
    let exec=DeveloperExecutionAuthority::provision();let auth=RebuildPublicationAuthority::provision();
    let net=DeveloperFrameAuthority::provision();let input=DeveloperInputAuthority::provision();
    let lineage=cc2_fixed_point::witness_cc2_fixed_point(Some(&exec),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let mut compiler=RebuildService::new(&lineage,&exec).unwrap();
    let source=format!("int main(){{int value=0;{}return value-54;}}","value=value+1;".repeat(96));
    let target_epoch=super::super::super::guest_tests::compile(&mut compiler,source.as_bytes(),&exec,&auth);
    let pump_epoch=super::super::super::guest_tests::compile(&mut compiler,DOWNLOAD,&exec,&auth);
    let target_dir=Temp::new();let bootstrap_dir=Temp::new();let boot_dir=Temp::new();
    let mut target=store::ArtifactStore::create(&target_dir.0,10,20,1,limits(),selected()).unwrap();
    let mut export=Policy{manifest:None};compiler.kernel.persist_linked_compiler_publication(target_epoch,&mut target,caller(),91,7,&mut export).unwrap();drop(target);
    let m=export.manifest.unwrap();let bytes=Arc::new(fs::read(target_dir.0.join("artifact.bytes")).unwrap());assert!(bytes.len()>8192);
    let mut bootstrap=store::ArtifactStore::create(&bootstrap_dir.0,10,20,1,limits(),selected()).unwrap();
    let mut export=BootstrapExport{manifest:None};compiler.kernel.persist_linked_compiler_publication(pump_epoch,&mut bootstrap,caller(),91,7,&mut export).unwrap();drop(bootstrap);
    let bm=export.manifest.unwrap();let boot_bytes=Arc::new(fs::read(bootstrap_dir.0.join("artifact.bytes")).unwrap());
    let target_record=fs::read(target_dir.0.join("artifact.record")).unwrap();
    let bootstrap_record=fs::read(bootstrap_dir.0.join("artifact.record")).unwrap();
    // No compilation, linking, source/tool provisioning, or receipt restoration
    // is reachable below this boundary. Expected bytes remain ONLY in fixture
    // validators; guest execution reads the persisted file through its adapters.
    drop(compiler);drop(lineage);
    let lane=Arc::new(Mutex::new(Authority::new(BootPolicy::new(bm,boot_bytes.clone(),m,bytes.clone()))));
    let mut record=FileRecord::create(&boot_dir.0,10,20,&ap::State{revision:7,value:bm.artifact,boot:0,last:None}).unwrap();
    let mut r=request(&record.load(10,20).unwrap(),72);
    let outcome=lane.lock().unwrap().reserve(&mut record,r).unwrap();drop(record);
    let mut record=FileRecord::open(&boot_dir.0,10,20).unwrap();
    assert_eq!(lane.lock().unwrap().reserve(&mut record,r).unwrap(),outcome); // lost reply/reopen recovery
    let mut bootstrap=store::ArtifactStore::open(&bootstrap_dir.0,10,20,2,limits()).unwrap();
    let mut guest=Some(RestartGuest::open(&mut record,r,&mut bootstrap,bm,caller(),download_config().limits,lane.clone()).unwrap());
    let mut network=Some(service(store::ArtifactStore::open(&target_dir.0,10,20,2,limits()).unwrap(),m,&bytes));
    let mut previous=guest.as_ref().unwrap().identity();let mut saved_binding=None;let mut retained_peer=None;
    for case in 0..4{
        // 0 initial admitted guest, 1 service-only, 2 guest-only, 3 both.
        if case==1 || case==3 {
            drop(network.take());lane.lock().unwrap().update(|p|p.service+=1);
            network=Some(service(store::ArtifactStore::open(&target_dir.0,10,20,3+case,limits()).unwrap(),m,&bytes));
            if let Some((b,q))=saved_binding{assert_eq!(lane.lock().unwrap().verify_read(b,q),ap::Verdict::Invalid);}
        }
        if case>=2 {
            drop(guest.take());lane.lock().unwrap().update(|p|p.attempt+=1);
            let attempt=lane.lock().unwrap().update(|p|p.attempt);r=request(&record.load(10,20).unwrap(),attempt);
            lane.lock().unwrap().reserve(&mut record,r).unwrap();
            guest=Some(RestartGuest::open(&mut record,r,&mut bootstrap,bm,caller(),download_config().limits,lane.clone()).unwrap());
            let id=guest.as_ref().unwrap().identity();assert_ne!(id.realm,previous.realm);assert_eq!(id.boot,previous.boot+1);
            assert_ne!(id.attempt,previous.attempt);
            if let Some((b,q))=saved_binding{assert_eq!(lane.lock().unwrap().verify_read(b,q),ap::Verdict::Invalid);}
        }else if case==1 {assert_eq!(guest.as_ref().unwrap().identity(),previous);}
        let g=guest.as_mut().unwrap();previous=g.identity();assert_eq!(g.test_kernel().compiler_publication_epoch(),0);
        let k=g.test_kernel();let(_,account)=k.compiler_candidate_account().unwrap();let owner=k.compiler_candidate_custodian().unwrap();
        let (peer,peer_state)=match retained_peer.take(){
            Some(pair)=>pair,
            None=>(k.fabric.scoped_pointers.reserve_host_storage(account,4096,k.fabric.scoped_pointers.revision()).unwrap(),
                k.processes[owner.process.slot].state),
        };
        k.fabric.scoped_pointers.check_host_storage(peer,owner,k.fabric.scoped_pointers.revision()).unwrap();
        assert_eq!(k.processes[owner.process.slot].state,peer_state);
        let baseline=k.fabric.scoped_pointers.total_reserved_bytes();
        let head=record.load(10,20).unwrap();let revision=g.launch_revision();
        lane.lock().unwrap().update(|p|p.challenge+=1);
        let mut factory=Factory{service:network.as_ref().unwrap(),attempts:Vec::new(),fault:if case==0{Fault::LostPrefix}else{Fault::None}};
        let run=g.download_and_launch(m,&input,&net,&mut factory,download_config(),revision,DevelopmentRunConfig::default()).unwrap();
        assert_eq!(run.execution().child_result,ProcessResult::Exited(42));assert_eq!(run.id().boot,previous.realm);drop(run);
        assert!(factory.attempts.len()>=3);assert_eq!(g.launch_revision(),revision+1);
        if let Some((b,q))=saved_binding{assert_eq!(lane.lock().unwrap().verify_read(b,q),ap::Verdict::Invalid);}
        saved_binding=lane.lock().unwrap().test_binding();
        assert_eq!(g.test_kernel().fabric.scoped_pointers.total_reserved_bytes(),baseline);
        assert_eq!(g.test_kernel().processes[owner.process.slot].state,peer_state);
        assert_eq!(g.test_kernel().compiler_publication_epoch(),0);assert_eq!(record.load(10,20).unwrap(),head);
        assert_eq!(fs::read(target_dir.0.join("artifact.record")).unwrap(),target_record);
        assert_eq!(fs::read(target_dir.0.join("artifact.bytes")).unwrap(),*bytes);
        assert_eq!(fs::read(bootstrap_dir.0.join("artifact.record")).unwrap(),bootstrap_record);
        assert_eq!(fs::read(bootstrap_dir.0.join("artifact.bytes")).unwrap(),*boot_bytes);
        assert_eq!(network.as_ref().unwrap().usage().unwrap().0,0);
        // A service change AFTER download invalidates original custody at launch.
        if case==1{
            let view=g.download(m,&input,&net,&mut factory,download_config()).unwrap();
            lane.lock().unwrap().update(|p|p.service+=1);
            assert!(view.launch_shared(&lane,revision+1,DevelopmentRunConfig::default()).is_err());
            assert_eq!(g.launch_revision(),revision+1);assert_eq!(g.test_kernel().fabric.scoped_pointers.total_reserved_bytes(),baseline);
        }
        // Revocation between evidence production and commit must be observed
        // inside the SAME read/execute mutex; it cannot consume admission.
        if case==3{
            lane.lock().unwrap().update(|p|{p.challenge+=1;p.revoke_execute=true;});
            let view=g.download(m,&input,&net,&mut factory,download_config()).unwrap();
            assert!(view.launch_shared(&lane,revision+1,DevelopmentRunConfig::default()).is_err());
            assert_eq!(g.launch_revision(),revision+1);assert_eq!(g.test_kernel().fabric.scoped_pointers.total_reserved_bytes(),baseline);
        }
        // Retain this exact peer charge/state across the service-only restart.
        if case==0{retained_peer=Some((peer,peer_state));}
        else{g.test_kernel().fabric.scoped_pointers.release_host_storage(peer).unwrap();}
        // Finish the deliberately invalidated service from case 1. The next
        // case then restarts ONLY the guest against this surviving replacement.
        drop(factory);
        if case==1{
            drop(network.take());
            network=Some(service(store::ArtifactStore::open(&target_dir.0,10,20,10,limits()).unwrap(),m,&bytes));
        }
    }
    eprintln!("RR110: service-only, guest-only and both-side restart launched retained exit-42 target; no recompilation, stale channels/revoked read denied, boot selection and files preserved");
}
