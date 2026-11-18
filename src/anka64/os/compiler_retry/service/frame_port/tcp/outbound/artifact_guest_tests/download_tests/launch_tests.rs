//! User-run release witness. Bootstrap/compile occurs only before persistence;
//! every subsequent launch uses the exact downloaded stored bytes.
use super::*;
use crate::anka64::os::compiler_retry::publication::consumer::stored_launch::tests::Policy as ExecutePolicy;
#[test]
#[ignore="real CC2 -> typed socket -> NIC DMA -> guarded TCP/file -> fresh live admission; release only"]
fn sr110_live_real_cc2_download_and_launch() {
    let exec=DeveloperExecutionAuthority::provision();let auth=RebuildPublicationAuthority::provision();
    let net=DeveloperFrameAuthority::provision();let input=DeveloperInputAuthority::provision();
    let lineage=cc2_fixed_point::witness_cc2_fixed_point(Some(&exec),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let mut compiler=RebuildService::new(&lineage,&exec).unwrap();
    let source=format!("int main(){{int value=0;{}return value-54;}}","value=value+1;".repeat(96));
    let image_epoch=super::super::super::guest_tests::compile(&mut compiler,source.as_bytes(),&exec,&auth);
    let pump_epoch=super::super::super::guest_tests::compile(&mut compiler,DOWNLOAD,&exec,&auth);
    let temp=Temp::new();let mut backend=store::ArtifactStore::create(&temp.0,10,20,1,limits(),selected()).unwrap();
    let mut export=Policy{manifest:None};
    compiler.kernel.persist_linked_compiler_publication(image_epoch,&mut backend,caller(),91,7,&mut export).unwrap();drop(backend);
    let m=export.manifest.unwrap();let bytes=Arc::new(fs::read(temp.0.join("artifact.bytes")).unwrap());assert!(bytes.len()>8192);
    let record=fs::read(temp.0.join("artifact.record")).unwrap();
    let service=service(store::ArtifactStore::open(&temp.0,10,20,2,limits()).unwrap(),m,&bytes);
    // Remove the original target receipt: launch must depend on downloaded
    // bytes and current stored dependencies, never the old local linked image.
    compiler.kernel.discard_linked_compiler_publication(image_epoch,Some(&auth)).unwrap();
    let mut drained=false;
    for _ in 0..2000 {if !compiler.kernel.advance_heap_cleanup(){drained=true;break;}}
    assert!(drained,"original target cleanup did not drain");
    let (_,account)=compiler.kernel.compiler_candidate_account().unwrap();
    let peer=compiler.kernel.fabric.scoped_pointers.reserve_host_storage(account,4096,
        compiler.kernel.fabric.scoped_pointers.revision()).unwrap();
    let baseline=compiler.kernel.fabric.scoped_pointers.total_reserved_bytes();let epoch=compiler.kernel.compiler_publication_epoch();
    let execution=Mutex::new(ExecutePolicy::new(m,(*bytes).clone(),7));
    let mut first=None;
    // A succeeds; replay and read revocation fail; C succeeds with fresh challenge.
    // Same host Kernel and compiled pump throughout; no later compile/link call.
    for case in 0..4 {
        let verifier=Arc::new(Mutex::new(ReadPolicy::new(m,bytes.clone())));
        let mut factory=Factory{service:&service,attempts:Vec::new(),fault:if case==0{Fault::LostPrefix}else{Fault::None}};
        let view=compiler.kernel.download_stored_compiler_image(pump_epoch,m,&exec,&input,&net,
            verifier.clone(),&mut factory,download_config()).unwrap();
        assert_eq!(view.envelope().unwrap().image(),&bytes[176..]);
        if case==2 {verifier.lock().unwrap().dependencies=false;}
        if case==3 {execution.lock().unwrap().challenge=8;}
        let result=view.launch(&execution,if case==0{0}else{1},DevelopmentRunConfig::default());
        match case {
            0|3=>{
                let report=result.unwrap();assert_eq!(report.execution().child_result,ProcessResult::Exited(42));
                assert!(report.execution().process_slots_observed>=2);
                if case==0 {first=Some(report.id());}else{
                    assert_eq!(report.id().boot,first.unwrap().boot);assert!(report.id().serial>first.unwrap().serial);
                }
                assert_eq!(report.test_kernel().compiler_publication_epoch(),epoch);drop(report);
            },
            _=>{assert!(result.is_err());drop(result);}
        }
        assert_eq!(compiler.kernel.fabric.scoped_pointers.total_reserved_bytes(),baseline);
        assert_eq!(compiler.kernel.compiler_publication_epoch(),epoch);
        assert_eq!(fs::read(temp.0.join("artifact.record")).unwrap(),record);
        assert_eq!(fs::read(temp.0.join("artifact.bytes")).unwrap(),*bytes);
        assert_eq!(service.usage().unwrap().0,0);
    }
    assert_eq!(compiler.kernel.stored_launch_revision(),2);
    assert!(compiler.kernel.linked_compiler_receipt(image_epoch).is_err());
    assert!(compiler.kernel.linked_compiler_receipt(pump_epoch).is_ok());
    compiler.kernel.fabric.scoped_pointers.release_host_storage(peer).unwrap();
    eprintln!("SR110 live: exact stored image exited 42; replay/revoked read denied; peer and durable state unchanged");
}
