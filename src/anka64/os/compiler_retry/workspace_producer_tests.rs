//! Explicit real-guest acceptance; excluded from fast component runs.
use super::*;
use crate::anka64::compiler_adapter::resources::growth::workspace::WorkspaceDirectory;

#[test]
#[ignore = "real CC2 directory acceptance; run explicitly in release mode"]
fn c31_real_workspace_compiler() {
    let authority=DeveloperExecutionAuthority::provision();
    let lineage=crate::anka64::cc2_fixed_point::witness_cc2_fixed_point(Some(&authority),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let image=producer::build(&lineage,&authority).unwrap();
    let a=WorkspaceDirectory::new([128,256,64,64,16,128,128],1<<20).unwrap();
    let b=WorkspaceDirectory::new([256,512,128,128,16,256,256],1<<20).unwrap();
    let small=b"int main(){return 42;}";
    let (old,expected)=observe("legacy workspace",&image,small,262144);
    assert!(matches!(old,CompilerReplyMetadata::SuccessMetadata{..}));
    let (report,actual)=observe_workspace("directory workspace",&image,small,262144,Some(a));
    assert!(matches!(report,CompilerReplyMetadata::SuccessMetadata{..}));assert_eq!(actual,expected);
    let mut source=String::from("int main(){return 0;}");
    for i in 0..65 {source.push_str(&format!("int f{i}(){{return {i};}}"));}
    let (old,bytes)=observe("legacy 66 functions rejected",&image,source.as_bytes(),262144);
    assert!(matches!(old,CompilerReplyMetadata::RepresentationRejected{diagnostic:8,..}));assert!(bytes.is_empty());
    let (r1,first)=observe_workspace("directory 66 functions",&image,source.as_bytes(),262144,Some(a));
    let (r2,second)=observe_workspace("directory independent capacity",&image,source.as_bytes(),262144,Some(b));
    assert!(matches!(r1,CompilerReplyMetadata::SuccessMetadata{..}));
    assert!(matches!(r2,CompilerReplyMetadata::SuccessMetadata{..}));assert_eq!(first,second);
    let module=crate::anka64::aom::AomModule::parse(&first).unwrap();assert_eq!(module.symbols.len(),66);
    let mut locals=String::from("int main(){");
    for i in 0..40 {locals.push_str(&format!("int v{i}={i};"));}
    locals.push_str("return v39;}");
    let (report,bytes)=observe_workspace("directory 40 locals",&image,locals.as_bytes(),262144,Some(a));
    assert!(matches!(report,CompilerReplyMetadata::SuccessMetadata{..}));assert!(!bytes.is_empty());
    eprintln!("C3.1 guest CC2: legacy parity, 66 functions/frames, capacity independence and 40 locals passed");
}

#[test]
#[ignore = "real guest preprocessing and CC2 source-growth acceptance; run in release mode"]
fn c32_real_source_growth_compiler() {
    use crate::anka64::source_bundle::{SourceBundle,SourceBundleMember,run_ankapp_growing,
        PreprocessGrowthPolicy,AnkaPreprocessError};
    let authority=DeveloperExecutionAuthority::provision();
    eprintln!("C3.2: building accepted lineage and protected producer");
    let lineage=crate::anka64::cc2_fixed_point::witness_cc2_fixed_point(Some(&authority),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let image=producer::build(&lineage,&authority).unwrap();
    let (_,preprocessor,_)=lineage.application_tools().unwrap();
    let body=b"int main(){return 42;}";
    let bundle=SourceBundle::new("main.c",[
        SourceBundleMember::new("pad.h",vec![b' ';70001]).unwrap(),
        SourceBundleMember::new("main.c",b"#include \"pad.h\"\nint main(){return 42;}".to_vec()).unwrap(),
    ]).unwrap();
    eprintln!("C3.2: real ankapp 64-KiB capacity retry then 128-KiB completion");
    let grown=run_ankapp_growing(&preprocessor.bytes,&bundle,
        PreprocessGrowthPolicy::new(65536,131072,2,1000000000).unwrap()).unwrap();
    assert_eq!(grown.attempts,2);assert_eq!(grown.output_capacity,131072);
    assert_eq!(grown.source.process_slots_observed,1);
    let mut expected=vec![b' ';70001];expected.push(b'\n');expected.extend_from_slice(body);
    assert_eq!(grown.source.bytes,expected);
    eprintln!("C3.2: real ankapp adequate capacity, same effective source");
    let direct=run_ankapp_growing(&preprocessor.bytes,&bundle,
        PreprocessGrowthPolicy::new(131072,131072,1,1000000000).unwrap()).unwrap();
    assert_eq!(direct.attempts,1);assert_eq!(direct.source,grown.source);
    assert!(grown.dispatched_budget>direct.dispatched_budget);
    let missing=SourceBundle::new("main.c",[
        SourceBundleMember::new("main.c",b"#include \"absent.h\"\n".to_vec()).unwrap()]).unwrap();
    assert_eq!(run_ankapp_growing(&preprocessor.bytes,&missing,
        PreprocessGrowthPolicy::new(4096,131072,2,1000000000).unwrap()),
        Err(AnkaPreprocessError::PreprocessorRejected(2)));
    assert_eq!(run_ankapp_growing(&preprocessor.bytes,&missing,
        PreprocessGrowthPolicy::new(4096,131072,2,1).unwrap()),Err(AnkaPreprocessError::WorkExhausted));
    let d=WorkspaceDirectory::new([128,256,64,64,16,128,128],1<<20).unwrap();
    let (small,reference)=observe_workspace("C3.2 small reference",&image,body,262144,Some(d));
    let mixed=b" \t\r\n\x0b\x0cint main(){return 42;} \t";
    let (mixed_report,mixed_aom)=observe_workspace("C3.2 mixed whitespace",&image,mixed,262144,Some(d));
    assert!(matches!(mixed_report,CompilerReplyMetadata::SuccessMetadata{..}));
    assert_eq!(mixed_aom,reference);
    let (report,actual)=observe_workspace("C3.2 source beyond 64 KiB",&image,&grown.source.bytes,262144,Some(d));
    assert!(matches!(small,CompilerReplyMetadata::SuccessMetadata{..}));
    assert!(matches!(report,CompilerReplyMetadata::SuccessMetadata{..}));assert_eq!(actual,reference);
    eprintln!("C3.2: guest include expansion, capacity retry, exact source, finite work and >64-KiB protected CC2 passed");
}

#[test]
#[ignore = "real CC2 forward/recursive struct acceptance; run explicitly in release mode"]
fn c33_real_recursive_struct_declarations() {
    let authority=DeveloperExecutionAuthority::provision();
    let lineage=crate::anka64::cc2_fixed_point::witness_cc2_fixed_point(Some(&authority),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let image=producer::build(&lineage,&authority).unwrap();
    let a=WorkspaceDirectory::new([128,256,64,64,16,128,128],1<<20).unwrap();
    let b=WorkspaceDirectory::new([256,512,128,128,16,256,256],1<<20).unwrap();
    // Forward declarations change neither emitted pointer code nor authority.
    let implicit=b"struct A{struct B *b;};struct B{struct A *a;};int main(){struct A *p=0;return p==0;}";
    let explicit=b"struct A;struct B;struct A;struct A{struct B *b;};struct B{struct A *a;};int main(){struct A *p=0;return p==0;}";
    let (r,expected)=observe_workspace("C3.3 implicit mutual pointers",&image,implicit,262144,Some(a));
    assert!(matches!(r,CompilerReplyMetadata::SuccessMetadata{..}));
    for directory in [None,Some(a),Some(b)] {
        let (r,actual)=observe_workspace("C3.3 explicit forward parity",&image,explicit,262144,directory);
        assert!(matches!(r,CompilerReplyMetadata::SuccessMetadata{..}));
        assert_eq!(actual,expected);
    }
    for source in [
        "struct Node{int value;struct Node *next;};int main(){struct Node *p=0;return p==0;}",
        "struct A;struct X{int x;};struct A{int a;};int main(){struct A *p=0;p=p+1;return p==0;}",
        "struct A;int main(){struct A *p=0;return p==0;}",
        "struct A{int a;};struct A;struct B{struct A a;};int main(){return 0;}",
    ] {
        let (r,bytes)=observe_workspace("C3.3 supported declaration",&image,source.as_bytes(),262144,Some(a));
        assert!(matches!(r,CompilerReplyMetadata::SuccessMetadata{..}),"{source}: {r:?}");
        crate::anka64::aom::AomModule::parse(&bytes).unwrap();
    }
    for (source,diagnostic) in [
        ("struct A;struct B{struct A a;};int main(){return 0;}",13),
        ("struct A{int a;struct A a2;};int main(){return 0;}",13),
        ("struct A{int a;};struct A{int b;};int main(){return 0;}",10),
        ("struct A;int main(){struct A *p=0;p=p+1;return 0;}",9),
        ("struct A;int main(){struct A *p=0;return *p;}",9),
        ("struct A{};int main(){return 0;}",13),
    ] {
        let (r,bytes)=observe_workspace("C3.3 incomplete/invalid rejected",&image,source.as_bytes(),262144,Some(a));
        assert!(matches!(r,CompilerReplyMetadata::RepresentationRejected{diagnostic:d,..}
            | CompilerReplyMetadata::SourceRejected{diagnostic:d,..} if d==diagnostic),"{source}: {r:?}");
        assert!(bytes.is_empty());
    }
    eprintln!("C3.3: forward/self/mutual declarations, profile/capacity parity and incomplete-layout rejection passed");
}

#[test]
#[ignore = "real CC2 wide local type encoding; run explicitly in release mode"]
fn c34_real_wide_struct_types() {
    let authority=DeveloperExecutionAuthority::provision();
    let lineage=crate::anka64::cc2_fixed_point::witness_cc2_fixed_point(Some(&authority),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let image=producer::build(&lineage,&authority).unwrap();
    let a=WorkspaceDirectory::new([128,256,64,64,32,128,128],1<<20).unwrap();
    let b=WorkspaceDirectory::new([256,512,128,128,64,256,256],1<<20).unwrap();
    let mut source=String::new();
    for i in 0..17 {source.push_str(&format!("struct S{i}{{int value;struct S{i} *next;}};"));}
    source.push_str("int main(){struct S16 *p=0;p=p+1;return p==0;}");
    let (r,bytes)=observe("C3.4 legacy 17 tags rejected",&image,source.as_bytes(),262144);
    assert!(matches!(r,CompilerReplyMetadata::RepresentationRejected{diagnostic:8,..}));
    assert!(bytes.is_empty());
    let (r,first)=observe_workspace("C3.4 directory 17 tags",&image,source.as_bytes(),262144,Some(a));
    assert!(matches!(r,CompilerReplyMetadata::SuccessMetadata{..}));
    let (r,second)=observe_workspace("C3.4 independent struct capacity",&image,source.as_bytes(),262144,Some(b));
    assert!(matches!(r,CompilerReplyMetadata::SuccessMetadata{..}));assert_eq!(first,second);
    crate::anka64::aom::AomModule::parse(&first).unwrap();
    // AOM v1 is deliberately unchanged: public scalar pointer types still use
    // depth*1000+base, independent of the private compiler's local encoding.
    let signatures=b"int **pass(int **p){return p;}int main(){return 0;}";
    let (r,bytes)=observe_workspace("C3.4 legacy public pointer encoding",&image,signatures,262144,Some(a));
    assert!(matches!(r,CompilerReplyMetadata::SuccessMetadata{..}));
    let module=crate::anka64::aom::AomModule::parse(&bytes).unwrap();
    let pass=module.symbols.iter().find(|s|s.name=="pass").unwrap();
    assert_eq!(pass.return_type,2001);assert_eq!(pass.parameter_types,vec![2001]);
    eprintln!("C3.4: 17 recursive tags, capacity independence, legacy count rejection and unchanged public pointer encoding passed");
}

#[test]
#[ignore = "real typed modules and heap-list execution; run explicitly in release mode"]
fn c35_real_typed_modules_and_heap_list() {
    use crate::anka64::{ankald,dev_runner,dev_shell,placement,pointer_frames};
    fn execute(linker:&[u8],modules:&[pointer_frames::ValidatedPointerModule],authority:&DeveloperExecutionAuthority)
        -> crate::anka64::os::ProcessResult {
        let image=ankald::run_protected_ankald(linker,modules).unwrap();
        let mut fabric=Fabric::with_application_heap(0x1000000).unwrap();
        let mut placement=placement::PhysicalPlacementManager::new(0x10000,0x700000).unwrap();
        let artifact=ankald::publish_linked_image(&mut fabric,&mut placement,"typed-list",&image).unwrap();
        let mut registry=dev_shell::DevelopmentArtifactRegistry::new();
        registry.register_linked_application(&fabric,&artifact).unwrap();
        let result=dev_runner::run_registered_artifact(&registry,Some(authority),&mut fabric,
            &mut placement,"rebuilt-application").unwrap();
        result.child_result
    }
    let authority=DeveloperExecutionAuthority::provision();
    let lineage=crate::anka64::cc2_fixed_point::witness_cc2_fixed_point(Some(&authority),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let image=producer::build(&lineage,&authority).unwrap();
    let (_,_,linker)=lineage.application_tools().unwrap();
    let directory=WorkspaceDirectory::new([128,256,64,64,32,128,128],1<<20).unwrap();
    let source=include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/bin/protected_modules/heap_list.c"));
    let provider=include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/bin/protected_modules/heap_list_provider.c"));
    let (r,a)=observe_workspace("C3/C4 list consumer",&image,source,65536,Some(directory));
    assert!(matches!(r,CompilerReplyMetadata::SuccessMetadata{..}));
    let (r,larger)=observe_workspace("C3/C4 capacity parity",&image,source,131072,Some(directory));
    assert!(matches!(r,CompilerReplyMetadata::SuccessMetadata{..}));assert_eq!(a,larger);
    let (r,b)=observe_workspace("C3/C4 list provider",&image,provider,65536,Some(directory));
    assert!(matches!(r,CompilerReplyMetadata::SuccessMetadata{..}));
    let a=pointer_frames::ValidatedPointerModule::from_aom(&a).unwrap();
    let b=pointer_frames::ValidatedPointerModule::from_aom(&b).unwrap();
    assert!(!a.module().interface.is_empty());assert!(!b.module().interface.is_empty());
    assert_eq!(execute(&linker.bytes,&[a.clone(),b.clone()],&authority),ProcessResult::Exited(0));
    // Type-compatible link cannot revive an escaped allocation alias.
    let stale=b"struct Node{int value;struct Node *next;};int main(){struct Node *p=malloc(sizeof(struct Node));p->value=7;free(p);return syscall(0,p->value,0,0);}";
    let (r,bytes)=observe_workspace("C3/C4 freed member alias",&image,stale,65536,Some(directory));
    assert!(matches!(r,CompilerReplyMetadata::SuccessMetadata{..}));
    let stale=pointer_frames::ValidatedPointerModule::from_aom(&bytes).unwrap();
    assert_eq!(execute(&linker.bytes,&[stale],&authority),ProcessResult::ProtectionFault);
    // Host precheck and independent guest linker both reject full-name/layout
    // substitution despite equal normalized numeric pointer signatures.
    let wrong=String::from_utf8(provider.to_vec()).unwrap().replace("int value;","char value;");
    let (r,bytes)=observe_workspace("C3/C4 incompatible definition",&image,wrong.as_bytes(),65536,Some(directory));
    assert!(matches!(r,CompilerReplyMetadata::SuccessMetadata{..}));
    let wrong=pointer_frames::ValidatedPointerModule::from_aom(&bytes).unwrap();
    assert!(ankald::run_protected_ankald(&linker.bytes,&[a.clone(),wrong.clone()]).is_err());
    assert!(ankald::run_ankald(&linker.bytes,&[a.bytes(),wrong.bytes()],"main").is_err());
    eprintln!("C3/C4: exact capacity parity, typed cross-module heap list, free/stale rejection and independent incompatible-layout rejection passed");
}

#[test]
#[ignore = "real CC2 workspace retry and exact-output parity; run explicitly in release mode"]
fn c3_workspace_retry_real_compiler() {
    use super::super::capture::CompilerCaptureSlice;
    use crate::anka64::compiler_adapter::RebuildAdmissionRole;
    let authority=DeveloperExecutionAuthority::provision();
    let lineage=crate::anka64::cc2_fixed_point::witness_cc2_fixed_point(Some(&authority),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let image=producer::build(&lineage,&authority).unwrap();
    let source=b"int f(){return 41;}int main(){return f()+1;}";
    let directory=WorkspaceDirectory::new([1,16,16,16,16,16,16],1<<20).unwrap();
    let adequate=WorkspaceDirectory::new([8,16,16,16,16,16,16],1<<20).unwrap();
    let (_,expected)=observe_workspace("workspace retry reference",&image,source,65536,Some(adequate));
    let mut next=budget(source,65536);let mut retried=false;
    for index in 0..9 {
        let (mut k,key)=machine(&image);
        // This acceptance harness supplies fresh machines; it does not claim
        // ordinary service admission. The runtime supplies the only retry budget.
        let mut attempt=if index==0 {
            k.load_compiler_request_with_workspace(key,next,source,directory).unwrap()
        } else {k.load_compiler_request(key,next,source).unwrap()};
        let owner=attempt.owner;let old=attempt.output;let agent=attempt.agent;
        let mut progress=ProducerProgress::new("workspace retry actual guest");
        let mut pending=None;let mut candidate=None;
        for _ in 0..PRODUCER_WORK_LIMIT / PRODUCER_QUANTUM as u64 {
            match k.run_compiler_capture_slice(&mut attempt,PRODUCER_QUANTUM,
                RebuildAdmissionRole::RelocatableModule).unwrap() {
                CompilerCaptureSlice::Running=>{},
                CompilerCaptureSlice::AwaitingCleanup(p)=>pending=Some(p),
                CompilerCaptureSlice::Captured(c)=>candidate=Some(c.retain().unwrap()),
            }
            assert!(collect_producer_trace(&mut k));progress.check(&k,key,PRODUCER_QUANTUM);
            if pending.is_some() || candidate.is_some() {break;}
        }
        if let Some(handle)=candidate {
            let mut ready=false;
            for _ in 0..200_000 {if k.poll_compiler_candidate(&handle).unwrap(){ready=true;break;}}
            assert!(ready);assert!(retried);
            assert_eq!(k.compiler_candidate(&handle).unwrap().unwrap().bytes,expected.as_slice());
            k.discard_compiler_candidate(&handle).unwrap();progress.done();
            eprintln!("C3: real table exhaustion -> cleanup -> carried directory retry -> byte-identical AOM");
            return;
        }
        let mut p=pending.expect("bounded guest must complete or request table growth");
        let mut released=None;
        for _ in 0..200_000 {if let Some(b)=k.poll_compiler_retry(&mut p).unwrap(){released=Some(b);break;}}
        next=released.expect("exact owner cleanup must complete");
        assert!(k.fabric.compiler_heap_owner_released(owner));
        assert!(k.fabric.authenticate_heap_token(owner,agent,old).is_err());
        assert_eq!(next.context().output_capacity(),65536);
        assert_eq!(next.workspace_directory().unwrap().words()[1],2);
        assert!(next.spent_work()>0);assert_eq!(next.remaining_retries(),7);
        retried=true;progress.done();
    }
    panic!("workspace growth exceeded bounded attempts");
}
