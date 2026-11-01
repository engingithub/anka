use super::*;
use super::super::tests::{machine,machine_with_owner_limit};
use crate::anka64::source_bundle::SourceBundleMember;
use crate::anka64::isa::Asm64;
fn bundle()->SourceBundle {SourceBundle::new("main.c",[SourceBundleMember::new("main.c",b"A".to_vec()).unwrap()]).unwrap()}
fn policy()->PreprocessGrowthPolicy {PreprocessGrowthPolicy::new(4096,8192,2,200000).unwrap()}
fn probe(syscall:u64,capacity:bool)->Vec<u8> {
    let mut a=Asm64::new();a.movi(4,65536);a.add(4,4,4);
    a.ld(5,4,32);a.ld(6,4,64);a.movi(7,65);a.st(7,5,0);
    a.movi(7,if capacity {7}else{0});a.st(7,6,0);
    if capacity {a.ld(7,4,40);} else {a.movi(7,1);}
    a.st(7,6,8);a.movi(0,syscall as i32);a.movi(1,if capacity {7}else{0});a.trap(0);a.to_bytes()
}
fn tool(k:&mut Kernel,bytes:&[u8])->CompilerInputHandle {k.ingest_compiler_input(CompilerInputRole::Tool,bytes).unwrap()}
fn held(k:&mut Kernel)->u64 {let(_,a)=k.compiler_candidate_account().unwrap();k.fabric.scoped_pointers.account_reserved_bytes(a).unwrap()}
#[test]
fn c2_preprocess_storage_returns_only_charged_exact_source() {
    let mut k=machine_with_owner_limit(48*1024*1024);let t=tool(&mut k,&probe(SYS_EXIT,false));let before=held(&mut k);
    let r=k.preprocess_compiler_source(&t,&bundle(),policy(),Some(&DeveloperExecutionAuthority::provision())).unwrap();
    assert_eq!(k.compiler_input(&r.input,CompilerInputRole::EffectiveSource).unwrap(),b"A");
    assert_eq!(r.attempts,1);assert_eq!(r.dispatched_budget,100000);assert_eq!(r.output_capacity,4096);
    assert!(held(&mut k)>before);k.discard_compiler_input(&r.input).unwrap();assert_eq!(held(&mut k),before);
}
#[test]
fn c2_preprocess_storage_exit_gate_across_slice_boundary_keeps_syscall_filter() {
    // TRAP just before, on, and after the final instruction of a 256-step slice.
    for trap_index in [254usize,255,256] {
        for syscall in [SYS_EXIT,SYS_WRITE] {
            let body=probe(syscall,false);
            let mut prefix=Asm64::new();
            for _ in 0..(trap_index+1-body.len()/4) {prefix.nop();}
            let mut image=prefix.to_bytes();image.extend_from_slice(&body);
            assert_eq!(image.len()/4-1,trap_index);
            let mut k=machine_with_owner_limit(48*1024*1024);
            let t=tool(&mut k,&image);let before=held(&mut k);
            let result=k.preprocess_compiler_source(&t,&bundle(),policy(),
                Some(&DeveloperExecutionAuthority::provision()));
            if syscall==SYS_EXIT {
                let r=result.unwrap();
                assert_eq!(k.compiler_input(&r.input,CompilerInputRole::EffectiveSource).unwrap(),b"A");
                k.discard_compiler_input(&r.input).unwrap();
            } else {
                assert!(matches!(result,Err(CompilerPreprocessError::Preprocess(
                    AnkaPreprocessError::RestrictedTransport))));
            }
            assert_eq!(held(&mut k),before);
        }
    }
}
#[test]
fn c2_preprocess_storage_quota_denial_precedes_execution() {
    let mut k=machine();let t=tool(&mut k,&probe(SYS_SPAWN,false));let before=held(&mut k);
    assert!(matches!(k.preprocess_compiler_source(&t,&bundle(),policy(),Some(&DeveloperExecutionAuthority::provision())),
        Err(CompilerPreprocessError::Heap(HeapError::Capacity(_)))));
    assert_eq!(held(&mut k),before);
}
#[test]
fn c2_preprocess_storage_forbids_dynamic_syscalls_and_refunds_failure() {
    for syscall in [SYS_SPAWN,SYS_EXEC,SYS_WRITE,SYS_MALLOC,SYS_YIELD] {
        let mut k=machine_with_owner_limit(48*1024*1024);let t=tool(&mut k,&probe(syscall,false));let before=held(&mut k);
        assert!(matches!(k.preprocess_compiler_source(&t,&bundle(),policy(),Some(&DeveloperExecutionAuthority::provision())),
            Err(CompilerPreprocessError::Preprocess(AnkaPreprocessError::RestrictedTransport))));
        assert_eq!(held(&mut k),before);assert_eq!(k.processes.len(),1);
    }
}
#[test]
fn c2_preprocess_storage_bounds_recursive_call_metadata() {
    let mut a=Asm64::new();a.call(0);a.halt(); // return address remains inside the executable map
    let mut k=machine_with_owner_limit(48*1024*1024);let t=tool(&mut k,&a.to_bytes());let before=held(&mut k);
    assert!(matches!(k.preprocess_compiler_source(&t,&bundle(),policy(),Some(&DeveloperExecutionAuthority::provision())),
        Err(CompilerPreprocessError::Preprocess(AnkaPreprocessError::RestrictedTransport))));
    assert_eq!(held(&mut k),before);
}
#[test]
fn c2_preprocess_storage_retries_share_fuel_and_refund_transport() {
    let mut k=machine_with_owner_limit(48*1024*1024);let t=tool(&mut k,&probe(SYS_EXIT,true));let before=held(&mut k);
    assert!(matches!(k.preprocess_compiler_source(&t,&bundle(),policy(),Some(&DeveloperExecutionAuthority::provision())),
        Err(CompilerPreprocessError::Preprocess(AnkaPreprocessError::WorkExhausted))));
    assert_eq!(held(&mut k),before);
}
#[test]
fn c2_preprocess_storage_requires_current_tool_and_authority() {
    let mut k=machine_with_owner_limit(48*1024*1024);let t=tool(&mut k,&probe(SYS_EXIT,false));let before=held(&mut k);
    assert!(matches!(k.preprocess_compiler_source(&t,&bundle(),policy(),None),Err(CompilerPreprocessError::Authority)));
    assert_eq!(held(&mut k),before);k.discard_compiler_input(&t).unwrap();
    assert!(matches!(k.preprocess_compiler_source(&t,&bundle(),policy(),Some(&DeveloperExecutionAuthority::provision())),
        Err(CompilerPreprocessError::Input(_))));
}
#[test]
fn c2_preprocess_storage_rejects_large_member_directory_before_machine() {
    let b=SourceBundle::new("f0",(0..257).map(|i|SourceBundleMember::new(format!("f{i}"),vec![65]).unwrap())).unwrap();
    let mut k=machine_with_owner_limit(48*1024*1024);let t=tool(&mut k,&probe(SYS_EXIT,false));let before=held(&mut k);
    assert!(matches!(k.preprocess_compiler_source(&t,&b,policy(),Some(&DeveloperExecutionAuthority::provision())),
        Err(CompilerPreprocessError::Preprocess(AnkaPreprocessError::StoragePolicy))));
    assert_eq!(held(&mut k),before);
}
#[test]
fn c2_preprocess_storage_preserves_live_peer_and_its_charge() {
    let mut k=machine_with_owner_limit(48*1024*1024);
    let (peer,_,_)=super::super::publication::tests::setup(&mut k);
    let account=k.fabric.scoped_pointers.heap_account(peer.owner).unwrap();
    let charge=k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap();
    let t=tool(&mut k,&probe(SYS_EXIT,false));
    let r=k.preprocess_compiler_source(&t,&bundle(),policy(),Some(&DeveloperExecutionAuthority::provision())).unwrap();
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap(),charge);
    k.fabric.authenticate_heap_token(peer.owner,peer.agent,peer.output).unwrap();
    assert_eq!(k.processes[peer.owner.process.slot].core.pc,0);
    k.discard_compiler_input(&r.input).unwrap();
}
#[test]
#[ignore="real charged ankapp include expansion; run in release mode"]
fn c2_preprocess_storage_real_include_growth() {
    let auth=DeveloperExecutionAuthority::provision();
    let lineage=crate::anka64::cc2_fixed_point::witness_cc2_fixed_point(Some(&auth),
        include_bytes!("../../../../../userspace/system/compiler/ankacc2_stage3.c"),
        include_bytes!("../../../../../userspace/system/compiler/ankapp.c"),
        include_bytes!("../../../../../userspace/system/compiler/ankald.c")).unwrap();
    let (_,pp,_)=lineage.application_tools().unwrap();
    let body=[vec![b' ';70000],b"int main(){return 0;}".to_vec()].concat();
    let b=SourceBundle::new("main.c",[
        SourceBundleMember::new("main.c",b"#include \"body.h\"\n".to_vec()).unwrap(),
        SourceBundleMember::new("body.h",body).unwrap()]).unwrap();
    // Match the accepted C3.2 70-KiB include-growth workload. This is a
    // finite shared instruction budget across both attempts, not a timeout.
    let p=PreprocessGrowthPolicy::new(65536,131072,2,1_000_000_000).unwrap();
    eprintln!("C2 preprocessing: reference include expansion, 64-KiB retry to 128 KiB; shared budget=1000000000");
    let expected=source_bundle::run_ankapp_growing(&pp.bytes,&b,p)
        .expect("legacy reference include growth must fit the established C3.2 budget");
    eprintln!("C2 preprocessing: reference complete; attempts={} dispatched_budget={}; starting accounted path",
        expected.attempts,expected.dispatched_budget);
    let mut k=machine_with_owner_limit(48*1024*1024);let t=tool(&mut k,&pp.bytes);let before=held(&mut k);
    let r=k.preprocess_compiler_source(&t,&b,p,Some(&auth)).unwrap();
    eprintln!("C2 preprocessing: accounted path complete; attempts={} dispatched_budget={}",r.attempts,r.dispatched_budget);
    assert_eq!(r.attempts,2);assert_eq!(r.dispatched_budget,expected.dispatched_budget);
    assert_eq!(k.compiler_input(&r.input,CompilerInputRole::EffectiveSource).unwrap(),expected.source.bytes);
    k.discard_compiler_input(&r.input).unwrap();assert_eq!(held(&mut k),before);
}
