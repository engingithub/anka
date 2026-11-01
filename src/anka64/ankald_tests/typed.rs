//! C3/C4: actual AOM v2 admission, guest linker parity and malformed trailers.
use super::*;
use crate::anka64::compiler_adapter::interfaces::*;
use crate::anka64::pointer_frames::ValidatedPointerModule;

fn w(out:&mut Vec<u8>,value:u64) {out.extend(value.to_le_bytes());}
fn name(out:&mut Vec<u8>,s:&str) {let mut b=[0;64];b[..s.len()].copy_from_slice(s.as_bytes());out.extend(b);}
fn reference(out:&mut Vec<u8>,wire:u64,tag:&str) {
    w(out,wire%1000);w(out,wire/1000);name(out,if wire%1000==4 {tag} else {""});
}
/// Test-only serialization. Execution/publication still consumes guest outputs.
fn typed(mut bytes:Vec<u8>,tag:&str,complete:bool,field_name:&str) -> Vec<u8> {
    let parsed=AomModule::parse(&bytes).unwrap();
    let mut trailer=TYPE_MAGIC.to_vec();
    for n in [1,0,1,parsed.symbols.len() as u64] {w(&mut trailer,n);}
    name(&mut trailer,tag);
    for n in if complete {[1,8,8,1,1,0]} else {[0;6]} {w(&mut trailer,n);}
    if complete {name(&mut trailer,field_name);reference(&mut trailer,1,"");w(&mut trailer,0);w(&mut trailer,1);}
    for (i,s) in parsed.symbols.iter().enumerate() {
        name(&mut trailer,&s.name);w(&mut trailer,s.binding);w(&mut trailer,s.parameter_types.len() as u64);
        reference(&mut trailer,s.return_type,tag);
        for j in 0..4 {
            let wire=s.parameter_types.get(j).copied().unwrap_or(0);
            let wire=if wire==1002 {1004} else {wire};
            if wire==0 {trailer.extend([0;80]);} else {reference(&mut trailer,wire,tag);}
            set_word(&mut bytes,parsed.header.symbol_offset as usize+i*160+128+j*8,wire);
        }
    }
    let size=trailer.len() as u64;set_word(&mut trailer,16,size);
    bytes.extend(trailer);let size=bytes.len() as u64;
    set_word(&mut bytes,8,2);set_word(&mut bytes,24,size);bytes
}

#[test]
fn c35_typed_objects_bind_exact_symbols_and_reject_tail_or_downgrade() {
    let fixture=protected_test_modules();
    let bytes=typed(fixture[0].bytes().to_vec(),"Node",true,"value");
    let module=AomModule::parse(&bytes).unwrap();assert!(!module.interface.is_empty());
    ValidatedPointerModule::from_aom(&bytes).unwrap();
    for offset in [8,24,module.header.symbol_offset as usize+160+128] {
        let mut bad=bytes.clone();set_word(&mut bad,offset,1);assert!(AomModule::parse(&bad).is_err());
    }
    let mut bad=bytes.clone();bad.extend([0;8]);let n=bad.len() as u64;set_word(&mut bad,24,n);
    assert!(AomModule::parse(&bad).is_err());
    let start=module.header.relocation_offset as usize+module.relocations.len()*48;
    for offset in [start,start+8,start+16,start+24,start+32,start+40+104] {
        let mut bad=bytes.clone();set_word(&mut bad,offset,u64::MAX);assert!(AomModule::parse(&bad).is_err());
    }
}

#[test]
fn c35_typed_guest_links_opaque_consumer_and_complete_provider() {
    let fixture=protected_test_modules();
    let a=typed(fixture[0].bytes().to_vec(),"Node",false,"");
    let b=typed(fixture[1].bytes().to_vec(),"Node",true,"value");
    let inputs=[ValidatedPointerModule::from_aom(&a).unwrap(),ValidatedPointerModule::from_aom(&b).unwrap()];
    let legacy=crate::anka64::ankald::run_protected_ankald(&ankald_image().bytes,&fixture).unwrap();
    let image=crate::anka64::ankald::run_protected_ankald(&ankald_image().bytes,&inputs).unwrap();
    assert_eq!(image,legacy,"type evidence must not change selected code or frame metadata");
}

#[test]
fn c35_typed_guest_and_host_reject_tag_and_complete_layout_conflicts() {
    let fixture=protected_test_modules();
    let a=typed(fixture[0].bytes().to_vec(),"Node",true,"value");
    for (tag,field) in [("Other","value"),("Node","different")] {
        let b=typed(fixture[1].bytes().to_vec(),tag,true,field);
        let inputs=[ValidatedPointerModule::from_aom(&a).unwrap(),ValidatedPointerModule::from_aom(&b).unwrap()];
        assert!(crate::anka64::ankald::run_protected_ankald(&ankald_image().bytes,&inputs).is_err());
        // Raw transport bypasses the host compatibility precheck and exercises
        // the real guest rejection independently.
        assert!(run_ankald(&ankald_image().bytes,&[&a,&b],"main").is_err());
    }
}

#[test]
fn c35_typed_guest_rejects_malformed_trailer_before_reference_traversal() {
    let fixture=protected_test_modules();
    let a=typed(fixture[0].bytes().to_vec(),"Node",false,"");
    let b=typed(fixture[1].bytes().to_vec(),"Node",true,"value");
    let parsed=AomModule::parse(&b).unwrap();
    let at=parsed.header.relocation_offset as usize+parsed.relocations.len()*48;
    for offset in [at+24,at+32,at+40+88,at+40+112+152] {
        let mut bad=b.clone();set_word(&mut bad,offset,u64::MAX);
        assert!(run_ankald(&ankald_image().bytes,&[&a,&bad],"main").is_err());
    }
}

#[test]
fn c4_large_link_policy_does_not_widen_default_or_producer_admission() {
    let inputs=protected_test_modules();
    // Geometry is accepted for the explicit profile, but no empty linker can
    // execute. A malformed entry remains rejected by result admission.
    assert_eq!(crate::anka64::ankald::run_large_protected_ankald(&[],&inputs),Err(AnkaldError::EmptyLinkerImage));
    assert_eq!(crate::anka64::ankald::run_large_protected_ankald(&[],&[]),Err(AnkaldError::EmptyInput));
}

#[test]
#[ignore = "real guest link/load beyond 1 MiB; run explicitly in release mode"]
fn c4_real_large_application_link_and_load() {
    use crate::anka64::{ankald,dev_runner,dev_shell,isa::Asm64};
    let size=1024*1024+4096usize;
    let mut code:Vec<u8>=std::iter::repeat_n((63u32<<26).to_le_bytes(),size/4).flatten().collect();
    code[..4].copy_from_slice(&(44u32<<26).to_le_bytes());
    // Ordinary C main returns through the explicitly selected CALL launcher.
    // The linker must still validate/copy every byte through the far frame end.
    let mut jump=Asm64::new();jump.movi(0,0);jump.nop();
    code[8..16].copy_from_slice(&jump.to_bytes());
    let branch=(48u32<<26)|(15<<22)|(((size-24-16)/4)as u32);
    code[16..20].copy_from_slice(&branch.to_le_bytes());
    let mut epilogue=Asm64::new();epilogue.punframe();epilogue.nop();epilogue.ret();epilogue.nop();
    code[size-16..].copy_from_slice(&epilogue.to_bytes());
    let metadata:Vec<u8>=[1345400887u64,2,size as u64,1,0,size as u64,16,0]
        .into_iter().flat_map(u64::to_le_bytes).collect();
    let bytes=protected_test_aom(&code,&metadata,&[("main",1,0,&[])],&[]);
    assert!(ValidatedPointerModule::from_aom(&bytes).is_err());
    let module=ValidatedPointerModule::from_aom_with_limit(&bytes,ankald::LARGE_APPLICATION_LIMIT).unwrap();
    assert!(ankald::run_protected_ankald(&[],std::slice::from_ref(&module)).is_err());
    let image=ankald::run_large_protected_ankald(&ankald_image().bytes,&[module]).unwrap();
    assert_eq!(image.code_size,size as u64);assert_eq!(&image.bytes[..size],code);
    let mut fabric=Fabric::with_application_heap(0x1000000).unwrap();
    let mut placement=PhysicalPlacementManager::new(0x10000,0x700000).unwrap();
    let artifact=publish_linked_image(&mut fabric,&mut placement,"large-application",&image).unwrap();
    let mut registry=dev_shell::DevelopmentArtifactRegistry::new();registry.register_linked_application(&fabric,&artifact).unwrap();
    let authority=dev_runner::DeveloperExecutionAuthority::provision();
    let report=dev_runner::run_registered_c_application_with_config(&registry,Some(&authority),&mut fabric,
        &mut placement,"rebuilt-application",dev_runner::DevelopmentRunConfig::default()).unwrap();
    assert_eq!(report.child_result,crate::anka64::os::ProcessResult::Exited(0));
}
