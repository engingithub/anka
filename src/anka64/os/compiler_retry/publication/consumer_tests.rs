use super::*;
use super::super::tests::{setup_bytes,freeze,retain,ready,publish};
use crate::anka64::os::compiler_retry::tests::{machine,machine_with_owner_limit};
use crate::anka64::os::compiler_retry::capture::tests::{aom,typed_aom};

pub(super) fn published(k:&mut Kernel,bytes:Vec<u8>,linker:Option<LinkedArtifactKey>) -> (u64,PublicationInputs) {
    let(mut attempt,mut inputs,_)=setup_bytes(k,bytes,16384);
    if let Some(key)=linker {inputs.linker=key;}
    freeze(k,&mut attempt,&inputs);
    let candidate=retain(k,&mut attempt);ready(k,&candidate);
    (publish(k,&candidate).unwrap(),inputs)
}
pub(super) fn charge(k:&Kernel)->u64 {
    let owner=k.compiler_candidate_custodian().unwrap();
    let account=k.fabric.scoped_pointers.heap_account(owner).unwrap();
    k.fabric.scoped_pointers.account_reserved_bytes(account).unwrap()
}
#[test]
fn c4_consumer_exact_order_and_typed_bytes_stay_charged_until_drop() {
    let mut k=machine();let a=typed_aom();let b=aom(false,2);
    let(ea,_)=published(&mut k,a.clone(),None);let(eb,_)=published(&mut k,b.clone(),None);
    let held=charge(&k);
    {
        let input=k.borrow_compiler_publication_modules(&[eb,ea],ApplicationLinkProfile::Standard).unwrap();
        assert_eq!(input.epochs,[eb,ea]);assert_eq!(input.modules[0].bytes(),b);
        assert_eq!(input.modules[1].bytes(),a);assert!(charge(input.kernel)>held);
        assert!(!input.modules[1].module().interface.is_empty());
    }
    assert_eq!(charge(&k),held);assert!(k.compiler_publication_receipt(ea).is_some());
    assert!(k.compiler_publication_receipt(eb).is_some());
}
#[test]
fn c4_consumer_rechecks_every_published_dependency_before_staging() {
    for index in 0..9 {
        let mut k=machine();let(epoch,inputs)=published(&mut k,aom(false,1),None);
        let held=charge(&k);let key=inputs.keys().nth(index).unwrap();
        let at=k.fabric.translate(key.object,0).unwrap();let byte=k.fabric.read_physical(at,1)[0];
        k.fabric.write_physical(at,&[byte^1]);
        assert!(k.borrow_compiler_publication_modules(&[epoch],ApplicationLinkProfile::Standard).is_err());
        assert_eq!(charge(&k),held);
        k.fabric.write_physical(at,&[byte]);
        assert!(k.borrow_compiler_publication_modules(&[epoch],ApplicationLinkProfile::Standard).is_ok());
        assert_eq!(charge(&k),held);
    }
}
#[test]
fn c4_consumer_rejects_revoked_tool_and_distinct_linker_bytes() {
    let mut k=machine();let(a,ia)=published(&mut k,aom(false,1),None);
    let(b,_)=published(&mut k,aom(false,2),None);let held=charge(&k);
    // Changing the frozen record simulates an independently valid but different
    // linker selection. A mere equal length must not establish tool identity.
    k.compiler_publications.records.get_mut(&b).unwrap().job.inputs[4].bytes[0]^=1;
    assert!(matches!(k.borrow_compiler_publication_modules(&[a,b],ApplicationLinkProfile::Standard),
        Err(CompilerLinkError::Binding)));
    assert_eq!(charge(&k),held);
    let owner=k.compiler_candidate_custodian().unwrap();
    k.fabric.domains.get_mut(&owner.domain).unwrap().capabilities
        .retain(|cap|cap.cap.object()!=ia.linker.object);
    assert!(k.borrow_compiler_publication_modules(&[a],ApplicationLinkProfile::Standard).is_err());
    assert_eq!(charge(&k),held);
}
#[test]
fn c4_consumer_rejects_role_unknown_epoch_and_dead_custodian() {
    let mut k=machine();let(e,_)=published(&mut k,aom(false,1),None);let held=charge(&k);
    for epochs in [&[][..],&[e+1][..]] {
        assert!(k.borrow_compiler_publication_modules(epochs,ApplicationLinkProfile::Standard).is_err());
    }
    for role in [RebuildAdmissionRole::ClosedTranslationUnit,RebuildAdmissionRole::LinkedImage] {
        k.compiler_publications.records.get_mut(&e).unwrap().job.role=role;
        assert!(k.borrow_compiler_publication_modules(&[e],ApplicationLinkProfile::Standard).is_err());
    }
    assert_eq!(charge(&k),held);
    k.stop_heap_service();
    assert!(k.borrow_compiler_publication_modules(&[e],ApplicationLinkProfile::Standard).is_err());
}
#[test]
fn c4_consumer_quota_failure_preserves_publications_and_peer_charge() {
    let mut k=machine();let(e,_)=published(&mut k,aom(false,1),None);
    let(owner,account)=k.compiler_candidate_account().unwrap();let held=charge(&k);
    let filler=k.fabric.scoped_pointers.reserve_host_storage(account,1024*1024-held,
        k.fabric.scoped_pointers.revision()).unwrap();
    assert!(matches!(k.borrow_compiler_publication_modules(&[e],ApplicationLinkProfile::Standard),
        Err(CompilerLinkError::Heap(_))));
    assert_eq!(charge(&k),1024*1024);
    assert_eq!(k.compiler_candidate_custodian().unwrap(),owner);
    k.fabric.scoped_pointers.release_host_storage(filler).unwrap();
    assert_eq!(charge(&k),held);
    assert!(k.borrow_compiler_publication_modules(&[e],ApplicationLinkProfile::Standard).is_ok());
}
#[test]
fn c4_consumer_link_requires_execution_authority_and_refunds_stage() {
    let mut k=machine();let(e,_)=published(&mut k,aom(false,1),None);let held=charge(&k);
    let input=k.borrow_compiler_publication_modules(&[e],ApplicationLinkProfile::Standard).unwrap();
    assert!(matches!(input.link(None),Err(CompilerLinkError::Authority)));
    assert_eq!(charge(&k),held);assert!(k.compiler_publication_receipt(e).is_some());
}
#[test]
fn c4_consumer_actual_guest_links_kernel_publication_with_capacity_parity() {
    // Transport fixture publishes a valid AOM; guest ankald is real. This is
    // not a replacement for the real CC2 lineage/list acceptance witness.
    let mut k=machine_with_owner_limit(48*1024*1024);
    let linker=&crate::anka64::ankald_tests::ankald_image().bytes;
    let owner=k.compiler_candidate_custodian().unwrap();
    let object=k.fabric.alloc_object("consumer-linker",linker.len() as u64,ObjectKind::Memory);
    k.fabric.place_object(object,0xc0000);
    assert!(k.fabric.initialize_object(object,0,linker));assert!(k.fabric.seal_object(object));
    k.fabric.grant(owner.domain,object,0,linker.len() as u64,Permissions::READ).unwrap();
    let key=LinkedArtifactKey{object,generation:k.fabric.objects[&object].generation};
    let bytes=aom(false,1);let(e,_)=published(&mut k,bytes.clone(),Some(key));
    let held=charge(&k);let authority=DeveloperExecutionAuthority::provision();
    let module=ValidatedPointerModule::from_aom(&bytes).unwrap();
    let expected=ankald::run_protected_ankald(linker,&[module]).unwrap();
    for profile in [ApplicationLinkProfile::Standard,ApplicationLinkProfile::Large] {
        {
            let input=k.borrow_compiler_publication_modules(&[e],profile).unwrap();
            let staging=charge(input.kernel);
            let output=input.link(Some(&authority)).unwrap();
            assert!(output.inputs.transport_reservation.is_none());
            let image_limit=match profile {ApplicationLinkProfile::Standard=>1024*1024,
                ApplicationLinkProfile::Large=>2*1024*1024};
            assert_eq!(charge(output.inputs.kernel),staging+image_limit,
                "machine is destroyed/refunded; exact linked bytes remain charged");
            assert_eq!(output.image(),&expected);assert_eq!(output.profile(),profile);
            assert_eq!(output.dependency_epochs(),[e]);assert!(charge(output.inputs.kernel)>held);
        }
        assert_eq!(charge(&k),held);assert!(k.compiler_publication_receipt(e).is_some());
    }
}

fn charged_tool(k:&mut Kernel,bytes:&[u8])->LinkedArtifactKey {
    let owner=k.compiler_candidate_custodian().unwrap();
    let object=k.fabric.alloc_object("bounded-linker-tool",bytes.len() as u64,ObjectKind::Memory);
    k.fabric.place_object(object,0xc0000);
    assert!(k.fabric.initialize_object(object,0,bytes));assert!(k.fabric.seal_object(object));
    k.fabric.grant(owner.domain,object,0,bytes.len() as u64,Permissions::READ).unwrap();
    LinkedArtifactKey {object,generation:k.fabric.objects[&object].generation}
}
#[test]
fn c2_linker_storage_quota_denial_precedes_guest_and_preserves_peer() {
    // Enough for staging + image, insufficient for the isolated machine.
    let mut k=machine_with_owner_limit(8*1024*1024);
    let mut a=crate::anka64::isa::Asm64::new();a.call(0);a.halt();
    let key=charged_tool(&mut k,&a.to_bytes());
    let(e,_)=published(&mut k,aom(false,1),Some(key));
    let(peer,_)=published(&mut k,aom(false,2),Some(key));
    let held=charge(&k);let epoch=k.compiler_publication_epoch();
    let input=k.borrow_compiler_publication_modules(&[e],ApplicationLinkProfile::Standard).unwrap();
    assert!(matches!(input.link(Some(&DeveloperExecutionAuthority::provision())),
        Err(CompilerLinkError::Heap(HeapError::Capacity(_)))));
    assert_eq!(charge(&k),held);assert_eq!(k.compiler_publication_epoch(),epoch);
    assert!(k.compiler_publication_receipt(peer).is_some());
    assert!(k.compiler_publication_receipt(e).is_some());
}
#[test]
fn c2_linker_storage_forbidden_syscalls_drop_machine_before_refund() {
    use crate::anka64::os::{SYS_SPAWN,SYS_EXEC,SYS_WRITE,SYS_MALLOC,SYS_YIELD};
    for syscall in [SYS_SPAWN,SYS_EXEC,SYS_WRITE,SYS_MALLOC,SYS_YIELD] {
        let mut k=machine_with_owner_limit(48*1024*1024);
        let mut a=crate::anka64::isa::Asm64::new();a.movi(0,syscall as i32);a.trap(0);a.halt();
        let key=charged_tool(&mut k,&a.to_bytes());
        let(e,_)=published(&mut k,aom(false,1),Some(key));let held=charge(&k);
        let objects=k.fabric.objects.len();let processes=k.processes.len();
        let input=k.borrow_compiler_publication_modules(&[e],ApplicationLinkProfile::Standard).unwrap();
        assert!(matches!(input.link(Some(&DeveloperExecutionAuthority::provision())),
            Err(CompilerLinkError::Link(ankald::AnkaldError::LinkerStateChanged))));
        assert_eq!(charge(&k),held);assert_eq!(k.fabric.objects.len(),objects);
        assert_eq!(k.processes.len(),processes);assert!(k.byte_output.is_empty());
        assert!(k.compiler_publication_receipt(e).is_some());
    }
}
#[test]
fn c2_linker_storage_recursive_guest_is_bounded_and_retry_keeps_input() {
    let mut k=machine_with_owner_limit(48*1024*1024);
    let mut a=crate::anka64::isa::Asm64::new();a.call(0);a.halt();
    let key=charged_tool(&mut k,&a.to_bytes());
    let(e,_)=published(&mut k,aom(false,1),Some(key));let held=charge(&k);
    for _ in 0..2 {
        let input=k.borrow_compiler_publication_modules(&[e],ApplicationLinkProfile::Standard).unwrap();
        assert!(matches!(input.link(Some(&DeveloperExecutionAuthority::provision())),
            Err(CompilerLinkError::Link(ankald::AnkaldError::LinkerStateChanged))));
        assert_eq!(charge(&k),held);assert!(k.compiler_publication_receipt(e).is_some());
    }
}
