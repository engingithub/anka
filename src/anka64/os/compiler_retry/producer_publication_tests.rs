//! Real guest CC2 integration, reusing the one accepted fixed-point build.
//! Test-owned source/tool ingestion and scheduling are not a user CLI or a
//! claim that all legacy code/stack/host storage has migrated to shared billing.
use super::*;
use super::super::flow::{CompilerFlowProgress,CompilerPublicationFlow};
use super::super::publication::{PublicationInputs,publication_profile};
use crate::anka64::ankald::LinkedArtifactKey;
use crate::anka64::compiler_adapter::{RebuildAdmissionRole,RebuildPublicationAuthority};
use crate::anka64::source_bundle::{SourceBundle,SourceBundleMember,run_ankapp};
use crate::anka64::fabric::HeapWorkLimits;
use crate::anka64::placement::{PhysicalExtent,VirtualExtent};
use crate::anka64::scoped_pointers::heap::{HeapPlacementLimits,RegistryLimits};

// Accounting includes host-side shadow tags and fixed registry/work tables,
// not only guest payload. A 32-MiB pool has 2,097,152 Option<ScopedPointer>
// shadow entries; their actual Rust layout is charged by HeapFabric::footprint.
// Keep room for that storage AND the whole payload pool. Fixture policy only.
const PUBLICATION_POOL_BYTES:u64=0x2000000;
const PUBLICATION_GLOBAL_BYTES:u64=0x20000000;
fn kernel() -> Kernel {
    let fabric=Fabric::with_private_heap_cpu_work(0x4000000,
        RegistryLimits {slots:4096,scopes:4096,owners:64,cleanup:512,global_bytes:PUBLICATION_GLOBAL_BYTES},
        HeapPlacementLimits {
            physical_pool:PhysicalExtent {base:0x1000000,size:PUBLICATION_POOL_BYTES},physical_claims:512,
            virtual_window:VirtualExtent {base:0x40000000,size:PUBLICATION_POOL_BYTES},per_owner_claims:128,
        },1,HeapWorkLimits {tickets:16,requests:16})
        .expect("C2.5c fixture budget must cover fixed registry, shadow and work storage");
    let mut k=Kernel::new(fabric);k.enable_heap_service(0x10000000).unwrap();k
}

/// Cheap preflight: exercise the exact real-producer profile without building
/// CC2. Protect the distinction between guest RAM, heap payload and accounting.
#[test]
fn c25_producer_publication_fixture_accounts_metadata_and_pool() {
    let k=kernel();
    let shadow=(PUBLICATION_POOL_BYTES/16)
        .checked_mul(std::mem::size_of::<Option<ScopedPointer>>() as u64).unwrap();
    let fixed=k.fabric.scoped_pointers.fixed_metadata_bytes();
    assert!(fixed>=shadow,"shadow storage must remain accounted");
    assert!(fixed.checked_add(PUBLICATION_POOL_BYTES).unwrap()<=PUBLICATION_GLOBAL_BYTES,
        "fixture must retain budget for its complete physical payload pool");
    assert!(k.compiler_candidate_custodian().is_ok());
    eprintln!("C2.5c fixture: shadow={shadow} fixed={fixed} payload_pool={PUBLICATION_POOL_BYTES} global_budget={PUBLICATION_GLOBAL_BYTES}");
}

fn admit(k:&mut Kernel,image:&AnkaldLinkedImage,existing:Option<LinkedArtifactKey>)
    -> (ProcessKey,LinkedArtifactKey)
{
    let domain=k.fabric.create_domain();let agent=AgentId(200+k.processes.len() as u64);
    k.fabric.register_agent(agent,AgentKind::Cpu(CoreId(0)),domain);
    let size=(image.code_size+16+4095)&!4095;
    let code=&image.bytes[..image.code_size as usize];
    let compiler=if let Some(key)=existing {
        assert_eq!(k.fabric.objects[&key.object].generation,key.generation);
        let at=k.fabric.translate(key.object,0).unwrap();
        assert_eq!(k.fabric.read_physical(at,image.code_size),code);
        k.fabric.grant(domain,key.object,0,size,Permissions::RX).unwrap();key
    } else {
        let object=k.fabric.alloc_object("c25c-cc2",size,ObjectKind::Memory);
        k.fabric.place_object(object,0x10000);k.fabric.write_physical(0x10000,code);
        install_trap_handler(&mut k.fabric,0x10000,size);seal_code_object(&mut k.fabric,object,domain);
        LinkedArtifactKey {object,generation:k.fabric.objects[&object].generation}
    };
    let custodian=k.compiler_candidate_custodian().unwrap();
    k.fabric.grant(custodian.domain,compiler.object,0,size,Permissions::READ).unwrap();
    let mut core=Anka64Core::new(agent,domain);core.address_map.add(0,size,compiler.object);core.trap_vector=size-16;
    let at=0x100000+k.processes.len() as u64*0x100000;
    assert!(at+0x100000<=0xc00000,"bounded fixture stack arena exhausted");
    let stack=k.fabric.alloc_object("c25c-stack",0x100000,ObjectKind::Memory);
    k.fabric.place_object(stack,at);k.fabric.grant(domain,stack,0,0x100000,Permissions::RW).unwrap();
    core.address_map.add(0x1000000,0x100000,stack);
    let program=ValidatedPointerProgram::from_image(code,&image.bytes[image.lit_start as usize..]).unwrap().unwrap();
    core.admit_pointer_program(&mut k.fabric,program,0,0x1000000,0x1100000).unwrap();
    (k.spawn(core),compiler)
}

fn sealed(k:&mut Kernel,cursor:&mut u64,bytes:&[u8]) -> LinkedArtifactKey {
    assert!(!bytes.is_empty());let size=bytes.len() as u64;
    let at=*cursor;*cursor+=((size+4095)&!4095).max(4096);assert!(*cursor<=0x1000000);
    let object=k.fabric.alloc_object("c25c-provenance",size,ObjectKind::Memory);
    k.fabric.place_object(object,at);assert!(k.fabric.initialize_object(object,0,bytes));assert!(k.fabric.seal_object(object));
    let owner=k.compiler_candidate_custodian().unwrap();k.fabric.grant(owner.domain,object,0,size,Permissions::READ).unwrap();
    LinkedArtifactKey {object,generation:k.fabric.objects[&object].generation}
}

fn bundle(source:&[u8]) -> SourceBundle {
    SourceBundle::new("/job/main.c",[
        SourceBundleMember::new("/job/main.c",b"#include \"/job/body.h\"\n".to_vec()).unwrap(),
        SourceBundleMember::new("/job/body.h",source.to_vec()).unwrap(),
    ]).unwrap()
}
fn bundle_bytes(bundle:&SourceBundle) -> Vec<u8> {
    // Canonical length-delimited root and ordered members, not path names alone.
    fn field(out:&mut Vec<u8>,bytes:&[u8]) {out.extend((bytes.len() as u64).to_le_bytes());out.extend(bytes);}
    let mut out=Vec::new();field(&mut out,bundle.root_name().as_bytes());
    out.extend((bundle.len() as u64).to_le_bytes());
    for m in bundle.members() {field(&mut out,m.logical_name().as_bytes());field(&mut out,m.bytes());}out
}
fn job_budget(job:u64,source:&[u8],capacity:u64) -> OutputRetryBudget {
    OutputRetryPolicy::new(0x100000,8,PRODUCER_WORK_LIMIT).unwrap().start(
        CompilerReplyContext::new(job,1,CompilerResourceBindings {source:21,tools:22,profile:23,dependencies:24,plan:25},
            source.len() as u64,capacity,OutputGrowthSupport::CompilerOutput).unwrap()).unwrap()
}
fn inputs(k:&mut Kernel,cursor:&mut u64,compiler:LinkedArtifactKey,bundle:&SourceBundle,
    source:&[u8],lineage:&Cc2FixedPointWitness,budget:&OutputRetryBudget) -> PublicationInputs
{
    let (cc2,pp,ld)=lineage.application_tools().unwrap();
    let plan:Vec<u8>=budget.publication_plan_words().into_iter().flat_map(u64::to_le_bytes).collect();
    PublicationInputs {bundle:sealed(k,cursor,&bundle_bytes(bundle)),source:sealed(k,cursor,source),compiler,
        preprocessor:sealed(k,cursor,&pp.bytes),linker:sealed(k,cursor,&ld.bytes),
        profile:sealed(k,cursor,&publication_profile()),plan:sealed(k,cursor,&plan),
        dependencies:vec![sealed(k,cursor,&cc2.bytes),sealed(k,cursor,producer::SOURCE)]}
}
fn start(k:&mut Kernel,key:ProcessKey,budget:OutputRetryBudget,source:&[u8],i:&PublicationInputs,
    auth:&RebuildPublicationAuthority) -> (CompilerPublicationFlow,AllocationOwner,ScopedPointer,AgentId) {
    let input=k.ingest_compiler_input(super::super::inputs::CompilerInputRole::EffectiveSource,source).unwrap();
    let loaded=k.load_compiler_request_from_input(key,budget,&input);
    k.discard_compiler_input(&input).unwrap();
    let a=loaded.unwrap();let saved=(a.owner,a.output,a.agent);
    let flow=k.begin_compiler_publication_flow(a,i,RebuildAdmissionRole::RelocatableModule,
        k.compiler_publication_epoch(),Some(auth)).unwrap();(flow,saved.0,saved.1,saved.2)
}
fn finish(k:&mut Kernel,flow:&mut CompilerPublicationFlow,key:ProcessKey,label:&'static str,
    auth:&RebuildPublicationAuthority,lineage:&Cc2FixedPointWitness) -> u64 {
    // The lineage remains immutably borrowed across execution and commit.
    lineage.application_tools().unwrap();
    let mut progress=ProducerProgress::new(label);
    loop {
        let step=k.advance_compiler_publication_flow(flow,PRODUCER_QUANTUM,Some(auth)).unwrap();
        progress.check(k,key,PRODUCER_QUANTUM);assert!(collect_producer_trace(k));
        match step {CompilerFlowProgress::Pending=>{},CompilerFlowProgress::Published(epoch)=>{progress.done();return epoch},
            CompilerFlowProgress::Retry(_)=>panic!("adequate attempt unexpectedly needed another retry")}
    }
}
fn verify(k:&Kernel,epoch:u64,expected:&[u8],source:&[u8],bundle:&SourceBundle,
    lineage:&Cc2FixedPointWitness,producer_owner:AllocationOwner) {
    let r=k.compiler_publication_receipt(epoch).unwrap();let(cc2,pp,ld)=lineage.application_tools().unwrap();
    assert_eq!(r.producer,producer_owner);assert_eq!(r.abi,2);assert_eq!(r.source_offset,0);
    assert_eq!(r.role,RebuildAdmissionRole::RelocatableModule);assert_eq!(r.permissions,Permissions::READ);
    assert_eq!(r.length,expected.len() as u64);assert!(r.heap_generation>0);assert!(!r.admission.is_empty());
    assert_eq!(r.inputs[0].bytes,bundle_bytes(bundle));assert_eq!(r.inputs[1].bytes,source);
    assert_eq!(r.inputs[3].bytes,pp.bytes);assert_eq!(r.inputs[4].bytes,ld.bytes);
    assert_eq!(r.inputs[7].bytes,cc2.bytes);assert_eq!(r.inputs[8].bytes,producer::SOURCE);
    let mut actual=vec![0;expected.len()];for(i,chunk)in actual.chunks_mut(4096).enumerate(){
        k.read_compiler_publication(epoch,(i*4096)as u64,chunk).unwrap();}
    assert_eq!(actual,expected,"published AOM must equal accepted-lineage reference exactly");
}

pub(super) fn check(image:&AnkaldLinkedImage,lineage:&Cc2FixedPointWitness,authority:&DeveloperExecutionAuthority) {
    let small=b"int main(){int x=41;int *p=&x;return *p+1;}";
    let mut large=String::from("int main(){int x=0;");large.push_str(&"x=x+1;".repeat(70));large.push_str("return x;}");
    let ba=bundle(large.as_bytes());let bb=bundle(small);
    let (compiler,pp,_)=lineage.application_tools().unwrap();
    let sa=run_ankapp(&pp.bytes,&ba).unwrap().bytes;let sb=run_ankapp(&pp.bytes,&bb).unwrap().bytes;
    let ra=crate::anka64::dev_compiler::compile_protected_application_aom_with_linked_compiler(compiler,&sa,authority).unwrap().bytes;
    let rb=crate::anka64::dev_compiler::compile_protected_application_aom_with_linked_compiler(compiler,&sb,authority).unwrap().bytes;
    let mut k=kernel();let mut cursor=0xc00000;let auth=RebuildPublicationAuthority::provision();
    let (ka,code)=admit(&mut k,image,None);let (kb,_)=admit(&mut k,image,Some(code));
    let ab=job_budget(71,&sa,4096);let bbgt=job_budget(72,&sb,65536);
    let mut ia=inputs(&mut k,&mut cursor,code,&ba,&sa,lineage,&ab);
    let ib=inputs(&mut k,&mut cursor,code,&bb,&sb,lineage,&bbgt);
    let (mut a,oa,old,aa)=start(&mut k,ka,ab,&sa,&ia,&auth);
    let (mut b,ob,bt,ab_agent)=start(&mut k,kb,bbgt,&sb,&ib,&auth);
    let old_extents=k.fabric.diagnostic_heap_extents(oa);
    let baccount=k.fabric.scoped_pointers.heap_account(ob).unwrap();
    let bcharge=k.fabric.scoped_pointers.account_reserved_bytes(baccount).unwrap();
    let mut progress=ProducerProgress::new("C2.5c concurrent A exhaustion / B progress");
    lineage.application_tools().unwrap();
    let next=loop {
        let step=k.advance_compiler_publication_flow(&mut a,PRODUCER_QUANTUM,Some(&auth)).unwrap();
        // Both clients execute, with deliberately unequal quanta to keep B live
        // across A's real exhaustion and cleanup instead of merely allocating B.
        assert!(matches!(k.advance_compiler_publication_flow(&mut b,1,Some(&auth)).unwrap(),CompilerFlowProgress::Pending));
        progress.check(&k,ka,PRODUCER_QUANTUM);assert!(collect_producer_trace(&mut k));
        match step {CompilerFlowProgress::Pending=>{},CompilerFlowProgress::Retry(next)=>break next,
            CompilerFlowProgress::Published(_)=>panic!("small A arena must exhaust")}
    };progress.done();
    assert!(k.fabric.compiler_heap_owner_released(oa));
    assert!(k.fabric.authenticate_heap_token(oa,aa,old).is_err());
    assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(baccount).unwrap(),bcharge);
    k.fabric.authenticate_heap_token(ob,ab_agent,bt).unwrap();
    assert_eq!(k.processes[kb.slot].state,ProcessState::Running);
    assert!(next.spent_work()>0);assert_eq!(next.remaining_retries(),7);
    let mut next=next;let mut retries=1;
    // Automatic retries consume the exact cleanup-released budget. The fixture
    // admits fresh cores; no source, tool or policy replacement is permitted.
    loop {
        let (kc,_)=admit(&mut k,image,Some(code));
        let plan:Vec<u8>=next.publication_plan_words().into_iter().flat_map(u64::to_le_bytes).collect();
        ia.plan=sealed(&mut k,&mut cursor,&plan);
        let (mut c,oc,_,_)=start(&mut k,kc,next,&sa,&ia,&auth);
        if retries==1 {
            assert!(k.fabric.diagnostic_heap_extents(oc).iter().any(|e|
                old_extents.iter().any(|old|old.base==e.base)),"C must reuse released A backing");
            assert!(k.fabric.authenticate_heap_token(oc,k.processes[kc.slot].core.agent,old).is_err());
        }
        // B completes while C is live. C later refreshes its expected epoch
        // under current authority and provenance, preserving B's publication.
        if retries==1 {
            let eb=finish(&mut k,&mut b,kb,"C2.5c B publication",&auth,lineage);
            assert_eq!(eb,1);verify(&k,eb,&rb,&sb,&bb,lineage,ob);
            // Consume the actual shared-Kernel publication, not a detached AOM
            // copied by this fixture into an unrelated artifact store.
            let reference_module=crate::anka64::pointer_frames::ValidatedPointerModule::from_aom(&rb).unwrap();
            let (_,_,selected_linker)=lineage.application_tools().unwrap();
            let expected_link=crate::anka64::ankald::run_protected_ankald(
                &selected_linker.bytes,&[reference_module]).unwrap();
            let linked_epoch={
                let inputs=k.borrow_compiler_publication_modules(&[eb],
                    crate::anka64::ankald::ApplicationLinkProfile::Standard).unwrap();
                let linked=inputs.link(Some(authority)).unwrap();
                assert_eq!(linked.dependency_epochs(),[eb]);
                assert_eq!(linked.image(),&expected_link);
                linked.publish(eb,Some(&auth)).unwrap()
            };
            assert_eq!(linked_epoch,2);
            let c_account=k.fabric.scoped_pointers.heap_account(oc).unwrap();
            let c_charge=k.fabric.scoped_pointers.account_reserved_bytes(c_account).unwrap();
            let run=k.run_linked_compiler_publication(linked_epoch,Some(authority),
                crate::anka64::dev_runner::DevelopmentRunConfig::default()).unwrap();
            assert_eq!(run.publication_epoch,linked_epoch);
            assert_eq!(run.execution().child_result,ProcessResult::Exited(42));
            assert!(run.execution().process_slots_observed>=2);
            drop(run);
            assert_eq!(k.processes[kc.slot].state,ProcessState::Running);
            assert_eq!(k.fabric.scoped_pointers.account_reserved_bytes(c_account).unwrap(),c_charge);
            assert_eq!(k.linked_compiler_receipt(linked_epoch).unwrap().image,&expected_link);
            eprintln!("C4: shared-Kernel CC2 publication -> guest linker -> READ-only linked receipt -> ordinary spawn/wait exit 42; independent C preserved");
        }
        let mut progress=ProducerProgress::new("C2.5c retry C publication");
        lineage.application_tools().unwrap();
        let outcome=loop {
            let step=k.advance_compiler_publication_flow(&mut c,PRODUCER_QUANTUM,Some(&auth)).unwrap();
            progress.check(&k,kc,PRODUCER_QUANTUM);assert!(collect_producer_trace(&mut k));
            if !matches!(step,CompilerFlowProgress::Pending){break step;}
        };progress.done();
        match outcome {
            CompilerFlowProgress::Retry(budget)=>{next=budget;retries+=1;assert!(retries<=8);},
            CompilerFlowProgress::Published(epoch)=>{
                assert_eq!(epoch,3);verify(&k,epoch,&ra,&sa,&ba,lineage,oc);
                verify(&k,1,&rb,&sb,&bb,lineage,ob);
                break;
            },CompilerFlowProgress::Pending=>unreachable!(),
        }
    }
    // A second adequate capacity publishes byte-identical small-source output.
    let (kd,_)=admit(&mut k,image,Some(code));let db=job_budget(73,&sb,131072);
    let mut id=ib;id.plan=sealed(&mut k,&mut cursor,&db.publication_plan_words().into_iter().flat_map(u64::to_le_bytes).collect::<Vec<_>>());
    let (mut d,od,_,_)=start(&mut k,kd,db,&sb,&id,&auth);
    let ed=finish(&mut k,&mut d,kd,"C2.5c capacity independence",&auth,lineage);
    assert_eq!(ed,4);verify(&k,ed,&rb,&sb,&bb,lineage,od);verify(&k,1,&rb,&sb,&bb,lineage,ob);
    eprintln!("C2.5c publication: real guest preprocessing + accepted CC2 lineage; retries={retries}; A cleanup/C backing reuse, stale A rejection, independent B, exact AOMs and READ-only receipts passed");
    k.stop_heap_service();assert!(k.compiler_publication_receipt(1).is_none());
}

// This profile expands pointer addition into element-size-many PADDs. A large
// pointee type produces real instructions with a small, valid source instead
// of thousands of parsed statements or an artificially padded AOM. Keep the
// struct pointer local: the AOM signature profile excludes struct-pointer
// parameters. Protected mode also excludes struct-valued locals. Only the
// pointer is local; main never calls walk. This is an output/publication test,
// not a claim that null-pointer arithmetic may execute successfully.
fn oversized_source() -> &'static [u8] {
    b"struct Block {int words[1000];};\n\
      int walk(){struct Block *p=0;p=p+0;p=p+0;p=p+0;p=p+0;p=p+0;return 0;}\n\
      int main(){return 0;}\n"
}

/// Dedicated acceptance gate: intentionally separate from the shared p107
/// witness and from fast bridge tests. Run explicitly with --ignored. This is
/// NOT a complete job-accounting or ordinary user-command closure claim.
#[test]
#[ignore = "real oversized CC2 acceptance; run explicitly in release mode"]
fn c26_real_cc2_oversized_publication() {
    let authority = DeveloperExecutionAuthority::provision();
    let lineage = crate::anka64::cc2_fixed_point::witness_cc2_fixed_point(Some(&authority),
        include_bytes!("../../../../userspace/system/compiler/ankacc2_stage3.c"),
        include_bytes!("../../../../userspace/system/compiler/ankapp.c"),
        include_bytes!("../../../../userspace/system/compiler/ankald.c")).unwrap();
    let (compiler, pp, _) = lineage.application_tools().unwrap();
    let source_bundle = bundle(oversized_source());
    let source = run_ankapp(&pp.bytes, &source_bundle).unwrap().bytes;
    // Independent accepted-lineage reference uses the existing bounded 1-MiB
    // guest compilation helper, not host byte generation or output padding.
    let reference = crate::anka64::dev_compiler::compile_protected_producer_aom(
        compiler, &source, &authority).unwrap().bytes;
    assert!(reference.len() > 262144 && reference.len() < 524288,
        "fixture must cross the real 256-KiB boundary: {} bytes", reference.len());
    eprintln!("C2.6 reference: source={} artifact={} bytes", source.len(), reference.len());
    let image = producer::build(&lineage, &authority).unwrap();
    let mut k = kernel();
    let mut cursor = 0xc00000;
    let auth = RebuildPublicationAuthority::provision();
    let (first, code) = admit(&mut k, &image, None);
    let mut budget = job_budget(81, &source, 262144);
    let mut inputs = inputs(&mut k, &mut cursor, code, &source_bundle, &source, &lineage, &budget);
    let mut process = first;
    let mut retries = 0;
    loop {
        let (mut flow, owner, old, agent) = start(&mut k, process, budget, &source, &inputs, &auth);
        let mut progress = ProducerProgress::new("C2.6 oversized retry/publication");
        let outcome = loop {
            let step = k.advance_compiler_publication_flow(&mut flow, PRODUCER_QUANTUM, Some(&auth)).unwrap();
            progress.check(&k, process, PRODUCER_QUANTUM);
            assert!(collect_producer_trace(&mut k));
            if !matches!(step, CompilerFlowProgress::Pending) { break step; }
        };
        progress.done();
        match outcome {
            CompilerFlowProgress::Retry(next) => {
                assert!(k.fabric.compiler_heap_owner_released(owner));
                assert!(k.fabric.authenticate_heap_token(owner, agent, old).is_err());
                assert_eq!(k.compiler_publication_epoch(), 0);
                assert!(next.spent_work() > 0);
                retries += 1;
                assert!(retries <= 8);
                budget = next; // Preserve the actual work/retry ledger.
                inputs.plan = sealed(&mut k, &mut cursor,
                    &budget.publication_plan_words().into_iter().flat_map(u64::to_le_bytes).collect::<Vec<_>>());
                process = admit(&mut k, &image, Some(code)).0;
            }
            CompilerFlowProgress::Published(epoch) => {
                assert!(retries > 0, "262144-byte initial arena must actually fail");
                assert_eq!(epoch, 1);
                verify(&k, epoch, &reference, &source, &source_bundle, &lineage, owner);
                break;
            }
            CompilerFlowProgress::Pending => unreachable!(),
        }
    }
    // A distinct, larger adequate starting capacity must publish identical
    // AOM bytes. Each receipt retains its own real plan and producer identity.
    let second = admit(&mut k, &image, Some(code)).0;
    let direct = job_budget(82, &source, 1048576);
    inputs.plan = sealed(&mut k, &mut cursor,
        &direct.publication_plan_words().into_iter().flat_map(u64::to_le_bytes).collect::<Vec<_>>());
    let (mut flow, owner, _, _) = start(&mut k, second, direct, &source, &inputs, &auth);
    let epoch = finish(&mut k, &mut flow, second, "C2.6 oversized direct publication", &auth, &lineage);
    assert_eq!(epoch, 2);
    verify(&k, epoch, &reference, &source, &source_bundle, &lineage, owner);
    let previous_owner = k.compiler_publication_receipt(1).unwrap().producer;
    verify(&k, 1, &reference, &source, &source_bundle, &lineage, previous_owner);
    eprintln!("C2.6 oversized publication: bytes={} retries={retries}; exact lineage AOM, capacity independence and prior receipt preservation passed", reference.len());
    k.stop_heap_service();
    assert!(k.compiler_publication_receipt(1).is_none());
    assert!(k.compiler_publication_receipt(2).is_none());
}

/// The same Kernel-owned job API used by an admission coordinator. The test
/// supplies trusted process/provenance admission, never reconstructs a retry
/// budget or drives capture/retention/publication internals between attempts.
#[test]
#[ignore = "real compiler job retry/link/run acceptance; run in release mode"]
fn c5_real_compiler_job_retry_publication() {
    use super::super::jobs::CompilerJobProgress;
    let execution=DeveloperExecutionAuthority::provision();
    let lineage=crate::anka64::cc2_fixed_point::witness_cc2_fixed_point(Some(&execution),
        include_bytes!("../../../../userspace/system/compiler/ankacc2_stage3.c"),
        include_bytes!("../../../../userspace/system/compiler/ankapp.c"),
        include_bytes!("../../../../userspace/system/compiler/ankald.c")).unwrap();
    let image=producer::build(&lineage,&execution).unwrap();
    let (compiler,pp,_)=lineage.application_tools().unwrap();
    let mut text=String::from("int main(){int x=0;");text.push_str(&"x=x+1;".repeat(70));text.push_str("return x;}");
    let bundle=bundle(text.as_bytes());let source=run_ankapp(&pp.bytes,&bundle).unwrap().bytes;
    let reference=crate::anka64::dev_compiler::compile_protected_application_aom_with_linked_compiler(
        compiler,&source,&execution).unwrap().bytes;
    let mut k=kernel();let mut cursor=0xc00000;let auth=RebuildPublicationAuthority::provision();
    let code=k.configure_compiler_admission(&image,0x10000,1,Some(&execution)).unwrap();
    let mut process=k.admit_compiler_process(Some(&execution)).unwrap();
    let budget=job_budget(91,&source,4096);
    let input_keys=inputs(&mut k,&mut cursor,code,&bundle,&source,&lineage,&budget);
    let pp_input=k.ingest_compiler_input(super::super::inputs::CompilerInputRole::Tool,&pp.bytes).unwrap();
    let preprocessed=k.preprocess_compiler_source(&pp_input,&bundle,
        crate::anka64::source_bundle::PreprocessGrowthPolicy::new(65536,131072,2,100000000).unwrap(),
        Some(&execution)).unwrap();
    assert_eq!(k.compiler_input(&preprocessed.input,super::super::inputs::CompilerInputRole::EffectiveSource).unwrap(),source);
    let attempt=k.load_compiler_request_from_input(process,budget,&preprocessed.input).unwrap();
    let old=(attempt.owner,attempt.agent,attempt.output);
    let h=k.begin_compiler_job_from_input(attempt,input_keys,&preprocessed.input,Some(&auth)).unwrap();
    k.discard_compiler_input(&preprocessed.input).unwrap();k.discard_compiler_input(&pp_input).unwrap();
    let mut retries=0;
    let epoch=loop {
        let mut progress=ProducerProgress::new("C5 Kernel-owned compiler job");
        let step=loop {
            let step=k.advance_compiler_job(&h,PRODUCER_QUANTUM,Some(&auth)).unwrap();
            progress.check(&k,process,PRODUCER_QUANTUM);assert!(collect_producer_trace(&mut k));
            if step!=CompilerJobProgress::Running {break step;}
        };progress.done();
        match step {
            CompilerJobProgress::NeedsProcess=>{
                retries+=1;assert!(retries<=8);
                assert!(k.fabric.compiler_heap_owner_released(old.0));
                assert!(k.fabric.authenticate_heap_token(old.0,old.1,old.2).is_err());
                let (words,directory)=k.compiler_job_retry_plan(&h).unwrap();
                assert!(words[20]>0,"cumulative work cannot reset");
                let plan:Vec<u8>=words.into_iter().chain(directory.into_iter().flatten())
                    .flat_map(u64::to_le_bytes).collect();
                let plan=sealed(&mut k,&mut cursor,&plan);
                k.retire_admitted_compiler(process).unwrap();
                process=k.admit_compiler_process(Some(&execution)).unwrap();
                k.resume_compiler_job(&h,process,plan,Some(&auth)).unwrap();
            },
            CompilerJobProgress::Published(epoch)=>break epoch,
            other=>panic!("unexpected job state {other:?}"),
        }
    };
    assert!(retries>0);let producer=k.compiler_publication_receipt(epoch).unwrap().producer;
    verify(&k,epoch,&reference,&source,&bundle,&lineage,producer);
    k.cancel_compiler_job(&h).unwrap();assert!(k.compiler_job_status(&h).is_err());
    k.retire_admitted_compiler(process).unwrap();
    // Disposing the job cannot dispose a successfully published artifact.
    let linked={let modules=k.borrow_compiler_publication_modules(&[epoch],
        crate::anka64::ankald::ApplicationLinkProfile::Standard).unwrap();
        modules.link(Some(&execution)).unwrap().publish(epoch,Some(&auth)).unwrap()};
    let run=k.run_linked_compiler_publication(linked,Some(&execution),
        crate::anka64::dev_runner::DevelopmentRunConfig::default()).unwrap();
    assert_eq!(run.execution().child_result,ProcessResult::Exited(70));
    drop(run);
    verify(&k,epoch,&reference,&source,&bundle,&lineage,producer);
    eprintln!("C5 job service: retained source/provenance, retries={retries}, exact AOM, guest link, receipt, C startup and exit 70 passed");
    k.stop_heap_service();
}
