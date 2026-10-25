//! Reuse the existing CC2 fixed-point witness: no second bootstrap per suite.
use super::*;
use crate::anka64::core::Anka64Core;
use crate::anka64::fabric::HeapWorkLimits;
use crate::anka64::isa::Asm64;
use crate::anka64::os::{Kernel, ProcessResult, ProcessState};
use crate::anka64::placement::{PhysicalExtent, VirtualExtent};
use crate::anka64::pointer_frames::ValidatedPointerProgram;
use crate::anka64::scoped_pointers::heap::{AllocationOwner, HeapPlacementLimits, RegistryLimits};
use crate::anka64::source_bundle::SourceBundleMember;
use crate::anka64::state::{AgentId, AgentKind, CoreId, ObjectKind, Permissions, ProcessKey};

fn bundle(source: &[u8]) -> SourceBundle {
    SourceBundle::new(
        "/bin/malloc_probe.c",
        [
            SourceBundleMember::new("/bin/malloc_probe.c", source.to_vec()).unwrap(),
            SourceBundleMember::new(
                "/include/stdlib.h",
                include_bytes!("../../../userspace/include/stdlib.h").to_vec(),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

pub(super) fn check_malloc_free(
    producer: &Cc2FixedPointWitness,
    execution: &DeveloperExecutionAuthority,
    publication: &RebuildPublicationAuthority,
) {
    let mut app = rebuild_protected_application(
        producer,
        &bundle(include_bytes!("../../../userspace/bin/malloc_probe.c")),
        Some(execution),
        Some(publication),
    )
    .unwrap();
    let report = app.run(Some(execution)).unwrap();
    assert_eq!(
        report.child_result,
        ProcessResult::Exited(0),
        "malloc probe output: {:?}",
        report.byte_output
    );
    assert_eq!(report.byte_output, [65, 0, 255, 66]);
    assert_eq!(
        app.fabric.scoped_pointers.total_reserved_bytes(),
        app.fabric.scoped_pointers.fixed_metadata_bytes()
    );
    // Re-run the same immutable publication in a fresh Kernel over the retained
    // Fabric. Cleanup-worker removal must leave the next run usable.
    assert_eq!(
        app.run(Some(execution)).unwrap().child_result,
        ProcessResult::Exited(0)
    );

    // Typed I/O must validate the private heap span and retain binary bytes.
    let source = b"int main(){char *p=malloc(4);int n=read_bytes(p,4);if(n!=4){return syscall(0,1,0,0);}n=write_bytes(p,4);free(p);return syscall(0,n-4,0,0);}";
    let mut io = rebuild_protected_application(
        producer,
        &bundle(source),
        Some(execution),
        Some(publication),
    )
    .unwrap();
    let ingress = crate::anka64::dev_runner::DeveloperInputAuthority::provision();
    let report = io
        .run_with_input(Some(execution), Some(&ingress), &[65, 0, 255, 66])
        .unwrap();
    assert_eq!(report.child_result, ProcessResult::Exited(0));
    assert_eq!(report.byte_output, [65, 0, 255, 66]);

    for (name, source) in [
        (
            "use-after-free",
            b"int main(){char *p=malloc(16);char *q=p;free(p);return syscall(0,*q,0,0);}".as_slice(),
        ),
        (
            "double-free",
            b"int main(){char *p=malloc(16);free(p);free(p);return syscall(0,0,0,0);}".as_slice(),
        ),
        (
            "interior-free",
            b"int main(){char *p=malloc(16);free(p+1);return syscall(0,0,0,0);}".as_slice(),
        ),
        (
            "local-free",
            b"int main(){char p;free(&p);return syscall(0,0,0,0);}".as_slice(),
        ),
        (
            "heap-cell-stale-alias",
            b"int main(){char *p=malloc(16);char **q=malloc(16);*q=p;free(p);p=*q;return syscall(0,0,0,0);}"
                .as_slice(),
        ),
    ] {
        let mut hostile = rebuild_protected_application(
            producer,
            &bundle(source),
            Some(execution),
            Some(publication),
        )
        .unwrap();
        assert_eq!(
            hostile.run(Some(execution)).unwrap().child_result,
            ProcessResult::ProtectionFault,
            "{name}"
        );
        assert_eq!(
            hostile.fabric.scoped_pointers.total_reserved_bytes(),
            hostile.fabric.scoped_pointers.fixed_metadata_bytes(),
            "{name}"
        );
    }
    for source in [
        b"int main(){char *p=1;return syscall(0,0,0,0);}".as_slice(),
        b"int main(){int n=0;free(n);return syscall(0,0,0,0);}".as_slice(),
        b"int main(){void *p=malloc(8);return syscall(0,*p,0,0);}".as_slice(),
    ] {
        assert!(matches!(
            rebuild_protected_application(
                producer,
                &bundle(source),
                Some(execution),
                Some(publication)
            ),
            Err(RebuildError::Compile(
                DevelopmentCompileError::CompilerRejected(9)
            ))
        ));
    }
    check_concurrent_c_clients(producer, execution);
    check_module_heap_return(producer, execution, publication);
    eprintln!(
        "protected malloc/free: C probe + typed I/O + hostile aliases + independent A/B/C reuse passed"
    );
}

fn check_module_heap_return(
    producer: &Cc2FixedPointWitness,
    execution: &DeveloperExecutionAuthority,
    publication: &RebuildPublicationAuthority,
) {
    let mut store = RebuildArtifactStore::new();
    let mut epochs = Vec::new();
    for source in [
        b"char *buffer();int main(){char *p=buffer();int n=0;if(p==0){return syscall(0,1,0,0);}if(*p!=0){return syscall(0,2,0,0);}*p=42;n=write_bytes(p,1);free(p);return syscall(0,n-1,0,0);}".as_slice(),
        b"char *buffer(){return malloc(16);}".as_slice(),
    ] {
        epochs.push(store.compile_module(store.epoch(),producer,&bundle(source),Some(execution),Some(publication)).unwrap());
    }
    let request = store.freeze_modules(&epochs).unwrap();
    let epoch = store
        .link_modules(&request, Some(execution), Some(publication))
        .unwrap();
    let receipt = store.linked_receipt(epoch).unwrap().clone();
    for _ in 0..2 {
        let result = store
            .run_linked_application(&receipt, Some(execution))
            .unwrap();
        assert_eq!(result.child_result, ProcessResult::Exited(0));
        assert_eq!(result.byte_output, [42]);
        assert_eq!(store.linked_receipt(epoch), Some(&receipt));
    }
}

fn compile(
    producer: &Cc2FixedPointWitness,
    execution: &DeveloperExecutionAuthority,
    source: &[u8],
) -> crate::anka64::ankald::AnkaldLinkedImage {
    let (compiler, _, linker) = producer.application_tools().unwrap();
    let aom = crate::anka64::dev_compiler::compile_protected_application_aom_with_linked_compiler(
        compiler, source, execution,
    )
    .unwrap();
    run_ankald(&linker.bytes, &[&aom.bytes], "main").unwrap()
}

// Trusted test loader: exact CC2/ankald output and the ordinary validated frame
// manifest. It neither issues heap pointers nor simulates allocator outcomes.
fn spawn(
    k: &mut Kernel,
    image: &crate::anka64::ankald::AnkaldLinkedImage,
    serial: u64,
) -> ProcessKey {
    assert_eq!(image.entry, 0);
    assert!(image.code_size < 0x10000);
    let code = &image.bytes[..image.code_size as usize];
    let program =
        ValidatedPointerProgram::from_image(code, &image.bytes[image.lit_start as usize..])
            .unwrap()
            .unwrap();
    let domain = k.fabric.create_domain();
    let agent = AgentId(200 + serial);
    k.fabric
        .register_agent(agent, AgentKind::Cpu(CoreId(0)), domain);
    let base = 0x10000 + serial * 0x40000;
    let code_obj =
        k.fabric
            .alloc_object("malloc-client-code", code.len() as u64, ObjectKind::Memory);
    assert!(k.fabric.place_object(code_obj, base));
    k.fabric.write_physical(base, code);
    assert!(k.fabric.seal_object(code_obj));
    k.fabric
        .grant(domain, code_obj, 0, code.len() as u64, Permissions::RX);
    let stack = k
        .fabric
        .alloc_object("malloc-client-stack", 0x10000, ObjectKind::Memory);
    assert!(k.fabric.place_object(stack, base + 0x10000));
    k.fabric.grant(domain, stack, 0, 0x10000, Permissions::RW);
    let mut asm = Asm64::new();
    asm.halt();
    let trap_bytes = asm.to_bytes();
    let trap = k.fabric.alloc_object(
        "malloc-client-trap",
        trap_bytes.len() as u64,
        ObjectKind::Memory,
    );
    assert!(k.fabric.place_object(trap, base + 0x20000));
    k.fabric.write_physical(base + 0x20000, &trap_bytes);
    assert!(k.fabric.seal_object(trap));
    k.fabric
        .grant(domain, trap, 0, trap_bytes.len() as u64, Permissions::RX);
    let mut core = Anka64Core::new(agent, domain);
    core.address_map.add(0, code.len() as u64, code_obj);
    core.address_map.add(0x20000, 0x10000, stack);
    core.address_map.add(0x40000, trap_bytes.len() as u64, trap);
    core.trap_vector = 0x40000;
    core.interrupts_enabled = false;
    core.admit_pointer_program(&mut k.fabric, program, 0, 0x20000, 0x30000)
        .unwrap();
    k.spawn(core)
}

fn owner(k: &Kernel, key: ProcessKey) -> AllocationOwner {
    k.processes[key.slot].core.heap_owner().unwrap()
}

fn check_concurrent_c_clients(
    producer: &Cc2FixedPointWitness,
    execution: &DeveloperExecutionAuthority,
) {
    let a_image=compile(producer,execution,b"int main(){char *p=malloc(8192);char *q=0;int i=0;if(p==0){return syscall(0,1,0,0);}*p=99;*(p+8191)=77;q=malloc(1);if(q!=0){return syscall(0,2,0,0);}while(i<80){i=i+1;}return syscall(0,0,0,0);}");
    let b_image=compile(producer,execution,b"int main(){char *p=malloc(4096);int i=0;if(p==0){return syscall(0,1,0,0);}*p=65;*(p+4095)=255;while(i<1200){i=i+1;}if((*p!=65)|(*(p+4095)!=255)){return syscall(0,2,0,0);}free(p);return syscall(0,0,0,0);}");
    let c_image=compile(producer,execution,b"int main(){char *p=malloc(8192);int i=0;if(p==0){return syscall(0,1,0,0);}while(i<8192){if(*(p+i)!=0){return syscall(0,2,0,0);}i=i+1;}*p=42;free(p);return syscall(0,0,0,0);}");
    let fabric = Fabric::with_private_heap_cpu_work(
        0x1000000,
        RegistryLimits {
            slots: 1024,
            scopes: 1024,
            owners: 8,
            cleanup: 16,
            global_bytes: 0x1000000,
        },
        HeapPlacementLimits {
            physical_pool: PhysicalExtent {
                base: 0x800000,
                size: 0x4000,
            },
            physical_claims: 16,
            virtual_window: VirtualExtent {
                base: 0x40000000,
                size: 0x4000,
            },
            per_owner_claims: 8,
        },
        1,
        HeapWorkLimits {
            tickets: 4,
            requests: 4,
        },
    )
    .unwrap();
    let mut k = Kernel::new(fabric);
    k.enable_heap_service(8192).unwrap();
    let a = spawn(&mut k, &a_image, 0);
    let b = spawn(&mut k, &b_image, 1);
    let mut a_extent = None;
    for _ in 0..20000 {
        k.run(32, 1);
        if let Some(extent) = k.fabric.diagnostic_heap_extents(owner(&k, a)).first() {
            a_extent = Some(*extent);
        }
        if k.processes[a.slot].state != ProcessState::Running {
            break;
        }
    }
    assert_eq!(k.processes[a.slot].result, Some(ProcessResult::Exited(0)));
    assert_eq!(k.processes[b.slot].state, ProcessState::Running);
    let b_extents = k.fabric.diagnostic_heap_extents(owner(&k, b));
    assert_eq!(b_extents.len(), 1);
    while k.advance_heap_cleanup() {}
    assert!(k.fabric.diagnostic_heap_extents(owner(&k, a)).is_empty());
    let c = spawn(&mut k, &c_image, 2);
    for _ in 0..2000 {
        k.run(32, 1);
        if !k.fabric.diagnostic_heap_extents(owner(&k, c)).is_empty() {
            break;
        }
    }
    assert_eq!(
        k.fabric.diagnostic_heap_extents(owner(&k, c)),
        vec![a_extent.expect("A acquired backing")]
    );
    assert_eq!(k.fabric.diagnostic_heap_extents(owner(&k, b)), b_extents);
    k.run(512, 20000);
    assert_eq!(k.processes[b.slot].result, Some(ProcessResult::Exited(0)));
    assert_eq!(k.processes[c.slot].result, Some(ProcessResult::Exited(0)));
    while k.advance_heap_cleanup() {}
    assert_eq!(
        k.fabric.scoped_pointers.total_reserved_bytes(),
        k.fabric.scoped_pointers.fixed_metadata_bytes()
    );
}
