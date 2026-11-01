use super::*;
use crate::anka64::source_bundle::{SourceBundle,SourceBundleMember};
fn bundle(source:&[u8])->SourceBundle {
    SourceBundle::new("main.c",[SourceBundleMember::new("main.c",source.to_vec()).unwrap()]).unwrap()
}
#[test]
fn c5_service_boot_quota_is_retained_and_realms_are_distinct() {
    let (a,_,ia)=realm().unwrap();let (b,_,ib)=realm().unwrap();
    assert_ne!(ia,ib);assert_ne!(ia,0);
    assert!(a.fabric.scoped_pointers.total_reserved_bytes()>=70*1024*1024);
    assert_eq!(a.fabric.scoped_pointers.total_reserved_bytes(),b.fabric.scoped_pointers.total_reserved_bytes());
}
#[test]
fn c5_service_bundle_freezes_exact_names_root_and_bytes() {
    let a=bundle(b"int main(){return 1;}");let b=bundle(b"int main(){return 2;}");
    let x=canonical_bundle(&a).unwrap();assert_ne!(x,canonical_bundle(&b).unwrap());
    assert_eq!(&x[..8],&6u64.to_le_bytes());assert_eq!(&x[8..14],b"main.c");
    assert!(canonical_bundle(&bundle(&vec![0;1048576])).is_err());
}
#[test]
fn c5_service_plan_preserves_retry_and_directory_words() {
    assert_eq!(binding_id(ObjectId(0)).unwrap(),1);
    assert!(binding_id(ObjectId(u64::MAX)).is_err());
    let w=std::array::from_fn(|i|i as u64+1);let d=std::array::from_fn(|i|i as u64+23);
    let (bytes,n)=plan_bytes(w,Some(d));assert_eq!(n,456);
    for (i,c) in bytes.chunks_exact(8).enumerate() {assert_eq!(u64::from_le_bytes(c.try_into().unwrap()),i as u64+1);}
    assert_eq!(plan_bytes(w,None).1,176);
}
#[test]
fn c5_service_provenance_is_sealed_and_cannot_overlap_heap_or_wrap() {
    let (mut k,_held,_)=realm().unwrap();let mut cursor=POOL_START;let mut count=0;
    let key=seal(&mut k,&mut cursor,&mut count,b"immutable").unwrap();
    assert_eq!(k.fabric.objects[&key.object].state,ObjectState::Sealed);
    assert!(!k.fabric.initialize_object(key.object,0,b"overwrite"));
    assert_eq!(k.fabric.read_physical(POOL_START,9),b"immutable");
    let objects=k.fabric.objects.len();
    for at in [0,POOL_START+1,POOL_END,u64::MAX] {
        cursor=at;assert!(allocate(&mut k,&mut cursor,&mut count,1).is_err());
    }
    assert_eq!(k.fabric.objects.len(),objects);
}
#[test]
fn c5_service_provenance_collision_preserves_peer_and_accounts_burned_slot() {
    let (mut k,_held,_)=realm().unwrap();let mut cursor=POOL_START;let mut count=0;
    let peer=seal(&mut k,&mut cursor,&mut count,b"peer").unwrap();
    cursor=POOL_START;assert!(seal(&mut k,&mut cursor,&mut count,b"evil").is_err());
    assert_eq!(k.fabric.read_physical(POOL_START,4),b"peer");
    assert!(k.fabric.objects.contains_key(&peer.object));assert_eq!(count,2);
    cursor=POOL_START+4096;count=MAX_OBJECTS;
    assert!(seal(&mut k,&mut cursor,&mut count,b"x").is_err());
}
fn stack(s:&RebuildService,p:ProcessKey)->(ObjectId,u64) {
    let (o,off)=s.kernel.processes[p.slot].core.address_map.resolve(0x1000000).unwrap();
    (o,s.kernel.fabric.translate(o,off).unwrap())
}
#[test]
#[ignore="real concurrent ordinary service; run explicitly in release mode"]
fn c5_service_real_concurrent_rebuild() {
    let exec=DeveloperExecutionAuthority::provision();let auth=RebuildPublicationAuthority::provision();
    let lineage=cc2_fixed_point::witness_cc2_fixed_point(Some(&exec),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let mut s=RebuildService::new(&lineage,&exec).unwrap();
    let a=s.submit(&bundle(b"int main(){return 0;}"),0x40000,512,&exec,&auth).unwrap();
    let b=s.submit(&bundle(b"int main(){return 42;}"),0x40000,WORK,&exec,&auth).unwrap();
    let aj=s.jobs[a.slot].as_ref().unwrap();let ap=aj.process;let old=aj.old;
    let aheap=s.kernel.fabric.diagnostic_heap_extents(old.0);
    let astack=stack(&s,ap);let bp=s.jobs[b.slot].as_ref().unwrap().process;let bstack=stack(&s,bp);
    assert!(s.submit(&bundle(b"int main(){return 9;}"),0x40000,WORK,&exec,&auth).is_err());
    assert!(s.poll(ServiceJobHandle{realm:s.identity+1,..b},&exec,&auth).is_err());
    // Both actual compiler processes execute; only A has a deliberately tiny ledger.
    assert!(s.poll(b,&exec,&auth).unwrap().is_none());
    let mut exhausted=false;
    for _ in 0..16 {match s.poll(a,&exec,&auth) {Err(e)=>{eprintln!("C5 service A exhausted: {e}");exhausted=true;break;},Ok(None)=>{},Ok(Some(_))=>panic!("A unexpectedly compiled within 512 instructions")}}
    assert!(exhausted);assert!(s.poll(a,&exec,&auth).is_err());
    assert!(s.kernel.fabric.compiler_heap_owner_released(old.0));
    assert!(s.kernel.fabric.authenticate_heap_token(old.0,old.1,old.2).is_err());
    assert_eq!(s.kernel.processes[bp.slot].state,ProcessState::Running);assert_eq!(stack(&s,bp),bstack);
    let c=s.submit(&bundle(b"int main(){return 70;}"),0x40000,WORK,&exec,&auth).unwrap();
    let cj=s.jobs[c.slot].as_ref().unwrap();let cp=cj.process;let fresh=cj.old;
    assert_eq!(cp.slot,ap.slot);assert_ne!(cp.generation,ap.generation);
    let cstack=stack(&s,cp);assert_eq!(cstack.1,astack.1);assert_ne!(cstack.0,astack.0);
    assert!(s.kernel.fabric.authenticate_heap_token(fresh.0,fresh.1,old.2).is_err());
    let cheap=s.kernel.fabric.diagnostic_heap_extents(fresh.0);
    assert!(cheap.iter().any(|c|aheap.iter().any(|a|a.base==c.base)),"C must reuse released A heap backing");
    let start=std::time::Instant::now();let mut last=start;let mut epochs=[None,None];
    while epochs.iter().any(Option::is_none) {
        assert!(start.elapsed().as_secs()<1200,"concurrent service diagnostic timeout");
        for (i,h) in [b,c].into_iter().enumerate() {if epochs[i].is_none() {epochs[i]=s.poll(h,&exec,&auth).unwrap();}}
        if last.elapsed().as_secs()>=5 {eprintln!("C5 ordinary service: B/C active {:.1}s",start.elapsed().as_secs_f64());last=std::time::Instant::now();}
    }
    assert!(s.poll(b,&exec,&auth).is_err());assert!(s.poll(c,&exec,&auth).is_err());
    for (e,exit) in epochs.into_iter().zip([42,70]) {
        let linked=s.link(&[e.unwrap()],&exec,&auth).unwrap();
        assert_eq!(s.run(linked,&exec,|bytes|{assert!(bytes.is_empty());Ok(())}).unwrap(),ProcessResult::Exited(exit));
    }
    assert!(s.kernel.fabric.authenticate_heap_token(old.0,old.1,old.2).is_err());
    eprintln!("C5 ordinary service: concurrent B/C, A exhaustion, same backing reuse, stale aliases, receipts and exits 42/70 passed");
}

#[test]
fn c5_http_source_places_main_before_helpers() {
    // Fixture guard: declarations may precede main, definitions may not.
    // The real guest-link witness checks the emitted entry contract.
    let source=include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/services/net/httpd_protected.c"));
    let first_definition=source.lines().find(|line|line.contains('{')).unwrap();
    assert_eq!(first_definition.trim(),"int main() {");
    for helper in ["getbyte", "putbyte", "reqok", "put200", "put404"] {
        let declaration=source.lines().find(|line|line.starts_with(&format!("int {}(",helper))).unwrap();
        assert!(declaration.ends_with(';'),"helper needs a forward declaration: {}",helper);
    }
}

#[test]
fn c5_http_read_loop_uses_supported_scalar_conjunction() {
    let source=include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/services/net/httpd_protected.c"));
    // CC2 has bitwise &, not C short-circuit &&. Keep both comparisons
    // parenthesized so & receives scalar 0/1 results, never an address.
    assert!(source.contains("while ((used<1024) & (done==0))"));
    assert!(!source.contains("&&") && !source.contains("||"));
    for (used,done,expected) in [(0,0,true),(23,0,true),(23,1,false),(1024,0,false),(1024,1,false)] {
        assert_eq!(((used<1024) as u64 & (done==0) as u64)!=0,expected);
    }
}

#[test]
#[ignore="real protected HTTP ordinary rebuild; run explicitly in release mode"]
fn c5_http_real_protected_application() {
    let exec=DeveloperExecutionAuthority::provision();let auth=RebuildPublicationAuthority::provision();
    let input_auth=dev_runner::DeveloperInputAuthority::provision();
    let lineage=cc2_fixed_point::witness_cc2_fixed_point(Some(&exec),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let mut s=RebuildService::new(&lineage,&exec).unwrap();
    let source=include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/services/net/httpd_protected.c"));
    let h=s.submit(&bundle(source),0x40000,WORK,&exec,&auth).unwrap();
    // Capture the authentic workspace through the actual ABI request. Read it
    // only for diagnostics, through the current heap lifetime checks.
    let job=s.jobs[h.slot].as_ref().unwrap();let (owner,agent,_)=job.old;
    let request=s.kernel.processes[job.process.slot].core.authenticated_pointer(&s.kernel.fabric,R0).unwrap().unwrap();
    let cell=s.kernel.fabric.scoped_pointers.add_heap_pointer(request,owner,288).unwrap();
    let workspace=s.kernel.fabric.load_heap_pointer_cell(owner,agent,cell).unwrap().unwrap();
    let start=std::time::Instant::now();let mut last=start;
    let module=loop {
        assert!(start.elapsed().as_secs()<1200,"HTTP compilation diagnostic timeout");
        if let Some(e)=s.poll(h,&exec,&auth).unwrap(){break e;}
        if last.elapsed().as_secs()>=5 {
            let job=s.jobs[h.slot].as_ref().unwrap();let process=&s.kernel.processes[job.process.slot];
            let (frames,locals)=process.core.diagnostic_frame_usage();
            let mut bytes=[0u8;16];
            let cursor=s.kernel.fabric.read_heap_bytes(owner,agent,workspace,&mut bytes).ok().map(|_|(
                u64::from_le_bytes(bytes[..8].try_into().unwrap()),u64::from_le_bytes(bytes[8..].try_into().unwrap())));
            eprintln!("C5 HTTP compile: {:.1}s polls={} retries={} pc={:#x} state={:?} frames={} live_locals={}/{} source_cursor_and_length={:?}",
                start.elapsed().as_secs_f64(),job.polls,job.retries,process.core.pc,process.state,
                frames,locals,super::super::admission::COMPILER_LOCAL_LIMIT,cursor);
            last=std::time::Instant::now();
        }
    };
    eprintln!("C5 HTTP compile completed in {:.2}s",start.elapsed().as_secs_f64());
    let linked=s.link(&[module],&exec,&auth).unwrap();
    let ok=&b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nAnka64 is alive."[..];
    let missing=&b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..];
    let good=b"GET /alive HTTP/1.1\r\n\r\n".to_vec();
    let mut boundary=b"GET /alive HTTP/1.1\r\n".to_vec();boundary.resize(1020,b'x');boundary.extend_from_slice(b"\r\n\r\n");
    let mut too_large=boundary.clone();too_large.push(b'x');
    let cases=[(good.clone(),0,ok),(b"GET /other HTTP/1.1\r\n\r\n".to_vec(),0,missing),
        (b"GET /alive HTTP/1.1\r\nX: \0\xff\r\n\r\n".to_vec(),0,ok),
        (b"GET /alive HTTP/1.1\r\n".to_vec(),0,missing),
        (boundary,0,ok),(too_large,14,&b""[..]),(Vec::new(),11,&b""[..]),(good,0,ok)];
    let held=s.kernel.fabric.scoped_pointers.total_reserved_bytes();
    for (case,(request,code,expected)) in cases.into_iter().enumerate() {
        // Compare while the charged report is borrowed, retaining only scalar
        // diagnostics. Check exit status first so empty output cannot hide it.
        let mut output_matches=false;let mut output_len=0;
        let result=s.run_with_input(linked,&exec,&input_auth,&request,|actual|{
            output_matches=actual==expected;output_len=actual.len();Ok(())
        }).unwrap();
        eprintln!("C5 HTTP case {}: input={} result={:?} output={}/{}",case,request.len(),result,output_len,expected.len());
        assert_eq!(result,ProcessResult::Exited(code),"HTTP case {} input={} output={}",case,request.len(),output_len);
        assert!(output_matches,"HTTP case {}: response bytes differ (actual length {}, expected {})",case,output_len,expected.len());
        assert_eq!(s.kernel.fabric.scoped_pointers.total_reserved_bytes(),held);
        assert!(s.kernel.linked_compiler_receipt(linked).is_ok());
    }
    eprintln!("C5 protected HTTP: ordinary rebuild, exact 200/404, binary headers, 1024-byte boundary, oversize/empty rejection, fresh input and refund passed");
}

#[test]
fn c5_http_frame_service_charges_expanded_fixed_registry() {
    let (k,_held,_)=realm().unwrap();
    let old=crate::anka64::scoped_pointers::ScopedPointers::with_limits(RegistryLimits{
        slots:4096,scopes:4096,owners:64,cleanup:512,global_bytes:0x20000000}).unwrap();
    assert!(k.fabric.scoped_pointers.fixed_metadata_bytes()>old.fixed_metadata_bytes());
    assert!(k.fabric.scoped_pointers.total_reserved_bytes()>=70*1024*1024+k.fabric.scoped_pointers.fixed_metadata_bytes());
}
