use super::*;
use crate::anka64::scoped_pointers::ScopedPointers;

const CPU: AgentId = AgentId(0);
const BASE: u64 = 0x1000;
const VA: u64 = 0x8040;
fn fixture() -> (Fabric, MemoryRequest) {
    let mut f = Fabric::new(0x4000);
    let object = f.alloc_object("stack", 256, ObjectKind::Memory);
    assert!(f.place_object(object, BASE));
    let domain = f.create_domain();
    f.grant(
        domain,
        object,
        0,
        256,
        Permissions(Permissions::RW.0 | Permissions::ATOMIC.0),
    )
    .unwrap();
    f.register_agent(CPU, AgentKind::Cpu(CoreId(0)), domain);
    assert!(f.protect_pointer_stack(object, 7, domain));
    f.write_physical(BASE, &[0xa7; 256]);
    let mut r = request(CPU, domain, object, 64, Width::Byte, AccessKind::Read);
    r.length = 64;
    (f, r)
}
fn local(r: MemoryRequest, offset: u64, length: u64) -> (MemoryRequest, u64, bool) {
    let mut l = r;
    l.offset += offset;
    l.length = length;
    (l, VA + offset, true)
}
fn snapshot(
    f: &Fabric,
) -> (
    Vec<u8>,
    String,
    BTreeMap<(ObjectId, Generation, u64), ScopedPointer>,
) {
    (
        f.memory.clone(),
        format!("{:?}", f.scoped_pointers),
        f.pointer_cells.clone(),
    )
}
fn denied(f: &mut Fabric, r: MemoryRequest, locals: Vec<(MemoryRequest, u64, bool)>) {
    let before = snapshot(f);
    assert!(f.issue_pointer_frame(7, r, VA, locals).is_err());
    assert_eq!(snapshot(f), before);
}
#[test]
fn r1_full_frame_clears_padding_and_tags_preserving_caller_cells() {
    let (mut f, r) = fixture();
    let scope = f.scoped_pointers.enter_scope_for(7).unwrap();
    let mut parent = r;
    parent.offset = 0;
    parent.length = 16;
    let p = f
        .register_scoped_pointer(scope, parent, 0x8000, true)
        .unwrap();
    let mut cell = parent;
    cell.kind = AccessKind::Write;
    f.store_pointer_cell(cell, Some(p)).unwrap();
    let outside = f.read_physical(BASE, 64).to_vec();
    cell.offset = 80;
    f.store_pointer_cell(cell, Some(p)).unwrap();
    let (_, locals) = f
        .issue_pointer_frame(7, r, VA, vec![local(r, 0, 8), local(r, 16, 16)])
        .unwrap();
    assert_eq!(f.read_physical(BASE + 64, 64), [0; 64]);
    assert_eq!(f.read_physical(BASE, 64), outside);
    assert_eq!(f.read_physical(BASE + 128, 128), [0xa7; 128]);
    assert_eq!(f.pointer_cells.len(), 1);
    assert_eq!(
        f.scoped_pointer_backing(locals[0], r.context.domain)
            .unwrap(),
        (r.object, 64)
    );
    let mut null = r;
    null.offset = 80;
    null.length = 16;
    assert_eq!(f.load_pointer_cell(null).unwrap(), None);
}
#[test]
fn r1_late_invalid_or_overlapping_local_preserves_all_state() {
    let (mut f, r) = fixture();
    let mut bad = local(r, 16, 16);
    bad.0.offset += 16;
    denied(&mut f, r, vec![local(r, 0, 8), bad]);
    denied(&mut f, r, vec![local(r, 0, 16), local(r, 8, 8)]);
}
#[test]
fn r1_padding_requires_full_frame_write_authority() {
    let (mut f, r) = fixture();
    f.domains
        .get_mut(&r.context.domain)
        .unwrap()
        .capabilities
        .clear();
    f.grant(r.context.domain, r.object, 64, 8, Permissions::RW)
        .unwrap();
    denied(&mut f, r, vec![local(r, 0, 8)]);
}
#[test]
fn r1_empty_frame_owns_padding_until_scope_retirement() {
    let (mut f, r) = fixture();
    let (scope, locals) = f.issue_pointer_frame(7, r, VA, vec![]).unwrap();
    f.write_physical(BASE + 64, &[0x55; 64]);
    denied(&mut f, r, vec![]);
    f.retire_pointer_frame(scope, &locals).unwrap();
    f.issue_pointer_frame(7, r, VA, vec![]).unwrap();
    assert_eq!(f.read_physical(BASE + 64, 64), [0; 64]);
}
#[test]
fn r1_legacy_live_local_also_blocks_frame_reuse() {
    let (mut f, r) = fixture();
    let scope = f.scoped_pointers.enter_scope_for(7).unwrap();
    let p = f.register_scoped_pointer(scope, r, VA, true).unwrap();
    denied(&mut f, r, vec![local(r, 0, 8)]);
    f.retire_pointer_frame(scope, &[p]).unwrap();
    f.issue_pointer_frame(7, r, VA, vec![local(r, 0, 8)])
        .unwrap();
    assert!(f.scoped_pointer_backing(p, r.context.domain).is_err());
}
#[test]
fn r1_pending_read_write_atomic_and_dma_work_prevents_scrub() {
    for kind in [AccessKind::Read, AccessKind::Write, AccessKind::Atomic] {
        for advances in 0..3 {
            let (mut f, r) = fixture();
            let mut work = r;
            work.kind = kind;
            let tx = f.submit(
                work,
                if kind == AccessKind::Read {
                    None
                } else {
                    Some(vec![1; 64])
                },
            );
            for _ in 0..advances {
                f.advance(tx);
            }
            assert!(!f.transactions[tx].state.is_terminal());
            denied(&mut f, r, vec![local(r, 0, 8)]);
        }
    }
    let (mut f, r) = fixture();
    let mut dma = r;
    dma.context.agent = AgentId(90);
    f.submit(dma, Some(vec![1; 64]));
    denied(&mut f, r, vec![]);
}
#[test]
fn r1_captured_physical_work_blocks_even_after_logical_rebinding() {
    let (mut f, r) = fixture();
    let o = f.alloc_object("old work", 64, ObjectKind::Memory);
    // Prepare real work at a legal, disjoint placement. Then move its
    // object away and place the stack over the captured physical span.
    // No illegal overlap is needed to exercise this pending-work census.
    let captured = 0x2000;
    assert!(f.place_object(o, captured));
    f.grant(r.context.domain, o, 0, 64, Permissions::READ)
        .unwrap();
    let mut work = r;
    work.object = o;
    work.offset = 0;
    let tx = f.submit(work, None);
    f.advance(tx);
    f.advance(tx);
    assert_eq!(f.transactions[tx].state, TxState::Prepared);
    assert_eq!(f.transactions[tx].physical_address, Some(captured));
    assert!(f.place_object(o, 0x3000));
    assert!(f.place_object(r.object, captured - r.offset));
    assert_eq!(f.translate(o, 0), Some(0x3000));
    assert_eq!(f.translate(r.object, r.offset), Some(captured));
    denied(&mut f, r, vec![]);
}
#[test]
fn r1_unrelated_pending_work_is_not_a_global_stop() {
    let (mut f, r) = fixture();
    let mut work = r;
    work.offset = 128;
    let tx = f.submit(work, None);
    f.issue_pointer_frame(7, r, VA, vec![local(r, 0, 8)])
        .unwrap();
    assert_eq!(f.transactions[tx].state, TxState::Requested);
}
#[test]
fn r1_current_external_authority_and_same_domain_agents_are_rechecked() {
    let (mut f, r) = fixture();
    f.register_agent(AgentId(1), AgentKind::Cpu(CoreId(1)), r.context.domain);
    denied(&mut f, r, vec![]);
    f.agents.remove(&AgentId(1));
    let other = f.create_domain();
    // Simulate a stale trusted setup bypass: admission must inspect actual grants.
    f.pointer_stack_objects.remove(&r.object);
    f.grant(other, r.object, 64, 64, Permissions::READ).unwrap();
    f.pointer_stack_objects
        .insert(r.object, (7, r.context.domain));
    denied(&mut f, r, vec![]);
}
#[test]
fn r1_physical_alias_and_bad_geometry_preserve_payload() {
    let (mut f, r) = fixture();
    let alias = f.alloc_object("alias", 16, ObjectKind::Memory);
    // Public placement already rejects this overlap. Deliberately inject
    // malformed trusted state only in this hostile fixture to exercise
    // PFRAME's independent physical-alias check.
    assert!(!f.place_object(alias, BASE + 80));
    assert_eq!(f.physical_base(alias), None);
    assert_eq!(f.placement.insert(alias, BASE + 80), None);
    assert_eq!(f.translate(alias, 0), Some(BASE + 80));
    denied(&mut f, r, vec![]);
    f.placement.remove(&alias);
    let mut bad = r;
    bad.offset += 1;
    denied(&mut f, bad, vec![]);
    bad = r;
    bad.length = u64::MAX;
    denied(&mut f, bad, vec![]);
}
#[test]
fn r1_exhausted_descriptor_or_scope_admission_cannot_clear_bytes() {
    let (mut f, r) = fixture();
    f.scoped_pointers = ScopedPointers::new(1);
    denied(&mut f, r, vec![local(r, 0, 8), local(r, 16, 16)]);
    f.scoped_pointers.enter_scope_for(8).unwrap();
    denied(&mut f, r, vec![]);
}

#[test]
fn c5_http_frame_order_fast_path_preserves_index_and_overlap_rejection() {
    let (mut f,r)=fixture();
    let (_,p)=f.issue_pointer_frame(7,r,VA,
        vec![local(r,32,8),local(r,0,8),local(r,16,8)]).unwrap();
    for (pointer,offset) in p.into_iter().zip([32,0,16]) {
        assert_eq!(f.scoped_pointer_backing(pointer,r.context.domain).unwrap(),(r.object,r.offset+offset));
    }
    let (mut f,r)=fixture();
    denied(&mut f,r,vec![local(r,0,24),local(r,16,8)]);
    denied(&mut f,r,vec![local(r,32,8),local(r,0,24),local(r,16,8)]);
}

#[test]
fn c5_http_frame_two_compilers_exceed_old_pool_retire_and_reuse() {
    use crate::anka64::scoped_pointers::heap::RegistryLimits;
    let mut f=Fabric::new(0x100000);
    f.scoped_pointers=ScopedPointers::with_limits(RegistryLimits {
        slots:36864,scopes:4096,owners:0,cleanup:0,global_bytes:0x4000000
    }).unwrap();
    let held=f.scoped_pointers.total_reserved_bytes();
    let mut owners=Vec::new();
    for owner in [7u64,8] {
        let object=f.alloc_object("nested-compiler-stack",0x30000,ObjectKind::Memory);
        assert!(f.place_object(object,0x10000+(owner-7)*0x30000));
        let domain=f.create_domain();f.grant(domain,object,0,0x30000,Permissions::RW).unwrap();
        let agent=AgentId(owner);f.register_agent(agent,AgentKind::Cpu(CoreId(owner)),domain);
        assert!(f.protect_pointer_stack(object,owner,domain));
        let mut frames=Vec::new();
        for depth in 0..7 {
            let offset=depth*10608; // 663 disjoint 16-byte compiler locals.
            let address=0x100000+offset;
            let mut r=request(agent,domain,object,offset,Width::Byte,AccessKind::Read);r.length=10608;
            let locals=(0..663).map(|i| {
                let mut l=r;l.offset+=i*16;l.length=16;(l,address+i*16,true)
            }).collect();
            frames.push(f.issue_pointer_frame(owner,r,address,locals).unwrap());
        }
        owners.push((domain,frames));
    }
    let a=owners[0].1[0].1[0];let b=owners[1].1[0].1[0];
    for (scope,pointers) in owners[0].1.iter().rev() {f.retire_pointer_frame(*scope,pointers).unwrap();}
    assert!(f.scoped_pointer_backing(a,owners[0].0).is_err());
    assert!(f.scoped_pointer_backing(b,owners[1].0).is_ok());
    let scope=f.scoped_pointers.enter_scope_for(9).unwrap();
    let c=f.scoped_pointers.register(scope,9,0x900000,16,true).unwrap();
    assert_ne!(a.words(),c.words());
    assert!(f.scoped_pointer_backing(a,owners[0].0).is_err());
    assert!(f.scoped_pointer_backing(b,owners[1].0).is_ok());
    assert_eq!(f.scoped_pointers.total_reserved_bytes(),held);
}
