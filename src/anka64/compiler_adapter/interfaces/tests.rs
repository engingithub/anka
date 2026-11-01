use super::*;
fn w(b: &mut Vec<u8>,n: u64) { b.extend_from_slice(&n.to_le_bytes()); }
fn put(b: &mut [u8],at: usize,n: u64) { b[at..at+8].copy_from_slice(&n.to_le_bytes()); }
fn name(s: &str) -> Vec<u8> { let mut b=vec![0;64];b[..s.len()].copy_from_slice(s.as_bytes());b }
fn ty(kind: u64,depth: u64,tag: &str) -> Vec<u8> {
    let mut b=Vec::new();w(&mut b,kind);w(&mut b,depth);b.extend(name(tag));b
}
fn field(n: &str,t: Vec<u8>,offset: u64,count: u64) -> Vec<u8> {
    let mut b=name(n);b.extend(t);w(&mut b,offset);w(&mut b,count);b
}
fn decl(n: &str,size: u64,alignment: u64,rank: u64,fields: Vec<Vec<u8>>) -> Vec<u8> {
    let mut b=name(n);w(&mut b,1);w(&mut b,size);w(&mut b,alignment);
    w(&mut b,fields.len() as u64);w(&mut b,rank);w(&mut b,0);
    for f in fields { b.extend(f); } b
}
fn opaque(n: &str) -> Vec<u8> { let mut b=name(n);b.resize(DECL_BYTES,0);b }
fn node() -> Vec<u8> {
    decl("Node",32,16,1,vec![field("value",ty(1,0,""),0,1),field("next",ty(4,1,"Node"),16,1)])
}
fn function(n: &str,binding: u64,ret: Vec<u8>,args: Vec<Vec<u8>>) -> Vec<u8> {
    let mut b=name(n);w(&mut b,binding);w(&mut b,args.len() as u64);b.extend(ret);
    for a in args { b.extend(a); }b.resize(FUNCTION_BYTES,0);b
}
fn pass(binding: u64) -> Vec<u8> { function("pass",binding,ty(4,1,"Node"),vec![ty(4,1,"Node")]) }
fn module(ds: Vec<Vec<u8>>,fs: Vec<Vec<u8>>) -> Vec<u8> {
    let mut b=TYPE_MAGIC.to_vec();w(&mut b,TYPE_VERSION);w(&mut b,0);
    w(&mut b,ds.len() as u64);w(&mut b,fs.len() as u64);
    for d in ds { b.extend(d); }for f in fs { b.extend(f); }
    let n=b.len() as u64;put(&mut b,16,n);b
}
fn limits() -> TypeLimits { TypeLimits { bytes:1<<20,declarations:4096,fields:4096,functions:4096 } }
fn work() -> TypeWork { TypeWork::new(1_000_000) }
fn parse(b: &[u8]) -> Result<TypeEvidence<'_>,TypeError> { TypeEvidence::parse(b,limits(),&mut work()) }

#[test]
fn c34_interfaces_independent_order_and_shared_struct_parameters_and_returns() {
    let a=module(vec![node()],vec![pass(1)]);
    let b=module(vec![opaque("Unrelated"),node()],vec![pass(2)]);
    let modules=[parse(&a).unwrap(),parse(&b).unwrap()];
    let proof=CompatibleInterfaces::validate(&modules,&mut work()).unwrap();
    proof.check_exact_inputs(&[&a,&b],&mut work()).unwrap();
    assert_eq!(modules[1].object_layout(&name("Node"),&mut work()),Ok((32,16)));
}
#[test]
fn c34_interfaces_opaque_transport_does_not_permit_object_layout() {
    let a=module(vec![node()],vec![pass(1)]);
    let b=module(vec![opaque("Node")],vec![pass(2)]);
    let modules=[parse(&a).unwrap(),parse(&b).unwrap()];
    CompatibleInterfaces::validate(&modules,&mut work()).unwrap();
    assert_eq!(modules[1].object_layout(&name("Node"),&mut work()),Err(TypeError::Incomplete));
}
#[test]
fn c34_interfaces_opaque_bridge_cannot_hide_conflicting_complete_definitions() {
    let a=module(vec![decl("Node",8,8,1,vec![field("x",ty(1,0,""),0,1)])],vec![]);
    let b=module(vec![opaque("Node")],vec![]);
    let c=module(vec![decl("Node",1,1,1,vec![field("x",ty(2,0,""),0,1)])],vec![]);
    let modules=[parse(&a).unwrap(),parse(&b).unwrap(),parse(&c).unwrap()];
    assert_eq!(CompatibleInterfaces::validate(&modules,&mut work()).unwrap_err(),TypeError::Conflict);
}
#[test]
fn c34_interfaces_same_size_different_field_type_or_name_is_incompatible() {
    let a=module(vec![decl("Node",8,8,1,vec![field("x",ty(1,0,""),0,1)])],vec![]);
    let b=module(vec![decl("Node",8,8,1,vec![field("y",ty(1,0,""),0,1)])],vec![]);
    let modules=[parse(&a).unwrap(),parse(&b).unwrap()];
    assert_eq!(CompatibleInterfaces::validate(&modules,&mut work()).unwrap_err(),TypeError::Conflict);
    let c=module(vec![decl("Node",8,1,1,vec![field("x",ty(2,0,""),0,8)])],vec![]);
    let modules=[parse(&a).unwrap(),parse(&c).unwrap()];
    assert_eq!(CompatibleInterfaces::validate(&modules,&mut work()).unwrap_err(),TypeError::Conflict);
}
#[test]
fn c34_interfaces_pointer_recursive_graph_terminates_without_layout_expansion() {
    let a=decl("A",16,16,1,vec![field("b",ty(4,1,"B"),0,1)]);
    let b=decl("B",16,16,1,vec![field("a",ty(4,1,"A"),0,1)]);
    let raw=module(vec![a,b],vec![]);
    let mut fuel=TypeWork::new(100);
    TypeEvidence::parse(&raw,limits(),&mut fuel).unwrap();assert!(fuel.remaining()>0);
}
#[test]
fn c34_interfaces_embedded_values_require_finite_rank_and_complete_layout() {
    let wrapper=decl("Wrapper",48,16,2,vec![field("node",ty(4,0,"Node"),0,1),field("tail",ty(2,0,""),32,1)]);
    parse(&module(vec![wrapper,node()],vec![])).unwrap();
    let cycle=decl("Node",8,8,1,vec![field("self_value",ty(4,0,"Node"),0,1)]);
    assert_eq!(parse(&module(vec![cycle],vec![])).unwrap_err(),TypeError::Cycle);
    let incomplete=decl("Wrapper",8,8,1,vec![field("node",ty(4,0,"Node"),0,1)]);
    assert_eq!(parse(&module(vec![incomplete,opaque("Node")],vec![])).unwrap_err(),TypeError::Incomplete);
}
#[test]
fn c34_interfaces_rejects_dangling_types_bad_depth_and_scalar_tag_smuggling() {
    let dangling=module(vec![],vec![pass(1)]);
    assert_eq!(parse(&dangling).unwrap_err(),TypeError::Type);
    for t in [ty(4,64,"Node"),ty(1,0,"Node"),ty(9,1,"")] {
        let raw=module(vec![opaque("Node")],vec![function("f",1,t,vec![])]);
        assert_eq!(parse(&raw).unwrap_err(),TypeError::Type);
    }
}
#[test]
fn c34_interfaces_call_lanes_keep_existing_protected_abi() {
    let pointer=ty(4,1,"Node");
    parse(&module(vec![opaque("Node")],vec![function("f",1,ty(3,0,""),vec![pointer.clone(),pointer.clone()])])).unwrap();
    let raw=module(vec![opaque("Node")],vec![function("f",1,ty(3,0,""),vec![ty(1,0,""),pointer,ty(1,0,"")])]);
    assert_eq!(parse(&raw).unwrap_err(),TypeError::Signature);
    let raw=module(vec![node()],vec![function("f",1,ty(4,0,"Node"),vec![])]);
    assert_eq!(parse(&raw).unwrap_err(),TypeError::Signature);
}
#[test]
fn c34_interfaces_rejects_conflicting_signatures_duplicate_exports_and_unresolved_imports() {
    let a=module(vec![node()],vec![pass(1)]);
    let b=module(vec![opaque("Node")],vec![function("pass",2,ty(1,0,""),vec![ty(4,1,"Node")])]);
    let modules=[parse(&a).unwrap(),parse(&b).unwrap()];
    assert_eq!(CompatibleInterfaces::validate(&modules,&mut work()).unwrap_err(),TypeError::Signature);
    let modules=[parse(&a).unwrap(),parse(&a).unwrap()];
    assert_eq!(CompatibleInterfaces::validate(&modules,&mut work()).unwrap_err(),TypeError::Duplicate);
    let b=module(vec![opaque("Node")],vec![pass(2)]);
    let modules=[parse(&b).unwrap()];
    assert_eq!(CompatibleInterfaces::validate(&modules,&mut work()).unwrap_err(),TypeError::Unresolved);
}
#[test]
fn c34_interfaces_rejects_duplicate_declarations_and_noncanonical_names() {
    assert_eq!(parse(&module(vec![node(),node()],vec![])).unwrap_err(),TypeError::Duplicate);
    let mut bad=node();bad[63]=b'x';
    assert_eq!(parse(&module(vec![bad],vec![])).unwrap_err(),TypeError::Name);
    let bad=decl("N",16,8,1,vec![field("x",ty(1,0,""),0,1),field("x",ty(1,0,""),8,1)]);
    assert_eq!(parse(&module(vec![bad],vec![])).unwrap_err(),TypeError::Duplicate);
}
#[test]
fn c34_interfaces_checks_canonical_padding_alignment_and_array_overflow() {
    for (offset,value) in [(72,48),(80,8),(104,1)] {
        let mut bad=node();put(&mut bad,offset,value);assert!(parse(&module(vec![bad],vec![])).is_err());
    }
    let mut bad=node();put(&mut bad,DECL_BYTES+FIELD_BYTES+144,8);
    assert_eq!(parse(&module(vec![bad],vec![])).unwrap_err(),TypeError::Layout);
    let mut bad=node();put(&mut bad,DECL_BYTES+152,u64::MAX);
    assert_eq!(parse(&module(vec![bad],vec![])).unwrap_err(),TypeError::Layout);
}
#[test]
fn c34_interfaces_truncation_tail_header_and_count_overflow_fail_closed() {
    let raw=module(vec![node()],vec![pass(1)]);
    for stop in [0,8,39,40,151,raw.len()-1] { assert!(parse(&raw[..stop]).is_err()); }
    let mut bad=raw.clone();bad.push(0);let n=bad.len() as u64;put(&mut bad,16,n);
    assert_eq!(parse(&bad).unwrap_err(),TypeError::Bounds);
    let mut bad=raw.clone();put(&mut bad,24,u64::MAX);assert_eq!(parse(&bad).unwrap_err(),TypeError::Limit);
    let mut bad=raw.clone();put(&mut bad,HEADER_BYTES+88,u64::MAX);assert_eq!(parse(&bad).unwrap_err(),TypeError::Bounds);
    let mut bad=raw;put(&mut bad,8,2);assert_eq!(parse(&bad).unwrap_err(),TypeError::Header);
}
#[test]
fn c34_interfaces_work_and_metadata_limits_are_enforced_before_expansion() {
    let raw=module(vec![node()],vec![pass(1)]);
    let mut l=limits();l.fields=1;
    assert_eq!(TypeEvidence::parse(&raw,l,&mut work()).unwrap_err(),TypeError::Limit);
    assert_eq!(TypeEvidence::parse(&raw,limits(),&mut TypeWork::new(1)).unwrap_err(),TypeError::Work);
    let modules=[parse(&raw).unwrap()];
    assert_eq!(CompatibleInterfaces::validate(&modules,&mut TypeWork::new(0)).unwrap_err(),TypeError::Work);
}
#[test]
fn c34_interfaces_exact_input_revalidation_rejects_substitution_and_reordering() {
    let a=module(vec![node()],vec![pass(1)]);
    let b=module(vec![opaque("Node")],vec![pass(2)]);
    let modules=[parse(&a).unwrap(),parse(&b).unwrap()];
    let proof=CompatibleInterfaces::validate(&modules,&mut work()).unwrap();
    assert_eq!(proof.check_exact_inputs(&[&b,&a],&mut work()),Err(TypeError::Changed));
    let mut changed=a.clone();changed[HEADER_BYTES+DECL_BYTES]=b'z';
    assert_eq!(proof.check_exact_inputs(&[&changed,&b],&mut work()),Err(TypeError::Changed));
    proof.check_exact_inputs(&[&a,&b],&mut work()).unwrap();
}
#[test]
fn c34_interfaces_empty_and_spare_function_records_are_not_authority() {
    assert_eq!(CompatibleInterfaces::validate(&[],&mut work()).unwrap_err(),TypeError::Unresolved);
    let mut f=pass(1);f[FUNCTION_BYTES-1]=1;
    assert_eq!(parse(&module(vec![node()],vec![f])).unwrap_err(),TypeError::Signature);
    let raw=module(vec![opaque("Node")],vec![]);
    parse(&raw).unwrap(); // declarations alone cannot mint pointers or code
}
