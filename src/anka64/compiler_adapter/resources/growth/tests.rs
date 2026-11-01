use super::*;
#[test]
fn c34_growth_source_crosses_old_limit_with_initialized_lookahead_extent() {
    assert_eq!(source_capacity(65528,1<<20),Ok(65536));
    assert_eq!(source_capacity(65529,1<<20),Ok(69632));
    assert_eq!(source_capacity(200_000,1<<20),Ok(200704));
    assert_eq!(source_capacity(0,4096),Ok(4096));
    assert_eq!(source_capacity(4096,4096),Err(GrowthError::Capacity));
    assert_eq!(source_capacity(u64::MAX,1<<20),Err(GrowthError::Overflow));
}
#[test]
fn c34_growth_workspace_crosses_all_old_table_counts_without_overlap() {
    let counts=[129,257,65,65,33,129,129];
    let plan=WorkspacePlan::new(counts,1<<20).unwrap();
    let mut stop=CONTROL_BYTES;
    for kind in KINDS {
        let s=plan.table(kind);assert!(s.offset>=stop);assert_eq!(s.count,counts[kind.index()]);
        assert_eq!(s.element(s.count-1),Ok(s.offset+(s.count-1)*s.stride));
        assert_eq!(s.element(s.count),Err(GrowthError::Index));
        stop=s.offset+s.count*s.stride;
    }
    assert_eq!(stop,plan.used());assert!(stop<=plan.capacity());assert_eq!(plan.capacity()%4096,0);
}
#[test]
fn c34_growth_workspace_does_not_depend_on_spare_budget() {
    let a=WorkspacePlan::new([128,128,64,64,64,256,128],1<<20).unwrap();
    let b=WorkspacePlan::new([128,128,64,64,64,256,128],2<<20).unwrap();assert_eq!(a,b);
    assert!(WorkspacePlan::new([u64::MAX,0,0,0,0,0,0],1<<20).is_err());
    assert!(WorkspacePlan::new([128;7],4096).is_err());
    assert_eq!(WorkspacePlan::new([0;7],4096).unwrap().capacity(),4096);
}
#[test]
fn c34_growth_requires_strict_finite_growth_and_policy_alignment() {
    assert_eq!(next_capacity(4096,4097,16384),Ok(8192));
    assert_eq!(next_capacity(8192,12289,16384),Ok(16384));
    assert_eq!(next_capacity(8192,8192,16384),Err(GrowthError::Geometry));
    assert_eq!(next_capacity(8192,16385,16384),Err(GrowthError::Capacity));
    assert_eq!(next_capacity(4096,8192,8193),Err(GrowthError::Policy));
    assert_eq!(next_capacity(4096,u64::MAX,16384),Err(GrowthError::Overflow));
}
fn policy() -> LinkLimits { LinkLimits { modules:16,frames:8192,metadata:1<<20,image:4<<20 } }
fn modules() -> [ModuleGeometry;2] {
    [ModuleGeometry {code:800_000,rodata:16,frames:3000,metadata:96_000},
     ModuleGeometry {code:800_000,rodata:32,frames:3000,metadata:96_000}]
}
#[test]
fn c34_growth_link_plan_crosses_image_and_frame_limits_without_spare_tail() {
    let p=LinkPlan::new(&modules(),policy()).unwrap();
    assert!(p.used>1<<20);assert_eq!(p.frames,6000);assert_eq!(p.code,1_600_000);
    assert_eq!(p.rodata_at,1_600_000);assert_eq!(p.metadata_at,1_600_048);
    assert_eq!(p.used,1_792_048);assert!(p.capacity>=p.used && p.capacity-p.used<4096);
    let mut more=policy();more.image=8<<20;
    assert_eq!(LinkPlan::new(&modules(),more).unwrap(),p);
}
#[test]
fn c34_growth_link_denial_checks_all_budgets_and_exact_geometry() {
    for p in [LinkLimits {image:1<<20,..policy()},LinkLimits {frames:5999,..policy()},
        LinkLimits {metadata:191999,..policy()},LinkLimits {modules:1,..policy()}] {
        assert!(LinkPlan::new(&modules(),p).is_err());
    }
    let mut m=modules();m[0].code=0;assert_eq!(LinkPlan::new(&m,policy()),Err(GrowthError::Geometry));
    m=modules();m[0].rodata=3;assert_eq!(LinkPlan::new(&m,policy()),Err(GrowthError::Geometry));
    m=modules();m[0].code=u64::MAX-7;assert_eq!(LinkPlan::new(&m,policy()),Err(GrowthError::Overflow));
}
#[test]
fn c34_growth_large_memory_does_not_relax_call_encoding() {
    assert_eq!(call_displacement(0,((1<<19)-1)*4),Ok((1<<19)-1));
    assert_eq!(call_displacement((1<<19)*4,0),Ok(-(1<<19)));
    assert_eq!(call_displacement(0,(1<<19)*4),Err(GrowthError::Encoding));
    assert_eq!(call_displacement(((1<<19)+1)*4,0),Err(GrowthError::Encoding));
    assert_eq!(call_displacement(0,3),Err(GrowthError::Encoding));
    assert_eq!(call_displacement(u64::MAX,0),Err(GrowthError::Encoding));
}
