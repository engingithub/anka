use super::*;
use crate::anka64::placement::{PhysicalExtent, VirtualExtent};

fn owner(slot: usize) -> AllocationOwner {
    AllocationOwner { process: ProcessKey { slot, generation: 0 }, context: 100+slot as u64,
        domain: DomainId(7+slot as u64) }
}
fn table(rows: usize, budget: u64) -> ScopedPointers {
    let mut r = ScopedPointers::with_heap_placement(
        RegistryLimits { slots: 8, scopes: 8, owners: 4, cleanup: rows, global_bytes: u64::MAX },
        HeapPlacementLimits { physical_pool: PhysicalExtent { base: 4096, size: 4096 },
            physical_claims: 8, virtual_window: VirtualExtent { base: 65536, size: 4096 },
            per_owner_claims: 8 }).unwrap();
    r.heap.limit = r.fixed_metadata_bytes()+budget;
    r
}
fn host(r: &mut ScopedPointers, a: OwnerAccount, n: u64) -> HostStorageReservation {
    r.reserve_host_storage(a,n,r.revision()).unwrap()
}
fn denied(r: &mut ScopedPointers, a: OwnerAccount, n: u64, revision: u64, expected: HeapError) {
    let before = format!("{r:?}");
    assert_eq!(r.reserve_host_storage(a,n,revision),Err(expected));
    assert_eq!(format!("{r:?}"),before,"denial must preserve the entire registry");
}

#[test]
fn c27_host_storage_works_with_full_guest_pool_without_changing_placement() {
    let mut r=table(4,32768);let a=r.admit_owner(owner(1),32768).unwrap();
    let p=r.reserve_heap(a,4096,r.revision()).unwrap();
    let placement=format!("{:?}",r.heap.placement);
    let h=super::super::no_alloc(||host(&mut r,a,8193));
    assert_eq!(r.check_host_storage(h,owner(1),r.revision()),Ok(8193));
    assert_eq!(r.account_reserved_bytes(a),Ok(16384));
    assert_eq!(format!("{:?}",r.heap.placement),placement);
    super::super::no_alloc(||r.release_host_storage(h)).unwrap();
    assert_eq!(format!("{:?}",r.heap.placement),placement);
    r.abort_heap(p).unwrap();assert_eq!(r.total_reserved_bytes(),r.fixed_metadata_bytes());
}

#[test]
fn c27_host_storage_and_heap_share_owner_and_global_limits() {
    let mut r=table(4,12288);let a=r.admit_owner(owner(1),8192).unwrap();
    let b=r.admit_owner(owner(2),8192).unwrap();let _ha=host(&mut r,a,4097);
    let rev=r.revision();denied(&mut r,a,1,rev,HeapError::Capacity(Resource::OwnerBytes));
    assert_eq!(r.reserve_heap(a,1,r.revision()),Err(HeapError::Capacity(Resource::OwnerBytes)));
    let pb=r.reserve_heap(b,4096,r.revision()).unwrap();
    let rev=r.revision();denied(&mut r,b,1,rev,HeapError::Capacity(Resource::GlobalBytes));
    r.abort_heap(pb).unwrap();let _hb=host(&mut r,b,4096);
    assert_eq!(r.total_reserved_bytes(),r.fixed_metadata_bytes()+12288);
}

#[test]
fn c27_host_storage_death_retains_charge_and_prevents_account_reuse() {
    let mut r=table(4,16384);let a=r.admit_owner(owner(1),16384).unwrap();let h=host(&mut r,a,4097);
    assert_eq!(r.close_owner(a),Ok(0)); // no fake heap-cleanup entry
    r.release_closed_heap_accounts();assert_eq!(r.heap_account(owner(1)),Some(a));
    assert_eq!(r.account_reserved_bytes(a),Ok(8192));
    assert_eq!(r.check_host_storage(h,owner(1),r.revision()),Err(HeapError::Closed));
    assert_eq!(r.release_owner(a),Err(HeapError::Busy));
    let rev=r.revision();denied(&mut r,a,1,rev,HeapError::Closed);
    r.release_host_storage(h).unwrap();r.release_closed_heap_accounts();
    assert_eq!(r.heap_account(owner(1)),None);
}

#[test]
fn c27_host_storage_reused_row_rejects_old_and_duplicate_refund() {
    let mut r=table(1,16384);let a=r.admit_owner(owner(1),16384).unwrap();let old=host(&mut r,a,1);
    r.release_host_storage(old).unwrap();let new=host(&mut r,a,4097);
    assert_eq!(old.row,new.row);assert_ne!(old.incarnation(),new.incarnation());
    let before=format!("{r:?}");
    assert_eq!(r.release_host_storage(old),Err(HeapError::StaleReservation));
    assert_eq!(format!("{r:?}"),before);assert_eq!(r.check_host_storage(old,owner(1),r.revision()),Err(HeapError::StaleReservation));
    r.release_host_storage(new).unwrap();assert!(r.release_host_storage(new).is_err());
}

#[test]
fn c27_host_storage_directory_exhaustion_is_atomic_and_reusable() {
    let mut r=table(1,16384);let a=r.admit_owner(owner(1),16384).unwrap();let h=host(&mut r,a,1);
    let rev=r.revision();denied(&mut r,a,1,rev,HeapError::Capacity(Resource::HostStorage));
    r.release_host_storage(h).unwrap();let _=host(&mut r,a,1);
}

#[test]
fn c27_host_storage_stale_revision_size_and_wrong_owner_reject() {
    let mut r=table(4,32768);let a=r.admit_owner(owner(1),32768).unwrap();let rev=r.revision();
    let h=host(&mut r,a,1);denied(&mut r,a,1,rev,HeapError::StaleRevision);
    for n in [0,i64::MAX as u64+1,u64::MAX] {let rev=r.revision();denied(&mut r,a,n,rev,HeapError::Size);}
    assert_eq!(r.check_host_storage(h,owner(2),r.revision()),Err(HeapError::Owner));
    assert_eq!(r.check_host_storage(h,owner(1),rev),Err(HeapError::StaleRevision));
}

#[test]
fn c27_host_storage_terminal_counters_fence_admission_but_allow_release() {
    for identity in [false,true] {
        let mut r=table(4,16384);let a=r.admit_owner(owner(1),16384).unwrap();let h=host(&mut r,a,1);
        if identity {r.heap.next_job=u64::MAX;} else {r.heap.revision=u64::MAX;}
        let rev=r.revision();denied(&mut r,a,1,rev,HeapError::Capacity(Resource::Identity));
        r.close_owner(a).unwrap();r.release_host_storage(h).unwrap();r.release_owner(a).unwrap();
        assert_eq!(r.total_reserved_bytes(),r.fixed_metadata_bytes());
    }
}

#[test]
fn c27_host_storage_a_exit_c_reuse_preserves_b_and_rejects_a_token() {
    let mut r=table(2,16384);let a=r.admit_owner(owner(1),8192).unwrap();
    let b=r.admit_owner(owner(2),8192).unwrap();let ha=host(&mut r,a,4096);let hb=host(&mut r,b,4097);
    r.close_owner(a).unwrap();assert_eq!(r.account_reserved_bytes(b),Ok(8192));
    r.release_host_storage(ha).unwrap();r.release_owner(a).unwrap();
    let c=r.admit_owner(owner(3),8192).unwrap();let hc=host(&mut r,c,4096);
    assert_eq!(ha.row,hc.row);assert_eq!(a.index,c.index);assert_ne!(a.serial,c.serial);
    assert_eq!(r.check_host_storage(hb,owner(2),r.revision()),Ok(4097));
    assert!(r.release_host_storage(ha).is_err());assert_eq!(r.account_reserved_bytes(b),Ok(8192));
    assert_eq!(r.account_reserved_bytes(c),Ok(4096));
}

#[test]
fn c27_host_storage_fixed_directory_is_charged_before_admission() {
    let small=table(1,16384);let large=table(4,16384);
    assert!(large.fixed_metadata_bytes()>=small.fixed_metadata_bytes()+3*std::mem::size_of::<Option<HostStorageRecord>>() as u64);
    let mut limits=RegistryLimits {slots:8,scopes:8,owners:4,cleanup:4,global_bytes:u64::MAX};
    let fixed=ScopedPointers::with_limits(limits).unwrap().fixed_metadata_bytes();limits.global_bytes=fixed-1;
    assert!(matches!(ScopedPointers::with_limits(limits),Err(HeapError::Capacity(Resource::GlobalBytes))));
}
