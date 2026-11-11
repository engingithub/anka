use super::*;
use super::super::typed_socket::{SocketRights,SocketTicket,SOCKET_AGAIN};
use crate::anka64::scoped_pointers::heap::{HeapPlacementLimits,RegistryLimits};
use crate::anka64::placement::VirtualExtent;

fn fixture(number:u64,length:u64,limit:u64)->(Kernel,ObjectId,ProcessKey) {
    let fabric=Fabric::with_private_heap(0x400000,
        RegistryLimits{slots:64,scopes:32,owners:4,cleanup:8,global_bytes:0x200000},
        HeapPlacementLimits{physical_pool:PhysicalExtent{base:0x300000,size:0x10000},
            physical_claims:8,virtual_window:VirtualExtent{base:0x100000,size:0x10000},
            per_owner_claims:8}).unwrap();
    let (mut k,stack)=typed_io_on_fabric(fabric,length,0,number);
    let owner=k.processes[0].core.heap_owner().unwrap();
    k.fabric.scoped_pointers.admit_owner(owner,limit).unwrap();
    (k,stack,owner.process)
}
fn again(k:&mut Kernel,number:u64,n:u64)->u64 {
    again_at(k,0,number,n)
}
pub(super) fn again_at(k:&mut Kernel,slot:usize,number:u64,n:u64)->u64 {
    let c=&mut k.processes[slot].core;
    c.write_register(0,number); c.write_register(1,0);
    c.write_register(4,n); c.write_register(5,0);
    c.enter_event(EventFrame{return_pc:c.pc,return_privilege:Privilege::User,
        interrupts_were_enabled:true,cause:EventCause::Syscall});
    k.handle_syscall(slot);
    k.processes[slot].core.r[0]
}
fn prepared(op:u64,n:u64,rights:SocketRights)->(Kernel,ObjectId,SocketTicket) {
    let (mut k,stack,key)=fixture(op,n,8192);
    let t=k.bind_socket(key,rights).unwrap(); (k,stack,t)
}

#[test]
fn s1_socket_binary_split_fin_and_reply_on_open_tx() {
    let (mut k,stack,t)=prepared(SYS_SOCKET_RECV,3,SocketRights::Duplex);
    k.handle_syscall(0);assert_eq!(k.processes[0].core.r[0],SOCKET_AGAIN);
    k.deliver_socket(t,&[65,0],false).unwrap();
    k.deliver_socket(t,&[255,66],true).unwrap();
    assert!(k.deliver_socket(t,&[77],false).is_err());
    assert_eq!(again(&mut k,SYS_SOCKET_RECV,5),u64::MAX); // whole capacity exceeds local
    assert_eq!(again(&mut k,SYS_SOCKET_RECV,3),3);
    assert_eq!(input_buffer(&k,stack),[65,0,255,0]);
    assert_eq!(again(&mut k,SYS_SOCKET_SEND,3),3);
    assert_eq!(again(&mut k,SYS_SOCKET_RECV,4),1);
    assert_eq!(input_buffer(&k,stack),[66,0,255,0]);
    assert_eq!(again(&mut k,SYS_SOCKET_RECV,4),0);
    assert_eq!(again(&mut k,SYS_SOCKET_RECV,5),u64::MAX);
    assert!(k.close_drained_socket(t).is_err());
    let mut out=[99;4];
    assert_eq!(k.take_socket_tx(t,&mut out).unwrap(),3);
    assert_eq!(out,[65,0,255,99]);assert_eq!(k.byte_output,[90]);
    k.close_drained_socket(t).unwrap();
}
#[test]
fn s1_socket_full_receive_refuses_entire_fragment_including_fin() {
    let (mut k,_,t)=prepared(SYS_SOCKET_RECV,4,SocketRights::Receive);
    k.deliver_socket(t,&[9;1023],false).unwrap();
    assert!(k.deliver_socket(t,&[7;2],true).is_err());
    k.deliver_socket(t,&[8],true).unwrap();
    k.handle_syscall(0);assert_eq!(k.processes[0].core.r[0],4);
    assert_eq!(again(&mut k,SYS_SOCKET_SEND,0),u64::MAX);
    assert!(k.take_socket_tx(t,&mut [0;1]).is_err());
}
#[test]
fn s1_socket_short_send_and_backpressure_preserve_queued_prefix() {
    let (mut k,_,t)=prepared(SYS_SOCKET_SEND,4,SocketRights::Send);
    k.handle_syscall(0);assert_eq!(k.processes[0].core.r[0],4);
    for _ in 1..256 {assert_eq!(again(&mut k,SYS_SOCKET_SEND,4),4);}
    assert_eq!(again(&mut k,SYS_SOCKET_SEND,4),SOCKET_AGAIN);
    assert_eq!(again(&mut k,SYS_SOCKET_SEND,0),0);
    let mut out=[90;2];assert_eq!(k.take_socket_tx(t,&mut out).unwrap(),2);
    assert_eq!(out,[65,0]);assert_eq!(again(&mut k,SYS_SOCKET_SEND,4),2);
    assert!(k.deliver_socket(t,&[1],false).is_err());
    assert_eq!(again(&mut k,SYS_SOCKET_RECV,0),u64::MAX);
    let mut all=[0;1024];assert_eq!(k.take_socket_tx(t,&mut all).unwrap(),1024);
    assert_eq!(&all[..4],&[0,0,65,0]);assert_eq!(&all[1022..],&[65,0]);
}
#[test]
fn s1_socket_cancel_or_death_refunds_and_never_retargets_a_saved_call() {
    for die in [false,true] {
        let (mut k,_,key)=fixture(SYS_SOCKET_RECV,1,8192);
        let before=k.fabric.scoped_pointers.total_reserved_bytes();
        let t=k.bind_socket(key,SocketRights::Duplex).unwrap();
        assert!(k.fabric.scoped_pointers.total_reserved_bytes()>before);
        k.deliver_socket(t,&[123],false).unwrap();
        if die {k.finish_process(key.slot,ProcessResult::ProtectionFault);}
        else {k.cancel_socket(t).unwrap();k.handle_syscall(0);assert_eq!(k.processes[0].core.r[0],u64::MAX);}
        assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),before);
        assert!(k.deliver_socket(t,&[1],true).is_err());
        assert!(k.bind_socket(key,SocketRights::Receive).is_err());
        assert!(k.cancel_socket(t).is_err());
    }
}
#[test]
fn s1_socket_wrong_kernel_ticket_and_unfunded_bind_cannot_route_bytes() {
    let (_,_,old)=prepared(SYS_SOCKET_RECV,1,SocketRights::Receive);
    let (mut k,_,new)=prepared(SYS_SOCKET_RECV,1,SocketRights::Receive);
    assert!(k.deliver_socket(old,&[13],true).is_err());
    assert!(k.cancel_socket(old).is_err());
    k.deliver_socket(new,&[42],true).unwrap();
    k.handle_syscall(0);assert_eq!(k.processes[0].core.r[0],1);
    let (mut denied,_,key)=fixture(SYS_SOCKET_SEND,0,1);
    let before=denied.fabric.scoped_pointers.total_reserved_bytes();
    assert!(denied.bind_socket(key,SocketRights::Send).is_err());
    assert_eq!(denied.fabric.scoped_pointers.total_reserved_bytes(),before);
    denied.handle_syscall(0);assert_eq!(denied.processes[0].core.r[0],u64::MAX);
    assert_eq!(denied.byte_output,[90]);
}

use super::super::typed_socket::SocketCapacity;
use crate::anka64::scoped_pointers::heap::{HeapError as SocketHeapError, Resource as SocketResource};

#[test]
fn s1_socket_capacity_asymmetric_queues_preserve_both_streams() {
    let (mut k,stack,key)=fixture(SYS_SOCKET_SEND,4,8192);
    let cap=SocketCapacity::new(64,4096).unwrap();
    let t=k.bind_socket_capacity(key,SocketRights::Duplex,cap).unwrap();
    let rx: Vec<u8>=(0..64).map(|i| (i+91) as u8).collect();
    k.deliver_socket(t,&rx,false).unwrap();
    assert!(k.deliver_socket(t,&[255],true).is_err());
    k.handle_syscall(0);
    assert_eq!(k.processes[0].core.r[0],4);
    for _ in 1..1024 { assert_eq!(again(&mut k,SYS_SOCKET_SEND,4),4); }
    assert_eq!(again(&mut k,SYS_SOCKET_SEND,4),SOCKET_AGAIN);
    let mut first=[0;17];
    assert_eq!(k.take_socket_tx(t,&mut first),Ok(17));
    let expected=[65,0,0,0].repeat(1024);
    assert_eq!(&first[..],&expected[..17]);
    for part in rx.chunks_exact(4) {
        assert_eq!(again(&mut k,SYS_SOCKET_RECV,4),4);
        assert_eq!(input_buffer(&k,stack).as_slice(),part);
    }
    // The rejected fragment's FIN did not close RX.
    assert_eq!(again(&mut k,SYS_SOCKET_RECV,4),SOCKET_AGAIN);
    k.deliver_socket(t,&[],true).unwrap();
    assert_eq!(again(&mut k,SYS_SOCKET_RECV,4),0);
    let mut rest=vec![0;4096];
    assert_eq!(k.take_socket_tx(t,&mut rest),Ok(4096-17));
    assert_eq!(&rest[..4096-17],&expected[17..]);
    k.close_drained_socket(t).unwrap();
}

fn capacity_peer(k:&mut Kernel, agent:AgentId, base:u64, n:u64, limit:u64) -> ProcessKey {
    let (core,_) = typed_io_test_core(&mut k.fabric,agent,base,2048,n,0,SYS_SOCKET_SEND);
    let key=k.spawn(core);
    let owner=k.processes[key.slot].core.heap_owner().unwrap();
    k.fabric.scoped_pointers.admit_owner(owner,limit).unwrap();
    key
}

#[test]
fn s1_socket_capacity_large_queue_keeps_authenticated_call_bound() {
    let (mut k,_,_)=fixture(SYS_SOCKET_SEND,4,8192);
    // The actual pointer covers 2048 bytes; only the call limit rejects 1025.
    let key=capacity_peer(&mut k,AgentId(3),0x40000,1025,16384);
    let t=k.bind_socket_capacity(key,SocketRights::Send,SocketCapacity::new(64,4096).unwrap()).unwrap();
    k.handle_syscall(key.slot);
    assert_eq!(k.processes[key.slot].core.r[0],u64::MAX);
    assert_eq!(k.socket_pending_tx(t),Ok(0));
    assert_eq!(again_at(&mut k,key.slot,SYS_SOCKET_SEND,1024),1024);
    let mut bytes=[1u8;1024];
    assert_eq!(k.take_socket_tx(t,&mut bytes),Ok(1024));
    assert_eq!(bytes[0],65);
    assert!(bytes[1..].iter().all(|b| *b==0));
}

#[test]
fn s1_socket_capacity_limits_and_owner_quota_are_atomic() {
    let (mut k,_,key)=fixture(SYS_SOCKET_SEND,4,4096);
    for (r,t) in [(0,64),(64,0),(65537,1),(1,65537),(usize::MAX,1)] {
        assert_eq!(SocketCapacity::new(r,t),Err(SocketHeapError::Configuration));
    }
    let before=k.fabric.scoped_pointers.total_reserved_bytes();
    let too_large=SocketCapacity::new(64,4096).unwrap();
    assert_eq!(k.bind_socket_capacity(key,SocketRights::Send,too_large),
        Err(SocketHeapError::Capacity(SocketResource::OwnerBytes)));
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),before);
    let small=k.bind_socket_capacity(key,SocketRights::Send,SocketCapacity::new(64,64).unwrap()).unwrap();
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes()-before,4096);
    k.cancel_socket(small).unwrap();
    assert!(k.cancel_socket(small).is_err());
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),before);
}

#[test]
fn s1_socket_capacity_peer_charge_global_denial_and_reuse_on_same_fabric() {
    let (mut k,_,a)=fixture(SYS_SOCKET_SEND,4,8192);
    let b=capacity_peer(&mut k,AgentId(3),0x40000,4,0x200000);
    let c=capacity_peer(&mut k,AgentId(4),0x80000,4,8192);
    let owner=k.processes[b.slot].core.heap_owner().unwrap();
    let reg=&mut k.fabric.scoped_pointers;
    let account=reg.heap_account(owner).unwrap();
    let before=reg.total_reserved_bytes();
    // Leave one page free. A needs two. No second socket per Kernel is assumed.
    let bulk=(0x200000-before)/4096*4096-4096;
    let b_bulk=reg.reserve_host_storage(account,bulk,reg.revision()).unwrap();
    let cap=SocketCapacity::new(64,4096).unwrap();
    assert_eq!(k.bind_socket_capacity(a,SocketRights::Duplex,cap),
        Err(SocketHeapError::Capacity(SocketResource::GlobalBytes)));
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),before+bulk);
    let reg=&mut k.fabric.scoped_pointers;
    reg.release_host_storage(b_bulk).unwrap();
    let b_live=reg.reserve_host_storage(account,1,reg.revision()).unwrap();
    let ta=k.bind_socket_capacity(a,SocketRights::Duplex,cap).unwrap();
    k.deliver_socket(ta,&[233;64],false).unwrap();
    let reg=&mut k.fabric.scoped_pointers;
    let b_more=reg.reserve_host_storage(account,1,reg.revision()).unwrap();
    assert_eq!(reg.total_reserved_bytes(),before+8192+8192);
    k.finish_process(a.slot,ProcessResult::ProtectionFault);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),before+8192);
    let tc=k.bind_socket_capacity(c,SocketRights::Duplex,cap).unwrap();
    assert!(k.deliver_socket(ta,&[1],true).is_err());
    assert!(k.cancel_socket(ta).is_err());
    assert_eq!(k.socket_pending_tx(tc),Ok(0));
    k.handle_syscall(c.slot); // C sends its own protected local
    assert_eq!(k.processes[c.slot].core.r[0],4);
    assert_eq!(again_at(&mut k,c.slot,SYS_SOCKET_RECV,4),SOCKET_AGAIN);
    k.deliver_socket(tc,&[7],true).unwrap();
    assert_eq!(again_at(&mut k,c.slot,SYS_SOCKET_RECV,4),1);
    k.cancel_socket(tc).unwrap();
    let reg=&mut k.fabric.scoped_pointers;
    for h in [b_more,b_live] {
        assert_eq!(reg.check_host_storage(h,owner,reg.revision()),Ok(1));
        reg.release_host_storage(h).unwrap();
    }
    assert_eq!(reg.total_reserved_bytes(),before);
}
