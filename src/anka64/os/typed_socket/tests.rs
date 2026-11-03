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
    let c=&mut k.processes[0].core;
    c.write_register(0,number); c.write_register(1,0);
    c.write_register(4,n); c.write_register(5,0);
    c.enter_event(EventFrame{return_pc:c.pc,return_privilege:Privilege::User,
        interrupts_were_enabled:true,cause:EventCause::Syscall});
    k.handle_syscall(0);
    k.processes[0].core.r[0]
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
