use super::*;
use crate::anka64::{os::{select_guest_call,select_guest_fixture,SYS_SOCKET_SEND,SYS_SOCKET_RECV,
    SYS_SOCKET_SHUT_WR,typed_socket::SOCKET_AGAIN},authority_persistence::{self as ap,protocol as p}};
use std::sync::{Arc,Mutex};
use p::client::ServerVerifier;

fn envelope()->Envelope {
    Envelope{correlation:42,request:ap::Request{anchor:10,installation:20,policy:3,caller:30,
        incarnation:4,sequence:1,expected:7,operation:ap::Operation::Select,argument:99,attempt:0}}
}
// Trusted test observations; no claim that an address is an identity credential.
struct Server{live:bool,bound:Option<p::client::Binding>}
impl ServerVerifier for Server {
    fn verify(&mut self,b:p::client::Binding,e:Envelope)->ap::Verdict{
        if b.connection!=0 && b.local==LOCAL.addr() && b.remote==STORAGE.addr() && e==envelope()
            && *self.bound.get_or_insert(b)==b && self.live {ap::Verdict::Valid}
        else {ap::Verdict::Invalid}
    }
}
struct Caller;
impl p::Verifier for Caller{
    type Peer=();
    fn verify(&mut self,_:&(),r:ap::Request)->Option<(ap::Context,ap::Access)>{
        (r==envelope().request).then_some((ap::Context{anchor:10,installation:20,policy:3,challenge:71,now:100,selected:true},
            ap::Access{anchor:10,installation:20,policy:3,caller:30,incarnation:4,operation:ap::Operation::Select,
            first:90,until:110,authentic:ap::Verdict::Valid,status:ap::Verdict::Valid}))
    }
}
struct Store{state:ap::State,reads:usize,commits:usize}
impl ap::DurableRecord for Store{
    fn load(&mut self,a:u64,i:u64)->Result<ap::State,ap::Error>{assert_eq!((a,i),(10,20));self.reads+=1;Ok(self.state.clone())}
    fn commit(&mut self,a:u64,i:u64,old:&ap::State,new:&ap::State)->Result<(),ap::Error>{
        assert_eq!((a,i),(10,20));assert_eq!(old,&self.state);self.commits+=1;self.state=new.clone();Ok(())
    }
}
fn remote(seq:u32,ack:u32,flags:u8,win:u16,body:&[u8])->Vec<u8>{
    make(STORAGE,LOCAL,Segment{seq,ack,flags,window:win,body})
}
#[derive(Clone,Copy,PartialEq,Eq)]
enum Scenario{Valid,BeforeFin,BeforeReplyEof,ReplyTail}
fn exercise(case:Scenario){
    let (mut k,stack,key)=select_guest_fixture();
    let baseline=k.fabric.scoped_pointers.total_reserved_bytes();
    let env=envelope();let want=env.encode().unwrap();
    let addr=k.fabric.translate(stack,0x4000-2048).unwrap();
    let lane=Arc::new(Mutex::new(Server{live:true,bound:None}));
    let mut store=Store{state:ap::State{revision:7,value:55,boot:8,last:None},reads:0,commits:0};
    let budget=p::DispatchBudget{slots:0,slot_limit:1,bytes:0,byte_limit:384,work:512,now:100,deadline:200};
    with_guest_select(&mut k,key,SocketCapacity::new(64,128).unwrap(),env,
        lane.clone(),&DeveloperFrameAuthority::provision(),|k,s|{
        let call=|k:&mut Kernel,op,n|select_guest_call(k,key.slot,op,n);
        let syn=s.start(k)?;
        let sent=parse(LOCAL,STORAGE,&syn).unwrap();assert_eq!((sent.flags,sent.body.len()),(SYN,0));
        let mut seq=sent.seq.wrapping_add(1);let mut peer=903u32;
        assert!(s.receive(k,&remote(peer-1,seq.wrapping_sub(1),SYN|ACK,64,&[]))?.is_none());
        let mut corrupt=remote(peer-1,seq,SYN|ACK,64,&[]);corrupt[50]^=1;
        assert!(s.receive(k,&corrupt)?.is_none());
        assert_eq!(k.select_handshake(s.ticket,false,||Ok(false)),Ok(false));
        assert_eq!(call(k,SYS_SOCKET_SEND,1),u64::MAX);
        let ack=s.receive(k,&remote(peer-1,seq,SYN|ACK,64,&[]))?.unwrap();
        assert_eq!(parse(LOCAL,STORAGE,&ack).unwrap().flags,ACK);
        assert_eq!(call(k,SYS_SOCKET_SHUT_WR,0),u64::MAX);
        // Test setup seeds a real protected local; ordinary guest syscalls do the copying.
        k.fabric.write_physical(addr,&[0;112]);assert_eq!(call(k,SYS_SOCKET_SEND,112),u64::MAX);
        k.fabric.write_physical(addr,&want);assert_eq!(call(k,SYS_SOCKET_SEND,112),112);
        assert_eq!(call(k,SYS_SOCKET_SHUT_WR,0),0);
        assert_eq!(call(k,SYS_SOCKET_SEND,1),u64::MAX);
        let mut received=Vec::new();
        for n in [64,48]{
            let emitted=s.flush(k)?.unwrap();let seg=parse(LOCAL,STORAGE,&emitted).unwrap();
            assert_eq!((seg.seq,seg.ack,seg.flags,seg.body.len()),(seq,peer,PSH|ACK,n));
            received.extend_from_slice(seg.body);seq=seq.wrapping_add(n as u32);
            assert!(s.flush(k)?.is_none()); // zero peer window, including the FIN offer
            if n==64{assert!(s.receive(k,&remote(peer,seq,ACK,48,&[]))?.is_none());}
        }
        assert_eq!(received.as_slice(),want.as_slice());
        assert!(p::dispatch(&mut store,&mut Caller,&(),&received,false,budget,true).is_err());
        assert_eq!((store.reads,store.commits),(0,0));
        assert!(s.receive(k,&remote(peer,seq,ACK,1,&[]))?.is_none());
        {let _locked=lane.lock().unwrap(); assert!(s.flush(k)?.is_none()); assert!(!s.local_fin);}
        if case==Scenario::BeforeFin{
            lane.lock().unwrap().live=false;assert!(s.flush(k).is_err());
            assert!(!s.local_fin && s.driver.parked());assert_eq!((store.reads,store.commits),(0,0));return Ok(())
        }
        let emitted=s.flush(k)?.unwrap();let fin=parse(LOCAL,STORAGE,&emitted).unwrap();
        assert_eq!((fin.flags,fin.seq,fin.body.len()),(FIN|ACK,seq,0));seq=seq.wrapping_add(1);
        let reply=p::dispatch(&mut store,&mut Caller,&(),&received,fin.flags&FIN!=0,budget,true).unwrap();
        assert_eq!((store.state.revision,store.state.value,store.commits),(8,99,1));
        for part in reply.chunks(64){
            assert!(s.receive(k,&remote(peer,seq,ACK|PSH,1,part))?.is_some());peer+=part.len() as u32;
            assert_eq!(call(k,SYS_SOCKET_RECV,64),SOCKET_AGAIN);
        }
        if case==Scenario::BeforeReplyEof{lane.lock().unwrap().live=false;}
        if case==Scenario::ReplyTail{assert!(s.receive(k,&remote(peer,seq,ACK|PSH,1,&[0])).is_err());}
        if case!=Scenario::Valid{
            assert!(s.receive(k,&remote(peer,seq,FIN|ACK,1,&[])).is_err());
            assert_eq!(call(k,SYS_SOCKET_RECV,64),u64::MAX);assert_eq!(store.commits,1);return Ok(())
        }
        assert!(s.receive(k,&remote(peer,seq,FIN|ACK,1,&[]))?.is_some());
        let mut guest=Vec::new();
        for n in [64,64,16,0]{
            assert_eq!(call(k,SYS_SOCKET_RECV,64),n);
            guest.extend_from_slice(k.fabric.read_physical(addr,n));
        }
        assert_eq!(guest.as_slice(),&reply[..]);
        assert_eq!(p::Reply::decode(&guest,true,env).unwrap().outcome(),Some(ap::Outcome{revision:8,value:99,boot:8}));
        Ok(())
    }).unwrap();
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(),baseline);
}
#[test] fn g110_outbound_half_close_and_receive(){exercise(Scenario::Valid)}
#[test] fn g110_outbound_revoke_before_fin(){exercise(Scenario::BeforeFin)}
#[test] fn g110_outbound_revoke_after_commit(){exercise(Scenario::BeforeReplyEof)}
#[test] fn g110_outbound_reply_tail_is_terminal(){exercise(Scenario::ReplyTail)}
