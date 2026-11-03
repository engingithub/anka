use super::*;
use crate::anka64::{cc2_fixed_point,compiler_adapter::RebuildPublicationAuthority,
    source_bundle::{SourceBundle,SourceBundleMember}};

#[test]
fn s4_tcp_persistent_driver_keeps_binding_and_does_not_replay_tx(){
    let mut d=Driver::new().unwrap();let bound=d.0.dev;
    for i in [3,7,12] {
        let rx=[i;95];let tx=[i+1;60];
        assert_eq!(d.rx(&rx).unwrap(),rx);assert_eq!(d.tx(&tx).unwrap(),tx);
        assert!(d.parked());assert_eq!(d.0.dev,bound);
    }
    d.0.k.fabric.revoke(bound.object);
    assert!(d.tx(&[55;60]).is_err());assert!(d.0.k.take_nic_tx(bound).is_none());
}
#[test]
fn s4_tcp_candidate_exact_lengths_role_and_credit(){
    let ok=ProcessResult::Exited(1);let mut r=vec![0;38+3+60];r[0]=3;r[3]=60;r[5]=3;
    assert_eq!(proposal(&ok,&r,false,3,57).unwrap().unwrap().data.len(),3);
    for (send,room,rx) in [(false,2,57),(true,3,57),(false,3,56)]{
        assert!(proposal(&ok,&r,send,room,rx).is_err());
    }
    r.push(0);assert!(proposal(&ok,&r,false,3,57).is_err());
    assert!(proposal(&ProcessResult::ProtectionFault,&[],false,FIFO,60).is_err());
    assert!(proposal(&ProcessResult::Exited(0),&[],false,FIFO,60).unwrap().is_none());
    assert!(proposal(&ProcessResult::Exited(0),&[],true,FIFO,74).is_err());
}
fn build(s:&mut RebuildService,src:&[u8],http:bool,e:&DeveloperExecutionAuthority,p:&RebuildPublicationAuthority)->u64 {
    let mut members=vec![SourceBundleMember::new("root.c",src.to_vec()).unwrap(),
        SourceBundleMember::new("stdlib.h",include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/include/stdlib.h")).to_vec()).unwrap()];
    if http{members.push(SourceBundleMember::new("http_reply.h",include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/services/net/http_reply.h")).to_vec()).unwrap());}
    let b=SourceBundle::new("root.c",members).unwrap();
    let h=s.submit(&b,0x40000,1_000_000_000,e,p).unwrap();
    let start=std::time::Instant::now();let mut last=start;
    let m=loop{
        assert!(start.elapsed().as_secs()<300,"S4 compile deadline");
        if let Some(m)=s.poll(h,e,p).unwrap(){break m;}
        if last.elapsed().as_secs()>=5{eprintln!("S4 {} compiling: {}s",if http{"HTTP"}else{"TCP"},start.elapsed().as_secs());last=std::time::Instant::now();}
    };
    s.link(&[m],e,p).unwrap()
}

#[test]
#[ignore="real NIC/TCP/socket/HTTP /alive path; one release bootstrap"]
fn s4_real_nic_tcp_http_alive(){
    let e=DeveloperExecutionAuthority::provision();let p=RebuildPublicationAuthority::provision();
    let input=DeveloperInputAuthority::provision();let socket=DeveloperSocketAuthority::provision();
    let net=DeveloperFrameAuthority::provision();
    let l=cc2_fixed_point::witness_cc2_fixed_point(Some(&e),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let mut s=RebuildService::new(&l,&e).unwrap();
    let tcp=build(&mut s,include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/services/net/tcp_session.c")),false,&e,&p);
    let http=build(&mut s,include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/services/net/httpd_socket.c")),true,&e,&p);
    let before=s.kernel.fabric.scoped_pointers.total_reserved_bytes();
    let capture=include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/examples/tcp-alive.expected"));
    let scenario=include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/examples/tcp-alive.replay"));
    let mut first_request=Vec::new();let mut syn=Vec::new();
    s.with_tcp_session(tcp,http,&e,&input,&socket,&net,|sess|{
        let mut wire=[0xa5;N];let mut at=0;let mut step=0;
        let counts=[60,0,0,0,60,0,0,0,0,0,60,128,60,0];
        for event in scenario.lines().filter(|v|!v.starts_with('#') && !v.is_empty()){
            let saved=sess.checkpoint;let used=sess.used;
            let n=if event=="serve" {
                assert!(!sess.fin,"HTTP must run before peer FIN");
                assert_eq!(&sess.fifo[..used],b"GET /alive HTTP/1.1\r\nX: \0\xff\r\n\r\n");
                sess.serve_http(&mut wire)?
            }else{
                let h=event.strip_prefix("rx ").unwrap();
                let frame=(0..h.len()).step_by(2).map(|i|u8::from_str_radix(&h[i..i+2],16).unwrap()).collect::<Vec<_>>();
                if step==0 {syn=frame.clone();}
                if step==4 {first_request=frame.clone();}
                sess.receive(&frame,&mut wire)?
            };
            assert_eq!(n,counts[step],"event {step}");
            if [1,3,5,6,7,8,9,13].contains(&step){assert_eq!(sess.checkpoint,saved);assert_eq!(sess.used,used);}
            if n!=0 {
                assert_eq!(u16::from_be_bytes(capture[at..at+2].try_into().unwrap()) as usize,n);
                assert_eq!(&wire[..n],&capture[at+2..at+2+n],"wire event {step}");at+=n+2;
            }
            if event=="serve" {
                assert_eq!(&wire[54..n],b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nAnka64 is alive.");
            }
            step+=1;
        }
        assert_eq!(step,counts.len());assert_eq!(at,capture.len());assert_eq!(sess.checkpoint[0],3);
        assert!(sess.serve_http(&mut wire).is_err());
        Ok(())
    }).unwrap();
    assert_eq!(s.kernel.fabric.scoped_pointers.total_reserved_bytes(),before);
    // A retired connection's valid data packet cannot seed a fresh conversation.
    s.with_tcp_session(tcp,http,&e,&input,&socket,&net,|sess|{
        assert_eq!(sess.receive(&first_request,&mut [0;N])?,0);assert_eq!(sess.checkpoint,[0;STATE]);
        assert_eq!(sess.used,0);
        // White-box fault injection strictly AFTER real RX. No guest state
        // checkpoint (including SYN_RCVD) can commit if the NIC rejects TX.
        let rx=sess.driver.rx(&syn)?;
        let d=sess.driver.0.dev;sess.driver.0.k.fabric.revoke(d.object);
        let mut wire=[0x9a;N];
        assert!(sess.transition(false,&rx,&mut wire).is_err());
        assert_eq!(sess.checkpoint,[0;STATE]);assert_eq!(wire,[0x9a;N]);
        assert!(sess.driver.0.k.take_nic_tx(d).is_none());Ok(())
    }).unwrap();
    assert_eq!(s.kernel.fabric.scoped_pointers.total_reserved_bytes(),before);
    for epoch in [tcp,http]{assert!(s.kernel.linked_compiler_receipt(epoch).is_ok());}
    eprintln!("S4 passed: NIC handshake, exact-once split payload, protected HTTP before FIN, exact 74-byte response inside committed TCP frame, close and refund");
}
