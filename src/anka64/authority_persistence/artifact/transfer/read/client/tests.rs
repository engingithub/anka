use super::*;
use super::super::tests::{fixture,request,Server};
fn client(work:u64)->ReadClient {ReadClient::new(request(),work,Duration::from_secs(10),32768).unwrap()}
#[test]
fn ar110_client_fragmented_reply_waits_for_real_eof() {
    let(_t,mut s,mut p,mut b)=fixture();let mut c=client(1000);let mut e=Server{valid:true};c.begin(7,&mut e).unwrap();
    let mut frame=Vec::new();for off in (0..HEADER).step_by(23){frame.extend_from_slice(c.request_fragment(7,off,(HEADER-off).min(23),&mut e).unwrap());}
    let reply=dispatch_read(&mut s,7,&frame,true,&mut b,&mut p).unwrap();
    for chunk in reply.bytes().chunks(17){assert!(!c.receive(7,chunk,false,&mut e).unwrap());}
    assert!(matches!(c.payload(&mut e),Err(Error::Conflict)));assert!(c.receive(7,&[],true,&mut e).unwrap());assert_eq!(c.payload(&mut e).unwrap(),&p.bytes[4096..8192]);
}
#[test]
fn ar110_client_default_denial_and_revocation_stop_request_suffix() {
    struct Deny;impl ReadServerEvidence for Deny {}
    let mut c=client(100);assert!(c.begin(7,&mut Deny).is_err());assert_eq!(c.state,State::Closed);
    let mut c=client(100);let mut e=Server{valid:true};c.begin(7,&mut e).unwrap();assert_eq!(c.request_fragment(7,0,64,&mut e).unwrap().len(),64);
    e.valid=false;assert!(c.request_fragment(7,64,64,&mut e).is_err());assert!(c.frame.iter().all(|b|*b==0));
}
#[test]
fn ar110_client_lost_reply_retry_preserves_scope_work_and_deadline() {
    let mut c=client(100);let mut e=Server{valid:true};c.begin(7,&mut e).unwrap();let deadline=c.deadline;
    c.receive(7,&[1,2,3],false,&mut e).unwrap();let before=c.remaining();c.retry(8,&mut e).unwrap();assert_eq!(c.remaining(),before-1);assert_eq!(c.deadline,deadline);assert_eq!(c.received,0);
    assert_eq!(c.request,ReadRequest{correlation:78,..request()});assert!(c.reply.iter().all(|b|*b==0));
    assert!(c.receive(7,&[],true,&mut e).is_err());assert_eq!(c.state,State::Closed);
}
#[test]
fn ar110_client_retry_cannot_reset_exhaustion_deadline_or_wrap() {
    let mut e=Server{valid:true};let mut c=client(1);c.begin(7,&mut e).unwrap();assert!(matches!(c.retry(8,&mut e),Err(Error::Capacity)));
    let mut c=client(10);c.begin(7,&mut e).unwrap();c.deadline=Instant::now();assert!(matches!(c.retry(8,&mut e),Err(Error::ExpiredRequest)));
    let mut c=ReadClient::new(ReadRequest{correlation:u64::MAX,..request()},10,Duration::from_secs(10),32768).unwrap();c.begin(7,&mut e).unwrap();assert!(matches!(c.retry(8,&mut e),Err(Error::Exhausted)));
}
#[test]
fn ar110_client_eof_revocation_tail_and_stale_echo_fail_closed() {
    let(_t,mut s,mut p,mut b)=fixture();let reply=dispatch_read(&mut s,7,&encode_read(request()).unwrap(),true,&mut b,&mut p).unwrap();
    let mut e=Server{valid:true};let mut c=client(100);c.begin(7,&mut e).unwrap();for x in reply.bytes().chunks(2048){c.receive(7,x,false,&mut e).unwrap();}e.valid=false;
    assert!(c.receive(7,&[],true,&mut e).is_err());assert!(c.reply.iter().all(|b|*b==0));
    e.valid=true;let mut c=client(100);c.begin(7,&mut e).unwrap();for x in reply.bytes().chunks(2048){c.receive(7,x,false,&mut e).unwrap();}assert!(c.receive(7,&[0],true,&mut e).is_err());
    let mut c=client(100);c.begin(7,&mut e).unwrap();c.retry(8,&mut e).unwrap();for x in reply.bytes().chunks(2048){c.receive(8,x,false,&mut e).unwrap();}assert!(c.receive(8,&[],true,&mut e).is_err());
}
#[test]
fn ar110_client_complete_result_rechecks_authority_and_cannot_retry() {
    let(_t,mut s,mut p,mut b)=fixture();let reply=dispatch_read(&mut s,7,&encode_read(request()).unwrap(),true,&mut b,&mut p).unwrap();
    let mut e=Server{valid:true};let mut c=client(100);c.begin(7,&mut e).unwrap();for x in reply.bytes().chunks(2048){c.receive(7,x,false,&mut e).unwrap();}c.receive(7,&[],true,&mut e).unwrap();
    assert_eq!(c.payload(&mut e).unwrap().len(),4096);e.valid=false;assert!(c.payload(&mut e).is_err());
    assert!(c.retry(8,&mut e).is_err());assert!(ReadClient::new(request(),10,Duration::from_secs(1),32767).is_err());
}
