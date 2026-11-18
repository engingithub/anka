use super::*;
use super::super::download::{DownloadConfig,DownloadTransport,DownloadConnection};
use crate::anka64::{authority_persistence::{artifact::transfer::read::ReadRequest,protocol::client::{DenyServer,ServerVerifier},artifact::retrieval::RetrievalLimits},
    dev_runner::{DeveloperExecutionAuthority,DeveloperInputAuthority,DevelopmentRunConfig},
    os::typed_socket::select::ServerLane,os::compiler_retry::service::frame_port::DeveloperFrameAuthority};
use std::{sync::{Arc,Mutex},time::Duration};
struct NoTransport{calls:usize}
impl DownloadTransport for NoTransport{
    fn connect(&mut self,_:ReadRequest)->Result<DownloadConnection<'_>,String>{self.calls+=1;Err("no transport".into())}
}
fn config()->DownloadConfig{DownloadConfig{limits:RetrievalLimits{max_bytes:2*1024*1024,work:100000,timeout:Duration::from_secs(10)},window:4096,retries:0,run:DevelopmentRunConfig::default()}}
fn manifest(k:&mut Kernel,e:u64)->Manifest{Envelope::new(k.linked_compiler_receipt(e).unwrap().image,ApplicationLinkProfile::Standard,identity(),&[dependency()]).unwrap().manifest}
#[test]
fn gd110_kernel_quota_denial_before_transport_refunds_private_reservation(){
    let(mut k,_,e)=fixture();let m=manifest(&mut k,e);let before=charge(&k);let(_,account)=k.compiler_candidate_account().unwrap();
    // Enough room for private bytes/decoder, but not for socket/session scratch.
    let filler=k.fabric.scoped_pointers.reserve_host_storage(account,256*1024*1024-before-m.size-32768-1024,k.fabric.scoped_pointers.revision()).unwrap();
    let filled=charge(&k);let mut transport=NoTransport{calls:0};
    assert!(k.download_stored_compiler_image(e,m,&DeveloperExecutionAuthority::provision(),&DeveloperInputAuthority::provision(),
        &DeveloperFrameAuthority::provision(),Arc::new(Mutex::new(DenyServer)),&mut transport,config()).is_err());
    assert_eq!(transport.calls,0);assert_eq!(charge(&k),filled);k.fabric.scoped_pointers.release_host_storage(filler).unwrap();
    assert_eq!(charge(&k),before);assert!(k.linked_compiler_receipt(e).is_ok());
}
#[test]
fn gd110_kernel_connect_failure_preserves_independent_charge_and_publications(){
    let(mut k,_,e)=fixture();let m=manifest(&mut k,e);let(_,account)=k.compiler_candidate_account().unwrap();
    let peer=k.fabric.scoped_pointers.reserve_host_storage(account,4096,k.fabric.scoped_pointers.revision()).unwrap();let before=charge(&k);
    let mut transport=NoTransport{calls:0};let v:ServerLane=Arc::new(Mutex::new(DenyServer));
    assert!(k.download_stored_compiler_image(e,m,&DeveloperExecutionAuthority::provision(),&DeveloperInputAuthority::provision(),
        &DeveloperFrameAuthority::provision(),v,&mut transport,DownloadConfig{retries:2,..config()}).is_err());
    assert_eq!(transport.calls,3);assert_eq!(charge(&k),before);assert_eq!(k.compiler_publication_epoch(),e);
    k.fabric.scoped_pointers.release_host_storage(peer).unwrap();
}
#[test]
fn gd110_kernel_provider_size_panic_before_open_refunds_image(){
    // A poisoned authority lane is rejected before transport, with private
    // reservation cleanup. In-run and final provider panics use the real witness.
    struct Policy;impl ServerVerifier for Policy{}
    let(mut k,_,e)=fixture();let m=manifest(&mut k,e);let before=charge(&k);let v=Arc::new(Mutex::new(Policy));
    let _=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{let _lock=v.lock().unwrap();panic!("injected poisoned read lane")}));
    let mut transport=NoTransport{calls:0};assert!(k.download_stored_compiler_image(e,m,&DeveloperExecutionAuthority::provision(),
        &DeveloperInputAuthority::provision(),&DeveloperFrameAuthority::provision(),v,&mut transport,config()).is_err());
    assert_eq!(transport.calls,0);assert_eq!(charge(&k),before);
}
