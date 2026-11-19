use super::*;
use crate::anka64::os::compiler_retry::publication::consumer::{stored_restart::{Authority,RestartGuest,tests::{Policy as BootPolicy,Memory,initial,request}},DownloadConfig,DownloadTransport,DownloadConnection};
use crate::anka64::dev_runner::{DeveloperInputAuthority,DevelopmentRunConfig};
use crate::anka64::os::compiler_retry::service::frame_port::DeveloperFrameAuthority;
use crate::anka64::authority_persistence::{Request,DurableRecord};
use std::sync::{Arc,Mutex};
fn fixture()->(Temp,ArtifactStore,Arc<Mutex<Authority<BootPolicy>>>,Memory,Request){
    let(k,_,t,s,p)=exported();drop(k);
    let bytes=Arc::new(p.bytes);let lane=Arc::new(Mutex::new(Authority::new(BootPolicy::new(p.manifest,bytes.clone(),p.manifest,bytes))));
    let mut head=initial(p.manifest.artifact);let r=request(&head.state,72);
    lane.lock().unwrap().reserve(&mut head,r).unwrap();(t,s,lane,head,r)
}
fn manifest(lane:&Arc<Mutex<Authority<BootPolicy>>>)->Manifest{lane.lock().unwrap().update(|p|p.bootstrap_manifest)}
#[test]
fn rr110_boot_opens_fresh_accounted_kernel_without_compiler_receipts(){
    let(t,mut store,lane,mut head,r)=fixture();let m=manifest(&lane);let record=fs::read(t.0.join("artifact.record")).unwrap();
    let before=head.state.clone();let mut guest=RestartGuest::open(&mut head,r,&mut store,m,caller(),read_limits(),lane.clone()).unwrap();
    assert_eq!(guest.identity().boot,1);assert_eq!(guest.identity().selected,m.artifact);assert_ne!(guest.identity().realm,0);
    assert_eq!(guest.launch_revision(),0);assert_eq!(guest.test_kernel().compiler_publication_epoch(),0);
    assert!(charge(guest.test_kernel())>=70*1024*1024+m.size+32768);
    assert_eq!(head.state,before);assert_eq!(fs::read(t.0.join("artifact.record")).unwrap(),record);
    assert!(lane.lock().unwrap().reserve(&mut head,r).is_err());drop(guest);
}
#[test]
fn rr110_boot_each_freshness_binding_denies_before_payload_inspection(){
    for fault in 1..=12{let(_t,mut store,lane,mut head,r)=fixture();let m=manifest(&lane);let before=head.state.clone();
        lane.lock().unwrap().update(|p|p.boot_fault=fault);
        assert!(RestartGuest::open(&mut head,r,&mut store,m,caller(),read_limits(),lane.clone()).is_err(),"fault {fault}");
        assert_eq!(lane.lock().unwrap().update(|p|p.inspections),0);assert_eq!(head.state,before);
        assert_eq!(lane.lock().unwrap().update(|p|p.consumed),0);
    }
}
#[test]
fn rr110_boot_replay_and_rolled_back_record_cannot_restore_guest(){
    let(_t,mut store,lane,mut head,r)=fixture();let m=manifest(&lane);let saved=head.state.clone();
    let guest=RestartGuest::open(&mut head,r,&mut store,m,caller(),read_limits(),lane.clone()).unwrap();let old=guest.identity();drop(guest);
    head.state=saved.clone();assert!(RestartGuest::open(&mut head,r,&mut store,m,caller(),read_limits(),lane.clone()).is_err());
    lane.lock().unwrap().update(|p|p.attempt=73);let fresh=request(&head.state,73);
    lane.lock().unwrap().reserve(&mut head,fresh).unwrap();
    let mut new=RestartGuest::open(&mut head,fresh,&mut store,m,caller(),read_limits(),lane.clone()).unwrap();
    assert_eq!(new.identity().boot,old.boot+1);assert_ne!(new.identity().realm,old.realm);assert_ne!(new.identity().attempt,old.attempt);
    assert_eq!(new.test_kernel().compiler_publication_epoch(),0);drop(new);
    // Restore the old store AND local challenge, while the external fixture's
    // consumed-attempt record remains outside that rollback.
    head.state=saved;lane.lock().unwrap().update(|p|p.attempt=72);
    assert!(RestartGuest::open(&mut head,r,&mut store,m,caller(),read_limits(),lane.clone()).is_err());
}
#[test]
fn rr110_boot_corrupt_file_and_revoked_bootstrap_leave_reservation_intact(){
    for corrupt in [false,true]{let(t,mut store,lane,mut head,r)=fixture();let m=manifest(&lane);let before=head.state.clone();
        if corrupt{let path=t.0.join("artifact.bytes");let mut b=fs::read(&path).unwrap();let i=b.len()-1;b[i]^=1;fs::write(path,b).unwrap();}
        else{lane.lock().unwrap().update(|p|p.bootstrap_valid=false);}
        assert!(RestartGuest::open(&mut head,r,&mut store,m,caller(),read_limits(),lane.clone()).is_err());
        assert_eq!(head.state,before);assert_eq!(lane.lock().unwrap().update(|p|p.consumed),0);
    }
}
#[test]
fn rr110_boot_provider_unwind_poison_prevents_redispatch(){
    let(_t,mut store,lane,mut head,r)=fixture();let m=manifest(&lane);let before=head.state.clone();
    lane.lock().unwrap().update(|p|p.panic_bootstrap=true);
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{let _=RestartGuest::open(&mut head,r,&mut store,m,caller(),read_limits(),lane.clone());}));
    assert!(result.is_err());assert!(lane.is_poisoned());assert_eq!(head.state,before);
    assert!(RestartGuest::open(&mut head,r,&mut store,m,caller(),read_limits(),lane.clone()).is_err());
}
struct NoTransport {calls:usize}
impl DownloadTransport for NoTransport {
    fn connect(&mut self,_:crate::anka64::authority_persistence::artifact::transfer::read::ReadRequest)->Result<DownloadConnection<'_>,String>{
        self.calls+=1;Err("injected no connection".into())
    }
}
#[test]
fn rr110_boot_revocation_and_failed_download_preserve_peer_and_boot_record(){
    let(_t,mut store,lane,mut head,r)=fixture();let m=manifest(&lane);let before=head.state.clone();
    let mut guest=RestartGuest::open(&mut head,r,&mut store,m,caller(),read_limits(),lane.clone()).unwrap();
    let k=guest.test_kernel();let(_,account)=k.compiler_candidate_account().unwrap();
    let peer=k.fabric.scoped_pointers.reserve_host_storage(account,4096,k.fabric.scoped_pointers.revision()).unwrap();let baseline=charge(k);
    let config=DownloadConfig{limits:read_limits(),window:4096,retries:1,run:DevelopmentRunConfig::default()};
    let input=DeveloperInputAuthority::provision();let net=DeveloperFrameAuthority::provision();
    let mut transport=NoTransport{calls:0};assert!(guest.download(m,&input,&net,&mut transport,config).is_err());
    assert_eq!(transport.calls,2);assert_eq!(charge(guest.test_kernel()),baseline);assert_eq!(head.state,before);
    lane.lock().unwrap().update(|p|p.valid=false);transport.calls=0;
    assert!(guest.download(m,&input,&net,&mut transport,config).is_err());assert_eq!(transport.calls,0);
    assert_eq!(charge(guest.test_kernel()),baseline);assert_eq!(guest.launch_revision(),0);
    guest.test_kernel().fabric.scoped_pointers.release_host_storage(peer).unwrap();
}
#[test]
fn rr110_shared_launch_cannot_substitute_a_different_read_lane(){
    let(mut k,_,_t,mut store,mut p)=exported();let before=charge(&k);
    let bytes=Arc::new(p.bytes.clone());let lane=Arc::new(Mutex::new(Authority::new(BootPolicy::new(p.manifest,bytes.clone(),p.manifest,bytes))));
    let view=k.retrieve_stored_compiler_image(&mut store,p.manifest,caller(),read_limits(),&mut p).unwrap();
    assert!(view.launch_shared(&lane,0,DevelopmentRunConfig::default()).is_err());
    assert_eq!(charge(&k),before);assert_eq!(k.stored_launch_revision(),0);
}
