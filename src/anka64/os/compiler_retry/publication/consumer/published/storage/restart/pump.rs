use super::*;
use super::super::super::execution::{machine_charge,LinkedCompilerRunReport};
use crate::anka64::os::application_run::{INPUT_BYTES,OUTPUT_BYTES};
pub(super) struct Pump<'a,P>{pub bootstrap:&'a Bootstrap,pub identity:BootIdentity,pub authority:&'a Arc<Mutex<Authority<P>>>}
struct Realm {fabric:Fabric,image:AnkaldLinkedImage}
impl Drop for Realm {fn drop(&mut self){
    self.fabric.scrub_retired_private_memory();
    crate::anka64::os::typed_socket::select::download::scrub(&mut self.image.bytes);
}}
impl<P:RestartEvidence> Pump<'_,P>{
    fn check(&self,k:&Kernel)->Result<(),String>{
        if k.stored_launch_realm()!=self.identity.realm{return Err("foreign bootstrap realm".into())}
        let owner=k.compiler_candidate_custodian().map_err(err)?;
        k.fabric.scoped_pointers.check_host_storage(self.bootstrap.charge,owner,k.fabric.scoped_pointers.revision()).map_err(err)?;
        let image=StoredEnvelope::decode(&self.bootstrap.bytes,self.bootstrap.manifest).map_err(err)?;
        let mut p=self.authority.try_lock().map_err(err)?;
        if p.active!=Some(self.identity) || p.current().is_none()
            || p.provider.bootstrap(self.identity,image)!=Verdict::Valid || p.current().is_none(){
            return Err("current bootstrap admission denied".into())
        }Ok(())
    }
}
impl<P:RestartEvidence> GuestReadPump for Pump<'_,P>{
    fn validation_work(&self)->u64{4*(self.bootstrap.manifest.size.div_ceil(4096)+4097)}
    fn validate(&mut self,k:&mut Kernel)->Result<(),String>{self.check(k)}
    fn run<'k>(&mut self,k:&'k mut Kernel,stream:SelectStream<'_>,config:DevelopmentRunConfig)
        ->Result<LinkedCompilerRunReport<'k>,String>{
        self.validate(k)?;
        let e=StoredEnvelope::decode(&self.bootstrap.bytes,self.bootstrap.manifest).map_err(err)?;
        let charge=machine_charge(e.image().len(),config).map_err(err)?
            .checked_add(12*1024*1024+2*INPUT_BYTES as u64+4096).ok_or("bootstrap run charge overflow")?;
        let (_,account)=k.compiler_candidate_account().map_err(err)?;
        let report=k.fabric.scoped_pointers.reserve_host_storage(account,OUTPUT_BYTES as u64+4096,k.fabric.scoped_pointers.revision()).map_err(err)?;
        let machine=match k.fabric.scoped_pointers.reserve_host_storage(account,charge,k.fabric.scoped_pointers.revision()){
            Ok(r)=>r,Err(e)=>{let _=k.fabric.scoped_pointers.release_host_storage(report);return Err(err(e))}
        };
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->Result<DevelopmentRunReport,String>{
            let mut bytes=Vec::new();bytes.try_reserve_exact(e.image().len()).map_err(err)?;
            if bytes.capacity()!=e.image().len(){return Err("bootstrap allocation capacity".into())}
            bytes.extend_from_slice(e.image());
            let mut realm=Realm{fabric:Fabric::new(0),image:AnkaldLinkedImage{bytes,code_size:e.code_size(),lit_start:e.literal_start(),entry:e.entry(),process_slots_observed:0}};
            realm.fabric=Fabric::with_application_heap(0x1000000).map_err(err)?;
            if !realm.fabric.application_run_storage_ok(){return Err("bootstrap realm unavailable".into())}
            let mut placement=PhysicalPlacementManager::new(0x10000,0x700000).map_err(err)?;
            let Realm{fabric,image}=&mut realm;
            let artifact=ankald::publish_linked_image(fabric,&mut placement,"restart-bootstrap",image).map_err(err)?;
            let mut registry=DevelopmentArtifactRegistry::new();registry.register_linked_application(fabric,&artifact).map_err(err)?;
            // Current boot/selected-pump evidence is checked AFTER the protected
            // child is constructed and BEFORE its first instruction/packet.
            let mut admitted=||self.check(k).is_ok();
            let mut run=dev_runner::run_accounted_stored_application_with_select(&registry,fabric,&mut placement,config,stream,&mut admitted).map_err(err)?;
            if run.byte_output.capacity()>OUTPUT_BYTES{
                crate::anka64::os::typed_socket::select::download::scrub(&mut run.byte_output);
                return Err("bootstrap output overflow".into())
            }Ok(run)
        }));
        // Realm Drop runs before any quota refund on error, success, or unwind.
        let result=match result{Ok(r)=>r,Err(payload)=>{
            let _=k.fabric.scoped_pointers.release_host_storage(machine);
            let _=k.fabric.scoped_pointers.release_host_storage(report);
            std::panic::resume_unwind(payload)
        }};
        let released=k.fabric.scoped_pointers.release_host_storage(machine);
        match result{
            Err(e)=>{let _=k.fabric.scoped_pointers.release_host_storage(report);Err(e)},
            Ok(mut execution)=>{
                if let Err(e)=released{
                    crate::anka64::os::typed_socket::select::download::scrub(&mut execution.byte_output);drop(execution);
                    let _=k.fabric.scoped_pointers.release_host_storage(report);return Err(err(e))
                }
                Ok(LinkedCompilerRunReport{publication_epoch:0,
                    profile:if self.bootstrap.manifest.profile==1{ApplicationLinkProfile::Standard}else{ApplicationLinkProfile::Large},
                    execution,kernel:k,reservation:Some(report)})
            }
        }
    }
}
