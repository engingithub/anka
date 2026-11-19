//! SR110 R2: consume a charged private image into one fresh, bounded live run.
//! No compiler, boot selector, durable admission, or guest-supplied grant bits.
use super::*;
use super::retrieval::RetrievedCompilerImage;
use crate::anka64::{dev_runner::{self,DevelopmentRunConfig,DevelopmentRunReport},
    dev_shell::DevelopmentArtifactRegistry,placement::PhysicalPlacementManager,
    authority_persistence::{artifact::{retrieval::StoredEnvelope,transfer::read::ReadRequest},protocol::client::Binding}};
use std::sync::{Arc,Mutex,atomic::{AtomicU64,Ordering}};
pub(crate) mod authority;
use authority::ExecuteEvidence;
const REPORT_CHARGE:u64=65536+4096;
static NEXT_BOOT:AtomicU64=AtomicU64::new(1);
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct LaunchId {pub boot:u64,pub serial:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum ReadOrigin {File(Scope),Guest{binding:Binding,request:ReadRequest}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct LaunchScope {
    pub id:LaunchId,pub owner:AllocationOwner,pub manifest:Manifest,pub origin:ReadOrigin,pub expected_revision:u64,
}
/// Fixed Kernel-lifetime ledger. Failed preflight consumes no challenge or
/// admission revision. Issued attempt IDs never rewind; completed admission
/// records retain their challenge after cleanup and cannot be replayed.
pub(crate) struct LaunchState {
    boot:u64,high:u64,revision:u64,challenge:u64,active:bool,last:Option<(LaunchScope,ExecuteEvidence)>,
}
impl Default for LaunchState {
    fn default()->Self {
        let boot=NEXT_BOOT.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|n|n.checked_add(1)).unwrap_or(0);
        Self{boot,high:0,revision:0,challenge:0,active:false,last:None}
    }
}
/// Trusted integration supplies independently authenticated CURRENT evidence.
/// All changes to execute, owner, read/dependency/provenance and clock state must
/// serialize on this same mutex. The adapter locks it from observation through
/// commit. A provider must not turn header equality or a CRC into authentication.
/// `now` is the provider's trusted monotonic authority clock, not caller time.
/// File origins require rechecking the actual service boot/ticket/read grant;
/// guest origins additionally recheck their original retained ServerLane below.
pub(crate) trait LaunchPolicy:Send {
    fn now(&mut self)->Option<u64> {None}
    fn validate_image(&mut self,_scope:LaunchScope,_image:StoredEnvelope<'_>)->Verdict {Verdict::Unknown}
    fn execute(&mut self,_scope:LaunchScope,_now:u64)->Option<ExecuteEvidence> {None}
}
fn err(e:impl std::fmt::Debug)->String {format!("{e:?}")}
struct Custody<'k> {
    image:RetrievedCompilerImage<'k>,machine:Option<HostStorageReservation>,report:Option<HostStorageReservation>,
    execution:Option<DevelopmentRunReport>,id:LaunchId,committed:bool,
}
impl Drop for Custody<'_> {
    fn drop(&mut self) {
        if let Some(run)=self.execution.as_mut() {
            crate::anka64::os::typed_socket::select::download::scrub(&mut run.byte_output);
        }
        drop(self.execution.take());
        // Any private realm has been destroyed (and its backing scrubbed) before
        // this guard drops. Release only our tokens, never another lane's token.
        for c in [&mut self.machine,&mut self.report] {
            if let Some(c)=c.take(){let _=self.image.kernel.fabric.scoped_pointers.release_host_storage(c);}
        }
        if self.committed && self.image.kernel.stored_launch.last.as_ref().is_some_and(|(s,_)|s.id==self.id) {
            self.image.kernel.stored_launch.active=false;
        }
        // image Drop scrubs the retained CS110 bytes before its own refund.
    }
}
/// Borrowed report and nonportable launch identity. No live process, capability
/// or owned output escapes. Image and report charges remain until this drops.
pub(crate) struct StoredLaunchReport<'k> {custody:Custody<'k>}
impl StoredLaunchReport<'_> {
    pub(crate) fn id(&self)->LaunchId {self.custody.id}
    pub(crate) fn execution(&self)->&DevelopmentRunReport {self.custody.execution.as_ref().unwrap()}
    #[cfg(test)]
    pub(crate) fn test_kernel(&self)->&Kernel {self.custody.image.kernel}
}
struct Realm {fabric:Fabric,image:ankald::AnkaldLinkedImage}
impl Drop for Realm {
    fn drop(&mut self) {
        self.fabric.scrub_retired_private_memory();
        crate::anka64::os::typed_socket::select::download::scrub(&mut self.image.bytes);
    }
}
impl Kernel {
    pub(crate) fn stored_launch_revision(&self)->u64 {self.stored_launch.revision}
    pub(crate) fn stored_launch_realm(&self)->u64 {self.stored_launch.boot}
}
impl<'k> RetrievedCompilerImage<'k> {
    /// Consumes private custody; even a rejected attempt cannot reuse this guard.
    /// This is synchronous, like the current linked-image runner. The enclosing
    /// Kernel, existing processes/publications and durable selection stay alive.
    pub(crate) fn launch(self,policy:&Mutex<impl LaunchPolicy>,expected_revision:u64,config:DevelopmentRunConfig)
        ->Result<StoredLaunchReport<'k>,String>
    {
        self.launch_inner(policy,expected_revision,config,None)
    }
    /// RR110 owns a single mutex for current boot, read and execute evidence.
    /// Require the EXACT retained read lane, then call its verifier directly
    /// under that same lock. No recursive locking or detached read snapshot.
    pub(crate) fn launch_shared<P:LaunchPolicy+crate::anka64::authority_persistence::protocol::client::ServerVerifier+'static>(
        self,policy:&Arc<Mutex<P>>,expected_revision:u64,config:DevelopmentRunConfig)
        ->Result<StoredLaunchReport<'k>,String>
    {
        let lane:crate::anka64::os::typed_socket::select::ServerLane=policy.clone();
        if self.read_verifier.as_ref().is_none_or(|r|!Arc::ptr_eq(r,&lane))
            || !matches!(self.origin,Some(ReadOrigin::Guest{..})) {return Err("foreign shared read/execute lane".into())}
        self.launch_inner(policy.as_ref(),expected_revision,config,Some(|p,b,r,e|
            p.verify_read(b,r)==Verdict::Valid && p.verify_download(e)==Verdict::Valid))
    }
    fn launch_inner<P:LaunchPolicy>(self,policy:&Mutex<P>,expected_revision:u64,config:DevelopmentRunConfig,
        shared:Option<fn(&mut P,Binding,ReadRequest,StoredEnvelope<'_>)->bool>)
        ->Result<StoredLaunchReport<'k>,String>
    {
        self.recheck().map_err(err)?;
        self.budget.as_ref().ok_or("missing retrieval budget")?.check().map_err(err)?;
        let envelope=self.envelope().map_err(err)?;
        let limit=if self.manifest.profile==1 {0x100000}else{0x200000};
        if envelope.entry()!=0 || envelope.code_size()!=envelope.literal_start()
            || envelope.literal_start()>=envelope.image().len()as u64 || envelope.image().len()>limit {
            return Err("stored executable geometry/profile".into())
        }
        let machine_charge=super::super::execution::machine_charge(envelope.image().len(),config).map_err(err)?;
        let state=&mut self.kernel.stored_launch;
        if state.boot==0 || state.active || state.revision!=expected_revision {return Err("stale or occupied launch lane".into())}
        state.high=state.high.checked_add(1).ok_or("launch identity exhausted")?;
        let id=LaunchId{boot:state.boot,serial:state.high};
        let scope=LaunchScope{id,owner:self.owner,manifest:self.manifest,
            origin:self.origin.ok_or("missing read origin")?,expected_revision};
        let mut custody=Custody{image:self,machine:None,report:None,execution:None,id,committed:false};
        let (_,account)=custody.image.kernel.compiler_candidate_account().map_err(err)?;
        custody.report=Some(custody.image.kernel.fabric.scoped_pointers.reserve_host_storage(account,REPORT_CHARGE,
            custody.image.kernel.fabric.scoped_pointers.revision()).map_err(err)?);
        custody.machine=Some(custody.image.kernel.fabric.scoped_pointers.reserve_host_storage(account,machine_charge,
            custody.image.kernel.fabric.scoped_pointers.revision()).map_err(err)?);
        let execution={
            // All parser/copy/placement/core allocations follow full reservation.
            let image=custody.image.envelope().map_err(err)?;
            let mut bytes=Vec::new();bytes.try_reserve_exact(image.image().len()).map_err(err)?;
            bytes.extend_from_slice(image.image());
            let mut realm=Realm{fabric:Fabric::new(0),
                image:ankald::AnkaldLinkedImage{bytes,code_size:image.code_size(),lit_start:image.literal_start(),
                    entry:image.entry(),process_slots_observed:0}};
            realm.fabric=Fabric::with_application_heap(0x1000000).map_err(err)?;
            if !realm.fabric.application_run_storage_ok(){return Err("private realm storage unavailable".into())}
            let mut placement=PhysicalPlacementManager::new(0x10000,0x700000).map_err(err)?;
            let Realm{fabric,image}=&mut realm;
            let artifact=ankald::publish_linked_image(fabric,&mut placement,"stored-live-launch",image).map_err(err)?;
            let mut registry=DevelopmentArtifactRegistry::new();
            registry.register_linked_application(fabric,&artifact).map_err(err)?;
            // A fresh child is staged by ordinary SYS_SPAWN, including protected
            // program admission. The callback is its only path to first dispatch.
            let mut admission_error=None;
            let mut admit=|| {
                let decision=(||->Result<(),String>{
                    custody.image.recheck().map_err(err)?;
                    custody.image.budget.as_mut().ok_or("missing retrieval budget")?
                        .spend(2*(scope.manifest.size.div_ceil(4096)+4097)).map_err(err)?;
                    let image=StoredEnvelope::decode(&custody.image.bytes,scope.manifest).map_err(err)?;
                    let mut p=policy.try_lock().map_err(err)?;
                    // Keep the original read lane locked too: revocation cannot
                    // race the execute decision. There is no network wait here.
                    let read_lane=custody.image.read_verifier.clone();
                    let mut reader=if shared.is_some(){None}else{match read_lane.as_ref(){Some(v)=>Some(v.try_lock().map_err(err)?),None=>None}};
                    if let ReadOrigin::Guest{binding,request}=scope.origin {
                        let valid=if let Some(check)=shared {check(&mut *p,binding,request,image)}else{
                            let r=reader.as_mut().ok_or("missing original read verifier")?;
                            r.verify_read(binding,request)==Verdict::Valid && r.verify_download(image)==Verdict::Valid
                        };
                        if !valid {return Err("current guest read evidence denied".into())}
                    }
                    if p.validate_image(scope,image)!=Verdict::Valid {return Err("current image/read/dependency evidence denied".into())}
                    let now=p.now().ok_or("authority clock unavailable")?;
                    let evidence=p.execute(scope,now).ok_or("current execute evidence denied")?;
                    if p.validate_image(scope,image)!=Verdict::Valid {return Err("image evidence revoked at commit".into())}
                    if let ReadOrigin::Guest{binding,request}=scope.origin {
                        let valid=if let Some(check)=shared {check(&mut *p,binding,request,image)}else{
                            let r=reader.as_mut().unwrap();
                            r.verify_read(binding,request)==Verdict::Valid && r.verify_download(image)==Verdict::Valid
                        };
                        if !valid {return Err("guest read evidence revoked at commit".into())}
                    }
                    // No cached authority timestamp: compare to a fresh clock
                    // observation AFTER all provider work at the commit boundary.
                    let commit_now=p.now().ok_or("authority clock unavailable")?;
                    custody.image.budget.as_ref().unwrap().check().map_err(err)?;
                    custody.image.recheck().map_err(err)?;
                    let state=&mut custody.image.kernel.stored_launch;
                    if !authority::allowed(scope,state,evidence,commit_now){return Err("T1 execute admission denied".into())}
                    // Infallible, serialized commit. Child already exists in
                    // private custody, cannot run until this callback succeeds.
                    state.revision+=1;state.challenge=evidence.context.challenge;
                    state.active=true;state.last=Some((scope,evidence));custody.committed=true;
                    Ok(())
                })();
                match decision {Ok(())=>true,Err(e)=>{admission_error=Some(e);false}}
            };
            let result=dev_runner::run_accounted_stored_application(&registry,fabric,&mut placement,config,&mut admit);
            drop(admit);
            // Realm Drop follows on every error/unwind, before custody refund.
            match result {Ok(run)=>run,Err(e)=>return Err(admission_error.unwrap_or_else(||err(e)))}
        };
        custody.execution=Some(execution);
        if custody.execution.as_ref().unwrap().byte_output.capacity()>65536 {return Err("oversized stored run output".into())}
        if let Some(c)=custody.machine {
            custody.image.kernel.fabric.scoped_pointers.release_host_storage(c).map_err(err)?;
            custody.machine=None;
        }
        Ok(StoredLaunchReport{custody})
    }
}
#[cfg(test)]
pub(crate) mod tests;
