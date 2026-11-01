//! Ordinary trusted rebuild coordinator. No test helpers or fabricated replies.
use super::*;
use super::jobs::{CompilerJobHandle,CompilerJobProgress};
use super::inputs::{CompilerInputHandle,CompilerInputRole};
use super::publication::{PublicationInputs,publication_profile};
use crate::anka64::{ankald,cc2_fixed_point,compiler_adapter,dev_runner,source_bundle};
use crate::anka64::compiler_adapter::resources::{CompilerResourceBindings,CompilerReplyContext,OutputGrowthSupport,OutputRetryPolicy};
use crate::anka64::compiler_adapter::resources::growth::workspace::WorkspaceDirectory;
use crate::anka64::scoped_pointers::heap::{RegistryLimits,HeapPlacementLimits,HostStorageReservation};
use crate::anka64::placement::{PhysicalExtent,VirtualExtent};
use crate::anka64::fabric::HeapWorkLimits;
use crate::anka64::dev_runner::DeveloperExecutionAuthority;
use crate::anka64::compiler_adapter::RebuildPublicationAuthority;
use crate::anka64::ankald::LinkedArtifactKey;
fn error(e:impl std::fmt::Debug)->String {format!("{e:?}")}
const POOL_START:u64=0x400000;
const POOL_END:u64=0x1000000;
const MAX_OBJECTS:u32=256;
const WORK:u64=1_000_000_000;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct ServiceJobHandle {realm:u64,slot:usize,serial:u64}
struct ActiveJob {
    serial:u64,handle:CompilerJobHandle,process:ProcessKey,polls:u64,retries:u32,
    #[cfg(test)] old:(AllocationOwner,AgentId,ScopedPointer),
}
/// Boot capacities remain charged until this entire owned realm is destroyed.
/// Completed source/tool/plan objects remain immutable for receipt validation.
pub(crate) struct RebuildService {
    pub(super) kernel:Kernel,
    _storage:HostStorageReservation,
    identity:u64,cursor:u64,objects:u32,next_serial:u64,
    compiler:LinkedArtifactKey,preprocessor:LinkedArtifactKey,linker:LinkedArtifactKey,
    profile:LinkedArtifactKey,dependencies:[LinkedArtifactKey;2],
    pp:CompilerInputHandle,jobs:[Option<ActiveJob>;2],
}
impl RebuildService {
    pub(crate) fn new(lineage:&cc2_fixed_point::Cc2FixedPointWitness,
        authority:&DeveloperExecutionAuthority)->Result<Self,String> {
        let image=compiler_adapter::producer::build(lineage,authority).map_err(error)?;
        let (cc,pp,ld)=lineage.application_tools().map_err(error)?;
        let (mut k,storage,identity)=realm()?;
        let compiler=k.configure_compiler_admission(&image,0x10000,2,Some(authority)).map_err(error)?;
        let pp_handle=k.ingest_compiler_input(CompilerInputRole::Tool,&pp.bytes).map_err(error)?;
        let mut cursor=POOL_START;let mut objects=0;
        let preprocessor=seal(&mut k,&mut cursor,&mut objects,&pp.bytes)?;
        let linker=seal(&mut k,&mut cursor,&mut objects,&ld.bytes)?;
        let profile=seal(&mut k,&mut cursor,&mut objects,&publication_profile())?;
        let dependencies=[seal(&mut k,&mut cursor,&mut objects,&cc.bytes)?,
            seal(&mut k,&mut cursor,&mut objects,compiler_adapter::producer::SOURCE)?];
        Ok(Self {kernel:k,_storage:storage,identity,cursor,objects,next_serial:1,
            compiler,preprocessor,linker,profile,dependencies,pp:pp_handle,jobs:[None,None]})
    }
    pub(crate) fn submit(&mut self,bundle:&source_bundle::SourceBundle,initial_output:u64,
        work:u64,execution:&DeveloperExecutionAuthority,publication:&RebuildPublicationAuthority)
        ->Result<ServiceJobHandle,String> {
        let slot=self.jobs.iter().position(Option::is_none).ok_or("two compiler jobs already active")?;
        if work==0 || work>WORK {return Err("invalid finite work budget".into());}
        let serial=self.next_serial;self.next_serial=serial.checked_add(1).ok_or("service serial exhausted")?;
        let bundle_bytes=canonical_bundle(bundle)?;
        let bundle_key=seal(&mut self.kernel,&mut self.cursor,&mut self.objects,&bundle_bytes)?;
        drop(bundle_bytes);
        let policy=source_bundle::PreprocessGrowthPolicy::new(65536,1048576,8,WORK).map_err(error)?;
        let source=self.kernel.preprocess_compiler_source(&self.pp,bundle,policy,Some(execution)).map_err(error)?;
        let mut process=None;
        let result=(||->Result<ActiveJob,String> {
            let n=self.kernel.compiler_input(&source.input,CompilerInputRole::EffectiveSource).map_err(error)?.len();
            let source_key=seal_input(&mut self.kernel,&mut self.cursor,&mut self.objects,&source.input)?;
            let mut budget=OutputRetryPolicy::new(0x100000,8,work).map_err(error)?.start(
                CompilerReplyContext::new(serial,1,CompilerResourceBindings{
                    source:binding_id(source_key.object)?,tools:binding_id(self.compiler.object)?,profile:binding_id(self.profile.object)?,
                    dependencies:binding_id(self.dependencies[0].object)?,plan:serial},n as u64,initial_output,
                    OutputGrowthSupport::CompilerOutput).map_err(error)?).map_err(error)?;
            let directory=WorkspaceDirectory::new([128,256,64,64,32,128,128],0x100000).map_err(error)?;
            budget.bind_workspace(Some(directory)).map_err(error)?;
            let (plan,n)=plan_bytes(budget.publication_plan_words(),Some(directory.binding_words()));
            let plan=seal(&mut self.kernel,&mut self.cursor,&mut self.objects,&plan[..n])?;
            let key=self.kernel.admit_compiler_process(Some(execution)).map_err(error)?;process=Some(key);
            let attempt=self.kernel.load_compiler_request_from_input(key,budget,&source.input).map_err(error)?;
            #[cfg(test)] let old=(attempt.owner,attempt.agent,attempt.output);
            let inputs=PublicationInputs{bundle:bundle_key,source:source_key,compiler:self.compiler,
                preprocessor:self.preprocessor,linker:self.linker,profile:self.profile,plan,
                dependencies:self.dependencies.to_vec()};
            let handle=self.kernel.begin_compiler_job_from_input(attempt,inputs,&source.input,Some(publication)).map_err(error)?;
            Ok(ActiveJob{serial,handle,process:key,polls:0,retries:0,#[cfg(test)] old})
        })();
        let discarded=self.kernel.discard_compiler_input(&source.input).map_err(error);
        match result {
            Ok(job)=>{
                self.jobs[slot]=Some(job);
                let h=ServiceJobHandle{realm:self.identity,slot,serial};
                if let Err(e)=discarded {let _=self.cancel(h);return Err(e);}
                Ok(h)
            },
            Err(e)=>{if let Some(p)=process {let _=self.retire(p,true);} Err(e)},
        }
    }
    fn check(&self,h:ServiceJobHandle)->Result<(),String> {
        if h.realm!=self.identity || self.jobs.get(h.slot).and_then(Option::as_ref)
            .is_none_or(|j|j.serial!=h.serial) {return Err("stale or foreign service job".into());}Ok(())
    }
    fn retire(&mut self,key:ProcessKey,abort:bool)->Result<(),String> {
        if abort && self.kernel.processes.get(key.slot).is_some_and(|p|p.generation==key.generation && !p.exited()) {
            self.kernel.finish_process(key.slot,ProcessResult::ProtectionFault);
        }
        for _ in 0..65536 {
            match self.kernel.retire_admitted_compiler(key) {
                Ok(())=>return Ok(()),
                Err(super::admission::CompilerAdmissionError::Busy)=>{self.kernel.advance_heap_cleanup();},
                Err(e)=>return Err(error(e)),
            }
        }
        Err("cleanup incomplete; compiler slot remains charged and quarantined".into())
    }
    pub(crate) fn cancel(&mut self,h:ServiceJobHandle)->Result<(),String> {
        self.check(h)?;let j=self.jobs[h.slot].take().unwrap();
        let cancelled=self.kernel.cancel_compiler_job(&j.handle).map_err(error);
        let retired=self.retire(j.process,true);cancelled.and(retired)
    }
    /// One bounded compile slice; different handles may be polled round-robin.
    /// Success consumes the handle, leaving the published artifact in custody.
    pub(crate) fn poll(&mut self,h:ServiceJobHandle,execution:&DeveloperExecutionAuthority,
        publication:&RebuildPublicationAuthority)->Result<Option<u64>,String> {
        self.check(h)?;let mut j=self.jobs[h.slot].take().unwrap();
        let result=(||->Result<Option<u64>,String> {
            j.polls=j.polls.checked_add(1).ok_or("poll counter exhausted")?;
            if j.polls>WORK/256+65536 {return Err("finite coordinator budget exhausted".into());}
            match self.kernel.advance_compiler_job(&j.handle,256,Some(publication)).map_err(error)? {
                CompilerJobProgress::Running=>Ok(None),
                CompilerJobProgress::NeedsProcess=>{
                    let (w,d)=self.kernel.compiler_job_retry_plan(&j.handle).map_err(error)?;
                    let (bytes,n)=plan_bytes(w,d);
                    let plan=seal(&mut self.kernel,&mut self.cursor,&mut self.objects,&bytes[..n])?;
                    self.retire(j.process,false)?;
                    j.process=self.kernel.admit_compiler_process(Some(execution)).map_err(error)?;
                    self.kernel.resume_compiler_job(&j.handle,j.process,plan,Some(publication)).map_err(error)?;
                    j.retries+=1;Ok(None)
                },
                CompilerJobProgress::Published(epoch)=>{
                    self.kernel.cancel_compiler_job(&j.handle).map_err(error)?;
                    self.retire(j.process,false)?;Ok(Some(epoch))
                },
                CompilerJobProgress::Closed=>Err("compiler job closed without publication".into()),
            }
        })();
        match result {
            Ok(None)=>{self.jobs[h.slot]=Some(j);Ok(None)},
            Ok(Some(e))=>Ok(Some(e)),
            Err(e)=>{let _=self.kernel.cancel_compiler_job(&j.handle);let _=self.retire(j.process,true);Err(e)},
        }
    }
    pub(crate) fn run(&mut self,epoch:u64,execution:&DeveloperExecutionAuthority,
        output:impl FnOnce(&[u8])->Result<(),String>)->Result<ProcessResult,String> {
        let report=self.kernel.run_linked_compiler_publication(epoch,Some(execution),
            dev_runner::DevelopmentRunConfig::default()).map_err(error)?;
        output(&report.execution().byte_output)?;
        Ok(report.execution().child_result.clone())
    }
    pub(crate) fn run_with_input(&mut self,epoch:u64,execution:&DeveloperExecutionAuthority,
        input_authority:&dev_runner::DeveloperInputAuthority,input:&[u8],
        output:impl FnOnce(&[u8])->Result<(),String>)->Result<ProcessResult,String> {
        let report=self.kernel.run_linked_compiler_publication_with_input(epoch,Some(execution),
            Some(input_authority),input,dev_runner::DevelopmentRunConfig::default()).map_err(error)?;
        output(&report.execution().byte_output)?;
        Ok(report.execution().child_result.clone())
    }
    pub(crate) fn link(&mut self,epochs:&[u64],execution:&DeveloperExecutionAuthority,
        publication:&RebuildPublicationAuthority)->Result<u64,String> {
        let prior=self.kernel.compiler_publication_epoch();
        self.kernel.borrow_compiler_publication_modules(epochs,ankald::ApplicationLinkProfile::Large)
            .map_err(error)?.link(Some(execution)).map_err(error)?.publish(prior,Some(publication)).map_err(error)
    }
}
fn realm()->Result<(Kernel,HostStorageReservation,u64),String> {
        let fabric=Fabric::with_private_heap_cpu_work(0x4000000,
            // Two CPU-only jobs each have a bounded local-frame allowance.
            // Heap identities retain 4096 slots of headroom. with_limits charges
            // the actual retained table capacities before either job is admitted.
            RegistryLimits{slots:2*super::admission::COMPILER_LOCAL_LIMIT+4096,
                scopes:4096,owners:64,cleanup:512,global_bytes:0x20000000},
            HeapPlacementLimits{physical_pool:PhysicalExtent{base:0x1000000,size:0x2000000},physical_claims:512,
                virtual_window:VirtualExtent{base:0x40000000,size:0x2000000},per_owner_claims:128},
            1,HeapWorkLimits{tickets:16,requests:16}).map_err(error)?;
        let mut k=Kernel::new(fabric);k.enable_heap_service(0x10000000).map_err(error)?;
        let (owner,account)=k.compiler_candidate_account().map_err(error)?;
        if owner.context==0 {return Err("zero service identity".into());}
        // Fixed RAM + bounded provenance/grant/job metadata + canonical bundle
        // staging. Shared heap and compiler arena retain their separate charges.
        let storage=k.fabric.scoped_pointers.reserve_host_storage(account,70*1024*1024,
            k.fabric.scoped_pointers.revision()).map_err(error)?;
        Ok((k,storage,owner.context))
}
// ObjectId(0) is valid; ABI binding labels are required to be nonzero.
// These checked labels identify frozen records and confer no authority.
fn binding_id(object:ObjectId)->Result<u64,String> {
    object.0.checked_add(1).ok_or_else(||"binding identity exhausted".into())
}
fn plan_bytes(words:[u64;22],directory:Option<[u64;35]>)->([u8;456],usize) {
    let mut bytes=[0;456];let mut n=0;
    for w in words.into_iter().chain(directory.into_iter().flatten()) {
        bytes[n..n+8].copy_from_slice(&w.to_le_bytes());n+=8;
    }(bytes,n)
}
fn allocate(k:&mut Kernel,cursor:&mut u64,objects:&mut u32,n:usize)->Result<LinkedArtifactKey,String> {
    if *cursor<POOL_START || *cursor%4096!=0 || n==0 || n>1048576 || *objects>=MAX_OBJECTS {return Err("provenance capacity exceeded".into());}
    let at=*cursor;let end=at.checked_add((n as u64+4095)&!4095).filter(|&e|e<=POOL_END)
        .ok_or("provenance backing exhausted")?;
    // Monotonic prepaid arena: even failed attempts cannot reuse old evidence.
    *cursor=end;*objects+=1;
    let object=k.fabric.try_alloc_object("rebuild-provenance",n as u64,ObjectKind::Memory).ok_or("object identity exhausted")?;
    if !k.fabric.place_object(object,at) || !k.fabric.zero_object_extent(object) {
        k.fabric.destroy_object(object);return Err("provenance placement denied".into());
    }
    Ok(LinkedArtifactKey{object,generation:k.fabric.objects[&object].generation})
}
fn finish_seal(k:&mut Kernel,key:LinkedArtifactKey)->Result<LinkedArtifactKey,String> {
    let owner=k.compiler_candidate_custodian().map_err(error)?;
    let size=k.fabric.objects[&key.object].size;
    if !k.fabric.seal_object(key.object) || k.fabric.grant(owner.domain,key.object,0,size,Permissions::READ).is_none() {
        k.fabric.destroy_object(key.object);return Err("sealed provenance grant denied".into());
    }
    Ok(LinkedArtifactKey{generation:k.fabric.objects[&key.object].generation,..key})
}
fn seal(k:&mut Kernel,cursor:&mut u64,objects:&mut u32,bytes:&[u8])->Result<LinkedArtifactKey,String> {
    let key=allocate(k,cursor,objects,bytes.len())?;
    if !k.fabric.initialize_object(key.object,0,bytes) {k.fabric.destroy_object(key.object);return Err("provenance initialization denied".into());}
    finish_seal(k,key)
}
fn seal_input(k:&mut Kernel,cursor:&mut u64,objects:&mut u32,h:&CompilerInputHandle)->Result<LinkedArtifactKey,String> {
    let n=k.compiler_input(h,CompilerInputRole::EffectiveSource).map_err(error)?.len();
    let key=allocate(k,cursor,objects,n)?;let mut scratch=[0;4096];
    for offset in (0..n).step_by(4096) {
        let len=(n-offset).min(4096);
        scratch[..len].copy_from_slice(&k.compiler_input(h,CompilerInputRole::EffectiveSource).map_err(error)?[offset..offset+len]);
        if !k.fabric.initialize_object(key.object,offset as u64,&scratch[..len]) {
            k.fabric.destroy_object(key.object);return Err("source initialization denied".into());
        }
    }finish_seal(k,key)
}
fn canonical_bundle(bundle:&source_bundle::SourceBundle)->Result<Vec<u8>,String> {
    let mut n=16usize.checked_add(bundle.root_name().len()).ok_or("bundle overflow")?;
    for m in bundle.members() {n=n.checked_add(16).and_then(|n|n.checked_add(m.logical_name().len()))
        .and_then(|n|n.checked_add(m.bytes().len())).ok_or("bundle overflow")?;}
    if bundle.len()>256 || n>1048576 {return Err("canonical bundle exceeds publication policy".into());}
    let mut out=Vec::new();out.try_reserve_exact(n).map_err(error)?;
    if out.capacity()>n {return Err("bundle capacity exceeds reservation".into());}
    fn field(out:&mut Vec<u8>,b:&[u8]) {out.extend_from_slice(&(b.len() as u64).to_le_bytes());out.extend_from_slice(b);}
    field(&mut out,bundle.root_name().as_bytes());out.extend_from_slice(&(bundle.len() as u64).to_le_bytes());
    for m in bundle.members() {field(&mut out,m.logical_name().as_bytes());field(&mut out,m.bytes());}Ok(out)
}
#[cfg(test)]
mod tests;
