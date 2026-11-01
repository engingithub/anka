//! Kernel-owned compiler jobs. Admission supplies a fresh protected process and
//! sealed plan; it cannot replace the retained source, tools or retry ledger.
//! This composes existing gates; preprocessor/process admission is still separate.
use super::*;
use super::flow::{CompilerFlowError,CompilerFlowProgress,CompilerPublicationFlow};
use super::inputs::{CompilerInputError,CompilerInputHandle};
use super::publication::{PublicationError,PublicationInputs,PublicationKey};
use crate::anka64::ankald::LinkedArtifactKey;
use crate::anka64::compiler_adapter::{RebuildAdmissionRole,RebuildPublicationAuthority};
use crate::anka64::scoped_pointers::heap::HostStorageReservation;
use std::collections::BTreeMap;

#[derive(Debug)]
pub(crate) enum CompilerJobError {
    Unknown, State, Storage, Authority,
    Heap(HeapError), Input(CompilerInputError), Publication(PublicationError), Flow(CompilerFlowError),
}
impl From<HeapError> for CompilerJobError {fn from(e:HeapError)->Self {Self::Heap(e)}}
impl From<CompilerInputError> for CompilerJobError {fn from(e:CompilerInputError)->Self {Self::Input(e)}}
impl From<PublicationError> for CompilerJobError {fn from(e:PublicationError)->Self {Self::Publication(e)}}
impl From<CompilerFlowError> for CompilerJobError {fn from(e:CompilerFlowError)->Self {Self::Flow(e)}}

#[derive(Debug)]
pub(crate) struct CompilerJobHandle {reservation:HostStorageReservation,custodian:AllocationOwner}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub(crate) enum CompilerJobProgress {Running,NeedsProcess,Published(u64),Closed}
enum Stage {Running(CompilerPublicationFlow),NeedsProcess(OutputRetryBudget),Published(u64),Closed}
struct Job {
    reservation:HostStorageReservation,custodian:AllocationOwner,charge:u64,
    source:Option<CompilerInputHandle>, inputs:PublicationInputs,
    pin:Option<PublicationKey>, stage:Stage,
}
#[derive(Default)]
pub(crate) struct CompilerJobs {records:BTreeMap<u64,Job>}
impl Job {
    fn progress(&self)->CompilerJobProgress {match &self.stage {
        Stage::Running(_)=>CompilerJobProgress::Running,
        Stage::NeedsProcess(_)=>CompilerJobProgress::NeedsProcess,
        Stage::Published(e)=>CompilerJobProgress::Published(*e),Stage::Closed=>CompilerJobProgress::Closed,
    }}
}

impl Kernel {
    fn check_compiler_job(&self,h:&CompilerJobHandle)->Result<(),CompilerJobError> {
        let j=self.compiler_jobs.records.get(&h.reservation.incarnation())
            .filter(|j|j.reservation==h.reservation && j.custodian==h.custodian)
            .ok_or(CompilerJobError::Unknown)?;
        if self.compiler_candidate_custodian().map_err(|_|CompilerJobError::Unknown)?!=j.custodian
            || self.fabric.scoped_pointers.check_host_storage(j.reservation,j.custodian,
                self.fabric.scoped_pointers.revision())?!=j.charge {return Err(CompilerJobError::Unknown);}
        Ok(())
    }

    /// Takes custody of an unstarted loaded attempt. On failure after taking
    /// custody, close that producer; peers and existing publications survive.
    /// Caller input is only borrowed ingress. Its retained copy is quota charged.
    pub(crate) fn begin_compiler_job(&mut self,attempt:CompilerOutputAttempt,
        inputs:PublicationInputs,source:&[u8],authority:Option<&RebuildPublicationAuthority>)
        -> Result<CompilerJobHandle,CompilerJobError> {
        let owner=attempt.owner;
        let preflight=(|| {
            authority.ok_or(CompilerJobError::Authority)?;
            if inputs.dependencies.len()>4096 || inputs.dependencies.capacity()>4096
                || source.len()>crate::anka64::compiler_adapter::resources::growth::workspace::DIRECTORY_SOURCE_LIMIT {
                return Err(CompilerJobError::Storage);
            }
            let (custodian,account)=self.compiler_candidate_account()?;
            let charge=(std::mem::size_of::<Job>() as u64).checked_add(4096)
                .and_then(|n|n.checked_add(inputs.dependencies.capacity() as u64*
                    std::mem::size_of::<LinkedArtifactKey>() as u64)).ok_or(CompilerJobError::Storage)?;
            let reservation=self.fabric.scoped_pointers.reserve_host_storage(account,charge,
                self.fabric.scoped_pointers.revision())?;
            Ok((custodian,charge,reservation))
        })();
        let (custodian,charge,reservation)=match preflight {Ok(x)=>x,Err(e)=>{
            if self.compiler_owner(owner.process).ok()==Some(owner) {
                self.finish_process(owner.process.slot,ProcessResult::ProtectionFault);
            }return Err(e)
        }};
        let h=CompilerJobHandle {reservation,custodian};
        let mut j=Job {reservation,custodian,charge,source:None,inputs,pin:None,stage:Stage::Closed};
        let result=(|| ->Result<(),CompilerJobError> {
            let mut flow=self.begin_compiler_publication_flow(attempt,&j.inputs,
                RebuildAdmissionRole::RelocatableModule,self.compiler_publication_epoch(),authority)?;
            j.pin=Some(flow.retain_retry_provenance());j.stage=Stage::Running(flow);
            self.recheck_compiler_job_pin(j.pin.unwrap(),Some(source))?;
            j.source=Some(self.ingest_compiler_directory_source(source)?);
            Ok(())
        })();
        if let Err(e)=result {
            let _=self.close_compiler_job_record(&mut j);
            // Keep failed refunds/cancellation in Kernel custody, not lost locals.
            if self.refund_compiler_job_record(&mut j).is_err() {
                self.compiler_jobs.records.insert(reservation.incarnation(),j);
            }
            return Err(e);
        }
        self.compiler_jobs.records.insert(reservation.incarnation(),j);
        Ok(h)
    }

    pub(crate) fn compiler_job_status(&self,h:&CompilerJobHandle)->Result<CompilerJobProgress,CompilerJobError> {
        self.check_compiler_job(h)?;Ok(self.compiler_jobs.records[&h.reservation.incarnation()].progress())
    }

    /// Read-only planning information. The non-Clone retry budget stays private
    /// to the job; callers cannot reset work, exchange sources, or replay it.
    pub(crate) fn compiler_job_retry_plan(&self,h:&CompilerJobHandle)
        ->Result<([u64;22],Option<[u64;35]>),CompilerJobError> {
        self.check_compiler_job(h)?;
        let Stage::NeedsProcess(b)=&self.compiler_jobs.records[&h.reservation.incarnation()].stage
            else {return Err(CompilerJobError::State)};
        Ok((b.publication_plan_words(),b.workspace_directory().map(|d|d.binding_words())))
    }

    pub(crate) fn advance_compiler_job(&mut self,h:&CompilerJobHandle,quantum:usize,
        authority:Option<&RebuildPublicationAuthority>)->Result<CompilerJobProgress,CompilerJobError> {
        self.check_compiler_job(h)?;
        let id=h.reservation.incarnation();let mut j=self.compiler_jobs.records.remove(&id).unwrap();
        let result=(|| ->Result<CompilerJobProgress,CompilerJobError> {
            let Stage::Running(flow)=&mut j.stage else {return Ok(j.progress())};
            match self.advance_compiler_publication_flow(flow,quantum,authority)? {
                CompilerFlowProgress::Pending=>{},
                CompilerFlowProgress::Retry(b)=>{
                    self.recheck_compiler_job_pin(j.pin.ok_or(CompilerJobError::State)?,None)?;
                    j.stage=Stage::NeedsProcess(b);
                },
                CompilerFlowProgress::Published(epoch)=>{
                    // Publication now owns the frozen evidence. Job disposal may
                    // not delete it or refund artifact/receipt storage.
                    j.pin=None;j.stage=Stage::Published(epoch);
                    if let Some(source)=&j.source {self.discard_compiler_input(source)?;j.source=None;}
                },
            }
            Ok(j.progress())
        })();
        if result.is_err() {let _=self.close_compiler_job_record(&mut j);}
        self.compiler_jobs.records.insert(id,j);result
    }

    /// Fresh process admission stays explicit. Only the next plan key changes;
    /// every other input and the actual retry budget comes from retained custody.
    /// Preflight denial leaves the waiting job and caller-owned process untouched.
    /// Once loading starts, a failure closes the new producer and the job.
    pub(crate) fn resume_compiler_job(&mut self,h:&CompilerJobHandle,key:ProcessKey,
        plan:LinkedArtifactKey,authority:Option<&RebuildPublicationAuthority>)
        ->Result<(),CompilerJobError> {
        self.check_compiler_job(h)?;authority.ok_or(CompilerJobError::Authority)?;
        let id=h.reservation.incarnation();
        let j=&self.compiler_jobs.records[&id];
        if !matches!(&j.stage,Stage::NeedsProcess(_)) {return Err(CompilerJobError::State);}
        let pin=j.pin.ok_or(CompilerJobError::State)?;
        let compiler=j.inputs.compiler;
        self.recheck_compiler_job_pin(pin,None)?;
        // Check the process identity before consuming the only carried budget.
        let owner=self.compiler_owner(key).map_err(|_|CompilerJobError::State)?;
        let core=&self.processes[key.slot].core;
        if self.fabric.scoped_pointers.heap_account(owner).is_some()
            || !self.processes[key.slot].is_schedulable()
            || core.compiler_publication_entry(&self.fabric).is_none_or(|(_,o,g,_,_)|
                compiler!=(LinkedArtifactKey {object:o,generation:g})) {
            return Err(CompilerJobError::State);
        }
        let mut j=self.compiler_jobs.records.remove(&id).unwrap();
        let Stage::NeedsProcess(budget)=std::mem::replace(&mut j.stage,Stage::Closed) else {unreachable!()};
        let result=(|| ->Result<(),CompilerJobError> {
            let source=j.source.as_ref().ok_or(CompilerJobError::State)?;
            let a=self.load_compiler_request_from_input(key,budget,source)?;
            j.inputs.plan=plan;
            let mut flow=self.begin_compiler_publication_flow(a,&j.inputs,
                RebuildAdmissionRole::RelocatableModule,self.compiler_publication_epoch(),authority)?;
            // Old and new snapshots overlap in the shared quota at this peak.
            let next_pin=flow.retain_retry_provenance();
            j.stage=Stage::Running(flow);
            if let Err(e)=self.discard_compiler_job_pin(pin) {
                // The old pin stays recorded if its refund fails. Cancel the
                // new flow before returning; its own Kernel tombstone is kept.
                if let Stage::Running(f)=&mut j.stage {let _=self.cancel_compiler_publication_flow(f);}
                return Err(e.into());
            }
            j.pin=Some(next_pin);Ok(())
        })();
        if result.is_err() {let _=self.close_compiler_job_record(&mut j);}
        self.compiler_jobs.records.insert(id,j);result
    }

    fn close_compiler_job_record(&mut self,j:&mut Job)->Result<(),CompilerJobError> {
        let stage=std::mem::replace(&mut j.stage,Stage::Closed);
        let flow=match stage {Stage::Running(mut f)=>self.cancel_compiler_publication_flow(&mut f),_=>Ok(())};
        // Try all independent disposals. Any failed pin/source refund stays
        // charged, readable only through the existing authenticated mechanisms.
        let pin=if let Some(p)=j.pin {self.discard_compiler_job_pin(p)} else {Ok(())};
        if pin.is_ok() {j.pin=None;}
        let source=if let Some(s)=&j.source {self.discard_compiler_input(s)} else {Ok(())};
        if source.is_ok() {j.source=None;}
        // Completed means a flow already cancelled itself after a failure.
        if let Err(e)=flow {if !matches!(e,CompilerFlowError::Completed) {return Err(e.into());}}
        pin?;source?;Ok(())
    }
    fn refund_compiler_job_record(&mut self,j:&mut Job)->Result<(),CompilerJobError> {
        if !matches!(&j.stage,Stage::Closed) || j.pin.is_some() || j.source.is_some() {return Err(CompilerJobError::State);}
        drop(std::mem::take(&mut j.inputs.dependencies));
        self.fabric.scoped_pointers.release_host_storage(j.reservation)?;Ok(())
    }
    pub(crate) fn cancel_compiler_job(&mut self,h:&CompilerJobHandle)->Result<(),CompilerJobError> {
        self.check_compiler_job(h)?;
        let id=h.reservation.incarnation();let mut j=self.compiler_jobs.records.remove(&id).unwrap();
        let closed=self.close_compiler_job_record(&mut j);
        let result=if closed.is_ok() {self.refund_compiler_job_record(&mut j)} else {closed};
        if result.is_err() {self.compiler_jobs.records.insert(id,j);}
        result
    }
    fn discard_compiler_job_records(&mut self,owner:Option<AllocationOwner>)->bool {
        // No temporary list allocation during death/shutdown. Producer closure
        // re-enters this hook with a different owner; remove before invoking it.
        let mut after=None;
        loop {
            let id=self.compiler_jobs.records.iter().find(|(id,j)|after.is_none_or(|a|**id>a)
                && owner.is_none_or(|o|j.custodian==o)).map(|(id,_)|*id);
            let Some(id)=id else {break};after=Some(id);
            let mut j=self.compiler_jobs.records.remove(&id).unwrap();
            let closed=self.close_compiler_job_record(&mut j);
            if closed.is_err() || self.refund_compiler_job_record(&mut j).is_err() {
                self.compiler_jobs.records.insert(id,j);
            }
        }
        !self.compiler_jobs.records.values().any(|j|owner.is_none_or(|o|j.custodian==o))
    }
    pub(crate) fn discard_compiler_jobs_owned_by(&mut self,owner:AllocationOwner) {self.discard_compiler_job_records(Some(owner));}
    pub(crate) fn discard_all_compiler_jobs(&mut self)->bool {self.discard_compiler_job_records(None)}
}

#[cfg(test)]
mod tests;
