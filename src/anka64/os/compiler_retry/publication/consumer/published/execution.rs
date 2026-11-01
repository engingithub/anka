//! Current linked receipt -> charged isolated realm -> charged output guard.
use super::*;
use crate::anka64::dev_runner::{self, DevelopmentRunConfig, DevelopmentRunReport};
use crate::anka64::dev_shell::DevelopmentArtifactRegistry;
use crate::anka64::placement::PhysicalPlacementManager;
use crate::anka64::os::application_run::{OUTPUT_BYTES,INPUT_BYTES};
use crate::anka64::dev_runner::DeveloperInputAuthority;
const INPUT_CHARGE:u64=2*INPUT_BYTES as u64+4096;
const REPORT_CHARGE:u64=OUTPUT_BYTES as u64+4096;

/// The borrowed result keeps output quota alive. No owned output Vec can be
/// extracted from this interface; drop destroys it before refund. Its artifact
/// key belongs to the destroyed isolated realm, not the shared Kernel.
pub(crate) struct LinkedCompilerRunReport<'k> {
    pub(crate) publication_epoch:u64,
    pub(crate) profile:ApplicationLinkProfile,
    execution:DevelopmentRunReport,
    kernel:&'k mut Kernel,
    reservation:Option<HostStorageReservation>,
}
impl LinkedCompilerRunReport<'_> {
    pub(crate) fn execution(&self)->&DevelopmentRunReport {&self.execution}
}
impl Drop for LinkedCompilerRunReport<'_> {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.execution.byte_output));
        if let Some(r)=self.reservation.take() {
            let _=self.kernel.fabric.scoped_pointers.release_host_storage(r);
        }
    }
}
fn machine_charge(image:usize,config:DevelopmentRunConfig)->Result<u64,CompilerLinkError> {
    let d=DevelopmentRunConfig::default();
    if image==0 || image>0x200000 || config.quantum==0 || config.max_rounds==0
        || config.quantum>d.quantum || config.max_rounds>d.max_rounds
        || config.quantum.checked_mul(config.max_rounds).is_none()
        || config.virtual_limit==0 || config.virtual_limit>0x1000000
        || config.supervisor_stack_size==0 || config.supervisor_stack_size>65536
        || config.child_stack_size==0 || config.child_stack_size>65536 {
        return Err(CompilerLinkError::Binding);
    }
    // Reserve the ENTIRE 64-MiB isolated registry quota, including its fixed
    // tables, heap/shadow/work storage and payload budget, before construction.
    // Separate allowances: 16-MiB RAM, 16-MiB bounded nonheap state (three
    // processes, stacks/cells, trace and output staging), 32*image for parser,
    // registry and core program copies. Conservative quota, not host RSS.
    Ok(96*1024*1024+32*image as u64)
}
impl Kernel {
    pub(crate) fn run_linked_compiler_publication(&mut self,epoch:u64,
        authority:Option<&DeveloperExecutionAuthority>,config:DevelopmentRunConfig)
        ->Result<LinkedCompilerRunReport<'_>,CompilerLinkError> {
        self.run_linked_compiler_publication_inner(epoch,authority,config,None)
    }
    pub(crate) fn run_linked_compiler_publication_with_input(&mut self,epoch:u64,
        authority:Option<&DeveloperExecutionAuthority>,input_authority:Option<&DeveloperInputAuthority>,
        input:&[u8],config:DevelopmentRunConfig)->Result<LinkedCompilerRunReport<'_>,CompilerLinkError> {
        let input_authority=input_authority.ok_or(CompilerLinkError::Authority)?;
        if input.len()>INPUT_BYTES {return Err(CompilerLinkError::Binding);}
        self.run_linked_compiler_publication_inner(epoch,authority,config,Some((input_authority,input)))
    }
    fn run_linked_compiler_publication_inner(&mut self,epoch:u64,
        authority:Option<&DeveloperExecutionAuthority>,config:DevelopmentRunConfig,
        input:Option<(&DeveloperInputAuthority,&[u8])>)
        ->Result<LinkedCompilerRunReport<'_>,CompilerLinkError> {
        let authority=authority.ok_or(CompilerLinkError::Authority)?;
        self.validate_linked_compiler_publication(epoch)?;
        let record=&self.compiler_publications.links[&epoch];
        let image=record.image.as_ref().ok_or(CompilerLinkError::Binding)?;
        let profile=record.profile;
        let limit=match profile {ApplicationLinkProfile::Standard=>0x100000,ApplicationLinkProfile::Large=>0x200000};
        if image.entry!=0 || image.code_size==0 || image.lit_start!=image.code_size
            || image.lit_start>=image.bytes.len() as u64 || image.bytes.len() as u64>limit {
            return Err(CompilerLinkError::Binding);
        }
        let charge=machine_charge(image.bytes.len(),config)?.checked_add(if input.is_some(){INPUT_CHARGE}else{0})
            .ok_or(CompilerLinkError::Binding)?;
        let (_,account)=self.compiler_candidate_account()?;
        let report=self.fabric.scoped_pointers.reserve_host_storage(account,REPORT_CHARGE,
            self.fabric.scoped_pointers.revision())?;
        let machine=match self.fabric.scoped_pointers.reserve_host_storage(account,charge,
            self.fabric.scoped_pointers.revision()) {
            Ok(r)=>r,
            Err(e)=>{let _=self.fabric.scoped_pointers.release_host_storage(report);return Err(e.into());}
        };
        let result=(||->Result<DevelopmentRunReport,CompilerLinkError> {
            let image=self.compiler_publications.links[&epoch].image.as_ref().ok_or(CompilerLinkError::Binding)?;
            let mut fabric=Fabric::with_application_heap(0x1000000)?;
            if !fabric.application_run_storage_ok() {return Err(CompilerLinkError::Storage);}
            let mut placement=PhysicalPlacementManager::new(0x10000,0x700000)
                .map_err(|_|CompilerLinkError::Binding)?;
            let artifact=ankald::publish_linked_image(&mut fabric,&mut placement,
                "compiler-publication-run",image).map_err(CompilerLinkError::Executable)?;
            let mut registry=DevelopmentArtifactRegistry::new();
            registry.register_linked_application(&fabric,&artifact).map_err(CompilerLinkError::Register)?;
            let run=match input {
                Some((input_authority,bytes))=>dev_runner::run_accounted_c_application_with_input(
                    &registry,authority,Some(input_authority),&mut fabric,&mut placement,config,bytes),
                None=>dev_runner::run_accounted_c_application(&registry,authority,&mut fabric,&mut placement,config),
            }.map_err(CompilerLinkError::Run)?;
            if run.byte_output.capacity()>OUTPUT_BYTES {return Err(CompilerLinkError::Storage);}
            Ok(run)
        })();
        // The closure has destroyed Fabric, placement, registry and all CPU /
        // cleanup state, including on timeout/fault. No device exists to retain
        // an external borrow. Report output has a separate live reservation.
        let released=self.fabric.scoped_pointers.release_host_storage(machine);
        match result {
            Err(e)=>{let _=self.fabric.scoped_pointers.release_host_storage(report);Err(e)},
            Ok(execution)=>{
                if let Err(e)=released {
                    drop(execution);
                    let _=self.fabric.scoped_pointers.release_host_storage(report);
                    return Err(e.into());
                }
                Ok(LinkedCompilerRunReport {publication_epoch:epoch,profile,execution,
                    kernel:self,reservation:Some(report)})
            }
        }
    }
}
#[cfg(test)]
mod tests;
