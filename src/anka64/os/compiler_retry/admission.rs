//! Prepaid, CPU-only compiler admission arena. Fixed capacity is retained for
//! this Kernel's lifetime, like fixed heap metadata; retiring a process does
//! not refund storage which the arena still owns. No caller physical writes.
use super::*;
use crate::anka64::ankald::{AnkaldLinkedImage,LinkedArtifactKey};
use crate::anka64::dev_runner::DeveloperExecutionAuthority;
use crate::anka64::pointer_frames::ValidatedPointerProgram;
use crate::anka64::scoped_pointers::heap::HostStorageReservation;
pub(crate) const COMPILER_LOCAL_LIMIT:usize=16384;
const STACK:u64=0x100000;
const STACK_VA:u64=0x1000000;
#[derive(Debug)]
pub(crate) enum CompilerAdmissionError {Authority,Configured,Geometry,Storage,Busy,Stale,Heap(HeapError)}
impl From<HeapError> for CompilerAdmissionError {fn from(e:HeapError)->Self {Self::Heap(e)}}
struct Slot {object:Option<ObjectId>,base:u64,process:Option<ProcessKey>}
pub(crate) struct CompilerAdmission {
    reservation:HostStorageReservation,owner:AllocationOwner,charge:u64,
    code:LinkedArtifactKey,code_size:u64,program:ValidatedPointerProgram,slots:Vec<Slot>,
}
impl Kernel {
    /// Trusted boot configuration selects disjoint backing. Fabric validates
    /// every placement against ALL objects and the private heap pool. The
    /// reservation precedes parsing, object allocation, copying and execution.
    pub(crate) fn configure_compiler_admission(&mut self,image:&AnkaldLinkedImage,
        base:u64,slots:usize,authority:Option<&DeveloperExecutionAuthority>)
        ->Result<LinkedArtifactKey,CompilerAdmissionError> {
        authority.ok_or(CompilerAdmissionError::Authority)?;
        if self.compiler_admission.is_some() {return Err(CompilerAdmissionError::Configured);}
        if slots==0 || slots>8 || base%4096!=0 || image.entry!=0
            || image.code_size==0 || image.lit_start!=image.code_size
            || image.bytes.len()>0x100000 || image.code_size>=image.bytes.len() as u64
            || self.fabric.timer.is_some() || !self.device_registry.devices.is_empty()
            || self.fabric.agents.values().any(|a|!matches!(a.kind,AgentKind::Cpu(_))) {
            return Err(CompilerAdmissionError::Geometry);
        }
        let code_size=(image.code_size+16+4095)&!4095;
        let end=base.checked_add(code_size).and_then(|b|b.checked_add(STACK*slots as u64))
            .filter(|&n|n<=self.fabric.mem_size() as u64).ok_or(CompilerAdmissionError::Geometry)?;
        // Payload plus conservative bounded parser/program/core metadata. This
        // is service quota, not an allocator RSS measurement. Retained arena
        // capacity remains charged even when all process slots are idle.
        let charge=(end-base)+(slots as u64+1)*(8*image.bytes.len() as u64+0x200000);
        let (owner,account)=self.compiler_candidate_account()?;
        let reservation=self.fabric.scoped_pointers.reserve_host_storage(account,charge,
            self.fabric.scoped_pointers.revision())?;
        let mut objects=Vec::new();
        let build=(|| {
            let program=ValidatedPointerProgram::from_image(&image.bytes[..image.code_size as usize],
                &image.bytes[image.lit_start as usize..]).map_err(|_|CompilerAdmissionError::Geometry)?
                .ok_or(CompilerAdmissionError::Geometry)?;
            let mut arena_slots=Vec::new();
            arena_slots.try_reserve_exact(slots).map_err(|_|CompilerAdmissionError::Storage)?;
            for i in 0..=slots {
                let size=if i==0 {code_size}else{STACK};
                let at=if i==0 {base}else{base+code_size+(i-1)as u64*STACK};
                let object=self.fabric.try_alloc_object("compiler-admission",size,ObjectKind::Memory)
                    .ok_or(CompilerAdmissionError::Storage)?;
                objects.push(object);
                if !self.fabric.place_object(object,at) || !self.fabric.zero_object_extent(object) {
                    return Err(CompilerAdmissionError::Geometry);
                }
                if i>0 {arena_slots.push(Slot{object:Some(object),base:at,process:None});}
            }
            let object=objects[0];
            if !self.fabric.initialize_object(object,0,&image.bytes[..image.code_size as usize]) {
                return Err(CompilerAdmissionError::Storage);
            }
            crate::anka64::guest_compiler::install_trap_handler(&mut self.fabric,base,code_size);
            if !self.fabric.seal_object(object) {return Err(CompilerAdmissionError::Storage);}
            self.fabric.grant(owner.domain,object,0,code_size,Permissions::READ)
                .ok_or(CompilerAdmissionError::Storage)?;
            let code=LinkedArtifactKey{object,generation:self.fabric.objects[&object].generation};
            Ok(CompilerAdmission{reservation,owner,charge,code,code_size,program,slots:arena_slots})
        })();
        match build {
            Ok(arena)=>{let code=arena.code;self.compiler_admission=Some(arena);Ok(code)},
            Err(error)=>{
                // No runnable process or exported authority exists on failure.
                for object in objects {self.fabric.destroy_object(object);}
                self.fabric.scoped_pointers.release_host_storage(reservation)?;
                Err(error)
            }
        }
    }
    pub(super) fn check_compiler_admission(&self)->Result<(),CompilerAdmissionError> {
        let a=self.compiler_admission.as_ref().ok_or(CompilerAdmissionError::Stale)?;
        if self.compiler_candidate_custodian()?!=a.owner
            || self.fabric.scoped_pointers.check_host_storage(a.reservation,a.owner,
                self.fabric.scoped_pointers.revision())?!=a.charge
            || self.fabric.objects.get(&a.code.object).is_none_or(|o|
                o.generation!=a.code.generation || o.state!=ObjectState::Sealed)
            || self.fabric.timer.is_some() || !self.device_registry.devices.is_empty()
            || self.fabric.agents.values().any(|a|!matches!(a.kind,AgentKind::Cpu(_))) {
            return Err(CompilerAdmissionError::Stale);
        }
        Ok(())
    }
    pub(crate) fn admit_compiler_process(&mut self,authority:Option<&DeveloperExecutionAuthority>)
        ->Result<ProcessKey,CompilerAdmissionError> {
        authority.ok_or(CompilerAdmissionError::Authority)?;self.check_compiler_admission()?;
        let a=self.compiler_admission.as_ref().unwrap();
        let index=a.slots.iter().position(|s|s.process.is_none()).ok_or(CompilerAdmissionError::Busy)?;
        let code=a.code;let size=a.code_size;let base=a.slots[index].base;
        let stack=a.slots[index].object.ok_or(CompilerAdmissionError::Storage)?;
        if self.fabric.translate(stack,0)!=Some(base) || !self.fabric.zero_object_extent(stack) {
            return Err(CompilerAdmissionError::Storage);
        }
        let agent=AgentId(self.fabric.agents.keys().map(|a|a.0).max().unwrap_or(0)
            .checked_add(1).ok_or(CompilerAdmissionError::Storage)?);
        self.next_pid.checked_add(1).ok_or(CompilerAdmissionError::Storage)?;
        let domain=self.fabric.try_create_compiler_domain().ok_or(CompilerAdmissionError::Storage)?;
        self.fabric.register_agent(agent,AgentKind::Cpu(CoreId(0)),domain);
        let result=(|| {
            self.fabric.grant(domain,code.object,0,size,Permissions::RX).ok_or(CompilerAdmissionError::Storage)?;
            self.fabric.grant(domain,stack,0,STACK,Permissions::RW).ok_or(CompilerAdmissionError::Storage)?;
            let mut core=Anka64Core::new(agent,domain);
            core.address_map.add(0,size,code.object);core.trap_vector=size-16;
            core.address_map.add(STACK_VA,STACK,stack);
            let program=self.compiler_admission.as_ref().unwrap().program.clone();
            core.admit_pointer_program(&mut self.fabric,program,0,STACK_VA,STACK_VA+STACK)
                .map_err(|_|CompilerAdmissionError::Geometry)?;
            Ok(core)
        })();
        match result {
            Ok(core)=>{let key=self.spawn(core);
                self.compiler_admission.as_mut().unwrap().slots[index].process=Some(key);Ok(key)},
            Err(error)=>{self.fabric.agents.remove(&agent);self.fabric.destroy_domain(domain);Err(error)}
        }
    }
    /// Explicit post-cleanup reuse. Does not cancel a running producer, consume
    /// its retry budget, drop published code, or refund the retained arena.
    pub(crate) fn retire_admitted_compiler(&mut self,key:ProcessKey)
        ->Result<(),CompilerAdmissionError> {
        self.check_compiler_admission()?;
        let a=self.compiler_admission.as_ref().unwrap();
        let index=a.slots.iter().position(|s|s.process==Some(key)).ok_or(CompilerAdmissionError::Stale)?;
        let p=self.processes.get(key.slot).filter(|p|p.generation==key.generation)
            .ok_or(CompilerAdmissionError::Stale)?;
        let owner=AllocationOwner{process:key,context:p.core.context_identity(),domain:p.core.domain};
        if !p.exited() || !self.fabric.compiler_heap_owner_released(owner)
            || !self.fabric.compiler_provenance_quiescent() {return Err(CompilerAdmissionError::Busy);}
        let agent=p.core.agent;let domain=p.core.domain;
        let base=a.slots[index].base;let object=a.slots[index].object.ok_or(CompilerAdmissionError::Storage)?;
        self.reclaim_process(key.slot);
        // Drop all saved event/register/frame copies before backing reuse.
        self.processes[key.slot].core=Anka64Core::new(agent,domain);
        self.processes[key.slot].cap_table=None;
        self.fabric.agents.remove(&agent);self.fabric.destroy_domain(domain);
        self.fabric.destroy_object(object);
        let slot=&mut self.compiler_admission.as_mut().unwrap().slots[index];
        slot.object=None; // on any later failure this slot stays quarantined
        let fresh=self.fabric.try_alloc_object("compiler-admission-stack",STACK,ObjectKind::Memory)
            .ok_or(CompilerAdmissionError::Storage)?;
        if !self.fabric.place_object(fresh,base) || !self.fabric.zero_object_extent(fresh) {
            self.fabric.destroy_object(fresh);return Err(CompilerAdmissionError::Storage);
        }
        let slot=&mut self.compiler_admission.as_mut().unwrap().slots[index];
        slot.object=Some(fresh);slot.process=None;Ok(())
    }
    pub(crate) fn compiler_admission_contains(&self,key:ProcessKey)->bool {
        self.compiler_admission.as_ref().is_some_and(|a|a.slots.iter().any(|s|s.process==Some(key)))
    }
}
#[cfg(test)]
mod tests;
