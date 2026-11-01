//! Bounded receipt-authorized application realm; never a general OS policy.
use super::*;
pub(crate) const OUTPUT_BYTES:usize=65536;
pub(crate) const INPUT_BYTES:usize=65536;
pub(crate) const IO_CHUNK:usize=4096;
const TRACE:usize=16384;
pub(super) struct ApplicationRunEnvelope { pub(super) spawned:bool }
pub(crate) fn output_fits(used:usize,count:u64)->bool {
    used<=OUTPUT_BYTES && count<=IO_CHUNK as u64 && count<=(OUTPUT_BYTES-used) as u64
}
impl Kernel {
    pub(crate) fn prepare_application_run(&mut self)->Result<(),()> {
        // Init, cleanup worker, then exactly one child via ordinary SYS_SPAWN.
        if self.application_run.is_some() || self.processes.len()!=2
            || !self.is_heap_service_process(1) || self.processes[0].core.protected_application()
            || !self.byte_output.is_empty() || self.fabric.timer.is_some()
            || !self.device_registry.devices.is_empty() {return Err(());}
        self.byte_output.try_reserve_exact(OUTPUT_BYTES).map_err(|_|())?;
        if self.byte_output.capacity()>OUTPUT_BYTES {return Err(());}
        self.fabric.prepare_preprocessor_trace(TRACE)?;
        self.application_run=Some(ApplicationRunEnvelope{spawned:false});
        Ok(())
    }
    pub(super) fn application_run_step_ok(&mut self,idx:usize)->bool {
        self.processes.len()<=3 && self.fabric.timer.is_none()
            && self.device_registry.devices.is_empty()
            && self.fabric.agents.values().all(|a|matches!(a.kind,AgentKind::Cpu(_)))
            && self.processes[idx].core.compiler_admission_depth_ok()
            && self.fabric.collect_application_run_trace(TRACE)
            && self.byte_output.capacity()<=OUTPUT_BYTES
    }
    pub(super) fn application_run_syscall_allowed(&mut self,idx:usize)->bool {
        if self.processes[idx].core.protected_application() {
            return self.processes[idx].core.protected_syscall_image().is_some_and(|(w,_)|
                matches!(w[0],SYS_EXIT|SYS_WRITE|SYS_READ_BYTES|SYS_MALLOC|SYS_FREE));
        }
        if idx!=0 {return false;}
        match self.processes[idx].core.r[R0 as usize] {
            SYS_EXIT|SYS_WAIT=>true,
            SYS_SPAWN=>{
                let e=self.application_run.as_mut().unwrap();
                if e.spawned || self.processes.len()!=2 {return false;}
                e.spawned=true;true
            },
            _=>false,
        }
    }
}
#[cfg(test)]
mod tests;
