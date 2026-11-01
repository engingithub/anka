//! Restricted CPU-only preprocessing transport. No syscall may grow objects,
//! process tables, mailboxes, device ledgers or host output buffers.
use super::*;
pub(crate) const PREPROCESS_SLICE:usize=256;
pub(crate) const PREPROCESS_CALLS:usize=1024;
pub(crate) const PREPROCESS_TRANSACTIONS:usize=PREPROCESS_SLICE*4;

fn pending_exit_gate(c:&Anka64Core)->bool {
    c.privilege==Privilege::Supervisor && c.pc==c.trap_vector
        && !c.interrupts_enabled && c.r[R0 as usize]==SYS_EXIT
        && c.event_frames.len()==1
        && matches!(c.event_frames.last(),Some(f)
            if f.cause==super::super::state::EventCause::Syscall
                && f.return_privilege==Privilege::User)
}

impl Kernel {
    pub(crate) fn prepare_preprocessor_transport(&mut self)->Result<(),()> {
        if self.processes.len()!=1 || self.fabric.timer.is_some()
            || !self.device_registry.devices.is_empty() || self.heap_service.is_some()
            || self.processes[0].core.protected_application()
            || !self.processes[0].core.event_frames.is_empty()
            || !self.processes[0].core.return_stack.is_empty()
            || !self.fabric.discard_completed_compiler_trace() {return Err(());}
        let c=&mut self.processes[0].core;
        c.return_stack.try_reserve_exact(PREPROCESS_CALLS).map_err(|_|())?;
        c.event_frames.try_reserve_exact(1).map_err(|_|())?;
        self.fabric.prepare_preprocessor_trace(PREPROCESS_TRANSACTIONS)?;
        if c.return_stack.capacity()>PREPROCESS_CALLS || c.event_frames.capacity()>1
            || !self.fabric.preprocessor_trace_within_bounds(PREPROCESS_TRANSACTIONS) {return Err(());}
        Ok(())
    }

    pub(crate) fn run_preprocessor_slice(&mut self,quantum:usize)->Result<(),()> {
        if quantum==0 || quantum>PREPROCESS_SLICE || self.processes.len()!=1
            || self.fabric.timer.is_some() || !self.device_registry.devices.is_empty()
            || self.heap_service.is_some() || !self.fabric.discard_completed_compiler_trace() {return Err(());}
        for _ in 0..quantum {
            if self.processes[0].exited() {break;}
            let c=&self.processes[0].core;
            // TRAP returns Continue after entering the supervisor gate; HALT
            // is the following instruction, possibly in the next slice.
            let exit_gate=pending_exit_gate(c);
            let user_step=c.privilege==Privilege::User && c.event_frames.is_empty();
            // Conservative prefix bound: at the limit, even a RET is refused.
            // No recursive-call instruction can grow the retained Vec past it.
            if c.protected_application() || c.return_stack.len()>=PREPROCESS_CALLS
                || !(user_step || exit_gate) {return Err(());}
            match self.processes[0].core.step(&mut self.fabric) {
                super::super::core::StepResult::Continue=>{
                    // A pending exit may execute only the terminating gate.
                    if exit_gate {return Err(());}
                },
                super::super::core::StepResult::Fault(_)=>return Err(()),
                super::super::core::StepResult::Halted=>{
                    match classify_halt(&self.processes[0].core) {
                        HaltDisposition::UserExit(code)=>self.finish_process(0,ProcessResult::Exited(code)),
                        HaltDisposition::Syscall if self.processes[0].core.r[R0 as usize]==SYS_EXIT=>self.handle_syscall(0),
                        _=>return Err(()),
                    }
                    break;
                },
            }
        }
        // These checks also make future instruction-set extensions fail closed
        // in diagnostics. The current scalar ISA uses at most fetch+read+write
        // (3 transactions), each payload at most eight bytes, per instruction.
        if !self.fabric.preprocessor_trace_within_bounds(PREPROCESS_TRANSACTIONS)
            || self.processes[0].core.return_stack.capacity()>PREPROCESS_CALLS
            || self.processes[0].core.event_frames.capacity()>1 {return Err(());}
        if !self.fabric.discard_completed_compiler_trace() {return Err(());}
        Ok(())
    }
}
