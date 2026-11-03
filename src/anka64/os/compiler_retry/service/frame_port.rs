//! S3: one real virtual-NIC round trip. The driver owns the NIC and bounce
//! object. A separate receipt-checked C realm sees only its private input and
//! output. No host protocol parser, guest physical peek, or source fallback.
use super::RebuildService;
use crate::anka64::scoped_pointers::heap::HostStorageReservation;
use crate::anka64::{
    dev_runner::{DeveloperExecutionAuthority,DeveloperInputAuthority,DevelopmentRunConfig},
    fabric::Fabric, isa::{Asm64,Cond,R0,R1,R2,R3,R4,R5,R6},
    nic::{NicController,NIC_MAX_FRAME_SIZE},
    os::{BootGrant,BootImage,BootInfo,BootMap,Kernel,ProcessResult,SYS_NIC_RX,SYS_NIC_TX,SYS_EXIT},
    state::{AccessContext,AccessKind,AgentId,AgentKind,CapabilityHandle,CoreId,
        DeviceBinding,DeviceRights,MemoryRequest,ObjectId,ObjectKind,Permissions,Privilege,Width},
};

/// Explicit host development policy for an isolated virtual NIC, not a host
/// network permission. Never inherited by the compiled packet application.
pub(crate) struct DeveloperFrameAuthority(());
impl DeveloperFrameAuthority {pub(crate) fn provision()->Self {Self(())}}

const N:usize=NIC_MAX_FRAME_SIZE;
const CONTROL:i32=0x8000;
const TRACE:usize=256;
// 2 MiB RAM, <=2 MiB fixed registry, bounded remaining Kernel/controller,
// trace entries, bounce buffer and synchronous copies (one RX, at most one TX).
const DRIVER_CHARGE:u64=8*1024*1024;
fn err(e:impl std::fmt::Debug)->String {format!("{e:?}")}

fn object(f:&mut Fabric,name:&str,size:usize,at:u64)->Result<ObjectId,String>{
    let o=f.alloc_object(name,size as u64,ObjectKind::Memory);
    if !f.place_object(o,at) || !f.zero_object_extent(o){return Err(format!("cannot place {name}"));}
    Ok(o)
}
fn nic_args(a:&mut Asm64,op:u64) {
    a.movi(R0,op as i32);a.movi(R1,0);a.movi(R2,0);a.movi(R3,1);a.movi(R4,0);a.trap(0);
}
struct Port {k:Kernel,dev:DeviceBinding,buffer:ObjectId,control:ObjectId,copy:AccessContext,ready:u64,trace_limit:usize}
impl Port {
    fn new()->Result<Self,String>{
        let mut a=Asm64::new();
        nic_args(&mut a,SYS_NIC_RX);
        let ready=a.here() as u64*4;
        a.movi(R6,CONTROL);
        let wait=a.here();
        a.ld(R5,R6,0);a.cmpi(R5,0);
        let back=wait-a.here();a.bcc(Cond::Eq,back);
        nic_args(&mut a,SYS_NIC_TX);
        a.mov(R1,R0);a.movi(R0,SYS_EXIT as i32);a.trap(0);
        Self::boot_program(a,ready,TRACE)
    }
    fn boot_program(a:Asm64,ready:u64,trace_limit:usize)->Result<Self,String>{
        let mut f=Fabric::with_preprocessor_storage(2*1024*1024).map_err(|_|"driver RAM/metadata")?;
        let code=a.to_bytes();
        let image=object(&mut f,"frame-driver",code.len(),0x10000)?;
        let buffer=object(&mut f,"nic-bounce",N,0x20000)?;
        let control=object(&mut f,"tx-length",8,0x21000)?;
        if !f.initialize_object(image,0,&code) || !f.seal_object(image){return Err("driver image".into());}
        // Copy actor has ordinary memory rights and no device handle. Its
        // requests pass Fabric authorization, translation and commit checks.
        let domain=f.create_domain();let agent=AgentId(301);
        f.register_agent(agent,AgentKind::Cpu(CoreId(1)),domain);
        f.grant(domain,buffer,0,N as u64,Permissions::RW).ok_or("copy grant")?;
        f.grant(domain,control,0,8,Permissions::WRITE).ok_or("length grant")?;
        let copy=AccessContext{agent,domain,privilege:Privilege::User};
        let mut k=Kernel::new(f);
        let dev=k.register_nic_device(NicController::new(AgentId(302))).ok_or("register NIC")?;
        k.boot(&BootInfo{
            image:BootImage{obj:image,code_offset:0,code_size:code.len() as u64,entry:0,lit_start:0},
            // Only the length word is mapped. The NIC uses the exact memory handle.
            grants:vec![BootGrant{obj:control,offset:0,size:8,perms:Permissions::READ}],
            maps:vec![BootMap{vaddr:CONTROL as u64,size:8,obj:control,obj_offset:0}],
            code_vaddr:0,stack_vaddr:0x20000,stack_size:0x4000,trap_vaddr:0x24000,
        }).map_err(err)?;
        let device=k.install_device_capability(0,dev.object,DeviceRights(DeviceRights::NIC_RX.0|DeviceRights::NIC_TX.0));
        let dma=k.install_capability(0,buffer,0,N as u64,Permissions::RW);
        if device!=Some(CapabilityHandle{slot:0,generation:0}) || dma!=Some(CapabilityHandle{slot:1,generation:0}) {
            return Err("unexpected driver capability setup".into());
        }
        // Before any finite request exists; never clear trace while DMA is live.
        k.fabric.prepare_preprocessor_trace(trace_limit).map_err(|_|"driver trace")?;
        Ok(Self{k,dev,buffer,control,copy,ready,trace_limit})
    }
    fn request(&self,obj:ObjectId,n:usize,kind:AccessKind)->MemoryRequest {
        MemoryRequest{context:self.copy,object:obj,offset:0,width:Width::Byte,length:n as u64,kind}
    }
    fn idle(&self)->bool {
        self.k.processes[0].io_wait.is_none() && self.k.device_registry.lookup(self.dev)
            .and_then(|d|d.controller.as_nic()).is_some_and(|nic|
                !nic.has_autonomous_work() && nic.completion_count()==0 && nic.rx_queue_len()==0)
    }
    fn step(&mut self)->Result<(),String>{
        self.k.run(1,1);
        if !self.k.fabric.preprocessor_trace_within_bounds(self.trace_limit) || !self.k.fabric.fault_log.is_empty(){
            return Err("driver trace/fault boundary".into());
        }
        Ok(())
    }
    // Consuming the unstarted port produces a single-use outbound permit.
    fn receive(mut self,frame:&[u8])->Result<(Received,Vec<u8>),String>{
        if frame.is_empty() || frame.len()>N || !self.k.inject_nic_rx(self.dev,frame){return Err("NIC ingress denied".into());}
        for _ in 0..96 {
            self.step()?;
            let p=&self.k.processes[0];
            if p.exited(){return Err("driver exited before RX".into());}
            if p.core.privilege==Privilege::User && (self.ready..=self.ready+4).contains(&p.core.pc) && self.idle() {
                let status=p.core.r[R0 as usize];let count=p.core.r[R1 as usize];
                if status!=0 || count!=frame.len() as u64{return Err(format!("RX status={status} count={count}"));}
                let r=self.request(self.buffer,count as usize,AccessKind::Read);
                let bytes=self.k.fabric.execute_read(r).map_err(err)?;
                return Ok((Received(self),bytes));
            }
        }
        Err("driver did not complete RX within 96 rounds".into())
    }
}
struct Received(Port);
impl Received {
    fn transmit(self,bytes:&[u8])->Result<Vec<u8>,String>{
        let mut p=self.0;
        if !(14..=N).contains(&bytes.len()) || !p.idle(){return Err("invalid TX offer".into());}
        let b=p.request(p.buffer,bytes.len(),AccessKind::Write);
        p.k.fabric.execute_write(b,bytes.to_vec()).map_err(err)?;
        let c=p.request(p.control,8,AccessKind::Write);
        p.k.fabric.execute_write(c,(bytes.len() as u64).to_le_bytes().to_vec()).map_err(err)?;
        for _ in 0..96 {
            p.step()?;
            if let Some(result)=&p.k.processes[0].result {
                if *result!=ProcessResult::Exited(0) || !p.idle(){return Err(format!("TX completion: {result:?}"));}
                let wire=p.k.take_nic_tx(p.dev).ok_or("no committed NIC TX")?;
                if wire.as_slice()!=bytes || p.k.take_nic_tx(p.dev).is_some(){return Err("wrong/extra NIC TX".into());}
                return Ok(wire)
            }
        }
        Err("driver did not complete TX within 96 rounds".into())
    }
}
enum Offer {Reply,Drop}
fn offer(result:&ProcessResult,bytes:&[u8])->Result<Offer,String>{
    match (result,bytes.len()) {
        (ProcessResult::Exited(1),14..=N)=>Ok(Offer::Reply),
        (ProcessResult::Exited(2|3|64),0)=>Ok(Offer::Drop),
        _=>Err(format!("invalid packet result {result:?}, {} output bytes",bytes.len())),
    }
}

// The result callback is host code and can unwind. Its frame borrow and all
// temporary machines drop before this outer quota guard, even on that path.
struct DriverHold<'a>{kernel:&'a mut Kernel, token:Option<HostStorageReservation>}
impl Drop for DriverHold<'_>{
    fn drop(&mut self){
        if let Some(t)=self.token.take(){let _=self.kernel.fabric.scoped_pointers.release_host_storage(t);}
    }
}

impl RebuildService {
    pub(crate) fn run_frame(&mut self,epoch:u64,exec:&DeveloperExecutionAuthority,
        input:&DeveloperInputAuthority,_net:&DeveloperFrameAuthority,frame:&[u8],
        emit:impl FnOnce(&[u8])->Result<(),String>)->Result<ProcessResult,String>{
        if frame.is_empty() || frame.len()>N {return Err("frame size must be 1..1514".into());}
        self.kernel.validate_linked_compiler_publication(epoch).map_err(err)?;
        let (_,account)=self.kernel.compiler_candidate_account().map_err(err)?;
        let reg=&mut self.kernel.fabric.scoped_pointers;
        let hold=reg.reserve_host_storage(account,DRIVER_CHARGE,reg.revision()).map_err(err)?;
        let mut guard=DriverHold{kernel:&mut self.kernel,token:Some(hold)};
        let result=(||{
            let (port,rx)=Port::new()?.receive(frame)?;
            let report=guard.kernel.run_linked_compiler_publication_with_input(epoch,Some(exec),Some(input),&rx,
                DevelopmentRunConfig{quantum:1024,max_rounds:2048,..DevelopmentRunConfig::default()}).map_err(err)?;
            let guest=report.execution();
            match offer(&guest.child_result,&guest.byte_output)? {
                Offer::Reply=>emit(&port.transmit(&guest.byte_output)?)?,
                Offer::Drop=>{drop(port);emit(&[])?;}
            }
            Ok(guest.child_result.clone())
        })();
        // All temporary machines, frames, and charged report borrows have
        // ended, on every Result branch. No external hardware owns this memory.
        guard.kernel.fabric.scoped_pointers.release_host_storage(hold).map_err(err)?;
        guard.token=None;
        result
    }
}
pub(crate) mod tcp;
#[cfg(test)]
mod tests;
