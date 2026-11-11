//! Exclusive bounded conversation. The broker routes records, never parses a
//! TCP/IP header. The ONLY checkpoint accepted as the next input comes from
//! the bound TCP publication after all effects of the previous step committed.
use super::*;
use crate::anka64::dev_runner::{DeveloperSocketAuthority,OrderedStream};
const FIFO:usize=1024;
const STATE:usize=32;
const RX_BUDGET:usize=16;
// Private driver plus 4096 fixed trace entries and bounded protocol staging.
const SESSION_CHARGE:u64=DRIVER_CHARGE+4*1024*1024;
struct Driver(Port);
impl Driver {
    fn new()->Result<Self,String>{
        // Each command begins/ends at user PC 0. No guest is scheduled while
        // the broker accesses the drained bounce buffer. -1=RX, positive=TX.
        let mut a=Asm64::new();
        a.movi(R6,CONTROL);a.ld(R5,R6,0);a.cmpi(R5,-1);
        let mut tx=Asm64::new();nic_args(&mut tx,SYS_NIC_TX);
        a.bcc(Cond::Eq,tx.here()+2);
        a.words_mut().extend(tx.to_bytes().chunks_exact(4).map(|b|u32::from_le_bytes(b.try_into().unwrap())));
        let back= -a.here();a.bcc(Cond::Al,back);
        nic_args(&mut a,SYS_NIC_RX);
        let back= -a.here();a.bcc(Cond::Al,back);
        Ok(Self(Port::boot_program(a,0,4096)?))
    }
    fn parked(&self)->bool {
        let p=&self.0.k.processes[0];
        !p.exited() && p.core.pc==0 && p.core.privilege==Privilege::User && self.0.idle()
            && self.0.k.device_registry.lookup(self.0.dev).and_then(|s|s.controller.as_nic())
               .is_some_and(|n|n.tx_frame_count()==0)
    }
    fn command(&mut self,word:u64,n:usize)->Result<(),String>{
        let p=&mut self.0;
        let ctl=p.request(p.control,8,AccessKind::Write);
        p.k.fabric.execute_write(ctl,word.to_le_bytes().to_vec()).map_err(err)?;
        for _ in 0..96 {
            p.step()?;let proc=&p.k.processes[0];
            if proc.exited(){return Err("TCP driver exited".into());}
            if proc.core.pc==0 && proc.core.privilege==Privilege::User && p.idle() {
                if proc.core.r[R0 as usize]!=0 || proc.core.r[R1 as usize]!=n as u64 {
                    return Err(format!("NIC completion status={} length={}, expected {n}",proc.core.r[0],proc.core.r[1]));}
                return Ok(())
            }
        }
        Err("TCP driver round budget exhausted".into())
    }
    fn rx(&mut self,b:&[u8])->Result<Vec<u8>,String>{
        if !self.parked() || b.is_empty() || b.len()>N || !self.0.k.inject_nic_rx(self.0.dev,b){return Err("RX admission".into());}
        self.command(u64::MAX,b.len())?;
        let req=self.0.request(self.0.buffer,b.len(),AccessKind::Read);
        self.0.k.fabric.execute_read(req).map_err(err)
    }
    fn tx(&mut self,b:&[u8])->Result<Vec<u8>,String>{
        if !self.parked() || !(14..=N).contains(&b.len()){return Err("TX admission".into());}
        let req=self.0.request(self.0.buffer,b.len(),AccessKind::Write);
        self.0.k.fabric.execute_write(req,b.to_vec()).map_err(err)?;
        self.command(b.len() as u64,b.len())?;
        let wire=self.0.k.take_nic_tx(self.0.dev).ok_or("missing TCP wire result")?;
        if wire.as_slice()!=b || !self.parked(){return Err("unexpected TCP wire result".into());}
        Ok(wire)
    }
}

struct Proposal<'a>{action:u8,state:&'a [u8],data:&'a [u8],wire:&'a [u8]}
fn proposal<'a>(status:&ProcessResult,b:&'a [u8],send:bool,room:usize,input_len:usize)
 ->Result<Option<Proposal<'a>>,String>{
    if !send && *status==ProcessResult::Exited(0) && b.is_empty(){return Ok(None);}
    if *status!=ProcessResult::Exited(1) || b.len()<6+STATE || b[1]!=0{return Err(format!("TCP result {status:?}, bytes={}",b.len()));}
    let wire=u16::from_be_bytes([b[2],b[3]]) as usize;let n=u16::from_be_bytes([b[4],b[5]]) as usize;
    if b.len()!=6+STATE+n+wire || n>room || wire>N{return Err("invalid TCP record lengths".into());}
    let ok=match (send,b[0]){
        (false,1|4)=>n==0 && wire==60, (false,2|5)=>n==0 && wire==0,
        (false,3)=>n>0 && wire==60 && n+54<=input_len,
        (true,6)=>n==0 && input_len>0 && input_len<=FIFO && wire==(54+input_len).max(60),
        _=>false,
    };
    if !ok{return Err("wrong TCP proposal for operation".into());}
    Ok(Some(Proposal{action:b[0],state:&b[6..6+STATE],data:&b[6+STATE..6+STATE+n],wire:&b[6+STATE+n..]}))
}

pub(crate) struct TcpSession<'a>{
    kernel:&'a mut Kernel, exec:&'a DeveloperExecutionAuthority,input:&'a DeveloperInputAuthority,
    socket:&'a DeveloperSocketAuthority,tcp:u64,http:u64,driver:Driver,
    checkpoint:[u8;STATE],fifo:[u8;FIFO],used:usize,fin:bool,served:bool,failed:bool,rx_count:usize,
}
impl TcpSession<'_>{
    // Only the valid prefix of the caller's buffer is changed/reported.
    fn transition(&mut self,send:bool,bytes:&[u8],out:&mut [u8;N])->Result<usize,String>{
        let mut envelope=[0u8;35+N];
        envelope[0]=if send{2}else{1};
        envelope[1..3].copy_from_slice(&((FIFO-self.used) as u16).to_be_bytes());
        envelope[3..35].copy_from_slice(&self.checkpoint);
        envelope[35..35+bytes.len()].copy_from_slice(bytes);
        let report=self.kernel.run_linked_compiler_publication_with_input(self.tcp,Some(self.exec),Some(self.input),&envelope[..35+bytes.len()],
            DevelopmentRunConfig{quantum:1024,max_rounds:2048,..DevelopmentRunConfig::default()}).map_err(err)?;
        let r=report.execution();
        let Some(p)=proposal(&r.child_result,&r.byte_output,send,FIFO-self.used,bytes.len())? else{return Ok(0)};
        // The strict fixed-header profile starts payload at byte 54. Bind
        // delivered/copied data to the originating bytes, without importing
        // TCP header interpretation or checksum decisions into the broker.
        if !p.data.is_empty() && bytes.get(54..54+p.data.len())!=Some(p.data) {
            return Err("TCP delivery differs from received prefix".into());
        }
        if send && p.wire.get(54..54+bytes.len())!=Some(bytes) {
            return Err("TCP wire proposal differs from protected HTTP response".into());
        }
        // Stage into the *unpublished* suffix before acknowledging delivery.
        let end=self.used+p.data.len();
        self.fifo[self.used..end].copy_from_slice(p.data);
        let count=if p.wire.is_empty(){0}else{
            let wire=self.driver.tx(p.wire)?;out[..wire.len()].copy_from_slice(&wire);wire.len()
        };
        self.checkpoint.copy_from_slice(p.state);self.used=end;
        if p.action==4{self.fin=true;}
        Ok(count)
    }
    pub(crate) fn receive(&mut self,frame:&[u8],wire:&mut [u8;N])->Result<usize,String>{
        if self.failed || self.rx_count>=RX_BUDGET {self.failed=true;return Err("TCP session closed or budget exhausted".into());}
        self.failed=true;self.rx_count+=1;
        let rx=self.driver.rx(frame)?;
        let n=self.transition(false,&rx,wire)?;
        self.failed=false;Ok(n)
    }
    /// An explicit application scheduling point. EOF is supplied only after
    /// the guest transport accepted FIN. No Rust HTTP request inspection.
    pub(crate) fn serve_http(&mut self,wire:&mut [u8;N])->Result<usize,String>{
        if self.failed || self.served || self.used==0{return Err("HTTP not ready or already served".into());}
        self.failed=true;
        let mut reply=[0u8;FIFO];
        let n={
            let stream=OrderedStream::new(self.socket,&self.fifo[..self.used],&[],self.fin,FIFO)?;
            let report=self.kernel.run_linked_compiler_publication_with_socket(self.http,self.exec,stream,
                DevelopmentRunConfig::default()).map_err(err)?;
            let r=report.execution();let n=r.byte_output.len();
            if r.child_result!=ProcessResult::Exited(0) || r.stream.is_none() || !(1..=FIFO).contains(&n) {
                return Err(format!("HTTP guest {:?}, output {n}",r.child_result));
            }
            reply[..n].copy_from_slice(&r.byte_output);n
        };
        let count=self.transition(true,&reply[..n],wire)?;
        self.fifo[..self.used].fill(0);self.used=0;self.served=true;self.failed=false;Ok(count)
    }
}
impl RebuildService{
    pub(crate) fn with_tcp_session(&mut self,tcp:u64,http:u64,exec:&DeveloperExecutionAuthority,
        input:&DeveloperInputAuthority,socket:&DeveloperSocketAuthority,_net:&DeveloperFrameAuthority,
        run:impl FnOnce(&mut TcpSession<'_>)->Result<(),String>)->Result<(),String>{
        if tcp==http{return Err("distinct TCP and HTTP receipts required".into());}
        for e in [tcp,http]{self.kernel.validate_linked_compiler_publication(e).map_err(err)?;}
        let (_,account)=self.kernel.compiler_candidate_account().map_err(err)?;
        let reg=&mut self.kernel.fabric.scoped_pointers;
        let hold=reg.reserve_host_storage(account,SESSION_CHARGE,reg.revision()).map_err(err)?;
        let mut guard=DriverHold{kernel:&mut self.kernel,token:Some(hold)};
        let result=(||{
            let mut s=TcpSession{kernel:&mut *guard.kernel,driver:Driver::new()?,exec,input,socket,tcp,http,
                checkpoint:[0;STATE],fifo:[0;FIFO],used:0,fin:false,served:false,failed:false,rx_count:0};
            run(&mut s)?;
            if s.failed{return Err("aborted TCP session".into());} Ok(())
        })();
        guard.kernel.fabric.scoped_pointers.release_host_storage(hold).map_err(err)?;guard.token=None;result
    }
}
#[cfg(test)]
mod tests;

pub(crate) mod outbound;
