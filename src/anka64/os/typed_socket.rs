//! One connected, copy-only endpoint in a Kernel. Trusted transport methods
//! below take already ordered stream bytes; they never issue or accept DMA.
pub(crate) mod select;
use super::*;
use crate::anka64::scoped_pointers::{ScopedPointer, heap::{AllocationOwner, HeapError, HostStorageReservation, Resource}};

// Tickets can reach the trusted adapter after a whole Kernel is replaced.
// Never derive their only identity from registry-local counters.
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_SOCKET_EPOCH: AtomicU64 = AtomicU64::new(1);

/// Limit on one authenticated guest copy. Independent of queue policy.
const SOCKET_CALL_MAX: usize = 1024;
pub(crate) const DEFAULT_SOCKET_QUEUE: usize = 1024;
// Policy ceiling per direction, not a promise of available owner/global quota.
const MAX_SOCKET_QUEUE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SocketCapacity { rx: usize, tx: usize }
impl SocketCapacity {
    pub(crate) const DEFAULT: Self = Self { rx: DEFAULT_SOCKET_QUEUE, tx: DEFAULT_SOCKET_QUEUE };

    pub(crate) fn new(rx: usize, tx: usize) -> Result<Self, HeapError> {
        if !(1..=MAX_SOCKET_QUEUE).contains(&rx) || !(1..=MAX_SOCKET_QUEUE).contains(&tx) {
            return Err(HeapError::Configuration);
        }
        Ok(Self { rx, tx })
    }
    pub(crate) fn rx(self) -> usize { self.rx }
    pub(crate) fn tx(self) -> usize { self.tx }
    fn layout(self) -> Result<(usize, u64), HeapError> {
        let pool = self.rx.checked_add(self.tx).ok_or(HeapError::Size)?;
        let bytes = pool.checked_add(std::mem::size_of::<Endpoint>()).ok_or(HeapError::Size)?;
        Ok((pool, u64::try_from(bytes).map_err(|_| HeapError::Size)?))
    }
}
pub(crate) const SOCKET_AGAIN: u64 = u64::MAX - 1;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SocketRights { Receive, Send, Duplex }

/// Trusted adapter ticket; opaque to guests. Owner includes the core context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SocketTicket { epoch: u64, owner: AllocationOwner, storage: HostStorageReservation }
pub(super) struct Endpoint {
    ticket: SocketTicket,
    rights: SocketRights,
    // RX starts at zero; TX starts at capacity.rx. Empty Vec is an inaccessible
    // cleanup obligation, never a live endpoint.
    queues: Vec<u8>,
    capacity: SocketCapacity,
    rx: usize,
    tx: usize,
    tx_limit: usize,
    fin: bool,
    select: Option<select::Select>,
}


impl Kernel {
    /// Caller already admitted this child and its owner account. Admission
    /// failure confers no rights and a cancelled binding cannot be substituted
    /// under an outstanding syscall in the same process incarnation.
    pub(crate) fn bind_socket(&mut self, key: ProcessKey, rights: SocketRights)
        -> Result<SocketTicket, HeapError>
    {
        self.bind_socket_capacity(key, rights, SocketCapacity::DEFAULT)
    }

    pub(crate) fn bind_socket_capacity(&mut self, key: ProcessKey, rights: SocketRights,
        capacity: SocketCapacity) -> Result<SocketTicket, HeapError> {
        if self.application_run.is_some() { return Err(HeapError::Busy); }
        self.bind_socket_window(key, rights, capacity, capacity.tx,None)
    }

    fn bind_socket_window(&mut self,key:ProcessKey,rights:SocketRights,capacity:SocketCapacity,tx_limit:usize,select:Option<select::Select>)
        -> Result<SocketTicket,HeapError> {
        if self.socket_endpoint.is_some() {return Err(HeapError::Busy);}
        if !(1..=capacity.tx).contains(&tx_limit) {return Err(HeapError::Configuration);}
        let (pool, base_charge) = capacity.layout()?;
        let charge=base_charge.checked_add(select.as_ref().map_or(0,|s|s.verifier_bytes())).ok_or(HeapError::Size)?;
        let p = self.processes.get(key.slot).ok_or(HeapError::Owner)?;
        let owner = CurrentHeapProcess::from_processes(&self.processes,key).ok_or(HeapError::Owner)?.owner();
        if p.socket_was_bound || !p.core.protected_application() || p.core.heap_owner()? != owner {
            return Err(HeapError::Owner);
        }
        let reg = &mut self.fabric.scoped_pointers;
        let account = reg.heap_account(owner).ok_or(HeapError::Owner)?;
        let epoch = NEXT_SOCKET_EPOCH.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |n| n.checked_add(1)).map_err(|_| HeapError::Capacity(Resource::Identity))?;
        let storage = reg.reserve_host_storage(account, charge, reg.revision())?;
        let ticket = SocketTicket { epoch, owner, storage };
        let e = self.socket_endpoint.insert(Endpoint { ticket, rights, queues:Vec::new(),capacity,rx:0,tx:0,tx_limit,fin:false,select });
        if e.queues.try_reserve_exact(pool).is_err() || e.queues.capacity() != pool {
            self.discard_socket()?;
            return Err(HeapError::HostAllocation);
        }
        e.queues.resize(pool,0);
        self.processes[key.slot].socket_was_bound = true;
        Ok(ticket)
    }

    /// Called by the explicitly selected stream runner in the gap after SPAWN
    /// and before the child is scheduled. No existing or foreign owner is adopted.
    pub(crate) fn bind_application_socket(&mut self,key:ProcessKey,capacity:SocketCapacity,window:usize,
        _authority:&crate::anka64::dev_runner::DeveloperSocketAuthority)->Result<SocketTicket,HeapError> {
        if self.processes.len()!=3 || key.slot!=2 || !(1..=capacity.tx).contains(&window)
            || !self.application_run.as_ref().is_some_and(|r|r.spawned && !r.socket)
            || self.processes[key.slot].parent!=Some(ProcessKey{slot:0,generation:self.processes[0].generation})
            || self.processes[key.slot].generation!=key.generation {return Err(HeapError::Owner);}
        self.compiler_heap_account(key)?;
        let ticket=self.bind_socket_window(key,SocketRights::Duplex,capacity,window,None)?;
        self.application_run.as_mut().unwrap().socket=true;
        Ok(ticket)
    }

    pub(crate) fn socket_current(&self, ticket: SocketTicket) -> bool {
        let Some(e) = self.socket_endpoint.as_ref() else { return false };
        let Ok((pool, charge)) = e.capacity.layout() else { return false };
        let Some(total)=charge.checked_add(e.select.as_ref().map_or(0,|s|s.verifier_bytes())) else {return false};
        e.ticket == ticket && e.queues.len() == pool
            && CurrentHeapProcess::from_processes(&self.processes,ticket.owner.process)
                .is_some_and(|p|p.owner()==ticket.owner)
            && self.fabric.scoped_pointers.check_host_storage(ticket.storage,ticket.owner,
                self.fabric.scoped_pointers.revision()) == Ok(total)
    }

    /// Accept ALL bytes and the trailing FIN, or neither. Transport retains a
    /// rejected fragment; a retransmission must first pass TCP sequence checks.
    pub(crate) fn deliver_socket(&mut self,ticket:SocketTicket,bytes:&[u8],fin:bool) -> Result<(),()> {
        if !self.socket_current(ticket) {return Err(());}
        let e=self.socket_endpoint.as_mut().ok_or(())?;
        if e.select.is_some() || e.rights==SocketRights::Send || e.fin || bytes.len()>e.capacity.rx-e.rx {return Err(());}
        e.queues[e.rx..e.rx+bytes.len()].copy_from_slice(bytes);
        e.rx+=bytes.len(); e.fin=fin;
        Ok(())
    }

    pub(super) fn socket_exit_drained(&self,idx:usize)->bool {
        self.socket_endpoint.as_ref().is_some_and(|e| e.ticket.owner.process.slot==idx
            && self.socket_current(e.ticket) && e.tx==0 && (e.select.is_none() || (e.fin && e.rx==0)))
    }

    pub(crate) fn socket_pending_tx(&self,ticket:SocketTicket)->Result<usize,()> {
        if !self.socket_current(ticket){return Err(());}
        Ok(self.socket_endpoint.as_ref().ok_or(())?.tx)
    }

    /// Successful copy transfers the prefix to the trusted transport's buffer.
    /// This does not acknowledge TCP delivery or completion of a NIC request.
    pub(crate) fn take_socket_tx(&mut self,ticket:SocketTicket,out:&mut [u8]) -> Result<usize,()> {
        if !self.socket_current(ticket) {return Err(());}
        let e=self.socket_endpoint.as_mut().ok_or(())?;
        if e.select.is_some() || e.rights==SocketRights::Receive {return Err(());}
        let n=e.tx.min(out.len());
        out[..n].copy_from_slice(&e.queues[e.capacity.rx..e.capacity.rx+n]);
        consume(&mut e.queues[e.capacity.rx..],&mut e.tx,n);
        Ok(n)
    }

    /// Graceful close is only acknowledged once both private queues are empty.
    /// Transport remains responsible for its own copied bytes, DMA and ACKs.
    pub(crate) fn close_drained_socket(&mut self,ticket:SocketTicket) -> Result<(),HeapError> {
        if !self.socket_current(ticket) {return Err(HeapError::Owner);}
        let e=self.socket_endpoint.as_ref().ok_or(HeapError::Owner)?;
        if e.rx!=0 || e.tx!=0 || (e.select.is_some() && !e.fin) {return Err(HeapError::Busy);}
        self.discard_socket()
    }
    pub(crate) fn cancel_socket(&mut self,ticket:SocketTicket) -> Result<(),HeapError> {
        if self.socket_endpoint.as_ref().map(|e|e.ticket)!=Some(ticket) {return Err(HeapError::Owner);}
        self.discard_socket()
    }
    pub(super) fn discard_socket(&mut self) -> Result<(),HeapError> {
        if let Some(e)=self.socket_endpoint.as_mut() {
            drop(std::mem::take(&mut e.queues));
            e.select.take();
            self.fabric.scoped_pointers.release_host_storage(e.ticket.storage)?;
            self.socket_endpoint=None;
        }
        Ok(())
    }
    pub(super) fn discard_socket_owned_by(&mut self, owner:AllocationOwner) {
        if self.socket_endpoint.as_ref().is_some_and(|e|e.ticket.owner==owner) {let _=self.discard_socket();}
    }

    pub(super) fn handle_typed_socket(&mut self,idx:usize,words:[u64;16],kinds:[Option<ScopedPointer>;6]) {
        let result=if words[0]==SYS_SOCKET_SHUT_WR {self.select_shutdown(idx,words,kinds)}
            else {self.copy_socket(idx,words,kinds)}.unwrap_or(u64::MAX);
        if let Some(run)=self.application_run.as_mut().filter(|r|r.socket) {
            run.last_socket=Some((words[0],words[4],result));
        }
        self.processes[idx].core.write_syscall_result(R0 as usize,result);
        self.resume_from_trap(idx);
    }

    fn copy_socket(&mut self,idx:usize,words:[u64;16],kinds:[Option<ScopedPointer>;6]) -> Option<u64> {
        let core=&self.processes.get(idx)?.core;
        if core.protected_syscall_image()!=Some((words,kinds)) || words[1]!=0 || words[5]!=0
            || kinds[0].is_some() || kinds[2].is_some() || words[4]>SOCKET_CALL_MAX as u64 {return None;}
        let pointer=kinds[1]?;
        if pointer.words()!=[words[2],words[3]] {return None;}
        let ticket=self.socket_endpoint.as_ref()?.ticket;
        if ticket.owner.process.slot!=idx || core.heap_owner().ok()?!=ticket.owner || !self.socket_current(ticket) {return None;}
        // Disjoint exclusive borrows cover preflight through queue commit.
        let e=self.socket_endpoint.as_mut()?;
        let fabric=&mut self.fabric;
        let rx=match words[0] {
            SYS_SOCKET_RECV if e.rights!=SocketRights::Send => true,
            SYS_SOCKET_SEND if e.rights!=SocketRights::Receive => false,
            _=>return None,
        };
        let (object,offset)=if rx {core.syscall_write_span(fabric,pointer,words[4])}
            else {core.syscall_read_span(fabric,pointer,words[4])}.ok()?;
        let lane=e.select.as_ref().map(|s|s.verifier.clone());
        let mut guard=match lane.as_ref(){Some(lane)=>Some(lane.try_lock().ok()?),None=>None};
        if let Some(s)=e.select.as_mut() {
            let v=&mut **guard.as_mut()?;
            if rx {
                if !s.read_ready(v)? {return Some(if words[4]==0 {0} else {SOCKET_AGAIN});}
                s.refill(&mut e.queues[..e.capacity.rx],&mut e.rx,&mut e.fin);
            } else {s.allow_write(words[4] as usize,v)?;}
        }
        if words[4]==0 {return Some(0);}
        let available=if rx {e.rx} else {e.tx_limit-e.tx};
        if available==0 {return Some(if rx && e.fin {0} else {SOCKET_AGAIN});}
        let n=available.min(words[4] as usize);
        let heap=fabric.scoped_pointers.is_heap_pointer(pointer);
        let request=MemoryRequest{context:AccessContext{agent:core.agent,domain:core.domain,
            privilege:Privilege::Supervisor},object,offset,length:n as u64,width:Width::Byte,
            kind:if rx {AccessKind::Write} else {AccessKind::Read}};
        if rx {
            if heap {fabric.write_heap_bytes(ticket.owner,core.agent,pointer,&e.queues[..n]).ok()?;}
            else {fabric.execute_write(request,e.queues[..n].to_vec()).ok()?;}
            consume(&mut e.queues[..e.capacity.rx],&mut e.rx,n);
        } else {
            let dest=&mut e.queues[e.capacity.rx+e.tx..e.capacity.rx+e.tx+n];
            if heap {fabric.read_heap_bytes(ticket.owner,core.agent,pointer,dest).ok()?;}
            else {dest.copy_from_slice(&fabric.execute_read(request).ok()?);}
            if let Some(s)=e.select.as_mut() {
                if !s.accept(dest) {dest.fill(0);return None;}
            }
            e.tx+=n;
        }
        Some(n as u64)
    }
}

fn consume(queue:&mut [u8],used:&mut usize,n:usize) {
    queue.copy_within(n..*used,0);
    queue[*used-n..*used].fill(0);
    *used-=n;
}
