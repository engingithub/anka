//! E4 bounded reference registry. Authority changes and effects share one mutex.
//! No credential parser/default allow-provider; P remains a trusted validator.
use super::*;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::sync::atomic::{AtomicU64, Ordering};
static REGISTRIES: AtomicU64 = AtomicU64::new(1);
const MAX_SLOTS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegistryError { Denied, Busy, Poisoned, Capacity, Exhausted, Configuration }
#[derive(Clone, Copy, Debug)]
pub(crate) struct Config { pub context:Context, pub runtime:u64, pub serial:u64, pub slots:usize }
/// Only a trusted freshness/fencing integration may supply these verdicts.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RestartEvidence { pub fenced:Verdict, pub fresh:Verdict, pub drained:bool }
/// Opaque, process-local registry reference. This is not a wire capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Handle {
    registry:u64, index:usize, generation:u64, runtime:u64, serial:u64, connection:u64, binding:u64,
}
/// Owned by the embedding operation/connection and retained across retries.
/// Creating another budget is a NEW admission decision, never client wire data.
pub(crate) struct UseBudget { remaining:u64, deadline:u64 }
impl UseBudget {
    pub(crate) fn new(work:u64, deadline:u64) -> Result<Self,RegistryError> {
        if work==0 || work>512 || deadline==0 {return Err(RegistryError::Configuration)}
        Ok(Self {remaining:work,deadline})
    }
    pub(crate) fn remaining(&self)->u64 {self.remaining}
    // Used by the transport only for a poll that did not enter with_caller.
    pub(crate) fn spend_poll(&mut self) -> bool {
        if self.remaining == 0 { return false; }
        self.remaining -= 1;
        true
    }
}
struct Entry<T> { peer:T, seal:Seal }
struct Slot<T> { generation:u64, entry:Option<Entry<T>> }
struct State<P:CallerProvider> {
    provider:P, config:Config, counter:u64, holder:u64, live:bool,
    slots:[Slot<P::Peer>;MAX_SLOTS],
}
pub(crate) struct Registry<P:CallerProvider> { id:u64, state:Mutex<State<P>> }
fn context_valid(c:Context)->bool {c.selected && c.anchor!=0 && c.installation!=0 && c.policy!=0 && c.challenge!=0}
fn same_context(a:Context,b:Context)->bool {
    a.anchor==b.anchor && a.installation==b.installation && a.policy==b.policy && a.challenge==b.challenge && a.selected==b.selected
}
impl<P:CallerProvider> Registry<P> {
    pub(crate) fn new(config:Config,provider:P)->Result<Self,RegistryError> {
        if !context_valid(config.context) || config.runtime==0 || config.serial==0 || !(1..=MAX_SLOTS).contains(&config.slots) {
            return Err(RegistryError::Configuration)
        }
        let id=REGISTRIES.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|v|v.checked_add(1)).map_err(|_|RegistryError::Exhausted)?;
        Ok(Self {id,state:Mutex::new(State {provider,config,counter:0,holder:0,live:true,
            slots:std::array::from_fn(|_|Slot {generation:0,entry:None})})})
    }
    fn lock(&self)->Result<MutexGuard<'_,State<P>>,RegistryError> {
        match self.state.try_lock() {
            Ok(s) if s.live=>Ok(s), Ok(_)=>Err(RegistryError::Denied),
            Err(TryLockError::WouldBlock)=>Err(RegistryError::Busy),
            Err(TryLockError::Poisoned(_))=>Err(RegistryError::Poisoned),
        }
    }
    fn snapshot_matches(s:&State<P>,v:Snapshot)->bool {
        same_context(s.config.context,v.context) && v.context.now>=s.config.context.now &&
        v.observed.scope.runtime==s.config.runtime && v.observed.scope.serial==s.config.serial
    }
    fn index(&self,s:&State<P>,h:Handle,current:bool)->Result<usize,RegistryError> {
        if h.registry!=self.id || h.index>=s.config.slots {return Err(RegistryError::Denied)}
        let slot=&s.slots[h.index];let e=slot.entry.as_ref().ok_or(RegistryError::Denied)?;
        let b=e.seal.scope;
        if h.generation!=slot.generation || h.runtime!=b.runtime || h.serial!=b.serial ||
            h.connection!=b.connection || h.binding!=b.binding ||
            (current && (h.runtime!=s.config.runtime || h.serial!=s.config.serial)) {return Err(RegistryError::Denied)}
        Ok(h.index)
    }
    /// Bounded publication from a trusted validator, never from incoming bytes.
    pub(crate) fn register(&self,peer:P::Peer,r:Request)->Result<Handle,RegistryError> {
        self.register_inner(peer,r,None)
    }
    /// The provider must independently bind evidence to the accepted channel.
    /// The transport-minted connection number is a correlation check, not proof.
    pub(crate) fn register_connection(&self,peer:P::Peer,r:Request,connection:u64)->Result<Handle,RegistryError> {
        self.register_inner(peer,r,Some(connection))
    }
    fn register_inner(&self,peer:P::Peer,r:Request,connection:Option<u64>)->Result<Handle,RegistryError> {
        let mut s=self.lock()?;
        let index=(0..s.config.slots).find(|&i|s.slots[i].entry.is_none() && s.slots[i].generation<u64::MAX).ok_or(RegistryError::Capacity)?;
        let v=s.provider.observe(&peer,r).ok_or(RegistryError::Denied)?;
        if !Self::snapshot_matches(&s,v) || !admitted(v) || !namespace(v,r) ||
            match v.observed.scope.role {Role::Caller=>caller(v,r).is_none(),Role::StorageServer=>!server(v,v.observed.scope.peer,r)} {
            return Err(RegistryError::Denied)
        }
        if connection.is_some_and(|id| id==0 || v.observed.scope.connection!=id || v.observed.scope.role!=Role::Caller) {
            return Err(RegistryError::Denied)
        }
        let generation=s.slots[index].generation.checked_add(1).ok_or(RegistryError::Exhausted)?;
        let b=v.observed.scope;
        s.config.context.now=v.context.now;
        s.slots[index]=Slot {generation,entry:Some(Entry {peer,seal:Seal::new(v)})};
        Ok(Handle {registry:self.id,index,generation,runtime:b.runtime,serial:b.serial,connection:b.connection,binding:b.binding})
    }
    /// Stale-serial entries may still be retired; retirement cannot authorize use.
    pub(crate) fn retire(&self,h:Handle)->Result<(),RegistryError> {
        let mut s=self.lock()?;let i=self.index(&s,h,false)?;s.slots[i].entry.take();Ok(())
    }
    /// All effective authority updates must linearize here, never via mutable
    /// provider state behind the lane. Busy means NOT applied; caller must retry.
    pub(crate) fn update(&self,c:Context)->Result<u64,RegistryError> {
        let mut s=self.lock()?;
        if !context_valid(c) || c.anchor!=s.config.context.anchor || c.installation!=s.config.context.installation ||
            c.now<s.config.context.now {return Err(RegistryError::Configuration)}
        let serial=s.config.serial.checked_add(1).ok_or(RegistryError::Exhausted)?;
        s.config.context=c;s.config.serial=serial;Ok(serial)
    }
    /// No live Rust guard is forcibly unlocked. After a real crash/restart the
    /// embedding must establish fencing/drainage outside this volatile registry.
    pub(crate) fn restart(&self,c:Context,runtime:u64,e:RestartEvidence)->Result<u64,RegistryError> {
        let mut s=self.lock()?;
        if e.fenced!=Verdict::Valid || e.fresh!=Verdict::Valid || !e.drained || !context_valid(c) || runtime==0 ||
            runtime==s.config.runtime || c.challenge==s.config.context.challenge ||
            c.anchor!=s.config.context.anchor || c.installation!=s.config.context.installation ||
            c.policy!=s.config.context.policy || c.now<s.config.context.now {return Err(RegistryError::Denied)}
        let serial=s.config.serial.checked_add(1).ok_or(RegistryError::Exhausted)?;
        for slot in &mut s.slots {slot.entry.take();}
        s.config.context=c;s.config.runtime=runtime;s.config.serial=serial;Ok(serial)
    }
    pub(crate) fn shutdown(&self)->Result<(),RegistryError> {
        let mut s=self.lock()?;s.live=false;for slot in &mut s.slots {slot.entry.take();}Ok(())
    }
    pub(crate) fn acquire<'a>(&'a self,h:Handle,r:Request,budget:&'a mut UseBudget)->Result<UseGuard<'a,P>,RegistryError> {
        if !shape(r) || budget.remaining==0 {return Err(RegistryError::Denied)}
        let mut s=self.lock()?;let index=self.index(&s,h,true)?;
        if s.config.context.now>=budget.deadline {return Err(RegistryError::Denied)}
        let ticket=s.counter.checked_add(1).ok_or(RegistryError::Exhausted)?;
        s.counter=ticket;s.holder=ticket;
        Ok(UseGuard {state:s,index,request:r,ticket,budget})
    }
}
/// Not Clone/Copy. Owns the mutex until Drop, including through backend errors.
/// Never hold this guard while waiting for network I/O or another authority lane.
pub(crate) struct UseGuard<'a,P:CallerProvider> {
    state:MutexGuard<'a,State<P>>,index:usize,request:Request,ticket:u64,budget:&'a mut UseBudget,
}
impl<P:CallerProvider> UseGuard<'_,P> {
    fn observe(&mut self)->Result<Snapshot,RegistryError> {
        let s=&mut *self.state;
        if s.holder!=self.ticket || self.budget.remaining==0 {return Err(RegistryError::Denied)}
        let entry=s.slots[self.index].entry.as_ref().ok_or(RegistryError::Denied)?;
        let v=s.provider.observe(&entry.peer,self.request).ok_or(RegistryError::Denied)?;
        if !entry.seal.current(v) || !Registry::<P>::snapshot_matches(s,v) || v.context.now>=self.budget.deadline {
            return Err(RegistryError::Denied)
        }
        // The trusted clock may advance, but never roll backwards across uses.
        s.config.context.now=v.context.now;Ok(v)
    }
    /// Only a fully admitted caller can enter this closure. The guard remains
    /// held for the ENTIRE closure. A failed effect does not refund the debit.
    fn with_caller<T>(&mut self,f:impl FnOnce(Context,Access)->T)->Result<T,RegistryError> {
        let v=self.observe()?;let a=caller(v,self.request).ok_or(RegistryError::Denied)?;
        self.budget.remaining-=1;Ok(f(v.context,a))
    }
    /// The backend request comes from the guard, not a second caller argument.
    pub(crate) fn execute<B:super::super::DurableRecord>(&mut self,backend:&mut B,capacity:bool)
        -> Result<Result<super::super::Outcome,super::super::Error>,RegistryError>
    {
        let request=self.request;
        self.with_caller(|c,a|super::super::transact(backend,c,request,a,capacity))
    }
    /// Disclosure callbacks are trusted nonblocking transport writes. No Context
    /// or Access is returned; the exact request must still match the guard.
    pub(crate) fn disclose<T>(&mut self,request:Request,write:impl FnOnce()->T)->Result<T,RegistryError> {
        if request!=self.request {return Err(RegistryError::Denied)}
        self.with_caller(|_,_|write())
    }
    pub(crate) fn recognize_server(&mut self,expected:u64)->Result<(),RegistryError> {
        let v=self.observe()?;
        if !server(v,expected,self.request) {return Err(RegistryError::Denied)}
        self.budget.remaining-=1;Ok(())
    }
}
impl<P:CallerProvider> Drop for UseGuard<'_,P> {
    fn drop(&mut self) {self.state.holder=0;}
}
#[cfg(test)]
#[path="registry/tests.rs"]
mod tests;
