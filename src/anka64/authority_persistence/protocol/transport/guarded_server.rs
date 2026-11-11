//! Opt-in E5 reference server. The binder must verify evidence for this actual
//! stream; neither a loopback address nor the transport nonce is a credential.
use super::*;
use super::super::guarded::{self, DeliveryError, DispatchError, PendingReply, ReplySink};
use super::super::super::evidence::{CallerProvider, registry::{Handle, Registry, RegistryError, UseBudget}};
use std::sync::Arc;

static CHANNELS: AtomicU64 = AtomicU64::new(1);
// Bound the work and disclosure of one successful socket write per poll.
const WRITE_QUANTUM: usize = 64;

struct Channel {
    stream: TcpStream,
    handle: Handle,
}
impl ReplySink for Channel {
    fn peer(&self) -> Option<Handle> { Some(self.handle) }
}
impl Write for Channel {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.write(&bytes[..bytes.len().min(WRITE_QUANTUM)])
    }
    fn flush(&mut self) -> io::Result<()> { self.stream.flush() }
}

enum Phase { Reading, Ready, Sending(PendingReply) }
struct Slot<P: CallerProvider> {
    registry: Arc<Registry<P>>,
    channel: Channel,
    id: u64,
    deadline: Instant,
    budget: UseBudget,
    phase: Phase,
    input: [u8; REQUEST_BYTES + 1],
    received: usize,
}
impl<P: CallerProvider> Drop for Slot<P> {
    fn drop(&mut self) {
        // The server exclusively owns the registry; no live guard escapes a poll.
        // A poisoned registry remains unusable until the entire instance is dropped.
        let _ = self.registry.retire(self.channel.handle);
        self.input.fill(0);
    }
}
impl<P: CallerProvider> Slot<P> {
    fn tick<B: DurableRecord>(&mut self, backend: &mut B, admission: DispatchBudget, capacity: bool) -> bool {
        if Instant::now() >= self.deadline || self.budget.remaining() == 0 { return false; }
        match &mut self.phase {
            Phase::Reading => {
                self.budget.spend_poll();
                match self.channel.stream.read(&mut self.input[self.received..]) {
                    Ok(0) if self.received == REQUEST_BYTES => { self.phase = Phase::Ready; true }
                    Ok(0) => false,
                    Ok(n) => { self.received += n; self.received <= REQUEST_BYTES }
                    Err(e) => transient(&e),
                }
            }
            Phase::Ready => {
                match guarded::dispatch(backend, &self.registry, self.channel.handle,
                        &self.input[..self.received], true, admission, &mut self.budget, capacity) {
                    Ok(reply) => { self.phase = Phase::Sending(reply); true }
                    Err(DispatchError::Registry(RegistryError::Busy)) => self.budget.spend_poll(),
                    Err(_) => false,
                }
            }
            Phase::Sending(reply) => match reply.write_once(&self.registry, &mut self.budget, &mut self.channel) {
                Ok(_) => !reply.complete(),
                Err(DeliveryError::Registry(RegistryError::Busy)) => self.budget.spend_poll(),
                Err(DeliveryError::Io(e)) => transient(&e), // already debited under guard
                Err(_) => false,
            }
        }
    }
}

/// One fixed table, one owned registry. Fresh registration per accepted stream.
/// The legacy Server remains separately selectable, never a fallback on denial.
pub(crate) struct GuardedServer<B: DurableRecord, P: CallerProvider> {
    listener: Option<TcpListener>,
    config: Config,
    service: u64,
    registry: Arc<Registry<P>>,
    backend: B,
    slots: Vec<Option<Slot<P>>>,
    live: usize,
    bytes: u64,
}
impl<B: DurableRecord, P: CallerProvider> GuardedServer<B,P> {
    pub(crate) fn bind(address: SocketAddr, config: Config, backend: B, registry: Registry<P>) -> io::Result<Self> {
        if !address.ip().is_loopback() || !config.valid() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,"loopback/configuration required"));
        }
        let service = SERVICES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| io::Error::other("service identity exhausted"))?;
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener: Some(listener), config, service, backend, registry: Arc::new(registry),
            slots: (0..config.slots).map(|_| None).collect(), live: 0, bytes: 0 })
    }
    pub(crate) fn address(&self) -> io::Result<SocketAddr> {
        self.listener.as_ref().ok_or_else(|| io::Error::other("closed"))?.local_addr()
    }
    pub(crate) fn usage(&self) -> (usize,u64) { (self.live,self.bytes) }
    #[cfg(test)]
    pub(crate) fn remaining(&self, t: Ticket) -> Option<u64> {
        self.slots.iter().flatten().find(|s| t.service==self.service && t.sequence==s.id)
            .map(|s| s.budget.remaining())
    }
    // Test observation only: no reply bytes, handles or authority escape.
    #[cfg(test)]
    fn test_phase(&self, t: Ticket) -> Option<&Phase> {
        self.slots.iter().flatten().find(|s| t.service == self.service && t.sequence == s.id)
            .map(|s| &s.phase)
    }
    #[cfg(test)]
    pub(crate) fn ready(&self, t: Ticket) -> bool {
        matches!(self.test_phase(t), Some(Phase::Ready))
    }
    #[cfg(test)]
    pub(crate) fn sent_bytes(&self, t: Ticket) -> Option<usize> {
        match self.test_phase(t) {
            Some(Phase::Sending(reply)) => Some(reply.sent_bytes()),
            _ => None,
        }
    }
    pub(crate) fn update(&self, c: Context) -> Result<u64,RegistryError> { self.registry.update(c) }
    pub(crate) fn cancel(&mut self, ticket: Ticket) -> bool {
        if ticket.service != self.service { return false; }
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|s| s.id == ticket.sequence) {
                slot.take(); self.live -= 1; self.bytes -= CHARGE; return true;
            }
        }
        false
    }
    pub(crate) fn shutdown(&mut self) {
        self.listener.take();
        for slot in &mut self.slots { slot.take(); }
        self.live = 0; self.bytes = 0;
    }

    /// Trusted, bounded binder supplies the provider peer, admission scope and
    /// absolute provider-clock deadline. None denies before reading any bytes.
    pub(crate) fn poll<F>(&mut self, binder: &mut F, capacity: bool) -> io::Result<Poll>
    where F: FnMut(&TcpStream,u64) -> Option<(P::Peer,Request,u64)> {
        let mut report = Poll { accepted: None, closed: 0, live: self.live };
        for cell in &mut self.slots {
            let Some(mut slot) = cell.take() else { continue };
            let admission = DispatchBudget { slots: (self.live-1) as u64, slot_limit: self.config.slots as u64,
                bytes: self.bytes-CHARGE, byte_limit: self.config.byte_limit,
                work: slot.budget.remaining(), now: 0, deadline: 1 };
            // Temporarily take ownership of the existing charge. Even unwind
            // during a backend effect closes this slot, never redispatching it.
            let mut charge = Reservation {live:&mut self.live, bytes:&mut self.bytes, installed:false};
            if slot.tick(&mut self.backend, admission, capacity) {
                *cell = Some(slot); charge.installed = true;
            } else { report.closed += 1; }
        }

        if let Some(listener) = &self.listener {
            if self.live < self.config.slots && self.config.byte_limit-self.bytes >= CHARGE {
                match listener.accept() {
                    Ok((stream,_)) => {
                        let mut charge = Reservation::new(&mut self.live,&mut self.bytes);
                        stream.set_nonblocking(true)?;
                        let id = CHANNELS.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|v|v.checked_add(1))
                            .map_err(|_|io::Error::other("channel identity exhausted"))?;
                        let deadline = Instant::now() + self.config.timeout;
                        let bound = binder(&stream,id).and_then(|(peer,request,until)| {
                            let budget = UseBudget::new(self.config.work,until).ok()?;
                            if Instant::now() >= deadline { return None; }
                            let handle = self.registry.register_connection(peer,request,id).ok()?;
                            Some((handle,budget))
                        });
                        if let Some((handle,budget)) = bound {
                            let cell = self.slots.iter_mut().find(|s|s.is_none()).expect("reserved slot");
                            *cell = Some(Slot { registry: self.registry.clone(), channel: Channel {stream,handle},
                                id, deadline, budget, phase: Phase::Reading, input: [0;REQUEST_BYTES+1], received: 0 });
                            charge.installed = true;
                            report.accepted = Some(Ticket {service:self.service,sequence:id});
                        } else {report.closed += 1;}
                    }
                    Err(e) if transient(&e) => {},
                    Err(e) => return Err(e),
                }
            }
        }
        report.live = self.live;
        Ok(report)
    }
}
