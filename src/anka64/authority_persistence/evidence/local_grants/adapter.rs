//! Hosted LG110 adapter. Ordinary-client crypto/HTTP runs outside the owner guard.
//! Private pipes, not preflight JSON, supply evidence. No live E9/E11 publication.
//! The trusted embedding provisions all mappings and authenticates Channel from
//! the actual transport. This module does not create a transport from peer fields.
use super::*;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path="adapter/codec.rs"] mod codec;
#[path="adapter/process.rs"] mod process;

/// Hosted seconds clock. The adapter/owner retain high-water marks; Instant
/// additionally bounds subprocess lifetime independently of wall-clock changes.
pub(crate) struct HostClock { start: Instant }
impl HostClock { pub(crate) fn new() -> Self { Self { start: Instant::now() } } }
impl Clock for HostClock {
    fn now(&mut self) -> Now {
        Now { tick: self.start.elapsed().as_secs(),
            wall: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0) }
    }
}

/// Trusted installation selection. Full token bytes are retained for the whole
/// bounded owner; the numeric token handle is never derived from a truncated hash.
pub(crate) struct Profile {
    pub config_path: PathBuf,
    pub token: Vec<u8>,
    pub issuer: String, pub audience: String, pub client: String, pub subject: String,
    pub holder: [u8; 32],
    pub subject_id: u64, pub holder_id: u64, pub max_age: u64,
}
/// Construct ONLY from a trusted, authenticated transport observation. binding
/// must identify the actual channel (e.g. a TLS exporter), never a peer nonce.
/// The downstream Kernel/Fabric gate still rechecks channel/runtime liveness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Channel { peer: u64, scope: Scope, holder: [u8; 32], binding: [u8; 32] }
impl Channel {
    pub(crate) fn from_authenticated_transport(peer: u64, scope: Scope, holder: [u8; 32], binding: [u8; 32]) -> Result<Self, Error> {
        if peer != scope.peer || !scope.valid() || holder == [0; 32] || binding == [0; 32] { return Err(Error::Denied); }
        Ok(Self { peer, scope, holder, binding })
    }
}
struct SharedClock<C>(Arc<Mutex<C>>);
impl<C> Clone for SharedClock<C> { fn clone(&self) -> Self { Self(self.0.clone()) } }
impl<C: Clock> Clock for SharedClock<C> {
    fn now(&mut self) -> Now { self.0.lock().expect("trusted clock poisoned").now() }
}
#[derive(Default)]
struct Slots { completion: Option<Completion>, possession: Option<(Channel, Possession)> }
struct Mailbox(Arc<Mutex<Slots>>);
impl Evidence for Mailbox {
    type Peer = Channel;
    fn completion(&mut self, q: Query) -> Option<Completion> {
        let mut s = self.0.try_lock().ok()?;
        if s.completion.as_ref()?.query != q { return None; }
        s.completion.take()
    }
    fn possession(&mut self, channel: &Channel, p: Proposal) -> Option<Possession> {
        let mut s = self.0.try_lock().ok()?;
        let (actual, proof) = s.possession.as_ref()?;
        if actual != channel || proof.proposal != p { return None; }
        s.possession.take().map(|(_, proof)| proof)
    }
}
/// Separate revocation handle remains usable while the adapter waits on HTTP.
pub(crate) struct Revoker<C>(Arc<Owner<Mailbox, SharedClock<C>>>);
impl<C: Clock> Revoker<C> { pub(crate) fn revoke(&self) -> Result<(), Error> { self.0.revoke() } }

/// A signing request, never permission. Fields cannot be replaced by a caller.
/// Sign bytes() with the holder's RSA key using SHA-256/PKCS#1 v1.5. This adapter
/// never signs. No token or signature is printed by its worker.
pub(crate) struct Challenge { proposal: Proposal, channel: Channel, record: Vec<u8> }
impl Challenge { pub(crate) fn bytes(&self) -> &[u8] { &self.record } }

pub(crate) struct Adapter<C> {
    owner: Arc<Owner<Mailbox, SharedClock<C>>>, slots: Arc<Mutex<Slots>>,
    clock: SharedClock<C>, config: Config, profile: Profile, session: [u8; 32],
    input_binding: [u8; 32], worker_deadline: Instant, preparations: u64, workers: u64,
    last_sample: Now, invalid_clock: bool,
}
impl<C: Clock> Adapter<C> {
    /// Hosted profile clock ticks MUST be monotonic seconds, wall time UNIX
    /// seconds. The owner checks rollback; an independent Instant bounds workers.
    /// Full installation policy must explicitly allocate this NEW operation.
    pub(crate) fn new(config: Config, profile: Profile, clock: C) -> Result<Self, Error> {
        if !codec::valid_profile(&profile) || config.identity.max_age != profile.max_age ||
            profile.token.len() as u64 > config.identity.max_bytes { return Err(Error::Configuration); }
        let mut clock = SharedClock(Arc::new(Mutex::new(clock)));
        let now = clock.now();
        let seconds = config.deadline.checked_sub(now.tick).ok_or(Error::Configuration)?;
        // The hosted worker lifetime is bounded even if the embedding's clock stops.
        let worker_deadline = Instant::now().checked_add(Duration::from_secs(seconds.min(30))).ok_or(Error::Configuration)?;
        let mut session = [0u8; 32];
        std::fs::File::open("/dev/urandom").map_err(|_| Error::Denied)?.read_exact(&mut session).map_err(|_| Error::Denied)?;
        if session == [0; 32] { return Err(Error::Denied); }
        let slots = Arc::new(Mutex::new(Slots::default()));
        let owner = Arc::new(Owner::new(config, Mailbox(slots.clone()), clock.clone())?);
        Ok(Self { owner, slots, clock, config, profile, session, input_binding: [0; 32],
            worker_deadline, preparations: config.work, workers: config.work, last_sample: now, invalid_clock: false })
    }
    pub(crate) fn revoker(&self) -> Revoker<C> { Revoker(self.owner.clone()) }
    pub(crate) fn view(&self) -> Result<View, Error> { self.owner.view() }
    fn sample(&mut self) -> Result<Now, Error> {
        if self.invalid_clock { return Err(Error::Poisoned); }
        let v = self.owner.view()?;
        let now = self.clock.now();
        if now.wall < self.last_sample.wall.max(v.last_wall) || now.tick < self.last_sample.tick.max(v.last_tick) {
            self.invalid_clock = true;
            let _ = self.owner.revoke(); // Terminal even if a later clock sample recovers.
            return Err(Error::Poisoned);
        }
        self.last_sample = now;
        Ok(now)
    }
    fn clear(&self) -> Result<(), Error> {
        let mut s = self.slots.try_lock().map_err(|_| Error::Busy)?;
        s.completion = None; s.possession = None; Ok(())
    }
    fn invoke(&mut self, record: &[u8], signature: &[u8]) -> Result<codec::Reply, ()> {
        self.workers = self.workers.checked_sub(1).ok_or(())?; // Reserve before process/IO; no refund.
        let raw = codec::request(record, signature)?;
        let output = process::worker(&self.profile.config_path, &raw, record.len() + 72, self.worker_deadline)?;
        codec::decode(record, &output)
    }
    pub(crate) fn refresh(&mut self) -> Result<Refresh, Error> {
        self.sample()?;
        self.clear()?;
        let q = self.owner.begin_query()?; // Reserve and unlock BEFORE remote work.
        let record = codec::record(1, self.session, codec::query(q), self.config.scope,
            self.profile.holder, [0; 32], self.input_binding, &self.profile);
        let reply = self.invoke(&record, &[]);
        self.complete_refresh(q, reply)
    }
    fn complete_refresh(&mut self, q: Query, reply: Result<codec::Reply, ()>) -> Result<Refresh, Error> {
        if reply.as_ref().is_ok_and(|r| r.outcome == 3 ||
            (r.outcome != 0 && self.input_binding != [0;32] && r.binding != self.input_binding)) {
            self.owner.revoke()?; return Ok(Refresh::Revoked);
        }
        let now = self.sample()?;
        let mut complete = Completion { query: q, checked: Verdict::Valid, result: Verdict::Unknown, observation: None };
        let mut binding = None;
        if let Ok(r) = reply {
            if matches!(r.outcome, 1 | 2) {
                binding = Some(r.binding);
                complete.result = if r.outcome == 1 { Verdict::Valid } else { Verdict::Invalid };
                complete.observation = Some(Observation {
                    token: Token { reference: self.config.grant.token, issuer: self.config.identity.issuer,
                        audience: self.config.identity.audience, client: self.config.identity.client,
                        subject: self.profile.subject_id, holder: self.profile.holder_id,
                        keyset: self.config.identity.keyset, profile: self.config.identity.profile,
                        issued: r.times[0], first: r.times[1], until: r.times[2],
                        syntax: Verdict::Valid, signature: Verdict::Valid },
                    status: Status { token: q.token, issuer: q.issuer, query: q.sequence, started: q.started,
                        observed: now.tick, checked: Verdict::Valid, active: Verdict::Valid },
                    mapping: Mapping { issuer: q.issuer, subject: self.profile.subject_id,
                        client: self.config.identity.client, installation: self.config.scope.installation,
                        peer: self.config.scope.peer, kind: self.config.scope.kind, policy: self.config.scope.policy,
                        enabled: Verdict::Valid }, bytes: self.profile.token.len() as u64 });
            }
        }
        self.slots.try_lock().map_err(|_| Error::Busy)?.completion = Some(complete);
        let result = self.owner.complete(q);
        // Only successful initial issuance fixes the private configuration binding.
        if matches!(result, Ok(Refresh::Issued | Refresh::Refreshed)) {
            self.input_binding = binding.ok_or(Error::Denied)?;
        }
        result
    }
    pub(crate) fn prepare(&mut self, channel: Channel) -> Result<Challenge, Error> {
        // Bounded preparation budget, never refunded by retries or refresh.
        if self.preparations == 0 { return Err(Error::Exhausted); }
        self.preparations -= 1;
        let v = self.owner.view()?; let now = self.sample()?;
        if v.mode != Mode::Issued || !v.usable(now) || self.input_binding == [0; 32] ||
            channel.scope != self.config.scope || channel.holder != self.profile.holder ||
            Instant::now() >= self.worker_deadline { return Err(Error::Denied); }
        let proposal = Proposal { owner: v.owner, domain: v.domain, incarnation: v.incarnation,
            grant_id: v.grant_id, revision: v.revision, sequence: v.next_seq, at_tick: now.tick,
            scope: self.config.scope };
        let record = codec::record(2, self.session, codec::proposal(proposal, self.config), self.config.scope,
            self.profile.holder, channel.binding, self.input_binding, &self.profile);
        Ok(Challenge { proposal, channel, record })
    }
    fn stage_possession(&self, channel: Channel, p: Proposal, r: codec::Reply) -> Result<(), Error> {
        if r.outcome == 3 || (r.outcome != 0 && r.binding != self.input_binding) {
            self.owner.revoke()?; return Err(Error::Denied);
        }
        if r.outcome == 1 && r.times == [0; 3] && r.binding != [0; 32] {
            self.slots.try_lock().map_err(|_| Error::Busy)?.possession = Some((channel, Possession {
                proposal: p, checked: Verdict::Valid, channel: Verdict::Valid,
                proof: Proof { token: self.config.grant.token, issuer: self.config.identity.issuer,
                    signer: self.profile.holder_id, scope: self.config.scope, signature: Verdict::Valid } }));
        }
        Ok(())
    }
    pub(crate) fn attempt<T>(&mut self, channel: Channel, challenge: Challenge, signature: &[u8],
        gate: impl FnOnce(&Scope) -> bool, submit: impl FnOnce() -> Result<T, ()>) -> Result<T, Error>
    {
        self.clear()?;
        let p = challenge.proposal; let v = self.owner.view()?; let now = self.sample()?;
        // Invalid/stale input still reaches the owner to spend its attempt, but
        // never launches expensive verification or populates the possession slot.
        if channel == challenge.channel && channel.scope == self.config.scope &&
            channel.holder == self.profile.holder && v.mode == Mode::Issued && v.usable(now) &&
            v.matches(p, self.config.scope, now) && (256..=512).contains(&signature.len()) {
            let expected = codec::record(2, self.session, codec::proposal(p, self.config), self.config.scope,
                self.profile.holder, channel.binding, self.input_binding, &self.profile);
            if expected == challenge.record {
                if let Ok(r) = self.invoke(&expected, signature) {
                    self.stage_possession(channel, p, r)?;
                }
            }
        }
        self.owner.attempt(&channel, p, gate, submit)
    }
}

#[cfg(test)]
#[path="adapter/tests.rs"] mod tests;
