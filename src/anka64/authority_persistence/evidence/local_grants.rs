//! LG110 bounded local grant owner. One token/grant, one original operation
//! budget, no regrant/restore API. This does NOT establish SA110 remote control,
//! manufacture KC110 current-authority fences, or enable the live/boot CLI.
//!
//! The trusted embedding selects a LOCAL domain/grant independently of Keycloak.
//! Token handles identify entire immutable bytes, not jti or truncated digests.
//! Only private, fully checked evidence enters this owner; peer JSON cannot
//! construct validator verdicts. No production provider is supplied here.
//!
//! Begin returns a correlation ticket after releasing the guard. Perform remote
//! IO/cryptography outside this module; completion only reads the trusted staged
//! result. All in-guard callbacks must be bounded, nonblocking and non-reentrant.
//! The host/native clock and evidence implementations are explicit dependencies.
use super::super::Verdict;
use super::serialized_authority::candidate::IdentityEvidence;
pub(crate) use super::serialized_authority::candidate::{
    Candidate, Configuration, Grant, Mapping, Proof, Scope, Status, Token,
};
// Reuse clock vocabulary only, never the SA110 coordinator or its attestation.
pub(crate) use super::serialized_authority::{Clock, Now};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

static OWNERS: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode { Unissued, Issued, Revoked, Poisoned }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error { Configuration, Exhausted, Busy, Denied, Poisoned, EffectUncertain }
/// Processing result, NOT a permission or a receipt usable by an effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refresh { Issued, Refreshed, Unavailable, Revoked }

/// Trusted, explicit NEW operation allocation. Reconnect/refresh cannot call this
/// to refill an existing operation; the embedding must enforce outer quotas.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Config {
    pub domain: u64, pub incarnation: u64, pub grant_id: u64,
    pub work: u64, pub deadline: u64, pub boot: u64,
    pub identity: Configuration, pub scope: Scope, pub grant: Grant,
}
/// Read-only diagnostic data. There is no constructor restoring it as state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct View {
    pub owner: u64, pub domain: u64, pub incarnation: u64, pub grant_id: u64,
    pub revision: u64, pub next_seq: u64, pub remaining: u64, pub deadline: u64,
    pub last_tick: u64, pub last_wall: u64, pub effects: u64, pub boot: u64,
    pub mode: Mode, pub pending: Option<Query>,
}
/// Copyable correlation only, never authority. owner is an additional process-
/// local non-reused identity; incarnation freshness across restart is separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Query {
    pub owner: u64, pub domain: u64, pub incarnation: u64, pub grant_id: u64,
    pub revision: u64, pub sequence: u64, pub started: u64,
    pub token: u64, pub issuer: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Observation {
    pub token: Token, pub status: Status, pub mapping: Mapping, pub bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Completion {
    pub query: Query, pub checked: Verdict, pub result: Verdict,
    pub observation: Option<Observation>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Proposal {
    pub owner: u64, pub domain: u64, pub incarnation: u64, pub grant_id: u64,
    pub revision: u64, pub sequence: u64, pub at_tick: u64, pub scope: Scope,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Possession {
    pub proposal: Proposal, pub checked: Verdict, pub proof: Proof, pub channel: Verdict,
}

/// Trusted integration interface; defaults supply no authority. Completion is
/// a bounded lookup of a result verified/staged OUTSIDE the owner lock, with
/// exact original-query correlation. Unknown means outage/unavailable; Invalid
/// means authenticated negative evidence for this token, not a network failure.
/// checked covers the ENTIRE result, including all observation fields.
///
/// Possession must independently bind an authenticated peer, actual channel,
/// holder and the entire LOCAL-GRANT-USE proposal (including scope, owner and
/// sequence). Echoing the requested proposal is not verification. A source may
/// share a private bounded mailbox with an external worker; this owner never
/// exposes its provider or accepts a peer-selected ready/permission bit.
pub(crate) trait Evidence {
    type Peer;
    fn completion(&mut self, _query: Query) -> Option<Completion> { None }
    fn possession(&mut self, _peer: &Self::Peer, _proposal: Proposal) -> Option<Possession> { None }
    /// Full owner/new-incarnation non-reuse verification, not numeric inequality.
    fn fresh_incarnation(&mut self, _owner: View, _new: u64) -> Verdict { Verdict::Unknown }
}
pub(crate) struct DenyEvidence;
impl Evidence for DenyEvidence { type Peer = (); }

struct Inner<P, C> {
    config: Config, state: View, observation: Option<Observation>, source: P, clock: C,
}
/// No Clone/Copy, state restoration or provider escape. Arc shares this owner.
pub(crate) struct Owner<P, C> { inner: Mutex<Inner<P, C>> }

impl View {
    fn clock_ok(self, now: Now) -> bool { now.wall >= self.last_wall && now.tick >= self.last_tick }
    fn integrity(self, now: Now) -> bool {
        self.owner != 0 && self.domain != 0 && self.incarnation != 0 && self.grant_id != 0 &&
        self.revision != 0 && self.next_seq != 0 && self.next_seq < u64::MAX &&
        self.remaining <= 512 && self.clock_ok(now)
    }
    fn usable(self, now: Now) -> bool {
        self.integrity(now) && matches!(self.mode, Mode::Unissued | Mode::Issued) &&
        self.remaining != 0 && now.tick < self.deadline
    }
    fn observe(&mut self, now: Now) {
        if !self.clock_ok(now) { self.mode = Mode::Poisoned; }
        self.last_wall = self.last_wall.max(now.wall);
        self.last_tick = self.last_tick.max(now.tick);
    }
    fn cost(&mut self, now: Now) {
        if !self.integrity(now) { self.mode = Mode::Poisoned; }
        self.remaining = self.remaining.saturating_sub(1);
        if self.next_seq != 0 && self.next_seq < u64::MAX { self.next_seq += 1; }
        self.observe(now);
    }
    fn matches(self, p: Proposal, scope: Scope, now: Now) -> bool {
        p.owner == self.owner && p.domain == self.domain && p.incarnation == self.incarnation &&
        p.grant_id == self.grant_id && p.revision == self.revision && p.sequence == self.next_seq &&
        p.at_tick == now.tick && p.scope == scope
    }
}
impl Observation {
    fn identity(self, c: Config, query: u64) -> IdentityEvidence {
        IdentityEvidence { config: c.identity, token: self.token, status: self.status,
            mapping: self.mapping, scope: c.scope, grant: c.grant, query, bytes: self.bytes }
    }
    fn candidate(self, c: Config, p: Possession) -> Candidate {
        Candidate { config: c.identity, token: self.token, status: self.status,
            mapping: self.mapping, scope: c.scope, proof: p.proof, grant: c.grant,
            query: self.status.query, bytes: self.bytes, channel: p.channel }
    }
    fn same_identity(self, previous: Self) -> bool {
        self.token == previous.token && self.mapping == previous.mapping && self.bytes == previous.bytes
    }
}

impl<P: Evidence, C: Clock> Owner<P, C> {
    pub(crate) fn new(config: Config, source: P, mut clock: C) -> Result<Self, Error> {
        let now = clock.now();
        if config.domain == 0 || config.incarnation == 0 || config.grant_id == 0 ||
            !(1..=512).contains(&config.work) || config.deadline <= now.tick ||
            !config.identity.valid() || !config.scope.valid() ||
            config.scope.installation != config.identity.installation ||
            config.scope.policy != config.identity.policy || config.grant.scope != config.scope ||
            config.grant.token == 0 || config.grant.permission != Verdict::Valid ||
            config.grant.first >= config.grant.until { return Err(Error::Configuration); }
        let owner = OWNERS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::Exhausted)?;
        Ok(Self { inner: Mutex::new(Inner { config, source, clock, observation: None, state: View {
            owner, domain: config.domain, incarnation: config.incarnation, grant_id: config.grant_id,
            revision: 1, next_seq: 1, remaining: config.work, deadline: config.deadline,
            last_tick: now.tick, last_wall: now.wall, effects: 0, boot: config.boot,
            mode: Mode::Unissued, pending: None,
        } }) })
    }
    fn lock(&self) -> Result<MutexGuard<'_, Inner<P, C>>, Error> {
        match self.inner.try_lock() {
            Ok(s) => Ok(s), Err(TryLockError::WouldBlock) => Err(Error::Busy),
            Err(TryLockError::Poisoned(_)) => Err(Error::Poisoned),
        }
    }
    pub(crate) fn view(&self) -> Result<View, Error> { Ok(self.lock()?.state) }
    fn step(s: &mut Inner<P, C>) -> (View, Now) {
        let before = s.state;
        let now = s.clock.now();
        s.state.cost(now); // Reserve before any provider/gate/submit can unwind.
        (before, now)
    }
    fn time(s: &mut Inner<P, C>) -> Now {
        let now = s.clock.now(); s.state.observe(now); now
    }
    fn denied(s: &Inner<P, C>) -> Error {
        if s.state.mode == Mode::Poisoned { Error::Poisoned } else { Error::Denied }
    }
    fn close(s: &mut Inner<P, C>, revision: u64) {
        s.state.revision = revision.saturating_add(1);
        s.state.pending = None;
        s.state.mode = if s.state.mode == Mode::Poisoned || revision == u64::MAX {
            Mode::Poisoned
        } else { Mode::Revoked };
    }
    /// Returns after unlocking. Starting another query while pending denies and
    /// spends work; it cannot replace the original start/correlation or deadline.
    pub(crate) fn begin_query(&self) -> Result<Query, Error> {
        let mut s = self.lock()?; let (before, now) = Self::step(&mut s);
        if s.state.mode == Mode::Poisoned || !before.usable(now) || before.pending.is_some() {
            return Err(Self::denied(&s));
        }
        let q = Query { owner: before.owner, domain: before.domain, incarnation: before.incarnation,
            grant_id: before.grant_id, revision: before.revision, sequence: before.next_seq,
            started: now.tick, token: s.config.grant.token, issuer: s.config.identity.issuer };
        s.state.pending = Some(q);
        Ok(q)
    }
    /// Consume only an exactly correlated, privately staged result. A verified
    /// negative can close after exhaustion; that exception permits a bounded
    /// mailbox lookup, never fresh network/crypto work or positive admission.
    pub(crate) fn complete(&self, requested: Query) -> Result<Refresh, Error> {
        let mut s = self.lock()?; let (before, first) = Self::step(&mut s);
        if s.state.mode == Mode::Poisoned || before.pending != Some(requested) ||
            requested.revision != before.revision { return Err(Self::denied(&s)); }
        let reply = s.source.completion(requested);
        let now = Self::time(&mut s);
        let Some(reply) = reply else { return Err(Self::denied(&s)); };
        if reply.checked != Verdict::Valid || reply.query != requested { return Err(Self::denied(&s)); }
        s.state.pending = None;
        if reply.result == Verdict::Invalid {
            Self::close(&mut s, before.revision);
            return if s.state.mode == Mode::Poisoned { Err(Error::Poisoned) } else { Ok(Refresh::Revoked) };
        }
        if s.state.mode == Mode::Poisoned { return Err(Error::Poisoned); }
        if reply.result == Verdict::Unknown { return Ok(Refresh::Unavailable); }
        let Some(observation) = reply.observation else { return Err(Error::Denied); };
        // No token replacement under a reused reference, even if a provider errs.
        let same = s.observation.is_none_or(|old| observation.same_identity(old));
        if !before.usable(first) || !before.usable(now) || !same ||
            observation.status.started != requested.started ||
            !observation.identity(s.config, requested.sequence).valid(now) { return Err(Error::Denied); }
        s.observation = Some(observation);
        s.state.mode = Mode::Issued;
        Ok(if before.mode == Mode::Unissued { Refresh::Issued } else { Refresh::Refreshed })
    }
    /// Trusted local revocation/policy invalidation; never a remote admin action.
    /// Closing does not require remaining work, an unexpired deadline or HTTP.
    pub(crate) fn revoke(&self) -> Result<(), Error> {
        let mut s = self.lock()?; let (before, _) = Self::step(&mut s);
        Self::close(&mut s, before.revision);
        if s.state.mode == Mode::Poisoned { Err(Error::Poisoned) } else { Ok(()) }
    }
    /// In-memory close and incarnation verification only. Not disk restore,
    /// cross-process uniqueness, regrant or boot-attempt consumption. At exhausted
    /// work or expired deadline, skip verification and remain permanently poisoned.
    pub(crate) fn restart(&self, incarnation: u64) -> Result<(), Error> {
        let mut s = self.lock()?; let (before, first) = Self::step(&mut s);
        Self::close(&mut s, before.revision);
        let fresh = if before.usable(first) && s.state.mode != Mode::Poisoned {
            s.source.fresh_incarnation(before, incarnation)
        } else { Verdict::Unknown };
        let now = Self::time(&mut s);
        if fresh == Verdict::Valid && incarnation != 0 && incarnation != before.incarnation &&
            before.usable(now) && s.state.mode != Mode::Poisoned {
            s.state.incarnation = incarnation;
            Ok(())
        } else { s.state.mode = Mode::Poisoned; Err(Error::Poisoned) }
    }
    /// Serialize current local authority and a synchronous, bounded effect.
    /// Each fragment/final delivery needs another attempt. gate retains all
    /// existing Kernel/Fabric/permit/content checks. Neither closure gets a
    /// transferable permission. Busy means no transition: outer polling must
    /// still charge ingress/work; never spin or perform IO inside the guard.
    pub(crate) fn attempt<T>(
        &self, peer: &P::Peer, proposal: Proposal,
        gate: impl FnOnce(&Scope) -> bool, submit: impl FnOnce() -> Result<T, ()>,
    ) -> Result<T, Error> {
        let mut s = self.lock()?; let (before, first) = Self::step(&mut s);
        if before.effects == u64::MAX { s.state.mode = Mode::Poisoned; }
        if s.state.mode == Mode::Poisoned || before.mode != Mode::Issued ||
            !before.usable(first) || !before.matches(proposal, s.config.scope, first) {
            return Err(Self::denied(&s));
        }
        let Some(observation) = s.observation else { return Err(Error::Denied); };
        let possession = s.source.possession(peer, proposal);
        let now = Self::time(&mut s);
        let Some(possession) = possession else { return Err(Self::denied(&s)); };
        let candidate = observation.candidate(s.config, possession);
        if possession.checked != Verdict::Valid || possession.proposal != proposal ||
            s.state.mode == Mode::Poisoned || !before.usable(now) ||
            !before.matches(proposal, s.config.scope, now) || !candidate.valid(now) {
            return Err(Self::denied(&s));
        }
        let permitted = gate(&s.config.scope);
        let now = Self::time(&mut s);
        if !permitted || s.state.mode == Mode::Poisoned || !before.usable(now) ||
            !before.matches(proposal, s.config.scope, now) || !candidate.valid(now) {
            return Err(Self::denied(&s));
        }
        s.state.effects += 1;
        match submit() {
            Ok(value) => Ok(value),
            Err(()) => {
                // Uncertain submission composes with terminal local closure;
                // keep the submitted count and charge that closing transition.
                let (loss, _) = Self::step(&mut s);
                Self::close(&mut s, loss.revision);
                s.state.mode = Mode::Poisoned;
                Err(Error::EffectUncertain)
            }
        }
    }
}

#[cfg(test)]
#[path="local_grants/tests.rs"]
mod tests;

// Hosted ordinary-client verification. Native transport/crypto suppliers remain separate.
#[cfg(unix)]
#[path="local_grants/adapter.rs"]
pub(crate) mod adapter;
