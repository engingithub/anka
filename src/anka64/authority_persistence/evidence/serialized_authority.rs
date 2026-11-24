//! SA110 bounded local refinement. One private owner, one original operation
//! budget, no restore-from-snapshot API, no bearer receipt. Not yet wired to the
//! live Keycloak CLI or the CC2/socket/NIC/file path.
//!
//! Trusted sources must attest exclusive mediation of ALL relevant authority
//! writers and independently verify complete records. A mutex cannot establish
//! control over bypassing Keycloak admins. All source/clock/gate callbacks below
//! are bounded and nonblocking, with no remote HTTP or nested authority locks.
//! Remote administration starts only after barrier returns a Change, outside the
//! guard. A copied Change/Proposal is correlation metadata, never permission.
use super::super::Verdict;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::sync::atomic::{AtomicU64, Ordering};

#[path="serialized_authority/candidate.rs"]
pub(crate) mod candidate;
use candidate::{Candidate, Scope};

static DOMAINS: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Now { pub wall: u64, pub tick: u64 }
/// Both units must agree with candidate validity/age and the original deadline.
/// Implementations are trusted clocks; neither timestamp comes from peer bytes.
pub(crate) trait Clock { fn now(&mut self) -> Now; }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode { Closed, Open, Poisoned }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error { Configuration, Exhausted, Busy, Denied, Poisoned, EffectUncertain }

/// Trusted NEW operation allocation, not a reconnect or budget-refill API.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Config {
    pub installation: u64, pub issuer: u64, pub policy: u64, pub keyset: u64,
    pub incarnation: u64, pub work: u64, pub deadline: u64, pub boot: u64,
}
/// Read-only copy. There is deliberately no constructor accepting this as state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct View {
    pub domain: u64, pub installation: u64, pub issuer: u64, pub policy: u64,
    pub keyset: u64, pub incarnation: u64, pub revision: u64, pub next_seq: u64,
    pub remaining: u64, pub deadline: u64, pub last_tick: u64, pub last_wall: u64,
    pub effects: u64, pub boot: u64, pub mode: Mode, pub pending: u64,
    pub controlled: Verdict,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Proposal {
    pub domain: u64, pub incarnation: u64, pub revision: u64, pub sequence: u64,
    pub token: u64, pub keyset: u64, pub at_tick: u64, pub scope: Scope,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Change {
    pub domain: u64, pub incarnation: u64, pub revision: u64, pub command: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Completion {
    pub change: Change, pub policy: u64, pub keyset: u64,
    pub checked: Verdict, pub enabled: Verdict,
}

/// Trusted integration only. Defaults deny; the preflight CLI is deliberately
/// NOT an implementation. Attestation covers the exact View, exclusive writer
/// mediation and reconciliation of unknown prior external actions. Completion
/// checks the entire requested change/outcome, not HTTP 200 or active=true.
/// Candidate must bind an authenticated Peer and independently observed channel;
/// the Proposal is a request to check, never a source of evidence.
pub(crate) trait Evidence {
    type Peer;
    fn attest(&mut self, _owner: View) -> Verdict { Verdict::Unknown }
    fn completion(&mut self, _change: Change) -> Option<Completion> { None }
    fn fresh_incarnation(&mut self, _owner: View, _new: u64) -> Verdict { Verdict::Unknown }
    fn candidate(&mut self, _peer: &Self::Peer, _proposal: Proposal) -> Option<Candidate> { None }
}
pub(crate) struct DenyEvidence;
impl Evidence for DenyEvidence { type Peer = (); }

struct Inner<P, C> { state: View, source: P, clock: C }
/// No Clone/Copy or state/provider escape. Sharing an Arc shares this same owner.
pub(crate) struct Coordinator<P, C> { inner: Mutex<Inner<P, C>> }

impl View {
    fn clock_ok(self, now: Now) -> bool { now.wall >= self.last_wall && now.tick >= self.last_tick }
    fn fault(self, now: Now) -> bool {
        !self.clock_ok(now) || self.next_seq == u64::MAX || self.effects == u64::MAX
    }
    fn budget(self, now: Now) -> bool {
        self.clock_ok(now) && self.remaining != 0 && now.tick < self.deadline && self.next_seq < u64::MAX
    }
    fn cost(&mut self, now: Now) {
        self.remaining = self.remaining.saturating_sub(1);
        self.next_seq = self.next_seq.saturating_add(1);
        self.observe(now);
    }
    fn observe(&mut self, now: Now) {
        if !self.clock_ok(now) { self.mode = Mode::Poisoned; }
        self.last_wall = self.last_wall.max(now.wall);
        self.last_tick = self.last_tick.max(now.tick);
    }
    fn change(self) -> Change {
        Change { domain: self.domain, incarnation: self.incarnation, revision: self.revision, command: self.pending }
    }
    fn slot(self, p: Proposal, c: Candidate, now: Now) -> bool {
        self.mode == Mode::Open && self.pending == 0 && self.controlled == Verdict::Valid &&
        self.budget(now) && self.effects < u64::MAX &&
        self.installation == c.config.installation && self.issuer == c.config.issuer &&
        self.policy == c.config.policy && self.keyset == c.config.keyset &&
        p.domain == self.domain && p.incarnation == self.incarnation && p.revision == self.revision &&
        p.sequence == self.next_seq && p.keyset == self.keyset && p.token == c.token.reference &&
        p.at_tick == now.tick && p.scope == c.scope
    }
}

impl<P: Evidence, C: Clock> Coordinator<P, C> {
    pub(crate) fn new(config: Config, source: P, mut clock: C) -> Result<Self, Error> {
        let now = clock.now();
        if config.installation == 0 || config.issuer == 0 || config.policy == 0 ||
            config.keyset == 0 || config.incarnation == 0 || !(1..=512).contains(&config.work) ||
            config.deadline <= now.tick { return Err(Error::Configuration); }
        // Process-local uniqueness only; cross-restart freshness is a separate
        // trusted attestation. Domain IDs saturate, never recycle in this process.
        let domain = DOMAINS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::Exhausted)?;
        Ok(Self { inner: Mutex::new(Inner { source, clock, state: View {
            domain, installation: config.installation, issuer: config.issuer,
            policy: config.policy, keyset: config.keyset, incarnation: config.incarnation,
            revision: 1, next_seq: 1, remaining: config.work, deadline: config.deadline,
            last_tick: now.tick, last_wall: now.wall, effects: 0, boot: config.boot,
            mode: Mode::Closed, pending: 0, controlled: Verdict::Unknown,
        } }) })
    }
    fn lock(&self) -> Result<MutexGuard<'_, Inner<P, C>>, Error> {
        match self.inner.try_lock() {
            Ok(s) => Ok(s),
            Err(TryLockError::WouldBlock) => Err(Error::Busy),
            // Never recover a poisoned mutex into an authorizing path.
            Err(TryLockError::Poisoned(_)) => Err(Error::Poisoned),
        }
    }
    pub(crate) fn view(&self) -> Result<View, Error> { Ok(self.lock()?.state) }
    // Spend BEFORE trusted providers/gates/effects can unwind. Mutex poisoning
    // then permanently prevents reuse. Clock failure itself also poisons mutex.
    fn begin(s: &mut Inner<P, C>) -> (View, Now) {
        let before = s.state; let now = s.clock.now();
        s.state.cost(now);
        if before.fault(now) { s.state.mode = Mode::Poisoned; }
        (before, now)
    }
    // Sample again after callbacks, so a late provider/gate cannot use an old
    // token lifetime or deadline. Observe every sample to detect in-call rollback.
    fn finish_time(s: &mut Inner<P, C>) -> Now {
        let now = s.clock.now(); s.state.observe(now); now
    }
    fn denied(s: &Inner<P, C>) -> Error {
        if s.state.mode == Mode::Poisoned { Error::Poisoned } else { Error::Denied }
    }
    pub(crate) fn establish(&self) -> Result<(), Error> {
        let mut s = self.lock()?; let (before, first) = Self::begin(&mut s);
        if before.mode != Mode::Closed || before.pending != 0 || s.state.mode == Mode::Poisoned {
            return Err(Self::denied(&s));
        }
        if !before.budget(first) { s.state.controlled = Verdict::Unknown; return Err(Self::denied(&s)); }
        let attested = s.source.attest(before);
        let now = Self::finish_time(&mut s);
        s.state.controlled = if attested == Verdict::Valid && before.budget(now) && s.state.mode != Mode::Poisoned {
            Verdict::Valid
        } else { Verdict::Unknown };
        if s.state.controlled == Verdict::Valid { Ok(()) } else { Err(Self::denied(&s)) }
    }
    /// Return only AFTER local close. Busy/Denied is NOT permission to perform
    /// an external change. No second pending command can replace the first.
    pub(crate) fn barrier(&self, command: u64) -> Result<Change, Error> {
        let mut s = self.lock()?; let (before, _) = Self::begin(&mut s);
        if before.pending != 0 || command == 0 { return Err(Self::denied(&s)); }
        s.state.revision = before.revision.saturating_add(1);
        s.state.pending = command;
        s.state.mode = if s.state.mode == Mode::Poisoned || before.revision == u64::MAX {
            Mode::Poisoned
        } else { Mode::Closed };
        if s.state.mode == Mode::Poisoned { Err(Error::Poisoned) } else { Ok(s.state.change()) }
    }
    pub(crate) fn complete(&self, requested: Change) -> Result<(), Error> {
        let mut s = self.lock()?; let (before, first) = Self::begin(&mut s);
        // Even unsolicited/mismatched completion closes an otherwise open lane.
        if s.state.mode != Mode::Poisoned { s.state.mode = Mode::Closed; }
        if s.state.mode == Mode::Poisoned || !before.budget(first) ||
            before.pending == 0 || requested != before.change() { return Err(Self::denied(&s)); }
        let ack = s.source.completion(requested);
        let now = Self::finish_time(&mut s);
        let Some(ack) = ack else { return Err(Self::denied(&s)); };
        if ack.checked != Verdict::Valid || ack.change != before.change() || ack.policy == 0 || ack.keyset == 0 {
            return Err(Self::denied(&s));
        }
        s.state.policy = ack.policy; s.state.keyset = ack.keyset; s.state.pending = 0;
        if before.mode == Mode::Closed && before.controlled == Verdict::Valid &&
            ack.enabled == Verdict::Valid && before.budget(now) && s.state.mode != Mode::Poisoned {
            s.state.mode = Mode::Open; Ok(())
        } else { Err(Self::denied(&s)) }
    }
    /// Detected loss is terminal, including while administration is pending.
    pub(crate) fn invalidate(&self) -> Result<(), Error> {
        let mut s = self.lock()?; let (before, _) = Self::begin(&mut s);
        s.state.revision = before.revision.saturating_add(1);
        s.state.controlled = Verdict::Unknown; s.state.mode = Mode::Poisoned; Ok(())
    }
    /// In-memory transition only. This neither restores serialized state nor
    /// proves durable recovery, fencing of other hosts, or boot authorization.
    pub(crate) fn recover(&self, incarnation: u64) -> Result<(), Error> {
        let mut s = self.lock()?; let (before, first) = Self::begin(&mut s);
        // Close before asking for reconciliation evidence, never carry control.
        s.state.controlled = Verdict::Unknown;
        if s.state.mode != Mode::Poisoned { s.state.mode = Mode::Closed; }
        let fresh = if before.budget(first) && s.state.mode != Mode::Poisoned {
            s.source.fresh_incarnation(before, incarnation)
        } else { Verdict::Unknown };
        let _now = Self::finish_time(&mut s);
        let newer = fresh == Verdict::Valid && incarnation > before.incarnation;
        if newer { s.state.incarnation = incarnation; }
        s.state.revision = before.revision.saturating_add(1); s.state.pending = 0;
        if !newer || before.revision == u64::MAX || before.mode == Mode::Poisoned {
            s.state.mode = Mode::Poisoned;
        }
        if s.state.mode == Mode::Poisoned { Err(Error::Poisoned) } else { Ok(()) }
    }
    /// The mutex covers ALL validation, existing-operation gate and submission.
    /// Callbacks are trusted synchronous operations, not async work enqueueing.
    /// No permission/receipt is passed to or returned from the callback. Each
    /// fragment and final disclosure must make a separate attempt. No network
    /// wait or reentrant coordinator call belongs in these callbacks.
    ///
    /// effects counts authorized submissions, NOT bytes or committed records.
    /// Any callback error is conservatively uncertain: retain its debit/count,
    /// poison the operation and never retry. An unwind poisons the mutex. A
    /// future backend must prove its actual effect boundary before integration.
    pub(crate) fn attempt<T>(
        &self, peer: &P::Peer, proposal: Proposal,
        gate: impl FnOnce(&Scope) -> bool,
        submit: impl FnOnce() -> Result<T, ()>,
    ) -> Result<T, Error> {
        let mut s = self.lock()?; let (before, first) = Self::begin(&mut s);
        if s.state.mode == Mode::Poisoned || before.mode != Mode::Open ||
            before.controlled != Verdict::Valid || !before.budget(first) {
            return Err(Self::denied(&s));
        }
        let evidence = s.source.candidate(peer, proposal);
        let now = Self::finish_time(&mut s);
        let Some(evidence) = evidence else { return Err(Self::denied(&s)); };
        if s.state.mode == Mode::Poisoned || !before.slot(proposal, evidence, now) || !evidence.valid(now) {
            return Err(Self::denied(&s));
        }
        let permitted = gate(&evidence.scope);
        let now = Self::finish_time(&mut s);
        if !permitted || s.state.mode == Mode::Poisoned ||
            !before.slot(proposal, evidence, now) || !evidence.valid(now) {
            return Err(Self::denied(&s));
        }
        // Space was checked against the owned before-state; this cannot wrap.
        s.state.effects += 1;
        match submit() {
            Ok(value) => Ok(value),
            Err(()) => {
                // Compose the submitted attempt with sa110_invalidate while
                // retaining the guard; the loss transition also spends work.
                let loss_time = s.clock.now();
                s.state.cost(loss_time);
                s.state.mode = Mode::Poisoned; s.state.controlled = Verdict::Unknown;
                s.state.revision = s.state.revision.saturating_add(1);
                Err(Error::EffectUncertain)
            }
        }
    }
}

#[cfg(test)]
#[path="serialized_authority/tests.rs"]
mod tests;
