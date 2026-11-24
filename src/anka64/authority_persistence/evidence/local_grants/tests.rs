//! Trusted primitive fixtures, NOT token/signature/network verification. All
//! deadline tests use a manual clock; thread ordering uses channels, not sleeps.
use super::*;
use std::sync::Arc;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Clone)]
struct ManualClock(Arc<Mutex<Now>>);
impl Clock for ManualClock { fn now(&mut self) -> Now { *self.0.lock().unwrap() } }

fn config() -> Config {
    let scope = Scope { installation: 20, policy: 3, peer: 30, kind: 1,
        artifact: 40, generation: 2, request: 50, operation: 1, role: 1,
        runtime: 6, connection: 7, binding: 8, local: 9, incarnation: 5,
        serial: 10, challenge: 11 };
    Config { domain: 500, incarnation: 5, grant_id: 600, work: 64, deadline: 200, boot: 71,
        identity: Configuration { issuer: 10, audience: 21, client: 22, installation: 20,
            policy: 3, keyset: 4, profile: 1, max_age: 30, max_bytes: 1024, selected: Verdict::Valid },
        scope, grant: Grant { token: 101, scope, first: 95, until: 145, permission: Verdict::Valid } }
}
fn observation(q: Query) -> Observation {
    Observation {
        token: Token { reference: 101, issuer: 10, audience: 21, client: 22, subject: 31,
            holder: 32, keyset: 4, profile: 1, issued: 90, first: 95, until: 150,
            syntax: Verdict::Valid, signature: Verdict::Valid },
        status: Status { token: 101, issuer: 10, query: q.sequence, started: q.started,
            observed: q.started, checked: Verdict::Valid, active: Verdict::Valid },
        mapping: Mapping { issuer: 10, subject: 31, client: 22, installation: 20,
            peer: 30, kind: 1, policy: 3, enabled: Verdict::Valid }, bytes: 800 }
}
fn completion(q: Query) -> Completion {
    Completion { query: q, checked: Verdict::Valid, result: Verdict::Valid,
        observation: Some(observation(q)) }
}
fn possession(p: Proposal, scope: Scope) -> Possession {
    Possession { proposal: p, checked: Verdict::Valid, channel: Verdict::Valid,
        proof: Proof { token: 101, issuer: 10, signer: 32, scope, signature: Verdict::Valid } }
}
struct Inputs {
    reply: Option<Completion>, use_reply: Option<Possession>, missing_use: bool,
    complete_at: Option<Now>, use_at: Option<Now>, restart_at: Option<Now>,
    fresh: Verdict, calls: [u64; 3], panic_complete: bool, panic_use: bool,
}
struct Source { inputs: Arc<Mutex<Inputs>>, clock: ManualClock, scope: Scope }
impl Evidence for Source {
    type Peer = u64;
    fn completion(&mut self, _q: Query) -> Option<Completion> {
        let mut i = self.inputs.lock().unwrap(); i.calls[0] += 1;
        if i.panic_complete { drop(i); panic!("injected completion unwind"); }
        if let Some(now) = i.complete_at { *self.clock.0.lock().unwrap() = now; }
        i.reply
    }
    fn possession(&mut self, peer: &u64, p: Proposal) -> Option<Possession> {
        let mut i = self.inputs.lock().unwrap(); i.calls[1] += 1;
        if i.panic_use { drop(i); panic!("injected possession unwind"); }
        if let Some(now) = i.use_at { *self.clock.0.lock().unwrap() = now; }
        if *peer != self.scope.peer || i.missing_use { return None; }
        Some(i.use_reply.unwrap_or_else(|| possession(p, self.scope)))
    }
    fn fresh_incarnation(&mut self, _v: View, _new: u64) -> Verdict {
        let mut i = self.inputs.lock().unwrap(); i.calls[2] += 1;
        if let Some(now) = i.restart_at { *self.clock.0.lock().unwrap() = now; }
        i.fresh
    }
}
struct Rig { owner: Owner<Source, ManualClock>, inputs: Arc<Mutex<Inputs>>, clock: ManualClock, config: Config }
impl Rig {
    fn new(c: Config) -> Self {
        let clock = ManualClock(Arc::new(Mutex::new(Now { wall: 100, tick: 100 })));
        let inputs = Arc::new(Mutex::new(Inputs { reply: None, use_reply: None,
            missing_use: false, complete_at: None, use_at: None, restart_at: None,
            fresh: Verdict::Unknown, calls: [0; 3], panic_complete: false, panic_use: false }));
        let source = Source { inputs: inputs.clone(), clock: clock.clone(), scope: c.scope };
        Self { owner: Owner::new(c, source, clock.clone()).unwrap(), inputs, clock, config: c }
    }
    fn issued() -> Self { let r = Self::new(config()); r.issue(); r }
    fn issue(&self) {
        let q = self.owner.begin_query().unwrap(); self.stage(completion(q));
        assert_eq!(self.owner.complete(q), Ok(Refresh::Issued));
    }
    fn stage(&self, c: Completion) { self.inputs.lock().unwrap().reply = Some(c); }
    fn time(&self, wall: u64, tick: u64) { *self.clock.0.lock().unwrap() = Now { wall, tick }; }
    fn view(&self) -> View { self.owner.view().unwrap() }
    fn proposal(&self) -> Proposal {
        let v = self.view(); let now = *self.clock.0.lock().unwrap();
        Proposal { owner: v.owner, domain: v.domain, incarnation: v.incarnation, grant_id: v.grant_id,
            revision: v.revision, sequence: v.next_seq, at_tick: now.tick, scope: self.config.scope }
    }
    fn run(&self) -> Result<u64, Error> {
        self.owner.attempt(&30, self.proposal(), |_| true, || Ok(42))
    }
}

#[test]
fn lg110_constructor_requires_explicit_bounded_configuration() {
    let mutations: &[fn(&mut Config)] = &[
        |c| c.domain = 0, |c| c.incarnation = 0, |c| c.grant_id = 0,
        |c| c.work = 0, |c| c.work = 513, |c| c.deadline = 100,
        |c| c.identity.selected = Verdict::Unknown, |c| c.identity.issuer = 0,
        |c| c.identity.audience = 0, |c| c.identity.client = 0,
        |c| c.identity.installation = 0, |c| c.identity.policy = 0,
        |c| c.identity.keyset = 0, |c| c.identity.profile = 2,
        |c| c.identity.max_age = 0, |c| c.identity.max_bytes = 0,
        |c| c.identity.max_bytes = 16385, |c| c.scope.challenge = 0,
        |c| c.scope.installation += 1, |c| c.scope.policy += 1,
        |c| c.grant.token = 0, |c| c.grant.permission = Verdict::Unknown,
        |c| c.grant.scope.role = 2, |c| c.grant.first = c.grant.until,
    ];
    for change in mutations {
        let mut c = config(); change(&mut c);
        let clock = ManualClock(Arc::new(Mutex::new(Now { wall: 100, tick: 100 })));
        assert!(matches!(Owner::new(c, DenyEvidence, clock), Err(Error::Configuration)));
    }
}
#[test]
fn lg110_default_source_never_issues_or_submits() {
    let r = Rig::new(config());
    let owner = Owner::new(config(), DenyEvidence, r.clock.clone()).unwrap();
    let q = owner.begin_query().unwrap();
    assert_eq!(owner.complete(q), Err(Error::Denied));
    let v = owner.view().unwrap();
    let mut p = r.proposal(); p.owner = v.owner; p.sequence = v.next_seq;
    assert_eq!(owner.attempt(&(), p, |_| panic!("gate"), || Ok(())), Err(Error::Denied));
    assert_eq!(owner.view().unwrap().effects, 0);
}
#[test]
fn lg110_owner_identity_and_local_domain_are_independent() {
    let a = Rig::issued(); let b = Rig::issued();
    assert_ne!(a.view().owner, b.view().owner);
    assert_ne!(a.view().domain, a.config.identity.issuer);
    assert_eq!(b.owner.attempt(&30, a.proposal(), |_| true, || Ok(())), Err(Error::Denied));
    assert_eq!(b.view().effects, 0);
}
#[test]
fn lg110_query_start_precedes_io_and_duplicate_spends_without_replacing() {
    let r = Rig::new(config()); let q = r.owner.begin_query().unwrap();
    assert_eq!((q.sequence, q.started), (1, 100));
    r.time(101, 105);
    assert_eq!(r.owner.begin_query(), Err(Error::Denied));
    assert_eq!(r.view().pending, Some(q));
    assert_eq!((r.view().remaining, r.view().next_seq), (62, 3));
    assert_eq!(r.inputs.lock().unwrap().calls, [0; 3]);
}
#[test]
fn lg110_initial_issue_only_changes_local_evidence_not_boot_or_effects() {
    let r = Rig::issued(); let v = r.view();
    assert_eq!(v.mode, Mode::Issued); assert_eq!(v.pending, None);
    assert_eq!((v.remaining, v.next_seq, v.revision, v.effects, v.boot), (62, 3, 1, 0, 71));
    assert_eq!(r.inputs.lock().unwrap().calls, [1, 0, 0]);
}
#[test]
fn lg110_success_submits_once_and_replay_spends_without_effect() {
    let r = Rig::issued(); let p = r.proposal();
    assert_eq!(r.owner.attempt(&30, p, |_| true, || Ok(42)), Ok(42));
    assert_eq!(r.owner.attempt(&30, p, |_| panic!("gate"), || Ok(42)), Err(Error::Denied));
    assert_eq!((r.view().remaining, r.view().next_seq, r.view().effects), (60, 5, 1));
}
#[test]
fn lg110_positive_refresh_preserves_identity_scope_budget_and_deadline() {
    let r = Rig::issued(); r.time(101, 120);
    let q = r.owner.begin_query().unwrap(); r.stage(completion(q));
    assert_eq!(r.owner.complete(q), Ok(Refresh::Refreshed));
    assert_eq!((r.view().remaining, r.view().deadline, r.view().revision), (60, 200, 1));
    r.time(102, 140); assert_eq!(r.run(), Ok(42)); // Old observation would be stale.
    assert_eq!(r.view().boot, 71);
}
#[test]
fn lg110_pending_refresh_keeps_only_original_evidence_window() {
    let r = Rig::issued(); r.time(101, 120); let q = r.owner.begin_query().unwrap();
    assert_eq!(r.run(), Ok(42)); r.time(102, 130);
    assert_eq!(r.run(), Err(Error::Denied)); assert_eq!(r.view().pending, Some(q));
    r.stage(completion(q)); assert_eq!(r.owner.complete(q), Ok(Refresh::Refreshed));
    assert_eq!(r.run(), Ok(42));
}
#[test]
fn lg110_outage_cannot_issue_and_cannot_renew_existing_evidence() {
    for issued in [false, true] {
        let r = if issued { Rig::issued() } else { Rig::new(config()) };
        r.time(101, 120); let q = r.owner.begin_query().unwrap();
        let mut c = completion(q); c.result = Verdict::Unknown; c.observation = None; r.stage(c);
        assert_eq!(r.owner.complete(q), Ok(Refresh::Unavailable));
        assert_eq!(r.view().pending, None);
        assert_eq!(r.run(), if issued { Ok(42) } else { Err(Error::Denied) });
        r.time(102, 130); assert_eq!(r.run(), Err(Error::Denied));
    }
}
#[test]
fn lg110_observation_age_starts_at_query_not_response_arrival() {
    for tick in [129, 130, 131] {
        let r = Rig::new(config()); let q = r.owner.begin_query().unwrap();
        let mut c = completion(q); c.observation.as_mut().unwrap().status.observed = tick;
        r.stage(c); r.time(100, tick);
        assert_eq!(r.owner.complete(q), if tick == 129 { Ok(Refresh::Issued) } else { Err(Error::Denied) });
        assert_eq!(r.view().effects, 0);
    }
}
#[test]
fn lg110_positive_completion_rechecks_time_after_provider() {
    for now in [Now { wall: 100, tick: 130 }, Now { wall: 145, tick: 100 }, Now { wall: 100, tick: 200 }] {
        let r = Rig::new(config()); let q = r.owner.begin_query().unwrap(); r.stage(completion(q));
        r.inputs.lock().unwrap().complete_at = Some(now);
        assert_eq!(r.owner.complete(q), Err(Error::Denied)); assert_eq!(r.view().mode, Mode::Unissued);
    }
}
#[test]
fn lg110_all_exclusive_time_boundaries_deny_use() {
    for boundary in 0..4 {
        let mut c = config(); if boundary == 1 { c.grant.until = 160; }
        let r = Rig::new(c); r.issue();
        let (wall, tick) = match boundary { 0 => (145, 100), 1 => (150, 100), 2 => (100, 130), _ => (100, 200) };
        r.time(wall, tick); assert_eq!(r.run(), Err(Error::Denied)); assert_eq!(r.view().effects, 0);
    }
}
#[test]
fn lg110_clock_rollback_poison_is_terminal_and_highwaters_never_lower() {
    for now in [Now { wall: 99, tick: 100 }, Now { wall: 100, tick: 99 }] {
        let r = Rig::issued(); *r.clock.0.lock().unwrap() = now;
        assert_eq!(r.run(), Err(Error::Poisoned));
        assert_eq!((r.view().last_wall, r.view().last_tick), (100, 100));
        r.time(101, 101); assert_eq!(r.owner.begin_query(), Err(Error::Poisoned));
        assert_eq!(r.view().mode, Mode::Poisoned);
    }
}
#[test]
fn lg110_verified_negative_revokes_after_exhaustion_and_deadline() {
    let mut c = config(); c.work = 3; let r = Rig::new(c); r.issue();
    let q = r.owner.begin_query().unwrap(); assert_eq!(r.view().remaining, 0);
    let mut reply = completion(q); reply.result = Verdict::Invalid; reply.observation = None;
    r.stage(reply); r.time(150, 200);
    assert_eq!(r.owner.complete(q), Ok(Refresh::Revoked));
    assert_eq!((r.view().remaining, r.view().revision), (0, 2));
    assert_eq!(r.run(), Err(Error::Denied));
}
#[test]
fn lg110_local_revoke_cancels_late_positive_and_preserves_prefix() {
    let r = Rig::issued(); assert_eq!(r.run(), Ok(42));
    let q = r.owner.begin_query().unwrap(); r.stage(completion(q)); r.owner.revoke().unwrap();
    assert_eq!(r.owner.complete(q), Err(Error::Denied));
    assert_eq!(r.run(), Err(Error::Denied)); // Suffix/final result needs another attempt.
    assert_eq!((r.view().effects, r.view().revision, r.view().mode), (1, 2, Mode::Revoked));
    assert_eq!(r.inputs.lock().unwrap().calls[0], 1); // Late reply never consulted.
}
#[test]
fn lg110_local_revoke_works_without_budget_or_network() {
    let mut c = config(); c.work = 2; let r = Rig::new(c); r.issue();
    r.time(200, 300); r.owner.revoke().unwrap();
    assert_eq!(r.view().mode, Mode::Revoked); assert_eq!(r.view().remaining, 0);
    assert_eq!(r.inputs.lock().unwrap().calls, [1, 0, 0]);
}
#[test]
fn lg110_last_work_unit_can_submit_but_next_attempt_cannot_refill() {
    let mut c = config(); c.work = 3; let r = Rig::new(c); r.issue();
    assert_eq!(r.run(), Ok(42)); assert_eq!(r.run(), Err(Error::Denied));
    assert_eq!(r.owner.begin_query(), Err(Error::Denied));
    assert_eq!((r.view().remaining, r.view().effects, r.view().deadline), (0, 1, 200));
}
#[test]
fn lg110_exhausted_positive_cannot_issue_or_refresh() {
    for issued in [false, true] {
        let mut c = config(); c.work = if issued { 3 } else { 1 };
        let r = Rig::new(c); if issued { r.issue(); }
        let q = r.owner.begin_query().unwrap(); r.stage(completion(q));
        assert_eq!(r.owner.complete(q), Err(Error::Denied)); assert_eq!(r.view().remaining, 0);
        assert_eq!(r.view().mode, if issued { Mode::Issued } else { Mode::Unissued });
        assert_eq!(r.run(), Err(Error::Denied));
    }
}
#[test]
fn lg110_gate_denial_spends_work_without_submission() {
    let r = Rig::issued();
    assert_eq!(r.owner.attempt(&30, r.proposal(), |_| false, || Ok(42)), Err(Error::Denied));
    assert_eq!((r.view().remaining, r.view().effects), (61, 0));
}
#[test]
fn lg110_provider_and_gate_time_changes_rechecked_before_submission() {
    for provider in [false, true] {
        for now in [Now { wall: 145, tick: 100 }, Now { wall: 100, tick: 101 }, Now { wall: 99, tick: 100 }] {
            let r = Rig::issued();
            if provider { r.inputs.lock().unwrap().use_at = Some(now); }
            let result = r.owner.attempt(&30, r.proposal(), |_| {
                if !provider { *r.clock.0.lock().unwrap() = now; } true
            }, || Ok(42));
            assert_eq!(result, Err(if now.wall == 99 { Error::Poisoned } else { Error::Denied }));
            assert_eq!(r.view().effects, 0);
        }
    }
}
#[test]
fn lg110_missing_and_unverified_completion_preserve_pending() {
    for checked in [None, Some(Verdict::Unknown), Some(Verdict::Invalid)] {
        let r = Rig::new(config()); let q = r.owner.begin_query().unwrap();
        if let Some(v) = checked { let mut c = completion(q); c.checked = v; c.result = Verdict::Invalid; r.stage(c); }
        assert_eq!(r.owner.complete(q), Err(Error::Denied)); assert_eq!(r.view().pending, Some(q));
        assert_eq!(r.view().mode, Mode::Unissued);
    }
}
#[test]
fn lg110_missing_positive_payload_clears_only_its_query_without_issuance() {
    let r = Rig::new(config()); let q = r.owner.begin_query().unwrap();
    let mut c = completion(q); c.observation = None; r.stage(c);
    assert_eq!(r.owner.complete(q), Err(Error::Denied));
    assert_eq!(r.view().pending, None); assert_eq!(r.view().mode, Mode::Unissued);
}
#[test]
fn lg110_fresh_restart_closes_without_restoring_accounting_or_authority() {
    let r = Rig::issued(); assert_eq!(r.run(), Ok(42));
    let q = r.owner.begin_query().unwrap(); r.stage(completion(q));
    r.inputs.lock().unwrap().fresh = Verdict::Valid; let before = r.view();
    r.owner.restart(6).unwrap(); let after = r.view();
    assert_eq!(after.incarnation, 6); assert_eq!(after.mode, Mode::Revoked);
    assert_eq!((after.remaining, after.deadline, after.effects, after.boot),
        (before.remaining - 1, before.deadline, before.effects, before.boot));
    assert_eq!(r.owner.complete(q), Err(Error::Denied)); assert_eq!(r.run(), Err(Error::Denied));
    assert_eq!(r.owner.begin_query(), Err(Error::Denied));
}
#[test]
fn lg110_unverified_reused_or_late_restart_poison_without_reopen() {
    for case in 0..5 {
        let r = Rig::issued();
        r.inputs.lock().unwrap().fresh = if case == 0 { Verdict::Unknown } else { Verdict::Valid };
        if case == 3 { r.inputs.lock().unwrap().restart_at = Some(Now { wall: 100, tick: 200 }); }
        if case == 4 { r.owner.inner.lock().unwrap().state.remaining = 0; }
        let incarnation = if case == 1 { 5 } else if case == 2 { 0 } else { 6 };
        assert_eq!(r.owner.restart(incarnation), Err(Error::Poisoned));
        assert_eq!(r.view().mode, Mode::Poisoned); assert_eq!(r.view().incarnation, 5);
        if case == 4 { assert_eq!(r.inputs.lock().unwrap().calls[2], 0); }
    }
}
#[test]
fn lg110_nonwrapping_sequence_revision_and_effect_counters() {
    for sequence in [0, u64::MAX] {
        let r = Rig::issued(); r.owner.inner.lock().unwrap().state.next_seq = sequence;
        assert_eq!(r.run(), Err(Error::Poisoned)); assert_eq!(r.view().next_seq, sequence);
    }
    let r = Rig::issued(); r.owner.inner.lock().unwrap().state.next_seq = u64::MAX - 1;
    assert_eq!(r.run(), Ok(42)); assert_eq!(r.view().next_seq, u64::MAX);
    assert_eq!(r.run(), Err(Error::Poisoned)); assert_eq!(r.view().effects, 1);
    let r = Rig::issued(); r.owner.inner.lock().unwrap().state.revision = u64::MAX;
    assert_eq!(r.owner.revoke(), Err(Error::Poisoned)); assert_eq!(r.view().revision, u64::MAX);
    let r = Rig::issued(); r.owner.inner.lock().unwrap().state.effects = u64::MAX;
    assert_eq!(r.run(), Err(Error::Poisoned)); assert_eq!(r.view().effects, u64::MAX);
}
#[test]
fn lg110_uncertain_submission_retains_count_and_charges_terminal_close() {
    let r = Rig::issued(); let before = r.view();
    assert_eq!(r.owner.attempt::<()>(&30, r.proposal(), |_| true, || Err(())), Err(Error::EffectUncertain));
    let after = r.view(); assert_eq!(after.effects, 1); assert_eq!(after.mode, Mode::Poisoned);
    assert_eq!((after.remaining, after.next_seq, after.revision),
        (before.remaining - 2, before.next_seq + 2, before.revision + 1));
    assert_eq!(r.run(), Err(Error::Poisoned)); assert_eq!(r.view().effects, 1);
}
#[test]
fn lg110_provider_gate_and_submit_unwinds_poison_owner() {
    for case in 0..4 {
        let r = Rig::issued(); let before = r.view();
        let result = catch_unwind(AssertUnwindSafe(|| {
            if case == 0 {
                let q = r.owner.begin_query().unwrap(); r.inputs.lock().unwrap().panic_complete = true;
                let _ = r.owner.complete(q);
            } else {
                if case == 1 { r.inputs.lock().unwrap().panic_use = true; }
                let _ = r.owner.attempt(&30, r.proposal(), |_| {
                    if case == 2 { panic!("injected gate unwind"); } true
                }, || { if case == 3 { panic!("injected submit unwind"); } Ok(42) });
            }
        }));
        assert!(result.is_err()); assert_eq!(r.owner.view(), Err(Error::Poisoned));
        assert_eq!(r.owner.revoke(), Err(Error::Poisoned));
        let guard = match r.owner.inner.lock() { Err(e) => e.into_inner(), Ok(_) => panic!("not poisoned") };
        assert_eq!(guard.state.remaining, before.remaining - if case == 0 { 2 } else { 1 });
        assert_eq!(guard.state.effects, if case == 3 { 1 } else { 0 });
    }
}

#[path="tests/bindings.rs"] mod bindings;
#[path="tests/ordering.rs"] mod ordering;
