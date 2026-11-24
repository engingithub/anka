use super::*;
use super::candidate::*;
use std::sync::{Arc, Mutex, mpsc};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn config() -> Config {
    Config { installation: 20, issuer: 10, policy: 3, keyset: 4, incarnation: 5,
        work: 64, deadline: 200, boot: 71 }
}
fn candidate() -> Candidate {
    let scope = Scope { installation: 20, policy: 3, peer: 30, kind: 1, artifact: 40,
        generation: 2, request: 50, operation: 1, role: 1, runtime: 6, connection: 7,
        binding: 8, local: 9, incarnation: 5, serial: 10, challenge: 11 };
    Candidate {
        config: Configuration { issuer: 10, audience: 21, client: 22, installation: 20,
            policy: 3, keyset: 4, profile: 1, max_age: 30, max_bytes: 1024, selected: Verdict::Valid },
        token: Token { reference: 101, issuer: 10, audience: 21, client: 22, subject: 31,
            holder: 32, keyset: 4, profile: 1, issued: 90, first: 95, until: 150,
            syntax: Verdict::Valid, signature: Verdict::Valid },
        status: Status { token: 101, issuer: 10, query: 102, started: 95, observed: 98,
            checked: Verdict::Valid, active: Verdict::Valid },
        mapping: Mapping { issuer: 10, subject: 31, client: 22, installation: 20,
            peer: 30, kind: 1, policy: 3, enabled: Verdict::Valid },
        scope, proof: Proof { token: 101, issuer: 10, signer: 32, scope, signature: Verdict::Valid },
        grant: Grant { token: 101, scope, first: 95, until: 145, permission: Verdict::Valid },
        query: 102, bytes: 512, channel: Verdict::Valid,
    }
}
#[derive(Clone)]
struct ManualClock(Arc<Mutex<Now>>);
impl Clock for ManualClock { fn now(&mut self) -> Now { *self.0.lock().unwrap() } }
#[derive(Clone, Copy)]
enum AckReply { Current, Missing, Exact(Completion) }
struct Inputs {
    candidate: Option<Candidate>, attested: Verdict, fresh: Verdict, ack: AckReply,
    enabled: Verdict, policy: u64, keyset: u64, observed: usize, completions: usize,
    delayed: Option<Now>, control_time: Option<Now>, panic_candidate: bool,
    attestations: usize, recoveries: usize,
}
struct Source { data: Arc<Mutex<Inputs>>, time: Arc<Mutex<Now>> }
impl Evidence for Source {
    type Peer = u64;
    fn attest(&mut self, _owner: View) -> Verdict {
        let mut d = self.data.lock().unwrap(); d.attestations += 1;
        if let Some(now) = d.control_time { *self.time.lock().unwrap() = now; }
        d.attested
    }
    fn completion(&mut self, change: Change) -> Option<Completion> {
        let mut d = self.data.lock().unwrap(); d.completions += 1;
        if let Some(now) = d.control_time { *self.time.lock().unwrap() = now; }
        match d.ack {
            AckReply::Missing => None, AckReply::Exact(ack) => Some(ack),
            AckReply::Current => Some(Completion { change, policy: d.policy, keyset: d.keyset,
                checked: Verdict::Valid, enabled: d.enabled }),
        }
    }
    fn fresh_incarnation(&mut self, _owner: View, _new: u64) -> Verdict {
        let mut d = self.data.lock().unwrap(); d.recoveries += 1;
        if let Some(now) = d.control_time { *self.time.lock().unwrap() = now; }
        d.fresh
    }
    fn candidate(&mut self, peer: &u64, _proposal: Proposal) -> Option<Candidate> {
        let mut d = self.data.lock().unwrap(); d.observed += 1;
        assert!(!d.panic_candidate, "injected SA110 provider unwind");
        if let Some(now) = d.delayed { *self.time.lock().unwrap() = now; }
        d.candidate.filter(|c| c.scope.peer == *peer)
    }
}
struct Rig {
    lane: Coordinator<Source, ManualClock>, data: Arc<Mutex<Inputs>>, time: Arc<Mutex<Now>>,
}
impl Rig {
    fn closed() -> Self { Self::with(config()) }
    fn with(cfg: Config) -> Self {
        let data = Arc::new(Mutex::new(Inputs { candidate: Some(candidate()), attested: Verdict::Valid,
            fresh: Verdict::Valid, ack: AckReply::Current, enabled: Verdict::Valid,
            policy: 3, keyset: 4, observed: 0, completions: 0, delayed: None, control_time: None,
            panic_candidate: false, attestations: 0, recoveries: 0 }));
        let time = Arc::new(Mutex::new(Now { wall: 100, tick: 100 }));
        let lane = Coordinator::new(cfg, Source { data: data.clone(), time: time.clone() }, ManualClock(time.clone())).unwrap();
        Self { lane, data, time }
    }
    fn open() -> Self {
        let r = Self::closed(); r.lane.establish().unwrap();
        let change = r.lane.barrier(201).unwrap(); r.lane.complete(change).unwrap(); r
    }
    fn view(&self) -> View { self.lane.view().unwrap() }
    fn proposal(&self) -> Proposal { proposal(self.view(), *self.time.lock().unwrap(), candidate()) }
    fn use_once(&self) -> Result<(), Error> { self.lane.attempt(&30, self.proposal(), |_| true, || Ok(())) }
}
fn proposal(v: View, now: Now, c: Candidate) -> Proposal {
    Proposal { domain: v.domain, incarnation: v.incarnation, revision: v.revision,
        sequence: v.next_seq, token: c.token.reference, keyset: v.keyset, at_tick: now.tick, scope: c.scope }
}
fn unchanged_frame(before: View, after: View) {
    assert_eq!((after.domain, after.installation, after.issuer, after.deadline, after.boot),
        (before.domain, before.installation, before.issuer, before.deadline, before.boot));
    assert!(after.remaining <= before.remaining); assert!(after.next_seq >= before.next_seq);
    assert!(after.effects >= before.effects); assert!(after.last_wall >= before.last_wall);
    assert!(after.last_tick >= before.last_tick);
}

#[test]
fn sa110_default_source_cannot_open_or_submit() {
    let time = ManualClock(Arc::new(Mutex::new(Now { wall: 100, tick: 100 })));
    let lane = Coordinator::new(config(), DenyEvidence, time).unwrap();
    assert_eq!(lane.establish(), Err(Error::Denied));
    let change = lane.barrier(1).unwrap(); assert_eq!(lane.complete(change), Err(Error::Denied));
    let p = proposal(lane.view().unwrap(), Now { wall: 100, tick: 100 }, candidate());
    assert_eq!(lane.attempt(&(), p, |_| panic!("gate"), || -> Result<(), ()> { panic!("effect") }), Err(Error::Denied));
    assert_eq!(lane.view().unwrap().controlled, Verdict::Unknown);
}
#[test]
fn sa110_constructor_checks_bounds_and_allocates_distinct_owners() {
    for bad in [0, 513, u64::MAX] {
        let mut c = config(); c.work = bad;
        let result = Coordinator::new(c, DenyEvidence, ManualClock(Arc::new(Mutex::new(Now { wall: 100, tick: 100 }))));
        assert!(matches!(result, Err(Error::Configuration)));
    }
    for field in 0..6 {
        let mut c = config();
        match field { 0 => c.installation = 0, 1 => c.issuer = 0, 2 => c.policy = 0,
            3 => c.keyset = 0, 4 => c.incarnation = 0, _ => c.deadline = 100 }
        let result = Coordinator::new(c, DenyEvidence, ManualClock(Arc::new(Mutex::new(Now { wall: 100, tick: 100 }))));
        assert!(matches!(result, Err(Error::Configuration)));
    }
    let a = Rig::open(); let b = Rig::open();
    assert_ne!(a.view().domain, b.view().domain);
    assert_eq!(b.lane.attempt(&30, a.proposal(), |_| true, || Ok(())), Err(Error::Denied));
}
#[test]
fn sa110_establishment_stays_closed_and_unknown_cannot_open() {
    for verdict in [Verdict::Unknown, Verdict::Invalid, Verdict::Valid] {
        let r = Rig::closed(); r.data.lock().unwrap().attested = verdict;
        let result = r.lane.establish();
        assert_eq!(result.is_ok(), verdict == Verdict::Valid);
        assert_eq!(r.view().mode, Mode::Closed); assert_eq!(r.use_once(), Err(Error::Denied));
        let c = r.lane.barrier(202).unwrap();
        assert_eq!(r.lane.complete(c).is_ok(), verdict == Verdict::Valid);
    }
}
#[test]
fn sa110_same_tick_replay_spends_work_without_second_effect() {
    let r = Rig::open(); let before = r.view(); let p = r.proposal();
    let mut output = Vec::new();
    r.lane.attempt(&30, p, |_| true, || { output.push(1); Ok(()) }).unwrap();
    assert_eq!(r.lane.attempt(&30, p, |_| panic!("replayed gate"), || { output.push(2); Ok(()) }), Err(Error::Denied));
    r.lane.attempt(&30, r.proposal(), |_| true, || { output.push(3); Ok(()) }).unwrap();
    assert_eq!(output, [1, 3]); let after = r.view(); unchanged_frame(before, after);
    assert_eq!(after.effects, 2); assert_eq!(after.next_seq, before.next_seq + 3);
    assert_eq!(after.remaining, before.remaining - 3);
}
#[test]
fn sa110_every_proposal_field_is_bound_before_gate_or_effect() {
    let mutations: &[fn(&mut Proposal)] = &[
        |p| p.domain += 1, |p| p.incarnation += 1, |p| p.revision += 1, |p| p.sequence += 1,
        |p| p.token += 1, |p| p.keyset += 1, |p| p.at_tick += 1,
        |p| p.scope.installation += 1, |p| p.scope.policy += 1, |p| p.scope.peer += 1,
        |p| p.scope.kind += 1, |p| p.scope.artifact += 1, |p| p.scope.generation += 1,
        |p| p.scope.request += 1, |p| p.scope.operation += 1, |p| p.scope.role += 1,
        |p| p.scope.runtime += 1, |p| p.scope.connection += 1, |p| p.scope.binding += 1,
        |p| p.scope.local += 1, |p| p.scope.incarnation += 1, |p| p.scope.serial += 1, |p| p.scope.challenge += 1,
    ];
    for (index, change) in mutations.iter().enumerate() {
        let r = Rig::open(); let mut p = r.proposal(); change(&mut p); let before = r.view();
        assert_eq!(r.lane.attempt(&30, p, |_| panic!("scope gate {index}"), || -> Result<(), ()> { panic!("effect") }), Err(Error::Denied));
        assert_eq!(r.view().effects, 0); assert_eq!(r.view().remaining, before.remaining - 1);
    }
}
#[test]
fn sa110_changed_peer_and_missing_evidence_deny_without_gate() {
    let r = Rig::open();
    assert_eq!(r.lane.attempt(&31, r.proposal(), |_| panic!("gate"), || Ok(())), Err(Error::Denied));
    r.data.lock().unwrap().candidate = None;
    assert_eq!(r.lane.attempt(&30, r.proposal(), |_| panic!("gate"), || Ok(())), Err(Error::Denied));
    assert_eq!(r.view().effects, 0);
}
#[test]
fn sa110_existing_gate_is_checked_under_guard_and_never_implied_by_identity() {
    let r = Rig::open(); let before = r.view();
    assert_eq!(r.lane.attempt(&30, r.proposal(), |scope| {
        assert_eq!(*scope, candidate().scope); assert_eq!(r.lane.barrier(300), Err(Error::Busy)); false
    }, || -> Result<(), ()> { panic!("effect") }), Err(Error::Denied));
    assert_eq!(r.view().remaining, before.remaining - 1); assert_eq!(r.view().effects, 0);
}
#[test]
fn sa110_effect_before_barrier_retains_prefix_and_blocks_suffix_and_final_delivery() {
    let r = Rig::open(); let mut bytes = Vec::new();
    r.lane.attempt(&30, r.proposal(), |_| true, || { bytes.extend_from_slice(b"prefix"); Ok(()) }).unwrap();
    let before = r.view(); let _change = r.lane.barrier(301).unwrap();
    for _ in 0..2 {
        assert_eq!(r.lane.attempt(&30, r.proposal(), |_| true, || { bytes.extend_from_slice(b"suffix"); Ok(()) }), Err(Error::Denied));
    }
    assert_eq!(bytes, b"prefix"); assert_eq!(r.view().effects, 1); unchanged_frame(before, r.view());
}
#[test]
fn sa110_barrier_before_use_blocks_cached_candidate_and_old_completion() {
    let r = Rig::open(); let old = r.proposal(); let c = r.lane.barrier(302).unwrap();
    assert_eq!(r.lane.attempt(&30, old, |_| true, || Ok(())), Err(Error::Denied));
    r.lane.complete(c).unwrap();
    let mut stale = r.proposal(); stale.revision = old.revision;
    assert_eq!(r.lane.attempt(&30, stale, |_| true, || Ok(())), Err(Error::Denied));
    r.use_once().unwrap();
    assert_eq!(r.lane.complete(c), Err(Error::Denied)); assert_eq!(r.view().mode, Mode::Closed);
}
#[test]
fn sa110_overlapping_command_never_replaces_pending_change() {
    let r = Rig::open(); let c = r.lane.barrier(303).unwrap(); let before = r.view();
    assert_eq!(r.lane.barrier(304), Err(Error::Denied));
    assert_eq!(r.lane.barrier(0), Err(Error::Denied));
    assert_eq!(r.view().pending, c.command); assert_eq!(r.view().revision, c.revision);
    assert_eq!(r.view().remaining, before.remaining - 2); r.lane.complete(c).unwrap();
}
#[test]
fn sa110_completion_requires_each_correlated_field_and_verified_result() {
    let mutations: &[fn(&mut Completion)] = &[
        |a| a.change.domain += 1, |a| a.change.incarnation += 1, |a| a.change.revision += 1,
        |a| a.change.command += 1, |a| a.checked = Verdict::Unknown, |a| a.checked = Verdict::Invalid,
        |a| a.policy = 0, |a| a.keyset = 0,
    ];
    for mutate in mutations {
        let r = Rig::open(); let change = r.lane.barrier(305).unwrap();
        let mut ack = Completion { change, policy: 3, keyset: 4, checked: Verdict::Valid, enabled: Verdict::Valid };
        mutate(&mut ack); r.data.lock().unwrap().ack = AckReply::Exact(ack);
        let before = r.view(); assert_eq!(r.lane.complete(change), Err(Error::Denied));
        assert_eq!(r.view().pending, change.command); assert_eq!(r.view().mode, Mode::Closed);
        assert_eq!((r.view().policy, r.view().keyset), (before.policy, before.keyset));
    }
}
#[test]
fn sa110_unavailable_and_disabled_completion_cannot_reopen() {
    let r = Rig::open(); let c = r.lane.barrier(306).unwrap();
    r.data.lock().unwrap().ack = AckReply::Missing;
    assert_eq!(r.lane.complete(c), Err(Error::Denied)); assert_eq!(r.view().pending, c.command);
    for enabled in [Verdict::Unknown, Verdict::Invalid] {
        let r = Rig::open(); let c = r.lane.barrier(307).unwrap(); r.data.lock().unwrap().enabled = enabled;
        assert_eq!(r.lane.complete(c), Err(Error::Denied));
        assert_eq!(r.view().mode, Mode::Closed); assert_eq!(r.view().pending, 0);
    }
}
#[test]
fn sa110_policy_key_rotation_requires_coherent_fresh_candidate() {
    let r = Rig::open(); let old = r.proposal(); let c = r.lane.barrier(308).unwrap();
    { let mut d = r.data.lock().unwrap(); d.policy = 13; d.keyset = 14; }
    r.lane.complete(c).unwrap(); assert_eq!(r.use_once(), Err(Error::Denied));
    let mut fresh = candidate(); fresh.config.policy = 13; fresh.config.keyset = 14;
    fresh.token.keyset = 14; fresh.mapping.policy = 13; fresh.scope.policy = 13;
    fresh.proof.scope = fresh.scope; fresh.grant.scope = fresh.scope;
    r.data.lock().unwrap().candidate = Some(fresh);
    assert_eq!(r.lane.attempt(&30, old, |_| true, || Ok(())), Err(Error::Denied));
    let p = proposal(r.view(), *r.time.lock().unwrap(), fresh);
    r.lane.attempt(&30, p, |_| true, || Ok(())).unwrap(); assert_eq!(r.view().effects, 1);
}
#[test]
fn sa110_deadline_is_exclusive_and_administration_never_refills() {
    let r = Rig::open(); let before = r.view(); *r.time.lock().unwrap() = Now { wall: 100, tick: 200 };
    assert_eq!(r.use_once(), Err(Error::Denied));
    let change = r.lane.barrier(309).unwrap(); assert_eq!(r.lane.complete(change), Err(Error::Denied));
    assert_eq!(r.lane.recover(6), Err(Error::Poisoned)); assert_eq!(r.lane.establish(), Err(Error::Poisoned));
    unchanged_frame(before, r.view()); assert_eq!(r.view().deadline, 200); assert_eq!(r.view().mode, Mode::Poisoned);
}
#[test]
fn sa110_last_work_unit_can_submit_then_exhaustion_still_allows_close() {
    let mut cfg = config(); cfg.work = 4; let r = Rig::with(cfg);
    r.lane.establish().unwrap(); let c = r.lane.barrier(310).unwrap(); r.lane.complete(c).unwrap();
    assert_eq!(r.view().remaining, 1); r.use_once().unwrap(); assert_eq!(r.view().remaining, 0);
    assert_eq!(r.use_once(), Err(Error::Denied));
    let c = r.lane.barrier(311).unwrap(); assert_eq!(r.lane.complete(c), Err(Error::Denied));
    assert_eq!(r.lane.recover(6), Err(Error::Poisoned)); assert_eq!(r.view().remaining, 0); assert_eq!(r.view().effects, 1);
}
#[test]
fn sa110_both_clock_rollbacks_poison_and_preserve_high_water_marks() {
    for now in [Now { wall: 99, tick: 100 }, Now { wall: 100, tick: 99 }] {
        let r = Rig::open(); r.use_once().unwrap(); let before = r.view(); *r.time.lock().unwrap() = now;
        assert_eq!(r.use_once(), Err(Error::Poisoned)); unchanged_frame(before, r.view());
        *r.time.lock().unwrap() = Now { wall: 101, tick: 101 };
        assert_eq!(r.lane.recover(6), Err(Error::Poisoned)); assert_eq!(r.use_once(), Err(Error::Poisoned));
    }
}
#[test]
fn sa110_time_is_resampled_after_provider_and_gate() {
    let r = Rig::open(); r.data.lock().unwrap().delayed = Some(Now { wall: 150, tick: 100 });
    assert_eq!(r.use_once(), Err(Error::Denied)); assert_eq!(r.view().effects, 0);
    let r = Rig::open();
    assert_eq!(r.lane.attempt(&30, r.proposal(), |_| {
        *r.time.lock().unwrap() = Now { wall: 145, tick: 100 }; true
    }, || -> Result<(), ()> { panic!("expired grant") }), Err(Error::Denied));
    let r = Rig::open();
    assert_eq!(r.lane.attempt(&30, r.proposal(), |_| {
        *r.time.lock().unwrap() = Now { wall: 99, tick: 100 }; true
    }, || -> Result<(), ()> { panic!("rollback") }), Err(Error::Poisoned));
}
#[test]
fn sa110_sequence_effect_and_revision_exhaustion_never_wrap() {
    for which in 0..3 {
        let r = Rig::open();
        { let mut s = r.lane.inner.lock().unwrap();
          match which { 0 => s.state.next_seq = u64::MAX, 1 => s.state.effects = u64::MAX, _ => s.state.revision = u64::MAX } }
        let before = r.view();
        if which == 2 { assert_eq!(r.lane.barrier(312), Err(Error::Poisoned)); }
        else { assert_eq!(r.use_once(), Err(Error::Poisoned)); }
        unchanged_frame(before, r.view()); assert_eq!(r.view().mode, Mode::Poisoned);
    }
    let r = Rig::open(); r.lane.inner.lock().unwrap().state.next_seq = u64::MAX - 1;
    r.use_once().unwrap(); assert_eq!(r.view().next_seq, u64::MAX);
    assert_eq!(r.use_once(), Err(Error::Poisoned)); assert_eq!(r.view().effects, 1);
}
#[test]
fn sa110_loss_of_control_pending_change_rejects_delayed_success() {
    let r = Rig::open(); r.use_once().unwrap(); let c = r.lane.barrier(313).unwrap(); let before = r.view();
    r.lane.invalidate().unwrap(); assert_eq!(r.lane.complete(c), Err(Error::Poisoned));
    assert_eq!(r.view().pending, c.command); assert_eq!(r.view().controlled, Verdict::Unknown);
    assert_eq!(r.lane.recover(6), Err(Error::Poisoned)); unchanged_frame(before, r.view());
    assert_eq!(r.use_once(), Err(Error::Poisoned));
}
#[test]
fn sa110_recovery_requires_new_incarnation_and_reestablishment_without_refill() {
    let r = Rig::open(); r.use_once().unwrap(); let old = r.proposal(); let pending = r.lane.barrier(314).unwrap();
    let before = r.view(); r.lane.recover(6).unwrap();
    assert_eq!(r.view().controlled, Verdict::Unknown); assert_eq!(r.view().mode, Mode::Closed);
    assert_eq!(r.view().pending, 0); assert_eq!(r.lane.complete(pending), Err(Error::Denied));
    r.lane.establish().unwrap(); let c = r.lane.barrier(315).unwrap(); r.lane.complete(c).unwrap();
    assert_eq!(r.lane.attempt(&30, old, |_| true, || Ok(())), Err(Error::Denied));
    r.use_once().unwrap(); unchanged_frame(before, r.view()); assert_eq!(r.view().effects, 2);
}
#[test]
fn sa110_unverified_or_reused_recovery_poison_is_terminal() {
    for (verdict, incarnation) in [(Verdict::Unknown, 6), (Verdict::Invalid, 6), (Verdict::Valid, 5), (Verdict::Valid, 0)] {
        let r = Rig::open(); r.data.lock().unwrap().fresh = verdict;
        assert_eq!(r.lane.recover(incarnation), Err(Error::Poisoned));
        r.data.lock().unwrap().fresh = Verdict::Valid;
        assert_eq!(r.lane.recover(7), Err(Error::Poisoned)); assert_eq!(r.lane.establish(), Err(Error::Poisoned));
    }
}
#[test]
fn sa110_uncertain_effect_keeps_submission_and_poison_prevents_retry() {
    let r = Rig::open(); let before = r.view(); let mut bytes = Vec::new();
    assert_eq!(r.lane.attempt(&30, r.proposal(), |_| true, || -> Result<(), ()> {
        bytes.extend_from_slice(b"partial"); Err(())
    }), Err(Error::EffectUncertain));
    assert_eq!(r.use_once(), Err(Error::Poisoned)); assert_eq!(bytes, b"partial");
    assert_eq!(r.view().effects, 1); unchanged_frame(before, r.view());
    // Submission, loss invalidation, and the denied retry each spend one unit.
    assert_eq!(r.view().remaining, before.remaining - 3);
    assert_eq!(r.view().next_seq, before.next_seq + 3);
}
#[test]
fn sa110_provider_gate_and_effect_unwind_poison_without_refund() {
    for phase in 0..3 {
        let r = Rig::open(); let before = r.view(); let p = r.proposal();
        if phase == 0 { r.data.lock().unwrap().panic_candidate = true; }
        let result = catch_unwind(AssertUnwindSafe(|| r.lane.attempt(&30, p,
            |_| { assert!(phase != 1, "injected gate unwind"); true },
            || { assert!(phase != 2, "injected effect unwind"); Ok(()) })));
        assert!(result.is_err()); assert_eq!(r.lane.view(), Err(Error::Poisoned));
        assert_eq!(r.lane.recover(6), Err(Error::Poisoned));
        let poisoned = match r.lane.inner.lock() { Err(e) => e.into_inner(), Ok(_) => panic!("mutex not poisoned") };
        assert_eq!(poisoned.state.remaining, before.remaining - 1);
        assert_eq!(poisoned.state.next_seq, before.next_seq + 1);
        assert_eq!(poisoned.state.effects, if phase == 2 { 1 } else { 0 });
    }
}
#[test]
fn sa110_threaded_effect_holds_guard_and_busy_barrier_is_not_authorization() {
    let r = Rig::open(); let p = r.proposal(); let lane = Arc::new(r.lane);
    let worker = lane.clone(); let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let join = std::thread::spawn(move || worker.attempt(&30, p, |_| true, || {
        // Test-only rendezvous to force this order; production effects may NOT wait.
        entered_tx.send(()).unwrap(); release_rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap(); Ok(41)
    }));
    entered_rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap(); assert_eq!(lane.barrier(316), Err(Error::Busy));
    assert_eq!(lane.invalidate(), Err(Error::Busy));
    release_tx.send(()).unwrap(); assert_eq!(join.join().unwrap(), Ok(41));
    let c = lane.barrier(316).unwrap(); assert_eq!(lane.view().unwrap().effects, 1);
    assert_eq!(lane.view().unwrap().pending, c.command);
    assert_eq!(lane.attempt(&30, p, |_| true, || Ok(())), Err(Error::Denied));
}
#[test]
fn sa110_threaded_barrier_finishes_before_use_and_late_ack_cannot_bypass_invalidation() {
    let r = Rig::open(); let p = r.proposal(); let lane = Arc::new(r.lane); let worker = lane.clone();
    let change = std::thread::spawn(move || worker.barrier(317)).join().unwrap().unwrap();
    assert_eq!(lane.attempt(&30, p, |_| true, || Ok(())), Err(Error::Denied));
    lane.invalidate().unwrap(); assert_eq!(lane.complete(change), Err(Error::Poisoned));
    assert_eq!(lane.view().unwrap().effects, 0);
}

#[test]
fn sa110_exhausted_or_expired_control_skips_provider_work() {
    let mut cfg = config(); cfg.work = 1; let r = Rig::with(cfg);
    r.lane.establish().unwrap(); let c = r.lane.barrier(318).unwrap();
    assert_eq!(r.lane.complete(c), Err(Error::Denied)); assert_eq!(r.use_once(), Err(Error::Denied));
    assert_eq!(r.lane.recover(6), Err(Error::Poisoned));
    let d = r.data.lock().unwrap();
    assert_eq!((d.attestations, d.completions, d.observed, d.recoveries), (1, 0, 0, 0));
    drop(d);
    let r = Rig::closed(); *r.time.lock().unwrap() = Now { wall: 100, tick: 200 };
    assert_eq!(r.lane.establish(), Err(Error::Denied));
    let c = r.lane.barrier(319).unwrap(); assert_eq!(r.lane.complete(c), Err(Error::Denied));
    assert_eq!(r.data.lock().unwrap().attestations, 0);
    assert_eq!(r.data.lock().unwrap().completions, 0);
}
#[test]
fn sa110_control_callbacks_recheck_deadline_and_clock_before_reopening() {
    let r = Rig::closed(); r.data.lock().unwrap().control_time = Some(Now { wall: 100, tick: 200 });
    assert_eq!(r.lane.establish(), Err(Error::Denied)); assert_eq!(r.view().controlled, Verdict::Unknown);
    let r = Rig::open(); let c = r.lane.barrier(320).unwrap();
    r.data.lock().unwrap().control_time = Some(Now { wall: 100, tick: 200 });
    assert_eq!(r.lane.complete(c), Err(Error::Denied)); assert_eq!(r.view().mode, Mode::Closed);
    assert_eq!(r.view().pending, 0); assert_eq!(r.use_once(), Err(Error::Denied));
    let r = Rig::open(); r.data.lock().unwrap().control_time = Some(Now { wall: 99, tick: 100 });
    assert_eq!(r.lane.recover(6), Err(Error::Poisoned)); assert_eq!(r.view().last_wall, 100);
}

#[path="tests/candidate.rs"]
mod candidate_checks;
