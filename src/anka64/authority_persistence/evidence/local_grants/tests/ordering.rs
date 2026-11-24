use super::*;
use std::sync::mpsc;

#[test]
fn lg110_submit_guard_orders_revocation_and_prevents_competing_effects() {
    let r = Rig::issued(); let proposal = r.proposal(); let owner = Arc::new(r.owner);
    let worker_owner = owner.clone();
    let (entered_tx, entered_rx) = mpsc::channel(); let (release_tx, release_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || worker_owner.attempt(&30, proposal, |_| true, || {
        entered_tx.send(()).unwrap(); release_rx.recv().unwrap(); Ok(42)
    }));
    entered_rx.recv().unwrap();
    // Collect before assertions so the worker is always released even on failure.
    let busy_view = owner.view(); let busy_revoke = owner.revoke();
    let busy_attempt = owner.attempt(&30, proposal, |_| true, || Ok(99));
    release_tx.send(()).unwrap(); let submitted = worker.join().unwrap();
    assert_eq!(busy_view, Err(Error::Busy)); assert_eq!(busy_revoke, Err(Error::Busy));
    assert_eq!(busy_attempt, Err(Error::Busy)); assert_eq!(submitted, Ok(42));
    owner.revoke().unwrap(); let v = owner.view().unwrap();
    assert_eq!((v.effects, v.remaining, v.next_seq), (1, 60, 5)); // Busy has no transition.
    let mut next = proposal; next.sequence = v.next_seq; next.revision = v.revision;
    assert_eq!(owner.attempt(&30, next, |_| true, || Ok(99)), Err(Error::Denied));
}
#[test]
fn lg110_external_query_wait_does_not_hold_local_owner_guard() {
    let r = Rig::issued(); let q = r.owner.begin_query().unwrap();
    let inputs = r.inputs.clone(); let owner = Arc::new(r.owner);
    let (started_tx, started_rx) = mpsc::channel(); let (finish_tx, finish_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        started_tx.send(()).unwrap(); finish_rx.recv().unwrap();
        inputs.lock().unwrap().reply = Some(completion(q));
    });
    started_rx.recv().unwrap(); let during_wait = owner.view(); let revoked = owner.revoke();
    finish_tx.send(()).unwrap(); worker.join().unwrap();
    assert_eq!(during_wait.unwrap().pending, Some(q)); assert_eq!(revoked, Ok(()));
    assert_eq!(owner.complete(q), Err(Error::Denied)); assert_eq!(owner.view().unwrap().effects, 0);
}
#[test]
fn lg110_reentrant_callback_observes_busy_without_duplicate_submission() {
    let r = Rig::issued(); let p = r.proposal();
    assert_eq!(r.owner.attempt(&30, p, |_| {
        assert_eq!(r.owner.revoke(), Err(Error::Busy)); true
    }, || {
        assert_eq!(r.owner.attempt(&30, p, |_| true, || Ok(99)), Err(Error::Busy)); Ok(42)
    }), Ok(42));
    assert_eq!((r.view().remaining, r.view().effects), (61, 1));
    r.owner.revoke().unwrap(); assert_eq!(r.run(), Err(Error::Denied));
}
#[test]
fn lg110_clock_unwind_poison_cannot_restore_owner() {
    struct BrokenClock { calls: u64 }
    impl Clock for BrokenClock {
        fn now(&mut self) -> Now {
            self.calls += 1;
            if self.calls == 2 { panic!("injected clock unwind"); }
            Now { wall: 100, tick: 100 }
        }
    }
    let owner = Owner::new(config(), DenyEvidence, BrokenClock { calls: 0 }).unwrap();
    assert!(catch_unwind(AssertUnwindSafe(|| owner.begin_query())).is_err());
    assert_eq!(owner.view(), Err(Error::Poisoned));
    assert_eq!(owner.revoke(), Err(Error::Poisoned));
}
