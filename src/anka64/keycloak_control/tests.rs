use super::*;
use std::cell::Cell;

#[derive(Clone)]
struct Time(Rc<Cell<Now>>);
impl Clock for Time { fn now(&mut self) -> Now { self.0.get() } }
fn setup(work: u64) -> (Coordinator<Mailbox, Time>, Rc<RefCell<Option<Completion>>>, Time) {
    let time = Time(Rc::new(Cell::new(Now { wall: 100, tick: 100 })));
    let slot = Rc::new(RefCell::new(None));
    let lane = Coordinator::new(Config { installation: 1, issuer: 1, policy: 1, keyset: 1,
        incarnation: 1, work, deadline: 200, boot: 17 }, Mailbox(slot.clone()), time.clone()).unwrap();
    (lane, slot, time)
}
fn request() -> Request {
    Request { action: 1, change: Change { domain: 2, incarnation: 3, revision: 4, command: 5 }, nonce: [6,7,8,9] }
}
fn response(r: Request) -> Vec<u8> {
    let mut raw = r.encode().to_vec(); raw[..8].copy_from_slice(RMAGIC);
    for word in [r.action, 0, 101, 0, if r.action == 1 {31} else {8}] { raw.extend_from_slice(&word.to_le_bytes()); }
    raw
}

#[test]
fn ac110_wire_exact_sizes_endianness_and_correlation() {
    let q = request(); let raw = response(q); assert_eq!(q.encode().len(), 80); assert_eq!(raw.len(), 120);
    assert_eq!(&q.encode()[8..16], &1u64.to_le_bytes());
    assert_eq!(&q.encode()[16..24], &2u64.to_le_bytes());
    assert_eq!(decode(q, &raw), Ok(Reply { original: 0, target: 101, restored: 0, flags: 31 }));
    let mut recover = q; recover.action = 2; assert!(decode(recover, &response(recover)).is_ok());
}
#[test]
fn ac110_wire_every_truncation_and_tail_is_rejected() {
    let q = request(); let raw = response(q);
    for n in 0..raw.len() { assert_eq!(decode(q, &raw[..n]), Err(())); }
    let mut tail = raw; tail.push(0); assert_eq!(decode(q, &tail), Err(()));
}
#[test]
fn ac110_wire_every_magic_echo_status_and_result_byte_is_bound() {
    let q = request(); let raw = response(q);
    for n in 0..88 { let mut changed = raw.clone(); changed[n] ^= 1; assert_eq!(decode(q, &changed), Err(()), "byte {n}"); }
    for offset in [88,104,112] { let mut changed = raw.clone(); changed[offset] ^= 1; assert_eq!(decode(q, &changed), Err(())); }
    let mut changed = raw.clone(); changed[96..104].copy_from_slice(&u64::MAX.to_le_bytes()); assert_eq!(decode(q, &changed), Err(()));
    let mut changed = raw; changed[96..104].copy_from_slice(&0u64.to_le_bytes()); assert_eq!(decode(q, &changed), Err(()));
}
#[test]
fn ac110_no_worker_for_invalid_action_nonce_or_exhausted_owner() {
    for (action, nonce, work) in [(0,[1,2,3,4],8), (3,[1,2,3,4],8), (1,[0;4],8), (1,[1,2,3,4],1)] {
        let (lane, slot, _) = setup(work);
        assert_eq!(exchange(&lane, &slot, action, nonce, |_| panic!("worker")), Err(()));
        assert_eq!(lane.view().unwrap().pending, 0);
    }
}
#[test]
fn ac110_real_coordinator_is_closed_and_unlocked_through_remote_work() {
    let (lane, slot, _) = setup(8); let before = lane.view().unwrap();
    exchange(&lane, &slot, 1, [1,2,3,4], |q| {
        let during = lane.view().unwrap(); // would return Busy if guard escaped
        assert_eq!(during.mode, Mode::Closed); assert_eq!(during.pending, q.change.command);
        assert_eq!(during.revision, before.revision + 1); assert_eq!(during.remaining, 7);
        Ok(response(q))
    }).unwrap();
    let after = lane.view().unwrap(); assert_eq!(after.mode, Mode::Closed);
    assert_eq!(after.controlled, Verdict::Unknown); assert_eq!(after.pending, 0);
    assert_eq!((after.effects, after.boot, after.remaining, after.deadline), (0,17,6,200));
    assert_eq!(lane.establish(), Err(Error::Denied));
}
#[test]
fn ac110_remote_failure_and_malformed_reply_poison_without_retry() {
    for malformed in [false, true] {
        let (lane, slot, _) = setup(8); let calls = Cell::new(0);
        assert_eq!(exchange(&lane, &slot, 1, [1;4], |q| {
            calls.set(calls.get()+1); if malformed { let mut r=response(q);r.push(0);Ok(r) } else { Err(()) }
        }), Err(()));
        assert_eq!(lane.view().unwrap().mode, Mode::Poisoned); assert_eq!(lane.view().unwrap().remaining, 6);
        assert_eq!(exchange(&lane, &slot, 1, [2;4], |_| panic!("retry")), Err(()));
        assert_eq!(calls.get(), 1);
    }
}
#[test]
fn ac110_deadline_and_clock_rollback_cannot_accept_late_completion() {
    for now in [Now {wall:100,tick:200}, Now {wall:99,tick:100}] {
        let (lane, slot, time) = setup(8);
        assert_eq!(exchange(&lane, &slot, 1, [1;4], |q| {time.0.set(now);Ok(response(q))}), Err(()));
        assert_eq!(lane.view().unwrap().mode, Mode::Poisoned); assert_eq!(lane.view().unwrap().effects, 0);
    }
}
#[test]
fn ac110_foreign_reply_and_pending_change_never_consume_completion() {
    let (lane, slot, _) = setup(8); lane.barrier(99).unwrap();
    assert_eq!(exchange(&lane,&slot,1,[1;4], |_| panic!("overlap")),Err(()));
    assert_eq!(lane.view().unwrap().pending,99);
    let (lane, slot, _) = setup(8);
    assert_eq!(exchange(&lane,&slot,1,[1;4], |mut q| {q.nonce[3]+=1;Ok(response(q))}),Err(()));
    assert_eq!(lane.view().unwrap().mode,Mode::Poisoned);
}
#[test]
fn ac110_recovery_reply_still_cannot_attest_control_or_authorize_use() {
    let (lane, slot, _) = setup(8);
    exchange(&lane,&slot,2,[1;4],|q|Ok(response(q))).unwrap();
    assert_eq!(lane.view().unwrap().controlled,Verdict::Unknown);
    assert_eq!(lane.view().unwrap().mode,Mode::Closed);
    assert_eq!(lane.recover(2),Err(Error::Poisoned));
}
#[test]
fn ac110_worker_unwind_leaves_barrier_closed_with_pending_command() {
    let (lane, slot, _) = setup(8);
    let failed=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
        exchange(&lane,&slot,1,[1;4], |_| panic!("injected control worker unwind"))));
    assert!(failed.is_err());let view=lane.view().unwrap();
    assert_eq!((view.mode,view.pending,view.effects),(Mode::Closed,1,0));
    assert_eq!(exchange(&lane,&slot,1,[2;4], |_| panic!("retry")),Err(()));
}

#[test]
fn ac110_cli_bad_arguments_do_not_start_worker() {
    for args in [vec![],vec!["--state"],vec!["--bad-secret"],vec!["--state","x","--bad-secret"],vec!["--state",""]] {
        assert_eq!(command(&args.into_iter().map(String::from).collect::<Vec<_>>()),2);
    }
    assert_eq!(command(&["--help".into()]),0);
}
