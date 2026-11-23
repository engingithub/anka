//! SC110 differential and ownership tests. Run on the developer machine.
use super::*;
use crate::anka64::scoped_pointers::heap::no_alloc;

const CPU: AgentId = AgentId(0);
const BASE: usize = 0x1000;
const BYTES: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 0x80];

fn fixture(fetch: bool) -> (Fabric, ObjectId, DomainId) {
    let mut f = Fabric::new(0x4000);
    let object = f.alloc_object("scalar", 512, ObjectKind::Memory);
    assert!(f.place_object(object, BASE as u64));
    assert!(f.initialize_object(object, 0, &BYTES));
    let domain = f.create_domain();
    if fetch { assert!(f.seal_object(object)); }
    f.grant(domain, object, 0, 512, if fetch { Permissions::RX } else { Permissions::RW });
    f.register_agent(CPU, AgentKind::Cpu(CoreId(0)), domain);
    (f, object, domain)
}

fn compare(a: &Transaction, b: &Transaction) {
    assert_eq!(a.id, b.id);
    assert_eq!(format!("{:?}", a.request), format!("{:?}", b.request));
    assert_eq!(a.state, b.state);
    assert_eq!(a.auth_generation, b.auth_generation);
    assert_eq!(a.physical_address, b.physical_address);
    assert_eq!(a.write_data, b.write_data);
    assert_eq!(a.read_data.as_deref(), b.read_data.as_deref());
    assert_eq!(format!("{:?}", a.fault), format!("{:?}", b.fault));
}

#[test]
fn sc110_scalar_all_widths_match_reference_read_and_fetch() {
    for fetch in [false, true] {
        for width in [Width::Byte, Width::Half, Width::Word, Width::Double] {
            let (mut old, object, domain) = fixture(fetch);
            let (mut new, _, _) = fixture(fetch);
            let kind = if fetch { AccessKind::Fetch } else { AccessKind::Read };
            let r = request(CPU, domain, object, 0, width, kind);
            let expected = old.execute_read(r).unwrap();
            let actual = new.execute_cpu_read(r).unwrap();
            assert_eq!(actual.as_slice(), expected.as_slice());
            assert!(matches!(actual, ReadPayload::Inline { .. }));
            assert!(matches!(old.transaction(0).read_data, Some(ReadPayload::Heap(_))));
            compare(old.transaction(0), new.transaction(0));
            assert_eq!(old.memory, new.memory);
        }
    }
}

#[test]
fn sc110_scalar_exact_last_byte_no_physical_widening() {
    let (mut f, object, domain) = fixture(false);
    f.memory.truncate(BASE + 512);
    f.memory[BASE + 511] = 255;
    f.domains.get_mut(&domain).unwrap().capabilities.clear();
    f.grant(domain, object, 511, 1, Permissions::READ);
    let bytes = f.execute_cpu_read(request(CPU, domain, object, 511, Width::Byte, AccessKind::Read)).unwrap();
    assert_eq!(bytes.as_slice(), &[255]);
    match bytes {
        ReadPayload::Inline { bytes, len } => { assert_eq!(len, 1); assert_eq!(&bytes[1..], &[0; 7]); }
        _ => panic!("scalar must be inline"),
    }
}

#[test]
fn sc110_scalar_failures_preserve_reference_fault_and_memory() {
    for case in 0..7 {
        let (mut old, object, domain) = fixture(false);
        let (mut new, _, _) = fixture(false);
        let mut r = request(CPU, domain, object, 0, Width::Word, AccessKind::Read);
        for f in [&mut old, &mut new] {
            match case {
                0 => f.domains.get_mut(&domain).unwrap().capabilities.clear(),
                1 => { f.domains.get_mut(&domain).unwrap().capabilities.clear(); f.grant(domain, object, 0, 512, Permissions::WRITE); }
                2 => { f.revoke(object); }
                3 => { f.placement.remove(&object); }
                4 => { f.memory.truncate(BASE + 2); }
                _ => {},
            }
        }
        if case == 5 { r.length = 0; }
        if case == 6 { r.offset = u64::MAX - 1; }
        let before = new.memory.clone();
        let a = old.execute_read(r).unwrap_err();
        let b = new.execute_cpu_read(r).unwrap_err();
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
        compare(old.transaction(0), new.transaction(0));
        assert!(new.transaction(0).read_data.is_none());
        assert_eq!(new.memory, before);
    }
}

#[test]
fn sc110_scalar_each_stage_revocation_matches_reference() {
    for advances in 0..=3 {
        let (mut old, object, domain) = fixture(false);
        let (mut new, _, _) = fixture(false);
        let r = request(CPU, domain, object, 0, Width::Word, AccessKind::Read);
        let a = old.submit(r, None);
        let b = new.submit_cpu_read(r);
        for _ in 0..advances { old.advance(a); new.advance(b); }
        old.revoke(object); new.revoke(object);
        for _ in 0..3 { old.advance(a); new.advance(b); }
        compare(old.transaction(a), new.transaction(b));
        assert_eq!(new.transaction(b).state, if advances == 3 { TxState::Committed } else { TxState::Faulted });
    }
}

#[test]
fn sc110_scalar_commit_rechecks_permission_and_prepared_span() {
    for remove_permission in [false, true] {
        let (mut old, object, domain) = fixture(false);
        let (mut new, _, _) = fixture(false);
        let r = request(CPU, domain, object, 0, Width::Double, AccessKind::Read);
        let a = old.submit(r, None); let b = new.submit_cpu_read(r);
        for _ in 0..2 { old.advance(a); new.advance(b); }
        for f in [&mut old, &mut new] {
            if remove_permission { f.domains.get_mut(&domain).unwrap().capabilities.clear(); }
            else { f.memory.truncate(BASE + 7); }
        }
        old.advance(a); new.advance(b);
        compare(old.transaction(a), new.transaction(b));
        assert_eq!(new.transaction(b).state, TxState::Faulted);
        assert!(new.transaction(b).read_data.is_none());
    }
}

#[test]
fn sc110_scalar_snapshot_is_from_commit_and_never_consumed() {
    let (mut f, object, domain) = fixture(false);
    let r = request(CPU, domain, object, 0, Width::Word, AccessKind::Read);
    let i = f.submit_cpu_read(r);
    for state in [TxState::Requested, TxState::Authorized, TxState::Prepared] {
        assert_eq!(f.transaction(i).state, state);
        assert!(f.transaction(i).read_data.is_none());
        if state != TxState::Prepared { f.advance(i); }
    }
    f.write_physical(BASE as u64, &[9, 8, 7, 6]);
    f.advance(i);
    let copy = f.transaction(i).read_data.as_ref().unwrap().clone();
    f.write_physical(BASE as u64, &[0; 4]);
    f.advance(i); // Terminal no-op, no recapture.
    assert_eq!(copy.as_slice(), &[9, 8, 7, 6]);
    for _ in 0..3 { assert_eq!(f.transaction(i).read_data.as_deref(), Some(&[9, 8, 7, 6][..])); }
    assert_eq!(f.transactions.len(), 1);
}

#[test]
fn sc110_scalar_bulk_and_mismatched_width_fall_back() {
    for (width, length) in [(Width::Byte, 9), (Width::Byte, 512), (Width::Word, 8)] {
        let (mut old, object, domain) = fixture(false); let (mut new, _, _) = fixture(false);
        let mut r = request(CPU, domain, object, 0, width, AccessKind::Read); r.length = length;
        let expected = old.execute_read(r).unwrap();
        let actual = new.execute_cpu_read(r).unwrap();
        assert!(matches!(actual, ReadPayload::Heap(_)));
        assert_eq!(actual.as_slice(), expected.as_slice());
        compare(old.transaction(0), new.transaction(0));
    }
}

#[test]
fn sc110_scalar_async_small_read_keeps_general_snapshot() {
    let (mut f, object, domain) = fixture(false);
    // Even a CPU-labelled request submitted through the asynchronous API stays general.
    let i = f.submit(request(CPU, domain, object, 0, Width::Word, AccessKind::Read), None);
    for _ in 0..3 { f.advance(i); }
    assert!(matches!(f.transaction(i).read_data, Some(ReadPayload::Heap(_))));
    f.write_physical(BASE as u64, &[0; 4]);
    assert_eq!(f.transaction(i).read_data.as_deref(), Some(&BYTES[..4]));
}

#[test]
fn sc110_scalar_write_and_atomic_never_select_inline() {
    for kind in [AccessKind::Write, AccessKind::Atomic] {
        let (mut f, object, domain) = fixture(false);
        let i = f.submit_cpu_read(request(CPU, domain, object, 0, Width::Double, kind));
        assert!(!f.transaction(i).scalar_read);
        assert!(f.transaction(i).read_data.is_none());
    }
}

#[test]
fn sc110_scalar_cleanup_retains_pending_fault_history_and_ids() {
    let (mut f, object, domain) = fixture(false);
    let r = request(CPU, domain, object, 0, Width::Word, AccessKind::Read);
    let pending = f.submit_cpu_read(r);
    for _ in 0..2 { f.advance(pending); assert!(!f.discard_completed_compiler_trace()); }
    f.advance(pending);
    f.revoke(object);
    let _ = f.execute_cpu_read(r).unwrap_err();
    let next = f.next_tx_id;
    let faults = format!("{:?}", f.fault_log);
    assert!(f.discard_completed_compiler_trace());
    assert_eq!(f.next_tx_id, next);
    assert_eq!(format!("{:?}", f.fault_log), faults);
    let i = f.submit_cpu_read(r);
    assert_eq!(f.transaction(i).id, TransactionId(next));
}

#[test]
fn sc110_scalar_payload_and_return_allocate_nothing() {
    let (mut f, object, domain) = fixture(false);
    f.transactions.reserve_exact(64);
    // Allocation counter tracks alloc/alloc_zeroed/realloc on this thread.
    no_alloc(|| {
        for _ in 0..8 {
            for width in [Width::Byte, Width::Half, Width::Word, Width::Double] {
                let bytes = f.execute_cpu_read(request(CPU, domain, object, 0, width, AccessKind::Read)).unwrap();
                assert!(matches!(bytes, ReadPayload::Inline { .. }));
                assert_eq!(bytes.as_slice(), &BYTES[..width.bytes() as usize]);
            }
        }
        assert!(f.discard_completed_compiler_trace());
    });
}

#[test]
fn sc110_scalar_record_footprint_stays_within_trace_allowance() {
    // Largest existing application trace is 16384 records. Leave at least
    // 8 MiB of its 16 MiB nonheap envelope for other bounded state.
    let size = std::mem::size_of::<Transaction>();
    assert!(size <= 384);
    assert!((size + 32) * 16384 <= 8 * 1024 * 1024);
    eprintln!("SC110 transaction record: {size} bytes; largest directory: {} bytes", size * 16384);
}
