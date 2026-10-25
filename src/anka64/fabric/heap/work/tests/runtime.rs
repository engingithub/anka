use super::*;
use crate::anka64::scoped_pointers::heap::{CleanupLease, CleanupWorker};

fn execute(k: &mut Kernel, ticket: HeapWorkTicket) -> Result<(), HeapError> {
    no_alloc(|| k.fabric.execute_heap_cpu_work(ticket))
}
fn cancel(k: &mut Kernel, ticket: HeapWorkTicket) -> Result<(), HeapError> {
    no_alloc(|| k.fabric.cancel_heap_cpu_work(ticket))
}
fn finish(k: &mut Kernel, ticket: HeapWorkTicket) -> Result<HeapWorkOutcome, HeapError> {
    no_alloc(|| k.fabric.finish_heap_cpu_work(ticket))
}
fn census(k: &mut Kernel, a: App) -> Result<HeapWorkCounts, HeapError> {
    no_alloc(|| k.fabric.heap_work_census(a.reservation, a.owner, a.object))
}
fn worker(k: &mut Kernel) -> (ProcessKey, CleanupWorker) {
    let key = process(k);
    let handle =
        no_alloc(|| k.enroll_cleanup_worker(key, k.fabric.scoped_pointers.revision())).unwrap();
    (key, handle)
}
fn claim(k: &mut Kernel, a: App, key: ProcessKey, w: CleanupWorker) -> CleanupLease {
    no_alloc(|| {
        k.fabric
            .close_attached_heap(a.reservation, a.owner, a.object)
    })
    .unwrap();
    no_alloc(|| {
        k.claim_heap_cleanup(
            key,
            w,
            a.reservation,
            a.owner,
            a.object,
            k.fabric.scoped_pointers.revision(),
        )
    })
    .unwrap()
}
fn ready(k: &mut Kernel, a: App, key: ProcessKey, lease: CleanupLease) -> Result<bool, HeapError> {
    no_alloc(|| k.heap_cleanup_ready(key, lease, a.owner, a.object))
}
fn base(k: &Kernel, a: App) -> usize {
    row(&k.fabric, a.object).extents.physical.base as usize
}
fn payload(k: &Kernel, t: HeapWorkTicket) -> &[u8; MAX_CPU_BYTES] {
    let record = work(k).checked_record(t).unwrap();
    &work(k).sources[record.source.index as usize]
        .request
        .as_ref()
        .unwrap()
        .payload
}

#[test]
fn a235c_write_applies_exact_owned_bytes_and_clears_all_overlapped_cells_only() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 33, true);
    let b = allocation(&mut k, 64, true);
    k.fabric.memory.fill(0xa5);
    k.fabric
        .private_heap
        .as_mut()
        .unwrap()
        .shadow
        .fill(Some(a.pointer));
    let t = write(&mut k, a, 15, &[0, 255]).unwrap();
    let mut expected = k.fabric.memory.clone();
    let start = base(&k, a);
    expected[start + 15..start + 17].copy_from_slice(&[0, 255]);
    let old_row = row(&k.fabric, a.object);
    let other_row = row(&k.fabric, b.object);
    let charged = k.fabric.scoped_pointers.total_reserved_bytes();
    execute(&mut k, t).unwrap();
    assert_eq!(k.fabric.memory, expected);
    let heap = k.fabric.private_heap.as_ref().unwrap();
    let first = heap.shadow_index(start as u64).unwrap();
    for (index, tag) in heap.shadow.iter().enumerate() {
        assert_eq!(
            *tag,
            if index == first || index == first + 1 {
                None
            } else {
                Some(a.pointer)
            }
        );
    }
    assert_eq!(row(&k.fabric, a.object), old_row);
    assert_eq!(row(&k.fabric, b.object), other_row);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), charged);
    assert_eq!(
        census(&mut k, a).unwrap(),
        HeapWorkCounts { cpu: 1, dma: 0 }
    );
}

#[test]
fn a235c_read_captures_exact_prefix_once_without_tags_or_backing_changes() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 33, true);
    let start = base(&k, a);
    k.fabric.memory[start..start + 4096].fill(0xe7);
    k.fabric.memory[start + 31..start + 33].copy_from_slice(&[65, 0]);
    k.fabric
        .private_heap
        .as_mut()
        .unwrap()
        .shadow
        .fill(Some(a.pointer));
    let t = read(&mut k, a, 31, 2).unwrap();
    let before = snapshot(&k.fabric);
    let shadow = k.fabric.private_heap.as_ref().unwrap().shadow.clone();
    execute(&mut k, t).unwrap();
    assert_only_heap_and_registry_changed(before, &k.fabric);
    assert_eq!(k.fabric.private_heap.as_ref().unwrap().shadow, shadow);
    assert_eq!(&payload(&k, t)[..2], &[65, 0]);
    assert!(payload(&k, t)[2..].iter().all(|b| *b == 0));
    k.fabric.memory[start + 31] = 99;
    rejects(&mut k, HeapError::WorkState, |k| execute(k, t));
    assert_eq!(payload(&k, t)[0], 65);
}

#[test]
fn a235c_full_page_and_final_logical_byte_execute_within_exact_bounds() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 4097, true);
    let bytes = [0x6b; MAX_CPU_BYTES];
    let write_ticket = write(&mut k, a, 0, &bytes).unwrap();
    let read_ticket = read(&mut k, a, 4096, 1).unwrap();
    let start = base(&k, a);
    k.fabric.memory[start + 4096..start + 8192].fill(0xde);
    execute(&mut k, write_ticket).unwrap();
    execute(&mut k, read_ticket).unwrap();
    assert_eq!(&k.fabric.memory[start..start + 4096], &bytes);
    assert!(
        k.fabric.memory[start + 4096..start + 8192]
            .iter()
            .all(|b| *b == 0xde)
    );
    assert_eq!(payload(&k, read_ticket)[0], 0xde);
    assert!(payload(&k, read_ticket)[1..].iter().all(|b| *b == 0));
}

#[test]
fn a235c_prepared_is_never_terminal_and_committed_stays_counted_until_consumed() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    let t = write(&mut k, a, 0, &[7]).unwrap();
    rejects(&mut k, HeapError::WorkState, |k| finish(k, t));
    assert_eq!(census(&mut k, a).unwrap().cpu, 1);
    execute(&mut k, t).unwrap();
    assert_eq!(census(&mut k, a).unwrap().cpu, 1);
    let before = snapshot(&k.fabric);
    let fixed = k.fabric.scoped_pointers.fixed_metadata_bytes();
    let charged = k.fabric.scoped_pointers.total_reserved_bytes();
    let allocation_row = row(&k.fabric, a.object);
    let shadow = k.fabric.private_heap.as_ref().unwrap().shadow.clone();
    assert_eq!(finish(&mut k, t).unwrap(), HeapWorkOutcome::Committed);
    assert_only_heap_and_registry_changed(before, &k.fabric);
    assert_eq!(row(&k.fabric, a.object), allocation_row);
    assert_eq!(k.fabric.private_heap.as_ref().unwrap().shadow, shadow);
    assert!(work(&k).records[0].is_none());
    assert!(work(&k).sources[0].request.is_none());
    assert_eq!(
        census(&mut k, a).unwrap(),
        HeapWorkCounts { cpu: 0, dma: 0 }
    );
    assert_eq!(k.fabric.scoped_pointers.fixed_metadata_bytes(), fixed);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), charged);
    assert!(
        k.fabric
            .scoped_pointers
            .reserved_extents(a.reservation)
            .is_ok()
    );
    rejects(&mut k, HeapError::StaleWork, |k| finish(k, t));
}

#[test]
fn a235c_cancellation_establishes_stopped_work_and_retains_pin_until_consumption() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    let t = write(&mut k, a, 0, &[7, 8, 9]).unwrap();
    let before = snapshot(&k.fabric);
    let shadow = k.fabric.private_heap.as_ref().unwrap().shadow.clone();
    cancel(&mut k, t).unwrap();
    assert_only_heap_and_registry_changed(before, &k.fabric);
    assert_eq!(k.fabric.private_heap.as_ref().unwrap().shadow, shadow);
    assert!(payload(&k, t).iter().all(|b| *b == 0));
    assert_eq!(census(&mut k, a).unwrap().cpu, 1);
    rejects(&mut k, HeapError::WorkState, |k| execute(k, t));
    rejects(&mut k, HeapError::WorkState, |k| cancel(k, t));
    assert_eq!(finish(&mut k, t).unwrap(), HeapWorkOutcome::Cancelled);
    assert_eq!(census(&mut k, a).unwrap().cpu, 0);
}

#[test]
fn a235c_committed_work_cannot_be_cancelled_or_executed_again() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    let t = write(&mut k, a, 0, &[9]).unwrap();
    execute(&mut k, t).unwrap();
    let start = base(&k, a);
    k.fabric.memory[start] = 77;
    rejects(&mut k, HeapError::WorkState, |k| cancel(k, t));
    rejects(&mut k, HeapError::WorkState, |k| execute(k, t));
    assert_eq!(k.fabric.memory[start], 77);
    assert_eq!(finish(&mut k, t).unwrap(), HeapWorkOutcome::Committed);
}

#[test]
fn a235c_already_admitted_work_finishes_after_owner_death_without_new_access() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 64, true);
    let b = allocation(&mut k, 64, true);
    let ta = write(&mut k, a, 0, &[91]).unwrap();
    let tb = read(&mut k, b, 0, 1).unwrap();
    let other = work(&k).checked_record(tb).unwrap();
    k.fabric.scoped_pointers.close_owner(a.account).unwrap();
    k.processes[a.key.slot].state = ProcessState::Zombie;
    let agent = k.processes[a.key.slot].core.agent;
    k.fabric.agents.remove(&agent);
    k.fabric.destroy_domain(a.owner.domain);
    rejects(&mut k, HeapError::Owner, |k| read(k, a, 0, 1));
    execute(&mut k, ta).unwrap();
    assert_eq!(k.fabric.memory[base(&k, a)], 91);
    assert_eq!(finish(&mut k, ta).unwrap(), HeapWorkOutcome::Committed);
    assert_eq!(work(&k).checked_record(tb).unwrap(), other);
    assert_eq!(census(&mut k, b).unwrap().cpu, 1);
    execute(&mut k, tb).unwrap();
    assert_eq!(finish(&mut k, tb).unwrap(), HeapWorkOutcome::Committed);
}

#[test]
fn a235c_fenced_worker_does_not_block_exact_terminal_consumption() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    let (key, w) = worker(&mut k);
    let t = write(&mut k, a, 0, &[5]).unwrap();
    let lease = claim(&mut k, a, key, w);
    k.fence_cleanup_worker(w).unwrap();
    execute(&mut k, t).unwrap();
    finish(&mut k, t).unwrap();
    rejects(&mut k, HeapError::Worker, |k| ready(k, a, key, lease));
    rejects(&mut k, HeapError::Busy, |k| {
        no_alloc(|| k.remove_cleanup_worker(w))
    });
    rejects(&mut k, HeapError::Busy, |k| {
        no_alloc(|| k.fabric.scoped_pointers.abort_heap(a.reservation))
    });
}

#[test]
fn a235c_census_counts_prepared_committed_cancelled_and_skips_only_empty_rows() {
    let mut k = machine(4, 4);
    let a = allocation(&mut k, 64, true);
    let b = allocation(&mut k, 64, true);
    let prepared = read(&mut k, a, 0, 1).unwrap();
    let cancelled = read(&mut k, a, 1, 1).unwrap();
    let committed = write(&mut k, a, 2, &[1]).unwrap();
    let foreign = read(&mut k, b, 0, 1).unwrap();
    cancel(&mut k, cancelled).unwrap();
    execute(&mut k, committed).unwrap();
    assert_eq!(
        census(&mut k, a).unwrap(),
        HeapWorkCounts { cpu: 3, dma: 0 }
    );
    assert_eq!(
        census(&mut k, b).unwrap(),
        HeapWorkCounts { cpu: 1, dma: 0 }
    );
    finish(&mut k, cancelled).unwrap(); // creates a hole before later active rows
    assert_eq!(census(&mut k, a).unwrap().cpu, 2);
    validate(&mut k, prepared).unwrap();
    validate(&mut k, foreign).unwrap();
}

#[test]
fn a235c_finish_validates_foreign_custody_in_the_complete_scan() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 64, true);
    let b = allocation(&mut k, 64, true);
    let ta = read(&mut k, a, 0, 1).unwrap();
    let _tb = read(&mut k, b, 0, 1).unwrap();
    execute(&mut k, ta).unwrap();
    k.fabric
        .private_heap
        .as_mut()
        .unwrap()
        .rows
        .iter_mut()
        .flatten()
        .find(|r| r.object == b.object)
        .unwrap()
        .logical += 1;
    rejects(&mut k, HeapError::StaleReservation, |k| census(k, a));
    rejects(&mut k, HeapError::StaleReservation, |k| finish(k, ta));
}

#[test]
fn a235c_orphan_source_rejects_census_and_ready_even_when_selected_count_would_be_zero() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 64, true);
    let b = allocation(&mut k, 64, true);
    let (key, w) = worker(&mut k);
    let _tb = read(&mut k, b, 0, 1).unwrap();
    let lease = claim(&mut k, a, key, w);
    work_mut(&mut k).records[0] = None;
    rejects(&mut k, HeapError::StaleWork, |k| census(k, a));
    rejects(&mut k, HeapError::StaleWork, |k| ready(k, a, key, lease));
}

#[test]
fn a235c_runtime_transitions_reject_substituted_source_before_any_effect_or_removal() {
    for terminal in [false, true] {
        let mut k = machine(1, 1);
        let a = allocation(&mut k, 64, true);
        let t = write(&mut k, a, 0, &[6]).unwrap();
        if terminal {
            execute(&mut k, t).unwrap();
        }
        work_mut(&mut k).sources[0]
            .request
            .as_mut()
            .unwrap()
            .key
            .generation += 1;
        rejects(&mut k, HeapError::StaleWork, |k| execute(k, t));
        rejects(&mut k, HeapError::StaleWork, |k| cancel(k, t));
        rejects(&mut k, HeapError::StaleWork, |k| finish(k, t));
    }
}

#[test]
fn a235c_changed_custody_quarantines_work_and_never_marks_it_terminal() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    let t = write(&mut k, a, 0, &[6]).unwrap();
    k.fabric
        .private_heap
        .as_mut()
        .unwrap()
        .rows
        .iter_mut()
        .flatten()
        .find(|r| r.object == a.object)
        .unwrap()
        .extents
        .physical
        .base += 4096;
    rejects(&mut k, HeapError::StaleReservation, |k| execute(k, t));
    rejects(&mut k, HeapError::StaleReservation, |k| cancel(k, t));
    rejects(&mut k, HeapError::StaleReservation, |k| finish(k, t));
    assert_eq!(
        work(&k).sources[0].request.as_ref().unwrap().state,
        CpuRequestState::Prepared
    );
}

#[test]
fn a235c_ready_requires_consumption_and_keeps_unrelated_pending_work() {
    let mut k = machine(2, 2);
    let a = allocation(&mut k, 64, true);
    let b = allocation(&mut k, 64, true);
    let (key, w) = worker(&mut k);
    let ta = write(&mut k, a, 0, &[7]).unwrap();
    let tb = read(&mut k, b, 0, 1).unwrap();
    let lease = claim(&mut k, a, key, w);
    assert!(!ready(&mut k, a, key, lease).unwrap());
    execute(&mut k, ta).unwrap();
    assert!(!ready(&mut k, a, key, lease).unwrap());
    finish(&mut k, ta).unwrap();
    let before = snapshot(&k.fabric);
    assert!(ready(&mut k, a, key, lease).unwrap());
    assert_eq!(snapshot(&k.fabric), before);
    validate(&mut k, tb).unwrap();
    assert_eq!(census(&mut k, b).unwrap().cpu, 1);
    rejects(&mut k, HeapError::Busy, |k| {
        no_alloc(|| k.fabric.scoped_pointers.abort_heap(a.reservation))
    });
}

#[test]
fn a235c_ready_rechecks_current_worker_process_role_and_exact_job() {
    for mode in 0..5 {
        let mut k = machine(0, 0);
        let a = allocation(&mut k, 64, true);
        let b = allocation(&mut k, 64, true);
        let (key, w) = worker(&mut k);
        let lease = claim(&mut k, a, key, w);
        assert!(ready(&mut k, a, key, lease).unwrap());
        let mut request = a;
        match mode {
            0 => k.fence_cleanup_worker(w).unwrap(),
            1 => k.processes[key.slot].state = ProcessState::Zombie,
            2 => k.processes[key.slot].generation += 1,
            3 => request.object = b.object,
            _ => request.owner = b.owner,
        }
        let error = match mode {
            3 => HeapError::StaleReservation,
            4 => HeapError::Owner,
            _ => HeapError::Worker,
        };
        rejects(&mut k, error, |k| ready(k, request, key, lease));
    }
}

fn legacy_conflict(k: &mut Kernel, key: ProcessKey) -> usize {
    let core = &k.processes[key.slot].core;
    let agent = core.agent;
    let domain = core.domain;
    let object = k
        .fabric
        .alloc_object("legacy pending", 64, ObjectKind::Memory);
    assert!(k.fabric.place_object(object, 0x1000));
    k.fabric
        .grant(domain, object, 0, 16, Permissions::RW)
        .unwrap();
    let mut req = request(agent, domain, object, 0, Width::Byte, AccessKind::Write);
    req.length = 16;
    let tx = k.fabric.submit(req, Some(vec![9; 16]));
    k.fabric.advance(tx);
    k.fabric.advance(tx);
    assert_eq!(k.fabric.transactions[tx].state, TxState::Prepared);
    // Hostile bypass fixture: not newly admitted private-heap DMA authority.
    k.fabric.transactions[tx].physical_address = Some(0x1ff8);
    tx
}

#[test]
fn a235c_legacy_conflict_blocks_effects_and_readiness_but_not_stopped_cancellation() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    let (key, w) = worker(&mut k);
    let t = write(&mut k, a, 0, &[8]).unwrap();
    let lease = claim(&mut k, a, key, w);
    let tx = legacy_conflict(&mut k, key);
    rejects(&mut k, HeapError::Busy, |k| execute(k, t));
    cancel(&mut k, t).unwrap();
    assert_eq!(finish(&mut k, t).unwrap(), HeapWorkOutcome::Cancelled);
    assert_eq!(census(&mut k, a).unwrap().cpu, 0);
    assert!(!ready(&mut k, a, key, lease).unwrap());
    let bytes = k.fabric.memory.clone();
    k.fabric.advance(tx); // existing legacy precommit gate rejects the overlap
    assert_eq!(k.fabric.transactions[tx].state, TxState::Faulted);
    assert_eq!(k.fabric.memory, bytes);
    assert!(ready(&mut k, a, key, lease).unwrap());
}

#[test]
fn a235c_saturated_revision_does_not_make_a_cached_ready_result_valid() {
    let mut k = machine(0, 0);
    let a = allocation(&mut k, 64, true);
    let (key, w) = worker(&mut k);
    let lease = claim(&mut k, a, key, w);
    fixture::set_revision(&mut k.fabric.scoped_pointers, u64::MAX);
    assert!(ready(&mut k, a, key, lease).unwrap());
    legacy_conflict(&mut k, key);
    assert_eq!(k.fabric.scoped_pointers.revision(), u64::MAX);
    assert!(!ready(&mut k, a, key, lease).unwrap());
}

#[test]
fn a235c_backend_row_reuse_uses_new_operation_request_and_generation() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    let b = allocation(&mut k, 64, true);
    let old = write(&mut k, a, 0, &[77]).unwrap();
    let old_source = work(&k).checked_record(old).unwrap().source;
    execute(&mut k, old).unwrap();
    finish(&mut k, old).unwrap();
    let new = read(&mut k, b, 0, 1).unwrap();
    let new_source = work(&k).checked_record(new).unwrap().source;
    assert_eq!(old.row, new.row);
    assert!(new.operation > old.operation);
    assert_eq!(old_source.index, new_source.index);
    assert_eq!(new_source.generation, old_source.generation + 1);
    assert!(new_source.request > old_source.request);
    assert!(payload(&k, new).iter().all(|b| *b == 0));
    rejects(&mut k, HeapError::StaleWork, |k| execute(k, old));
    rejects(&mut k, HeapError::StaleWork, |k| cancel(k, old));
    rejects(&mut k, HeapError::StaleWork, |k| finish(k, old));
    validate(&mut k, new).unwrap();
}

#[test]
fn a235c_exhausted_source_generation_is_not_reset_on_consumption() {
    let mut k = machine(1, 1);
    let a = allocation(&mut k, 64, true);
    work_mut(&mut k).sources[0].next_generation = Some(u64::MAX);
    let t = read(&mut k, a, 0, 1).unwrap();
    cancel(&mut k, t).unwrap();
    finish(&mut k, t).unwrap();
    assert!(work(&k).sources[0].request.is_none());
    assert_eq!(work(&k).sources[0].next_generation, None);
    rejects(
        &mut k,
        HeapError::Capacity(Resource::BackendRequests),
        |k| read(k, a, 0, 1),
    );
}

#[test]
fn a235c_terminal_work_consumes_at_revision_exhaustion_without_reopening_admission() {
    for cancelled in [false, true] {
        let mut k = machine(1, 1);
        let a = allocation(&mut k, 64, true);
        let t = write(&mut k, a, 0, &[8]).unwrap();
        fixture::set_revision(&mut k.fabric.scoped_pointers, u64::MAX);
        if cancelled {
            cancel(&mut k, t).unwrap();
        } else {
            execute(&mut k, t).unwrap();
        }
        finish(&mut k, t).unwrap();
        assert_eq!(census(&mut k, a).unwrap().cpu, 0);
        assert_eq!(k.fabric.scoped_pointers.revision(), u64::MAX);
        rejects(&mut k, HeapError::StaleRevision, |k| read(k, a, 0, 1));
    }
}

#[test]
fn a235c_terminal_consumption_does_not_reset_exhausted_operation_or_request_ids() {
    for operation in [false, true] {
        let mut k = machine(1, 1);
        let a = allocation(&mut k, 64, true);
        if operation {
            work_mut(&mut k).next_operation = u64::MAX - 1;
        } else {
            work_mut(&mut k).next_request = Some(u64::MAX);
        }
        let t = read(&mut k, a, 0, 1).unwrap();
        execute(&mut k, t).unwrap();
        finish(&mut k, t).unwrap();
        rejects(&mut k, HeapError::Capacity(Resource::Identity), |k| {
            read(k, a, 0, 1)
        });
    }
}

#[test]
fn a235c_zero_backend_profile_can_observe_drained_unpublished_cleanup_without_release() {
    let mut k = Kernel::new(
        Fabric::with_private_heap_and_workers(0x10000, limits(), profile(), 1).unwrap(),
    );
    let a = allocation(&mut k, 64, false);
    let (key, w) = worker(&mut k);
    let start = base(&k, a);
    k.fabric.memory[start..start + 4096].fill(0xac);
    let lease = claim(&mut k, a, key, w);
    let charged = k.fabric.scoped_pointers.total_reserved_bytes();
    let before = snapshot(&k.fabric);
    assert_eq!(
        census(&mut k, a).unwrap(),
        HeapWorkCounts { cpu: 0, dma: 0 }
    );
    assert!(ready(&mut k, a, key, lease).unwrap());
    assert_eq!(snapshot(&k.fabric), before);
    assert_eq!(k.fabric.scoped_pointers.total_reserved_bytes(), charged);
    assert!(
        k.fabric.memory[start..start + 4096]
            .iter()
            .all(|b| *b == 0xac)
    );
    rejects(&mut k, HeapError::Busy, |k| {
        no_alloc(|| k.fabric.scoped_pointers.abort_heap(a.reservation))
    });
}
