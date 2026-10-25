//! TEST FIXTURES ONLY. This module is compiled only under #[cfg(test)].
//! Tests initialize real backing, then synthesize the not-yet-implemented
//! publication checkpoint. Passing these tests is not end-to-end malloc proof.
use super::*;

pub(crate) fn activate(t: &mut ScopedPointers, r: HeapReservation) -> ScopedPointer {
    let record = t.reservation_record(r).unwrap();
    assert!(record.ever_attached && !record.published);
    assert!(!t.account(record.owner).unwrap().closed);
    assert_eq!(t.slots[r.slot].state, SlotState::Reserved);
    assert!(!t.heap.cleanup[record.cleanup].unwrap().queued);
    let Record::Heap(record) = &mut t.slots[r.slot].record else {
        unreachable!()
    };
    record.published = true;
    t.slots[r.slot].state = SlotState::Live;
    t.heap.advance();
    token(r, 0)
}

pub(crate) fn token(r: HeapReservation, position: u64) -> ScopedPointer {
    ScopedPointer {
        slot: r.slot,
        generation: r.generation,
        position,
    }
}

pub(crate) fn at(p: ScopedPointer, position: u64) -> ScopedPointer {
    ScopedPointer { position, ..p }
}

pub(crate) fn set_revision(t: &mut ScopedPointers, revision: u64) {
    t.heap.revision = revision;
}

#[cfg(test)]
mod tests;
