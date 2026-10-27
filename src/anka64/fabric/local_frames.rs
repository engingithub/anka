//! R1: preflight the complete new frame, initialize bytes/kinds, then issue.
use super::*;
use crate::anka64::core::PointerMachineError as E;
use crate::anka64::scoped_pointers::{
    LocalFrameBacking, PointerBacking, PointerError, Scope, ScopedPointer,
};

// Invalid ranges fail closed when considering potentially conflicting work.
fn overlaps(a: u64, n: u64, b: u64, m: u64) -> bool {
    if n == 0 || m == 0 {
        return false;
    }
    match (a.checked_add(n), b.checked_add(m)) {
        (Some(end_a), Some(end_b)) => a < end_b && b < end_a,
        _ => true,
    }
}

impl Fabric {
    pub(crate) fn issue_pointer_frame(
        &mut self,
        owner: u64,
        frame: MemoryRequest,
        address: u64,
        registrations: Vec<(MemoryRequest, u64, bool)>,
    ) -> Result<(Scope, Vec<ScopedPointer>), E> {
        let invalid = || E::Pointer(PointerError::InvalidRange);
        if owner == 0
            || frame.context.privilege != Privilege::User
            || frame.kind != AccessKind::Read
            || self.pointer_stack_objects.get(&frame.object) != Some(&(owner, frame.context.domain))
            || !self.agents.get(&frame.context.agent).is_some_and(|a| {
                a.domain == frame.context.domain && matches!(a.kind, AgentKind::Cpu(_))
            })
        {
            return Err(E::Pointer(PointerError::Domain));
        }
        if address % 16 != 0
            || frame.offset % 16 != 0
            || frame.length == 0
            || frame.length % 16 != 0
            || registrations.len() > 4096
        {
            return Err(invalid());
        }
        let end = address.checked_add(frame.length).ok_or_else(invalid)?;
        frame.offset.checked_add(frame.length).ok_or_else(invalid)?;
        // Padding also requires full READ/WRITE authority before it is cleared.
        let backing = self.checked_local_backing(&frame, true)?;
        let physical = self
            .translate(frame.object, frame.offset)
            .ok_or(E::Unmapped)?;
        let physical_end = physical.checked_add(frame.length).ok_or_else(invalid)?;
        if physical % 16 != 0
            || physical_end > self.memory.len() as u64
            || self.heap_pool_overlaps(physical, frame.length)
        {
            return Err(invalid());
        }
        self.scoped_pointers
            .preflight_frame(registrations.len())
            .map_err(E::Pointer)?;
        for (i, (local, at, writable)) in registrations.iter().enumerate() {
            if local.context.agent != frame.context.agent
                || local.context.domain != frame.context.domain
                || local.context.privilege != frame.context.privilege
                || local.kind != AccessKind::Read
                || local.object != frame.object
                || *at < address
                || at.checked_add(local.length).is_none_or(|n| n > end)
                || frame.offset.checked_add(*at - address) != Some(local.offset)
            {
                return Err(invalid());
            }
            let current = self.checked_local_backing(local, *writable)?;
            if current.generation != backing.generation {
                return Err(invalid());
            }
            if registrations[..i]
                .iter()
                .any(|(other, prior, _)| overlaps(*at, local.length, *prior, other.length))
            {
                return Err(invalid());
            }
        }
        self.preflight_local_frame_exclusion(&frame, physical)?;
        let mut pointers = Vec::new();
        pointers
            .try_reserve_exact(registrations.len())
            .map_err(|_| E::Pointer(PointerError::Exhausted))?;

        // Serialized commit. No allocation, callback, yield, or fallible
        // validation occurs after the first write. The registry is fixed-size.
        self.memory[physical as usize..physical_end as usize].fill(0);
        let placement = &self.placement;
        self.pointer_cells.retain(|(object, _, offset), _| {
            // Unplaced unrelated identities have no cells in this extent.
            let Some(cell) = placement
                .get(object)
                .and_then(|base| base.checked_add(*offset))
            else {
                return true;
            };
            !overlaps(physical, frame.length, cell, 16)
        });
        let scope = self
            .scoped_pointers
            .enter_scope_for(owner)
            .expect("reserved frame scope");
        self.scoped_pointers.bind_frame(
            scope,
            LocalFrameBacking {
                backing,
                length: frame.length,
            },
        );
        for (local, at, writable) in registrations {
            let pointer = self
                .scoped_pointers
                .register(scope, frame.context.domain.0, at, local.length, writable)
                .expect("complete serialized local preflight");
            self.scoped_pointers.bind_backing(
                pointer,
                PointerBacking {
                    object: local.object,
                    generation: backing.generation,
                    offset: local.offset,
                },
            );
            pointers.push(pointer);
        }
        Ok((scope, pointers))
    }

    fn preflight_local_frame_exclusion(
        &self,
        frame: &MemoryRequest,
        physical: u64,
    ) -> Result<(), E> {
        let denied = || E::Pointer(PointerError::Rights);
        // CPU-only private stack profile: a second registered agent in this
        // domain shares its grants, even if it currently has no pending request.
        if self
            .agents
            .iter()
            .any(|(id, a)| *id != frame.context.agent && a.domain == frame.context.domain)
            || self.domains.values().any(|d| {
                d.id != frame.context.domain
                    && d.capabilities.iter().any(|e| {
                        e.cap.object() == frame.object
                            && self.validate(&e.cap)
                            && overlaps(frame.offset, frame.length, e.cap.offset(), e.cap.length())
                    })
            })
        {
            return Err(denied());
        }
        // Alias object identities must not provide a second route to the same
        // bytes. Conservative rejection also covers an alias before export.
        if self.objects.values().any(|o| {
            o.id != frame.object
                && matches!(o.state, ObjectState::Active | ObjectState::Sealed)
                && self
                    .placement
                    .get(&o.id)
                    .is_some_and(|base| overlaps(physical, frame.length, *base, o.size))
        }) {
            return Err(denied());
        }
        for live in self
            .scoped_pointers
            .live_frame_backings()
            .chain(self.scoped_pointers.live_local_backings())
        {
            if (live.backing.object == frame.object
                && overlaps(frame.offset, frame.length, live.backing.offset, live.length))
                || self
                    .placement
                    .get(&live.backing.object)
                    .and_then(|b| b.checked_add(live.backing.offset))
                    .is_some_and(|at| overlaps(physical, frame.length, at, live.length))
            {
                return Err(denied());
            }
        }
        for tx in self
            .transactions
            .iter()
            .filter(|tx| !tx.state.is_terminal())
        {
            let r = &tx.request;
            if (r.object == frame.object
                && overlaps(frame.offset, frame.length, r.offset, r.length))
                || tx
                    .physical_address
                    .is_some_and(|at| overlaps(physical, frame.length, at, r.length))
                || self
                    .placement
                    .get(&r.object)
                    .and_then(|b| b.checked_add(r.offset))
                    .is_some_and(|at| overlaps(physical, frame.length, at, r.length))
            {
                return Err(denied());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
