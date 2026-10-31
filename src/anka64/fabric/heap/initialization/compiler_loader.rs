//! Trusted image overlay at FIRST private publication. Source and request are
//! never guest-writable; malloc's existing zero/RW reply path is unchanged.
use super::*;
use crate::anka64::os::CurrentHeapProcess;

#[derive(Debug, Clone, Copy)]
pub(crate) struct CompilerHeapRegion {
    pub(crate) pointer: ScopedPointer,
    pub(crate) words: [u64; 16],
}

fn rights(role: u64) -> Result<Permissions, HeapError> {
    match role {
        1 | 15 => Ok(Permissions::READ),
        2 | 3 | 16 => Ok(Permissions::RW),
        _ => Err(HeapError::Configuration),
    }
}

impl Fabric {
    pub(crate) fn describe_compiler_region(
        &self,
        current: &CurrentHeapProcess<'_>,
        snapshot: HeapInitialization,
        role: u64,
        valid_bytes: u64,
    ) -> Result<CompilerHeapRegion, HeapError> {
        let plan = self.check_initialization_snapshot(
            snapshot,
            current.owner(),
            self.scoped_pointers.revision(),
        )?;
        let rights = rights(role)?;
        if !snapshot.is_complete() || snapshot.version() == 0 || valid_bytes > plan.row.logical {
            return Err(HeapError::StaleInitialization);
        }
        let pointer = plan.registry.pointer();
        let pair = pointer.words();
        let account = self
            .scoped_pointers
            .heap_account(current.owner())
            .ok_or(HeapError::Owner)?;
        Ok(CompilerHeapRegion {
            pointer,
            words: [
                role,
                if rights == Permissions::READ { 1 } else { 3 },
                plan.row.object.0,
                plan.row.object_generation.0,
                pair[0],
                pair[1],
                plan.row.logical,
                valid_bytes,
                1,
                plan.row.logical,
                plan.row.extents.virtual_extent.base,
                plan.row.extents.physical.size,
                account.serial(),
                plan.row.reservation.incarnation(),
                0,
                0,
            ],
        })
    }

    /// Data and typed cells are checked before the first write. All fallible
    /// work precedes a single exclusive publication; no scheduler can see a
    /// partially constructed image. This does not reuse write_private_heap,
    /// whose arbitrary dirty staging writes still invalidate initialization.
    pub(crate) fn publish_compiler_region(
        &mut self,
        current: &CurrentHeapProcess<'_>,
        snapshot: HeapInitialization,
        role: u64,
        payload: &[u8],
        cells: &[(u64, ScopedPointer)],
    ) -> Result<CompilerHeapRegion, HeapError> {
        let owner = current.owner();
        let rights = rights(role)?;
        let region =
            self.describe_compiler_region(current, snapshot, role, payload.len() as u64)?;
        let mut plan =
            self.check_initialization_snapshot(snapshot, owner, self.scoped_pointers.revision())?;
        if payload.len() > 65528
            || cells.len() > 5
            || (role != 15 && !cells.is_empty())
            || (role == 15 && (payload.len() != 768 || cells.len() != 5))
            || (matches!(role, 2 | 3 | 16) && !payload.is_empty())
            || !self.agents.get(&current.agent()).is_some_and(|a| {
                a.domain == owner.domain
                    && matches!(a.kind, crate::anka64::state::AgentKind::Cpu(_))
            })
        {
            return Err(HeapError::Configuration);
        }
        let closure = self
            .scoped_pointers
            .prepare_attached_heap_closure(plan.row.reservation, owner)?;
        self.check_heap_cleanup_drain(&closure, plan.row.object)?;
        let mut shadow = [0usize; 5];
        for (i, &(offset, pointer)) in cells.iter().enumerate() {
            // Exactly one typed pair in each declared region record.
            if offset != 160 + i as u64 * 128 {
                return Err(HeapError::Size);
            }
            let span = self.checked_heap_backing_span(
                plan.row.logical,
                plan.row.extents,
                offset,
                16,
                true,
            )?;
            let start = usize::try_from(offset).map_err(|_| HeapError::Size)?;
            let pair = pointer.words();
            let mut words = [0u8; 16];
            words[..8].copy_from_slice(&pair[0].to_le_bytes());
            words[8..].copy_from_slice(&pair[1].to_le_bytes());
            if payload.get(start..start + 16) != Some(words.as_slice()) {
                return Err(HeapError::MissingKind);
            }
            if i == 3 {
                // The directory's self-reference becomes live in this SAME
                // commit. A different reserved token cannot use this exception.
                if pointer != region.pointer {
                    return Err(HeapError::MissingKind);
                }
            } else {
                self.checked_live_heap(owner, current.agent(), pointer)?;
            }
            shadow[i] = span.shadow.start;
        }
        plan.row.initialization_version = plan
            .row
            .initialization_version
            .checked_add(1)
            .ok_or(HeapError::Capacity(Resource::Identity))?;
        plan.row.planned_rights = rights;
        let slot = plan.registry.slot();
        let start = plan.row.extents.physical.base as usize;
        // Registry/layout preflight established backing containment. Remaining
        // padding stays zero, and every cell not listed here stays untyped.
        self.memory[start..start + payload.len()].copy_from_slice(payload);
        let heap = self.private_heap.as_mut().unwrap();
        for (i, &(_, pointer)) in cells.iter().enumerate() {
            heap.shadow[shadow[i]] = Some(pointer);
        }
        heap.rows[slot] = Some(plan.row);
        let pointer = self
            .scoped_pointers
            .commit_heap_image_publication(plan.registry, rights == Permissions::RW);
        debug_assert_eq!(pointer, region.pointer);
        Ok(region)
    }
}
