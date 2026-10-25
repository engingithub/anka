//! Exact-context heap transport and one-use owned syscall replies.
use super::*;
use crate::anka64::scoped_pointers::{
    ScopedPointer,
    heap::{AllocationOwner, HeapError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeapEventPermit {
    owner: AllocationOwner,
    event: u64,
    number: u64,
}

impl Anka64Core {
    pub(crate) fn bind_heap_process(&mut self, key: ProcessKey) {
        self.heap_owner = Some(AllocationOwner {
            process: key,
            context: self.context_id,
            domain: self.domain,
        });
    }
    pub(crate) fn heap_owner(&self) -> Result<AllocationOwner, HeapError> {
        self.heap_owner
            .filter(|o| o.context == self.context_id && o.domain == self.domain)
            .ok_or(HeapError::Owner)
    }
    pub(crate) fn prepare_heap_event(
        &self,
        owner: AllocationOwner,
    ) -> Result<HeapEventPermit, HeapError> {
        let (words, _) = self.protected_syscall_image().ok_or(HeapError::Owner)?;
        let saved = self.saved_event_contexts.last().ok_or(HeapError::Owner)?;
        if self.heap_owner()? != owner
            || saved.event_id == 0
            || saved.result_consumed
            || saved.scalar_results.iter().any(Option::is_some)
            || !matches!(words[0], 21 | 22)
        {
            return Err(HeapError::Owner);
        }
        Ok(HeapEventPermit {
            owner,
            event: saved.event_id,
            number: words[0],
        })
    }
    pub(crate) fn valid_heap_event(&self, permit: HeapEventPermit, owner: AllocationOwner) -> bool {
        self.prepare_heap_event(owner).is_ok_and(|p| p == permit)
    }
    /// Only the exact prepared event can receive this reply. No scheduler or
    /// callback occurs between final validation, publication and this commit.
    pub(crate) fn commit_heap_event(
        &mut self,
        permit: HeapEventPermit,
        pointer: Option<ScopedPointer>,
        status: u64,
        malloc: bool,
    ) {
        assert!(self.valid_heap_event(permit, permit.owner));
        assert_eq!(permit.number, if malloc { 21 } else { 22 });
        assert!(malloc || pointer.is_none());
        let saved = self.saved_event_contexts.last_mut().unwrap();
        let image = saved.image.as_mut().unwrap();
        let words = pointer.map(|p| p.words()).unwrap_or([0, 0]);
        image.words[0] = words[0];
        image.words[1] = words[1];
        image.kinds[0] = pointer;
        if malloc {
            image.words[2] = status;
            image.words[3] = 0;
            image.kinds[1] = None;
        }
        saved.result_consumed = true;
    }
    pub(crate) fn check_application_pointer(
        &self,
        fabric: &Fabric,
        pointer: ScopedPointer,
    ) -> Result<(), PointerMachineError> {
        if fabric.scoped_pointers.is_heap_pointer(pointer) {
            fabric
                .authenticate_heap_token(
                    self.heap_owner().map_err(PointerMachineError::Heap)?,
                    self.agent,
                    pointer,
                )
                .map_err(PointerMachineError::Heap)
        } else {
            fabric
                .scoped_pointer_backing(pointer, self.domain)
                .map(|_| ())
        }
    }
    pub(super) fn add_application_pointer(
        &self,
        fabric: &Fabric,
        pointer: ScopedPointer,
        delta: i64,
    ) -> Result<ScopedPointer, PointerMachineError> {
        if fabric.scoped_pointers.is_heap_pointer(pointer) {
            fabric
                .scoped_pointers
                .add_heap_pointer(
                    pointer,
                    self.heap_owner().map_err(PointerMachineError::Heap)?,
                    delta,
                )
                .map_err(PointerMachineError::Heap)
        } else {
            fabric
                .scoped_pointers
                .add(pointer, self.domain.0, delta)
                .map_err(PointerMachineError::Pointer)
        }
    }
    pub(super) fn pointer_load_indirect(
        &mut self,
        fabric: &mut Fabric,
        dst: u8,
        base: u8,
        displacement: i64,
    ) -> Result<(), PointerMachineError> {
        let p = self
            .authenticated_pointer(fabric, base)?
            .ok_or(PointerMachineError::MissingKind)?;
        if fabric.scoped_pointers.is_heap_pointer(p) {
            Self::pointer_pair_index(dst)?;
            let p = self.add_application_pointer(fabric, p, displacement)?;
            let token = fabric
                .load_heap_pointer_cell(
                    self.heap_owner().map_err(PointerMachineError::Heap)?,
                    self.agent,
                    p,
                )
                .map_err(PointerMachineError::Heap)?;
            self.install_pointer(dst, token)
        } else {
            let address = self.pointer_address(fabric, base, displacement, false)?;
            self.pointer_load(fabric, dst, address)
        }
    }
    pub(super) fn pointer_store_indirect(
        &self,
        fabric: &mut Fabric,
        src: u8,
        base: u8,
        displacement: i64,
    ) -> Result<(), PointerMachineError> {
        let p = self
            .authenticated_pointer(fabric, base)?
            .ok_or(PointerMachineError::MissingKind)?;
        if fabric.scoped_pointers.is_heap_pointer(p) {
            let source = self.authenticated_pointer(fabric, src)?;
            let p = self.add_application_pointer(fabric, p, displacement)?;
            fabric
                .store_heap_pointer_cell(
                    self.heap_owner().map_err(PointerMachineError::Heap)?,
                    self.agent,
                    p,
                    source,
                )
                .map_err(PointerMachineError::Heap)
        } else {
            let address = self.pointer_address(fabric, base, displacement, true)?;
            self.pointer_store(fabric, src, address)
        }
    }
}
