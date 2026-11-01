//! ABI-2 publication: freeze actual loader provenance BEFORE execution, retain
//! charges, recheck current sealed inputs, and insert artifact+receipt together.
use super::*;
use super::retained::{CompilerCandidateError, CompilerCandidateHandle};
use crate::anka64::ankald::LinkedArtifactKey;
use crate::anka64::compiler_adapter::{RebuildAdmissionRole, RebuildPublicationAuthority};
use crate::anka64::scoped_pointers::heap::HeapReservation;
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublicationError {
    Authority, Epoch, Exhausted, Binding, NotReady, Storage,
    Heap(HeapError), Candidate(CompilerCandidateError),
}
impl From<HeapError> for PublicationError { fn from(e: HeapError) -> Self { Self::Heap(e) } }
impl From<CompilerCandidateError> for PublicationError { fn from(e: CompilerCandidateError) -> Self { Self::Candidate(e) } }

/// All keys belong to this Kernel's Fabric. Dependencies retain exact order.
/// Names alone confer nothing: freeze checks actual seals, grants and contents.
pub(crate) struct PublicationInputs {
    pub(crate) bundle: LinkedArtifactKey,
    pub(crate) source: LinkedArtifactKey,
    pub(crate) compiler: LinkedArtifactKey,
    pub(crate) preprocessor: LinkedArtifactKey,
    pub(crate) linker: LinkedArtifactKey,
    pub(crate) profile: LinkedArtifactKey,
    pub(crate) plan: LinkedArtifactKey,
    pub(crate) dependencies: Vec<LinkedArtifactKey>,
}
impl PublicationInputs {
    fn keys(&self) -> impl Iterator<Item=LinkedArtifactKey> + '_ {
        [self.bundle, self.source, self.compiler, self.preprocessor, self.linker,
            self.profile, self.plan].into_iter().chain(self.dependencies.iter().copied())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicationKey { reservation: HeapReservation, custodian: AllocationOwner }

pub(crate) struct FrozenInput {
    pub(crate) key: LinkedArtifactKey,
    pub(crate) bytes: Vec<u8>,
}
struct FrozenJob {
    key: PublicationKey,
    producer: AllocationOwner,
    context: CompilerReplyContext,
    role: RebuildAdmissionRole,
    expected_epoch: u64,
    charge: u64,
    inputs: Vec<FrozenInput>,
    admission: Vec<u64>,
    discarding: bool,
}
impl FrozenJob {
    fn discard_bytes(&mut self) {
        self.discarding = true;
        drop(std::mem::take(&mut self.inputs));
        drop(std::mem::take(&mut self.admission));
    }
}
struct Published {
    job: FrozenJob,
    reservation: HeapReservation,
    object: ObjectId,
    pointer: ScopedPointer,
    length: u64,
}
#[derive(Default)]
pub(crate) struct CompilerPublications {
    epoch: u64,
    #[cfg(test)]
    fail_before_commit: bool,
    jobs: BTreeMap<u64, FrozenJob>,
    records: BTreeMap<u64, Published>,
}

/// Borrowed receipt: exact immutable evidence, not execution authority. The heap
/// generation is the protected token's epoch, NOT a legacy object generation.
pub(crate) struct CompilerPublicationReceipt<'a> {
    pub(crate) epoch: u64,
    pub(crate) abi: u64,
    pub(crate) source_offset: u64,
    pub(crate) role: RebuildAdmissionRole,
    pub(crate) producer: AllocationOwner,
    pub(crate) custodian: AllocationOwner,
    pub(crate) context: CompilerReplyContext,
    pub(crate) object: ObjectId,
    pub(crate) heap_generation: u64,
    pub(crate) length: u64,
    pub(crate) permissions: Permissions,
    pub(crate) inputs: &'a [FrozenInput],
    pub(crate) admission: &'a [u64],
}

pub(crate) fn publication_profile() -> Vec<u8> {
    [2u64, 2, 0].into_iter().flat_map(u64::to_le_bytes).collect()
}

fn sealed_length(f: &Fabric, domain: DomainId, key: LinkedArtifactKey) -> Result<u64, PublicationError> {
    let object = f.objects.get(&key.object).ok_or(PublicationError::Binding)?;
    if object.state != ObjectState::Sealed || object.generation != key.generation
        || key.generation.0 == 0 || object.size == 0 || object.size > 1024*1024
        // Provenance includes the compiler that just executed. Its legitimate
        // FETCH history is required, not evidence that output was executed.
        // Keep the global quiescence guard; the compile-only no-FETCH guard
        // belongs to output capture, not to sealed tool/source dependencies.
        || !f.compiler_provenance_quiescent()
        || f.find_authorizing_cap(domain, key.object, 0, object.size, Permissions::READ)
            .is_none_or(|cap| cap.generation() != key.generation) {
        return Err(PublicationError::Binding);
    }
    Ok(object.size)
}
fn read_chunk(f: &mut Fabric, owner: AllocationOwner, agent: AgentId,
    key: LinkedArtifactKey, offset: u64, count: u64) -> Result<Vec<u8>, PublicationError>
{
    let length = sealed_length(f, owner.domain, key)?;
    if count == 0 || count > 4096 || offset.checked_add(count).is_none_or(|n| n > length) {
        return Err(PublicationError::Binding);
    }
    let bytes = f.execute_read(MemoryRequest {
        context: AccessContext { agent, domain: owner.domain, privilege: Privilege::User },
        object: key.object, offset, width: Width::Byte, length: count, kind: AccessKind::Read,
    }).map_err(|_| PublicationError::Binding)?;
    if bytes.len() as u64 != count { return Err(PublicationError::Binding); }
    Ok(bytes)
}
fn recheck(f: &mut Fabric, owner: AllocationOwner, agent: AgentId, inputs: &[FrozenInput])
    -> Result<(), PublicationError>
{
    for input in inputs {
        if sealed_length(f, owner.domain, input.key)? != input.bytes.len() as u64 {
            return Err(PublicationError::Binding);
        }
        for (i, expected) in input.bytes.chunks(4096).enumerate() {
            if read_chunk(f, owner, agent, input.key, (i*4096) as u64, expected.len() as u64)? != expected {
                return Err(PublicationError::Binding);
            }
        }
    }
    Ok(())
}

impl Kernel {
    pub(crate) fn compiler_publication_epoch(&self) -> u64 { self.compiler_publications.epoch }

    pub(crate) fn freeze_compiler_publication(&mut self, attempt: &mut CompilerOutputAttempt,
        inputs: &PublicationInputs, role: RebuildAdmissionRole, expected_epoch: u64,
        authority: Option<&RebuildPublicationAuthority>) -> Result<PublicationKey, PublicationError>
    {
        authority.ok_or(PublicationError::Authority)?;
        if expected_epoch != self.compiler_publications.epoch { return Err(PublicationError::Epoch); }
        self.compiler_publications.epoch.checked_add(1).ok_or(PublicationError::Exhausted)?;
        if attempt.publication.is_some() || inputs.dependencies.len() > 4096
            || role == RebuildAdmissionRole::LinkedImage { return Err(PublicationError::Binding); }
        let budget = attempt.budget.as_ref().ok_or(PublicationError::Binding)?;
        let context = budget.context();
        let plan_words = budget.publication_plan_words();
        let source = attempt.loaded_source.ok_or(PublicationError::Binding)?;
        if self.compiler_owner(attempt.owner.process).ok() != Some(attempt.owner) {
            return Err(PublicationError::Binding);
        }
        let (program, object, generation, _, _) = self.processes[attempt.owner.process.slot].core
            .compiler_publication_entry(&self.fabric).ok_or(PublicationError::Binding)?;
        if inputs.compiler != (LinkedArtifactKey { object, generation }) { return Err(PublicationError::Binding); }
        let words = program.frames.iter().try_fold(4usize, |n,f|
            n.checked_add(5)?.checked_add(f.exits.len())?.checked_add(f.locals.len().checked_mul(5)?))
            .ok_or(PublicationError::Storage)?;
        let (custodian, account) = self.compiler_candidate_account()?;
        let agent = self.processes[custodian.process.slot].core.agent;
        let total = inputs.keys().try_fold(0u64, |n,key|
            n.checked_add(sealed_length(&self.fabric, custodian.domain, key)?).ok_or(PublicationError::Storage))?;
        // Reserve snapshots, canonical admission, map/receipt descriptors and
        // one bounded READ scratch chunk before allocating any retained payload.
        let charge = total.checked_add((words as u64).checked_mul(8).ok_or(PublicationError::Storage)?)
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add((inputs.dependencies.len() as u64 + 7)*128 + 8192))
            .ok_or(PublicationError::Storage)?;
        let reservation = self.fabric.scoped_pointers.reserve_heap(account, charge, self.fabric.scoped_pointers.revision())?;
        let key = PublicationKey { reservation, custodian };
        // Install the charged obligation before fallible reads/allocations.
        self.compiler_publications.jobs.insert(reservation.incarnation(), FrozenJob {
            key, producer: attempt.owner, context, role, expected_epoch, charge,
            inputs: Vec::new(), admission: Vec::new(), discarding: false,
        });
        let result = (|| -> Result<(), PublicationError> {
            let job = self.compiler_publications.jobs.get_mut(&reservation.incarnation()).unwrap();
            job.inputs.try_reserve_exact(inputs.dependencies.len()+7).map_err(|_| PublicationError::Storage)?;
            for input in inputs.keys() {
                let length = sealed_length(&self.fabric, custodian.domain, input)? as usize;
                let mut snapshot = Vec::new();
                snapshot.try_reserve_exact(length).map_err(|_| PublicationError::Storage)?;
                for offset in (0..length).step_by(4096) {
                    snapshot.extend(read_chunk(&mut self.fabric, custodian, agent, input,
                        offset as u64, (length-offset).min(4096) as u64)?);
                }
                job.inputs.push(FrozenInput { key: input, bytes: snapshot });
            }
            if job.inputs[1].bytes.len() as u64 != context.source_length()
                || job.inputs[5].bytes != publication_profile()
                || !job.inputs[6].bytes.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).eq(plan_words)
                || job.inputs[6].bytes.len() != 22*8 { return Err(PublicationError::Binding); }
            for (i, expected) in job.inputs[1].bytes.chunks(4096).enumerate() {
                let token = self.fabric.scoped_pointers.add_heap_pointer(source, attempt.owner, (i*4096) as i64)?;
                let mut bytes = [0u8;4096];
                self.fabric.read_heap_bytes(attempt.owner, attempt.agent, token, &mut bytes[..expected.len()])?;
                if &bytes[..expected.len()] != expected { return Err(PublicationError::Binding); }
            }
            let (program, _, _, offset, base) = self.processes[attempt.owner.process.slot].core
                .compiler_publication_entry(&self.fabric).ok_or(PublicationError::Binding)?;
            let end = offset.checked_add(program.code.len() as u64).ok_or(PublicationError::Binding)?;
            if job.inputs[2].bytes.get(offset as usize..end as usize) != Some(program.code.as_slice()) {
                return Err(PublicationError::Binding);
            }
            job.admission.try_reserve_exact(words).map_err(|_| PublicationError::Storage)?;
            job.admission.extend([base,offset,program.code.len() as u64,program.frames.len() as u64]);
            for f in &program.frames {
                job.admission.extend([f.entry,f.end,f.size,f.exits.len() as u64,f.locals.len() as u64]);
                job.admission.extend(f.exits.iter().copied());
                for l in &f.locals { job.admission.extend([l.offset,l.length,l.alignment,u64::from(l.writable),u64::from(l.pointer_slot)]); }
            }
            Ok(())
        })();
        if let Err(error) = result { let _ = self.cancel_compiler_publication(key); return Err(error); }
        attempt.publication = Some(key);
        Ok(key)
    }

    pub(crate) fn cancel_compiler_publication(&mut self, key: PublicationKey) -> Result<(), PublicationError> {
        let job = self.compiler_publications.jobs.get_mut(&key.reservation.incarnation())
            .filter(|j| j.key == key).ok_or(PublicationError::Binding)?;
        job.discard_bytes();
        self.fabric.scoped_pointers.abort_heap(key.reservation)?;
        self.compiler_publications.jobs.remove(&key.reservation.incarnation());
        Ok(())
    }

    /// pub108_refresh: reauthorize a ready candidate after another client has
    /// committed. No record is published, overwritten or refunded by refresh.
    pub(crate) fn refresh_compiler_publication_epoch(&mut self, handle:&CompilerCandidateHandle,
        expected_old:u64, authority:Option<&RebuildPublicationAuthority>) -> Result<u64,PublicationError>
    {
        authority.ok_or(PublicationError::Authority)?;
        let epoch=self.compiler_publications.epoch;
        if expected_old>epoch {return Err(PublicationError::Epoch);}
        epoch.checked_add(1).ok_or(PublicationError::Exhausted)?;
        let view=self.compiler_candidate(handle)?.ok_or(PublicationError::NotReady)?;
        let key=view.publication.ok_or(PublicationError::Binding)?;
        let job=self.compiler_publications.jobs.get(&key.reservation.incarnation())
            .filter(|j| j.key==key && !j.discarding && j.producer==view.producer
                && j.context==view.context && j.role==view.role && j.expected_epoch==expected_old)
            .ok_or(PublicationError::Binding)?;
        if self.compiler_candidate_custodian()?!=key.custodian {return Err(PublicationError::Binding);}
        let plan=self.fabric.scoped_pointers.prepare_heap_attachment(key.reservation,key.custodian,
            self.fabric.scoped_pointers.revision())?;
        if plan.logical()!=job.charge {return Err(PublicationError::Binding);}
        let agent=self.processes[key.custodian.process.slot].core.agent;
        recheck(&mut self.fabric,key.custodian,agent,&job.inputs)?;
        self.compiler_publications.jobs.get_mut(&key.reservation.incarnation()).unwrap().expected_epoch=epoch;
        Ok(epoch)
    }

    pub(crate) fn publish_compiler_candidate(&mut self, handle: &CompilerCandidateHandle,
        expected_epoch: u64, authority: Option<&RebuildPublicationAuthority>) -> Result<u64, PublicationError>
    {
        authority.ok_or(PublicationError::Authority)?;
        if self.compiler_publications.epoch != expected_epoch { return Err(PublicationError::Epoch); }
        let epoch = expected_epoch.checked_add(1).ok_or(PublicationError::Exhausted)?;
        let view = self.compiler_candidate(handle)?.ok_or(PublicationError::NotReady)?;
        let key = view.publication.ok_or(PublicationError::Binding)?;
        let length = view.bytes.len() as u64;
        let job = self.compiler_publications.jobs.get(&key.reservation.incarnation())
            .filter(|j| j.key == key && !j.discarding && j.producer == view.producer
                && j.context == view.context && j.role == view.role && j.expected_epoch == expected_epoch)
            .ok_or(PublicationError::Binding)?;
        if self.compiler_candidate_custodian()? != key.custodian { return Err(PublicationError::Binding); }
        let plan = self.fabric.scoped_pointers.prepare_heap_attachment(key.reservation, key.custodian,
            self.fabric.scoped_pointers.revision())?;
        if plan.logical() != job.charge { return Err(PublicationError::Binding); }
        let agent = self.processes[key.custodian.process.slot].core.agent;
        recheck(&mut self.fabric, key.custodian, agent, &job.inputs)?;
        let (_, account) = self.compiler_candidate_account()?;
        let reservation = self.fabric.scoped_pointers.reserve_heap(account, length, self.fabric.scoped_pointers.revision())?;
        let object = match self.fabric.attach_private_heap(reservation, key.custodian, self.fabric.scoped_pointers.revision()) {
            Ok(object) => object,
            Err(error) => { let _ = self.fabric.scoped_pointers.abort_heap(reservation); return Err(error.into()); }
        };
        let result = (|| -> Result<ScopedPointer, PublicationError> {
            let mut init = self.fabric.private_heap_initialization(reservation, key.custodian, object,
                self.fabric.scoped_pointers.revision())?;
            while !init.is_complete() {
                init = self.fabric.initialize_private_heap_chunk(init, key.custodian,
                    (init.rounded_bytes()-init.initialized_bytes()).min(4096), self.fabric.scoped_pointers.revision())?;
            }
            let current = CurrentHeapProcess::from_processes(&self.processes, key.custodian.process)
                .ok_or(PublicationError::Binding)?;
            let bytes = &self.compiler_candidates.get(handle)?.bytes;
            let (actual, pointer) = self.fabric.publish_compiler_artifact(&current, init, bytes)?;
            if actual != object { return Err(PublicationError::Binding); }
            #[cfg(test)]
            if self.compiler_publications.fail_before_commit { return Err(PublicationError::Storage); }
            // Still no visibility. Destroy/refund private capture before commit;
            // artifact + frozen receipt charges remain independently retained.
            self.discard_compiler_candidate(handle)?;
            Ok(pointer)
        })();
        let pointer = match result {
            Ok(pointer) => pointer,
            Err(error) => { let _ = self.fabric.close_attached_heap(reservation, key.custodian, object); return Err(error); }
        };
        let job = self.compiler_publications.jobs.remove(&key.reservation.incarnation()).unwrap();
        // Single visibility point, followed only by the nonwrapping epoch update.
        self.compiler_publications.records.insert(epoch, Published { job, reservation, object, pointer, length });
        self.compiler_publications.epoch = epoch;
        Ok(epoch)
    }

    pub(crate) fn compiler_publication_receipt(&self, epoch: u64) -> Option<CompilerPublicationReceipt<'_>> {
        let r = self.compiler_publications.records.get(&epoch)?;
        if r.job.discarding || self.compiler_candidate_custodian().ok()? != r.job.key.custodian { return None; }
        let agent = self.processes[r.job.key.custodian.process.slot].core.agent;
        self.fabric.authenticate_heap_token(r.job.key.custodian, agent, r.pointer).ok()?;
        self.fabric.scoped_pointers.prepare_heap_attachment(r.job.key.reservation, r.job.key.custodian,
            self.fabric.scoped_pointers.revision()).ok()?;
        Some(CompilerPublicationReceipt { epoch, abi:2, source_offset:0, role:r.job.role,
            producer:r.job.producer, custodian:r.job.key.custodian, context:r.job.context,
            object:r.object, heap_generation:r.pointer.words()[0]>>32, length:r.length,
            permissions:Permissions::READ, inputs:&r.job.inputs, admission:&r.job.admission })
    }

    pub(crate) fn read_compiler_publication(&self, epoch: u64, offset: u64, bytes: &mut [u8])
        -> Result<(), PublicationError>
    {
        let receipt = self.compiler_publication_receipt(epoch).ok_or(PublicationError::Binding)?;
        if bytes.len() > 4096 || offset.checked_add(bytes.len() as u64).is_none_or(|n|n>receipt.length) {
            return Err(PublicationError::Binding);
        }
        let r = &self.compiler_publications.records[&epoch];
        let pointer = self.fabric.scoped_pointers.add_heap_pointer(r.pointer, r.job.key.custodian,
            i64::try_from(offset).map_err(|_| PublicationError::Binding)?)?;
        let agent = self.processes[r.job.key.custodian.process.slot].core.agent;
        self.fabric.read_heap_bytes(r.job.key.custodian, agent, pointer, bytes)?;
        Ok(())
    }

    fn discard_publication_storage(&mut self, owner: Option<AllocationOwner>) -> bool {
        let fabric = &mut self.fabric;
        self.compiler_publications.jobs.retain(|_, j| {
            if owner.is_some_and(|o|o!=j.key.custodian) { return true; }
            j.discard_bytes(); fabric.scoped_pointers.abort_heap(j.key.reservation).is_err()
        });
        self.compiler_publications.records.retain(|_, r| {
            if owner.is_some_and(|o|o!=r.job.key.custodian) { return true; }
            r.job.discard_bytes();
            if fabric.close_attached_heap(r.reservation,r.job.key.custodian,r.object).is_err() { return true; }
            fabric.scoped_pointers.abort_heap(r.job.key.reservation).is_err()
        });
        self.compiler_publications.jobs.is_empty() && self.compiler_publications.records.is_empty()
    }
    pub(crate) fn discard_compiler_publications_owned_by(&mut self, owner: AllocationOwner) {
        self.discard_publication_storage(Some(owner));
    }
    pub(crate) fn discard_all_compiler_publications(&mut self) -> bool { self.discard_publication_storage(None) }
}

#[cfg(test)]
pub(super) mod tests;
