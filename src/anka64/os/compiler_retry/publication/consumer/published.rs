//! In-memory linked artifact/receipt commit. Never an executable grant.
use super::*;
use crate::anka64::scoped_pointers::heap::HeapReservation;
mod execution;
pub(crate) use execution::LinkedCompilerRunReport;

pub(crate) struct PublishedCompilerLink {
    owner: AllocationOwner,
    stage: Option<HostStorageReservation>,
    image_charge: Option<HostStorageReservation>,
    heap: Option<HeapReservation>,
    object: ObjectId,
    pointer: ScopedPointer,
    epochs: Vec<u64>,
    modules: Vec<ValidatedPointerModule>,
    linker: Vec<u8>,
    profile: ApplicationLinkProfile,
    image: Option<AnkaldLinkedImage>,
    discarding: bool,
}

/// Current, borrowed evidence. Object IDs and heap generations are separate;
/// neither this receipt nor its bytes authorize application execution.
pub(crate) struct LinkedCompilerReceipt<'a> {
    pub(crate) epoch: u64,
    pub(crate) role: RebuildAdmissionRole,
    pub(crate) owner: AllocationOwner,
    pub(crate) object: ObjectId,
    pub(crate) heap_generation: u64,
    pub(crate) permissions: Permissions,
    pub(crate) profile: ApplicationLinkProfile,
    pub(crate) dependencies: &'a [u64],
    pub(crate) image: &'a AnkaldLinkedImage,
}

impl CompilerLinkedOutput<'_> {
    /// Transfer charged custody without cloning bytes. Rejection preserves all
    /// input/prior publications; this private linked result is dropped. Retry
    /// relinks the still-current modules. No partial receipt becomes visible.
    pub(crate) fn publish(mut self, expected_epoch:u64,
        authority:Option<&RebuildPublicationAuthority>) -> Result<u64,CompilerLinkError>
    {
        authority.ok_or(CompilerLinkError::Authority)?;
        let g=&mut self.inputs;
        if g.kernel.compiler_publications.epoch!=expected_epoch {
            return Err(PublicationError::Epoch.into());
        }
        let epoch=expected_epoch.checked_add(1).ok_or(PublicationError::Exhausted)?;
        if g.kernel.compiler_candidate_custodian()?!=g.owner {
            return Err(CompilerLinkError::Binding);
        }
        for &e in &g.epochs {g.kernel.recheck_link_publication(e)?;}
        for r in [g.reservation,g.image_reservation] {
            g.kernel.fabric.scoped_pointers.check_host_storage(r.ok_or(CompilerLinkError::Binding)?,
                g.owner,g.kernel.fabric.scoped_pointers.revision())?;
        }
        let image=g.image.as_ref().ok_or(CompilerLinkError::Binding)?;
        ankald::validate_application_link_result(&g.modules,image,g.profile).map_err(CompilerLinkError::Link)?;
        let length=image.bytes.len() as u64;
        let (_,account)=g.kernel.compiler_candidate_account()?;
        let reservation=g.kernel.fabric.scoped_pointers.reserve_heap(account,length,
            g.kernel.fabric.scoped_pointers.revision())?;
        let object=match g.kernel.fabric.attach_private_heap(reservation,g.owner,
            g.kernel.fabric.scoped_pointers.revision()) {
            Ok(object)=>object,
            Err(error)=>{let _=g.kernel.fabric.scoped_pointers.abort_heap(reservation);return Err(error.into());}
        };
        let result=(|| -> Result<ScopedPointer,CompilerLinkError> {
            let mut init=g.kernel.fabric.private_heap_initialization(reservation,g.owner,object,
                g.kernel.fabric.scoped_pointers.revision())?;
            while !init.is_complete() {
                init=g.kernel.fabric.initialize_private_heap_chunk(init,g.owner,
                    (init.rounded_bytes()-init.initialized_bytes()).min(4096),
                    g.kernel.fabric.scoped_pointers.revision())?;
            }
            let current=CurrentHeapProcess::from_processes(&g.kernel.processes,g.owner.process)
                .ok_or(CompilerLinkError::Binding)?;
            let (actual,pointer)=g.kernel.fabric.publish_compiler_artifact(&current,init,
                &g.image.as_ref().ok_or(CompilerLinkError::Binding)?.bytes)?;
            if actual!=object {return Err(CompilerLinkError::Binding);}
            #[cfg(test)]
            if g.kernel.compiler_publications.fail_before_commit {return Err(CompilerLinkError::Storage);}
            Ok(pointer)
        })();
        let pointer=match result {
            Ok(pointer)=>pointer,
            Err(error)=>{
                let _=g.kernel.fabric.close_attached_heap(reservation,g.owner,object);
                return Err(error);
            }
        };
        // No fallible work after moving custody. Host image/staging charges
        // remain live beside the independently charged READ-only heap artifact.
        let record=PublishedCompilerLink {owner:g.owner,stage:g.reservation.take(),
            image_charge:g.image_reservation.take(),heap:Some(reservation),object,pointer,
            epochs:std::mem::take(&mut g.epochs),modules:std::mem::take(&mut g.modules),
            linker:std::mem::take(&mut g.linker),profile:g.profile,image:g.image.take(),discarding:false};
        g.kernel.compiler_publications.links.insert(epoch,record);
        g.kernel.compiler_publications.epoch=epoch;
        Ok(epoch)
    }
}

impl Kernel {
    fn validate_linked_compiler_publication(&mut self,epoch:u64)->Result<(),CompilerLinkError> {
        let n=self.compiler_publications.links.get(&epoch).ok_or(CompilerLinkError::Binding)?.epochs.len();
        if n==0 || n>4096 {return Err(CompilerLinkError::Binding);}
        for index in 0..n {
            let e=self.compiler_publications.links[&epoch].epochs[index];
            self.recheck_link_publication(e)?;
        }
        let r=&self.compiler_publications.links[&epoch];
        if r.discarding || self.compiler_candidate_custodian()?!=r.owner || r.heap.is_none()
            || r.modules.len()!=n {return Err(CompilerLinkError::Binding);}
        let image=r.image.as_ref().ok_or(CompilerLinkError::Binding)?;
        for reservation in [r.stage,r.image_charge] {
            self.fabric.scoped_pointers.check_host_storage(reservation.ok_or(CompilerLinkError::Binding)?,
                r.owner,self.fabric.scoped_pointers.revision())?;
        }
        let agent=self.processes[r.owner.process.slot].core.agent;
        self.fabric.authenticate_heap_token(r.owner,agent,r.pointer)?;
        let mut scratch=[0u8;4096];
        for (&e,module) in r.epochs.iter().zip(&r.modules) {
            let source=self.compiler_publication_receipt(e).ok_or(CompilerLinkError::Binding)?;
            if source.role!=RebuildAdmissionRole::RelocatableModule
                || source.length!=module.bytes().len() as u64
                || source.inputs.get(4).is_none_or(|i|i.bytes!=r.linker) {
                return Err(CompilerLinkError::Binding);
            }
            for (i,expected) in module.bytes().chunks(4096).enumerate() {
                self.read_compiler_publication(e,(i*4096) as u64,&mut scratch[..expected.len()])?;
                if &scratch[..expected.len()]!=expected {return Err(CompilerLinkError::Binding);}
            }
        }
        // Compare authentic immutable heap storage with the retained image.
        // This is a data read, not a legacy physical-memory bypass.
        for (i,expected) in image.bytes.chunks(4096).enumerate() {
            let pointer=self.fabric.scoped_pointers.add_heap_pointer(r.pointer,r.owner,(i*4096)as i64)?;
            self.fabric.read_heap_bytes(r.owner,agent,pointer,&mut scratch[..expected.len()])?;
            if &scratch[..expected.len()]!=expected {return Err(CompilerLinkError::Binding);}
        }
        // Profile and complete image geometry remain bound to typed inputs.
        ankald::validate_application_link_result(&r.modules,image,r.profile).map_err(CompilerLinkError::Link)
    }

    pub(crate) fn linked_compiler_receipt(&mut self,epoch:u64)
        -> Result<LinkedCompilerReceipt<'_>,CompilerLinkError>
    {
        self.validate_linked_compiler_publication(epoch)?;
        let r=&self.compiler_publications.links[&epoch];
        Ok(LinkedCompilerReceipt {epoch,role:RebuildAdmissionRole::LinkedImage,owner:r.owner,
            object:r.object,heap_generation:r.pointer.words()[0]>>32,permissions:Permissions::READ,
            profile:r.profile,dependencies:&r.epochs,image:r.image.as_ref().unwrap()})
    }

    pub(crate) fn read_linked_compiler_publication(&mut self,epoch:u64,offset:u64,bytes:&mut[u8])
        ->Result<(),CompilerLinkError>
    {
        if bytes.len()>4096 {return Err(CompilerLinkError::Binding);}
        self.validate_linked_compiler_publication(epoch)?;
        let r=&self.compiler_publications.links[&epoch];
        let length=r.image.as_ref().unwrap().bytes.len() as u64;
        if offset.checked_add(bytes.len()as u64).is_none_or(|end|end>length) {
            return Err(CompilerLinkError::Binding);
        }
        let pointer=self.fabric.scoped_pointers.add_heap_pointer(r.pointer,r.owner,
            i64::try_from(offset).map_err(|_|CompilerLinkError::Binding)?)?;
        let agent=self.processes[r.owner.process.slot].core.agent;
        self.fabric.read_heap_bytes(r.owner,agent,pointer,bytes)?;
        Ok(())
    }

    pub(crate) fn discard_linked_compiler_publication(&mut self,epoch:u64,
        authority:Option<&RebuildPublicationAuthority>)->Result<(),CompilerLinkError>
    {
        authority.ok_or(CompilerLinkError::Authority)?;
        let r=self.compiler_publications.links.get_mut(&epoch).ok_or(CompilerLinkError::Binding)?;
        discard_record(&mut self.fabric,r)?;
        self.compiler_publications.links.remove(&epoch);
        Ok(())
    }

    pub(crate) fn discard_compiler_links_owned_by(&mut self,owner:Option<AllocationOwner>)->bool {
        let fabric=&mut self.fabric;
        self.compiler_publications.links.retain(|_,r| {
            if owner.is_some_and(|o|o!=r.owner) {return true;}
            discard_record(fabric,r).is_err()
        });
        self.compiler_publications.links.is_empty()
    }
}

fn discard_record(fabric:&mut Fabric,r:&mut PublishedCompilerLink)->Result<(),HeapError> {
    r.discarding=true;
    drop(r.image.take());drop(std::mem::take(&mut r.modules));
    drop(std::mem::take(&mut r.linker));drop(std::mem::take(&mut r.epochs));
    // Successful closure transfers physical reclamation to existing workers;
    // it does not refund the payload before drainage and scrub.
    if let Some(heap)=r.heap {
        fabric.close_attached_heap(heap,r.owner,r.object)?;r.heap=None;
    }
    if let Some(charge)=r.image_charge {
        fabric.scoped_pointers.release_host_storage(charge)?;r.image_charge=None;
    }
    if let Some(charge)=r.stage {
        fabric.scoped_pointers.release_host_storage(charge)?;r.stage=None;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anka64::os::compiler_retry::tests::machine_with_limits;
    use crate::anka64::os::compiler_retry::capture::tests::aom;
    use super::super::tests::{published,charge};

    fn fixture()->(Kernel,u64) {
        fixture_bytes(aom(false,1))
    }
    pub(super) fn fixture_bytes(bytes:Vec<u8>)->(Kernel,u64) {
        let mut k=machine_with_limits(256*1024*1024,512*1024*1024);
        let linker=&crate::anka64::ankald_tests::ankald_image().bytes;
        let owner=k.compiler_candidate_custodian().unwrap();
        let object=k.fabric.alloc_object("linked-publication-tool",linker.len()as u64,ObjectKind::Memory);
        k.fabric.place_object(object,0xc0000);
        assert!(k.fabric.initialize_object(object,0,linker));assert!(k.fabric.seal_object(object));
        k.fabric.grant(owner.domain,object,0,linker.len()as u64,Permissions::READ).unwrap();
        let key=LinkedArtifactKey{object,generation:k.fabric.objects[&object].generation};
        let(e,_)=published(&mut k,bytes,Some(key));(k,e)
    }
    pub(super) fn link(k:&mut Kernel,module:u64)->CompilerLinkedOutput<'_> {
        k.borrow_compiler_publication_modules(&[module],ApplicationLinkProfile::Standard).unwrap()
            .link(Some(&DeveloperExecutionAuthority::provision())).unwrap()
    }
    fn drain(k:&mut Kernel) {
        for _ in 0..2000 {if !k.advance_heap_cleanup() {return;}}
        panic!("linked artifact cleanup did not finish");
    }
    #[test]
    fn c4_linked_publication_keeps_exact_read_only_image_and_ordered_receipt() {
        let(mut k,m)=fixture();let held=charge(&k);let auth=RebuildPublicationAuthority::provision();
        let linked=link(&mut k,m);let expected=linked.image().clone();
        let e=linked.publish(m,Some(&auth)).unwrap();assert_eq!(e,m+1);
        let r=k.linked_compiler_receipt(e).unwrap();
        assert_eq!(r.epoch,e);assert_eq!(r.role,RebuildAdmissionRole::LinkedImage);
        assert_eq!(r.permissions,Permissions::READ);assert_eq!(r.profile,ApplicationLinkProfile::Standard);
        assert_eq!(r.dependencies,[m]);assert_eq!(r.image,&expected);assert!(r.heap_generation>0);
        let (owner,object)=(r.owner,r.object);
        let token=k.compiler_publications.links[&e].pointer;
        let agent=k.processes[owner.process.slot].core.agent;
        assert!(k.fabric.write_heap_bytes(owner,agent,token,&[1]).is_err());
        assert_eq!(k.compiler_publications.links[&e].object,object);
        let mut bytes=vec![0;expected.bytes.len()];
        for(i,chunk)in bytes.chunks_mut(4096).enumerate() {
            k.read_linked_compiler_publication(e,(i*4096)as u64,chunk).unwrap();
        }
        assert_eq!(bytes,expected.bytes);assert!(charge(&k)>held);
        assert!(k.read_linked_compiler_publication(e,expected.bytes.len()as u64,&mut[0]).is_err());
        assert!(k.read_linked_compiler_publication(e,0,&mut[0;4097]).is_err());
        assert!(k.compiler_publication_receipt(e).is_none(),"linked image is not a module");
        assert!(k.borrow_compiler_publication_modules(&[e],ApplicationLinkProfile::Standard).is_err());
        assert!(k.compiler_publication_receipt(m).is_some());
    }
    #[test]
    fn c4_linked_publication_denies_missing_authority_stale_and_exhausted_epoch() {
        let(mut k,m)=fixture();let held=charge(&k);let auth=RebuildPublicationAuthority::provision();
        assert!(matches!(link(&mut k,m).publish(m,None),Err(CompilerLinkError::Authority)));
        assert_eq!(charge(&k),held);
        assert!(matches!(link(&mut k,m).publish(0,Some(&auth)),
            Err(CompilerLinkError::Publication(PublicationError::Epoch))));
        assert_eq!(charge(&k),held);assert_eq!(k.compiler_publication_epoch(),m);
        k.compiler_publications.epoch=u64::MAX;
        assert!(matches!(link(&mut k,m).publish(u64::MAX,Some(&auth)),
            Err(CompilerLinkError::Publication(PublicationError::Exhausted))));
        assert!(k.compiler_publications.links.is_empty());assert_eq!(charge(&k),held);
    }
    #[test]
    fn c4_linked_publication_changed_provenance_denies_existing_receipt_and_read() {
        let(mut k,m)=fixture();let auth=RebuildPublicationAuthority::provision();
        let e=link(&mut k,m).publish(m,Some(&auth)).unwrap();
        let key=k.compiler_publications.records[&m].job.inputs[1].key;
        let at=k.fabric.translate(key.object,0).unwrap();let old=k.fabric.read_physical(at,1)[0];
        k.fabric.write_physical(at,&[old^1]);
        assert!(k.linked_compiler_receipt(e).is_err());
        assert!(k.read_linked_compiler_publication(e,0,&mut[0;8]).is_err());
        k.fabric.write_physical(at,&[old]);assert!(k.linked_compiler_receipt(e).is_ok());
        let owner=k.compiler_candidate_custodian().unwrap();
        k.fabric.domains.get_mut(&owner.domain).unwrap().capabilities.retain(|c|c.cap.object()!=key.object);
        assert!(k.linked_compiler_receipt(e).is_err());
    }
    #[test]
    fn c4_linked_publication_failure_after_seal_retains_cleanup_without_visibility() {
        let(mut k,m)=fixture();let auth=RebuildPublicationAuthority::provision();let held=charge(&k);
        k.compiler_publications.fail_before_commit=true;
        assert!(matches!(link(&mut k,m).publish(m,Some(&auth)),Err(CompilerLinkError::Storage)));
        assert_eq!(k.compiler_publication_epoch(),m);assert!(k.compiler_publications.links.is_empty());
        assert!(charge(&k)>held,"sealed private heap must remain charged until worker cleanup");
        k.compiler_publications.fail_before_commit=false;drain(&mut k);
        assert_eq!(charge(&k),held);assert!(k.compiler_publication_receipt(m).is_some());
        assert!(link(&mut k,m).publish(m,Some(&auth)).is_ok());
    }
    #[test]
    fn c4_linked_publication_discard_releases_only_link_and_rejects_old_token() {
        let(mut k,m)=fixture();let auth=RebuildPublicationAuthority::provision();let held=charge(&k);
        let e=link(&mut k,m).publish(m,Some(&auth)).unwrap();
        let r=&k.compiler_publications.links[&e];let(owner,pointer)=(r.owner,r.pointer);
        let agent=k.processes[owner.process.slot].core.agent;
        assert!(k.discard_linked_compiler_publication(e,None).is_err());
        assert!(k.linked_compiler_receipt(e).is_ok());
        k.discard_linked_compiler_publication(e,Some(&auth)).unwrap();
        assert!(k.fabric.authenticate_heap_token(owner,agent,pointer).is_err());
        assert!(k.linked_compiler_receipt(e).is_err());drain(&mut k);assert_eq!(charge(&k),held);
        assert!(k.compiler_publication_receipt(m).is_some());
        let next=link(&mut k,m).publish(e,Some(&auth)).unwrap();assert_eq!(next,e+1);
        assert!(k.fabric.authenticate_heap_token(owner,agent,pointer).is_err());
        assert!(k.linked_compiler_receipt(next).is_ok());
    }
    #[test]
    fn c4_linked_publication_shutdown_destroys_records_before_custodian_teardown() {
        let(mut k,m)=fixture();let auth=RebuildPublicationAuthority::provision();
        let e=link(&mut k,m).publish(m,Some(&auth)).unwrap();
        let owner=k.compiler_candidate_custodian().unwrap();
        k.stop_heap_service();
        assert!(k.compiler_publications.links.is_empty());assert!(k.compiler_publications.records.is_empty());
        assert!(k.fabric.scoped_pointers.heap_account(owner).is_none());
        assert!(k.linked_compiler_receipt(e).is_err());
    }
    #[test]
    fn c4_linked_publication_quota_denial_keeps_source_and_refunds_only_private_stage() {
        let(mut k,m)=fixture();let auth=RebuildPublicationAuthority::provision();let held=charge(&k);
        let mut output=link(&mut k,m);
        let (_,account)=output.inputs.kernel.compiler_candidate_account().unwrap();
        let current=charge(output.inputs.kernel);
        let filler=output.inputs.kernel.fabric.scoped_pointers.reserve_host_storage(account,
            256*1024*1024-current,output.inputs.kernel.fabric.scoped_pointers.revision()).unwrap();
        assert!(matches!(output.publish(m,Some(&auth)),Err(CompilerLinkError::Heap(_))));
        assert_eq!(k.compiler_publication_epoch(),m);assert!(k.compiler_publications.links.is_empty());
        k.fabric.scoped_pointers.release_host_storage(filler).unwrap();
        assert_eq!(charge(&k),held);assert!(k.compiler_publication_receipt(m).is_some());
    }

}
