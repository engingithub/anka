//! Explicit C-function entry policy. Direct process entries retain their ABI.
use super::*;

#[derive(Clone,Copy)]
pub(super) struct CallableApplicationEntry {
    object:ObjectId, generation:Generation, code_size:u64, image_size:u64,
}

impl Kernel {
    /// Trusted runner policy, after independent execution authorization. Not a
    /// syscall or receipt capability. Bind one exact current protected artifact;
    /// changing the object, generation or geometry never retargets selection.
    pub(crate) fn select_callable_application_entry(&mut self,object:ObjectId,
        generation:Generation,code_size:u64,image_size:u64)->Result<(),()> {
        if self.callable_application_entry.is_some() || code_size==0
            || code_size>=image_size || code_size%4!=0 {return Err(());}
        let obj=self.fabric.objects.get(&object).ok_or(())?;
        if obj.state!=ObjectState::Sealed || obj.generation!=generation || obj.size!=image_size {
            return Err(());
        }
        let base=self.fabric.translate(object,0).ok_or(())?;
        if base.checked_add(image_size).is_none_or(|n|n>self.fabric.mem_size()as u64) {return Err(());}
        let bytes=self.fabric.read_physical(base,image_size);
        if !matches!(crate::anka64::pointer_frames::ValidatedPointerProgram::from_image(
            &bytes[..code_size as usize],&bytes[code_size as usize..]),Ok(Some(_))) {return Err(());}
        self.callable_application_entry=Some(CallableApplicationEntry {object,generation,code_size,image_size});
        Ok(())
    }

    pub(super) fn callable_application_startup(&self,desc:&ProcessImageDesc,layout:&ProcessLayout)
        ->Result<Option<(u64,[u8;16])>,()> {
        let Some(bound)=self.callable_application_entry else{return Ok(None);};
        if desc.code_obj!=bound.object {return Ok(None);}
        let object=self.fabric.objects.get(&bound.object).ok_or(())?;
        if object.state!=ObjectState::Sealed || object.generation!=bound.generation
            || object.size!=bound.image_size || desc.code_offset!=0 || desc.entry!=0
            || desc.code_size!=bound.code_size || desc.lit_start!=bound.code_size
            || desc.image_size!=bound.image_size {return Err(());}
        let pc=layout.trap_vaddr.checked_add(16).ok_or(())?;
        let bytes=launcher(pc,layout.code_vaddr)?;
        Ok(Some((pc,bytes)))
    }
}

fn launcher(pc:u64,target:u64)->Result<[u8;16],()> {
    let delta=target as i128-pc as i128;
    let words=delta/4;
    if pc%4!=0 || target%4!=0 || delta%4!=0
        || words< -(1i128<<21) || words>=1i128<<21 {return Err(());}
    let mut a=Asm64::new();
    a.call(words as i32);a.mov(R1,R0);a.movi(R0,SYS_EXIT as i32);a.trap(0);
    a.to_bytes().try_into().map_err(|_|())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture()->(Kernel,ProcessImageDesc,ProcessLayout) {
        let mut a=Asm64::new();a.pframe(0);a.nop();a.movi(R0,42);a.nop();
        a.punframe();a.nop();a.ret();a.nop();
        let code=a.to_bytes();let n=code.len()as u64;let mut bytes=code;
        for w in [1345400887u64,2,n,1,0,n,16,0] {bytes.extend_from_slice(&w.to_le_bytes());}
        let mut f=Fabric::new(65536);let object=f.alloc_object("entry",bytes.len()as u64,ObjectKind::Memory);
        f.place_object(object,4096);assert!(f.initialize_object(object,0,&bytes));assert!(f.seal_object(object));
        let generation=f.objects[&object].generation;let mut k=Kernel::new(f);
        k.select_callable_application_entry(object,generation,n,bytes.len()as u64).unwrap();
        (k,ProcessImageDesc {code_obj:object,code_offset:0,code_size:n,lit_start:n,
            image_size:bytes.len()as u64,entry:0},
            ProcessLayout {code_vaddr:0,stack_vaddr:0x1000,stack_size:0x1000,trap_vaddr:0x2000})
    }
    #[test]
    fn c4_startup_real_call_targets_main_and_passes_return_value_to_exit() {
        let pc=0x14010u64;let target=0x2000u64;let b=launcher(pc,target).unwrap();
        let ins:Vec<_>=b.chunks_exact(4).map(|w|decode(u32::from_le_bytes(w.try_into().unwrap()))).collect();
        assert_eq!(ins[0].desc.semantics,crate::anka64::desc::Sem::Call);
        assert_eq!(pc as i128+ins[0].imm as i128*4,target as i128);
        assert_eq!((ins[1].rd,ins[1].rs1),(R1,R0));
        assert_eq!((ins[2].rd,ins[2].imm),(R0,SYS_EXIT as i64));
        assert_eq!(ins[3].desc.semantics,crate::anka64::desc::Sem::Trap);
    }
    #[test]
    fn c4_startup_rejects_unaligned_and_unencodable_targets() {
        for (pc,target) in [(1,0),(0,2),(0,1<<23),((1<<23)+4,0),(u64::MAX,0)] {
            assert!(launcher(pc,target).is_err());
        }
        assert!(launcher(1<<23,0).is_ok());
        assert!(launcher(0,(1<<23)-4).is_ok());
    }
    #[test]
    fn c4_startup_selection_binds_exact_current_image_and_geometry() {
        let(k,mut d,l)=fixture();
        assert!(k.callable_application_startup(&d,&l).unwrap().is_some());
        d.entry=8;assert!(k.callable_application_startup(&d,&l).is_err());d.entry=0;
        d.code_offset=8;assert!(k.callable_application_startup(&d,&l).is_err());d.code_offset=0;
        d.code_size+=8;assert!(k.callable_application_startup(&d,&l).is_err());d.code_size-=8;
        d.lit_start+=8;assert!(k.callable_application_startup(&d,&l).is_err());d.lit_start-=8;
        d.image_size+=8;assert!(k.callable_application_startup(&d,&l).is_err());d.image_size-=8;
        let mut k=k;k.fabric.objects.get_mut(&d.code_obj).unwrap().generation=Generation(99);
        assert!(k.callable_application_startup(&d,&l).is_err());
    }
    #[test]
    fn c4_startup_selection_does_not_retarget_other_images_or_replace_policy() {
        let(mut k,mut d,l)=fixture();let generation=k.fabric.objects[&d.code_obj].generation;
        assert!(k.select_callable_application_entry(d.code_obj,generation,d.code_size,d.image_size).is_err());
        d.code_obj=ObjectId(999);
        assert!(k.callable_application_startup(&d,&l).unwrap().is_none());
        let fresh=Kernel::new(Fabric::new(65536));
        assert!(fresh.callable_application_startup(&d,&l).unwrap().is_none());
    }
}
