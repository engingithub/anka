//! Validated, immutable local-frame manifests. No guest integer issuance path.
use super::scoped_pointers::{Scope, ScopedPointer};
use super::state::{DomainId, ObjectId, Generation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalStorage {
    pub offset: u64,
    pub length: u64,
    pub alignment: u64,
    pub writable: bool,
    pub pointer_slot: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameManifest {
    pub entry: u64,
    pub end: u64,
    pub size: u64,
    pub exits: Vec<u64>,
    pub locals: Vec<LocalStorage>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError { Geometry, Manifest, Context, Control, Capacity }

/// Construction validates complete code and manifest structure. Binding to a
/// current sealed Fabric object and process mapping happens at trusted admission.
#[derive(Debug, Clone)]
pub struct ValidatedPointerProgram {
    pub(crate) code: Vec<u8>,
    pub(crate) frames: Vec<FrameManifest>,
}
impl ValidatedPointerProgram {
    /// Canonical linked literal manifest, version 2. Exact consumption only.
    /// Returns None for legacy bytes; protected opcodes still cannot execute
    /// without successful trusted admission.
    pub(crate) fn from_image(code:&[u8],metadata:&[u8]) -> Result<Option<Self>,FrameError> {
        fn word(bytes:&[u8],at:&mut usize) -> Result<u64,FrameError> {
            let end=at.checked_add(8).ok_or(FrameError::Geometry)?;
            let value=u64::from_le_bytes(bytes.get(*at..end).ok_or(FrameError::Geometry)?.try_into().unwrap());
            *at=end;Ok(value)
        }
        if code.len()<4 || super::isa::decode(u32::from_le_bytes(code[..4].try_into().unwrap())).desc.semantics!=super::desc::Sem::PointerFrame {return Ok(None);}
        if metadata.len()<8 || u64::from_le_bytes(metadata[..8].try_into().unwrap())!=1345400887 {return Err(FrameError::Manifest);}
        let mut at=8;
        if word(metadata,&mut at)?!=2 || word(metadata,&mut at)?!=code.len() as u64 {return Err(FrameError::Geometry);}
        let count=word(metadata,&mut at)?;
        if count==0||count>4096 {return Err(FrameError::Capacity);}
        let mut frames=Vec::new();
        for _ in 0..count {
            let entry=word(metadata,&mut at)?;let end=word(metadata,&mut at)?;let size=word(metadata,&mut at)?;
            let n=word(metadata,&mut at)?;if n>4096 {return Err(FrameError::Capacity);}
            let mut locals=Vec::new();
            for _ in 0..n {
                let offset=word(metadata,&mut at)?;let length=word(metadata,&mut at)?;
                let alignment=word(metadata,&mut at)?;let flags=word(metadata,&mut at)?;
                if flags!=1 && flags!=3 {return Err(FrameError::Manifest);}
                locals.push(LocalStorage{offset,length,alignment,writable:true,pointer_slot:flags==3});
            }
            if entry%4!=0||end%4!=0||end>code.len() as u64||end<=entry {return Err(FrameError::Geometry);}
            let exits=(entry..end).step_by(4).filter(|&pc| super::isa::decode(u32::from_le_bytes(code[pc as usize..pc as usize+4].try_into().unwrap())).desc.semantics==super::desc::Sem::PointerUnframe).collect();
            frames.push(FrameManifest{entry,end,size,exits,locals});
        }
        if at!=metadata.len() {return Err(FrameError::Geometry);}
        Self::validate(code,frames).map(Some)
    }

    pub fn validate(code: &[u8], frames: Vec<FrameManifest>) -> Result<Self, FrameError> {
        use super::desc::Sem;
        use super::isa::decode;
        if code.is_empty() || code.len()%4!=0 || frames.is_empty() || frames.len()>4096 { return Err(FrameError::Geometry); }
        let mut ranges:Vec<_>=frames.iter().map(|f| (f.entry,f.end)).collect();
        ranges.sort_unstable();
        let mut prior_end=0;
        for &(start,end) in &ranges { if start!=prior_end||end<=start {return Err(FrameError::Geometry);}prior_end=end; }
        if prior_end!=code.len() as u64 {return Err(FrameError::Geometry);}
        for (index, frame) in frames.iter().enumerate() {
            if frame.end<=frame.entry || frame.end>code.len() as u64
                || frame.entry%4!=0 || frame.end%4!=0 || frame.size==0 || frame.size%16!=0
                || frame.locals.len()>4096 || frame.exits.is_empty() { return Err(FrameError::Manifest); }

            let first=decode(u32::from_le_bytes(code[frame.entry as usize..frame.entry as usize+4].try_into().unwrap()));
            if first.desc.semantics!=Sem::PointerFrame || first.imm!=index as i64 { return Err(FrameError::Manifest); }
            for (i, local) in frame.locals.iter().enumerate() {
                if !matches!(local.alignment,1|2|4|8|16) || local.offset%local.alignment!=0
                    || local.length==0 || local.offset.checked_add(local.length).is_none_or(|e| e>frame.size)
                    || (local.pointer_slot && (local.alignment!=16 || local.length!=16)) { return Err(FrameError::Manifest); }
                for other in &frame.locals[..i] {
                    if local.offset<other.offset+other.length && other.offset<local.offset+local.length { return Err(FrameError::Manifest); }
                }
            }
            for pc in (frame.entry..frame.end).step_by(4) {
                let insn=decode(u32::from_le_bytes(code[pc as usize..pc as usize+4].try_into().unwrap()));
                if insn.is_illegal() { return Err(FrameError::Manifest); }
                match insn.desc.semantics {
                    Sem::Load|Sem::Store|Sem::LoadByte|Sem::StoreByte|Sem::Xchg|Sem::Eret|Sem::Halt => return Err(FrameError::Manifest),
                    Sem::PointerFrame if pc!=frame.entry => return Err(FrameError::Control),
                    Sem::PointerLocal if insn.imm<0 || insn.imm as usize>=frame.locals.len() => return Err(FrameError::Manifest),
                    Sem::PointerUnframe if !frame.exits.contains(&pc) => return Err(FrameError::Control),
                    Sem::Branch => {
                        let target=(pc as i128)+(insn.imm as i128)*4;
                        if target<=frame.entry as i128 || target>=frame.end as i128 { return Err(FrameError::Control); }
                    }
                    Sem::Call => {
                        let target=(pc as i128)+(insn.imm as i128)*4;
                        if !frames.iter().any(|f| f.entry as i128==target) { return Err(FrameError::Control); }
                    }
                    Sem::Ret => {
                        let mut previous=pc;
                        while previous>frame.entry {
                            previous-=4;
                            if decode(u32::from_le_bytes(code[previous as usize..previous as usize+4].try_into().unwrap())).desc.semantics!=Sem::Nop { break; }
                        }
                        if !frame.exits.contains(&previous) { return Err(FrameError::Control); }
                    }
                    _=>{}
                }
            }
            // No fall-through across function boundaries or arbitrary exit sites.
            let mut last_pc=frame.end as usize-4;
            while last_pc>frame.entry as usize && decode(u32::from_le_bytes(code[last_pc..last_pc+4].try_into().unwrap())).desc.semantics==Sem::Nop {last_pc-=4;}
            let last=decode(u32::from_le_bytes(code[last_pc..last_pc+4].try_into().unwrap()));
            if last.desc.semantics!=Sem::Ret { return Err(FrameError::Control); }
            for &pc in &frame.exits {
                if pc<frame.entry || pc.checked_add(4).is_none_or(|n|n>=frame.end) || pc%4!=0 || frame.exits.iter().filter(|&&x| x==pc).count()!=1 { return Err(FrameError::Control); }
                let word=u32::from_le_bytes(code[pc as usize..pc as usize+4].try_into().unwrap());
                if decode(word).desc.semantics!=Sem::PointerUnframe { return Err(FrameError::Control); }
            }
        }
        if prior_end!=code.len() as u64 { return Err(FrameError::Geometry); }
        Ok(Self { code:code.to_vec(), frames })
    }
}
#[derive(Debug, Clone)]
pub(crate) struct ActiveFrame {
    pub scope: Scope,
    pub manifest: usize,
    pub call_depth: usize,
    pub parent_cursor: u64,
    pub parent_fp: u64,
    pub return_lr: u64,
    pub locals: Vec<ScopedPointer>,
}
#[derive(Debug, Clone)]
pub(crate) struct FrameState {
    pub program: ValidatedPointerProgram,
    pub context: u64,
    pub domain: DomainId,
    pub code_object: ObjectId,
    pub code_generation: Generation,
    pub code_offset: u64,
    pub code_base: u64,
    pub stack_low: u64,
    pub cursor: u64,
    pub pending_entry: Option<u64>,
    pub active: Vec<ActiveFrame>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anka64::isa::Asm64;
    #[test]
    fn protected_artifact_requires_exact_complete_metadata() {
        let mut asm=Asm64::new();asm.pframe(0);asm.punframe();asm.ret();
        let code=asm.to_bytes();
        let words=[1345400887u64,2,12,1,0,12,16,1,0,4,1,1];
        let bytes:Vec<u8>=words.iter().flat_map(|w|w.to_le_bytes()).collect();
        assert!(matches!(ValidatedPointerProgram::from_image(&code,&bytes),Ok(Some(_))));
        for n in 0..bytes.len() {assert!(ValidatedPointerProgram::from_image(&code,&bytes[..n]).is_err());}
        let mut extra=bytes.clone();extra.extend_from_slice(&0u64.to_le_bytes());
        assert!(ValidatedPointerProgram::from_image(&code,&extra).is_err());
        for (index,value) in [(1,1u64),(2,16),(3,4097),(8,15),(9,0),(10,3),(11,2)] {
            let mut bad=bytes.clone();bad[index*8..index*8+8].copy_from_slice(&value.to_le_bytes());
            assert!(ValidatedPointerProgram::from_image(&code,&bad).is_err());
        }
        // Ordinary literals do not opt a legacy image into a protected profile.
        let mut legacy=Asm64::new();legacy.nop();
        assert!(matches!(ValidatedPointerProgram::from_image(&legacy.to_bytes(),&bytes),Ok(None)));
    }
}
