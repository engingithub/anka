//! Validated, immutable local-frame manifests. No guest integer issuance path.
use std::collections::BTreeSet;

use super::aom::{AomError, AomModule};
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
        if code.len()<4 || super::isa::decode(u32::from_le_bytes(code[..4].try_into().unwrap())).desc.semantics!=super::desc::Sem::PointerFrame {return Ok(None);}
        Self::validate(code, Self::parse_manifest(code, metadata)?).map(Some)
    }

    fn parse_manifest(code: &[u8], metadata: &[u8]) -> Result<Vec<FrameManifest>, FrameError> {
        fn word(bytes:&[u8],at:&mut usize) -> Result<u64,FrameError> {
            let end=at.checked_add(8).ok_or(FrameError::Geometry)?;
            let value=u64::from_le_bytes(bytes.get(*at..end).ok_or(FrameError::Geometry)?.try_into().unwrap());
            *at=end;Ok(value)
        }
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
        Ok(frames)
    }

    pub fn validate(code: &[u8], frames: Vec<FrameManifest>) -> Result<Self, FrameError> {
        // Executable admission never permits unresolved calls.
        Self::validate_structure(code, &frames, &BTreeSet::new())?;
        Ok(Self { code: code.to_vec(), frames })
    }

    // Only the module constructor supplies import sites, after checking each
    // complete relocation and CALL/NOP slot. This returns no executable token.
    fn validate_structure(code: &[u8], frames: &[FrameManifest],
        import_calls: &BTreeSet<u64>) -> Result<(), FrameError> {
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
                        if !import_calls.contains(&pc) && !frames.iter().any(|f| f.entry as i128==target) { return Err(FrameError::Control); }
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
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PointerModuleError {
    Aom(AomError),
    Frames(FrameError),
    Capacity,
    Geometry,
    Symbol,
    Relocation,
}

/// Structurally checked relocatable bytes, NOT an executable program or a
/// producer receipt. Publication still requires the adapter's lineage checks.
/// No conversion into ValidatedPointerProgram is provided: linked bytes must
/// independently pass the closed-image constructor.
#[derive(Debug, Clone)]
pub(crate) struct ValidatedPointerModule {
    bytes: Vec<u8>,
    module: AomModule,
    frames: Vec<FrameManifest>,
}

impl ValidatedPointerModule {
    pub(crate) fn bytes(&self) -> &[u8] { &self.bytes }
    pub(crate) fn module(&self) -> &AomModule { &self.module }
    pub(crate) fn frames(&self) -> &[FrameManifest] { &self.frames }

    pub(crate) fn from_aom(bytes: &[u8]) -> Result<Self, PointerModuleError> {
        use super::aom::AOM_HEADER_SIZE;
        use super::desc::Sem;
        use super::isa::decode;

        const NOP: u32 = 63 << 26;
        const CALL: u32 = 50 << 26;
        if bytes.len() as u64 > super::dev_compiler::DEVELOPMENT_COMPILER_OUTPUT_SIZE {
            return Err(PointerModuleError::Capacity);
        }
        let module = AomModule::parse(bytes).map_err(PointerModuleError::Aom)?;
        // This compiler profile has no literal pool or inter-section payload.
        if module.header.rodata_offset != AOM_HEADER_SIZE + module.header.code_size
            || module.header.symbol_offset != module.header.rodata_offset + module.header.rodata_size {
            return Err(PointerModuleError::Geometry);
        }
        let frames = ValidatedPointerProgram::parse_manifest(&module.code, &module.rodata)
            .map_err(PointerModuleError::Frames)?;
        if frames.iter().any(|frame| frame.entry % 8 != 0 || frame.end % 8 != 0) {
            return Err(PointerModuleError::Geometry);
        }
        for slot in module.code.chunks_exact(8) {
            let word = u32::from_le_bytes(slot[..4].try_into().unwrap());
            let pad = u32::from_le_bytes(slot[4..].try_into().unwrap());
            if pad != NOP || (decode(word).desc.semantics == Sem::Call && word & !0x3fffff != CALL) {
                return Err(PointerModuleError::Relocation);
            }
        }

        // Manifest ordinals follow definition-table order, even when earlier
        // prototypes cause that order to differ from emitted code order.
        let exports: Vec<_> = module.symbols.iter().filter(|symbol| symbol.is_export()).collect();
        if exports.len() != frames.len()
            || exports.iter().zip(&frames).any(|(symbol, frame)| symbol.value != frame.entry) {
            return Err(PointerModuleError::Symbol);
        }
        for symbol in &module.symbols {
            let mut lane = 0;
            for &ty in &symbol.parameter_types {
                if ty >= 1000 {
                    lane = (lane + 1) & !1;
                    lane += 2;
                } else {
                    lane += 1;
                }
            }
            if lane > 4 { return Err(PointerModuleError::Symbol); }
        }

        let mut imports = BTreeSet::new();
        for relocation in &module.relocations {
            // AOM parsing already checked section/kind/width/bounds and that
            // the named symbol is an import. Check the exact patch slot here.
            let pc = relocation.offset;
            let word = u32::from_le_bytes(module.code[pc as usize..pc as usize+4].try_into().unwrap());
            if relocation.addend != 0 || word != CALL || !imports.insert(pc)
                || !frames.iter().any(|frame| frame.entry < pc && pc + 8 <= frame.end) {
                return Err(PointerModuleError::Relocation);
            }
        }
        ValidatedPointerProgram::validate_structure(&module.code, &frames, &imports)
            .map_err(PointerModuleError::Frames)?;
        Ok(Self { bytes: bytes.to_vec(), module, frames })
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

    fn encode_module(module: &AomModule) -> Vec<u8> {
        use super::super::aom::*;
        let rodata = AOM_HEADER_SIZE + module.code.len() as u64;
        let symbols = rodata + module.rodata.len() as u64;
        let relocations = symbols + module.symbols.len() as u64 * AOM_SYMBOL_SIZE;
        let total = relocations + module.relocations.len() as u64 * AOM_RELOCATION_SIZE;
        let mut bytes = AOM_MAGIC.to_vec();
        for word in [1, AOM_HEADER_SIZE, total, AOM_HEADER_SIZE, module.code.len() as u64,
            8, rodata, module.rodata.len() as u64, 8, symbols, module.symbols.len() as u64,
            relocations, module.relocations.len() as u64] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&module.code);
        bytes.extend_from_slice(&module.rodata);
        for symbol in &module.symbols {
            bytes.extend_from_slice(&(symbol.name.len() as u64).to_le_bytes());
            let mut name = [0; 64];
            name[..symbol.name.len()].copy_from_slice(symbol.name.as_bytes());
            bytes.extend_from_slice(&name);
            for word in [symbol.binding, symbol.kind, symbol.section, symbol.value,
                symbol.size, symbol.return_type, symbol.parameter_types.len() as u64] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            for i in 0..4 {
                bytes.extend_from_slice(&symbol.parameter_types.get(i).copied().unwrap_or(0).to_le_bytes());
            }
        }
        for relocation in &module.relocations {
            for word in [relocation.section, relocation.offset, relocation.width,
                relocation.kind, relocation.symbol_index, relocation.addend as u64] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
        bytes
    }

    fn module_fixture() -> AomModule {
        use super::super::aom::*;
        let mut asm = Asm64::new();
        asm.pframe(0); asm.nop(); asm.call(0); asm.nop();
        asm.punframe(); asm.nop(); asm.ret(); asm.nop();
        asm.pframe(1); asm.nop(); asm.punframe(); asm.nop(); asm.ret(); asm.nop();
        let code = asm.to_bytes();
        let words = [1345400887u64, 2, 56, 2,
            0, 32, 32, 2, 0, 8, 8, 1, 16, 16, 16, 3,
            32, 56, 16, 0];
        let rodata = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let symbol = |name: &str, binding, value, parameter_types| AomSymbol {
            name: name.to_owned(), binding, kind: AOM_SYMBOL_FUNCTION,
            section: if binding == AOM_BINDING_EXPORT { AOM_SECTION_CODE } else { AOM_SECTION_UNDEFINED },
            value, size: 0, return_type: 1, parameter_types,
        };
        let module = AomModule {
            // encode_module derives geometry from the fixture's sections.
            header: AomHeader { total_size: 0, code_offset: 0, code_size: 0,
                code_align: 8, rodata_offset: 0, rodata_size: 0, rodata_align: 8,
                symbol_offset: 0, symbol_count: 0, relocation_offset: 0, relocation_count: 0 },
            code, rodata,
            symbols: vec![symbol("main", AOM_BINDING_EXPORT, 0, vec![]),
                symbol("local", AOM_BINDING_EXPORT, 32, vec![1002, 1]),
                symbol("external", AOM_BINDING_IMPORT, 0, vec![1002, 1])],
            relocations: vec![AomRelocation { section: AOM_SECTION_CODE, offset: 8,
                width: 8, kind: AOM_RELOC_CALL_PC20, symbol_index: 2, addend: 0 }],
        };
        AomModule::parse(&encode_module(&module)).unwrap()
    }

    fn closed_module_fixture() -> AomModule {
        let mut module = module_fixture();
        module.relocations.clear();
        module.symbols.pop();
        // The call at 8 now targets the local function at 32.
        module.code[8..12].copy_from_slice(&((50u32 << 26) | 6).to_le_bytes());
        module
    }

    fn reject_module_change(change: impl FnOnce(&mut AomModule)) {
        let mut module = module_fixture();
        change(&mut module);
        assert!(ValidatedPointerModule::from_aom(&encode_module(&module)).is_err());
    }

    fn manifest_word(module: &mut AomModule, index: usize, value: u64) {
        module.rodata[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn protected_module_keeps_unresolved_calls_out_of_execution() {
        let bytes = encode_module(&module_fixture());
        let checked = ValidatedPointerModule::from_aom(&bytes).unwrap();
        assert_eq!(checked.bytes(), bytes);
        assert_eq!(checked.frames().len(), 2);
        assert_eq!(checked.module().relocations.len(), 1);
        assert!(matches!(ValidatedPointerProgram::from_image(&checked.module().code,
            &checked.module().rodata), Err(FrameError::Control)));
    }

    #[test]
    fn protected_module_accepts_dense_definition_order_distinct_from_code_order() {
        let mut module = closed_module_fixture();
        assert!(ValidatedPointerModule::from_aom(&encode_module(&module)).is_ok());
        let mut recursive = module.clone();
        recursive.code[8..12].copy_from_slice(&((50u32 << 26) | 0x3ffffe).to_le_bytes());
        assert!(ValidatedPointerModule::from_aom(&encode_module(&recursive)).is_ok());
        // A forward declaration can put the second emitted definition first
        // in the symbol/frame table. The permutation must agree everywhere.
        let original = module.rodata.clone();
        module.rodata.truncate(32);
        module.rodata.extend_from_slice(&original[128..160]);
        module.rodata.extend_from_slice(&original[32..128]);
        module.symbols.swap(0, 1);
        module.code[..4].copy_from_slice(&((44u32 << 26) | 1).to_le_bytes());
        module.code[32..36].copy_from_slice(&(44u32 << 26).to_le_bytes());
        let checked = ValidatedPointerModule::from_aom(&encode_module(&module)).unwrap();
        assert_eq!(checked.frames()[0].entry, 32);
        assert_eq!(checked.frames()[1].entry, 0);
        assert!(matches!(ValidatedPointerProgram::from_image(&module.code, &module.rodata), Ok(Some(_))));
    }

    #[test]
    fn protected_module_rejects_malformed_import_relocations() {
        reject_module_change(|m| m.relocations.push(m.relocations[0].clone()));
        reject_module_change(|m| m.relocations.clear());
        reject_module_change(|m| m.relocations[0].addend = 1);
        for offset in [0, 4, 16, 24, 56, u64::MAX] {
            reject_module_change(|m| m.relocations[0].offset = offset);
        }
        reject_module_change(|m| m.relocations[0].width = 4);
        reject_module_change(|m| m.relocations[0].kind = 2);
        reject_module_change(|m| m.relocations[0].section = 2);
        reject_module_change(|m| m.relocations[0].symbol_index = 0);
        reject_module_change(|m| m.relocations[0].symbol_index = u64::MAX);
    }

    #[test]
    fn protected_module_requires_canonical_call_and_padding_bytes() {
        for word in [(50u32 << 26) | 1, (50u32 << 26) | (1 << 22), 63u32 << 26] {
            reject_module_change(|m| m.code[8..12].copy_from_slice(&word.to_le_bytes()));
        }
        // Every slot's paired NOP is checked, including PFRAME and RET slots.
        for at in (4..56).step_by(8) {
            reject_module_change(|m| m.code[at..at+4].copy_from_slice(&0u32.to_le_bytes()));
        }
        let mut local = closed_module_fixture();
        local.code[8..12].copy_from_slice(&((50u32 << 26) | (1 << 22) | 6).to_le_bytes());
        assert!(ValidatedPointerModule::from_aom(&encode_module(&local)).is_err());
    }

    #[test]
    fn protected_module_requires_a_definition_frame_bijection() {
        // Equal counts are insufficient: duplicate/interior exports still fail.
        reject_module_change(|m| m.symbols[1].value = 0);
        reject_module_change(|m| m.symbols[1].value = 40);
        reject_module_change(|m| m.symbols.swap(0, 1));
        reject_module_change(|m| m.symbols[1].binding = 2);
        reject_module_change(|m| m.code[..4].copy_from_slice(&((44u32 << 26) | 2).to_le_bytes()));
        reject_module_change(|m| manifest_word(m, 16, 0));
    }

    #[test]
    fn protected_module_checks_export_and_import_argument_lanes() {
        for symbol in [1, 2] {
            for signature in [vec![], vec![1, 2, 1, 2], vec![1002, 1001],
                vec![1, 1002], vec![1002, 1, 1], vec![1, 1, 1002]] {
                let mut module = module_fixture();
                module.symbols[symbol].parameter_types = signature;
                assert!(ValidatedPointerModule::from_aom(&encode_module(&module)).is_ok());
            }
            for signature in [vec![1, 1002, 1], vec![1002, 1001, 1], vec![1, 1, 1, 1002]] {
                reject_module_change(|m| m.symbols[symbol].parameter_types = signature);
            }
        }
    }

    #[test]
    fn protected_module_preserves_complete_frame_and_instruction_checks() {
        for (index, value) in [(1, 1), (2, 48), (3, 4097), (5, 24), (6, 31),
            (8, 32), (9, 0), (10, 3), (12, 0), (13, 8), (15, 2), (17, 64)] {
            reject_module_change(|m| manifest_word(m, index, value));
        }
        for word in [32u32 << 26, (38u32 << 26) | (1 << 22),
            (45u32 << 26) | (8 << 22) | 2, 44u32 << 26] {
            let mut module = closed_module_fixture();
            module.code[8..12].copy_from_slice(&word.to_le_bytes());
            assert!(ValidatedPointerModule::from_aom(&encode_module(&module)).is_err());
        }
        for at in [16, 24] {
            reject_module_change(|m| m.code[at..at+4].copy_from_slice(&(63u32 << 26).to_le_bytes()));
        }
        for displacement in [-2i32, 6, 100000] {
            let mut module = closed_module_fixture();
            let branch = (48u32 << 26) | (15 << 22) | (displacement as u32 & 0x3fffff);
            module.code[8..12].copy_from_slice(&branch.to_le_bytes());
            assert!(ValidatedPointerModule::from_aom(&encode_module(&module)).is_err());
        }
        reject_module_change(|m| m.rodata.extend_from_slice(&0u64.to_le_bytes()));
    }

    #[test]
    fn protected_module_rejects_truncated_oversized_and_unsupported_aom() {
        let bytes = encode_module(&module_fixture());
        for end in 0..bytes.len() {
            assert!(ValidatedPointerModule::from_aom(&bytes[..end]).is_err());
        }
        let mut changed = bytes.clone();
        changed[8..16].copy_from_slice(&2u64.to_le_bytes());
        assert!(matches!(ValidatedPointerModule::from_aom(&changed),
            Err(PointerModuleError::Aom(AomError::UnsupportedVersion(2)))));
        changed.resize(super::super::dev_compiler::DEVELOPMENT_COMPILER_OUTPUT_SIZE as usize + 1, 0);
        assert!(matches!(ValidatedPointerModule::from_aom(&changed), Err(PointerModuleError::Capacity)));
    }

    #[test]
    fn protected_module_public_type_validation_is_bounded_for_large_tags() {
        reject_module_change(|m| m.symbols[2].parameter_types = vec![u64::MAX]);
        reject_module_change(|m| m.symbols[2].return_type = u64::MAX);
        let mut module = module_fixture();
        let deep_pointer = u64::MAX / 1000 * 1000 + 1;
        module.symbols[2].parameter_types = vec![deep_pointer];
        assert!(ValidatedPointerModule::from_aom(&encode_module(&module)).is_ok());
    }
}
