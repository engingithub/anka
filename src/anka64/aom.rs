//! Anka Object Module (AOM) v1 parser and structural validator.
//!
//! Phase 10.3 freezes the first byte-level object format.  AOM is deliberately
//! small: one code section, an optional read-only-data section, a fixed-width
//! function symbol table, and fixed-width typed relocations.  It is an object
//! representation only; parsing a valid module grants no execution authority.

pub const AOM_MAGIC: [u8; 8] = *b"ANKAOM1\0";
pub const AOM_VERSION: u64 = 1;
pub const AOM_HEADER_SIZE: u64 = 112;
pub const AOM_SYMBOL_SIZE: u64 = 160;
pub const AOM_RELOCATION_SIZE: u64 = 48;
pub const AOM_SECTION_UNDEFINED: u64 = 0;
pub const AOM_SECTION_CODE: u64 = 1;
pub const AOM_SECTION_RODATA: u64 = 2;
pub const AOM_BINDING_EXPORT: u64 = 1;
pub const AOM_BINDING_IMPORT: u64 = 2;
pub const AOM_SYMBOL_FUNCTION: u64 = 1;
pub const AOM_RELOC_CALL_PC20: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AomHeader {
    pub total_size: u64,
    pub code_offset: u64,
    pub code_size: u64,
    pub code_align: u64,
    pub rodata_offset: u64,
    pub rodata_size: u64,
    pub rodata_align: u64,
    pub symbol_offset: u64,
    pub symbol_count: u64,
    pub relocation_offset: u64,
    pub relocation_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AomSymbol {
    pub name: String,
    pub binding: u64,
    pub kind: u64,
    pub section: u64,
    pub value: u64,
    pub size: u64,
    pub return_type: u64,
    pub parameter_types: Vec<u64>,
}

impl AomSymbol {
    pub fn is_export(&self) -> bool {
        self.binding == AOM_BINDING_EXPORT
    }

    pub fn is_import(&self) -> bool {
        self.binding == AOM_BINDING_IMPORT
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AomRelocation {
    pub section: u64,
    pub offset: u64,
    pub width: u64,
    pub kind: u64,
    pub symbol_index: u64,
    pub addend: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AomModule {
    pub header: AomHeader,
    pub code: Vec<u8>,
    pub rodata: Vec<u8>,
    pub symbols: Vec<AomSymbol>,
    pub relocations: Vec<AomRelocation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AomError {
    Truncated,
    BadMagic,
    UnsupportedVersion(u64),
    BadHeaderSize(u64),
    BadTotalSize,
    BadAlignment,
    BadSectionBounds,
    BadTableGeometry,
    BadSymbol,
    DuplicateSymbol,
    BadRelocation,
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AomError> {
    let end = offset.checked_add(8).ok_or(AomError::Truncated)?;
    let word = bytes.get(offset..end).ok_or(AomError::Truncated)?;
    Ok(u64::from_le_bytes(word.try_into().expect("eight-byte AOM word")))
}

fn aligned(value: u64, alignment: u64) -> bool {
    alignment != 0 && alignment.is_power_of_two() && value % alignment == 0
}

fn portable_public_type(mut type_tag: u64) -> bool {
    while type_tag >= 1000 {
        type_tag -= 1000;
    }
    matches!(type_tag, 1 | 2 | 3)
}

fn checked_range(offset: u64, size: u64, total: u64) -> Result<std::ops::Range<usize>, AomError> {
    let end = offset.checked_add(size).ok_or(AomError::BadSectionBounds)?;
    if end > total {
        return Err(AomError::BadSectionBounds);
    }
    let start = usize::try_from(offset).map_err(|_| AomError::BadSectionBounds)?;
    let end = usize::try_from(end).map_err(|_| AomError::BadSectionBounds)?;
    Ok(start..end)
}

impl AomModule {
    pub fn parse(bytes: &[u8]) -> Result<Self, AomError> {
        if bytes.len() < AOM_HEADER_SIZE as usize {
            return Err(AomError::Truncated);
        }
        if bytes.get(0..8) != Some(AOM_MAGIC.as_slice()) {
            return Err(AomError::BadMagic);
        }
        let version = read_u64(bytes, 8)?;
        if version != AOM_VERSION {
            return Err(AomError::UnsupportedVersion(version));
        }
        let header_size = read_u64(bytes, 16)?;
        if header_size != AOM_HEADER_SIZE {
            return Err(AomError::BadHeaderSize(header_size));
        }

        let header = AomHeader {
            total_size: read_u64(bytes, 24)?,
            code_offset: read_u64(bytes, 32)?,
            code_size: read_u64(bytes, 40)?,
            code_align: read_u64(bytes, 48)?,
            rodata_offset: read_u64(bytes, 56)?,
            rodata_size: read_u64(bytes, 64)?,
            rodata_align: read_u64(bytes, 72)?,
            symbol_offset: read_u64(bytes, 80)?,
            symbol_count: read_u64(bytes, 88)?,
            relocation_offset: read_u64(bytes, 96)?,
            relocation_count: read_u64(bytes, 104)?,
        };

        if header.total_size != bytes.len() as u64 {
            return Err(AomError::BadTotalSize);
        }
        if header.code_offset != AOM_HEADER_SIZE || header.code_size == 0 || header.code_size % 8 != 0 {
            return Err(AomError::BadSectionBounds);
        }
        if !aligned(header.code_offset, header.code_align)
            || header.code_align < 8
            || !aligned(header.rodata_offset, header.rodata_align)
            || header.rodata_align < 8
            || !aligned(header.symbol_offset, 8)
            || !aligned(header.relocation_offset, 8)
        {
            return Err(AomError::BadAlignment);
        }

        let code_range = checked_range(header.code_offset, header.code_size, header.total_size)?;
        let rodata_range = checked_range(header.rodata_offset, header.rodata_size, header.total_size)?;
        let code_end = header.code_offset.checked_add(header.code_size)
            .ok_or(AomError::BadSectionBounds)?;
        let rodata_end = header.rodata_offset.checked_add(header.rodata_size)
            .ok_or(AomError::BadSectionBounds)?;
        if header.rodata_offset < code_end || header.symbol_offset < rodata_end {
            return Err(AomError::BadSectionBounds);
        }

        let symbol_bytes = header.symbol_count.checked_mul(AOM_SYMBOL_SIZE)
            .ok_or(AomError::BadTableGeometry)?;
        let expected_reloc = header.symbol_offset.checked_add(symbol_bytes)
            .ok_or(AomError::BadTableGeometry)?;
        if expected_reloc != header.relocation_offset {
            return Err(AomError::BadTableGeometry);
        }
        let relocation_bytes = header.relocation_count.checked_mul(AOM_RELOCATION_SIZE)
            .ok_or(AomError::BadTableGeometry)?;
        let expected_total = header.relocation_offset.checked_add(relocation_bytes)
            .ok_or(AomError::BadTableGeometry)?;
        if expected_total != header.total_size {
            return Err(AomError::BadTableGeometry);
        }

        let mut symbols = Vec::new();
        for index in 0..header.symbol_count {
            let base_u64 = header.symbol_offset + index * AOM_SYMBOL_SIZE;
            let base = usize::try_from(base_u64).map_err(|_| AomError::BadTableGeometry)?;
            let name_len = read_u64(bytes, base)?;
            if name_len == 0 || name_len > 63 {
                return Err(AomError::BadSymbol);
            }
            let name_len_usize = name_len as usize;
            let name_storage = bytes.get(base + 8..base + 72).ok_or(AomError::Truncated)?;
            if name_storage[name_len_usize..].iter().any(|byte| *byte != 0) {
                return Err(AomError::BadSymbol);
            }
            let name_bytes = &name_storage[..name_len_usize];
            let first = name_bytes[0];
            let first_ok = first == b'_' || first.is_ascii_alphabetic();
            let rest_ok = name_bytes[1..].iter()
                .all(|byte| *byte == b'_' || (*byte).is_ascii_alphanumeric());
            if !first_ok || !rest_ok {
                return Err(AomError::BadSymbol);
            }
            let name = std::str::from_utf8(name_bytes).map_err(|_| AomError::BadSymbol)?.to_owned();
            if symbols.iter().any(|symbol: &AomSymbol| symbol.name.as_str() == name.as_str()) {
                return Err(AomError::DuplicateSymbol);
            }

            let binding = read_u64(bytes, base + 72)?;
            let kind = read_u64(bytes, base + 80)?;
            let section = read_u64(bytes, base + 88)?;
            let value = read_u64(bytes, base + 96)?;
            let size = read_u64(bytes, base + 104)?;
            let return_type = read_u64(bytes, base + 112)?;
            let argc = read_u64(bytes, base + 120)?;
            if kind != AOM_SYMBOL_FUNCTION || argc > 4 || !portable_public_type(return_type) {
                return Err(AomError::BadSymbol);
            }
            match binding {
                AOM_BINDING_EXPORT => {
                    if section != AOM_SECTION_CODE || value >= header.code_size || value % 8 != 0 {
                        return Err(AomError::BadSymbol);
                    }
                }
                AOM_BINDING_IMPORT => {
                    if section != AOM_SECTION_UNDEFINED || value != 0 || size != 0 {
                        return Err(AomError::BadSymbol);
                    }
                }
                _ => return Err(AomError::BadSymbol),
            }
            let mut parameter_types = Vec::new();
            for p in 0..argc as usize {
                let parameter_type = read_u64(bytes, base + 128 + p * 8)?;
                if parameter_type == 3 || !portable_public_type(parameter_type) {
                    return Err(AomError::BadSymbol);
                }
                parameter_types.push(parameter_type);
            }
            for p in argc as usize..4 {
                if read_u64(bytes, base + 128 + p * 8)? != 0 {
                    return Err(AomError::BadSymbol);
                }
            }
            symbols.push(AomSymbol {
                name,
                binding,
                kind,
                section,
                value,
                size,
                return_type,
                parameter_types,
            });
        }

        let mut relocations = Vec::new();
        for index in 0..header.relocation_count {
            let base_u64 = header.relocation_offset + index * AOM_RELOCATION_SIZE;
            let base = usize::try_from(base_u64).map_err(|_| AomError::BadTableGeometry)?;
            let relocation = AomRelocation {
                section: read_u64(bytes, base)?,
                offset: read_u64(bytes, base + 8)?,
                width: read_u64(bytes, base + 16)?,
                kind: read_u64(bytes, base + 24)?,
                symbol_index: read_u64(bytes, base + 32)?,
                addend: read_u64(bytes, base + 40)? as i64,
            };
            if relocation.section != AOM_SECTION_CODE
                || relocation.width != 8
                || relocation.kind != AOM_RELOC_CALL_PC20
                || relocation.offset % 8 != 0
                || (match relocation.offset.checked_add(relocation.width) {
                    Some(end) => end > header.code_size,
                    None => true,
                })
                || relocation.symbol_index >= header.symbol_count
                || !symbols[relocation.symbol_index as usize].is_import()
            {
                return Err(AomError::BadRelocation);
            }
            relocations.push(relocation);
        }

        Ok(Self {
            header,
            code: bytes[code_range].to_vec(),
            rodata: bytes[rodata_range].to_vec(),
            symbols,
            relocations,
        })
    }

    pub fn symbol(&self, name: &str) -> Option<&AomSymbol> {
        self.symbols.iter().find(|symbol| symbol.name == name)
    }
}
