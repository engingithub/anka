//! Motorola S-record (SREC / S19 / S28) loader and writer.
//!
//! The S-record format is the native object format for Motorola 68000
//! toolchains.  Using it here is both historically appropriate and
//! removes the "poke every byte" bottleneck.
//!
//! # Format
//!
//! Each line is an ASCII record: `S<type><byte_count><address><data...><checksum>`
//!
//! ```text
//! Type  Address    Description
//! ────  ─────────  ────────────────────────────────────────
//! S0    —          Header (optional, ignored by loader)
//! S1    16-bit     Data record
//! S2    24-bit     Data record
//! S3    32-bit     Data record
//! S5    16-bit     Record count (optional)
//! S7    32-bit     End record with entry address
//! S8    24-bit     End record with entry address
//! S9    16-bit     End record with entry address
//! ```
//!
//! Checksum = one's complement of (byte_count + address bytes + data bytes).

use std::fmt;

// ---------------------------------------------------------------------------
// Parsed record
// ---------------------------------------------------------------------------

/// A single parsed S-record line.
#[derive(Debug, Clone)]
pub enum Record {
    /// S0: header (contains optional name/description).
    Header(Vec<u8>),
    /// S1/S2/S3: data at an address.
    Data { address: u32, data: Vec<u8> },
    /// S7/S8/S9: end record with entry address.
    End { entry: u32 },
    /// S5: record count.
    Count(u16),
}

/// Result of loading an S-record file.
#[derive(Debug)]
pub struct SrecFile {
    pub records: Vec<Record>,
    pub entry: Option<u32>,
}

impl SrecFile {
    /// Total data bytes across all data records.
    pub fn data_size(&self) -> usize {
        self.records
            .iter()
            .map(|r| match r {
                Record::Data { data, .. } => data.len(),
                _ => 0,
            })
            .sum()
    }

    /// Lowest data address.
    pub fn base_address(&self) -> Option<u32> {
        self.records.iter().filter_map(|r| match r {
            Record::Data { address, .. } => Some(*address),
            _ => None,
        }).min()
    }

    /// Highest address + 1.
    pub fn end_address(&self) -> Option<u32> {
        self.records.iter().filter_map(|r| match r {
            Record::Data { address, data, .. } => Some(*address + data.len() as u32),
            _ => None,
        }).max()
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse error with line number.
#[derive(Debug)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

/// Parse a complete S-record file from text.
pub fn parse(text: &str) -> Result<SrecFile, ParseError> {
    let mut records = Vec::new();
    let mut entry = None;

    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('S') && !line.starts_with('s') {
            return Err(ParseError {
                line: lineno + 1,
                message: "expected 'S' prefix".into(),
            });
        }

        let record = parse_line(line, lineno + 1)?;

        if let Record::End { entry: e } = &record {
            entry = Some(*e);
        }

        records.push(record);
    }

    Ok(SrecFile { records, entry })
}

fn parse_line(line: &str, lineno: usize) -> Result<Record, ParseError> {
    let err = |msg: &str| ParseError {
        line: lineno,
        message: msg.into(),
    };

    if line.len() < 4 {
        return Err(err("record too short"));
    }

    let stype = line.as_bytes()[1];
    let hex = &line[2..];
    let bytes = hex_decode(hex).map_err(|_| err("invalid hex"))?;

    if bytes.is_empty() {
        return Err(err("empty record"));
    }

    let byte_count = bytes[0] as usize;
    if bytes.len() != byte_count + 1 {
        return Err(err(&format!(
            "byte count {} but {} bytes follow",
            byte_count,
            bytes.len() - 1
        )));
    }

    // Verify checksum
    let sum: u8 = bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    if sum != 0xFF {
        return Err(err(&format!("checksum error (sum={:#04X}, expected 0xFF)", sum)));
    }

    // Strip byte_count and checksum
    let payload = &bytes[1..bytes.len() - 1];

    match stype {
        b'0' => {
            // S0: header — address is 0x0000 (2 bytes), rest is data
            if payload.len() < 2 {
                return Err(err("S0 too short"));
            }
            Ok(Record::Header(payload[2..].to_vec()))
        }
        b'1' => {
            // S1: 16-bit address
            if payload.len() < 2 {
                return Err(err("S1 too short"));
            }
            let addr = u16::from_be_bytes([payload[0], payload[1]]) as u32;
            Ok(Record::Data {
                address: addr,
                data: payload[2..].to_vec(),
            })
        }
        b'2' => {
            // S2: 24-bit address
            if payload.len() < 3 {
                return Err(err("S2 too short"));
            }
            let addr =
                (payload[0] as u32) << 16 | (payload[1] as u32) << 8 | payload[2] as u32;
            Ok(Record::Data {
                address: addr,
                data: payload[3..].to_vec(),
            })
        }
        b'3' => {
            // S3: 32-bit address
            if payload.len() < 4 {
                return Err(err("S3 too short"));
            }
            let addr = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            Ok(Record::Data {
                address: addr,
                data: payload[4..].to_vec(),
            })
        }
        b'5' => {
            if payload.len() < 2 {
                return Err(err("S5 too short"));
            }
            let count = u16::from_be_bytes([payload[0], payload[1]]);
            Ok(Record::Count(count))
        }
        b'7' => {
            if payload.len() < 4 {
                return Err(err("S7 too short"));
            }
            let addr = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            Ok(Record::End { entry: addr })
        }
        b'8' => {
            if payload.len() < 3 {
                return Err(err("S8 too short"));
            }
            let addr =
                (payload[0] as u32) << 16 | (payload[1] as u32) << 8 | payload[2] as u32;
            Ok(Record::End { entry: addr })
        }
        b'9' => {
            if payload.len() < 2 {
                return Err(err("S9 too short"));
            }
            let addr = u16::from_be_bytes([payload[0], payload[1]]) as u32;
            Ok(Record::End { entry: addr })
        }
        _ => Err(err(&format!("unknown record type S{}", stype as char))),
    }
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, ()> {
    if hex.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let hi = hex_nibble(hex.as_bytes()[i])?;
        let lo = hex_nibble(hex.as_bytes()[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(()),
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Write a binary image as an S-record string.
///
/// Produces S2 records (24-bit address) with 32 data bytes per line,
/// plus an S8 end record with the entry address.
pub fn write(data: &[u8], base: u32, entry: u32) -> String {
    let mut out = String::new();

    // S0 header
    let header_data = b"ANKA";
    let s0 = make_s0(header_data);
    out.push_str(&s0);
    out.push('\n');

    // S2 data records (24-bit address, up to 32 data bytes each)
    let chunk_size = 32;
    let mut record_count = 0u16;

    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        let addr = base + (i * chunk_size) as u32;
        let s2 = make_s2(addr, chunk);
        out.push_str(&s2);
        out.push('\n');
        record_count += 1;
    }

    // S5 record count
    let s5 = make_s5(record_count);
    out.push_str(&s5);
    out.push('\n');

    // S8 end record (24-bit entry address)
    let s8 = make_s8(entry);
    out.push_str(&s8);
    out.push('\n');

    out
}

fn make_s0(header: &[u8]) -> String {
    // byte_count = 2 (address) + header.len() + 1 (checksum)
    let byte_count = (2 + header.len() + 1) as u8;
    let mut sum: u8 = byte_count;
    // address = 0x0000
    // sum already includes byte_count; add 0x00 + 0x00
    let mut hex = format!("S0{:02X}0000", byte_count);
    for &b in header {
        hex.push_str(&format!("{:02X}", b));
        sum = sum.wrapping_add(b);
    }
    let checksum = !sum;
    hex.push_str(&format!("{:02X}", checksum));
    hex
}

fn make_s2(addr: u32, data: &[u8]) -> String {
    // byte_count = 3 (address) + data.len() + 1 (checksum)
    let byte_count = (3 + data.len() + 1) as u8;
    let a2 = ((addr >> 16) & 0xFF) as u8;
    let a1 = ((addr >> 8) & 0xFF) as u8;
    let a0 = (addr & 0xFF) as u8;

    let mut sum: u8 = byte_count
        .wrapping_add(a2)
        .wrapping_add(a1)
        .wrapping_add(a0);

    let mut hex = format!("S2{:02X}{:02X}{:02X}{:02X}", byte_count, a2, a1, a0);
    for &b in data {
        hex.push_str(&format!("{:02X}", b));
        sum = sum.wrapping_add(b);
    }
    let checksum = !sum;
    hex.push_str(&format!("{:02X}", checksum));
    hex
}

fn make_s5(count: u16) -> String {
    let byte_count: u8 = 3; // 2 (address/count) + 1 (checksum)
    let hi = (count >> 8) as u8;
    let lo = count as u8;
    let sum: u8 = byte_count.wrapping_add(hi).wrapping_add(lo);
    let checksum = !sum;
    format!("S5{:02X}{:02X}{:02X}{:02X}", byte_count, hi, lo, checksum)
}

fn make_s8(entry: u32) -> String {
    let byte_count: u8 = 4; // 3 (address) + 1 (checksum)
    let a2 = ((entry >> 16) & 0xFF) as u8;
    let a1 = ((entry >> 8) & 0xFF) as u8;
    let a0 = (entry & 0xFF) as u8;
    let sum: u8 = byte_count
        .wrapping_add(a2)
        .wrapping_add(a1)
        .wrapping_add(a0);
    let checksum = !sum;
    format!("S8{:02X}{:02X}{:02X}{:02X}{:02X}", byte_count, a2, a1, a0, checksum)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_simple() {
        let data = vec![0x70, 0x48, 0x1C, 0x80, 0x4E, 0x72, 0x27, 0x00];
        let base = 0x002000;
        let entry = 0x002000;

        let text = write(&data, base, entry);
        let parsed = parse(&text).expect("parse failed");

        assert_eq!(parsed.entry, Some(entry));

        // Reconstruct data from records
        let mut reconstructed = vec![0u8; data.len()];
        for rec in &parsed.records {
            if let Record::Data { address, data: d } = rec {
                let offset = (*address - base) as usize;
                reconstructed[offset..offset + d.len()].copy_from_slice(d);
            }
        }
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn parse_s19_format() {
        // Hand-verified S19: MOVEQ #42,D0; MOVEQ #10,D1 at address 0x1000
        // S1: byte_count=07, addr=1000, data=702A720A, checksum=D2
        // S9: byte_count=03, entry=1000, checksum=EC
        let text = "\
S0030000FC
S1071000702A720AD2
S9031000EC";
        let parsed = parse(text).expect("parse failed");
        assert_eq!(parsed.entry, Some(0x1000));

        let data_records: Vec<_> = parsed
            .records
            .iter()
            .filter_map(|r| match r {
                Record::Data { address, data } => Some((*address, data.clone())),
                _ => None,
            })
            .collect();

        assert_eq!(data_records.len(), 1);
        assert_eq!(data_records[0].0, 0x1000);
        assert_eq!(data_records[0].1[0], 0x70); // MOVEQ
        assert_eq!(data_records[0].1[1], 0x2A); // #42
        assert_eq!(data_records[0].1[2], 0x72); // MOVEQ
        assert_eq!(data_records[0].1[3], 0x0A); // #10
    }

    #[test]
    fn checksum_verified() {
        // Corrupt the checksum
        let text = "S1130000702A720AD08170481C8070691C80FF";
        let result = parse(text);
        assert!(result.is_err());
    }

    #[test]
    fn write_produces_valid_srec() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let text = write(&data, 0x1000, 0x1000);

        // Every line should parse
        let parsed = parse(&text).expect("own output should parse");
        assert_eq!(parsed.entry, Some(0x1000));
        assert_eq!(parsed.data_size(), 4);
    }

    #[test]
    fn asm_builder_to_srec() {
        use crate::asm::Asm;

        let mut a = Asm::new(0x1000);
        a.moveq(42, 0); // MOVEQ #42, D0
        a.stop(0x2700); // STOP
        let binary = a.assemble();

        let srec = write(&binary, 0x1000, 0x1000);
        let parsed = parse(&srec).unwrap();
        assert_eq!(parsed.entry, Some(0x1000));
        assert!(parsed.data_size() > 0);
    }
}
