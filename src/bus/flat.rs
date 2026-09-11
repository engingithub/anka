//! Flat (plain RAM) bus — the simplest Bus implementation.
//!
//! Maps the entire 16 MB address space to a byte vector.
//! Good enough for initial bring-up; later replaced by a
//! mapped bus with ROM / MMIO regions.

use super::{Bus, ADDR_MASK_68K};

/// A simple flat memory bus backed by a `Vec<u8>`.
pub struct FlatBus {
    mem: Vec<u8>,
}

impl FlatBus {
    /// Create a bus with `size` bytes of zeroed memory.
    pub fn new(size: usize) -> Self {
        Self {
            mem: vec![0u8; size],
        }
    }

    /// Create a 16 MB bus (full 68000 address space).
    pub fn new_16mb() -> Self {
        Self::new(16 * 1024 * 1024)
    }

    /// Load a byte slice into memory starting at `base`.
    pub fn load(&mut self, base: u32, data: &[u8]) {
        let start = (base & ADDR_MASK_68K) as usize;
        let end = start + data.len();
        assert!(
            end <= self.mem.len(),
            "load at {:#x} + {} exceeds memory size {}",
            base,
            data.len(),
            self.mem.len()
        );
        self.mem[start..end].copy_from_slice(data);
    }

    /// Direct slice access (for debugging / tests).
    pub fn slice(&self, start: u32, len: usize) -> &[u8] {
        let s = (start & ADDR_MASK_68K) as usize;
        &self.mem[s..s + len]
    }
}

impl Bus for FlatBus {
    fn read8(&mut self, addr: u32) -> u8 {
        let a = (addr & ADDR_MASK_68K) as usize;
        if a < self.mem.len() {
            self.mem[a]
        } else {
            0xFF // Open-bus reads return 0xFF
        }
    }

    fn write8(&mut self, addr: u32, val: u8) {
        let a = (addr & ADDR_MASK_68K) as usize;
        if a < self.mem.len() {
            self.mem[a] = val;
        }
        // Writes to unmapped space are silently dropped.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_roundtrip() {
        let mut bus = FlatBus::new(1024);
        bus.write8(0x00, 0x42);
        assert_eq!(bus.read8(0x00), 0x42);
    }

    #[test]
    fn big_endian_word() {
        let mut bus = FlatBus::new(1024);
        bus.write16(0x00, 0xBEEF);
        assert_eq!(bus.read8(0x00), 0xBE);
        assert_eq!(bus.read8(0x01), 0xEF);
        assert_eq!(bus.read16(0x00), 0xBEEF);
    }

    #[test]
    fn big_endian_long() {
        let mut bus = FlatBus::new(1024);
        bus.write32(0x00, 0xDEAD_BEEF);
        assert_eq!(bus.read32(0x00), 0xDEAD_BEEF);
        assert_eq!(bus.read16(0x00), 0xDEAD);
        assert_eq!(bus.read16(0x02), 0xBEEF);
    }

    #[test]
    fn load_and_read() {
        let mut bus = FlatBus::new(1024);
        bus.load(0x100, &[0x4E, 0x71]); // NOP opcode
        assert_eq!(bus.read16(0x100), 0x4E71);
    }

    #[test]
    fn address_wraps_24bit() {
        let mut bus = FlatBus::new_16mb();
        bus.write8(0x01_000_042, 0xAA);
        assert_eq!(bus.read8(0x000_042), 0xAA); // 24-bit mask
    }
}
