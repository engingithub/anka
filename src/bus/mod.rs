//! Memory bus abstraction.
//!
//! The Bus trait decouples the CPU from the physical memory layout.
//! A single address space can later contain:
//!
//!   RAM + ROM + MMIO + GPU registers + interrupt controller
//!
//! The 68000 external address bus is 24 bits (16 MB), but we use u32
//! addresses to accommodate future Anka64 extensions.
//!
//! Design note: the trait takes `&mut self` because I/O side-effects
//! (device registers, cycle counting) are expected.

pub mod console;
pub mod device;
mod flat;
mod mapped;

pub use flat::FlatBus;
pub use mapped::MappedBus;

/// Address mask for the original MC68000 (24-bit address bus).
pub const ADDR_MASK_68K: u32 = 0x00FF_FFFF;

/// Memory bus interface.
///
/// Implementors map addresses to RAM, ROM, or device registers.
/// All accesses are big-endian (Motorola byte order).
pub trait Bus {
    // --- Reads ---

    fn read8(&mut self, addr: u32) -> u8;

    fn read16(&mut self, addr: u32) -> u16 {
        let hi = self.read8(addr) as u16;
        let lo = self.read8(addr.wrapping_add(1)) as u16;
        (hi << 8) | lo
    }

    fn read32(&mut self, addr: u32) -> u32 {
        let hi = self.read16(addr) as u32;
        let lo = self.read16(addr.wrapping_add(2)) as u32;
        (hi << 16) | lo
    }

    // --- Writes ---

    fn write8(&mut self, addr: u32, val: u8);

    fn write16(&mut self, addr: u32, val: u16) {
        self.write8(addr, (val >> 8) as u8);
        self.write8(addr.wrapping_add(1), val as u8);
    }

    fn write32(&mut self, addr: u32, val: u32) {
        self.write16(addr, (val >> 16) as u16);
        self.write16(addr.wrapping_add(2), val as u16);
    }
}
