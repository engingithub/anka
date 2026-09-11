//! MappedBus — routes addresses to RAM or MMIO devices.
//!
//! The address space is divided into regions:
//!
//!   RAM + ROM + MMIO devices
//!
//! Each device is registered at a base address and occupies a fixed
//! number of bytes.  Addresses that don't hit any device fall through
//! to the underlying RAM.
//!
//! This is the bus that makes the machine boundary real:
//!
//!   ┌─────────┐     ┌──────────┐     ┌───────────┐
//!   │   CPU   │────▶│ MappedBus│────▶│  Console  │
//!   └─────────┘     │          │────▶│  (future)  │
//!                   │          │────▶│    RAM     │
//!                   └──────────┘     └───────────┘

use super::device::Device;
use super::{Bus, ADDR_MASK_68K};

/// A device mapping: base address + boxed device.
struct Mapping {
    base: u32,
    device: Box<dyn Device>,
}

/// A bus with RAM and memory-mapped devices.
pub struct MappedBus {
    ram: Vec<u8>,
    devices: Vec<Mapping>,
}

impl MappedBus {
    /// Create a bus with the given RAM size.
    pub fn new(ram_size: usize) -> Self {
        Self {
            ram: vec![0u8; ram_size],
            devices: Vec::new(),
        }
    }

    /// Create a bus with the full 68000 address space (16 MB).
    pub fn new_16mb() -> Self {
        Self::new(16 * 1024 * 1024)
    }

    /// Register a device at the given base address.
    pub fn add_device(&mut self, base: u32, device: Box<dyn Device>) {
        let size = device.size();
        eprintln!(
            "  MMIO: {:#010X}–{:#010X}  {} ({})",
            base,
            base + size - 1,
            device.name(),
            size
        );
        self.devices.push(Mapping { base, device });
    }

    /// Load a byte slice into RAM at the given address.
    pub fn load(&mut self, base: u32, data: &[u8]) {
        let start = (base & ADDR_MASK_68K) as usize;
        let end = start + data.len();
        assert!(
            end <= self.ram.len(),
            "load at {:#x} + {} exceeds RAM size {}",
            base,
            data.len(),
            self.ram.len()
        );
        self.ram[start..end].copy_from_slice(data);
    }

    /// Find a device that covers the given address.
    /// Returns (device, offset_within_device) or None.
    fn find_device_mut(&mut self, addr: u32) -> Option<(&mut dyn Device, u32)> {
        for mapping in &mut self.devices {
            let offset = addr.wrapping_sub(mapping.base);
            if offset < mapping.device.size() {
                return Some((mapping.device.as_mut(), offset));
            }
        }
        None
    }

    /// Get a mutable reference to a device by name, with checked downcast.
    pub fn device_mut<T: Device + 'static>(&mut self, name: &str) -> Option<&mut T> {
        for mapping in &mut self.devices {
            if mapping.device.name() == name {
                return mapping.device.as_any_mut().downcast_mut::<T>();
            }
        }
        None
    }
}

impl Bus for MappedBus {
    fn read8(&mut self, addr: u32) -> u8 {
        let masked = addr & ADDR_MASK_68K;
        if let Some((dev, offset)) = self.find_device_mut(masked) {
            return dev.read(offset);
        }
        let a = masked as usize;
        if a < self.ram.len() {
            self.ram[a]
        } else {
            0xFF
        }
    }

    fn write8(&mut self, addr: u32, val: u8) {
        let masked = addr & ADDR_MASK_68K;
        if let Some((dev, offset)) = self.find_device_mut(masked) {
            dev.write(offset, val);
            return;
        }
        let a = masked as usize;
        if a < self.ram.len() {
            self.ram[a] = val;
        }
    }

    fn pending_irq(&mut self) -> u8 {
        let mut max_level = 0u8;
        for mapping in &self.devices {
            let level = mapping.device.irq_level();
            if level > max_level {
                max_level = level;
            }
        }
        max_level
    }

    fn tick(&mut self, cycles: u32) {
        for mapping in &mut self.devices {
            mapping.device.tick(cycles);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::console::Console;

    #[test]
    fn ram_read_write() {
        let mut bus = MappedBus::new(1024);
        bus.write8(0x10, 0x42);
        assert_eq!(bus.read8(0x10), 0x42);
    }

    #[test]
    fn device_intercepts_writes() {
        let mut bus = MappedBus::new(1024);
        bus.add_device(0x00F0_0000, Box::new(Console::new()));

        // TX_READY should read 0x01
        let ready = bus.read8(0x00F0_0001);
        assert_eq!(ready, 0x01);
    }

    #[test]
    fn device_does_not_shadow_ram() {
        let mut bus = MappedBus::new(16 * 1024 * 1024);
        bus.add_device(0x00F0_0000, Box::new(Console::new()));

        // RAM outside the device window should work normally.
        bus.write8(0x0010, 0xAB);
        assert_eq!(bus.read8(0x0010), 0xAB);
    }

    #[test]
    fn load_into_ram() {
        let mut bus = MappedBus::new(1024);
        bus.load(0x100, &[0xDE, 0xAD]);
        assert_eq!(bus.read16(0x100), 0xDEAD);
    }
}
