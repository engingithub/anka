//! Device trait — the interface between the bus and I/O peripherals.
//!
//! A Device occupies a range of addresses on the bus and responds to
//! byte-level reads and writes.  The address passed to each method is
//! an *offset* relative to the device's base address.
//!
//! This is the boundary where:
//!
//!   CPU arithmetic  →  observable I/O

/// A memory-mapped I/O device.
pub trait Device {
    /// Human-readable name (for debug/trace output).
    fn name(&self) -> &str;

    /// Size of the device's address window in bytes.
    fn size(&self) -> u32;

    /// Read a byte at the given offset within the device.
    fn read(&mut self, offset: u32) -> u8;

    /// Write a byte at the given offset within the device.
    fn write(&mut self, offset: u32, val: u8);
}
