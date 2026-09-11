//! Device trait — the interface between the bus and I/O peripherals.
//!
//! A Device occupies a range of addresses on the bus and responds to
//! byte-level reads and writes.  The address passed to each method is
//! an *offset* relative to the device's base address.
//!
//! Devices may also generate interrupts and consume clock cycles.
//!
//! This is the boundary where:
//!
//!   CPU arithmetic  →  observable I/O

use std::any::Any;

/// A memory-mapped I/O device.
pub trait Device: Any {
    /// Human-readable name (for debug/trace output).
    fn name(&self) -> &str;

    /// Size of the device's address window in bytes.
    fn size(&self) -> u32;

    /// Read a byte at the given offset within the device.
    fn read(&mut self, offset: u32) -> u8;

    /// Write a byte at the given offset within the device.
    fn write(&mut self, offset: u32, val: u8);

    /// Return the interrupt level this device is currently asserting
    /// (1–7), or 0 if no interrupt is pending.
    fn irq_level(&self) -> u8 { 0 }

    /// Advance the device's internal state by the given number of
    /// CPU cycles.  Used by clocked devices (e.g. timer).
    fn tick(&mut self, _cycles: u32) {}

    /// Downcast support — the TCB should contain no unchecked casts.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
