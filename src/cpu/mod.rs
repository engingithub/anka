//! MC68000 CPU core.
//!
//! The CPU is generic over the Bus implementation so the same core
//! works with flat RAM, memory-mapped I/O, or a future multi-device bus.
//!
//! Architectural state:
//!
//!   D₀…D₇ ∈ BV₃₂     (data registers)
//!   A₀…A₇ ∈ BV₃₂     (address registers — A7 is the stack pointer)
//!   PC    ∈ BV₃₂     (program counter)
//!   SR    ∈ BV₁₆     (status register)
//!   cycles            (elapsed machine cycles)

pub mod bv;
pub mod ea;
pub mod exec;
pub mod types;

use crate::bus::Bus;
use types::StatusRegister;

/// MC68000 processor state.
pub struct Cpu<B: Bus> {
    /// Data registers D0–D7.
    pub d: [u32; 8],
    /// Address registers A0–A7.  A7 is the active stack pointer.
    pub a: [u32; 8],
    /// Supervisor stack pointer (SSP) — swapped with A7 on privilege change.
    pub ssp: u32,
    /// User stack pointer (USP).
    pub usp: u32,
    /// Program counter.
    pub pc: u32,
    /// Status register.
    pub sr: StatusRegister,
    /// Elapsed machine cycles.
    pub cycles: u64,
    /// Whether the CPU is halted.
    pub halted: bool,
    /// The system bus.
    pub bus: B,
}

impl<B: Bus> Cpu<B> {
    /// Create a new CPU in its reset state attached to the given bus.
    ///
    /// Per the 68000 reset sequence:
    ///   - SSP is loaded from address 0x000000 (long).
    ///   - PC  is loaded from address 0x000004 (long).
    ///   - SR  enters supervisor mode with interrupts masked.
    pub fn new(mut bus: B) -> Self {
        let ssp = bus.read32(0x000000);
        let pc = bus.read32(0x000004);

        Self {
            d: [0; 8],
            a: [0, 0, 0, 0, 0, 0, 0, ssp],
            ssp,
            usp: 0,
            pc,
            sr: StatusRegister::new(),
            cycles: 0,
            halted: false,
            bus,
        }
    }

    /// Fetch the next word from the instruction stream and advance PC.
    #[inline]
    pub fn fetch_word(&mut self) -> u16 {
        let w = self.bus.read16(self.pc);
        self.pc = self.pc.wrapping_add(2);
        w
    }

    /// Fetch the next longword from the instruction stream.
    #[inline]
    pub fn fetch_long(&mut self) -> u32 {
        let hi = self.fetch_word() as u32;
        let lo = self.fetch_word() as u32;
        (hi << 16) | lo
    }

    /// Push a longword onto the active stack (pre-decrement A7).
    pub fn push32(&mut self, val: u32) {
        self.a[7] = self.a[7].wrapping_sub(4);
        let sp = self.a[7];
        self.bus.write32(sp, val);
    }

    /// Pop a longword from the active stack (post-increment A7).
    pub fn pop32(&mut self) -> u32 {
        let sp = self.a[7];
        let val = self.bus.read32(sp);
        self.a[7] = self.a[7].wrapping_add(4);
        val
    }

    /// Push a word onto the active stack.
    pub fn push16(&mut self, val: u16) {
        self.a[7] = self.a[7].wrapping_sub(2);
        let sp = self.a[7];
        self.bus.write16(sp, val);
    }

    /// Pop a word from the active stack.
    pub fn pop16(&mut self) -> u16 {
        let sp = self.a[7];
        let val = self.bus.read16(sp);
        self.a[7] = self.a[7].wrapping_add(2);
        val
    }
}
