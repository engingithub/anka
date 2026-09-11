/// Operand size — the 68000 operates on byte, word, and long operands.
///
/// Every ALU operation and memory access is parameterised by one of these
/// widths, and all bitvector arithmetic is masked accordingly:
///
///   ADD_n(a, b) = (a + b) mod 2^n
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Size {
    Byte, // 8-bit
    Word, // 16-bit
    Long, // 32-bit
}

impl Size {
    /// Bit-mask for the active bits at this width.
    ///
    /// ```text
    /// Byte → 0x0000_00FF
    /// Word → 0x0000_FFFF
    /// Long → 0xFFFF_FFFF
    /// ```
    #[inline]
    pub const fn mask(self) -> u32 {
        match self {
            Size::Byte => 0xFF,
            Size::Word => 0xFFFF,
            Size::Long => 0xFFFF_FFFF,
        }
    }

    /// The most-significant bit at this width (the sign bit).
    #[inline]
    pub const fn msb(self) -> u32 {
        match self {
            Size::Byte => 0x80,
            Size::Word => 0x8000,
            Size::Long => 0x8000_0000,
        }
    }

    /// Number of bits.
    #[inline]
    pub const fn bits(self) -> u32 {
        match self {
            Size::Byte => 8,
            Size::Word => 16,
            Size::Long => 32,
        }
    }

    /// Number of bytes.
    #[inline]
    pub const fn bytes(self) -> u32 {
        match self {
            Size::Byte => 1,
            Size::Word => 2,
            Size::Long => 4,
        }
    }
}

// ---------------------------------------------------------------------------
// Status Register (SR) bit positions
// ---------------------------------------------------------------------------
// The 68000 SR is 16 bits:
//   bits 15..8  = system byte  (T1 T0 S _ _ I₂ I₁ I₀)
//   bits  7..0  = CCR          (_ _ _ X N Z V C)
// ---------------------------------------------------------------------------

/// Condition Code Register flags — the lower byte of the SR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ccr {
    pub c: bool, // Carry
    pub v: bool, // Overflow
    pub z: bool, // Zero
    pub n: bool, // Negative
    pub x: bool, // Extend
}

impl Ccr {
    /// Pack the CCR into the low 5 bits of a byte (XNZVC).
    #[inline]
    pub const fn to_byte(self) -> u8 {
        (self.c as u8)
            | ((self.v as u8) << 1)
            | ((self.z as u8) << 2)
            | ((self.n as u8) << 3)
            | ((self.x as u8) << 4)
    }

    /// Unpack from a byte.
    #[inline]
    pub const fn from_byte(b: u8) -> Self {
        Self {
            c: b & 1 != 0,
            v: b & 2 != 0,
            z: b & 4 != 0,
            n: b & 8 != 0,
            x: b & 16 != 0,
        }
    }
}

/// Status Register — full 16-bit value with helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusRegister(pub u16);

impl StatusRegister {
    // Bit positions
    const C: u16 = 1 << 0;
    const V: u16 = 1 << 1;
    const Z: u16 = 1 << 2;
    const N: u16 = 1 << 3;
    const X: u16 = 1 << 4;
    const S: u16 = 1 << 13; // Supervisor mode
    const T: u16 = 1 << 15; // Trace

    pub const fn new() -> Self {
        // Boot in supervisor mode with interrupts masked.
        Self(Self::S | 0x0700)
    }

    // --- CCR accessors ------------------------------------------------

    #[inline]
    pub const fn ccr(self) -> Ccr {
        Ccr::from_byte(self.0 as u8)
    }

    #[inline]
    pub fn set_ccr(&mut self, ccr: Ccr) {
        self.0 = (self.0 & 0xFF00) | ccr.to_byte() as u16;
    }

    // --- Individual flags ---------------------------------------------

    #[inline]
    pub const fn c(self) -> bool {
        self.0 & Self::C != 0
    }
    #[inline]
    pub const fn v(self) -> bool {
        self.0 & Self::V != 0
    }
    #[inline]
    pub const fn z(self) -> bool {
        self.0 & Self::Z != 0
    }
    #[inline]
    pub const fn n(self) -> bool {
        self.0 & Self::N != 0
    }
    #[inline]
    pub const fn x(self) -> bool {
        self.0 & Self::X != 0
    }
    #[inline]
    pub const fn supervisor(self) -> bool {
        self.0 & Self::S != 0
    }
    #[inline]
    pub const fn trace(self) -> bool {
        self.0 & Self::T != 0
    }

    /// Interrupt priority mask (bits 10..8).
    #[inline]
    pub const fn ipl_mask(self) -> u8 {
        ((self.0 >> 8) & 7) as u8
    }
}

impl Default for StatusRegister {
    fn default() -> Self {
        Self::new()
    }
}
