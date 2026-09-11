//! Bitvector arithmetic for the MC68000.
//!
//! All operations are width-aware: results are masked to the operand size
//! so that host (Rust) arithmetic never silently redefines 68000 semantics.
//!
//! The fundamental model is:
//!
//!   ADD_n(a, b) = (a + b) mod 2^n
//!
//! with condition codes derived algebraically from the operands and result.

use super::types::{Ccr, Size};

// ---------------------------------------------------------------------------
// Primitive helpers
// ---------------------------------------------------------------------------

/// Mask a value to the given operand width.
#[inline]
pub const fn mask(val: u32, size: Size) -> u32 {
    val & size.mask()
}

/// Test the MSB (sign bit) at the given width.
#[inline]
pub const fn is_negative(val: u32, size: Size) -> bool {
    val & size.msb() != 0
}

/// Sign-extend a value from `size` to 32 bits.
#[inline]
pub const fn sign_extend(val: u32, size: Size) -> u32 {
    let masked = val & size.mask();
    if masked & size.msb() != 0 {
        masked | !size.mask()
    } else {
        masked
    }
}

// ---------------------------------------------------------------------------
// Addition with full CCR
// ---------------------------------------------------------------------------

/// Bitvector addition: r = (a + b) mod 2^n, returning (result, CCR).
///
/// Condition codes follow 68000 semantics:
///   Z ⟺ r = 0
///   N ⟺ msb(r) = 1
///   V ⟺ ¬(a_s ⊕ b_s) ∧ (a_s ⊕ r_s)   (signed overflow)
///   C ⟺ unsigned carry out
///   X ← C
pub fn add(a: u32, b: u32, size: Size) -> (u32, Ccr) {
    let m = size.mask();
    let s = size.msb();

    let aa = a & m;
    let bb = b & m;
    let r = aa.wrapping_add(bb) & m;

    let z = r == 0;
    let n = r & s != 0;
    let v = ((!(aa ^ bb)) & (aa ^ r) & s) != 0;
    let c = carry(aa, bb, size);

    (r, Ccr { c, v, z, n, x: c })
}

/// Bitvector addition with extend (X) bit — used by ADDX.
///
/// r = (a + b + x) mod 2^n
///
/// Z is only *cleared*, never set (per 68000 spec: Z is ANDed with prior Z).
pub fn addx(a: u32, b: u32, x_in: bool, old_z: bool, size: Size) -> (u32, Ccr) {
    let m = size.mask();
    let s = size.msb();

    let aa = a & m;
    let bb = b & m;
    let xi = x_in as u32;
    let r = aa.wrapping_add(bb).wrapping_add(xi) & m;

    // Z is *cleared* if result non-zero, but never *set*.
    let z = old_z && r == 0;
    let n = r & s != 0;
    let v = ((!(aa ^ bb)) & (aa ^ r) & s) != 0;
    let c = carry_with_extend(aa, bb, xi, size);

    (r, Ccr { c, v, z, n, x: c })
}

// ---------------------------------------------------------------------------
// Subtraction with full CCR
// ---------------------------------------------------------------------------

/// Bitvector subtraction: r = (a − b) mod 2^n, returning (result, CCR).
///
/// In the 68000, SUB destination,source computes dst − src.
/// Borrow (C) is set when unsigned src > unsigned dst.
pub fn sub(a: u32, b: u32, size: Size) -> (u32, Ccr) {
    let m = size.mask();
    let s = size.msb();

    let aa = a & m;
    let bb = b & m;
    let r = aa.wrapping_sub(bb) & m;

    let z = r == 0;
    let n = r & s != 0;
    // Overflow: signs of a and b differ, and result sign differs from a.
    let v = ((aa ^ bb) & (aa ^ r) & s) != 0;
    let c = bb > aa; // Borrow

    (r, Ccr { c, v, z, n, x: c })
}

/// Bitvector subtraction with extend (X) bit — used by SUBX.
pub fn subx(a: u32, b: u32, x_in: bool, old_z: bool, size: Size) -> (u32, Ccr) {
    let m = size.mask();
    let s = size.msb();

    let aa = a & m;
    let bb = b & m;
    let xi = x_in as u32;
    let r = aa.wrapping_sub(bb).wrapping_sub(xi) & m;

    let z = old_z && r == 0;
    let n = r & s != 0;
    let v = ((aa ^ bb) & (aa ^ r) & s) != 0;
    // Borrow: bb + x > aa  (unsigned)
    let c = (bb as u64 + xi as u64) > aa as u64;

    (r, Ccr { c, v, z, n, x: c })
}

// ---------------------------------------------------------------------------
// Logical operations
// ---------------------------------------------------------------------------

/// AND with CCR update (V and C are always cleared).
pub fn and(a: u32, b: u32, size: Size) -> (u32, Ccr) {
    let r = (a & b) & size.mask();
    (r, logic_ccr(r, size))
}

/// OR with CCR update.
pub fn or(a: u32, b: u32, size: Size) -> (u32, Ccr) {
    let r = (a | b) & size.mask();
    (r, logic_ccr(r, size))
}

/// EOR (exclusive OR) with CCR update.
pub fn eor(a: u32, b: u32, size: Size) -> (u32, Ccr) {
    let r = (a ^ b) & size.mask();
    (r, logic_ccr(r, size))
}

/// NOT (one's complement) with CCR update.
pub fn not(val: u32, size: Size) -> (u32, Ccr) {
    let r = (!val) & size.mask();
    (r, logic_ccr(r, size))
}

/// NEG (two's complement negate): r = (0 − val) mod 2^n.
pub fn neg(val: u32, size: Size) -> (u32, Ccr) {
    sub(0, val, size)
}

// ---------------------------------------------------------------------------
// Compare (subtraction without storing the result)
// ---------------------------------------------------------------------------

/// CMP: compute (a − b), return only flags.
pub fn cmp(a: u32, b: u32, size: Size) -> Ccr {
    sub(a, b, size).1
}

// ---------------------------------------------------------------------------
// Shifts and rotates
// ---------------------------------------------------------------------------

/// Arithmetic shift left: MSB goes to C/X, zero fills from the right.
pub fn asl(val: u32, count: u32, size: Size) -> (u32, Ccr) {
    let m = size.mask();
    let s = size.msb();
    let mut v_flag = false;

    if count == 0 {
        let r = val & m;
        return (
            r,
            Ccr {
                c: false,
                v: false,
                z: r == 0,
                n: r & s != 0,
                x: false, // X unaffected on zero count — caller preserves old X
            },
        );
    }

    let mut data = val & m;
    let mut c = false;

    for _ in 0..count {
        c = data & s != 0;
        let prev_sign = data & s;
        data = (data << 1) & m;
        if data & s != prev_sign {
            v_flag = true;
        }
    }

    let r = data;
    (
        r,
        Ccr {
            c,
            v: v_flag,
            z: r == 0,
            n: r & s != 0,
            x: c,
        },
    )
}

/// Arithmetic shift right: sign bit is replicated, LSB goes to C/X.
pub fn asr(val: u32, count: u32, size: Size) -> (u32, Ccr) {
    let m = size.mask();
    let s = size.msb();

    if count == 0 {
        let r = val & m;
        return (
            r,
            Ccr {
                c: false,
                v: false,
                z: r == 0,
                n: r & s != 0,
                x: false,
            },
        );
    }

    let mut data = val & m;
    let mut c = false;

    for _ in 0..count {
        c = data & 1 != 0;
        let sign = data & s;
        data = (data >> 1) | sign;
        data &= m;
    }

    let r = data;
    (
        r,
        Ccr {
            c,
            v: false, // V is always cleared for ASR
            z: r == 0,
            n: r & s != 0,
            x: c,
        },
    )
}

/// Logical shift left.
pub fn lsl(val: u32, count: u32, size: Size) -> (u32, Ccr) {
    let m = size.mask();
    let s = size.msb();

    if count == 0 {
        let r = val & m;
        return (
            r,
            Ccr {
                c: false,
                v: false,
                z: r == 0,
                n: r & s != 0,
                x: false,
            },
        );
    }

    let mut data = val & m;
    let mut c = false;

    for _ in 0..count {
        c = data & s != 0;
        data = (data << 1) & m;
    }

    let r = data;
    (
        r,
        Ccr {
            c,
            v: false,
            z: r == 0,
            n: r & s != 0,
            x: c,
        },
    )
}

/// Logical shift right.
pub fn lsr(val: u32, count: u32, size: Size) -> (u32, Ccr) {
    let m = size.mask();
    let s = size.msb();

    if count == 0 {
        let r = val & m;
        return (
            r,
            Ccr {
                c: false,
                v: false,
                z: r == 0,
                n: r & s != 0,
                x: false,
            },
        );
    }

    let mut data = val & m;
    let mut c = false;

    for _ in 0..count {
        c = data & 1 != 0;
        data >>= 1;
    }

    let r = data & m;
    (
        r,
        Ccr {
            c,
            v: false,
            z: r == 0,
            n: r & s != 0,
            x: c,
        },
    )
}

/// Rotate left (no extend).
pub fn rol(val: u32, count: u32, size: Size) -> (u32, Ccr) {
    let m = size.mask();
    let s = size.msb();
    let bits = size.bits();

    let mut data = val & m;
    let mut c = false;

    let effective = if bits > 0 { count % bits } else { 0 };

    for _ in 0..effective {
        c = data & s != 0;
        data = ((data << 1) | c as u32) & m;
    }

    let r = data;
    (
        r,
        Ccr {
            c: if count == 0 { false } else { c },
            v: false,
            z: r == 0,
            n: r & s != 0,
            x: false, // X unaffected by ROL
        },
    )
}

/// Rotate right (no extend).
pub fn ror(val: u32, count: u32, size: Size) -> (u32, Ccr) {
    let m = size.mask();
    let s = size.msb();
    let bits = size.bits();

    let mut data = val & m;
    let mut c = false;

    let effective = if bits > 0 { count % bits } else { 0 };

    for _ in 0..effective {
        c = data & 1 != 0;
        data = (data >> 1) | ((c as u32) * s);
        data &= m;
    }

    let r = data;
    (
        r,
        Ccr {
            c: if count == 0 { false } else { c },
            v: false,
            z: r == 0,
            n: r & s != 0,
            x: false,
        },
    )
}

// ---------------------------------------------------------------------------
// Multiply / divide
// ---------------------------------------------------------------------------

/// MULU.W — unsigned 16×16 → 32.
pub fn mulu(a: u16, b: u16) -> (u32, Ccr) {
    let r = a as u32 * b as u32;
    (
        r,
        Ccr {
            c: false,
            v: false,
            z: r == 0,
            n: r & 0x8000_0000 != 0,
            x: false, // X unaffected
        },
    )
}

/// MULS.W — signed 16×16 → 32.
pub fn muls(a: u16, b: u16) -> (u32, Ccr) {
    let r = (a as i16 as i32 * b as i16 as i32) as u32;
    (
        r,
        Ccr {
            c: false,
            v: false,
            z: r == 0,
            n: r & 0x8000_0000 != 0,
            x: false,
        },
    )
}

/// DIVU.W — unsigned 32 / 16 → 16 quotient : 16 remainder.
///
/// Returns `None` on divide-by-zero or overflow (quotient > 0xFFFF).
pub fn divu(dividend: u32, divisor: u16) -> Option<(u32, Ccr)> {
    if divisor == 0 {
        return None; // Triggers divide-by-zero trap
    }
    let q = dividend / divisor as u32;
    if q > 0xFFFF {
        // Overflow — V set, other flags undefined.
        return Some((
            dividend, // Result register unchanged on overflow
            Ccr {
                c: false,
                v: true,
                z: false,
                n: false,
                x: false,
            },
        ));
    }
    let rem = dividend % divisor as u32;
    let r = (rem << 16) | q;
    Some((
        r,
        Ccr {
            c: false,
            v: false,
            z: (q & 0xFFFF) == 0,
            n: q & 0x8000 != 0,
            x: false,
        },
    ))
}

/// DIVS.W — signed 32 / 16 → 16 quotient : 16 remainder.
pub fn divs(dividend: u32, divisor: u16) -> Option<(u32, Ccr)> {
    if divisor == 0 {
        return None;
    }
    let num = dividend as i32;
    let den = divisor as i16 as i32;
    let q = num / den;
    if q > 0x7FFF || q < -0x8000 {
        return Some((
            dividend,
            Ccr {
                c: false,
                v: true,
                z: false,
                n: false,
                x: false,
            },
        ));
    }
    let rem = (num % den) as u16;
    let r = (rem as u32) << 16 | (q as u16 as u32);
    Some((
        r,
        Ccr {
            c: false,
            v: false,
            z: (q as u16) == 0,
            n: q as u16 & 0x8000 != 0,
            x: false,
        },
    ))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// CCR for logical operations: V = 0, C = 0.
fn logic_ccr(r: u32, size: Size) -> Ccr {
    Ccr {
        c: false,
        v: false,
        z: r == 0,
        n: r & size.msb() != 0,
        x: false, // X unaffected — caller preserves old X
    }
}

/// Unsigned carry out of a + b at the given width.
fn carry(a: u32, b: u32, size: Size) -> bool {
    match size {
        Size::Byte => (a as u16 + b as u16) > 0xFF,
        Size::Word => (a as u64 + b as u64) > 0xFFFF,
        Size::Long => (a as u64 + b as u64) > 0xFFFF_FFFF,
    }
}

/// Unsigned carry out of a + b + x.
fn carry_with_extend(a: u32, b: u32, x: u32, size: Size) -> bool {
    match size {
        Size::Byte => (a as u64 + b as u64 + x as u64) > 0xFF,
        Size::Word => (a as u64 + b as u64 + x as u64) > 0xFFFF,
        Size::Long => (a as u64 + b as u64 + x as u64) > 0xFFFF_FFFF,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_byte_overflow() {
        let (r, ccr) = add(0x80, 0x80, Size::Byte);
        assert_eq!(r, 0x00);
        assert!(ccr.z);
        assert!(!ccr.n);
        assert!(ccr.v); // signed overflow: -128 + -128
        assert!(ccr.c); // unsigned carry
    }

    #[test]
    fn add_word_no_overflow() {
        let (r, ccr) = add(0x1234, 0x0001, Size::Word);
        assert_eq!(r, 0x1235);
        assert!(!ccr.z);
        assert!(!ccr.n);
        assert!(!ccr.v);
        assert!(!ccr.c);
    }

    #[test]
    fn sub_borrow() {
        let (r, ccr) = sub(0x00, 0x01, Size::Byte);
        assert_eq!(r, 0xFF);
        assert!(!ccr.z);
        assert!(ccr.n);
        assert!(!ccr.v);
        assert!(ccr.c); // Borrow
    }

    #[test]
    fn and_clears_vc() {
        let (r, ccr) = and(0xFF, 0x0F, Size::Byte);
        assert_eq!(r, 0x0F);
        assert!(!ccr.c);
        assert!(!ccr.v);
    }

    #[test]
    fn sign_extend_byte() {
        assert_eq!(sign_extend(0x80, Size::Byte), 0xFFFF_FF80);
        assert_eq!(sign_extend(0x7F, Size::Byte), 0x7F);
    }

    #[test]
    fn sign_extend_word() {
        assert_eq!(sign_extend(0x8000, Size::Word), 0xFFFF_8000);
        assert_eq!(sign_extend(0x7FFF, Size::Word), 0x7FFF);
    }

    #[test]
    fn mulu_basic() {
        let (r, ccr) = mulu(100, 200);
        assert_eq!(r, 20_000);
        assert!(!ccr.z);
        assert!(!ccr.n);
    }

    #[test]
    fn divu_basic() {
        let (r, ccr) = divu(20_000, 100).unwrap();
        let q = r & 0xFFFF;
        let rem = r >> 16;
        assert_eq!(q, 200);
        assert_eq!(rem, 0);
        assert!(!ccr.v);
    }

    #[test]
    fn divu_by_zero_returns_none() {
        assert!(divu(100, 0).is_none());
    }

    #[test]
    fn lsl_basic() {
        let (r, ccr) = lsl(0x01, 4, Size::Byte);
        assert_eq!(r, 0x10);
        assert!(!ccr.c);
        assert!(!ccr.z);
    }

    #[test]
    fn asr_preserves_sign() {
        let (r, _ccr) = asr(0x80, 1, Size::Byte);
        assert_eq!(r, 0xC0); // sign bit replicated
    }
}
