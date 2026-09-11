//! Effective Address (EA) decoding for the MC68000.
//!
//! The 68000 instruction set is highly regular around its EA modes.
//! Rather than coding each opcode as an isolated special case, we
//! centralise address-mode decoding:
//!
//!   opcode → instruction + size + EA mode + EA register
//!
//! Then `read_ea` / `write_ea` handle the memory/register access
//! uniformly for all instructions.

use crate::bus::Bus;
use crate::cpu::types::Size;
use crate::cpu::Cpu;

/// Decoded effective address mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ea {
    /// Dn — data register direct.
    DataReg(u8),
    /// An — address register direct.
    AddrReg(u8),
    /// (An) — address register indirect.
    AddrIndirect(u8),
    /// (An)+ — post-increment.
    PostIncrement(u8),
    /// -(An) — pre-decrement.
    PreDecrement(u8),
    /// (d16, An) — displacement.
    Displacement(u8, i16),
    /// (d8, An, Xn) — indexed (brief extension word).
    Indexed {
        an: u8,
        xn: u8,
        xn_is_addr: bool,
        xn_long: bool,
        disp: i8,
    },
    /// (xxx).W — absolute short.
    AbsoluteWord(u16),
    /// (xxx).L — absolute long.
    AbsoluteLong(u32),
    /// (d16, PC) — PC-relative with displacement.
    PcDisplacement(i16),
    /// (d8, PC, Xn) — PC-relative indexed.
    PcIndexed {
        xn: u8,
        xn_is_addr: bool,
        xn_long: bool,
        disp: i8,
    },
    /// #imm — immediate data.
    Immediate,
}

impl Ea {
    /// Decode from 6-bit mode/register fields in an opcode.
    ///
    /// `mode` is bits [5:3], `reg` is bits [2:0] of the EA field.
    /// Some modes require extension words, which are fetched via `cpu.fetch_word()`.
    pub fn decode<B: Bus>(mode: u8, reg: u8, cpu: &mut Cpu<B>) -> Self {
        match mode {
            0b000 => Ea::DataReg(reg),
            0b001 => Ea::AddrReg(reg),
            0b010 => Ea::AddrIndirect(reg),
            0b011 => Ea::PostIncrement(reg),
            0b100 => Ea::PreDecrement(reg),
            0b101 => {
                let disp = cpu.fetch_word() as i16;
                Ea::Displacement(reg, disp)
            }
            0b110 => {
                let ext = cpu.fetch_word();
                let xn = ((ext >> 12) & 0x07) as u8;
                let xn_is_addr = ext & 0x8000 != 0;
                let xn_long = ext & 0x0800 != 0;
                let disp = ext as u8 as i8;
                Ea::Indexed {
                    an: reg,
                    xn,
                    xn_is_addr,
                    xn_long,
                    disp,
                }
            }
            0b111 => match reg {
                0b000 => {
                    let addr = cpu.fetch_word();
                    Ea::AbsoluteWord(addr)
                }
                0b001 => {
                    let hi = cpu.fetch_word() as u32;
                    let lo = cpu.fetch_word() as u32;
                    Ea::AbsoluteLong((hi << 16) | lo)
                }
                0b010 => {
                    let disp = cpu.fetch_word() as i16;
                    Ea::PcDisplacement(disp)
                }
                0b011 => {
                    let ext = cpu.fetch_word();
                    let xn = ((ext >> 12) & 0x07) as u8;
                    let xn_is_addr = ext & 0x8000 != 0;
                    let xn_long = ext & 0x0800 != 0;
                    let disp = ext as u8 as i8;
                    Ea::PcIndexed {
                        xn,
                        xn_is_addr,
                        xn_long,
                        disp,
                    }
                }
                0b100 => Ea::Immediate,
                _ => panic!("Invalid EA mode 111/{}", reg),
            },
            _ => panic!("Invalid EA mode {}", mode),
        }
    }
}

/// Compute the effective address (memory location) for an EA that
/// refers to memory. Register-direct modes don't have an address.
pub fn effective_addr<B: Bus>(ea: &Ea, size: Size, cpu: &mut Cpu<B>) -> u32 {
    match *ea {
        Ea::AddrIndirect(an) => cpu.a[an as usize],
        Ea::PostIncrement(an) => {
            let addr = cpu.a[an as usize];
            let inc = increment(an, size);
            cpu.a[an as usize] = cpu.a[an as usize].wrapping_add(inc);
            addr
        }
        Ea::PreDecrement(an) => {
            let dec = increment(an, size);
            cpu.a[an as usize] = cpu.a[an as usize].wrapping_sub(dec);
            cpu.a[an as usize]
        }
        Ea::Displacement(an, disp) => cpu.a[an as usize].wrapping_add(disp as u32),
        Ea::Indexed {
            an,
            xn,
            xn_is_addr,
            xn_long,
            disp,
        } => {
            let base = cpu.a[an as usize];
            let index = index_value(cpu, xn, xn_is_addr, xn_long);
            base.wrapping_add(index).wrapping_add(disp as i32 as u32)
        }
        Ea::AbsoluteWord(w) => w as i16 as u32, // sign-extended to 32
        Ea::AbsoluteLong(l) => l,
        Ea::PcDisplacement(disp) => {
            // PC already advanced past the extension word; the base
            // is the address of the extension word itself (PC − 2).
            cpu.pc.wrapping_sub(2).wrapping_add(disp as u32)
        }
        Ea::PcIndexed {
            xn,
            xn_is_addr,
            xn_long,
            disp,
        } => {
            let base = cpu.pc.wrapping_sub(2);
            let index = index_value(cpu, xn, xn_is_addr, xn_long);
            base.wrapping_add(index).wrapping_add(disp as i32 as u32)
        }
        Ea::DataReg(_) | Ea::AddrReg(_) | Ea::Immediate => {
            panic!("effective_addr called on register-direct or immediate EA");
        }
    }
}

/// Read an operand through an EA.
pub fn read_ea<B: Bus>(ea: &Ea, size: Size, cpu: &mut Cpu<B>) -> u32 {
    match *ea {
        Ea::DataReg(dn) => cpu.d[dn as usize] & size.mask(),
        Ea::AddrReg(an) => cpu.a[an as usize] & size.mask(),
        Ea::Immediate => read_immediate(size, cpu),
        _ => {
            let addr = effective_addr(ea, size, cpu);
            read_mem(addr, size, &mut cpu.bus)
        }
    }
}

/// Write a result through an EA.
pub fn write_ea<B: Bus>(ea: &Ea, size: Size, cpu: &mut Cpu<B>, val: u32) {
    match *ea {
        Ea::DataReg(dn) => {
            let i = dn as usize;
            let m = size.mask();
            cpu.d[i] = (cpu.d[i] & !m) | (val & m);
        }
        Ea::AddrReg(an) => {
            // Writes to An always affect the full 32 bits for word/long;
            // byte writes to An are not encodable on the 68000.
            let i = an as usize;
            match size {
                Size::Word => cpu.a[i] = val as i16 as u32, // sign-extend
                Size::Long => cpu.a[i] = val,
                Size::Byte => panic!("byte write to address register"),
            }
        }
        Ea::Immediate => panic!("write to immediate EA"),
        _ => {
            let addr = effective_addr(ea, size, cpu);
            write_mem(addr, size, &mut cpu.bus, val);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read immediate data from the instruction stream (big-endian).
fn read_immediate<B: Bus>(size: Size, cpu: &mut Cpu<B>) -> u32 {
    match size {
        Size::Byte => {
            let w = cpu.fetch_word();
            (w & 0xFF) as u32
        }
        Size::Word => cpu.fetch_word() as u32,
        Size::Long => {
            let hi = cpu.fetch_word() as u32;
            let lo = cpu.fetch_word() as u32;
            (hi << 16) | lo
        }
    }
}

/// Read from the bus at the given size.
fn read_mem<B: Bus>(addr: u32, size: Size, bus: &mut B) -> u32 {
    match size {
        Size::Byte => bus.read8(addr) as u32,
        Size::Word => bus.read16(addr) as u32,
        Size::Long => bus.read32(addr),
    }
}

/// Write to the bus at the given size.
fn write_mem<B: Bus>(addr: u32, size: Size, bus: &mut B, val: u32) {
    match size {
        Size::Byte => bus.write8(addr, val as u8),
        Size::Word => bus.write16(addr, val as u16),
        Size::Long => bus.write32(addr, val),
    }
}

/// Increment/decrement amount for post-increment and pre-decrement.
///
/// A7 (the stack pointer) always moves by at least 2 to keep the stack
/// word-aligned, even for byte operations.
fn increment(an: u8, size: Size) -> u32 {
    match size {
        Size::Byte => {
            if an == 7 {
                2
            } else {
                1
            }
        }
        Size::Word => 2,
        Size::Long => 4,
    }
}

/// Index register value (used by mode 110 and 111/011).
fn index_value<B: Bus>(cpu: &Cpu<B>, xn: u8, is_addr: bool, long: bool) -> u32 {
    let raw = if is_addr {
        cpu.a[xn as usize]
    } else {
        cpu.d[xn as usize]
    };
    if long {
        raw
    } else {
        raw as i16 as u32 // sign-extend low word
    }
}
