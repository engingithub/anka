//! Instruction decoder and executor.
//!
//! The 68000 ISA is decoded from 16-bit opcodes. The general pattern is:
//!
//!   opcode → instruction + size + EA mode + EA register
//!
//! Most instructions follow the regular pipeline:
//!
//!   decode opcode
//!       ↓
//!   decode EA
//!       ↓
//!   read source
//!       ↓
//!   bitvector operation
//!       ↓
//!   update CCR
//!       ↓
//!   write destination

use crate::bus::Bus;
use crate::cpu::bv;
use crate::cpu::ea::{self, Ea};
use crate::cpu::types::{Ccr, Size};
use crate::cpu::Cpu;

impl<B: Bus> Cpu<B> {
    /// Execute one instruction, tick devices, and check for pending
    /// interrupts.  Returns the number of cycles consumed.
    pub fn step(&mut self) -> u32 {
        if self.halted {
            // Check if an interrupt can wake us from STOP
            let irq = self.bus.pending_irq();
            if irq > 0 {
                let ipl = self.sr.ipl_mask();
                if irq > ipl || irq == 7 {
                    self.halted = false;
                    self.accept_interrupt(irq);
                    return 44;
                }
            }
            self.bus.tick(4);
            return 4;
        }

        let opcode = self.fetch_word();
        let cycles = self.execute(opcode);

        // Check for bus fault (access violation) — vector 2
        if self.bus.bus_fault().is_some() {
            self.bus.clear_bus_fault();
            self.trap(2);
            return cycles;
        }

        // Advance clocked devices
        self.bus.tick(cycles);

        // Sample interrupt lines (68000 checks after each instruction)
        let irq = self.bus.pending_irq();
        if irq > 0 {
            let ipl = self.sr.ipl_mask();
            if irq > ipl || irq == 7 {
                self.accept_interrupt(irq);
            }
        }

        cycles
    }

    /// Decode and execute a single opcode.
    fn execute(&mut self, opcode: u16) -> u32 {
        // Top 4 bits select the instruction group.
        match opcode >> 12 {
            0x0 => self.group_0000(opcode),
            0x1 => self.move_byte(opcode),
            0x2 => self.move_long(opcode),
            0x3 => self.move_word(opcode),
            0x4 => self.group_0100(opcode),
            0x5 => self.group_0101(opcode),
            0x6 => self.branch(opcode),
            0x7 => self.moveq(opcode),
            0x8 => self.group_1000(opcode),
            0x9 => self.sub_group(opcode),
            0xB => self.group_1011(opcode),
            0xC => self.group_1100(opcode),
            0xD => self.add_group(opcode),
            0xE => self.shift_group(opcode),
            _ => self.illegal(opcode),
        }
    }

    // =======================================================================
    // MOVE (groups 1, 2, 3)
    // =======================================================================

    fn move_byte(&mut self, opcode: u16) -> u32 {
        self.do_move(opcode, Size::Byte)
    }

    fn move_word(&mut self, opcode: u16) -> u32 {
        self.do_move(opcode, Size::Word)
    }

    fn move_long(&mut self, opcode: u16) -> u32 {
        self.do_move(opcode, Size::Long)
    }

    /// Generic MOVE: size is determined by the group bits.
    ///
    /// Encoding: 00ss ddd DDD SSS sss
    ///   ss   = size (from group)
    ///   DDD  = destination mode (bits 8..6)
    ///   ddd  = destination register (bits 11..9)
    ///   SSS  = source mode (bits 5..3)
    ///   sss  = source register (bits 2..0)
    fn do_move(&mut self, opcode: u16, size: Size) -> u32 {
        let src_mode = ((opcode >> 3) & 7) as u8;
        let src_reg = (opcode & 7) as u8;
        let dst_reg = ((opcode >> 9) & 7) as u8;
        let dst_mode = ((opcode >> 6) & 7) as u8;

        let src_ea = Ea::decode(src_mode, src_reg, self);
        let val = ea::read_ea(&src_ea, size, self);

        // MOVE updates N, Z, clears V, C. X is unaffected.
        let old_x = self.sr.x();
        let n = bv::is_negative(val, size);
        let z = (val & size.mask()) == 0;
        self.sr.set_ccr(Ccr {
            n,
            z,
            v: false,
            c: false,
            x: old_x,
        });

        let dst_ea = Ea::decode(dst_mode, dst_reg, self);
        ea::write_ea(&dst_ea, size, self, val);

        4 // Simplified cycle count
    }

    // =======================================================================
    // MOVEQ (group 7): MOVEQ #imm8, Dn
    // =======================================================================

    fn moveq(&mut self, opcode: u16) -> u32 {
        let dn = ((opcode >> 9) & 7) as usize;
        let imm = opcode as u8 as i8 as i32 as u32; // sign-extend to 32
        self.d[dn] = imm;

        let old_x = self.sr.x();
        self.sr.set_ccr(Ccr {
            n: imm & 0x8000_0000 != 0,
            z: imm == 0,
            v: false,
            c: false,
            x: old_x,
        });

        4
    }

    // =======================================================================
    // ADD group (0xD)
    // =======================================================================

    fn add_group(&mut self, opcode: u16) -> u32 {
        let reg = ((opcode >> 9) & 7) as usize;
        let opmode = (opcode >> 6) & 7;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;

        match opmode {
            // ADD <ea>, Dn  (sizes: 000=byte, 001=word, 010=long)
            0b000 | 0b001 | 0b010 => {
                let size = opmode_size_012(opmode);
                let src_ea = Ea::decode(ea_mode, ea_reg, self);
                let src = ea::read_ea(&src_ea, size, self);
                let dst = self.d[reg] & size.mask();
                let (result, ccr) = bv::add(dst, src, size);

                // Preserve upper bits of Dn for byte/word.
                let m = size.mask();
                self.d[reg] = (self.d[reg] & !m) | (result & m);
                self.sr.set_ccr(ccr);
                4
            }
            // ADD Dn, <ea>
            0b100 | 0b101 | 0b110 => {
                let size = opmode_size_456(opmode);
                let dst_ea = Ea::decode(ea_mode, ea_reg, self);
                let dst = ea::read_ea(&dst_ea, size, self);
                let src = self.d[reg] & size.mask();
                let (result, ccr) = bv::add(dst, src, size);
                ea::write_ea(&dst_ea, size, self, result);
                self.sr.set_ccr(ccr);
                8
            }
            // ADDA
            0b011 => {
                // ADDA.W <ea>, An — source is sign-extended to 32.
                let src_ea = Ea::decode(ea_mode, ea_reg, self);
                let src = ea::read_ea(&src_ea, Size::Word, self);
                let src32 = bv::sign_extend(src, Size::Word);
                self.a[reg] = self.a[reg].wrapping_add(src32);
                8 // ADDA does not affect CCR
            }
            0b111 => {
                // ADDA.L <ea>, An
                let src_ea = Ea::decode(ea_mode, ea_reg, self);
                let src = ea::read_ea(&src_ea, Size::Long, self);
                self.a[reg] = self.a[reg].wrapping_add(src);
                8
            }
            _ => self.illegal(opcode),
        }
    }

    // =======================================================================
    // SUB group (0x9)
    // =======================================================================

    fn sub_group(&mut self, opcode: u16) -> u32 {
        let reg = ((opcode >> 9) & 7) as usize;
        let opmode = (opcode >> 6) & 7;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;

        match opmode {
            // SUB <ea>, Dn
            0b000 | 0b001 | 0b010 => {
                let size = opmode_size_012(opmode);
                let src_ea = Ea::decode(ea_mode, ea_reg, self);
                let src = ea::read_ea(&src_ea, size, self);
                let dst = self.d[reg] & size.mask();
                let (result, ccr) = bv::sub(dst, src, size);

                let m = size.mask();
                self.d[reg] = (self.d[reg] & !m) | (result & m);
                self.sr.set_ccr(ccr);
                4
            }
            // SUB Dn, <ea>
            0b100 | 0b101 | 0b110 => {
                let size = opmode_size_456(opmode);
                let dst_ea = Ea::decode(ea_mode, ea_reg, self);
                let dst = ea::read_ea(&dst_ea, size, self);
                let src = self.d[reg] & size.mask();
                let (result, ccr) = bv::sub(dst, src, size);
                ea::write_ea(&dst_ea, size, self, result);
                self.sr.set_ccr(ccr);
                8
            }
            // SUBA.W
            0b011 => {
                let src_ea = Ea::decode(ea_mode, ea_reg, self);
                let src = ea::read_ea(&src_ea, Size::Word, self);
                let src32 = bv::sign_extend(src, Size::Word);
                self.a[reg] = self.a[reg].wrapping_sub(src32);
                8
            }
            // SUBA.L
            0b111 => {
                let src_ea = Ea::decode(ea_mode, ea_reg, self);
                let src = ea::read_ea(&src_ea, Size::Long, self);
                self.a[reg] = self.a[reg].wrapping_sub(src);
                8
            }
            _ => self.illegal(opcode),
        }
    }

    // =======================================================================
    // Branch (group 6): Bcc, BRA, BSR
    // =======================================================================

    fn branch(&mut self, opcode: u16) -> u32 {
        let condition = ((opcode >> 8) & 0xF) as u8;
        let disp8 = opcode as u8 as i8;

        // If displacement is 0, read a 16-bit displacement from the stream.
        let displacement = if disp8 == 0 {
            self.fetch_word() as i16 as i32
        } else {
            disp8 as i32
        };

        // The displacement is relative to (PC + 2) at the start of the
        // instruction — but we already advanced past the opcode, so
        // for disp8 != 0 we use pc directly; for disp8 == 0 we already
        // advanced past the extension word too.
        let target = if disp8 == 0 {
            self.pc.wrapping_sub(2).wrapping_add(displacement as u32)
        } else {
            self.pc.wrapping_add(displacement as u32)
        };

        match condition {
            0b0000 => {
                // BRA — always branch
                self.pc = target;
                10
            }
            0b0001 => {
                // BSR — branch to subroutine
                self.push32(self.pc);
                self.pc = target;
                18
            }
            _ => {
                if self.test_condition(condition) {
                    self.pc = target;
                    10
                } else {
                    8
                }
            }
        }
    }

    // =======================================================================
    // Group 0x0: immediate ops, bit manipulation
    // =======================================================================

    fn group_0000(&mut self, opcode: u16) -> u32 {
        // ORI, ANDI, SUBI, ADDI, EORI, CMPI, and bit ops
        let top = (opcode >> 8) & 0xF;

        match top {
            0x0 if opcode & 0x00C0 != 0x00C0 => self.ori(opcode),
            0x2 if opcode & 0x00C0 != 0x00C0 => self.andi(opcode),
            0x4 if opcode & 0x00C0 != 0x00C0 => self.subi(opcode),
            0x6 if opcode & 0x00C0 != 0x00C0 => self.addi(opcode),
            0xA if opcode & 0x00C0 != 0x00C0 => self.eori(opcode),
            0xC if opcode & 0x00C0 != 0x00C0 => self.cmpi(opcode),
            _ => self.illegal(opcode),
        }
    }

    fn addi(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let imm_ea = Ea::Immediate;
        let imm = ea::read_ea(&imm_ea, size, self);

        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let dst_ea = Ea::decode(ea_mode, ea_reg, self);
        let dst = ea::read_ea(&dst_ea, size, self);

        let (result, ccr) = bv::add(dst, imm, size);
        ea::write_ea(&dst_ea, size, self, result);
        self.sr.set_ccr(ccr);
        8
    }

    fn subi(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let imm_ea = Ea::Immediate;
        let imm = ea::read_ea(&imm_ea, size, self);

        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let dst_ea = Ea::decode(ea_mode, ea_reg, self);
        let dst = ea::read_ea(&dst_ea, size, self);

        let (result, ccr) = bv::sub(dst, imm, size);
        ea::write_ea(&dst_ea, size, self, result);
        self.sr.set_ccr(ccr);
        8
    }

    fn ori(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let imm = ea::read_ea(&Ea::Immediate, size, self);

        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let dst_ea = Ea::decode(ea_mode, ea_reg, self);
        let dst = ea::read_ea(&dst_ea, size, self);

        let (result, ccr) = bv::or(dst, imm, size);
        let old_x = self.sr.x();
        ea::write_ea(&dst_ea, size, self, result);
        self.sr.set_ccr(Ccr { x: old_x, ..ccr });
        8
    }

    fn andi(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let imm = ea::read_ea(&Ea::Immediate, size, self);

        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let dst_ea = Ea::decode(ea_mode, ea_reg, self);
        let dst = ea::read_ea(&dst_ea, size, self);

        let (result, ccr) = bv::and(dst, imm, size);
        let old_x = self.sr.x();
        ea::write_ea(&dst_ea, size, self, result);
        self.sr.set_ccr(Ccr { x: old_x, ..ccr });
        8
    }

    fn eori(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let imm = ea::read_ea(&Ea::Immediate, size, self);

        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let dst_ea = Ea::decode(ea_mode, ea_reg, self);
        let dst = ea::read_ea(&dst_ea, size, self);

        let (result, ccr) = bv::eor(dst, imm, size);
        let old_x = self.sr.x();
        ea::write_ea(&dst_ea, size, self, result);
        self.sr.set_ccr(Ccr { x: old_x, ..ccr });
        8
    }

    fn cmpi(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let imm = ea::read_ea(&Ea::Immediate, size, self);

        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let dst_ea = Ea::decode(ea_mode, ea_reg, self);
        let dst = ea::read_ea(&dst_ea, size, self);

        let ccr = bv::cmp(dst, imm, size);
        let old_x = self.sr.x();
        self.sr.set_ccr(Ccr { x: old_x, ..ccr });
        8
    }

    // =======================================================================
    // Group 0x4: misc (CLR, NEG, NOT, LEA, JSR, JMP, RTS, NOP, …)
    // =======================================================================

    fn group_0100(&mut self, opcode: u16) -> u32 {
        match opcode {
            0x4E71 => 4, // NOP
            0x4E75 => {
                // RTS
                self.pc = self.pop32();
                16
            }
            0x4E70 => {
                // RESET (supervisor only — simplified)
                20
            }
            0x4E72 => {
                // STOP #imm
                let imm = self.fetch_word();
                self.sr.0 = imm;
                self.halted = true;
                4
            }
            0x4E73 => {
                // RTE — return from exception
                let new_sr = self.pop16();
                let new_pc = self.pop32();
                self.set_sr_value(new_sr);
                self.pc = new_pc;
                20
            }
            0x4E76 => {
                // TRAPV — trap on overflow
                if self.sr.v() {
                    self.trap(7);
                }
                4
            }
            0x4E77 => {
                // RTR — return and restore CCR
                let ccr = self.pop16() as u8;
                self.pc = self.pop32();
                let old_sys = self.sr.0 & 0xFF00;
                self.sr.0 = old_sys | ccr as u16;
                20
            }
            op if op & 0xFFF8 == 0x4E50 => {
                // LINK An, #disp
                let an = (op & 7) as usize;
                let disp = self.fetch_word() as i16;
                self.push32(self.a[an]);
                self.a[an] = self.a[7];
                self.a[7] = (self.a[7] as i32 + disp as i32) as u32;
                16
            }
            op if op & 0xFFF8 == 0x4E58 => {
                // UNLK An
                let an = (op & 7) as usize;
                self.a[7] = self.a[an];
                self.a[an] = self.pop32();
                12
            }
            _ => {
                // Further sub-decoding
                let sub = (opcode >> 8) & 0xF;
                match sub {
                    0x0 if opcode & 0xC0 == 0xC0 => self.move_from_sr(opcode),
                    0x4 if opcode & 0xC0 == 0xC0 => self.move_to_ccr(opcode),
                    0x6 if opcode & 0xC0 == 0xC0 => self.move_to_sr(opcode),
                    0x0 if opcode & 0xC0 != 0xC0 => self.negx(opcode),
                    0x2 if opcode & 0xC0 != 0xC0 => self.clr(opcode),
                    0x4 if opcode & 0xC0 != 0xC0 => self.neg_op(opcode),
                    0x6 if opcode & 0xC0 != 0xC0 => self.not_op(opcode),
                    0x8 if opcode & 0xFFF8 == 0x4840 => self.swap(opcode),
                    0x8 if opcode & 0xFFF8 == 0x4880 => self.ext_word(opcode),
                    0x8 if opcode & 0xFFF8 == 0x48C0 => self.ext_long(opcode),
                    0x8 if opcode & 0xFF80 == 0x4880 => self.movem_to_mem(opcode),
                    0x8 if opcode & 0xC0 == 0x40 => self.pea(opcode),
                    0xA if opcode & 0xC0 != 0xC0 => self.tst(opcode),
                    0xC if opcode & 0xFF80 == 0x4C80 => self.movem_to_reg(opcode),
                    0xE if opcode & 0xC0 == 0x80 => self.jsr(opcode),
                    0xE if opcode & 0xC0 == 0xC0 => self.jmp(opcode),
                    _ => {
                        // LEA: 0100 rrr 111 mmm rrr
                        if opcode & 0x01C0 == 0x01C0 {
                            self.lea(opcode)
                        } else {
                            self.illegal(opcode)
                        }
                    }
                }
            }
        }
    }

    fn clr(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let dst_ea = Ea::decode(ea_mode, ea_reg, self);
        ea::write_ea(&dst_ea, size, self, 0);

        let old_x = self.sr.x();
        self.sr.set_ccr(Ccr {
            n: false,
            z: true,
            v: false,
            c: false,
            x: old_x,
        });
        4
    }

    fn neg_op(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let dst_ea = Ea::decode(ea_mode, ea_reg, self);
        let val = ea::read_ea(&dst_ea, size, self);
        let (result, ccr) = bv::neg(val, size);
        ea::write_ea(&dst_ea, size, self, result);
        self.sr.set_ccr(ccr);
        4
    }

    fn negx(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let dst_ea = Ea::decode(ea_mode, ea_reg, self);
        let val = ea::read_ea(&dst_ea, size, self);
        let old_z = self.sr.z();
        let (result, ccr) = bv::subx(0, val, self.sr.x(), old_z, size);
        ea::write_ea(&dst_ea, size, self, result);
        self.sr.set_ccr(ccr);
        4
    }

    fn not_op(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let dst_ea = Ea::decode(ea_mode, ea_reg, self);
        let val = ea::read_ea(&dst_ea, size, self);
        let (result, ccr) = bv::not(val, size);
        let old_x = self.sr.x();
        ea::write_ea(&dst_ea, size, self, result);
        self.sr.set_ccr(Ccr { x: old_x, ..ccr });
        4
    }

    fn tst(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let src_ea = Ea::decode(ea_mode, ea_reg, self);
        let val = ea::read_ea(&src_ea, size, self);

        let old_x = self.sr.x();
        self.sr.set_ccr(Ccr {
            n: bv::is_negative(val, size),
            z: (val & size.mask()) == 0,
            v: false,
            c: false,
            x: old_x,
        });
        4
    }

    fn ext_word(&mut self, opcode: u16) -> u32 {
        // EXT.W Dn — sign-extend byte → word
        let dn = (opcode & 7) as usize;
        let val = (self.d[dn] as u8 as i8 as i16 as u16) as u32;
        self.d[dn] = (self.d[dn] & 0xFFFF_0000) | val;

        let old_x = self.sr.x();
        self.sr.set_ccr(Ccr {
            n: val & 0x8000 != 0,
            z: (val & 0xFFFF) == 0,
            v: false,
            c: false,
            x: old_x,
        });
        4
    }

    fn ext_long(&mut self, opcode: u16) -> u32 {
        // EXT.L Dn — sign-extend word → long
        let dn = (opcode & 7) as usize;
        let val = self.d[dn] as u16 as i16 as i32 as u32;
        self.d[dn] = val;

        let old_x = self.sr.x();
        self.sr.set_ccr(Ccr {
            n: val & 0x8000_0000 != 0,
            z: val == 0,
            v: false,
            c: false,
            x: old_x,
        });
        4
    }

    fn swap(&mut self, opcode: u16) -> u32 {
        let dn = (opcode & 7) as usize;
        let val = self.d[dn];
        self.d[dn] = (val >> 16) | (val << 16);
        let result = self.d[dn];

        let old_x = self.sr.x();
        self.sr.set_ccr(Ccr {
            n: result & 0x8000_0000 != 0,
            z: result == 0,
            v: false,
            c: false,
            x: old_x,
        });
        4
    }

    fn lea(&mut self, opcode: u16) -> u32 {
        let an = ((opcode >> 9) & 7) as usize;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let src_ea = Ea::decode(ea_mode, ea_reg, self);
        let addr = ea::effective_addr(&src_ea, Size::Long, self);
        self.a[an] = addr;
        4
    }

    fn pea(&mut self, opcode: u16) -> u32 {
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let src_ea = Ea::decode(ea_mode, ea_reg, self);
        let addr = ea::effective_addr(&src_ea, Size::Long, self);
        self.push32(addr);
        12
    }

    fn jsr(&mut self, opcode: u16) -> u32 {
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let src_ea = Ea::decode(ea_mode, ea_reg, self);
        let addr = ea::effective_addr(&src_ea, Size::Long, self);
        self.push32(self.pc);
        self.pc = addr;
        16
    }

    fn jmp(&mut self, opcode: u16) -> u32 {
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let src_ea = Ea::decode(ea_mode, ea_reg, self);
        let addr = ea::effective_addr(&src_ea, Size::Long, self);
        self.pc = addr;
        8
    }

    // =======================================================================
    // Group 0x5: ADDQ / SUBQ / Scc / DBcc
    // =======================================================================

    fn group_0101(&mut self, opcode: u16) -> u32 {
        if opcode & 0x00C0 == 0x00C0 {
            // Scc or DBcc
            if opcode & 0x0038 == 0x0008 {
                self.dbcc(opcode)
            } else {
                self.scc(opcode)
            }
        } else if opcode & 0x0100 == 0 {
            self.addq(opcode)
        } else {
            self.subq(opcode)
        }
    }

    fn addq(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let imm = ((opcode >> 9) & 7) as u32;
        let imm = if imm == 0 { 8 } else { imm };

        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;

        if ea_mode == 0b001 {
            // ADDQ to An: full 32-bit add, no flags.
            self.a[ea_reg as usize] = self.a[ea_reg as usize].wrapping_add(imm);
            4
        } else {
            let dst_ea = Ea::decode(ea_mode, ea_reg, self);
            let dst = ea::read_ea(&dst_ea, size, self);
            let (result, ccr) = bv::add(dst, imm, size);
            ea::write_ea(&dst_ea, size, self, result);
            self.sr.set_ccr(ccr);
            4
        }
    }

    fn subq(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let imm = ((opcode >> 9) & 7) as u32;
        let imm = if imm == 0 { 8 } else { imm };

        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;

        if ea_mode == 0b001 {
            self.a[ea_reg as usize] = self.a[ea_reg as usize].wrapping_sub(imm);
            4
        } else {
            let dst_ea = Ea::decode(ea_mode, ea_reg, self);
            let dst = ea::read_ea(&dst_ea, size, self);
            let (result, ccr) = bv::sub(dst, imm, size);
            ea::write_ea(&dst_ea, size, self, result);
            self.sr.set_ccr(ccr);
            4
        }
    }

    fn scc(&mut self, opcode: u16) -> u32 {
        let condition = ((opcode >> 8) & 0xF) as u8;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let dst_ea = Ea::decode(ea_mode, ea_reg, self);

        let val = if self.test_condition(condition) {
            0xFF
        } else {
            0x00
        };
        ea::write_ea(&dst_ea, Size::Byte, self, val as u32);
        4
    }

    fn dbcc(&mut self, opcode: u16) -> u32 {
        let condition = ((opcode >> 8) & 0xF) as u8;
        let dn = (opcode & 7) as usize;
        let disp = self.fetch_word() as i16;

        if self.test_condition(condition) {
            // Condition true: do not decrement, do not branch.
            return 12;
        }

        // Decrement Dn.W (only the low word).
        let counter = (self.d[dn] as u16).wrapping_sub(1);
        self.d[dn] = (self.d[dn] & 0xFFFF_0000) | counter as u32;

        if counter != 0xFFFF {
            // Branch
            self.pc = self.pc.wrapping_sub(2).wrapping_add(disp as u32);
            10
        } else {
            // Counter expired, fall through.
            14
        }
    }

    // =======================================================================
    // Group 0x8: OR / DIVU / DIVS / SBCD
    // =======================================================================

    fn group_1000(&mut self, opcode: u16) -> u32 {
        let opmode = (opcode >> 6) & 7;

        if opmode == 0b011 {
            return self.divu(opcode);
        }
        if opmode == 0b111 {
            return self.divs_op(opcode);
        }

        // OR <ea>, Dn / OR Dn, <ea>
        let reg = ((opcode >> 9) & 7) as usize;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;

        match opmode {
            0b000 | 0b001 | 0b010 => {
                let size = opmode_size_012(opmode);
                let src_ea = Ea::decode(ea_mode, ea_reg, self);
                let src = ea::read_ea(&src_ea, size, self);
                let dst = self.d[reg] & size.mask();
                let (result, ccr) = bv::or(dst, src, size);
                let old_x = self.sr.x();
                let m = size.mask();
                self.d[reg] = (self.d[reg] & !m) | (result & m);
                self.sr.set_ccr(Ccr { x: old_x, ..ccr });
                4
            }
            0b100 | 0b101 | 0b110 => {
                let size = opmode_size_456(opmode);
                let dst_ea = Ea::decode(ea_mode, ea_reg, self);
                let dst = ea::read_ea(&dst_ea, size, self);
                let src = self.d[reg] & size.mask();
                let (result, ccr) = bv::or(dst, src, size);
                let old_x = self.sr.x();
                ea::write_ea(&dst_ea, size, self, result);
                self.sr.set_ccr(Ccr { x: old_x, ..ccr });
                8
            }
            _ => self.illegal(opcode),
        }
    }

    fn divu(&mut self, opcode: u16) -> u32 {
        let dn = ((opcode >> 9) & 7) as usize;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let src_ea = Ea::decode(ea_mode, ea_reg, self);
        let divisor = ea::read_ea(&src_ea, Size::Word, self) as u16;
        let dividend = self.d[dn];

        match bv::divu(dividend, divisor) {
            None => {
                self.trap(5); // Divide by zero
                38
            }
            Some((result, ccr)) => {
                if !ccr.v {
                    self.d[dn] = result;
                }
                let old_x = self.sr.x();
                self.sr.set_ccr(Ccr { x: old_x, ..ccr });
                140 // Worst-case DIVU timing
            }
        }
    }

    fn divs_op(&mut self, opcode: u16) -> u32 {
        let dn = ((opcode >> 9) & 7) as usize;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let src_ea = Ea::decode(ea_mode, ea_reg, self);
        let divisor = ea::read_ea(&src_ea, Size::Word, self) as u16;
        let dividend = self.d[dn];

        match bv::divs(dividend, divisor) {
            None => {
                self.trap(5);
                38
            }
            Some((result, ccr)) => {
                if !ccr.v {
                    self.d[dn] = result;
                }
                let old_x = self.sr.x();
                self.sr.set_ccr(Ccr { x: old_x, ..ccr });
                158
            }
        }
    }

    // =======================================================================
    // Group 0xB: CMP / CMPA / EOR
    // =======================================================================

    fn group_1011(&mut self, opcode: u16) -> u32 {
        let reg = ((opcode >> 9) & 7) as usize;
        let opmode = (opcode >> 6) & 7;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;

        match opmode {
            // CMP <ea>, Dn
            0b000 | 0b001 | 0b010 => {
                let size = opmode_size_012(opmode);
                let src_ea = Ea::decode(ea_mode, ea_reg, self);
                let src = ea::read_ea(&src_ea, size, self);
                let dst = self.d[reg] & size.mask();
                let ccr = bv::cmp(dst, src, size);
                let old_x = self.sr.x();
                self.sr.set_ccr(Ccr { x: old_x, ..ccr });
                4
            }
            // CMPA.W
            0b011 => {
                let src_ea = Ea::decode(ea_mode, ea_reg, self);
                let src = ea::read_ea(&src_ea, Size::Word, self);
                let src32 = bv::sign_extend(src, Size::Word);
                let ccr = bv::cmp(self.a[reg], src32, Size::Long);
                let old_x = self.sr.x();
                self.sr.set_ccr(Ccr { x: old_x, ..ccr });
                6
            }
            // CMPA.L
            0b111 => {
                let src_ea = Ea::decode(ea_mode, ea_reg, self);
                let src = ea::read_ea(&src_ea, Size::Long, self);
                let ccr = bv::cmp(self.a[reg], src, Size::Long);
                let old_x = self.sr.x();
                self.sr.set_ccr(Ccr { x: old_x, ..ccr });
                6
            }
            // EOR Dn, <ea>
            0b100 | 0b101 | 0b110 => {
                let size = opmode_size_456(opmode);
                let dst_ea = Ea::decode(ea_mode, ea_reg, self);
                let dst = ea::read_ea(&dst_ea, size, self);
                let src = self.d[reg] & size.mask();
                let (result, ccr) = bv::eor(src, dst, size);
                let old_x = self.sr.x();
                ea::write_ea(&dst_ea, size, self, result);
                self.sr.set_ccr(Ccr { x: old_x, ..ccr });
                8
            }
            _ => self.illegal(opcode),
        }
    }

    // =======================================================================
    // Group 0xC: AND / MULU / MULS / EXG
    // =======================================================================

    fn group_1100(&mut self, opcode: u16) -> u32 {
        let opmode = (opcode >> 6) & 7;

        if opmode == 0b011 {
            return self.mulu_op(opcode);
        }
        if opmode == 0b111 {
            return self.muls_op(opcode);
        }

        // AND <ea>, Dn / AND Dn, <ea>
        let reg = ((opcode >> 9) & 7) as usize;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;

        match opmode {
            0b000 | 0b001 | 0b010 => {
                let size = opmode_size_012(opmode);
                let src_ea = Ea::decode(ea_mode, ea_reg, self);
                let src = ea::read_ea(&src_ea, size, self);
                let dst = self.d[reg] & size.mask();
                let (result, ccr) = bv::and(dst, src, size);
                let old_x = self.sr.x();
                let m = size.mask();
                self.d[reg] = (self.d[reg] & !m) | (result & m);
                self.sr.set_ccr(Ccr { x: old_x, ..ccr });
                4
            }
            0b100 | 0b101 | 0b110 => {
                let size = opmode_size_456(opmode);
                let dst_ea = Ea::decode(ea_mode, ea_reg, self);
                let dst = ea::read_ea(&dst_ea, size, self);
                let src = self.d[reg] & size.mask();
                let (result, ccr) = bv::and(dst, src, size);
                let old_x = self.sr.x();
                ea::write_ea(&dst_ea, size, self, result);
                self.sr.set_ccr(Ccr { x: old_x, ..ccr });
                8
            }
            _ => self.illegal(opcode),
        }
    }

    fn mulu_op(&mut self, opcode: u16) -> u32 {
        let dn = ((opcode >> 9) & 7) as usize;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let src_ea = Ea::decode(ea_mode, ea_reg, self);
        let src = ea::read_ea(&src_ea, Size::Word, self) as u16;
        let dst = self.d[dn] as u16;
        let (result, ccr) = bv::mulu(dst, src);
        self.d[dn] = result;
        let old_x = self.sr.x();
        self.sr.set_ccr(Ccr { x: old_x, ..ccr });
        70
    }

    fn muls_op(&mut self, opcode: u16) -> u32 {
        let dn = ((opcode >> 9) & 7) as usize;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let src_ea = Ea::decode(ea_mode, ea_reg, self);
        let src = ea::read_ea(&src_ea, Size::Word, self) as u16;
        let dst = self.d[dn] as u16;
        let (result, ccr) = bv::muls(dst, src);
        self.d[dn] = result;
        let old_x = self.sr.x();
        self.sr.set_ccr(Ccr { x: old_x, ..ccr });
        70
    }

    // =======================================================================
    // Group 0xE: shifts and rotates
    // =======================================================================

    fn shift_group(&mut self, opcode: u16) -> u32 {
        let size = size_from_bits_6_7(opcode);
        let direction = (opcode >> 8) & 1; // 0 = right, 1 = left
        let ir = (opcode >> 5) & 1; // 0 = count in field, 1 = count in reg
        let kind = (opcode >> 3) & 3; // 00=AS, 01=LS, 10=ROX, 11=RO

        let dn = (opcode & 7) as usize;
        let count_field = ((opcode >> 9) & 7) as u32;

        let count = if ir == 1 {
            self.d[count_field as usize] % 64
        } else if count_field == 0 {
            8
        } else {
            count_field
        };

        let val = self.d[dn];

        let (result, mut ccr) = match (kind, direction) {
            (0b00, 1) => bv::asl(val, count, size),
            (0b00, _) => bv::asr(val, count, size),
            (0b01, 1) => bv::lsl(val, count, size),
            (0b01, _) => bv::lsr(val, count, size),
            (0b11, 1) => bv::rol(val, count, size),
            (0b11, _) => bv::ror(val, count, size),
            // ROXL/ROXR not yet implemented — treat as NOP for now
            _ => (val & size.mask(), self.sr.ccr()),
        };

        // Preserve X if count == 0
        if count == 0 {
            ccr.x = self.sr.x();
        }

        let m = size.mask();
        self.d[dn] = (self.d[dn] & !m) | (result & m);
        self.sr.set_ccr(ccr);
        6 + 2 * count
    }

    // =======================================================================
    // Condition testing
    // =======================================================================

    fn test_condition(&self, cc: u8) -> bool {
        let sr = self.sr;
        match cc {
            0x0 => true,                                    // T  (always)
            0x1 => false,                                   // F  (never)
            0x2 => !sr.c() && !sr.z(),                     // HI
            0x3 => sr.c() || sr.z(),                        // LS
            0x4 => !sr.c(),                                 // CC (HS)
            0x5 => sr.c(),                                  // CS (LO)
            0x6 => !sr.z(),                                 // NE
            0x7 => sr.z(),                                  // EQ
            0x8 => !sr.v(),                                 // VC
            0x9 => sr.v(),                                  // VS
            0xA => !sr.n(),                                 // PL
            0xB => sr.n(),                                  // MI
            0xC => sr.n() == sr.v(),                        // GE
            0xD => sr.n() != sr.v(),                        // LT
            0xE => !sr.z() && (sr.n() == sr.v()),           // GT
            0xF => sr.z() || (sr.n() != sr.v()),            // LE
            _ => unreachable!(),
        }
    }

    // =======================================================================
    // MOVEM — move multiple registers
    // =======================================================================

    /// MOVEM registers to memory: 0100 1000 1s mmm rrr
    /// For pre-decrement mode -(An), the register list is reversed:
    /// bit 0 = A7, bit 1 = A6, ..., bit 7 = A0, bit 8 = D7, ..., bit 15 = D0
    fn movem_to_mem(&mut self, opcode: u16) -> u32 {
        let long = opcode & 0x0040 != 0;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let mask = self.fetch_word();

        if ea_mode == 4 {
            // Pre-decrement mode -(An): register order is reversed
            let an = ea_reg as usize;
            for bit in 0..16u16 {
                if mask & (1 << bit) != 0 {
                    // bit 0=A7, 1=A6...7=A0, 8=D7, 9=D6...15=D0
                    let val = if bit < 8 {
                        self.a[7 - bit as usize]
                    } else {
                        self.d[15 - bit as usize]
                    };
                    if long {
                        self.a[an] = self.a[an].wrapping_sub(4);
                        self.bus.write32(self.a[an], val);
                    } else {
                        self.a[an] = self.a[an].wrapping_sub(2);
                        self.bus.write16(self.a[an], val as u16);
                    }
                }
            }
        } else {
            // Other modes: normal register order
            // bit 0=D0, 1=D1...7=D7, 8=A0, 9=A1...15=A7
            let ea = Ea::decode(ea_mode, ea_reg, self);
            let mut addr = match &ea {
                Ea::AddrIndirect(r) => self.a[*r as usize],
                Ea::Displacement(r, d) => (self.a[*r as usize] as i32 + *d as i32) as u32,
                Ea::AbsoluteLong(a) => *a,
                Ea::AbsoluteWord(a) => *a as i16 as i32 as u32,
                _ => { self.illegal(opcode); return 4; }
            };
            for bit in 0..16u16 {
                if mask & (1 << bit) != 0 {
                    let val = if bit < 8 { self.d[bit as usize] }
                              else { self.a[(bit - 8) as usize] };
                    if long {
                        self.bus.write32(addr, val);
                        addr = addr.wrapping_add(4);
                    } else {
                        self.bus.write16(addr, val as u16);
                        addr = addr.wrapping_add(2);
                    }
                }
            }
        }
        8
    }

    /// MOVEM memory to registers: 0100 1100 1s mmm rrr
    /// Normal register order: bit 0=D0...7=D7, 8=A0...15=A7
    fn movem_to_reg(&mut self, opcode: u16) -> u32 {
        let long = opcode & 0x0040 != 0;
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let mask = self.fetch_word();

        if ea_mode == 3 {
            // Post-increment mode (An)+
            let an = ea_reg as usize;
            for bit in 0..16u16 {
                if mask & (1 << bit) != 0 {
                    if long {
                        let val = self.bus.read32(self.a[an]);
                        self.a[an] = self.a[an].wrapping_add(4);
                        if bit < 8 { self.d[bit as usize] = val; }
                        else { self.a[(bit - 8) as usize] = val; }
                    } else {
                        let val = self.bus.read16(self.a[an]) as i16 as i32 as u32;
                        self.a[an] = self.a[an].wrapping_add(2);
                        if bit < 8 { self.d[bit as usize] = val; }
                        else { self.a[(bit - 8) as usize] = val; }
                    }
                }
            }
        } else {
            let ea = Ea::decode(ea_mode, ea_reg, self);
            let mut addr = match &ea {
                Ea::AddrIndirect(r) => self.a[*r as usize],
                Ea::Displacement(r, d) => (self.a[*r as usize] as i32 + *d as i32) as u32,
                Ea::AbsoluteLong(a) => *a,
                Ea::AbsoluteWord(a) => *a as i16 as i32 as u32,
                _ => { self.illegal(opcode); return 4; }
            };
            for bit in 0..16u16 {
                if mask & (1 << bit) != 0 {
                    if long {
                        let val = self.bus.read32(addr);
                        addr = addr.wrapping_add(4);
                        if bit < 8 { self.d[bit as usize] = val; }
                        else { self.a[(bit - 8) as usize] = val; }
                    } else {
                        let val = self.bus.read16(addr) as i16 as i32 as u32;
                        addr = addr.wrapping_add(2);
                        if bit < 8 { self.d[bit as usize] = val; }
                        else { self.a[(bit - 8) as usize] = val; }
                    }
                }
            }
        }
        12
    }

    // =======================================================================
    // MOVE to/from SR, CCR — privilege-sensitive register access
    // =======================================================================

    /// Set SR with proper supervisor/user stack switching.
    fn set_sr_value(&mut self, new_sr: u16) {
        let was_super = self.sr.supervisor();
        let will_be_super = new_sr & 0x2000 != 0;

        if was_super && !will_be_super {
            self.ssp = self.a[7];
            self.a[7] = self.usp;
        } else if !was_super && will_be_super {
            self.usp = self.a[7];
            self.a[7] = self.ssp;
        }

        self.sr.0 = new_sr;
        self.bus.set_supervisor(will_be_super);
    }

    /// MOVE SR, <ea>  (0x40C0) — read SR to destination
    fn move_from_sr(&mut self, opcode: u16) -> u32 {
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let ea = Ea::decode(ea_mode, ea_reg, self);
        ea::write_ea(&ea, Size::Word, self, self.sr.0 as u32);
        6
    }

    /// MOVE <ea>, CCR  (0x44C0) — write CCR only (low byte of SR)
    fn move_to_ccr(&mut self, opcode: u16) -> u32 {
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let ea = Ea::decode(ea_mode, ea_reg, self);
        let val = ea::read_ea(&ea, Size::Word, self) as u16;
        self.sr.0 = (self.sr.0 & 0xFF00) | (val & 0xFF);
        12
    }

    /// MOVE <ea>, SR  (0x46C0) — write full SR (privileged)
    fn move_to_sr(&mut self, opcode: u16) -> u32 {
        let ea_mode = ((opcode >> 3) & 7) as u8;
        let ea_reg = (opcode & 7) as u8;
        let ea = Ea::decode(ea_mode, ea_reg, self);
        let val = ea::read_ea(&ea, Size::Word, self) as u16;
        self.set_sr_value(val);
        12
    }

    // =======================================================================
    // Traps / exceptions
    // =======================================================================

    /// Process a software trap or exception.
    /// Saves SR and PC, enters supervisor mode, jumps to the vector.
    fn trap(&mut self, vector: u8) {
        let old_sr = self.sr.0;

        // Switch to supervisor stack if currently in user mode
        if !self.sr.supervisor() {
            self.usp = self.a[7];
            self.a[7] = self.ssp;
            self.sr.0 |= 0x2000;
        }
        self.bus.set_supervisor(true);

        // Build exception frame: push PC, then SR
        self.push32(self.pc);
        self.push16(old_sr);

        // Clear trace
        self.sr.0 &= !0x8000;

        // Load handler from vector table
        let vec_addr = (vector as u32) * 4;
        self.pc = self.bus.read32(vec_addr);
    }

    /// Accept a hardware interrupt at the given level (1–7).
    /// Uses auto-vectored interrupt vectors 25–31.
    pub fn accept_interrupt(&mut self, level: u8) {
        let old_sr = self.sr.0;

        // Switch to supervisor stack if currently in user mode
        if !self.sr.supervisor() {
            self.usp = self.a[7];
            self.a[7] = self.ssp;
        }

        // Enter supervisor mode, mask to this interrupt level, clear trace
        self.sr.0 = (old_sr | 0x2000) & !0x8000;
        self.sr.0 = (self.sr.0 & 0xF8FF) | ((level as u16) << 8);
        self.bus.set_supervisor(true);

        // Build exception frame: push PC, then SR (68000 group 1 frame)
        self.push32(self.pc);
        self.push16(old_sr);

        // Auto-vectored: level N → vector 24 + N → address (24+N)*4
        let vector = 24 + level as u32;
        self.pc = self.bus.read32(vector * 4);
    }

    fn illegal(&mut self, _opcode: u16) -> u32 {
        self.trap(4); // Illegal instruction vector
        34
    }
}

// ---------------------------------------------------------------------------
// Size decoding helpers
// ---------------------------------------------------------------------------

/// Decode size from bits [7:6] (used by most instructions):
///   00 = Byte, 01 = Word, 10 = Long.
fn size_from_bits_6_7(opcode: u16) -> Size {
    match (opcode >> 6) & 3 {
        0b00 => Size::Byte,
        0b01 => Size::Word,
        0b10 => Size::Long,
        _ => panic!("Invalid size encoding {}", (opcode >> 6) & 3),
    }
}

/// Opmode 000/001/010 → Byte/Word/Long.
fn opmode_size_012(opmode: u16) -> Size {
    match opmode {
        0 => Size::Byte,
        1 => Size::Word,
        2 => Size::Long,
        _ => unreachable!(),
    }
}

/// Opmode 100/101/110 → Byte/Word/Long.
fn opmode_size_456(opmode: u16) -> Size {
    match opmode {
        4 => Size::Byte,
        5 => Size::Word,
        6 => Size::Long,
        _ => unreachable!(),
    }
}
