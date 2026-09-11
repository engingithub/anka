//! Anka ROM Monitor — a tiny interactive monitor for the MC68000.
//!
//! Built as a 68000 binary using the Asm builder.  The monitor provides:
//!
//!   putchar → puts → puthex8/16/32 → dump → peek/poke → jump
//!
//! Register conventions inside the monitor:
//!   A6 = console base (constant, 0x00F00000)
//!   A7 = stack pointer
//!   D0 = scratch / argument / return value
//!   D1-D3 = scratch (clobbered by subroutines)
//!   D4-D5 = preserved across command handlers (loop counters)

use crate::asm::Asm;

pub const CONSOLE_BASE: u32 = 0x00F0_0000;

/// Build the monitor ROM.  Returns the binary image to be loaded at `entry`.
pub fn build(entry: u32) -> Vec<u8> {
    let mut a = Asm::new(entry);

    // ==================================================================
    // Entry point
    // ==================================================================
    a.label("start");
    a.lea(CONSOLE_BASE, 6); // A6 = console base
    a.lea_label("msg_banner", 0);
    a.bsr("puts");

    // ==================================================================
    // Main loop: prompt → getchar → dispatch
    // ==================================================================
    a.label("main");
    a.moveq(b'>' as i8, 0);
    a.bsr("putchar");
    a.moveq(b' ' as i8, 0);
    a.bsr("putchar");
    a.bsr("getchar");

    // Ignore CR/LF (from piped input or terminal)
    a.cmpi_b(0x0D, 0);
    a.beq("main");
    a.cmpi_b(0x0A, 0);
    a.beq("main");

    // Command dispatch
    a.cmpi_b(b'h', 0);
    a.beq("cmd_help");
    a.cmpi_b(b'?', 0);
    a.beq("cmd_help");
    a.cmpi_b(b'd', 0);
    a.beq("cmd_dump");
    a.cmpi_b(b'w', 0);
    a.beq("cmd_write");
    a.cmpi_b(b'g', 0);
    a.beq("cmd_go");
    a.cmpi_b(b'q', 0);
    a.beq("cmd_quit");

    // Unknown command — echo it and print "?"
    a.bsr("putchar");
    a.lea_label("msg_unknown", 0);
    a.bsr("puts");
    a.bra("main");

    // ==================================================================
    // cmd_help
    // ==================================================================
    a.label("cmd_help");
    a.bsr("putchar");
    a.bsr("newline");
    a.lea_label("msg_help", 0);
    a.bsr("puts");
    a.bra("main");

    // ==================================================================
    // cmd_dump: d ADDR — dump 256 bytes (16 rows × 16 cols)
    // ==================================================================
    a.label("cmd_dump");
    a.bsr("putchar"); // echo 'd'
    a.bsr("read_hex"); // D0 = start address
    a.movea_l_dn(0, 0); // A0 = address (before newline clobbers D0)
    a.bsr("newline");
    a.moveq(15, 4); // D4 = 16 rows - 1

    a.label("dump_row");
    a.move_l_an_dn(0, 0); // D0 = current address
    a.bsr("put_hex32");
    a.moveq(b':' as i8, 0);
    a.bsr("putchar");
    a.moveq(b' ' as i8, 0);
    a.bsr("putchar");
    a.moveq(15, 5); // D5 = 16 cols - 1

    a.label("dump_col");
    a.move_b_postinc_dn(0, 0); // D0 = (A0)+
    a.bsr("put_hex8");
    a.moveq(b' ' as i8, 0);
    a.bsr("putchar");
    a.dbra(5, "dump_col");

    a.bsr("newline");
    a.dbra(4, "dump_row");
    a.bra("main");

    // ==================================================================
    // cmd_write: w ADDR VAL — poke one byte
    // ==================================================================
    a.label("cmd_write");
    a.bsr("putchar"); // echo 'w'
    a.bsr("read_hex"); // D0 = address
    a.push_l(0); // save address
    a.bsr("read_hex"); // D0 = value
    a.move_l_dn_dn(0, 1); // D1 = value
    a.pop_l(0); // D0 = address
    a.movea_l_dn(0, 0); // A0 = address
    a.move_b_dn_indirect(1, 0); // (A0) = D1.B
    a.bsr("newline");
    a.lea_label("msg_ok", 0);
    a.bsr("puts");
    a.bra("main");

    // ==================================================================
    // cmd_go: g ADDR — jump to address
    // ==================================================================
    a.label("cmd_go");
    a.bsr("putchar"); // echo 'g'
    a.bsr("read_hex");
    a.movea_l_dn(0, 0); // A0 = target (before newline clobbers D0)
    a.bsr("newline");
    a.jmp_indirect(0); // JMP (A0)

    // ==================================================================
    // cmd_quit: q — halt
    // ==================================================================
    a.label("cmd_quit");
    a.bsr("putchar");
    a.bsr("newline");
    a.stop(0x2700);

    // ==================================================================
    // Subroutines
    // ==================================================================

    // ---- putchar: D0.B → console TX ----
    a.label("putchar");
    a.move_b_dn_indirect(0, 6); // MOVE.B D0, (A6)
    a.rts();

    // ---- getchar: blocking read → D0.B ----
    a.label("getchar");
    a.move_b_disp_dn(3, 6, 0); // MOVE.B 3(A6), D0  [RX_READY]
    a.beq("getchar"); // spin if not ready
    a.move_b_disp_dn(2, 6, 0); // MOVE.B 2(A6), D0  [RX_DATA]
    a.rts();

    // ---- puts: A0 = string → TX until NUL ----
    a.label("puts");
    a.move_b_postinc_dn(0, 0); // MOVE.B (A0)+, D0
    a.beq("puts_done");
    a.bsr("putchar");
    a.bra("puts");
    a.label("puts_done");
    a.rts();

    // ---- newline: print CR + LF ----
    a.label("newline");
    a.moveq(13, 0); // CR
    a.bsr("putchar");
    a.moveq(10, 0); // LF
    a.bsr("putchar");
    a.rts();

    // ---- put_hex_nibble: D0 low nibble → hex ASCII → TX ----
    a.label("put_hex_nibble");
    a.andi_b(0x0F, 0);
    a.cmpi_b(0x0A, 0);
    a.bcs("hex_digit"); // if < 10, it's a digit
    a.addi_b(b'A' - 10, 0); // 'A' - 10 = 55
    a.bsr("putchar");
    a.rts();
    a.label("hex_digit");
    a.addi_b(b'0', 0); // '0' = 48
    a.bsr("putchar");
    a.rts();

    // ---- put_hex8: D0.B → two hex chars ----
    a.label("put_hex8");
    a.push_l(0); // save D0
    a.lsr_b(4, 0); // high nibble
    a.bsr("put_hex_nibble");
    a.pop_l(0); // restore D0
    a.bsr("put_hex_nibble"); // low nibble
    a.rts();

    // ---- put_hex32: D0.L → eight hex chars ----
    //
    // Strategy: SWAP to access high word, LSR.W #8 for high byte.
    //   byte3 = (D0 >> 24), byte2 = (D0 >> 16) & 0xFF
    //   byte1 = (D0 >> 8) & 0xFF, byte0 = D0 & 0xFF
    a.label("put_hex32");
    a.push_l(0); // [orig]
    a.swap(0); // D0 = low:high → high-word in low position
    a.push_l(0); // [swapped, orig]
    a.lsr_w(8, 0); // D0.W = byte3
    a.bsr("put_hex8"); // print byte3
    a.pop_l(0); // D0 = swapped
    a.bsr("put_hex8"); // print byte2 (low byte of swapped)
    a.pop_l(0); // D0 = original
    a.push_l(0); // [orig]
    a.lsr_w(8, 0); // D0.W = byte1
    a.bsr("put_hex8"); // print byte1
    a.pop_l(0); // D0 = original
    a.bsr("put_hex8"); // print byte0
    a.rts();

    // ---- read_hex: read hex string → D0.L ----
    //
    // Reads chars from console. Terminates on CR, LF, or space
    // (space only terminates if at least one digit has been read).
    // Echoes hex digits, skips leading spaces.
    a.label("read_hex");
    a.clr_l(2); // D2 = accumulator
    a.clr_l(3); // D3 = digit count

    a.label("rh_loop");
    a.bsr("getchar");

    // Terminators
    a.cmpi_b(0x0D, 0); // CR
    a.beq("rh_done");
    a.cmpi_b(0x0A, 0); // LF
    a.beq("rh_done");
    a.cmpi_b(b' ', 0); // space
    a.beq("rh_space");

    // Echo valid hex chars
    a.push_l(0);
    a.bsr("putchar");
    a.pop_l(0);

    // Range check: '0'–'9'
    a.cmpi_b(b'0', 0);
    a.bcs("rh_loop"); // < '0' → ignore
    a.cmpi_b(b'9' + 1, 0);
    a.bcs("rh_09"); // <= '9' → digit

    // Range check: 'A'–'F'
    a.cmpi_b(b'A', 0);
    a.bcs("rh_loop");
    a.cmpi_b(b'F' + 1, 0);
    a.bcs("rh_af_upper");

    // Range check: 'a'–'f'
    a.cmpi_b(b'a', 0);
    a.bcs("rh_loop");
    a.cmpi_b(b'f' + 1, 0);
    a.bcs("rh_af_lower");

    a.bra("rh_loop"); // not hex → ignore

    a.label("rh_09");
    a.subi_b(b'0', 0); // nibble = char - '0'
    a.bra("rh_accum");

    a.label("rh_af_upper");
    a.subi_b(b'A' - 10, 0); // nibble = char - 'A' + 10
    a.bra("rh_accum");

    a.label("rh_af_lower");
    a.subi_b(b'a' - 10, 0); // nibble = char - 'a' + 10

    a.label("rh_accum");
    a.lsl_l(4, 2); // D2 <<= 4
    a.andi_b(0x0F, 0); // mask nibble
    a.or_b_dn(0, 2); // D2 |= D0.B
    a.addq_l(1, 3); // D3++
    a.bra("rh_loop");

    a.label("rh_space");
    a.tst_l(3); // have we read any digits?
    a.beq("rh_loop"); // no → skip leading space
    // fall through to rh_done

    a.label("rh_done");
    a.move_l_dn_dn(2, 0); // D0 = accumulator
    a.rts();

    // ==================================================================
    // String data
    // ==================================================================

    a.label("msg_banner");
    a.ascii_z("\r\nAnka Monitor v0.1\r\n");

    a.label("msg_help");
    a.ascii_z(concat!(
        "Commands:\r\n",
        "  d ADDR      Dump 256 bytes at address\r\n",
        "  w ADDR VAL  Write byte at address\r\n",
        "  g ADDR      Go (jump to address)\r\n",
        "  q           Quit (halt CPU)\r\n",
        "  h           This help\r\n",
    ));

    a.label("msg_unknown");
    a.ascii_z(" ?\r\n");

    a.label("msg_ok");
    a.ascii_z("OK\r\n");

    a.assemble()
}
