//! Anka — MC68000 emulator entry point.
//!
//! Loads a binary image, boots the emulated CPU, and runs until STOP or halt.

use anka::bus::FlatBus;
use anka::cpu::Cpu;

fn main() {
    println!("Anka — MC68000 Emulator v0.1.0");
    println!();

    // Build a small test program in memory.
    let mut bus = FlatBus::new_16mb();

    // Vector table:
    //   0x000000: Initial SSP = 0x00100000
    //   0x000004: Initial PC  = 0x001000
    let ssp: u32 = 0x0010_0000;
    let entry: u32 = 0x0000_1000;

    // Write vector table (big-endian)
    store_long(&mut bus, 0x000000, ssp);
    store_long(&mut bus, 0x000004, entry);

    // A small test program at 0x1000:
    //   MOVEQ  #42, D0        ; 7042
    //   MOVEQ  #10, D1        ; 720A
    //   ADD.L  D1, D0         ; D081
    //   NOP                   ; 4E71
    //   STOP   #$2700         ; 4E72 2700
    let program: &[u16] = &[
        0x702A, // MOVEQ #42, D0   ($2A = 42)
        0x720A, // MOVEQ #10, D1   ($0A = 10)
        0xD081, // ADD.L D1, D0
        0x4E71, // NOP
        0x4E72, // STOP
        0x2700, // #$2700 (immediate for STOP)
    ];

    let mut addr = entry;
    for &word in program {
        store_word(&mut bus, addr, word);
        addr += 2;
    }

    // Boot the CPU
    let mut cpu = Cpu::new(bus);
    println!(
        "Reset: SSP={:#010X}  PC={:#010X}",
        cpu.a[7], cpu.pc
    );
    println!();

    // Execute until halted
    let mut steps = 0u64;
    while !cpu.halted && steps < 1000 {
        let pc_before = cpu.pc;
        let cycles = cpu.step();
        cpu.cycles += cycles as u64;
        steps += 1;

        println!(
            "  PC={:#010X}  cycles=+{:<3}  D0={:#010X}  D1={:#010X}",
            pc_before, cycles, cpu.d[0], cpu.d[1]
        );
    }

    println!();
    println!(
        "Halted after {} steps, {} total cycles.",
        steps, cpu.cycles
    );
    println!(
        "D0 = {} (expected 52 = 42 + 10)",
        cpu.d[0]
    );
    println!("SR = {:#06X}", cpu.sr.0);
}

fn store_word(bus: &mut FlatBus, addr: u32, val: u16) {
    use anka::bus::Bus;
    bus.write16(addr, val);
}

fn store_long(bus: &mut FlatBus, addr: u32, val: u32) {
    use anka::bus::Bus;
    bus.write32(addr, val);
}
