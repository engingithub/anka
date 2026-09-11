//! Anka — MC68000 emulator entry point.
//!
//! Loads a raw binary image into emulated memory and executes it,
//! or runs a built-in self-test if no file is given.

use std::env;
use std::fs;
use std::process;

use anka::bus::{Bus, FlatBus};
use anka::cpu::Cpu;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("anka {}", VERSION);
        return;
    }

    // Parse options
    let mut rom_path: Option<String> = None;
    let mut load_addr: u32 = 0x0000_1000;
    let mut max_steps: u64 = 10_000_000;
    let mut trace = false;
    let mut self_test = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--load-addr" => {
                i += 1;
                load_addr = parse_u32(&args, i, "--load-addr");
            }
            "--max-steps" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --max-steps requires a value");
                    process::exit(2);
                }
                max_steps = args[i]
                    .replace('_', "")
                    .parse()
                    .unwrap_or_else(|_| {
                        eprintln!("error: invalid --max-steps value: {}", args[i]);
                        process::exit(2);
                    });
            }
            "--trace" | "-t" => trace = true,
            "--self-test" => self_test = true,
            arg if arg.starts_with('-') => {
                eprintln!("error: unknown option: {}", arg);
                eprintln!("Try 'anka --help' for usage.");
                process::exit(2);
            }
            _ => {
                if rom_path.is_some() {
                    eprintln!("error: multiple ROM files not supported (got '{}')", args[i]);
                    process::exit(2);
                }
                rom_path = Some(args[i].clone());
            }
        }
        i += 1;
    }

    if self_test || rom_path.is_none() {
        if rom_path.is_none() && !self_test {
            println!("No ROM file given — running built-in self-test.");
            println!("Try 'anka --help' for usage.");
            println!();
        }
        run_self_test(trace);
        return;
    }

    // Load ROM file
    let path = rom_path.unwrap();
    let data = fs::read(&path).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{}': {}", path, e);
        process::exit(1);
    });

    if data.is_empty() {
        eprintln!("error: ROM file '{}' is empty", path);
        process::exit(1);
    }

    println!("Anka — MC68000 Emulator v{}", VERSION);
    println!();
    println!("  ROM:       {}  ({} bytes)", path, data.len());
    println!("  Load addr: {:#010X}", load_addr);
    println!("  Max steps: {}", max_steps);
    println!("  Trace:     {}", if trace { "on" } else { "off" });
    println!();

    let mut bus = FlatBus::new_16mb();

    // If the ROM is loaded at address 0, it includes its own vector table.
    // Otherwise, synthesize a minimal vector table pointing at load_addr.
    if load_addr == 0 {
        bus.load(0, &data);
    } else {
        // Vector table: SSP at 0x00100000, PC at load_addr
        bus.write32(0x000000, 0x0010_0000);
        bus.write32(0x000004, load_addr);
        bus.load(load_addr, &data);
    }

    let mut cpu = Cpu::new(bus);
    println!(
        "Reset: SSP={:#010X}  PC={:#010X}",
        cpu.a[7], cpu.pc
    );
    println!();

    run_cpu(&mut cpu, max_steps, trace);
    print_state(&cpu);
}

// ---------------------------------------------------------------------------
// Built-in self-test
// ---------------------------------------------------------------------------

fn run_self_test(trace: bool) {
    println!("Anka — MC68000 Emulator v{}", VERSION);
    println!("Running built-in self-test: MOVEQ #42,D0 + MOVEQ #10,D1 → ADD.L D1,D0");
    println!();

    let mut bus = FlatBus::new_16mb();

    let ssp: u32 = 0x0010_0000;
    let entry: u32 = 0x0000_1000;

    bus.write32(0x000000, ssp);
    bus.write32(0x000004, entry);

    // MOVEQ #42,D0 ; MOVEQ #10,D1 ; ADD.L D1,D0 ; NOP ; STOP #$2700
    let program: &[u16] = &[0x702A, 0x720A, 0xD081, 0x4E71, 0x4E72, 0x2700];

    let mut addr = entry;
    for &word in program {
        bus.write16(addr, word);
        addr += 2;
    }

    let mut cpu = Cpu::new(bus);
    println!("Reset: SSP={:#010X}  PC={:#010X}", cpu.a[7], cpu.pc);
    println!();

    run_cpu(&mut cpu, 1000, trace);

    println!();
    let expected = 52u32;
    let actual = cpu.d[0];
    if actual == expected {
        println!("PASS: D0 = {} (42 + 10 = 52)", actual);
    } else {
        println!("FAIL: D0 = {} (expected {})", actual, expected);
        process::exit(1);
    }
    print_state(&cpu);
}

// ---------------------------------------------------------------------------
// Execution loop
// ---------------------------------------------------------------------------

fn run_cpu<B: Bus>(cpu: &mut Cpu<B>, max_steps: u64, trace: bool) {
    let mut steps = 0u64;

    while !cpu.halted && steps < max_steps {
        let pc_before = cpu.pc;
        let cycles = cpu.step();
        cpu.cycles += cycles as u64;
        steps += 1;

        if trace {
            println!(
                "  PC={:#010X}  cycles=+{:<3}  D0={:#010X}  D1={:#010X}  D2={:#010X}  SR={:#06X}",
                pc_before, cycles, cpu.d[0], cpu.d[1], cpu.d[2], cpu.sr.0
            );
        }
    }

    if !cpu.halted && steps >= max_steps {
        eprintln!(
            "warning: execution limit reached ({} steps). Use --max-steps to increase.",
            max_steps
        );
    }

    println!(
        "Halted after {} steps, {} total cycles.",
        steps, cpu.cycles
    );
}

fn print_state<B: Bus>(cpu: &Cpu<B>) {
    println!();
    println!("  D0={:#010X}  D1={:#010X}  D2={:#010X}  D3={:#010X}", cpu.d[0], cpu.d[1], cpu.d[2], cpu.d[3]);
    println!("  D4={:#010X}  D5={:#010X}  D6={:#010X}  D7={:#010X}", cpu.d[4], cpu.d[5], cpu.d[6], cpu.d[7]);
    println!("  A0={:#010X}  A1={:#010X}  A2={:#010X}  A3={:#010X}", cpu.a[0], cpu.a[1], cpu.a[2], cpu.a[3]);
    println!("  A4={:#010X}  A5={:#010X}  A6={:#010X}  A7={:#010X}", cpu.a[4], cpu.a[5], cpu.a[6], cpu.a[7]);
    println!("  PC={:#010X}  SR={:#06X}", cpu.pc, cpu.sr.0);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_u32(args: &[String], i: usize, flag: &str) -> u32 {
    if i >= args.len() {
        eprintln!("error: {} requires a value", flag);
        process::exit(2);
    }
    let s = args[i].trim_start_matches("0x").trim_start_matches("0X");
    if args[i].starts_with("0x") || args[i].starts_with("0X") {
        u32::from_str_radix(s, 16).unwrap_or_else(|_| {
            eprintln!("error: invalid {} value: {}", flag, args[i]);
            process::exit(2);
        })
    } else {
        args[i].parse().unwrap_or_else(|_| {
            eprintln!("error: invalid {} value: {}", flag, args[i]);
            process::exit(2);
        })
    }
}

fn print_help() {
    println!(
        "\
Anka — MC68000 CPU Emulator v{}

USAGE:
    anka [OPTIONS] [ROM_FILE]

DESCRIPTION:
    Loads a raw binary ROM image into emulated MC68000 memory and
    executes it. If no ROM file is given, runs a built-in self-test.

    The ROM is loaded at --load-addr (default 0x1000) and a minimal
    vector table is synthesised (SSP=0x100000, PC=load-addr). If
    --load-addr is 0, the ROM is expected to contain its own vector
    table starting at address 0.

ARGUMENTS:
    ROM_FILE            Raw binary file to load into memory

OPTIONS:
    --load-addr ADDR    Load address for the ROM (default: 0x1000)
                        Accepts decimal or 0x-prefixed hex
    --max-steps N       Stop after N instructions (default: 10,000,000)
    --trace, -t         Print every instruction as it executes
    --self-test         Run the built-in self-test and exit
    --version, -V       Print version and exit
    --help, -h          Print this help and exit

EXAMPLES:
    anka                            Run built-in self-test
    anka --self-test --trace        Self-test with instruction trace
    anka rom.bin                    Load ROM at 0x1000 and run
    anka rom.bin --trace            Load ROM with instruction trace
    anka rom.bin --load-addr 0x0    ROM includes its own vector table
    anka rom.bin --max-steps 5000   Stop after 5000 instructions

NOTES:
    The emulated CPU is a Motorola MC68000 with a 24-bit address bus
    (16 MB flat memory). All arithmetic uses explicit bitvector
    semantics — Rust host arithmetic never redefines 68000 behaviour.",
        VERSION
    );
}
