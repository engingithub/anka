//! Anka — MC68000 emulator entry point.

use std::collections::VecDeque;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::process;
use std::sync::{Arc, Mutex};
use std::thread;

use anka::bus::console::Console;
use anka::bus::timer::Timer;
use anka::bus::{Bus, FlatBus, MappedBus};
use anka::cpu::Cpu;
use anka::monitor;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const CONSOLE_BASE: u32 = 0x00F0_0000;
const TIMER_BASE: u32 = 0x00F0_0010;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Subcommand: anka asm
    if args.len() > 1 && args[1] == "asm" {
        run_asm(&args[2..]);
        return;
    }
    // Subcommand: anka cc
    if args.len() > 1 && args[1] == "cc" {
        run_cc(&args[2..]);
        return;
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("anka {}", VERSION);
        return;
    }

    let mut rom_path: Option<String> = None;
    let mut load_addr: u32 = 0x0000_1000;
    let mut max_steps: u64 = 10_000_000;
    let mut trace = false;
    let mut self_test = false;
    let mut hello = false;
    let mut monitor = false;
    let mut os_demo = false;
    let mut emit_srec: Option<String> = None;

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
                max_steps = args[i].replace('_', "").parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid --max-steps value: {}", args[i]);
                    process::exit(2);
                });
            }
            "--trace" | "-t" => trace = true,
            "--self-test" => self_test = true,
            "--hello" => hello = true,
            "--monitor" => monitor = true,
            "--os" => os_demo = true,
            "--emit-srec" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --emit-srec requires an output path");
                    process::exit(2);
                }
                emit_srec = Some(args[i].clone());
            }
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

    // --emit-srec: produce an S-record file from a built-in program
    if let Some(ref out_path) = emit_srec {
        let (binary, base, name) = if monitor {
            let rom = anka::monitor::build(0x1000);
            (rom, 0x1000u32, "monitor")
        } else if hello {
            let rom = build_hello_rom();
            (rom, 0x1000u32, "hello")
        } else {
            let rom = build_self_test_rom();
            (rom, 0x1000u32, "self-test")
        };

        let srec_text = anka::srec::write(&binary, base, base);
        fs::write(out_path, &srec_text).unwrap_or_else(|e| {
            eprintln!("error: cannot write '{}': {}", out_path, e);
            process::exit(1);
        });
        eprintln!("Wrote {} S-record ({} bytes) → {}", name, binary.len(), out_path);
        return;
    }

    if os_demo {
        run_os(trace);
        return;
    }
    if monitor {
        run_monitor(trace);
        return;
    }
    if hello {
        run_hello(trace);
        return;
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

    // Load external ROM (raw binary or S-record)
    let path = rom_path.unwrap();
    let is_srec = path.ends_with(".srec")
        || path.ends_with(".s19")
        || path.ends_with(".s28")
        || path.ends_with(".s37")
        || path.ends_with(".mot");

    let console = Console::new();
    let rx_buf = console.rx_buffer();
    let mut bus = MappedBus::new_16mb();
    bus.add_device(CONSOLE_BASE, Box::new(console));
    bus.add_device(TIMER_BASE, Box::new(Timer::new(1000, 6)));

    if is_srec {
        let text = fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("error: cannot read '{}': {}", path, e);
            process::exit(1);
        });
        let srec = anka::srec::parse(&text).unwrap_or_else(|e| {
            eprintln!("error: {}: {}", path, e);
            process::exit(1);
        });

        // Load all data records into memory
        for rec in &srec.records {
            if let anka::srec::Record::Data { address, data } = rec {
                bus.load(*address, data);
            }
        }

        // Use entry from S-record if available, otherwise use --load-addr.
        // Always set up the vector table (SSP + reset PC) unless the
        // S-record itself loaded data at address 0x000000.
        let entry = srec.entry.unwrap_or(load_addr);
        let covers_vectors = srec.records.iter().any(|r| matches!(
            r, anka::srec::Record::Data { address, data }
            if *address <= 0x000004 && *address + data.len() as u32 > 0x000004
        ));
        if !covers_vectors {
            bus.write32(0x000000, 0x0010_0000); // SSP
            bus.write32(0x000004, entry);        // Reset PC
        }

        eprintln!("Anka — MC68000 Emulator v{}", VERSION);
        eprintln!();
        eprintln!("  S-record:  {}  ({} data bytes)", path, srec.data_size());
        eprintln!("  Range:     {:#010X}–{:#010X}",
            srec.base_address().unwrap_or(0),
            srec.end_address().unwrap_or(0));
        eprintln!("  Entry:     {:#010X}{}", entry,
            if srec.entry.is_some() { " (from S-record)" } else { "" });
        eprintln!("  Console:   {:#010X}", CONSOLE_BASE);
        eprintln!("  Trace:     {}", if trace { "on" } else { "off" });
        eprintln!();
    } else {
        let data = fs::read(&path).unwrap_or_else(|e| {
            eprintln!("error: cannot read '{}': {}", path, e);
            process::exit(1);
        });
        if data.is_empty() {
            eprintln!("error: ROM file '{}' is empty", path);
            process::exit(1);
        }

        if load_addr == 0 {
            bus.load(0, &data);
        } else {
            bus.write32(0x000000, 0x0010_0000);
            bus.write32(0x000004, load_addr);
            bus.load(load_addr, &data);
        }

        eprintln!("Anka — MC68000 Emulator v{}", VERSION);
        eprintln!();
        eprintln!("  ROM:       {}  ({} bytes)", path, data.len());
        eprintln!("  Load addr: {:#010X}", load_addr);
        eprintln!("  Console:   {:#010X}", CONSOLE_BASE);
        eprintln!("  Max steps: {}", max_steps);
        eprintln!("  Trace:     {}", if trace { "on" } else { "off" });
        eprintln!();
    }

    // Start stdin reader for interactive console input
    spawn_stdin_reader(rx_buf);

    let mut cpu = Cpu::new(bus);
    eprintln!("Reset: SSP={:#010X}  PC={:#010X}", cpu.a[7], cpu.pc);
    eprintln!();

    run_cpu(&mut cpu, max_steps, trace);
    print_state(&cpu);
}

// ---------------------------------------------------------------------------
// Interactive monitor
// ---------------------------------------------------------------------------

fn run_monitor(trace: bool) {
    eprintln!("Anka — MC68000 Emulator v{}", VERSION);
    eprintln!("Starting interactive monitor. Press 'h' for help, 'q' to quit.");
    eprintln!();

    let entry: u32 = 0x0000_1000;
    let rom = monitor::build(entry);

    let console = Console::new();
    let rx_buf = console.rx_buffer();

    let mut bus = MappedBus::new_16mb();
    bus.add_device(CONSOLE_BASE, Box::new(console));
    bus.add_device(TIMER_BASE, Box::new(Timer::new(1000, 6)));

    // Vector table
    bus.write32(0x000000, 0x0010_0000); // SSP
    bus.write32(0x000004, entry); // PC
    bus.load(entry, &rom);

    // Start stdin reader
    let _raw = RawTerminal::enter();
    spawn_stdin_reader(rx_buf);

    let mut cpu = Cpu::new(bus);

    // The monitor runs indefinitely until STOP.
    run_cpu(&mut cpu, u64::MAX, trace);
    eprintln!();
    print_state(&cpu);
}

// ---------------------------------------------------------------------------
// AnkaOS demo — preemptive multitasking
// ---------------------------------------------------------------------------

fn run_os(trace: bool) {
    eprintln!("Anka — MC68000 Emulator v{}", VERSION);
    eprintln!("AnkaOS v0.0 — preemptive multitasking demo");
    eprintln!();

    let kernel = anka::os::build(0x1000);

    let console = Console::new();
    let rx_buf = console.rx_buffer();
    let mut bus = MappedBus::new_16mb();
    bus.add_device(CONSOLE_BASE, Box::new(console));
    bus.add_device(TIMER_BASE, Box::new(Timer::new(200, 6)));

    // Vector table
    bus.write32(0x000000, 0x0010_0000);   // SSP
    bus.write32(0x000004, 0x0000_1000);   // Reset PC → kernel entry

    // Find timer ISR address and set auto-vector level 6
    let isr_offset = kernel.windows(4)
        .position(|w| w[0] == 0x48 && w[1] == 0xE7 && w[2] == 0xFF && w[3] == 0xFE)
        .expect("could not find timer_isr in kernel");
    let isr_addr = 0x1000 + isr_offset as u32;
    bus.write32(0x078, isr_addr);

    bus.load(0x1000, &kernel);

    spawn_stdin_reader(rx_buf);
    let mut cpu = Cpu::new(bus);

    eprintln!("Reset: SSP={:#010X}  PC={:#010X}", cpu.a[7], cpu.pc);
    eprintln!("Timer ISR: {:#010X}", isr_addr);
    eprintln!();

    run_cpu(&mut cpu, 1_000_000, trace);
    eprintln!();
    print_state(&cpu);
}

// ---------------------------------------------------------------------------
// Hello demo
// ---------------------------------------------------------------------------

/// Build the hello ROM as a flat binary at address 0x1000.
fn build_hello_rom() -> Vec<u8> {
    let mut a = anka::asm::Asm::new(0x1000);
    a.lea_label("msg", 0);          // LEA msg, A0
    a.lea(CONSOLE_BASE, 1);         // LEA $00F00000, A1
    a.label("loop");
    a.move_b_postinc_dn(0, 0);      // MOVE.B (A0)+, D0
    a.beq("done");
    a.move_b_dn_indirect(0, 1);     // MOVE.B D0, (A1)
    a.bra("loop");
    a.label("done");
    a.stop(0x2700);
    a.label("msg");
    a.ascii_z("Hello from Anka!\n");
    a.assemble()
}

fn run_hello(trace: bool) {
    eprintln!("Anka — MC68000 Emulator v{}", VERSION);
    eprintln!("Running hello demo: CPU → MMIO console → stdout");
    eprintln!();

    let rom = build_hello_rom();
    let mut bus = MappedBus::new_16mb();
    bus.add_device(CONSOLE_BASE, Box::new(Console::new()));

    bus.write32(0x000000, 0x0010_0000);
    bus.write32(0x000004, 0x0000_1000);
    bus.load(0x1000, &rom);

    let mut cpu = Cpu::new(bus);
    eprintln!("Reset: SSP={:#010X}  PC={:#010X}", cpu.a[7], cpu.pc);
    eprintln!();

    run_cpu(&mut cpu, 10_000, trace);
    eprintln!();
    print_state(&cpu);
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

/// Build the self-test ROM as a flat binary at address 0x1000.
fn build_self_test_rom() -> Vec<u8> {
    let mut a = anka::asm::Asm::new(0x1000);
    a.moveq(42, 0); // MOVEQ #42, D0
    a.moveq(10, 1); // MOVEQ #10, D1
    a.emit(0xD081); // ADD.L D1, D0
    a.nop();
    a.stop(0x2700);
    a.assemble()
}

fn run_self_test(trace: bool) {
    println!("Anka — MC68000 Emulator v{}", VERSION);
    println!("Running built-in self-test: MOVEQ #42,D0 + MOVEQ #10,D1 → ADD.L D1,D0");
    println!();

    let rom = build_self_test_rom();
    let mut bus = FlatBus::new_16mb();
    bus.write32(0x000000, 0x0010_0000);
    bus.write32(0x000004, 0x0000_1000);
    bus.load(0x1000, &rom);

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
// CPU execution loop
// ---------------------------------------------------------------------------

fn run_cpu<B: Bus>(cpu: &mut Cpu<B>, max_steps: u64, trace: bool) {
    let mut steps = 0u64;

    while !cpu.halted && steps < max_steps {
        let pc_before = cpu.pc;
        let cycles = cpu.step();
        cpu.cycles += cycles as u64;
        steps += 1;

        if trace {
            eprintln!(
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

    eprintln!("Halted after {} steps, {} total cycles.", steps, cpu.cycles);
}

fn print_state<B: Bus>(cpu: &Cpu<B>) {
    eprintln!();
    eprintln!(
        "  D0={:#010X}  D1={:#010X}  D2={:#010X}  D3={:#010X}",
        cpu.d[0], cpu.d[1], cpu.d[2], cpu.d[3]
    );
    eprintln!(
        "  D4={:#010X}  D5={:#010X}  D6={:#010X}  D7={:#010X}",
        cpu.d[4], cpu.d[5], cpu.d[6], cpu.d[7]
    );
    eprintln!(
        "  A0={:#010X}  A1={:#010X}  A2={:#010X}  A3={:#010X}",
        cpu.a[0], cpu.a[1], cpu.a[2], cpu.a[3]
    );
    eprintln!(
        "  A4={:#010X}  A5={:#010X}  A6={:#010X}  A7={:#010X}",
        cpu.a[4], cpu.a[5], cpu.a[6], cpu.a[7]
    );
    eprintln!("  PC={:#010X}  SR={:#06X}", cpu.pc, cpu.sr.0);
}

// ---------------------------------------------------------------------------
// Stdin reader thread
// ---------------------------------------------------------------------------

fn spawn_stdin_reader(buf: Arc<Mutex<VecDeque<u8>>>) {
    thread::spawn(move || {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let mut byte = [0u8; 1];
        loop {
            match handle.read(&mut byte) {
                Ok(1) => {
                    buf.lock().unwrap().push_back(byte[0]);
                }
                _ => break, // EOF or error
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Terminal raw mode (Unix)
// ---------------------------------------------------------------------------

struct RawTerminal {
    #[cfg(unix)]
    original: libc::termios,
    #[cfg(unix)]
    fd: i32,
}

impl RawTerminal {
    /// Enter raw mode if stdin is a TTY.  Returns a guard that
    /// restores the terminal on drop.
    fn enter() -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = io::stdin().as_raw_fd();

            // Only enable raw mode if stdin is a terminal.
            if unsafe { libc::isatty(fd) } != 1 {
                return None;
            }

            unsafe {
                let mut original: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(fd, &mut original) != 0 {
                    return None;
                }
                let mut raw = original;
                // Disable echo and canonical mode; keep ISIG so Ctrl-C works.
                raw.c_lflag &= !(libc::ECHO | libc::ICANON);
                raw.c_cc[libc::VMIN] = 1;
                raw.c_cc[libc::VTIME] = 0;
                if libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) != 0 {
                    return None;
                }
                Some(Self { original, fd })
            }
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original);
        }
    }
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

// ---------------------------------------------------------------------------
// Assembler subcommand
// ---------------------------------------------------------------------------

fn run_asm(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("\
AnkaASM — MC68000 text assembler

USAGE:
    anka asm <source.s> [-o <output.srec>] [--base ADDR]

OPTIONS:
    -o FILE         Output S-record file (default: source with .srec extension)
    --base ADDR     Base address for code (default: 0x1000)
    --raw           Output raw binary instead of S-record
    --help, -h      Print this help

EXAMPLE:
    anka asm hello.s -o hello.srec
    anka hello.srec                    ; load and run the result");
        return;
    }

    let mut source_path: Option<String> = None;
    let mut output_path: Option<String> = None;
    let mut base: u32 = 0x0000_1000;
    let mut raw = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: -o requires an output path");
                    process::exit(2);
                }
                output_path = Some(args[i].clone());
            }
            "--base" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --base requires an address");
                    process::exit(2);
                }
                base = parse_u32(&args, i, "--base");
            }
            "--raw" => raw = true,
            arg if arg.starts_with('-') => {
                eprintln!("error: unknown option: {}", arg);
                process::exit(2);
            }
            _ => {
                if source_path.is_some() {
                    eprintln!("error: multiple source files not supported");
                    process::exit(2);
                }
                source_path = Some(args[i].clone());
            }
        }
        i += 1;
    }

    let source_path = source_path.unwrap_or_else(|| {
        eprintln!("error: no source file given");
        eprintln!("Try 'anka asm --help' for usage.");
        process::exit(2);
    });

    let default_out = if raw {
        source_path.rsplit_once('.').map_or_else(
            || format!("{}.bin", source_path),
            |(stem, _)| format!("{}.bin", stem),
        )
    } else {
        source_path.rsplit_once('.').map_or_else(
            || format!("{}.srec", source_path),
            |(stem, _)| format!("{}.srec", stem),
        )
    };
    let output_path = output_path.unwrap_or(default_out);

    let source = fs::read_to_string(&source_path).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{}': {}", source_path, e);
        process::exit(1);
    });

    match anka::asm::text::assemble(&source, base) {
        Ok(binary) => {
            let out_data = if raw {
                binary.clone()
            } else {
                anka::srec::write(&binary, base, base).into_bytes()
            };

            fs::write(&output_path, &out_data).unwrap_or_else(|e| {
                eprintln!("error: cannot write '{}': {}", output_path, e);
                process::exit(1);
            });

            let fmt = if raw { "binary" } else { "S-record" };
            eprintln!("AnkaASM: {} → {} ({} bytes {}, base {:#010X})",
                source_path, output_path, binary.len(), fmt, base);
        }
        Err(errors) => {
            for e in &errors {
                eprintln!("{}:{}", source_path, e);
            }
            eprintln!("{} error(s)", errors.len());
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// C compiler subcommand
// ---------------------------------------------------------------------------

fn run_cc(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("\
AnkaCC — tiny C compiler targeting MC68000

USAGE:
    anka cc <source.c> [-o <output.srec>] [--base ADDR] [--run]

OPTIONS:
    -o FILE         Output S-record file (default: source with .srec extension)
    --base ADDR     Base address for code (default: 0x1000)
    --raw           Output raw binary instead of S-record
    --run           Compile and immediately execute
    --help, -h      Print this help

EXAMPLE:
    anka cc hello.c -o hello.srec
    anka cc hello.c --run               ; compile and execute
    anka hello.srec                      ; load and run the result");
        return;
    }

    let mut source_path: Option<String> = None;
    let mut output_path: Option<String> = None;
    let mut base: u32 = 0x0000_1000;
    let mut raw = false;
    let mut run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: -o requires an output path");
                    process::exit(2);
                }
                output_path = Some(args[i].clone());
            }
            "--base" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --base requires an address");
                    process::exit(2);
                }
                base = parse_u32(&args, i, "--base");
            }
            "--raw" => raw = true,
            "--run" => run = true,
            arg if arg.starts_with('-') => {
                eprintln!("error: unknown option: {}", arg);
                process::exit(2);
            }
            _ => {
                if source_path.is_some() {
                    eprintln!("error: multiple source files not supported");
                    process::exit(2);
                }
                source_path = Some(args[i].clone());
            }
        }
        i += 1;
    }

    let source_path = source_path.unwrap_or_else(|| {
        eprintln!("error: no source file given");
        eprintln!("Try 'anka cc --help' for usage.");
        process::exit(2);
    });

    let source = fs::read_to_string(&source_path).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{}': {}", source_path, e);
        process::exit(1);
    });

    let binary = match anka::cc::compile(&source, base) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}:{}", source_path, e);
            process::exit(1);
        }
    };

    eprintln!("AnkaCC: compiled {} → {} bytes", source_path, binary.len());

    if run {
        // Run immediately
        let console = Console::new();
        let rx_buf = console.rx_buffer();
        let mut bus = MappedBus::new_16mb();
        bus.add_device(CONSOLE_BASE, Box::new(console));
        bus.add_device(TIMER_BASE, Box::new(Timer::new(1000, 6)));
        bus.write32(0x000000, 0x0010_0000); // SSP
        bus.write32(0x000004, base);         // PC = _start
        bus.load(base as u32, &binary);

        spawn_stdin_reader(rx_buf);
        let mut cpu = Cpu::new(bus);
        run_cpu(&mut cpu, 10_000_000, false);
        eprintln!();
        print_state(&cpu);
    } else {
        // Write output file
        let default_out = if raw {
            source_path.rsplit_once('.').map_or_else(
                || format!("{}.bin", source_path),
                |(stem, _)| format!("{}.bin", stem),
            )
        } else {
            source_path.rsplit_once('.').map_or_else(
                || format!("{}.srec", source_path),
                |(stem, _)| format!("{}.srec", stem),
            )
        };
        let output_path = output_path.unwrap_or(default_out);

        let out_data = if raw {
            binary.clone()
        } else {
            anka::srec::write(&binary, base, base).into_bytes()
        };

        fs::write(&output_path, &out_data).unwrap_or_else(|e| {
            eprintln!("error: cannot write '{}': {}", output_path, e);
            process::exit(1);
        });

        let fmt = if raw { "binary" } else { "S-record" };
        eprintln!("AnkaCC: {} → {} ({} bytes {}, base {:#010X})",
            source_path, output_path, binary.len(), fmt, base);
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

    The machine includes an MMIO console at {:#010X}:
      +0x00  TX_DATA   (W)  Write byte → stdout
      +0x01  TX_READY  (R)  Always 0x01
      +0x02  RX_DATA   (R)  Read byte from input buffer
      +0x03  RX_READY  (R)  0x01 if data available

ARGUMENTS:
    ROM_FILE            Raw binary or Motorola S-record file to load.
                        S-record files (.srec .s19 .s28 .s37 .mot) are
                        detected by extension and loaded with their
                        embedded addresses and entry point.

OPTIONS:
    --load-addr ADDR    Load address for raw binary ROMs (default: 0x1000)
    --max-steps N       Stop after N instructions (default: 10,000,000)
    --trace, -t         Print every instruction as it executes (stderr)
    --self-test         Run the built-in arithmetic self-test
    --hello             Run the I/O demo (prints 'Hello from Anka!')
    --monitor           Start the interactive ROM monitor
    --emit-srec FILE    Write a built-in program as a Motorola S-record
                        file instead of running it.  Combine with
                        --self-test, --hello, or --monitor.
    --version, -V       Print version and exit
    --help, -h          Print this help and exit

EXAMPLES:
    anka                            Run built-in self-test
    anka --monitor                  Interactive monitor (try 'h' for help)
    anka --monitor --trace          Monitor with instruction trace
    anka --hello                    CPU prints via MMIO console
    anka rom.bin                    Load ROM at 0x1000 and run
    anka rom.bin --trace            Load ROM with instruction trace
    anka rom.bin --load-addr 0x0    ROM includes its own vector table
    anka program.srec               Load S-record file and run
    anka --hello --emit-srec h.srec Write hello demo as S-record file
    anka asm hello.s                Assemble source → hello.srec
    anka asm hello.s -o out.srec    Assemble with explicit output path
    anka cc hello.c --run           Compile and run C program
    anka cc hello.c -o hello.srec   Compile C to S-record

MEMORY MAP:
    0x000000–0x0003FF    Vector table (1 KB)
    0x000400–0xEFFFFF    RAM (program + data)
    0xF00000–0xF0000F    Console (MMIO)
    0xF00010–0xF00017    Timer (MMIO)
    0xF00018–0xFFFFFF    (reserved for future devices)",
        VERSION, CONSOLE_BASE
    );
}
