//! Anka — MC68000 emulator entry point.

use std::collections::VecDeque;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::process;
use std::sync::{Arc, Mutex};
use std::thread;

use anka::bus::console::Console;
use anka::bus::{Bus, FlatBus, MappedBus};
use anka::cpu::Cpu;
use anka::monitor;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const CONSOLE_BASE: u32 = 0x00F0_0000;

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

    let mut rom_path: Option<String> = None;
    let mut load_addr: u32 = 0x0000_1000;
    let mut max_steps: u64 = 10_000_000;
    let mut trace = false;
    let mut self_test = false;
    let mut hello = false;
    let mut monitor = false;

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

    // Load external ROM
    let path = rom_path.unwrap();
    let data = fs::read(&path).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{}': {}", path, e);
        process::exit(1);
    });
    if data.is_empty() {
        eprintln!("error: ROM file '{}' is empty", path);
        process::exit(1);
    }

    eprintln!("Anka — MC68000 Emulator v{}", VERSION);
    eprintln!();
    eprintln!("  ROM:       {}  ({} bytes)", path, data.len());
    eprintln!("  Load addr: {:#010X}", load_addr);
    eprintln!("  Console:   {:#010X}", CONSOLE_BASE);
    eprintln!("  Max steps: {}", max_steps);
    eprintln!("  Trace:     {}", if trace { "on" } else { "off" });
    eprintln!();

    let console = Console::new();
    let rx_buf = console.rx_buffer();
    let mut bus = MappedBus::new_16mb();
    bus.add_device(CONSOLE_BASE, Box::new(console));

    if load_addr == 0 {
        bus.load(0, &data);
    } else {
        bus.write32(0x000000, 0x0010_0000);
        bus.write32(0x000004, load_addr);
        bus.load(load_addr, &data);
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
// Hello demo
// ---------------------------------------------------------------------------

fn run_hello(trace: bool) {
    eprintln!("Anka — MC68000 Emulator v{}", VERSION);
    eprintln!("Running hello demo: CPU → MMIO console → stdout");
    eprintln!();

    let mut bus = MappedBus::new_16mb();
    bus.add_device(CONSOLE_BASE, Box::new(Console::new()));

    let ssp: u32 = 0x0010_0000;
    let entry: u32 = 0x0000_1000;
    let string_addr: u32 = 0x0000_2000;

    bus.write32(0x000000, ssp);
    bus.write32(0x000004, entry);
    bus.load(string_addr, b"Hello from Anka!\n");

    let program: &[u16] = &[
        0x41F9, 0x0000, 0x2000, // LEA $00002000, A0
        0x43F9, 0x00F0, 0x0000, // LEA $00F00000, A1
        0x1018, // MOVE.B (A0)+, D0
        0x6704, // BEQ.S done
        0x1280, // MOVE.B D0, (A1)
        0x60F8, // BRA.S loop
        0x4E72, 0x2700, // STOP #$2700
    ];

    let mut addr = entry;
    for &word in program {
        bus.write16(addr, word);
        addr += 2;
    }

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

fn run_self_test(trace: bool) {
    println!("Anka — MC68000 Emulator v{}", VERSION);
    println!("Running built-in self-test: MOVEQ #42,D0 + MOVEQ #10,D1 → ADD.L D1,D0");
    println!();

    let mut bus = FlatBus::new_16mb();
    bus.write32(0x000000, 0x0010_0000);
    bus.write32(0x000004, 0x0000_1000);
    let program: &[u16] = &[0x702A, 0x720A, 0xD081, 0x4E71, 0x4E72, 0x2700];
    let mut addr = 0x0000_1000u32;
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
    ROM_FILE            Raw binary file to load into memory

OPTIONS:
    --load-addr ADDR    Load address for the ROM (default: 0x1000)
    --max-steps N       Stop after N instructions (default: 10,000,000)
    --trace, -t         Print every instruction as it executes (stderr)
    --self-test         Run the built-in arithmetic self-test
    --hello             Run the I/O demo (prints 'Hello from Anka!')
    --monitor           Start the interactive ROM monitor
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

MEMORY MAP:
    0x000000–0x0003FF    Vector table (1 KB)
    0x000400–0xEFFFFF    RAM (program + data)
    0xF00000–0xF0000F    Console (MMIO)
    0xF00010–0xFFFFFF    (reserved for future devices)",
        VERSION, CONSOLE_BASE
    );
}
