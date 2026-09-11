//! MMIO Console — the simplest possible output device.
//!
//! Memory map (offsets from base address):
//!
//!   0x00  TX_DATA  (W)  Write a byte → character appears on stdout
//!   0x01  TX_READY (R)  Always 0x01 (transmitter ready)
//!   0x02  RX_DATA  (R)  Read a byte from stdin (0x00 if nothing available)
//!   0x03  RX_READY (R)  0x01 if a character is available, 0x00 otherwise
//!
//! This is deliberately minimal — close to a bare ACIA/UART, but without
//! baud rates, interrupts, or control registers.  It is enough to build
//! putchar → puts → printf → a ROM monitor.
//!
//! The device window is 16 bytes (room to grow without moving anything).

use std::collections::VecDeque;
use std::io::{self, Write};

use super::device::Device;

/// Base offsets within the console's 16-byte window.
const TX_DATA: u32 = 0x00;
const TX_READY: u32 = 0x01;
const RX_DATA: u32 = 0x02;
const RX_READY: u32 = 0x03;

/// A simple console device that writes to stdout and reads from stdin.
pub struct Console {
    /// Characters waiting to be read by the CPU.
    rx_buf: VecDeque<u8>,
}

impl Console {
    pub fn new() -> Self {
        Self {
            rx_buf: VecDeque::new(),
        }
    }

    /// Push a character into the receive buffer (as if typed on a terminal).
    pub fn inject_char(&mut self, ch: u8) {
        self.rx_buf.push_back(ch);
    }

    /// Try to read a byte from stdin (non-blocking best-effort).
    fn poll_stdin(&mut self) {
        // For now, don't actually poll stdin in the hot loop.
        // Characters can be injected via inject_char() or a future
        // terminal-raw-mode layer.  This keeps the emulator deterministic
        // and avoids blocking on read().
    }
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Console {
    fn name(&self) -> &str {
        "console"
    }

    fn size(&self) -> u32 {
        16
    }

    fn read(&mut self, offset: u32) -> u8 {
        match offset {
            TX_DATA => 0x00,  // TX register reads as 0
            TX_READY => 0x01, // Always ready to transmit
            RX_DATA => {
                self.poll_stdin();
                self.rx_buf.pop_front().unwrap_or(0x00)
            }
            RX_READY => {
                self.poll_stdin();
                if self.rx_buf.is_empty() { 0x00 } else { 0x01 }
            }
            _ => 0x00,
        }
    }

    fn write(&mut self, offset: u32, val: u8) {
        match offset {
            TX_DATA => {
                // The moment of truth: CPU arithmetic → observable I/O.
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                let _ = handle.write_all(&[val]);
                let _ = handle.flush();
            }
            _ => {
                // Writes to other offsets are silently ignored.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_ready_always_set() {
        let mut con = Console::new();
        assert_eq!(con.read(TX_READY), 0x01);
    }

    #[test]
    fn rx_empty_returns_zero() {
        let mut con = Console::new();
        assert_eq!(con.read(RX_READY), 0x00);
        assert_eq!(con.read(RX_DATA), 0x00);
    }

    #[test]
    fn inject_and_read() {
        let mut con = Console::new();
        con.inject_char(b'A');
        con.inject_char(b'B');

        assert_eq!(con.read(RX_READY), 0x01);
        assert_eq!(con.read(RX_DATA), b'A');
        assert_eq!(con.read(RX_READY), 0x01);
        assert_eq!(con.read(RX_DATA), b'B');
        assert_eq!(con.read(RX_READY), 0x00);
    }
}
