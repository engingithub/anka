//! MMIO Console — the simplest possible output device.
//!
//! Memory map (offsets from base address):
//!
//!   0x00  TX_DATA  (W)  Write a byte → character appears on stdout
//!   0x01  TX_READY (R)  Always 0x01 (transmitter ready)
//!   0x02  RX_DATA  (R)  Read a byte from input buffer
//!   0x03  RX_READY (R)  0x01 if a character is available, 0x00 otherwise

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use super::device::Device;

const TX_DATA: u32 = 0x00;
const TX_READY: u32 = 0x01;
const RX_DATA: u32 = 0x02;
const RX_READY: u32 = 0x03;

/// A simple console device that writes to stdout and reads from a
/// shared input buffer.  For interactive use, a stdin-reader thread
/// pushes bytes into `rx_buf` via `rx_buffer()`.
pub struct Console {
    rx_buf: Arc<Mutex<VecDeque<u8>>>,
}

impl Console {
    pub fn new() -> Self {
        Self {
            rx_buf: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Get a handle to the RX buffer for feeding input from another thread.
    pub fn rx_buffer(&self) -> Arc<Mutex<VecDeque<u8>>> {
        self.rx_buf.clone()
    }

    /// Push a character into the receive buffer.
    pub fn inject_char(&self, ch: u8) {
        self.rx_buf.lock().unwrap().push_back(ch);
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
            TX_DATA => 0x00,
            TX_READY => 0x01,
            RX_DATA => self.rx_buf.lock().unwrap().pop_front().unwrap_or(0x00),
            RX_READY => {
                if self.rx_buf.lock().unwrap().is_empty() {
                    0x00
                } else {
                    0x01
                }
            }
            _ => 0x00,
        }
    }

    fn write(&mut self, offset: u32, val: u8) {
        if offset == TX_DATA {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            let _ = handle.write_all(&[val]);
            let _ = handle.flush();
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
