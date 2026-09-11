//! Anka Calling Convention (ACC v0)
//!
//! This module documents the software contract that all Anka guest code
//! must follow.  The monitor already observes this convention; future
//! assembler output and compiled code will depend on it.
//!
//! # Register Roles
//!
//! ```text
//! Register    Role              Convention
//! ────────    ──────────────    ──────────────────────────────────────
//! D0          Return value /    Caller-saved.  First integer return.
//!             scratch           First integer argument (≤32 bits).
//! D1          Scratch           Caller-saved.  Second integer argument.
//! D2–D7      Preserved          Callee-saved.  Subroutines must save
//!                               and restore before returning.
//!
//! A0          Pointer scratch   Caller-saved.  First pointer argument.
//!                               Also used as return pointer.
//! A1          Pointer scratch   Caller-saved.  Second pointer argument.
//! A2–A5      Preserved          Callee-saved.
//! A6          Frame pointer /   Callee-saved.  May also serve as a
//!             base register     dedicated base (e.g., console base in
//!                               the monitor).
//! A7          Stack pointer     Always valid, word-aligned.
//! ```
//!
//! # Argument Passing
//!
//! ```text
//! Position    Data argument     Pointer argument
//! ────────    ──────────────    ──────────────────
//! 1st         D0                A0
//! 2nd         D1                A1
//! 3rd+        stack (right to left, caller removes)
//! ```
//!
//! If a function takes both data and pointer arguments, each class fills
//! its own register slots independently.  For example:
//!
//! ```text
//! void memset(void *dst, int val, int count);
//!   → A0 = dst, D0 = val, D1 = count
//! ```
//!
//! Arguments wider than 32 bits (future Anka64) pass in register pairs
//! or on the stack.
//!
//! # Return Values
//!
//! ```text
//! Type          Register
//! ────────      ────────
//! integer ≤32   D0
//! pointer       A0
//! 64-bit        D0:D1 (high:low)  [future]
//! struct        caller allocates, passes pointer in A0
//! ```
//!
//! # Stack Frame
//!
//! ```text
//!        ┌──────────────────┐  high addresses
//!        │  caller's frame  │
//!        ├──────────────────┤
//!        │  3rd+ arguments  │  ← pushed right-to-left
//!        ├──────────────────┤
//!        │  return address  │  ← pushed by BSR/JSR
//!  A7 →  ├──────────────────┤
//!        │  saved registers │  ← callee-saved D2–D7, A2–A6
//!        │  local variables │
//!        └──────────────────┘  low addresses
//! ```
//!
//! The stack grows downward (pre-decrement push, post-increment pop).
//! The stack pointer must remain **word-aligned** (even address) at all
//! times.  A7 byte operations auto-align by using a 2-byte increment.
//!
//! # Condition Codes
//!
//! The CCR is **caller-saved** (not preserved across calls).
//! The X (extend) flag follows the C flag from arithmetic operations
//! and is undefined after subroutine calls.
//!
//! # Naming
//!
//! Public symbols use `snake_case`.  Module-private labels may use a
//! leading dot (`.loop`, `.done`) or a prefix (`rh_loop` for read_hex).
//!
//! # Platform Constants
//!
//! ```text
//! Address         Contents
//! ────────        ────────────────────────
//! 0x000000        Vector table (1 KB)
//! 0x000400        RAM begins
//! 0x001000        Default ROM load address
//! 0x00F00000      Console device (MMIO)
//!   +0x00           TX_DATA  (W)
//!   +0x01           TX_READY (R)
//!   +0x02           RX_DATA  (R)
//!   +0x03           RX_READY (R)
//! 0x00100000      Default initial SSP
//! ```

// This module is documentation-only.  The constants below let code
// refer to the convention symbolically rather than by magic number.

/// Caller-saved data registers (D0, D1).
pub const CALLER_SAVED_DATA: [u8; 2] = [0, 1];

/// Callee-saved data registers (D2–D7).
pub const CALLEE_SAVED_DATA: [u8; 6] = [2, 3, 4, 5, 6, 7];

/// Caller-saved address registers (A0, A1).
pub const CALLER_SAVED_ADDR: [u8; 2] = [0, 1];

/// Callee-saved address registers (A2–A6).
pub const CALLEE_SAVED_ADDR: [u8; 5] = [2, 3, 4, 5, 6];

/// Default initial stack pointer.
pub const DEFAULT_SSP: u32 = 0x0010_0000;

/// Default ROM entry point.
pub const DEFAULT_ENTRY: u32 = 0x0000_1000;

/// Console MMIO base address.
pub const CONSOLE_BASE: u32 = 0x00F0_0000;

/// Timer MMIO base address.
pub const TIMER_BASE: u32 = 0x00F0_0010;

/// Console register offsets.
pub mod console {
    pub const TX_DATA: u32 = 0x00;
    pub const TX_READY: u32 = 0x01;
    pub const RX_DATA: u32 = 0x02;
    pub const RX_READY: u32 = 0x03;
}

/// Timer register offsets.
pub mod timer {
    pub const CTRL: u32 = 0x00;
    pub const IRQ_LVL: u32 = 0x01;
    pub const PERIOD_H: u32 = 0x02;
    pub const PERIOD_L: u32 = 0x03;
    pub const TICKS: u32 = 0x04;
    pub const STATUS: u32 = 0x07;
}

/// Protection controller MMIO base address.
pub const PROTECT_BASE: u32 = 0x00F0_0020;

/// Protection controller register offsets.
pub mod protect {
    /// Write: set active domain index (byte).
    pub const DOMAIN: u32 = 0x00;
    /// Read: violation count (32-bit).
    pub const VIOLATIONS: u32 = 0x04;
}
