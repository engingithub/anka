//! Anka — MC68000 CPU emulator with bitvector semantics.
//!
//! The Anka emulator models the Motorola MC68000 programmer-visible state
//! as transformations of fixed-width bitvectors:
//!
//!   D₀…D₇ ∈ BV₃₂,  A₀…A₇ ∈ BV₃₂,  PC ∈ BV₃₂,  SR ∈ BV₁₆
//!
//! All arithmetic is width-aware: results are masked to the operand size
//! so that Rust's host arithmetic never silently redefines 68000 semantics.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────┐
//! │         Cpu<B: Bus>            │
//! │  D0-D7  A0-A7  PC  SR  cycles │
//! └────────────┬───────────────────┘
//!              │ read/write
//!              ▼
//! ┌────────────────────────────────┐
//! │         Bus trait              │
//! │  read8/16/32  write8/16/32    │
//! └────────────┬───────────────────┘
//!              │
//!   ┌──────────┼──────────┐
//!   ▼          ▼          ▼
//! FlatBus   MappedBus   (future)
//! ```

pub mod abi;
pub mod asm;
pub mod bus;
pub mod cc;
pub mod cpu;
pub mod hostile;
pub mod monitor;
pub mod os;
pub mod os_protected;
pub mod protection;
pub mod srec;
