//! Anka64 architectural state model.
//!
//! Defines the state space of the machine before register counts,
//! opcode fields, or assembly syntax:
//!
//!   S = (C, A, D, O, T, M, F, E)
//!
//! where:
//!   C = CPU core states
//!   A = non-CPU agent states
//!   D = protection domains
//!   O = object table
//!   T = translation/placement state
//!   M = physical memory
//!   F = transaction/fabric state
//!   E = pending external events
//!
//! The state model is the formal contract: the machine is what
//! these types say it is.

pub mod state;
pub mod fabric;
pub mod isa;
pub mod core;
