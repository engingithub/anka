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
pub mod placement;
pub mod dev_shell;
pub mod dev_compiler;
pub mod aom;
pub mod dev_runner;
pub mod dev_monitor;
pub mod desc;
pub mod isa;
pub mod core;
pub mod cc;
pub mod os;
pub mod guest_compiler;
#[cfg(test)]
mod bootstrap_tests;
#[cfg(test)]
mod ethernet_tests;
#[cfg(test)]
mod arp_tests;
#[cfg(test)]
mod ipv4_icmp_tests;
#[cfg(test)]
mod udp_tests;
#[cfg(test)]
mod tcp_tests;
#[cfg(test)]
mod socket_tests;
#[cfg(test)]
mod http_tests;
#[cfg(test)]
mod ankacc2_tests;
#[cfg(test)]
mod aom_tests;
pub mod multicore;
pub mod ankad;
pub mod system_image;
pub mod block;
pub mod nic;
pub mod host_net;
