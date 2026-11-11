//! Version-1 codec/dispatcher and bounded localhost reference transport.
//! Authentication remains a trusted verifier boundary, never wire assertions.
use super::{Access,Context,DurableRecord,Error,Operation,Outcome,Request,Verdict,authorized,transact};
#[path="protocol/codec.rs"]
mod codec;
pub(crate) use codec::{Envelope,Reply,Status,WireError,REQUEST_BYTES,REPLY_BYTES};
#[path="protocol/dispatch.rs"]
mod dispatch;
pub(crate) use dispatch::{dispatch,DispatchBudget,Verifier,DenyAll,ClientEvidence,ClientResult,accept_reply};
#[cfg(test)]
#[path="protocol/tests.rs"]
mod tests;

#[path="protocol/transport.rs"]
pub(crate) mod transport;
#[path="protocol/client.rs"]
pub(crate) mod client;

#[path="protocol/guarded.rs"]
pub(crate) mod guarded;
