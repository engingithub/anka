//! E8 caller-side refinement of the E7 first-read gate. All inputs to this
//! module are trusted verifier/transport outputs, never wire representations.
use super::*;
use super::super::{DurableRecord, protocol::transport::{Poll, guarded_server::GuardedServer}};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Transcript {
    pub runtime: u64,
    pub connection: u64,
    pub binding: u64,
}

impl Transcript {
    fn of(scope: Scope) -> Self {
        Self { runtime: scope.runtime, connection: scope.connection, binding: scope.binding }
    }
}

/// The anchor attests all four fields together. The handle is a verifier-local
/// reference to a key; it is neither key material nor a caller-chosen number.
#[derive(Clone, Copy)]
pub(crate) struct KeyAssociation {
    pub issuer: u64,
    pub subject: u64,
    pub kind: Kind,
    pub holder: u64,
    pub verified: Verdict,
}

#[derive(Clone, Copy)]
pub(crate) struct Signer {
    pub transcript: Transcript,
    pub holder: u64,
    pub verified: Verdict,
}

/// A coherent, current view from the validator. The actual observation must
/// come from the trusted channel independently of the presented proof.
#[derive(Clone, Copy)]
pub(crate) struct CurrentEvidence {
    pub context: Context,
    pub actual: Observation,
    pub identity: Identity,
    pub key: KeyAssociation,
    pub proof: BindingProof,
    pub signer: Signer,
    pub grant: Option<Permit>,
}

/// Called inside the existing registry lane. Providers must be nonblocking;
/// changes to effective authority must use the registry's update discipline.
pub(crate) trait EvidenceSource {
    fn current(&mut self, actual: Transcript, scope: Request) -> Option<CurrentEvidence>;
}

/// Only the accept path below constructs the retained peer. It captures no grant.
pub(crate) struct BoundPeer(Transcript);

pub(crate) struct PeerBinder<S>(S);
impl<S> PeerBinder<S> {
    pub(crate) fn new(source: S) -> Self { Self(source) }
}
impl<S: EvidenceSource> CallerProvider for PeerBinder<S> {
    type Peer = BoundPeer;
    fn observe(&mut self, peer: &BoundPeer, request: Request) -> Option<Snapshot> {
        let e = self.0.current(peer.0, request)?;
        if Transcript::of(e.actual.scope) != peer.0
            || e.key.verified != Verdict::Valid || e.key.issuer != e.context.anchor
            || e.key.subject != e.identity.subject || e.key.kind != e.identity.kind
            || e.key.holder == 0 || e.signer.holder != e.key.holder
            || e.signer.verified != Verdict::Valid
            || e.signer.transcript != Transcript::of(e.proof.scope)
        {
            return None;
        }
        let snapshot = Snapshot { context: e.context, identity: e.identity,
            permit: e.grant?, proof: e.proof, observed: e.actual };
        // E1 checks proof == actual over the whole scope, recognition, current
        // grant and its exact projection. E4 checks serial/seal under its guard.
        caller(snapshot, request)?;
        Some(snapshot)
    }
}

impl<B: DurableRecord, S: EvidenceSource> GuardedServer<B, PeerBinder<S>> {
    /// Resolve an independently authenticated transcript for this exact stream.
    /// An address, transport nonce or request alone cannot authenticate it.
    pub(crate) fn poll_verified<F>(&mut self, resolve: &mut F, capacity: bool) -> std::io::Result<Poll>
    where F: FnMut(&std::net::TcpStream, u64) -> Option<(Transcript, Request, u64)> {
        self.poll(&mut |stream, minted| {
            let (t, req, deadline) = resolve(stream, minted)?;
            (t.runtime != 0 && t.binding != 0 && t.connection == minted)
                .then_some((BoundPeer(t), req, deadline))
        }, capacity)
    }
}
