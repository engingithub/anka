//! E2 refinement of anka110_evidence_admission.kleis (E1).
//!
//! Inputs below are TRUSTED validator outputs, never decoded wire assertions.
//! The provider must authenticate every associated field, observe current time,
//! policy/revocation and the actual channel, and serialize observation with the
//! protected effect. Base E2 checks do not implement cryptography or exclusion;
//! the registry submodule supplies E4's guarded reference authority lane.
//! No production provider is supplied. Unknown/missing evidence always denies.
use super::{Access, Context, Operation, Request, Verdict};
use super::protocol::{self, Envelope};
use super::protocol::client::{Binding as StreamBinding, ServerVerifier};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind { Person, Installation, Workload }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role { Caller, StorageServer }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub issuer: u64, pub subject: u64, pub kind: Kind, pub audience: u64,
    pub policy: u64, pub challenge: u64, pub first: u64, pub until: u64,
    pub authentic: Verdict, pub possession: Verdict, pub status: Verdict,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Permit {
    pub issuer: u64, pub subject: u64, pub kind: Kind, pub audience: u64,
    pub policy: u64, pub incarnation: u64, pub role: Role, pub operation: Operation,
    pub first: u64, pub until: u64, pub authentic: Verdict, pub status: Verdict,
}
/// Equality handles, not token encodings or cryptographic nonce widths. Runtime
/// and channel freshness across restart must come from the trusted provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scope {
    pub runtime: u64, pub connection: u64, pub binding: u64, pub local: u64,
    pub peer: u64, pub kind: Kind, pub incarnation: u64, pub role: Role,
    pub operation: Operation, pub serial: u64, pub challenge: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BindingProof { pub scope: Scope, pub validated: Verdict }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Observation { pub scope: Scope, pub live: bool, pub channel: Verdict }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub context: Context, pub identity: Identity, pub permit: Permit,
    pub proof: BindingProof, pub observed: Observation,
}
fn window(now: u64, first: u64, until: u64) -> bool { first <= now && now < until }
fn shape(r: Request) -> bool {
    // Reuse the canonical request validator; correlation is transport-only.
    (Envelope { correlation: 1, request: r }).encode().is_ok()
}
fn admitted(s: Snapshot) -> bool {
    let c=s.context; let i=s.identity; let p=s.permit; let o=s.observed.scope;
    c.selected && c.anchor!=0 && c.installation!=0 && c.policy!=0 && c.challenge!=0 &&
    o.runtime!=0 && o.connection!=0 && o.binding!=0 && o.local!=0 && o.peer!=0 &&
    o.incarnation!=0 && o.serial!=0 && o.challenge==c.challenge &&
    s.observed.live && s.observed.channel==Verdict::Valid &&
    s.proof.validated==Verdict::Valid && s.proof.scope==o &&
    i.issuer==c.anchor && i.subject==o.peer && i.kind==o.kind &&
    i.audience==c.installation && i.policy==c.policy && i.challenge==c.challenge &&
    window(c.now,i.first,i.until) && i.authentic==Verdict::Valid &&
    i.possession==Verdict::Valid && i.status==Verdict::Valid &&
    p.issuer==c.anchor && p.subject==o.peer && p.kind==o.kind &&
    p.audience==c.installation && p.policy==c.policy && p.incarnation==o.incarnation &&
    p.role==o.role && p.operation==o.operation && window(c.now,p.first,p.until) &&
    p.authentic==Verdict::Valid && p.status==Verdict::Valid
}
fn namespace(s: Snapshot, r: Request) -> bool {
    shape(r) && r.anchor==s.context.anchor && r.installation==s.context.installation &&
    r.policy==s.context.policy && r.operation==s.observed.scope.operation
}
fn caller(s: Snapshot, r: Request) -> Option<Access> {
    if !admitted(s) || !namespace(s,r) || s.observed.scope.role!=Role::Caller ||
        r.caller!=s.observed.scope.peer || r.incarnation!=s.observed.scope.incarnation { return None }
    Some(Access { anchor:r.anchor, installation:r.installation, policy:r.policy,
        caller:r.caller, incarnation:r.incarnation, operation:r.operation,
        first:s.identity.first.max(s.permit.first), until:s.identity.until.min(s.permit.until),
        authentic:Verdict::Valid, status:Verdict::Valid })
}
fn server(s: Snapshot, expected: u64, r: Request) -> bool {
    admitted(s) && namespace(s,r) && s.observed.scope.role==Role::StorageServer &&
    matches!(s.observed.scope.kind,Kind::Installation|Kind::Workload) && s.observed.scope.peer==expected
}
/// Private retained admission; no cached Access escapes without revalidation.
/// Scope includes the frozen serial. Renewal of identity/permit needs a fresh
/// admission rather than silently extending an existing admission's lifetime.
struct Seal { context: Context, identity: Identity, permit: Permit, scope: Scope }
impl Seal {
    fn new(s: Snapshot) -> Self { Self { context:s.context, identity:s.identity, permit:s.permit, scope:s.observed.scope } }
    fn current(&self, s: Snapshot) -> bool {
        s.observed.scope==self.scope && s.context.anchor==self.context.anchor &&
        s.context.installation==self.context.installation && s.context.policy==self.context.policy &&
        s.context.challenge==self.context.challenge && s.identity==self.identity && s.permit==self.permit
        // now/live/status are validated again by caller/server, never cached.
    }
}
/// Trusted integration obtains a CURRENT snapshot for an actual channel handle.
/// Peer must be an authenticated handle, never just a caller ID or IP address.
/// The request is a scope to check, not evidence from which to invent authority.
pub(crate) trait CallerProvider {
    type Peer;
    fn observe(&mut self, _peer: &Self::Peer, _request: Request) -> Option<Snapshot> { None }
}
pub(crate) struct DenyCallerProvider;
impl CallerProvider for DenyCallerProvider { type Peer=(); }
/// Fields and construction are private. Retains the authenticated handle and all
/// binding/scope evidence; no public conversion to a reusable bare Access.
pub(crate) struct CallerAdmission<P> { peer: P, seal: Seal }
pub(crate) struct CallerAdapter<P: CallerProvider> { provider: P }
impl<P: CallerProvider> CallerAdapter<P> {
    pub(crate) fn new(provider: P) -> Self { Self { provider } }
    pub(crate) fn admit(&mut self, peer: P::Peer, request: Request) -> Option<CallerAdmission<P::Peer>> {
        let s=self.provider.observe(&peer,request)?;
        caller(s,request)?;
        Some(CallerAdmission { peer, seal:Seal::new(s) })
    }
}
impl<P: CallerProvider> protocol::Verifier for CallerAdapter<P> {
    type Peer=CallerAdmission<P::Peer>;
    fn verify(&mut self, peer: &Self::Peer, request: Request) -> Option<(Context,Access)> {
        let s=self.provider.observe(&peer.peer,request)?;
        if !peer.seal.current(s) { return None }
        Some((s.context,caller(s,request)?))
    }
}
/// Trusted provider maps the ACTUAL client stream and expected request to fresh
/// authenticated server evidence. It must check both endpoints/direction, not
/// infer identity from their addresses. No blocking provider calls in poll().
pub(crate) trait StorageProvider {
    fn observe(&mut self, _stream: StreamBinding, _expected: Envelope) -> Option<Snapshot> { None }
}
pub(crate) struct DenyStorageProvider;
impl StorageProvider for DenyStorageProvider {}
struct ServerAdmission { stream: StreamBinding, seal: Seal }
/// One fixed-size cache for the currently owned connection. A reconnect needs
/// newly validated evidence; an unchanged connection cannot refresh away a
/// serial/policy change. A production provider must supply restart freshness.
pub(crate) struct StorageAdapter<P: StorageProvider> {
    provider: P, expected_server: u64, active: Option<ServerAdmission>,
}
impl<P: StorageProvider> StorageAdapter<P> {
    pub(crate) fn new(provider: P, expected_server: u64) -> Self { Self { provider, expected_server, active:None } }
}
impl<P: StorageProvider> ServerVerifier for StorageAdapter<P> {
    fn verify(&mut self, stream: StreamBinding, expected: Envelope) -> Verdict {
        if expected.correlation==0 { return Verdict::Invalid }
        let Some(s)=self.provider.observe(stream,expected) else { return Verdict::Invalid };
        if s.observed.scope.connection!=stream.connection || !server(s,self.expected_server,expected.request) {
            return Verdict::Invalid
        }
        if let Some(a)=&self.active {
            if a.stream.connection==stream.connection {
                return if a.stream==stream && a.seal.current(s) { Verdict::Valid } else { Verdict::Invalid }
            }
            // The client creates monotonically increasing process-local connection
            // IDs. Reject backwards replay; this is not cross-restart freshness.
            if stream.connection<=a.stream.connection { return Verdict::Invalid }
        }
        self.active=Some(ServerAdmission { stream, seal:Seal::new(s) });
        Verdict::Valid
    }
}
#[cfg(test)]
#[path="evidence/tests.rs"]
mod tests;

#[path="evidence/registry.rs"]
pub(crate) mod registry;
