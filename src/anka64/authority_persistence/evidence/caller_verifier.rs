//! E10: project E9's checked statements into the E8 caller binder. These are
//! trusted, bounded, nonblocking providers inside the existing registry guard.
//! No constructor here decodes peer bytes or implements signature verification.
use super::*;
use super::peer_binder::{CurrentEvidence, EvidenceSource, KeyAssociation, Signer, Transcript};

#[derive(Clone, Copy)]
pub(crate) struct Credential {
    pub reference: u64, pub issuer: u64, pub subject: u64, pub kind: Kind,
    pub audience: u64, pub policy: u64, pub holder: u64,
    pub first: u64, pub until: u64, pub signature: Verdict,
}

#[derive(Clone, Copy)]
pub(crate) struct Possession {
    pub issuer: u64, pub reference: u64, pub signer: u64, pub signed: BindingProof,
}

#[derive(Clone, Copy)]
pub(crate) struct Status {
    pub issuer: u64, pub reference: u64, pub policy: u64, pub serial: u64,
    pub first: u64, pub until: u64, pub current: Verdict,
}

/// The accepted channel and current authority context, obtained independently
/// of the presented credential and proof. Missing or stale observations deny.
pub(crate) trait LiveChannel {
    fn observe(&mut self, transcript: Transcript) -> Option<(Context, Observation)>;
}

/// Results of signature primitives over canonical, domain-separated messages.
/// issuer and signer identify the keys actually used, never wire key hints.
pub(crate) trait Statements {
    fn checked(&mut self, transcript: Transcript) -> Option<(Credential, Possession)>;
}

/// Local current lookups under the same guard; a recognized caller may have
/// no permit. References are unique within an issuer and are never recycled.
pub(crate) trait Authority {
    fn status(&mut self, issuer: u64, reference: u64) -> Option<Status>;
    fn permit(&mut self, context: Context, scope: Scope, request: Request) -> Option<Permit>;
}

pub(crate) struct CallerVerifier<C, S, A> {
    pub channel: C, pub statements: S, pub authority: A,
}

impl<C: LiveChannel, S: Statements, A: Authority> EvidenceSource for CallerVerifier<C, S, A> {
    fn current(&mut self, transcript: Transcript, request: Request) -> Option<CurrentEvidence> {
        let (c, actual) = self.channel.observe(transcript)?;
        let o = actual.scope;
        if !c.selected || c.anchor == 0 || c.installation == 0 || c.policy == 0 || c.challenge == 0
            || !actual.live || actual.channel != Verdict::Valid || o.role != Role::Caller
            || o.runtime == 0 || o.connection == 0 || o.binding == 0 || o.local == 0
            || o.peer == 0 || o.incarnation == 0 || o.serial == 0 || o.challenge != c.challenge
            || (o.runtime, o.connection, o.binding) != (transcript.runtime, transcript.connection, transcript.binding)
        { return None; }

        let (d, p) = self.statements.checked(transcript)?;
        if d.signature != Verdict::Valid || d.reference == 0 || d.holder == 0
            || d.issuer != c.anchor || d.subject != o.peer || d.kind != o.kind
            || d.audience != c.installation || d.policy != c.policy || !window(c.now, d.first, d.until)
            || p.signed.validated != Verdict::Valid || p.signed.scope != o
            || p.issuer != d.issuer || p.reference != d.reference || p.signer != d.holder
        { return None; }

        let s = self.authority.status(d.issuer, d.reference)?;
        if s.current != Verdict::Valid || s.issuer != d.issuer || s.reference != d.reference
            || s.policy != c.policy || s.serial != o.serial || !window(c.now, s.first, s.until)
        { return None; }

        Some(CurrentEvidence {
            context: c, actual,
            identity: Identity { issuer: d.issuer, subject: d.subject, kind: d.kind, audience: d.audience,
                policy: d.policy, challenge: o.challenge, first: d.first, until: d.until,
                authentic: d.signature, possession: p.signed.validated, status: s.current },
            key: KeyAssociation { issuer: d.issuer, subject: d.subject, kind: d.kind,
                holder: d.holder, verified: d.signature },
            proof: p.signed,
            signer: Signer { transcript, holder: p.signer, verified: p.signed.validated },
            grant: self.authority.permit(c, o, request),
        })
    }
}
