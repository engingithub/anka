//! E12 reference refinement of E11. Only trusted nonblocking sources construct
//! these inputs. Neither endpoint addresses nor data in a reply are credentials.
use super::*;
use super::caller_verifier::{Authority, Credential};

/// Obtained independently from checked peer statements, for this actual socket.
#[derive(Clone, Copy)]
pub(crate) struct LiveStorage {
    pub stream: StreamBinding,
    pub binding: u64,
    pub context: Context,
    pub serial: u64,
    pub observed: Observation,
}

pub(crate) trait StorageChannel {
    fn live(&mut self, stream: StreamBinding) -> Option<LiveStorage>;
}

/// Receipt of the STORAGE-SERVER signature primitive (different message domain
/// and Rust type from E10 caller possession). The verified signature covers
/// issuer, credential reference, and every field of the signed scope together.
#[derive(Clone, Copy)]
pub(crate) struct ServerPossession {
    pub issuer: u64, pub reference: u64, pub signer: u64, pub signed: BindingProof,
}
pub(crate) trait ServerStatements {
    fn checked_server(&mut self, stream: StreamBinding) -> Option<(Credential, ServerPossession)>;
}

pub(crate) struct StorageVerifier<C,S,A> {
    runtime: u64, local: u64, expected_server: u64,
    channel: C, statements: S, authority: A,
}

impl<C: StorageChannel,S: ServerStatements,A: Authority> StorageVerifier<C,S,A> {
    /// The initiator configures the target. The peer cannot choose this value.
    pub(crate) fn adapter(runtime:u64, local:u64, expected_server:u64, channel:C, statements:S,
                          authority:A) -> StorageAdapter<Self> {
        StorageAdapter::new(Self {runtime,local,expected_server,channel,statements,authority},expected_server)
    }
}
impl<C: StorageChannel,S: ServerStatements,A: Authority> StorageProvider for StorageVerifier<C,S,A> {
    fn observe(&mut self, stream:StreamBinding, expected:Envelope) -> Option<Snapshot> {
        let l=self.channel.live(stream)?;
        let c=l.context;
        let o=l.observed.scope;
        if l.stream!=stream || o.connection!=stream.connection || o.binding!=l.binding
            || o.runtime!=self.runtime || o.local!=self.local || o.peer!=self.expected_server
            || o.serial!=l.serial || o.role!=Role::StorageServer
            || !matches!(o.kind,Kind::Installation|Kind::Workload)
        {return None}

        let (d,p)=self.statements.checked_server(stream)?;
        if d.reference==0 || d.holder==0 || d.signature!=Verdict::Valid
            || d.issuer!=c.anchor || d.subject!=o.peer || d.kind!=o.kind
            || d.audience!=c.installation || d.policy!=c.policy || !window(c.now,d.first,d.until)
            || p.issuer!=d.issuer || p.reference!=d.reference || p.signer!=d.holder
            || p.signed.scope!=o || p.signed.validated!=Verdict::Valid
        {return None}
        let s=self.authority.status(d.issuer,d.reference)?;
        if s.current!=Verdict::Valid || s.issuer!=d.issuer || s.reference!=d.reference
            || s.policy!=c.policy || s.serial!=l.serial || !window(c.now,s.first,s.until)
        {return None}
        let snapshot=Snapshot {context:c, observed:l.observed, proof:p.signed,
            identity:Identity {issuer:d.issuer,subject:d.subject,kind:d.kind,audience:d.audience,
                policy:d.policy,challenge:o.challenge,first:d.first,until:d.until,
                authentic:d.signature,possession:p.signed.validated,status:s.current},
            permit:self.authority.permit(c,o,expected.request)?};
        // E1 recognizes the configured server/namespace and exact operation;
        // StorageAdapter additionally freezes the first admission for this stream.
        server(snapshot,self.expected_server,expected.request).then_some(snapshot)
    }
}

#[cfg(all(test,any(target_os="linux",target_os="macos")))]
#[path="storage_verifier/tests.rs"]
mod tests;
