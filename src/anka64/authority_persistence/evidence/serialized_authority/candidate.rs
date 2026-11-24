//! Field-for-field KC110 candidate checks. All verdicts are trusted validator
//! outputs, not decoded token/JSON claims. Equality handles are collision-free
//! identities supplied by the embedding; these u64s are NOT truncated hashes.
use super::{Now, Verdict};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Configuration {
    pub issuer: u64, pub audience: u64, pub client: u64, pub installation: u64,
    pub policy: u64, pub keyset: u64, pub profile: u64, pub max_age: u64,
    pub max_bytes: u64, pub selected: Verdict,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Token {
    pub reference: u64, pub issuer: u64, pub audience: u64, pub client: u64,
    pub subject: u64, pub holder: u64, pub keyset: u64, pub profile: u64,
    pub issued: u64, pub first: u64, pub until: u64,
    pub syntax: Verdict, pub signature: Verdict,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mapping {
    pub issuer: u64, pub subject: u64, pub client: u64, pub installation: u64,
    pub peer: u64, pub kind: u64, pub policy: u64, pub enabled: Verdict,
}
/// Complete KC110 scope, including artifact identity and generation. These tags
/// retain the formal E9/E11 vocabulary; this module adds no guest file CRUD ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scope {
    pub installation: u64, pub policy: u64, pub peer: u64, pub kind: u64,
    pub artifact: u64, pub generation: u64, pub request: u64, pub operation: u64,
    pub role: u64, pub runtime: u64, pub connection: u64, pub binding: u64,
    pub local: u64, pub incarnation: u64, pub serial: u64, pub challenge: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Status {
    pub token: u64, pub issuer: u64, pub query: u64, pub started: u64,
    pub observed: u64, pub checked: Verdict, pub active: Verdict,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Proof {
    pub token: u64, pub issuer: u64, pub signer: u64,
    pub scope: Scope, pub signature: Verdict,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Grant {
    pub token: u64, pub scope: Scope, pub first: u64, pub until: u64,
    pub permission: Verdict,
}
/// Checked, bounded inputs from the trusted source. No cached "ready" verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub config: Configuration, pub token: Token, pub status: Status,
    pub mapping: Mapping, pub scope: Scope, pub proof: Proof, pub grant: Grant,
    pub query: u64, pub bytes: u64, pub channel: Verdict,
}
fn window(now: u64, first: u64, until: u64) -> bool { first <= now && now < until }

impl Scope {
    fn valid(self) -> bool {
        self.installation != 0 && self.policy != 0 && self.peer != 0 &&
        matches!(self.kind, 1..=3) && self.artifact != 0 && self.generation != 0 &&
        self.request != 0 && matches!(self.operation, 1 | 2) && matches!(self.role, 1 | 2) &&
        self.runtime != 0 && self.connection != 0 && self.binding != 0 &&
        self.local != 0 && self.incarnation != 0 && self.serial != 0 && self.challenge != 0
    }
}
impl Candidate {
    /// kc110_candidate, recomputed inside the coordinator at the final clock
    /// sample. Observation age begins BEFORE the outbound query, not at arrival.
    pub(super) fn valid(self, now: Now) -> bool {
        let c = self.config; let t = self.token; let i = self.status;
        let m = self.mapping; let s = self.scope; let p = self.proof; let g = self.grant;
        c.selected == Verdict::Valid && c.issuer != 0 && c.audience != 0 &&
        c.client != 0 && c.installation != 0 && c.policy != 0 && c.keyset != 0 &&
        c.profile == 1 && c.max_age != 0 && (1..=16384).contains(&c.max_bytes) &&
        self.bytes != 0 && self.bytes <= c.max_bytes &&
        t.syntax == Verdict::Valid && t.signature == Verdict::Valid &&
        t.reference != 0 && t.subject != 0 && t.holder != 0 &&
        t.issuer == c.issuer && t.audience == c.audience && t.client == c.client &&
        t.keyset == c.keyset && t.profile == c.profile && t.issued <= now.wall &&
        t.issued < t.until && window(now.wall, t.first, t.until) &&
        self.query != 0 && i.query == self.query && i.token == t.reference &&
        i.issuer == c.issuer && i.checked == Verdict::Valid && i.active == Verdict::Valid &&
        i.started <= i.observed && i.observed <= now.tick &&
        now.tick.checked_sub(i.started).is_some_and(|age| age < c.max_age) &&
        m.enabled == Verdict::Valid && m.issuer == c.issuer && m.subject == t.subject &&
        m.client == t.client && m.installation == c.installation && m.installation == s.installation &&
        m.policy == c.policy && m.policy == s.policy && m.peer == s.peer && m.kind == s.kind &&
        s.valid() && self.channel == Verdict::Valid && p.signature == Verdict::Valid &&
        p.token == t.reference && p.issuer == c.issuer && p.signer == t.holder && p.scope == s &&
        g.permission == Verdict::Valid && g.token == t.reference && g.scope == s &&
        window(now.wall, g.first, g.until)
    }
}
