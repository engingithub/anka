use super::*;
pub(super) const LIMIT: usize = 24576;
pub(super) fn valid_profile(p: &Profile) -> bool {
    let text = |s: &str, max: usize| !s.is_empty() && s.len() <= max &&
        !s.chars().any(|c| c.is_control());
    !p.config_path.as_os_str().is_empty() && !p.token.is_empty() && p.token.len() <= 16384 &&
        text(&p.issuer, 2048) && text(&p.audience, 256) && text(&p.client, 256) && text(&p.subject, 256) &&
        p.holder != [0; 32] && p.subject_id != 0 && p.holder_id != 0 && (1..=5).contains(&p.max_age)
}
pub(super) fn query(q: Query) -> [u64; 9] {
    [q.owner, q.domain, q.incarnation, q.grant_id, q.revision, q.sequence, q.started, q.token, q.issuer]
}
pub(super) fn proposal(p: Proposal, c: Config) -> [u64; 9] {
    [p.owner, p.domain, p.incarnation, p.grant_id, p.revision, p.sequence, p.at_tick, c.grant.token, c.identity.issuer]
}
fn scope_words(s: Scope) -> [u64; 16] {
    [s.installation, s.policy, s.peer, s.kind, s.artifact, s.generation, s.request, s.operation,
     s.role, s.runtime, s.connection, s.binding, s.local, s.incarnation, s.serial, s.challenge]
}
/// Canonical binary signed record: magic, kind, random session, nine correlation
/// u64s, sixteen scope u64s, three full 32-byte bindings, max-age u64, then length-prefixed
/// exact token/issuer/audience/client/subject bytes. All integers little-endian.
/// Record is signed in full; signature length/data are transport framing only.
pub(super) fn record(kind: u64, session: [u8; 32], correlation: [u64; 9], scope: Scope,
    holder: [u8; 32], channel: [u8; 32], inputs: [u8; 32], p: &Profile) -> Vec<u8>
{
    let mut out = Vec::with_capacity(512 + p.token.len());
    out.extend_from_slice(b"LG110A1\0"); out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&session);
    for value in correlation.into_iter().chain(scope_words(scope)) { out.extend_from_slice(&value.to_le_bytes()); }
    for value in [holder, channel, inputs] { out.extend_from_slice(&value); }
    out.extend_from_slice(&p.max_age.to_le_bytes());
    for value in [p.token.as_slice(), p.issuer.as_bytes(), p.audience.as_bytes(), p.client.as_bytes(), p.subject.as_bytes()] {
        out.extend_from_slice(&(value.len() as u32).to_le_bytes()); out.extend_from_slice(value);
    }
    out
}
pub(super) fn request(record: &[u8], signature: &[u8]) -> Result<Vec<u8>, ()> {
    if record.len() < 352 || record.len() + 4 + signature.len() > LIMIT || signature.len() > 512 { return Err(()); }
    let mut out = record.to_vec(); out.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    out.extend_from_slice(signature); Ok(out)
}
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Reply { pub outcome: u64, pub times: [u64; 3], pub binding: [u8; 32] }
pub(super) fn decode(record: &[u8], raw: &[u8]) -> Result<Reply, ()> {
    if raw.len() != record.len() + 72 || raw.len() > LIMIT + 72 || &raw[..8] != b"LG110R1\0" ||
        &raw[72..] != record { return Err(()); }
    let word = |n| u64::from_le_bytes(raw[n..n+8].try_into().unwrap());
    let r = Reply { outcome: word(8), times: [word(16), word(24), word(32)], binding: raw[40..72].try_into().unwrap() };
    if r.outcome > 3 || (matches!(r.outcome, 0 | 3) && (r.times != [0; 3] || r.binding != [0; 32])) ||
        (matches!(r.outcome, 1 | 2) && r.binding == [0; 32]) { return Err(()); }
    Ok(r)
}
