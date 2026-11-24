use super::*;

#[test]
fn sa110_candidate_checks_all_scalar_bindings_and_windows() {
    let mutations: &[fn(&mut Candidate)] = &[
        |c| c.config.issuer = 0, |c| c.config.audience = 0, |c| c.config.client = 0,
        |c| c.config.installation = 0, |c| c.config.policy = 0, |c| c.config.keyset = 0,
        |c| c.config.profile = 2, |c| c.config.max_age = 0, |c| c.config.max_bytes = 0,
        |c| c.config.max_bytes = 16385, |c| c.config.max_bytes = 511,
        |c| c.token.reference = 0, |c| c.token.subject = 0, |c| c.token.holder = 0,
        |c| c.token.issuer += 1, |c| c.token.audience += 1, |c| c.token.client += 1,
        |c| c.token.keyset += 1, |c| c.token.profile += 1,
        |c| c.token.issued = 101, |c| c.token.issued = c.token.until,
        |c| c.token.first = 101, |c| c.token.until = 100,
        |c| c.query = 0, |c| c.query += 1, |c| c.bytes = 0, |c| c.bytes = 1025,
        |c| c.status.query += 1, |c| c.status.token += 1, |c| c.status.issuer += 1,
        |c| c.status.started = 99, |c| c.status.observed = 101, |c| c.status.started = 70,
        |c| c.mapping.issuer += 1, |c| c.mapping.subject += 1, |c| c.mapping.client += 1,
        |c| c.mapping.installation += 1, |c| c.mapping.policy += 1, |c| c.mapping.peer += 1,
        |c| c.mapping.kind += 1, |c| c.proof.token += 1, |c| c.proof.issuer += 1,
        |c| c.proof.signer += 1, |c| c.grant.token += 1, |c| c.grant.first = 101,
        |c| c.grant.until = 100,
    ];
    for (index, change) in mutations.iter().enumerate() {
        let r = Rig::open(); let mut c = candidate(); change(&mut c);
        r.data.lock().unwrap().candidate = Some(c);
        let before = r.view();
        assert_eq!(r.lane.attempt(&30, r.proposal(), |_| panic!("candidate gate {index}"), || Ok(())), Err(Error::Denied), "mutation {index}");
        assert_eq!(r.view().effects, 0); assert_eq!(r.view().remaining, before.remaining - 1);
    }
}
#[test]
fn sa110_candidate_unknown_and_invalid_verdicts_never_become_authority() {
    let fields: &[fn(&mut Candidate, Verdict)] = &[
        |c, v| c.config.selected = v, |c, v| c.token.syntax = v, |c, v| c.token.signature = v,
        |c, v| c.status.checked = v, |c, v| c.status.active = v, |c, v| c.mapping.enabled = v,
        |c, v| c.proof.signature = v, |c, v| c.grant.permission = v, |c, v| c.channel = v,
    ];
    for field in fields { for verdict in [Verdict::Unknown, Verdict::Invalid] {
        let r = Rig::open(); let mut c = candidate(); field(&mut c, verdict);
        r.data.lock().unwrap().candidate = Some(c);
        assert_eq!(r.use_once(), Err(Error::Denied)); assert_eq!(r.view().effects, 0);
    } }
}
fn scope_fields() -> Vec<fn(&mut Scope)> {
    vec![|s| s.installation += 1, |s| s.policy += 1, |s| s.peer += 1, |s| s.kind += 1,
        |s| s.artifact += 1, |s| s.generation += 1, |s| s.request += 1, |s| s.operation += 1,
        |s| s.role += 1, |s| s.runtime += 1, |s| s.connection += 1, |s| s.binding += 1,
        |s| s.local += 1, |s| s.incarnation += 1, |s| s.serial += 1, |s| s.challenge += 1]
}
#[test]
fn sa110_candidate_proof_and_grant_bind_every_scope_field() {
    for change in scope_fields() { for proof in [false, true] {
        let r = Rig::open(); let mut c = candidate();
        if proof { change(&mut c.proof.scope); } else { change(&mut c.grant.scope); }
        r.data.lock().unwrap().candidate = Some(c);
        assert_eq!(r.use_once(), Err(Error::Denied)); assert_eq!(r.view().effects, 0);
    } }
}
#[test]
fn sa110_candidate_rejects_coherently_malformed_scope_tags_and_zero_fields() {
    let changes: &[fn(&mut Scope)] = &[
        |s| s.installation = 0, |s| s.policy = 0, |s| s.peer = 0, |s| s.kind = 0,
        |s| s.kind = 4, |s| s.artifact = 0, |s| s.generation = 0, |s| s.request = 0,
        |s| s.operation = 0, |s| s.operation = 3, |s| s.role = 0, |s| s.role = 3,
        |s| s.runtime = 0, |s| s.connection = 0, |s| s.binding = 0, |s| s.local = 0,
        |s| s.incarnation = 0, |s| s.serial = 0, |s| s.challenge = 0,
    ];
    for change in changes {
        let r = Rig::open(); let mut c = candidate(); change(&mut c.scope);
        c.proof.scope = c.scope; c.grant.scope = c.scope;
        c.mapping.installation = c.scope.installation; c.mapping.policy = c.scope.policy;
        c.mapping.peer = c.scope.peer; c.mapping.kind = c.scope.kind;
        r.data.lock().unwrap().candidate = Some(c);
        let p = proposal(r.view(), *r.time.lock().unwrap(), c);
        assert_eq!(r.lane.attempt(&c.scope.peer, p, |_| true, || Ok(())), Err(Error::Denied));
    }
}
#[test]
fn sa110_candidate_accepts_formal_kind_role_operation_tags_and_boundary_values() {
    for kind in 1..=3 { for role in 1..=2 { for operation in 1..=2 {
        let r = Rig::open(); let mut c = candidate();
        c.scope.kind = kind; c.scope.role = role; c.scope.operation = operation;
        c.mapping.kind = kind; c.proof.scope = c.scope; c.grant.scope = c.scope;
        c.token.first = 100; c.token.issued = 100; c.grant.first = 100;
        c.status.started = 71; c.status.observed = 100; c.bytes = c.config.max_bytes;
        r.data.lock().unwrap().candidate = Some(c);
        let p = proposal(r.view(), *r.time.lock().unwrap(), c);
        r.lane.attempt(&30, p, |_| true, || Ok(())).unwrap();
    } } }
}
#[test]
fn sa110_candidate_age_starts_before_query_and_never_at_arrival() {
    let r = Rig::open(); let mut c = candidate();
    c.status.started = 70; c.status.observed = 100; r.data.lock().unwrap().candidate = Some(c);
    assert_eq!(r.use_once(), Err(Error::Denied));
    c.status.started = u64::MAX; c.status.observed = u64::MAX;
    r.data.lock().unwrap().candidate = Some(c); assert_eq!(r.use_once(), Err(Error::Denied));
    assert_eq!(r.view().effects, 0);
}
