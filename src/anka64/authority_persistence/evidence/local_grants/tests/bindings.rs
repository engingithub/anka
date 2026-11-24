use super::*;

#[test]
fn lg110_every_query_binding_rejects_foreign_request_and_reply() {
    let changes: &[fn(&mut Query)] = &[
        |q| q.owner += 1, |q| q.domain += 1, |q| q.incarnation += 1,
        |q| q.grant_id += 1, |q| q.revision += 1, |q| q.sequence += 1,
        |q| q.started += 1, |q| q.token += 1, |q| q.issuer += 1,
    ];
    for change in changes {
        for foreign_request in [false, true] {
            let r = Rig::issued(); let q = r.owner.begin_query().unwrap();
            let mut foreign = q; change(&mut foreign);
            let mut c = completion(if foreign_request { q } else { foreign });
            c.result = Verdict::Invalid; r.stage(c);
            assert_eq!(r.owner.complete(if foreign_request { foreign } else { q }), Err(Error::Denied));
            assert_eq!(r.view().pending, Some(q)); assert_eq!(r.view().mode, Mode::Issued);
            assert_eq!(r.inputs.lock().unwrap().calls[0], if foreign_request { 1 } else { 2 });
        }
    }
}
#[test]
fn lg110_every_observation_binding_is_rechecked_without_cached_ready_bit() {
    let changes: &[fn(&mut Observation)] = &[
        |o| o.token.reference += 1, |o| o.token.issuer += 1, |o| o.token.audience += 1,
        |o| o.token.client += 1, |o| o.token.subject = 0, |o| o.token.holder = 0,
        |o| o.token.keyset += 1, |o| o.token.profile += 1,
        |o| o.token.issued = 101, |o| o.token.first = 101, |o| o.token.until = 100,
        |o| o.token.syntax = Verdict::Unknown, |o| o.token.signature = Verdict::Invalid,
        |o| o.status.token += 1, |o| o.status.issuer += 1, |o| o.status.query += 1,
        |o| o.status.started = 99, |o| o.status.observed = 99, |o| o.status.observed = 101,
        |o| o.status.checked = Verdict::Unknown, |o| o.status.active = Verdict::Invalid,
        |o| o.mapping.issuer += 1, |o| o.mapping.subject += 1, |o| o.mapping.client += 1,
        |o| o.mapping.installation += 1, |o| o.mapping.peer += 1, |o| o.mapping.kind += 1,
        |o| o.mapping.policy += 1, |o| o.mapping.enabled = Verdict::Unknown,
        |o| o.bytes = 0, |o| o.bytes = 1025,
    ];
    for change in changes {
        let r = Rig::new(config()); let q = r.owner.begin_query().unwrap(); let mut c = completion(q);
        change(c.observation.as_mut().unwrap()); r.stage(c);
        assert_eq!(r.owner.complete(q), Err(Error::Denied)); assert_eq!(r.view().mode, Mode::Unissued);
        assert_eq!(r.view().effects, 0);
    }
}
#[test]
fn lg110_refresh_cannot_rebind_token_reference_to_different_claims() {
    let changes: &[fn(&mut Observation)] = &[
        |o| o.token.holder += 1,
        |o| { o.token.subject += 1; o.mapping.subject += 1; },
        |o| o.token.issued += 1, |o| o.token.first += 1, |o| o.token.until += 1,
        |o| o.bytes += 1,
    ];
    for change in changes {
        let r = Rig::issued(); let old = r.owner.inner.lock().unwrap().observation;
        let q = r.owner.begin_query().unwrap(); let mut c = completion(q);
        change(c.observation.as_mut().unwrap()); r.stage(c);
        // Mutated evidence independently passes static identity checks, but may
        // not replace the immutable bytes/claims under the same token handle.
        assert!(c.observation.unwrap().identity(r.config, q.sequence).valid(Now { wall: 100, tick: 100 }));
        assert_eq!(r.owner.complete(q), Err(Error::Denied));
        assert_eq!(r.owner.inner.lock().unwrap().observation, old);
        assert_eq!(r.run(), Ok(42));
    }
}
fn proposal_changes() -> Vec<fn(&mut Proposal)> {
    vec![|p| p.owner += 1, |p| p.domain += 1, |p| p.incarnation += 1,
        |p| p.grant_id += 1, |p| p.revision += 1, |p| p.sequence += 1, |p| p.at_tick += 1]
}
fn scope_changes() -> Vec<fn(&mut Scope)> {
    vec![|s| s.installation += 1, |s| s.policy += 1, |s| s.peer += 1, |s| s.kind += 1,
        |s| s.artifact += 1, |s| s.generation += 1, |s| s.request += 1, |s| s.operation = 2,
        |s| s.role = 2, |s| s.runtime += 1, |s| s.connection += 1, |s| s.binding += 1,
        |s| s.local += 1, |s| s.incarnation += 1, |s| s.serial += 1, |s| s.challenge += 1]
}
#[test]
fn lg110_proposal_owner_sequence_tick_and_entire_scope_are_exact() {
    for change in proposal_changes() {
        let r = Rig::issued(); let mut p = r.proposal(); change(&mut p);
        assert_eq!(r.owner.attempt(&30, p, |_| panic!("gate"), || Ok(())), Err(Error::Denied));
        assert_eq!(r.inputs.lock().unwrap().calls[1], 0);
    }
    for change in scope_changes() {
        let r = Rig::issued(); let mut p = r.proposal(); change(&mut p.scope);
        assert_eq!(r.owner.attempt(&30, p, |_| panic!("gate"), || Ok(())), Err(Error::Denied));
        assert_eq!(r.inputs.lock().unwrap().calls[1], 0);
    }
}
#[test]
fn lg110_full_possession_record_is_bound_to_original_proposal() {
    for change in proposal_changes() {
        let r = Rig::issued(); let p = r.proposal(); let mut proof = possession(p, r.config.scope);
        change(&mut proof.proposal); r.inputs.lock().unwrap().use_reply = Some(proof);
        assert_eq!(r.run(), Err(Error::Denied)); assert_eq!(r.view().effects, 0);
    }
    for change in scope_changes() {
        let r = Rig::issued(); let p = r.proposal(); let mut proof = possession(p, r.config.scope);
        change(&mut proof.proposal.scope); r.inputs.lock().unwrap().use_reply = Some(proof);
        assert_eq!(r.run(), Err(Error::Denied));
    }
}
#[test]
fn lg110_holder_proof_channel_and_actual_peer_are_independent_requirements() {
    let changes: &[fn(&mut Possession)] = &[
        |p| p.checked = Verdict::Unknown, |p| p.checked = Verdict::Invalid,
        |p| p.channel = Verdict::Unknown, |p| p.channel = Verdict::Invalid,
        |p| p.proof.token += 1, |p| p.proof.issuer += 1, |p| p.proof.signer += 1,
        |p| p.proof.signature = Verdict::Unknown, |p| p.proof.signature = Verdict::Invalid,
    ];
    for change in changes {
        let r = Rig::issued(); let mut p = possession(r.proposal(), r.config.scope);
        change(&mut p); r.inputs.lock().unwrap().use_reply = Some(p);
        assert_eq!(r.run(), Err(Error::Denied)); assert_eq!(r.view().effects, 0);
    }
    for change in scope_changes() {
        let r = Rig::issued(); let mut p = possession(r.proposal(), r.config.scope);
        change(&mut p.proof.scope); r.inputs.lock().unwrap().use_reply = Some(p);
        assert_eq!(r.run(), Err(Error::Denied));
    }
    let r = Rig::issued();
    assert_eq!(r.owner.attempt(&31, r.proposal(), |_| true, || Ok(())), Err(Error::Denied));
    r.inputs.lock().unwrap().missing_use = true; assert_eq!(r.run(), Err(Error::Denied));
}
#[test]
fn lg110_role_two_is_separate_from_caller_role_and_never_auto_projected() {
    let mut c = config(); c.scope.role = 2; c.grant.scope = c.scope;
    let r = Rig::new(c); r.issue(); assert_eq!(r.run(), Ok(42));
    let mut p = r.proposal(); p.scope.role = 1;
    assert_eq!(r.owner.attempt(&30, p, |_| true, || Ok(42)), Err(Error::Denied));
    assert_eq!(r.view().effects, 1); assert_eq!(r.view().boot, 71);
}
