use super::*;

fn context() -> CompilerReplyContext {
    CompilerReplyContext::new(
        11,
        1,
        CompilerResourceBindings {
            source: 31,
            tools: 32,
            profile: 33,
            dependencies: 34,
            plan: 35,
        },
        73,
        4096,
        OutputGrowthSupport::CompilerOutput,
    )
    .unwrap()
}

fn reply(context: CompilerReplyContext, status: u64) -> [u64; 16] {
    let b = context.bindings;
    [
        COMPILER_RESOURCE_MAGIC,
        2,
        context.job,
        context.attempt,
        status,
        0,
        0,
        0,
        context.source_length,
        0,
        b.source,
        b.tools,
        b.profile,
        b.dependencies,
        b.plan,
        0,
    ]
}

fn bytes(words: [u64; 16]) -> [u8; 128] {
    let mut out = [0; 128];
    for (dest, word) in out.chunks_exact_mut(8).zip(words) {
        dest.copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn success(context: CompilerReplyContext) -> [u64; 16] {
    let mut words = reply(context, 0);
    words[7] = 112;
    words
}

fn need(context: CompilerReplyContext, minimum: u64) -> OutputCapacityNeed {
    let mut words = reply(context, 1);
    words[5] = COMPILER_OUTPUT_ROLE;
    words[6] = minimum;
    match context.decode(&bytes(words)).unwrap() {
        CompilerReplyMetadata::NeedOutputCapacity(need) => need,
        other => panic!("expected capacity metadata, got {other:?}"),
    }
}

fn budget() -> OutputRetryBudget {
    OutputRetryPolicy::new(64 * 4096, 3, 100)
        .unwrap()
        .start(context())
        .unwrap()
}

#[test]
fn c2_reply_decodes_exact_little_endian_success_metadata() {
    let c = context();
    assert_eq!(
        c.decode(&bytes(success(c))),
        Ok(CompilerReplyMetadata::SuccessMetadata { used_output: 112 })
    );
    let mut large = c;
    large.output_capacity = 512 * 1024;
    let mut words = success(large);
    words[7] = 256 * 1024 + 8;
    assert_eq!(
        large.decode(&bytes(words)),
        Ok(CompilerReplyMetadata::SuccessMetadata {
            used_output: words[7]
        })
    );
    // Decoding is deliberately not AOM validation or publication.
}

#[test]
fn c2_reply_rejects_truncation_suffix_and_wrong_endianness() {
    let c = context();
    let wire = bytes(success(c));
    for len in 0..128 {
        assert_eq!(
            c.decode(&wire[..len]),
            Err(CompilerResourceError::ReplyLength)
        );
    }
    let mut extended = wire.to_vec();
    extended.push(0);
    assert_eq!(c.decode(&extended), Err(CompilerResourceError::ReplyLength));
    let reversed = success(c).map(u64::swap_bytes);
    assert_eq!(
        c.decode(&bytes(reversed)),
        Err(CompilerResourceError::ReplyMagic)
    );
}

#[test]
fn c2_reply_checks_every_identity_binding_and_reserved_word() {
    let c = context();
    for (field, error) in [
        (0, CompilerResourceError::ReplyMagic),
        (1, CompilerResourceError::ReplyVersion),
        (2, CompilerResourceError::ReplyIdentity),
        (3, CompilerResourceError::ReplyIdentity),
        (10, CompilerResourceError::ReplyBindings),
        (11, CompilerResourceError::ReplyBindings),
        (12, CompilerResourceError::ReplyBindings),
        (13, CompilerResourceError::ReplyBindings),
        (14, CompilerResourceError::ReplyBindings),
        (15, CompilerResourceError::ReplyReserved),
    ] {
        let mut words = success(c);
        words[field] ^= 1;
        assert_eq!(c.decode(&bytes(words)), Err(error), "word {field}");
    }
}

#[test]
fn c2_reply_cannot_select_coordinator_status_or_legacy_error_eight() {
    let c = context();
    for status in [4, 5, 6, 7, 8, u64::MAX] {
        assert_eq!(
            c.decode(&bytes(reply(c, status))),
            Err(CompilerResourceError::ReplyStatus)
        );
    }
}

#[test]
fn c2_success_requires_exact_consumption_aligned_complete_prefix_and_zero_controls() {
    let c = context();
    for (field, value) in [
        (5, 3),
        (6, 8192),
        (7, 0),
        (7, 104),
        (7, 113),
        (7, 4104),
        (7, u64::MAX),
        (8, 72),
        (8, 74),
        (9, 1),
    ] {
        let mut words = success(c);
        words[field] = value;
        assert_eq!(
            c.decode(&bytes(words)),
            Err(CompilerResourceError::ReplyFields),
            "{field}={value}"
        );
    }
}

#[test]
fn c2_source_and_representation_rejections_are_terminal_metadata() {
    let c = context();
    for status in [2, 3] {
        let mut words = reply(c, status);
        words[8] = 12;
        words[9] = 8; // Diagnostic 8 is not NeedCapacity.
        let expected = if status == 2 {
            CompilerReplyMetadata::SourceRejected {
                cursor: 12,
                diagnostic: 8,
            }
        } else {
            CompilerReplyMetadata::RepresentationRejected {
                cursor: 12,
                diagnostic: 8,
            }
        };
        assert_eq!(c.decode(&bytes(words)), Ok(expected));
        for (field, value) in [(5, 3), (6, 8192), (7, 112), (8, 74), (9, 0)] {
            let mut bad = words;
            bad[field] = value;
            assert_eq!(
                c.decode(&bytes(bad)),
                Err(CompilerResourceError::ReplyFields)
            );
        }
    }
}

#[test]
fn c2_need_requires_admitted_output_growth_and_role_three() {
    let c = context();
    let mut words = reply(c, 1);
    words[5] = 3;
    words[6] = 4097;
    assert_eq!(need(c, 4097).minimum(), 4097);
    for role in (0..=17).filter(|role| *role != 3).chain([u64::MAX]) {
        words[5] = role;
        assert_eq!(
            c.decode(&bytes(words)),
            Err(CompilerResourceError::UnsupportedGrowth)
        );
    }
    let mut fixed = c;
    fixed.growth = OutputGrowthSupport::FixedOnly;
    words[5] = 3;
    assert_eq!(
        fixed.decode(&bytes(words)),
        Err(CompilerResourceError::UnsupportedGrowth)
    );
}

#[test]
fn c2_need_rejects_nonprogress_overflow_partial_output_and_diagnostics() {
    let c = context();
    let mut words = reply(c, 1);
    words[5] = 3;
    words[6] = 4097;
    for (field, value) in [
        (6, 0),
        (6, 4096),
        (6, AC2_MAX + 1),
        (6, u64::MAX),
        (7, 112),
        (8, 74),
        (9, 1),
    ] {
        let mut bad = words;
        bad[field] = value;
        assert_eq!(
            c.decode(&bytes(bad)),
            Err(CompilerResourceError::ReplyFields)
        );
    }
}

#[test]
fn c2_growth_rounds_minimum_doubles_and_saturates_at_ceiling() {
    let mut b = budget();
    b.reserve_work(1).unwrap();
    assert_eq!(
        b.propose_retry(&need(b.context(), 4097))
            .unwrap()
            .output_capacity(),
        8192
    );
    assert_eq!(
        b.propose_retry(&need(b.context(), 12000))
            .unwrap()
            .output_capacity(),
        12288
    );
    let mut c = context();
    c.output_capacity = 3 * 4096;
    let mut capped = OutputRetryPolicy::new(4 * 4096, 1, 10)
        .unwrap()
        .start(c)
        .unwrap();
    capped.reserve_work(1).unwrap();
    assert_eq!(
        capped
            .propose_retry(&need(c, 3 * 4096 + 1))
            .unwrap()
            .output_capacity(),
        4 * 4096
    );
}

#[test]
fn c2_growth_proposal_can_cross_old_output_limit_without_allocating() {
    let mut c = context();
    c.output_capacity = 256 * 1024;
    let mut b = OutputRetryPolicy::new(1024 * 1024, 2, 100)
        .unwrap()
        .start(c)
        .unwrap();
    b.reserve_work(10).unwrap();
    let p = b.propose_retry(&need(c, 256 * 1024 + 1)).unwrap();
    assert_eq!(p.output_capacity(), 512 * 1024);
    assert_eq!(p.next_attempt(), 2);
    assert_eq!(p.remaining_retries(), 1);
    assert_eq!(p.spent_work(), 10);
    assert_eq!(b.context(), c); // A preview grants nothing and commits nothing.
    assert_eq!(b.remaining_retries(), 2);
}

#[test]
fn c2_growth_near_signed_maximum_does_not_wrap_or_exceed_ceiling() {
    let ceiling = AC2_MAX & !(PAGE - 1);
    let mut c = context();
    c.output_capacity = ceiling - PAGE;
    let mut b = OutputRetryPolicy::new(ceiling, 1, 10)
        .unwrap()
        .start(c)
        .unwrap();
    b.reserve_work(1).unwrap();
    assert_eq!(
        b.propose_retry(&need(c, ceiling - 1))
            .unwrap()
            .output_capacity(),
        ceiling
    );
    assert_eq!(
        b.propose_retry(&need(c, AC2_MAX)),
        Err(CompilerResourceError::CapacityBudgetDenied)
    );
}

#[test]
fn c2_denial_and_repeated_preview_preserve_current_budget() {
    let mut b = budget();
    b.reserve_work(7).unwrap();
    let before = (b.context(), b.remaining_retries(), b.spent_work());
    assert_eq!(
        b.propose_retry(&need(b.context(), 64 * 4096 + 1)),
        Err(CompilerResourceError::CapacityBudgetDenied)
    );
    let n = need(b.context(), 4097);
    assert_eq!(b.propose_retry(&n), b.propose_retry(&n));
    assert_eq!((b.context(), b.remaining_retries(), b.spent_work()), before);
}

#[test]
fn c2_retry_hint_cannot_cross_job_attempt_or_frozen_context() {
    let mut b = budget();
    b.reserve_work(1).unwrap();
    for field in 0..10 {
        let mut c = context();
        match field {
            0 => c.job += 1,
            1 => c.attempt += 1,
            2 => c.bindings.source += 1,
            3 => c.bindings.tools += 1,
            4 => c.bindings.profile += 1,
            5 => c.bindings.dependencies += 1,
            6 => c.bindings.plan += 1,
            7 => c.source_length += 1,
            8 => c.output_capacity += PAGE,
            _ => c.job = u64::MAX,
        }
        assert_eq!(
            b.propose_retry(&need(c, c.output_capacity + 1)),
            Err(CompilerResourceError::ReplyIdentity)
        );
    }
}

#[test]
fn c2_retry_requires_positive_work_and_remaining_work_and_retries() {
    let mut b = budget();
    let n = need(b.context(), 4097);
    assert_eq!(
        b.propose_retry(&n),
        Err(CompilerResourceError::WorkBudgetDenied)
    );
    b.reserve_work(100).unwrap();
    assert_eq!(
        b.propose_retry(&n),
        Err(CompilerResourceError::WorkBudgetDenied)
    );
    let mut no_retries = OutputRetryPolicy::new(8192, 0, 100)
        .unwrap()
        .start(context())
        .unwrap();
    no_retries.reserve_work(1).unwrap();
    assert_eq!(
        no_retries.propose_retry(&n),
        Err(CompilerResourceError::RetryBudgetDenied)
    );
}

#[test]
fn c2_work_and_retry_counters_carry_forward_without_reset() {
    let mut b = budget();
    b.reserve_work(30).unwrap();
    // Inspect planned scalar states, not a real cleanup/admission/launch.
    for (attempt, spent) in [(2, 30), (3, 60), (4, 90)] {
        let n = need(b.context(), b.context.output_capacity + 1);
        let proposal = b.propose_retry(&n).unwrap();
        assert_eq!(proposal.next_attempt(), attempt);
        assert_eq!(proposal.spent_work(), spent);
        assert_eq!(proposal.next_budget.context.bindings, context().bindings);
        b = proposal.next_budget;
        let n = need(b.context(), b.context.output_capacity + 1);
        if b.remaining_retries() > 0 {
            assert_eq!(
                b.propose_retry(&n),
                Err(CompilerResourceError::WorkBudgetDenied)
            );
            b.reserve_work(30).unwrap();
        } else {
            assert_eq!(
                b.propose_retry(&n),
                Err(CompilerResourceError::RetryBudgetDenied)
            );
        }
    }
    assert_eq!(b.spent_work(), 90);
}

#[test]
fn c2_work_reservations_reject_zero_overflow_and_exhaustion_without_mutation() {
    let mut b = OutputRetryPolicy::new(8192, 1, u64::MAX)
        .unwrap()
        .start(context())
        .unwrap();
    assert_eq!(
        b.reserve_work(0),
        Err(CompilerResourceError::WorkBudgetDenied)
    );
    b.reserve_work(u64::MAX - 1).unwrap();
    assert_eq!(
        b.reserve_work(2),
        Err(CompilerResourceError::WorkBudgetDenied)
    );
    assert_eq!(b.spent_work(), u64::MAX - 1);
    b.reserve_work(1).unwrap();
    assert_eq!(
        b.reserve_work(1),
        Err(CompilerResourceError::WorkBudgetDenied)
    );
    assert_eq!(b.spent_work(), u64::MAX);
}

#[test]
fn c2_attempt_identity_never_wraps() {
    let mut c = context();
    c.attempt = u64::MAX;
    let mut b = OutputRetryPolicy::new(8192, 1, 10)
        .unwrap()
        .start(c)
        .unwrap();
    b.reserve_work(1).unwrap();
    assert_eq!(
        b.propose_retry(&need(c, 4097)),
        Err(CompilerResourceError::AttemptExhausted)
    );
    assert_eq!(b.context(), c);
    assert_eq!(b.remaining_retries(), 1);
}

#[test]
fn c2_configuration_rejects_invalid_identity_capacity_binding_and_source_span() {
    let c = context();
    for capacity in [0, 1, 4095, 4097, AC2_MAX, AC2_MAX + 1, u64::MAX] {
        assert_eq!(
            OutputRetryPolicy::new(capacity, 1, 10),
            Err(CompilerResourceError::InvalidConfiguration)
        );
        assert!(CompilerReplyContext::new(1, 1, c.bindings, 73, capacity, c.growth).is_err());
    }
    for (job, attempt, source) in [
        (0, 1, 73),
        (1, 0, 73),
        (1, 1, AC2_MAX - 6),
        (1, 1, u64::MAX),
    ] {
        assert!(
            CompilerReplyContext::new(job, attempt, c.bindings, source, 4096, c.growth).is_err()
        );
    }
    for i in 0..5 {
        let mut b = c.bindings;
        match i {
            0 => b.source = 0,
            1 => b.tools = 0,
            2 => b.profile = 0,
            3 => b.dependencies = 0,
            _ => b.plan = 0,
        }
        assert!(CompilerReplyContext::new(1, 1, b, 73, 4096, c.growth).is_err());
    }
    assert_eq!(
        OutputRetryPolicy::new(8192, 1, 0),
        Err(CompilerResourceError::InvalidConfiguration)
    );
    let mut c = c;
    c.output_capacity = 8192;
    assert_eq!(
        OutputRetryPolicy::new(4096, 1, 1).unwrap().start(c),
        Err(CompilerResourceError::CapacityBudgetDenied)
    );
}
