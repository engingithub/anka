//! Private-pipe verdict fixtures here; Python tests exercise real RSA/mTLS.
use super::*;
#[derive(Clone)]
struct ManualClock(Arc<Mutex<Now>>);
impl Clock for ManualClock { fn now(&mut self) -> Now { *self.0.lock().unwrap() } }
fn config() -> Config {
    let scope = Scope { installation: 20, policy: 3, peer: 30, kind: 1, artifact: 40, generation: 2,
        request: 50, operation: 1, role: 1, runtime: 6, connection: 7, binding: 8, local: 9,
        incarnation: 5, serial: 10, challenge: 11 };
    Config { domain: 500, incarnation: 5, grant_id: 600, work: 64, deadline: 200, boot: 71,
        identity: Configuration { issuer: 10, audience: 21, client: 22, installation: 20, policy: 3,
            keyset: 4, profile: 1, max_age: 5, max_bytes: 16384, selected: Verdict::Valid },
        scope, grant: Grant { token: 101, scope, first: 95, until: 145, permission: Verdict::Valid } }
}
fn profile() -> Profile {
    Profile { config_path: PathBuf::from("/nonexistent/private-config.json"), token: b"a.b.c".to_vec(),
        issuer: "https://issuer/realms/r".into(), audience: "aud".into(), client: "client".into(),
        subject: "subject".into(), holder: [3; 32], subject_id: 31, holder_id: 32, max_age: 5 }
}
fn rig() -> (Adapter<ManualClock>, ManualClock) {
    let clock=ManualClock(Arc::new(Mutex::new(Now {wall:100,tick:100})));
    (Adapter::new(config(),profile(),clock.clone()).unwrap(),clock)
}
fn positive() -> codec::Reply { codec::Reply { outcome:1,times:[90,95,150],binding:[4;32] } }
fn issue(a: &mut Adapter<ManualClock>) {
    let q=a.owner.begin_query().unwrap();
    assert_eq!(a.complete_refresh(q,Ok(positive())),Ok(Refresh::Issued));
}
fn channel() -> Channel {
    Channel::from_authenticated_transport(30,config().scope,[3;32],[9;32]).unwrap()
}
fn reply_bytes(record: &[u8]) -> Vec<u8> {
    let mut out=b"LG110R1\0".to_vec();
    for v in [1u64,90,95,150] {out.extend_from_slice(&v.to_le_bytes());}
    out.extend_from_slice(&[4;32]);out.extend_from_slice(record);out
}
#[test]
fn la110_canonical_full_width_record_matches_python_golden() {
    let record=codec::record(2,[7;32],[1,500,5,600,1,3,100,101,10],config().scope,[3;32],[9;32],[4;32],&profile());
    assert_eq!(record.as_slice(),include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/scripts/keycloak/fixtures/lg110-holder-record.bin")));
    let mut p=profile();p.token=vec![b'a';16384];
    let wide=codec::record(2,[7;32],[u64::MAX;9],config().scope,[3;32],[9;32],[4;32],&p);
    assert_eq!(&wide[48..56],&u64::MAX.to_le_bytes());
    assert!(codec::request(&wide,&[0;512]).unwrap().len()<=codec::LIMIT);
}
#[test]
fn la110_reply_every_truncation_tail_and_correlation_substitution_denies() {
    let rec=codec::record(1,[7;32],[1,500,5,600,1,3,100,101,10],config().scope,[3;32],[0;32],[0;32],&profile());
    let raw=reply_bytes(&rec);assert_eq!(codec::decode(&rec,&raw),Ok(positive()));
    for n in 0..raw.len() {assert_eq!(codec::decode(&rec,&raw[..n]),Err(()));}
    let mut tail=raw.clone();tail.push(0);assert_eq!(codec::decode(&rec,&tail),Err(()));
    for offset in (72..raw.len()).chain(0..8) {
        let mut bad=raw.clone();bad[offset]^=1;assert_eq!(codec::decode(&rec,&bad),Err(()));
    }
}
#[test]
fn la110_reply_outcomes_never_accept_unknown_flags_or_positive_without_binding() {
    let rec=vec![0;400];let raw=reply_bytes(&rec);
    for outcome in [0,3,4,u64::MAX] {
        let mut bad=raw.clone();bad[8..16].copy_from_slice(&outcome.to_le_bytes());
        assert_eq!(codec::decode(&rec,&bad),Err(()));
    }
    let mut bad=raw;bad[40..72].fill(0);assert_eq!(codec::decode(&rec,&bad),Err(()));
}
#[test]
fn la110_profile_is_bounded_and_local_mapping_ids_are_explicit() {
    let mut p=profile();assert!(codec::valid_profile(&p));
    p.token=vec![0;16385];assert!(!codec::valid_profile(&p));
    let mut p=profile();p.subject_id=0;assert!(!codec::valid_profile(&p));
    let mut p=profile();p.holder_id=0;assert!(!codec::valid_profile(&p));
    let mut p=profile();p.subject="bad\nsubject".into();assert!(!codec::valid_profile(&p));
    let (_, clock)=rig();let mut c=config();c.identity.max_age=6;
    assert!(matches!(Adapter::new(c,profile(),clock),Err(Error::Configuration)));
}
#[test]
fn la110_checked_completion_pins_inputs_and_preserves_original_query_age() {
    let (mut a,clock)=rig();let q=a.owner.begin_query().unwrap();
    *clock.0.lock().unwrap()=Now {wall:100,tick:104};
    assert_eq!(a.complete_refresh(q,Ok(positive())),Ok(Refresh::Issued));
    assert_eq!(a.input_binding,[4;32]);assert_eq!(a.view().unwrap().effects,0);
    let observation=a.owner.inner.lock().unwrap().observation.unwrap();
    assert_eq!((observation.status.started,observation.status.observed),(100,104));
    assert_eq!((observation.token.subject,observation.token.holder),(31,32));
    assert_eq!(a.view().unwrap().boot,71);
}
#[test]
fn la110_late_completion_cannot_issue_or_pin_inputs() {
    let (mut a,clock)=rig();let q=a.owner.begin_query().unwrap();
    *clock.0.lock().unwrap()=Now {wall:100,tick:105};
    assert_eq!(a.complete_refresh(q,Ok(positive())),Err(Error::Denied));
    assert_eq!(a.input_binding,[0;32]);assert_eq!(a.view().unwrap().mode,Mode::Unissued);
}
#[test]
fn la110_outage_retains_old_bounds_and_verified_negative_closes() {
    let (mut a,_)=rig();issue(&mut a);
    let q=a.owner.begin_query().unwrap();assert_eq!(a.complete_refresh(q,Err(())),Ok(Refresh::Unavailable));
    assert_eq!(a.view().unwrap().mode,Mode::Issued);assert_eq!(a.input_binding,[4;32]);
    let q=a.owner.begin_query().unwrap();let mut r=positive();r.outcome=2;
    assert_eq!(a.complete_refresh(q,Ok(r)),Ok(Refresh::Revoked));
    assert_eq!(a.view().unwrap().mode,Mode::Revoked);
}
#[test]
fn la110_changed_config_binding_is_terminal_not_a_refresh() {
    for outcome in [1,3] {
        let (mut a,_)=rig();issue(&mut a);let q=a.owner.begin_query().unwrap();
        let mut r=positive();r.outcome=outcome;r.binding=[5;32];
        assert_eq!(a.complete_refresh(q,Ok(r)),Ok(Refresh::Revoked));
        assert_eq!(a.owner.begin_query(),Err(Error::Denied));
    }
}
#[test]
fn la110_revoker_closes_pending_remote_completion_without_adapter_lock() {
    let (mut a,_)=rig();issue(&mut a);let q=a.owner.begin_query().unwrap();
    let revoke=a.revoker();std::thread::spawn(move||revoke.revoke()).join().unwrap().unwrap();
    assert_eq!(a.complete_refresh(q,Ok(positive())),Err(Error::Denied));
    assert_eq!(a.view().unwrap().mode,Mode::Revoked);
}
#[test]
fn la110_preparation_binds_session_scope_and_actual_transport_certificate() {
    let (mut a,_)=rig();issue(&mut a);let c=a.prepare(channel()).unwrap();
    assert_eq!(&c.bytes()[16..48],&a.session);
    assert_eq!(&c.bytes()[280..312],&channel().binding);
    let mut wrong=channel();wrong.holder=[8;32];assert!(matches!(a.prepare(wrong),Err(Error::Denied)));
    wrong=channel();wrong.scope.connection+=1;assert!(matches!(a.prepare(wrong),Err(Error::Denied)));
    assert!(Channel::from_authenticated_transport(31,config().scope,[3;32],[9;32]).is_err());
    assert!(Channel::from_authenticated_transport(30,config().scope,[3;32],[0;32]).is_err());
    assert_eq!(a.preparations,61);
}
#[test]
fn la110_preparation_exhaustion_never_refills_on_refresh() {
    let (mut a,_)=rig();issue(&mut a);a.preparations=1;
    assert!(a.prepare(channel()).is_ok());
    let q=a.owner.begin_query().unwrap();assert_eq!(a.complete_refresh(q,Ok(positive())),Ok(Refresh::Refreshed));
    assert!(matches!(a.prepare(channel()),Err(Error::Exhausted)));
    a.workers=0;
    assert_eq!(a.invoke(&vec![0;400], &[]),Err(()));
    assert_eq!(a.workers,0);
}
#[test]
fn la110_staged_possession_is_single_use_and_cannot_move_to_another_channel() {
    let (mut a,_)=rig();issue(&mut a);let challenge=a.prepare(channel()).unwrap();let p=challenge.proposal;
    a.stage_possession(channel(),p,codec::Reply {outcome:1,times:[0;3],binding:[4;32]}).unwrap();
    let mut source=Mailbox(a.slots.clone());let mut wrong=channel();wrong.binding[0]^=1;
    assert!(source.possession(&wrong,p).is_none());assert!(source.possession(&channel(),p).is_some());
    assert!(source.possession(&channel(),p).is_none());
}
#[test]
fn la110_staged_proof_still_requires_current_owner_clock_and_existing_gate() {
    for late in [false,true] {
        let (mut a,clock)=rig();issue(&mut a);let challenge=a.prepare(channel()).unwrap();let p=challenge.proposal;
        a.stage_possession(channel(),p,codec::Reply {outcome:1,times:[0;3],binding:[4;32]}).unwrap();
        if late {*clock.0.lock().unwrap()=Now {wall:100,tick:101};}
        assert_eq!(a.owner.attempt(&channel(),p,|_|false,||Ok(())),Err(Error::Denied));
        assert_eq!(a.view().unwrap().effects,0);
    }
}
#[test]
fn la110_valid_staged_proof_submits_once_and_replay_cannot_escape_budget() {
    let (mut a,_)=rig();issue(&mut a);let challenge=a.prepare(channel()).unwrap();let p=challenge.proposal;
    a.stage_possession(channel(),p,codec::Reply {outcome:1,times:[0;3],binding:[4;32]}).unwrap();
    assert_eq!(a.owner.attempt(&channel(),p,|_|true,||Ok(42)),Ok(42));
    assert_eq!(a.owner.attempt(&channel(),p,|_|true,||Ok(42)),Err(Error::Denied));
    assert_eq!((a.view().unwrap().effects,a.view().unwrap().remaining),(1,60));
}
#[test]
fn la110_bad_signature_shape_and_changed_channel_spend_without_worker() {
    let (mut a,_)=rig();issue(&mut a);let challenge=a.prepare(channel()).unwrap();
    assert_eq!(a.attempt(channel(),challenge,&[],|_|true,||Ok(42)),Err(Error::Denied));
    let challenge=a.prepare(channel()).unwrap();let mut wrong=channel();wrong.binding[0]^=1;
    assert_eq!(a.attempt(wrong,challenge,&[0;256],|_|true,||Ok(42)),Err(Error::Denied));
    assert_eq!((a.view().unwrap().remaining,a.view().unwrap().effects),(60,0));
}

#[test]
fn la110_adapter_clock_rollback_between_preparations_is_terminal() {
    let (mut a,clock)=rig();issue(&mut a);
    *clock.0.lock().unwrap()=Now {wall:101,tick:104};
    assert!(a.prepare(channel()).is_ok());
    *clock.0.lock().unwrap()=Now {wall:100,tick:102};
    assert!(matches!(a.prepare(channel()),Err(Error::Poisoned)));
    *clock.0.lock().unwrap()=Now {wall:102,tick:104};
    assert_eq!(a.refresh(),Err(Error::Poisoned));
    assert!(matches!(a.view().unwrap().mode,Mode::Revoked|Mode::Poisoned));
}
