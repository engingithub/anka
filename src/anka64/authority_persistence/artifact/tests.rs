use super::*;
use std::sync::atomic::{AtomicU64,Ordering};
static SERIAL:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {fn new()->Self {
    let n=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    Self(std::env::temp_dir().join(format!("anka-artifact-{}-{n}-{}",std::process::id(),SERIAL.fetch_add(1,Ordering::Relaxed))))
}}
impl Drop for Temp {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn limits()->Limits {Limits{max_payload:32768,window:4096,owner_bytes:65536,total_bytes:131072,other_bytes:20000,work:20}}
fn selected()->Selection {Selection{revision:7,artifact:55,generation:1}}
fn caller()->Caller {Caller{owner:30,incarnation:4}}
fn manifest()->Manifest {Manifest{anchor:10,installation:20,artifact:99,generation:2,role:2,profile:4,size:10000,image:101,metadata:102,dependencies:103,provenance:104}}
fn payload()->Vec<u8> {(0..10000).map(|n|n as u8).collect()}
struct Proof {manifest:Manifest,bytes:Vec<u8>,boot:u64,checks:usize,deny_after:Option<usize>,retired:Verdict,consume:bool,action:Option<Action>}
impl Proof {fn new()->Self {Self{manifest:manifest(),bytes:payload(),boot:9,checks:0,deny_after:None,retired:Verdict::Valid,consume:true,action:None}}}
impl Evidence for Proof {
    fn authorize(&mut self,s:Scope)->Verdict {
        self.checks+=1;
        if s.manifest!=self.manifest || s.boot!=self.boot || s.caller.owner==0 || s.caller.incarnation==0
            || self.deny_after.is_some_and(|n|self.checks>n) || self.action.is_some_and(|a|s.action!=a) {Verdict::Invalid}else{Verdict::Valid}
    }
    fn inspect(&mut self,r:&mut dyn Read)->Result<Manifest,Error> {
        if !self.consume {return Ok(self.manifest)}
        let mut got=Vec::new();r.read_to_end(&mut got).map_err(io_error)?;
        if got!=self.bytes {return Err(Error::CorruptRecord)}
        Ok(self.manifest)
    }
    fn retired(&mut self,s:Scope)->Verdict {if s.boot==self.boot && s.manifest==self.manifest {self.retired}else{Verdict::Invalid}}
}
fn empty()->(Temp,ArtifactStore,Proof) {
    let t=Temp::new();let s=ArtifactStore::create(&t.0,10,20,9,limits(),selected()).unwrap();(t,s,Proof::new())
}
fn reserved()->(Temp,ArtifactStore,Proof,Ticket) {
    let(t,mut s,mut e)=empty();let h=s.reserve(manifest(),caller(),&mut e).unwrap();(t,s,e,h)
}
fn fill(s:&mut ArtifactStore,h:Ticket,e:&mut Proof) {
    let bytes=payload();let start=s.state.cursor as usize;
    for (i,b) in bytes[start..].chunks(limits().window as usize).enumerate() {
        s.append(h,start as u64+i as u64*limits().window,b,e).unwrap();
    }
}
fn sealed()->(Temp,ArtifactStore,Proof,Ticket) {
    let(t,mut s,mut e,h)=reserved();fill(&mut s,h,&mut e);s.seal(h,&mut e).unwrap();(t,s,e,h)
}
fn head(s:&ArtifactStore)->Vec<u8> {fs::read(s.dir.join(HEAD)).unwrap()}
fn reopen(t:&Temp)->ArtifactStore {ArtifactStore::open(&t.0,10,20,9,limits()).unwrap()}
fn resign(bytes:&mut [u8]) {let n=bytes.len();let crc=checksum(&bytes[..n-8]);bytes[n-8..].copy_from_slice(&crc.to_le_bytes());}
fn word(bytes:&mut [u8],index:usize,n:u64) {bytes[8+index*8..16+index*8].copy_from_slice(&n.to_le_bytes());resign(bytes);}

#[test]
fn as110_codec_exact_shape_and_all_bit_flips() {
    let(_t,s,_e)=empty();let bytes=codec::encode(&s.state).unwrap();assert_eq!(bytes.len(),336);
    assert_eq!(codec::decode(&bytes,10,20),Ok(s.state.clone()));
    for i in 0..bytes.len() {for bit in 0..8 {let mut bad=bytes;bad[i]^=1<<bit;assert!(codec::decode(&bad,10,20).is_err());}}
    for n in 0..bytes.len() {assert!(codec::decode(&bytes[..n],10,20).is_err());}
    let mut tail=bytes.to_vec();tail.push(0);assert!(codec::decode(&tail,10,20).is_err());
    for (i,v) in [(0,2),(10,5),(14,1),(25,1),(36,1),(4,0)] {
        let mut bad=bytes;word(&mut bad,i,v);assert!(codec::decode(&bad,10,20).is_err());
    }
    assert_eq!(codec::decode(&bytes,11,20),Err(Error::Authority));
}
#[test]
fn as110_reservation_quota_denials_preserve_generation_and_head() {
    for owner in [true,false] {
        let t=Temp::new();let mut l=limits();let charge=l.charge(manifest()).unwrap();
        if owner {l.owner_bytes=charge-1}else{l.total_bytes=l.other_bytes+charge-1}
        let mut s=ArtifactStore::create(&t.0,10,20,9,l,selected()).unwrap();let old=head(&s);
        assert_eq!(s.reserve(manifest(),caller(),&mut Proof::new()),Err(Error::Capacity));assert_eq!(head(&s),old);assert_eq!(s.state.high,0);
    }
}
#[test]
fn as110_configuration_overflow_and_bad_geometry_fail_before_create() {
    for l in [Limits{window:0,..limits()},Limits{max_payload:1,..limits()},Limits{window:u64::MAX,max_payload:u64::MAX,..limits()},Limits{other_bytes:u64::MAX,..limits()}] {
        let t=Temp::new();assert!(ArtifactStore::create(&t.0,10,20,9,l,selected()).is_err());assert!(!t.0.exists());
    }
}
#[test]
fn as110_default_authority_denies_without_writes() {
    let(_t,mut s,_e)=empty();let old=head(&s);
    assert_eq!(s.reserve(manifest(),caller(),&mut Deny),Err(Error::Authority));assert_eq!(head(&s),old);assert!(!s.dir.join(DATA).exists());
}
#[test]
fn as110_real_file_chunks_retry_tail_seal_publish_and_read() {
    let(t,mut s,mut e,h)=reserved();let bytes=payload();let usage=s.usage().unwrap();
    s.append(h,0,&bytes[..4096],&mut e).unwrap();let work=s.state.remaining;
    s.append(h,0,&bytes[..4096],&mut e).unwrap();assert_eq!(s.state.cursor,4096);assert_eq!(s.state.remaining,work-1);
    s.append(h,4096,&bytes[4096..8192],&mut e).unwrap();s.append(h,8192,&bytes[8192..],&mut e).unwrap();
    s.seal(h,&mut e).unwrap();assert_eq!(s.state.selected,selected());assert_eq!(s.usage().unwrap(),usage);
    s.seal(h,&mut e).unwrap();let result=s.publish(h,70,7,&mut e).unwrap();assert_eq!(result.revision,8);
    assert_eq!(s.read(Caller{owner:31,incarnation:5},8192,1808,&mut e).unwrap(),bytes[8192..]);
    assert_eq!(fs::read(t.0.join(DATA)).unwrap(),bytes);assert_eq!(s.usage().unwrap(),usage);
}
#[test]
fn as110_chunk_forgery_gap_window_and_stale_ticket_are_rejected() {
    let(_t,mut s,mut e,h)=reserved();let bytes=payload();s.append(h,0,&bytes[..4096],&mut e).unwrap();let old=head(&s);
    assert_eq!(s.append(h,1,&bytes[..64],&mut e),Err(Error::Conflict));
    let mut changed=bytes[..4096].to_vec();changed[12]^=1;assert_eq!(s.append(h,0,&changed,&mut e),Err(Error::Conflict));
    assert_eq!(s.append(h,4096,&bytes[..4097],&mut e),Err(Error::Capacity));
    assert_eq!(s.append(Ticket{serial:h.serial+1,..h},4096,&bytes[..64],&mut e),Err(Error::Authority));
    assert_eq!(s.append(Ticket{caller:Caller{owner:31,..caller()},..h},4096,&bytes[..64],&mut e),Err(Error::Authority));
    assert_eq!(head(&s),old);
}
#[test]
fn as110_retry_spends_one_finite_work_budget() {
    let t=Temp::new();let l=Limits{work:2,..limits()};let mut s=ArtifactStore::create(&t.0,10,20,9,l,selected()).unwrap();let mut e=Proof::new();let h=s.reserve(manifest(),caller(),&mut e).unwrap();
    s.append(h,0,&payload()[..64],&mut e).unwrap();s.append(h,0,&payload()[..64],&mut e).unwrap();let old=head(&s);
    assert_eq!(s.append(h,0,&payload()[..64],&mut e),Err(Error::Capacity));assert_eq!(head(&s),old);
}
#[test]
fn as110_seal_checks_actual_bytes_and_all_manifest_fields() {
    let(_t,mut s,mut e,h)=reserved();assert_eq!(s.seal(h,&mut e),Err(Error::Conflict));fill(&mut s,h,&mut e);
    e.consume=false;assert_eq!(s.seal(h,&mut e),Err(Error::CorruptRecord));e.consume=true;
    // Keep authorization valid while the validator reports different actual metadata.
    struct Wrong {inner:Proof}
    impl Evidence for Wrong {
        fn authorize(&mut self,s:Scope)->Verdict {self.inner.authorize(s)}
        fn inspect(&mut self,r:&mut dyn Read)->Result<Manifest,Error> {let mut m=self.inner.inspect(r)?;m.provenance+=1;Ok(m)}
    }
    assert_eq!(s.seal(h,&mut Wrong{inner:Proof::new()}),Err(Error::CorruptRecord));assert_eq!(s.state.phase,Phase::Staging);
    s.seal(h,&mut e).unwrap();assert_eq!(s.append(h,10000,&[1],&mut e),Err(Error::Conflict));
}
#[test]
fn as110_lost_publication_reply_reopens_and_retries_exactly_once() {
    let(t,mut s,mut e,h)=sealed();let result=s.publish(h,70,7,&mut e).unwrap();drop(s);
    let mut s=reopen(&t);assert_eq!(s.publish(h,70,7,&mut e),Ok(result));assert_eq!(s.state.selected.revision,8);
    assert_eq!(s.publish(h,71,7,&mut e),Err(Error::Conflict));assert_eq!(s.publish(h,70,8,&mut e),Err(Error::Conflict));
}
#[test]
fn as110_publish_requires_distinct_grant_and_expected_revision() {
    let(_t,mut s,mut e,h)=sealed();let old=head(&s);e.action=Some(Action::Upload);
    assert_eq!(s.publish(h,70,7,&mut e),Err(Error::Authority));e.action=None;
    assert_eq!(s.publish(h,70,6,&mut e),Err(Error::Conflict));assert_eq!(head(&s),old);
}
#[test]
fn as110_revocation_after_commit_hides_reply_without_rollback() {
    let(t,mut s,mut e,h)=sealed();e.checks=0;e.deny_after=Some(2);
    assert_eq!(s.publish(h,70,7,&mut e),Err(Error::Authority));assert_eq!(s.state.phase,Phase::Published);drop(s);
    let mut s=reopen(&t);assert_eq!(s.publish(h,70,7,&mut Proof::new()).unwrap().revision,8);
}
#[test]
fn as110_read_rechecks_evidence_after_validation_and_bounds_range() {
    let(_t,mut s,mut e,h)=sealed();s.publish(h,70,7,&mut e).unwrap();e.checks=0;e.deny_after=Some(1);
    assert_eq!(s.read(caller(),0,64,&mut e),Err(Error::Authority));e.deny_after=None;
    assert_eq!(s.read(caller(),9999,2,&mut e),Err(Error::InvalidRequest));assert_eq!(s.read(caller(),0,4097,&mut e),Err(Error::InvalidRequest));
    assert_eq!(s.read(caller(),u64::MAX,1,&mut e),Err(Error::InvalidRequest));
}
#[test]
fn as110_published_objects_cannot_be_written_or_deleted() {
    let(t,mut s,mut e,h)=sealed();s.publish(h,70,7,&mut e).unwrap();let old=head(&s);
    assert_eq!(s.discard(h,&mut e),Err(Error::Conflict));assert_eq!(s.reap(h,&mut e),Err(Error::Conflict));
    assert_eq!(s.append(h,0,&[1],&mut e),Err(Error::Conflict));assert_eq!(head(&s),old);assert!(t.0.join(DATA).exists());
}
#[test]
fn as110_a_cleanup_c_reuse_preserves_b_and_rejects_a_alias() {
    let(_ta,mut a,mut ea,ha)=sealed();let(_tb,mut b,mut eb,hb)=sealed();b.publish(hb,70,7,&mut eb).unwrap();let before=head(&b);
    a.discard(ha,&mut ea).unwrap();let idle=a.usage().unwrap();assert_eq!(idle.candidate,0);assert_eq!(idle.other,20000);assert!(idle.service>0);
    let hc=a.reserve(manifest(),Caller{owner:32,incarnation:5},&mut ea).unwrap();assert!(hc.serial>ha.serial);
    assert_eq!(a.append(ha,0,&[1],&mut ea),Err(Error::Authority));assert_eq!(head(&b),before);
    assert_eq!(b.read(caller(),0,64,&mut eb).unwrap(),payload()[..64]);
}
#[test]
fn as110_retirement_cleanup_is_separate_from_live_user_authority() {
    let(_t,mut s,mut e,h)=sealed();e.deny_after=Some(0);e.retired=Verdict::Unknown;
    assert_eq!(s.discard(h,&mut e),Err(Error::Authority));assert_eq!(s.reap(h,&mut e),Err(Error::Authority));
    e.retired=Verdict::Valid;s.reap(h,&mut e).unwrap();assert_eq!(s.state.phase,Phase::Empty);
}
#[test]
fn as110_cleanup_crash_intent_and_deletion_recover_before_refund() {
    for cut in [Cut::CleanupIntent,Cut::PayloadDeleted] {
        let(t,mut s,mut e,h)=sealed();s.cut=Some(cut);assert_eq!(s.discard(h,&mut e),Err(Error::CommitUncertain));
        assert!(s.state.charge>0);assert_eq!(s.usage(),Err(Error::CommitUncertain));drop(s);
        let mut s=reopen(&t);assert_eq!(s.state.phase,Phase::Empty);assert!(!t.0.join(DATA).exists());assert_eq!(s.state.high,h.serial);
        let next=s.reserve(manifest(),caller(),&mut e).unwrap();assert!(next.serial>h.serial);
    }
}
#[test]
fn as110_reservation_cut_points_never_issue_an_undurable_handle() {
    for cut in [Cut::BeforeLedger,Cut::PartialLedger,Cut::LedgerSynced,Cut::Renamed,Cut::DirectorySynced] {
        let(t,mut s,mut e)=empty();s.cut=Some(cut);assert_eq!(s.reserve(manifest(),caller(),&mut e),Err(Error::CommitUncertain));drop(s);
        let mut s=reopen(&t);let h=s.reserve(manifest(),caller(),&mut e).unwrap();assert_eq!(h.serial,1);
        assert_eq!(s.reserve(manifest(),caller(),&mut e),Ok(h));assert_eq!(s.state.high,1);
    }
}
#[test]
fn as110_append_cut_points_recover_only_acknowledged_prefix() {
    for cut in [Cut::PayloadWritten,Cut::PartialLedger,Cut::LedgerSynced,Cut::Renamed,Cut::DirectorySynced] {
        let(t,mut s,mut e,h)=reserved();s.cut=Some(cut);assert_eq!(s.append(h,0,&payload()[..64],&mut e),Err(Error::CommitUncertain));drop(s);
        let mut s=reopen(&t);assert!(s.state.cursor==0 || s.state.cursor==64);
        assert_eq!(fs::metadata(t.0.join(DATA)).unwrap().len(),s.state.cursor);
        s.append(h,0,&payload()[..64],&mut e).unwrap();assert_eq!(s.state.cursor,64);
    }
}
#[test]
fn as110_publication_cut_points_keep_old_or_complete_new() {
    for cut in [Cut::BeforeLedger,Cut::PartialLedger,Cut::LedgerSynced,Cut::Renamed,Cut::DirectorySynced] {
        let(t,mut s,mut e,h)=sealed();s.cut=Some(cut);assert_eq!(s.publish(h,70,7,&mut e),Err(Error::CommitUncertain));drop(s);
        let mut s=reopen(&t);let new=matches!(cut,Cut::Renamed|Cut::DirectorySynced);
        assert_eq!(s.state.selected.revision,if new{8}else{7});
        assert_eq!(s.publish(h,70,7,&mut e).unwrap().revision,8);assert_eq!(s.state.charge,limits().charge(manifest()).unwrap());
    }
}
#[test]
fn as110_reopen_requires_fresh_boot_authority_and_same_limits() {
    let(t,mut s,mut e,h)=sealed();s.publish(h,70,7,&mut e).unwrap();drop(s);
    assert!(matches!(ArtifactStore::open(&t.0,10,20,10,Limits{window:64,..limits()}),Err(Error::Conflict)));
    let mut s=ArtifactStore::open(&t.0,10,20,10,limits()).unwrap();assert_eq!(s.read(caller(),0,64,&mut e),Err(Error::Authority));
    e.boot=10;assert_eq!(s.read(caller(),0,64,&mut e).unwrap(),payload()[..64]);
}
#[test]
fn as110_lock_namespace_and_reprovisioning_are_fenced() {
    let(t,s,_e)=empty();assert!(matches!(ArtifactStore::open(&t.0,10,20,9,limits()),Err(Error::BackendBusy)));
    assert!(ArtifactStore::create(&t.0,10,20,9,limits(),selected()).is_err());drop(s);
    assert!(matches!(ArtifactStore::open(&t.0,11,20,9,limits()),Err(Error::Authority)));let _s=reopen(&t);
}
#[test]
fn as110_corrupt_head_never_promotes_valid_pending() {
    let(t,s,_e)=empty();let good=head(&s);drop(s);fs::write(t.0.join(PENDING),&good).unwrap();fs::write(t.0.join(HEAD),b"bad").unwrap();
    assert!(matches!(ArtifactStore::open(&t.0,10,20,9,limits()),Err(Error::CorruptRecord)));assert!(t.0.join(PENDING).exists());
}
#[test]
fn as110_payload_corruption_and_symlink_fail_closed() {
    let(t,s,_e,_h)=sealed();drop(s);let mut bytes=payload();bytes[5]^=1;fs::write(t.0.join(DATA),&bytes).unwrap();
    assert!(matches!(ArtifactStore::open(&t.0,10,20,9,limits()),Err(Error::CorruptRecord)));
    fs::remove_file(t.0.join(DATA)).unwrap();let other=t.0.join("unrelated");fs::write(&other,payload()).unwrap();
    std::os::unix::fs::symlink(&other,t.0.join(DATA)).unwrap();assert!(ArtifactStore::open(&t.0,10,20,9,limits()).is_err());assert_eq!(fs::read(other).unwrap(),payload());
}
#[test]
fn as110_serial_and_revision_exhaustion_never_wrap() {
    let(t,mut s,mut e)=empty();s.state.high=u64::MAX;fs::write(t.0.join(HEAD),codec::encode(&s.state).unwrap()).unwrap();
    assert_eq!(s.reserve(manifest(),caller(),&mut e),Err(Error::Exhausted));
    let t2=Temp::new();let mut s=ArtifactStore::create(&t2.0,10,20,9,limits(),Selection{revision:u64::MAX,..selected()}).unwrap();
    let h=s.reserve(manifest(),caller(),&mut e).unwrap();fill(&mut s,h,&mut e);s.seal(h,&mut e).unwrap();let old=head(&s);
    assert_eq!(s.publish(h,70,u64::MAX,&mut e),Err(Error::Exhausted));assert_eq!(head(&s),old);
}
#[test]
fn as110_repeated_private_cycles_bound_files_and_preserve_watermark() {
    let(_t,mut s,mut e)=empty();
    for i in 1..=12 {let h=s.reserve(manifest(),caller(),&mut e).unwrap();assert_eq!(h.serial,i);s.append(h,0,&payload()[..64],&mut e).unwrap();s.discard(h,&mut e).unwrap();
        assert_eq!(fs::read_dir(&s.dir).unwrap().count(),2);assert_eq!(s.state.charge,0);}
}
#[test]
fn as110_seal_cut_points_recover_private_or_verified_durable_bytes() {
    for cut in [Cut::BeforeLedger,Cut::PartialLedger,Cut::LedgerSynced,Cut::Renamed,Cut::DirectorySynced] {
        let(t,mut s,mut e,h)=reserved();fill(&mut s,h,&mut e);s.cut=Some(cut);
        assert_eq!(s.seal(h,&mut e),Err(Error::CommitUncertain));drop(s);
        let mut s=reopen(&t);assert_eq!(s.state.phase,if matches!(cut,Cut::Renamed|Cut::DirectorySynced){Phase::Sealed}else{Phase::Staging});
        assert_eq!(fs::read(t.0.join(DATA)).unwrap(),payload());s.seal(h,&mut e).unwrap();assert_eq!(s.state.selected,selected());
    }
}

#[test]
fn as110_progress_requires_current_bound_authority_and_preserves_work() {
    let(_t,mut s,mut e,h)=reserved();let remaining=s.state.remaining;
    assert_eq!(s.upload_progress(h,&mut e).unwrap(),(0,false,4096));
    assert_eq!(s.state.remaining,remaining);
    assert_eq!(s.upload_progress(h,&mut Deny),Err(Error::Authority));
    let bad=Ticket{serial:h.serial+1,..h};assert!(s.upload_progress(bad,&mut e).is_err());
    fill(&mut s,h,&mut e);s.seal(h,&mut e).unwrap();
    assert_eq!(s.upload_progress(h,&mut e).unwrap(),(10000,true,4096));
    s.publish(h,91,7,&mut e).unwrap();assert!(s.upload_progress(h,&mut e).is_err());
}
#[test]
fn as110_outcome_recovery_binds_full_request_manifest_caller_and_current_grant() {
    let(t,mut s,mut e,h)=sealed();assert_eq!(s.publication_outcome(manifest(),caller(),91,7,&mut e).unwrap(),None);
    let selected=s.publish(h,91,7,&mut e).unwrap();let usage=s.usage().unwrap();drop(s);let mut s=reopen(&t);
    assert_eq!(s.publication_outcome(manifest(),caller(),91,7,&mut e).unwrap(),Some(selected));
    assert!(s.publication_outcome(manifest(),caller(),92,7,&mut e).is_err());
    assert!(s.publication_outcome(manifest(),caller(),91,8,&mut e).is_err());
    let mut m=manifest();m.provenance+=1;assert!(s.publication_outcome(m,caller(),91,7,&mut e).is_err());
    assert!(s.publication_outcome(manifest(),Caller{incarnation:5,..caller()},91,7,&mut e).is_err());
    assert!(s.publication_outcome(manifest(),caller(),91,7,&mut Deny).is_err());
    e.bytes[0]^=1;assert!(s.publication_outcome(manifest(),caller(),91,7,&mut e).is_err());
    assert_eq!(s.usage().unwrap(),usage);
}
