use super::*;
use super::super::{transact,Access,Context,Verdict};
use std::sync::atomic::{AtomicU64,Ordering};
static SERIAL:AtomicU64=AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new()->Self {
        let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        Self(std::env::temp_dir().join(format!("anka110-{}-{now}-{}",std::process::id(),SERIAL.fetch_add(1,Ordering::Relaxed))))
    }
}
impl Drop for Temp {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn initial()->State {State{revision:7,value:55,boot:8,last:None}}
fn request()->Request {Request{anchor:10,installation:20,policy:3,caller:30,incarnation:4,sequence:1,expected:7,operation:Operation::Select,argument:99,attempt:0}}
fn after()->State {State{revision:8,value:99,boot:8,last:Some(request())}}
fn context()->Context {Context{anchor:10,installation:20,policy:3,challenge:71,now:100,selected:true}}
fn access()->Access {Access{anchor:10,installation:20,policy:3,caller:30,incarnation:4,operation:Operation::Select,first:90,until:110,authentic:Verdict::Valid,status:Verdict::Valid}}
fn resign(bytes:&mut [u8;RECORD_BYTES]) {let c=checksum(&bytes[..RECORD_BYTES-8]);bytes[RECORD_BYTES-8..].copy_from_slice(&c.to_le_bytes());}
fn word(bytes:&mut [u8;RECORD_BYTES],index:usize,value:u64) {bytes[8+8*index..16+8*index].copy_from_slice(&value.to_le_bytes());resign(bytes);}

#[test]
fn d110_codec_exact_roundtrip_and_crc_vector() {
    assert_eq!(checksum(b"123456789"),0x6c40_df5f_0b49_7347);
    for s in [initial(),after(),State{revision:8,value:55,boot:9,last:Some(Request{operation:Operation::ReserveBoot,argument:55,attempt:71,..request()})}] {
        let bytes=encode(10,20,&s).unwrap();assert_eq!(bytes.len(),152);assert_eq!(decode(&bytes,10,20),Ok(s));
    }
}
#[test]
fn d110_codec_rejects_every_single_bit_flip() {
    let bytes=encode(10,20,&after()).unwrap();
    for i in 0..RECORD_BYTES {for bit in 0..8 {let mut bad=bytes;bad[i]^=1<<bit;assert!(decode(&bad,10,20).is_err(),"byte {i} bit {bit}");}}
}
#[test]
fn d110_codec_rejects_truncation_tail_and_rechecksummed_bad_shape() {
    let bytes=encode(10,20,&after()).unwrap();
    for n in 0..RECORD_BYTES {assert_eq!(decode(&bytes[..n],10,20),Err(Error::CorruptRecord));}
    let mut tail=bytes.to_vec();tail.push(0);assert_eq!(decode(&tail,10,20),Err(Error::CorruptRecord));
    for (index,value) in [(0,2),(6,2),(12,0),(13,8),(14,3),(15,100),(16,1)] {
        let mut bad=bytes;word(&mut bad,index,value);assert_eq!(decode(&bad,10,20),Err(Error::CorruptRecord));
    }
    let mut absent=encode(10,20,&initial()).unwrap();word(&mut absent,9,3);
    assert_eq!(decode(&absent,10,20),Err(Error::CorruptRecord));
}
#[test]
fn d110_commit_reopen_and_retry_are_exact() {
    let tmp=Temp::new();let mut b=FileRecord::create(&tmp.0,10,20,&initial()).unwrap();
    let o=transact(&mut b,context(),request(),access(),true).unwrap();drop(b);
    let mut b=FileRecord::open(&tmp.0,10,20).unwrap();
    assert_eq!(b.load(10,20),Ok(after()));
    assert_eq!(transact(&mut b,context(),request(),access(),false),Ok(o));
    assert_eq!(fs::metadata(tmp.0.join(HEAD)).unwrap().len(),RECORD_BYTES as u64);
    assert!(!tmp.0.join(PENDING).exists());
}
#[test]
fn d110_provision_and_reopen_never_reset_existing_installation() {
    let tmp=Temp::new();assert!(FileRecord::open(&tmp.0,10,20).is_err());assert!(!tmp.0.exists());
    let b=FileRecord::create(&tmp.0,10,20,&initial()).unwrap();drop(b);
    assert!(FileRecord::create(&tmp.0,10,20,&initial()).is_err());
    assert_eq!(FileRecord::open(&tmp.0,10,20).unwrap().load(10,20),Ok(initial()));
    fs::remove_file(tmp.0.join(HEAD)).unwrap();
    assert!(FileRecord::open(&tmp.0,10,20).is_err());assert!(!tmp.0.join(HEAD).exists());
}
#[test]
fn d110_lock_fences_other_openers_and_releases_on_close() {
    // Open the descriptor in the child, after exec. Other tests can spawn
    // processes in parallel without inheriting a reference to this lock.
    let tmp=Temp::new();
    let output=child(&tmp,"release");
    assert!(output.status.success(), "release helper failed: {output:?}");
    // The helper creates this path. A mismatched --exact filter cannot pass.
    assert!(tmp.0.join(LOCK).is_file(), "release helper did not run");
}
#[test]
fn d110_namespace_substitution_is_rejected_without_writes() {
    let tmp=Temp::new();let mut b=FileRecord::create(&tmp.0,10,20,&initial()).unwrap();
    let bytes=fs::read(tmp.0.join(HEAD)).unwrap();
    assert_eq!(b.load(10,21),Err(Error::Authority));
    assert_eq!(b.commit(11,20,&initial(),&after()),Err(Error::Authority));drop(b);
    // Valid open performs orphan cleanup; a namespace mismatch must never reach it.
    fs::write(tmp.0.join(PENDING),b"orphan").unwrap();
    match FileRecord::open(&tmp.0,10,21) {
        Err(Error::Authority)=>{},
        Err(other)=>panic!("open for installation 21: expected Authority, got {other:?}"),
        Ok(_)=>panic!("opened installation 20 as installation 21"),
    }
    assert_eq!(fs::read(tmp.0.join(HEAD)).unwrap(),bytes);
    assert_eq!(fs::read(tmp.0.join(PENDING)).unwrap().as_slice(),b"orphan");
    // A rejected opener must also release its own descriptor.
    let mut owner=FileRecord::open(&tmp.0,10,20).expect("reopen for installation 20");
    assert_eq!(owner.load(10,20),Ok(initial()));
    assert!(!tmp.0.join(PENDING).exists());
}
#[test]
fn d110_compare_and_commit_rechecks_complete_before_state() {
    let tmp=Temp::new();let mut b=FileRecord::create(&tmp.0,10,20,&initial()).unwrap();
    assert_eq!(b.commit(10,20,&State{boot:7,..initial()},&after()),Err(Error::Conflict));
    assert_eq!(b.commit(10,20,&initial(),&State{boot:9,..after()}),Err(Error::InvalidRequest));
    b.commit(10,20,&initial(),&after()).unwrap();
    assert_eq!(b.commit(10,20,&initial(),&after()),Err(Error::Conflict));
    assert_eq!(b.load(10,20),Ok(after()));
}
#[test]
fn d110_fault_boundaries_preserve_old_or_recover_complete_new() {
    for cut in [Cut::BeforeWrite,Cut::PartialWrite,Cut::FileSynced,Cut::Renamed,Cut::DirectorySynced] {
        let tmp=Temp::new();let mut b=FileRecord::create(&tmp.0,10,20,&initial()).unwrap();b.cut=Some(cut);
        let result=b.commit(10,20,&initial(),&after());
        let renamed=matches!(cut,Cut::Renamed|Cut::DirectorySynced);
        assert_eq!(result,Err(if renamed {Error::CommitUncertain}else{Error::BackendUnavailable}));
        if renamed {assert_eq!(b.load(10,20),Err(Error::CommitUncertain));}
        drop(b);let mut b=FileRecord::open(&tmp.0,10,20).unwrap();
        assert_eq!(b.load(10,20),Ok(if renamed{after()}else{initial()}));
        assert!(!tmp.0.join(PENDING).exists());
        assert!(transact(&mut b,context(),request(),access(),true).is_ok());
        assert_eq!(b.load(10,20),Ok(after()));
    }
}
#[test]
fn d110_corrupt_head_never_falls_back_to_valid_pending() {
    let tmp=Temp::new();drop(FileRecord::create(&tmp.0,10,20,&initial()).unwrap());
    let pending=encode(10,20,&after()).unwrap();fs::write(tmp.0.join(PENDING),pending).unwrap();
    fs::write(tmp.0.join(HEAD),b"broken").unwrap();
    assert!(matches!(FileRecord::open(&tmp.0,10,20),Err(Error::CorruptRecord)));
    assert_eq!(fs::read(tmp.0.join(HEAD)).unwrap(),b"broken");
    assert_eq!(fs::read(tmp.0.join(PENDING)).unwrap(),pending);
}
#[test]
fn d110_orphan_pending_is_discarded_only_with_valid_head() {
    let tmp=Temp::new();drop(FileRecord::create(&tmp.0,10,20,&initial()).unwrap());
    fs::write(tmp.0.join(PENDING),b"partial").unwrap();
    let mut b=FileRecord::open(&tmp.0,10,20).unwrap();
    assert_eq!(b.load(10,20),Ok(initial()));assert!(!tmp.0.join(PENDING).exists());
}
#[test]
fn d110_symlink_head_is_not_followed() {
    let tmp=Temp::new();drop(FileRecord::create(&tmp.0,10,20,&initial()).unwrap());
    fs::rename(tmp.0.join(HEAD),tmp.0.join("other")).unwrap();
    std::os::unix::fs::symlink("other",tmp.0.join(HEAD)).unwrap();
    assert!(matches!(FileRecord::open(&tmp.0,10,20),Err(Error::CorruptRecord)));
}
#[test]
fn d110_repeated_commits_keep_storage_bounded() {
    let tmp=Temp::new();let mut b=FileRecord::create(&tmp.0,10,20,&initial()).unwrap();
    for n in 1..=12 {
        let r=Request{sequence:n,expected:6+n,argument:100+n,..request()};
        transact(&mut b,context(),r,access(),true).unwrap();
        assert_eq!(fs::read_dir(&tmp.0).unwrap().count(),2);
        assert_eq!(fs::metadata(tmp.0.join(HEAD)).unwrap().len(),152);
    }
}
fn child(tmp:&Temp,mode:&str)->std::process::Output {
    let module=module_path!().split_once("::").unwrap().1;
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact",&format!("{module}::d110_process_child"),"--nocapture"])
        .env("ANKA110_CHILD_DIRECTORY",&tmp.0).env("ANKA110_CHILD_MODE",mode)
        .env("ANKA110_TEST_PROCESS_EXIT","1").output().unwrap()
}
#[test]
fn d110_process_exit_releases_lock_and_recovers_cut_points() {
    for (mode,renamed) in [("partial",false),("flushed",false),("renamed",true),("durable",true)] {
        let tmp=Temp::new();drop(FileRecord::create(&tmp.0,10,20,&initial()).unwrap());
        let output=child(&tmp,mode);assert_eq!(output.status.code(),Some(73),"{output:?}");
        let mut b=FileRecord::open(&tmp.0,10,20).unwrap();
        assert_eq!(b.load(10,20),Ok(if renamed{after()}else{initial()}));
        assert!(transact(&mut b,context(),request(),access(),true).is_ok());
    }
}
#[test]
fn d110_second_process_is_fenced() {
    let tmp=Temp::new();let _b=FileRecord::create(&tmp.0,10,20,&initial()).unwrap();
    let output=child(&tmp,"locked");assert!(output.status.success(),"{output:?}");
}
// Subprocess helper: inert in the ordinary parent test run.
#[test]
fn d110_process_child() {
    let Some(directory)=std::env::var_os("ANKA110_CHILD_DIRECTORY") else {return};
    let mode=std::env::var("ANKA110_CHILD_MODE").unwrap();
    if mode=="release" {
        use std::os::unix::fs::MetadataExt;
        let path=Path::new(&directory);
        let lock=path.join(LOCK);
        let owner=FileRecord::create(path,10,20,&initial()).expect("create first writer");
        let inode=fs::metadata(&lock).unwrap();
        match FileRecord::open(path,10,20) {
            Err(Error::BackendBusy)=>{},
            Err(e)=>panic!("live writer: expected BackendBusy, got {e:?}"),
            Ok(_)=>panic!("live writer failed to fence a second opener"),
        }
        drop(owner);
        // Single immediate attempt: no polling or retry that could hide a leak.
        let mut next=FileRecord::open(path,10,20).expect("immediate reopen after sole writer dropped");
        assert_eq!(next.load(10,20),Ok(initial()));
        let same=fs::metadata(&lock).expect("lock file must persist");
        assert_eq!((inode.dev(),inode.ino()),(same.dev(),same.ino()));
        assert!(matches!(FileRecord::open(path,10,20),Err(Error::BackendBusy)),
            "replacement writer did not fence its peer");
        return
    }
    if mode=="locked" {assert!(matches!(FileRecord::open(Path::new(&directory),10,20),Err(Error::BackendBusy)));return}
    let mut b=FileRecord::open(Path::new(&directory),10,20).unwrap();
    b.cut=Some(match mode.as_str(){"partial"=>Cut::PartialWrite,"flushed"=>Cut::FileSynced,"renamed"=>Cut::Renamed,"durable"=>Cut::DirectorySynced,_=>panic!("bad test mode")});
    let _=b.commit(10,20,&initial(),&after());panic!("checkpoint did not terminate child");
}
