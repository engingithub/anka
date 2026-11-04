//! Host-local, single-writer durable record. Linux/macOS only, private local
//! filesystem directory, honest kernel/device, cooperating writers. No remote
//! credentials or encryption. CRC detects corruption; it is not authentication.
//! Never run on NFS/SMB or an attacker-writable directory. The lock file is never
//! replaced/unlinked. Atomic same-directory rename and successful flush barriers
//! are explicit durability assumptions. No protection against snapshot rollback.
use super::{DurableRecord,Error,Operation,Request,State};
use std::{fs::{self,File,OpenOptions,DirBuilder},io::{Read,Write},path::{Path,PathBuf}};
use std::os::{fd::AsRawFd,unix::fs::{DirBuilderExt,OpenOptionsExt}};

const MAGIC:&[u8;8]=b"ANKAPS1\0";
const WORDS:usize=17;
const RECORD_BYTES:usize=8+WORDS*8+8; // 152: magic, canonical words, CRC64-ECMA.
const HEAD:&str="record";
const PENDING:&str="pending";
const LOCK:&str="writer.lock";
unsafe extern "C" { fn flock(fd:i32,operation:i32)->i32; }
#[cfg(target_os="macos")]
unsafe extern "C" { fn fcntl(fd:i32,command:i32,...)->i32; }

fn io_error(_:std::io::Error)->Error {Error::BackendUnavailable}
fn file_barrier(file:&File)->Result<(),Error> {
    file.sync_all().map_err(io_error)?;
    #[cfg(target_os="macos")]
    {
        // Darwin fcntl.h: F_FULLFSYNC=51. No fallback to weaker fsync on failure.
        // SAFETY: file owns a valid fd; this command has no variadic argument.
        if unsafe {fcntl(file.as_raw_fd(),51)}!=0 {return Err(Error::BackendUnavailable)}
    }
    Ok(())
}
fn dir_barrier(path:&Path)->Result<(),Error> {File::open(path).and_then(|f|f.sync_all()).map_err(io_error)}
fn regular(path:&Path)->Result<(),Error> {
    let meta=fs::symlink_metadata(path).map_err(io_error)?;
    if !meta.file_type().is_file() {return Err(Error::CorruptRecord)}
    Ok(())
}
fn lock_file(path:&Path,create:bool)->Result<File,Error> {
    if !create {regular(path)?;}
    let f=OpenOptions::new().read(true).write(true).create_new(create).mode(0o600).open(path).map_err(io_error)?;
    // SAFETY: live fd and the Linux/Darwin LOCK_EX | LOCK_NB constants (2 | 4).
    if unsafe {flock(f.as_raw_fd(),2|4)}!=0 {
        return Err(if std::io::Error::last_os_error().kind()==std::io::ErrorKind::WouldBlock {
            Error::BackendBusy
        } else {Error::BackendUnavailable})
    }
    Ok(f) // fd lifetime holds lock; close also releases it after process death.
}
fn checksum(bytes:&[u8])->u64 {
    let mut crc=0u64;
    for &byte in bytes {
        crc^=(byte as u64)<<56;
        for _ in 0..8 {crc=if crc&(1<<63)!=0 {(crc<<1)^0x42f0_e1eb_a9ea_3693} else {crc<<1};}
    }
    crc
}
fn valid_state(anchor:u64,installation:u64,s:&State)->bool {
    if anchor==0 || installation==0 || s.revision==0 || s.value==0 {return false}
    if let Some(r)=s.last {
        if r.anchor!=anchor || r.installation!=installation || r.caller==0 || r.incarnation==0
            || r.sequence==0 || r.expected.checked_add(1)!=Some(s.revision) || r.argument!=s.value {return false}
        match r.operation {
            Operation::Select => r.attempt==0,
            Operation::ReserveBoot => r.attempt!=0 && s.boot!=0,
        }
    } else {true} // Provisioning supplies an initial nonzero revision/value.
}
fn encode(anchor:u64,installation:u64,s:&State)->Result<[u8;RECORD_BYTES],Error> {
    if !valid_state(anchor,installation,s) {return Err(Error::CorruptRecord)}
    let mut words=[0u64;WORDS];
    words[..7].copy_from_slice(&[1,anchor,installation,s.revision,s.value,s.boot,u64::from(s.last.is_some())]);
    if let Some(r)=s.last {
        words[7..].copy_from_slice(&[r.anchor,r.installation,r.policy,r.caller,r.incarnation,
            r.sequence,r.expected,match r.operation {Operation::Select=>1,Operation::ReserveBoot=>2},r.argument,r.attempt]);
    }
    let mut bytes=[0u8;RECORD_BYTES];bytes[..8].copy_from_slice(MAGIC);
    for (i,w) in words.iter().enumerate(){bytes[8+i*8..16+i*8].copy_from_slice(&w.to_le_bytes());}
    let crc=checksum(&bytes[..RECORD_BYTES-8]);bytes[RECORD_BYTES-8..].copy_from_slice(&crc.to_le_bytes());
    Ok(bytes)
}
fn decode(bytes:&[u8],anchor:u64,installation:u64)->Result<State,Error> {
    if bytes.len()!=RECORD_BYTES || &bytes[..8]!=MAGIC {return Err(Error::CorruptRecord)}
    let word=|offset:usize|u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap());
    if checksum(&bytes[..RECORD_BYTES-8])!=word(RECORD_BYTES-8) {return Err(Error::CorruptRecord)}
    let mut w=[0u64;WORDS];for (i,x) in w.iter_mut().enumerate(){*x=word(8+i*8);}
    if w[0]!=1 {return Err(Error::CorruptRecord)}
    if w[1]!=anchor || w[2]!=installation {return Err(Error::Authority)}
    let last=match w[6] {
        0 if w[7..].iter().all(|&x|x==0)=>None,
        1=>Some(Request{anchor:w[7],installation:w[8],policy:w[9],caller:w[10],incarnation:w[11],
            sequence:w[12],expected:w[13],operation:match w[14]{1=>Operation::Select,2=>Operation::ReserveBoot,_=>return Err(Error::CorruptRecord)},
            argument:w[15],attempt:w[16]}),
        _=>return Err(Error::CorruptRecord),
    };
    let s=State{revision:w[3],value:w[4],boot:w[5],last};
    if !valid_state(anchor,installation,&s) {return Err(Error::CorruptRecord)}
    Ok(s)
}
fn valid_successor(before:&State,after:&State)->bool {
    let Some(r)=after.last else {return false};
    if r.expected!=before.revision || before.revision.checked_add(1)!=Some(after.revision)
        || before.sequence().checked_add(1)!=Some(r.sequence) {return false}
    match r.operation {
        Operation::Select=>r.attempt==0 && after.value==r.argument && after.boot==before.boot,
        Operation::ReserveBoot=>r.attempt!=0 && r.argument==before.value && after.value==before.value
            && before.boot.checked_add(1)==Some(after.boot),
    }
}

#[cfg(test)]
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Cut { BeforeWrite, PartialWrite, FileSynced, Renamed, DirectorySynced }

pub(crate) struct FileRecord {
    directory:PathBuf,anchor:u64,installation:u64,
    _lock:File, // Never remove this inode: every cooperating opener locks it.
    poisoned:bool,
    #[cfg(test)] cut:Option<Cut>,
}
impl FileRecord {
    /// Explicit trusted provisioning only. Refuses an existing directory; never
    /// treats missing/corrupt data in an existing installation as first enrollment.
    pub(crate) fn create(path:&Path,anchor:u64,installation:u64,initial:&State)->Result<Self,Error> {
        if initial.last.is_some() {return Err(Error::InvalidRequest)}
        let bytes=encode(anchor,installation,initial)?;
        // Parent must already exist. Resolve it before creating anything.
        let parent=path.parent().filter(|p|!p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let parent=fs::canonicalize(parent).map_err(io_error)?;
        let name=path.file_name().ok_or(Error::InvalidRequest)?;
        let directory=parent.join(name);
        DirBuilder::new().mode(0o700).create(&directory).map_err(io_error)?;
        // On any failure, keep the partial directory quarantined. Never retry
        // provisioning by overwriting it or silently deleting a prior record.
        let lock=lock_file(&directory.join(LOCK),true)?;
        file_barrier(&lock)?;
        let mut head=OpenOptions::new().write(true).create_new(true).mode(0o600).open(directory.join(HEAD)).map_err(io_error)?;
        head.write_all(&bytes).map_err(io_error)?;
        file_barrier(&head)?;dir_barrier(&directory)?;dir_barrier(&parent)?;file_barrier(&head)?;
        Ok(Self{directory,anchor,installation,_lock:lock,poisoned:false,#[cfg(test)]cut:None})
    }
    pub(crate) fn open(path:&Path,anchor:u64,installation:u64)->Result<Self,Error> {
        if anchor==0 || installation==0 {return Err(Error::Authority)}
        if !fs::symlink_metadata(path).map_err(io_error)?.file_type().is_dir() {return Err(Error::CorruptRecord)}
        let directory=fs::canonicalize(path).map_err(io_error)?;
        let lock=lock_file(&directory.join(LOCK),false)?;
        let s=Self{directory,anchor,installation,_lock:lock,poisoned:false,#[cfg(test)]cut:None};
        // Validate visible head before any cleanup. Never promote pending data.
        s.read_head()?;
        let head=OpenOptions::new().read(true).write(true).open(s.directory.join(HEAD)).map_err(io_error)?;
        file_barrier(&head)?;dir_barrier(&s.directory)?;file_barrier(&head)?;
        s.remove_pending()?;
        Ok(s)
    }
    fn bound(&self,anchor:u64,installation:u64)->Result<(),Error> {
        if (anchor,installation)!=(self.anchor,self.installation){return Err(Error::Authority)}
        if self.poisoned{return Err(Error::CommitUncertain)}
        Ok(())
    }
    fn read_head(&self)->Result<State,Error> {
        let path=self.directory.join(HEAD);regular(&path)?;
        let mut bytes=Vec::with_capacity(RECORD_BYTES+1);
        File::open(path).map_err(io_error)?.take((RECORD_BYTES+1) as u64).read_to_end(&mut bytes).map_err(io_error)?;
        decode(&bytes,self.anchor,self.installation)
    }
    fn remove_pending(&self)->Result<(),Error> {
        let path=self.directory.join(PENDING);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_file()=>fs::remove_file(path).map_err(io_error),
            Ok(_)=>Err(Error::CorruptRecord),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(()),
            Err(e)=>Err(io_error(e)),
        }
    }
    #[cfg(test)]
    fn checkpoint(&self,cut:Cut)->Result<(),Error> {
        if self.cut==Some(cut) {
            if std::env::var_os("ANKA110_TEST_PROCESS_EXIT").is_some() {std::process::exit(73)}
            Err(if matches!(cut,Cut::Renamed|Cut::DirectorySynced){Error::CommitUncertain}else{Error::BackendUnavailable})
        } else {Ok(())}
    }
}
impl DurableRecord for FileRecord {
    fn load(&mut self,anchor:u64,installation:u64)->Result<State,Error> {
        self.bound(anchor,installation)?;self.read_head()
    }
    fn commit(&mut self,anchor:u64,installation:u64,before:&State,after:&State)->Result<(),Error> {
        self.bound(anchor,installation)?;
        if self.read_head()?!=*before {return Err(Error::Conflict)}
        if !valid_successor(before,after){return Err(Error::InvalidRequest)}
        let bytes=encode(anchor,installation,after)?;
        self.remove_pending()?;
        #[cfg(test)] self.checkpoint(Cut::BeforeWrite)?;
        let pending=self.directory.join(PENDING);
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&pending).map_err(io_error)?;
        // Separate write segments provide an actual short/torn pending fixture.
        file.write_all(&bytes[..RECORD_BYTES/2]).map_err(io_error)?;
        #[cfg(test)] self.checkpoint(Cut::PartialWrite)?;
        file.write_all(&bytes[RECORD_BYTES/2..]).map_err(io_error)?;
        file_barrier(&file)?;
        #[cfg(test)] self.checkpoint(Cut::FileSynced)?;
        // From this point even an IO error cannot be reported as definite abort.
        self.poisoned=true;
        fs::rename(&pending,self.directory.join(HEAD)).map_err(|_|Error::CommitUncertain)?;
        #[cfg(test)] self.checkpoint(Cut::Renamed)?;
        dir_barrier(&self.directory).map_err(|_|Error::CommitUncertain)?;
        file_barrier(&file).map_err(|_|Error::CommitUncertain)?;
        #[cfg(test)] self.checkpoint(Cut::DirectorySynced)?;
        self.poisoned=false;
        Ok(())
    }
}

#[cfg(test)]
#[path="file_backend/tests.rs"]
mod tests;
