//! AS110 single-candidate host file store. Same private-directory, honest-host,
//! advisory-lock and durability assumptions as FileRecord. No S3, network wire
//! protocol, executable loader or production evidence provider is supplied here.
//! Published objects are immutable and retained. Other objects are an external
//! custodian obligation, conservatively charged by Limits::other_bytes.
use super::{Error, Verdict};
use super::file_backend::{checksum, dir_barrier, file_barrier, io_error, lock_file, regular};
use std::{fs::{self, DirBuilder, File, OpenOptions}, io::{Read, Seek, SeekFrom, Write}, path::{Path, PathBuf}};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

#[path="artifact/codec.rs"]
mod codec;
#[path="artifact/transfer.rs"]
pub(crate) mod transfer;
use codec::{Snapshot, Phase, RECORD_BYTES};
// Stable persisted accounting units, independent of Rust layout/compiler version.
const _: () = assert!(std::mem::size_of::<Snapshot>()<=1024);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub anchor:u64, pub installation:u64, pub artifact:u64, pub generation:u64,
    pub role:u64, pub profile:u64, pub size:u64, pub image:u64, pub metadata:u64,
    pub dependencies:u64, pub provenance:u64,
}
impl Manifest {
    fn valid(self)->bool {
        self.anchor!=0 && self.installation!=0 && self.artifact!=0 && self.generation!=0
            && matches!(self.role,1|2) && self.profile!=0 && self.size!=0
            && self.image!=0 && self.metadata!=0 && self.provenance!=0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Caller {pub owner:u64, pub incarnation:u64}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {Upload, Publish, Read, Retire}
/// Trusted provider must project CURRENT authority for this exact scope. Boot is
/// the current service epoch, not persisted pointer authority or a process ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scope {
    pub manifest:Manifest, pub caller:Caller, pub boot:u64, pub ticket:u64, pub action:Action,
}
/// Implementations belong to trusted integration, never to the requesting guest.
/// inspect must derive the full manifest from actual bytes and independently
/// validated metadata/dependencies/provenance, including their durable retention.
/// Equality IDs are not a substitute for cryptographic verification.
pub(crate) trait Evidence {
    fn authorize(&mut self,_scope:Scope)->Verdict {Verdict::Unknown}
    fn inspect(&mut self,_bytes:&mut dyn Read)->Result<Manifest,Error> {Err(Error::Authority)}
    fn retired(&mut self,_scope:Scope)->Verdict {Verdict::Unknown}
}
pub(crate) struct Deny;
impl Evidence for Deny {}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    pub max_payload:u64, pub window:u64, pub owner_bytes:u64, pub total_bytes:u64,
    pub other_bytes:u64, pub work:u64,
}
impl Limits {
    fn fixed(self)->Option<u64> {
        // Conservative reservation for ledger snapshots/codec scratch and two IO buffers.
        (6*RECORD_BYTES as u64 + 3*1024)
            .checked_add(self.window.checked_mul(2)?)
    }
    fn valid(self)->bool {
        self.max_payload!=0 && self.window!=0 && self.window<=self.max_payload
            && usize::try_from(self.window).is_ok() && self.work!=0
            && self.fixed().and_then(|n|self.other_bytes.checked_add(n))
                .is_some_and(|n|n<=self.total_bytes)
    }
    fn charge(self,m:Manifest)->Result<u64,Error> {
        // Attribute service metadata/scratch to the candidate while active;
        // keep that reservation with the service when the slot is empty.
        if !self.valid() || m.size>self.max_payload {return Err(Error::Capacity)}
        let charge=m.size.checked_add(self.fixed().ok_or(Error::Capacity)?).ok_or(Error::Capacity)?;
        if charge>self.owner_bytes || self.other_bytes.checked_add(charge).is_none_or(|n|n>self.total_bytes) {
            return Err(Error::Capacity)
        }
        Ok(charge)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Selection {pub revision:u64,pub artifact:u64,pub generation:u64}
impl Selection {fn valid(self)->bool {self.revision!=0 && ((self.artifact==0 && self.generation==0)||(self.artifact!=0 && self.generation!=0))}}
/// Opaque request selector, not authority. Every use rechecks the current provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ticket {anchor:u64,installation:u64,serial:u64,caller:Caller}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Usage {pub candidate:u64,pub service:u64,pub other:u64}

const HEAD:&str="artifact.record";
const PENDING:&str="artifact.pending";
const DATA:&str="artifact.bytes";
const LOCK:&str="artifact.lock";
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cut {BeforeLedger,PartialLedger,LedgerSynced,Renamed,DirectorySynced,PayloadWritten,CleanupIntent,PayloadDeleted}

#[derive(Debug)]
pub(crate) struct ArtifactStore {
    dir:PathBuf, _lock:File, state:Snapshot, boot:u64, poisoned:bool,
    #[cfg(test)] cut:Option<Cut>,
}
impl ArtifactStore {
    pub(crate) fn create(path:&Path,anchor:u64,installation:u64,boot:u64,limits:Limits,selected:Selection)->Result<Self,Error> {
        if boot==0 || anchor==0 || installation==0 || !selected.valid() {return Err(Error::InvalidRequest)}
        if !limits.valid() {return Err(Error::Capacity)}
        let state=Snapshot::empty(anchor,installation,limits,selected);
        let bytes=codec::encode(&state)?;
        let parent=fs::canonicalize(path.parent().filter(|p|!p.as_os_str().is_empty()).unwrap_or(Path::new("."))).map_err(io_error)?;
        let dir=parent.join(path.file_name().ok_or(Error::InvalidRequest)?);
        DirBuilder::new().mode(0o700).create(&dir).map_err(io_error)?;
        // Partial provisioning is quarantined; an existing directory is never reset.
        let lock=lock_file(&dir.join(LOCK),true)?;file_barrier(&lock)?;
        let mut head=OpenOptions::new().write(true).create_new(true).mode(0o600).open(dir.join(HEAD)).map_err(io_error)?;
        head.write_all(&bytes).map_err(io_error)?;file_barrier(&head)?;
        dir_barrier(&dir)?;dir_barrier(&parent)?;file_barrier(&head)?;
        Ok(Self{dir,_lock:lock,state,boot,poisoned:false,#[cfg(test)]cut:None})
    }
    pub(crate) fn open(path:&Path,anchor:u64,installation:u64,boot:u64,limits:Limits)->Result<Self,Error> {
        if anchor==0 || installation==0 || boot==0 {return Err(Error::Authority)}
        if !fs::symlink_metadata(path).map_err(io_error)?.file_type().is_dir(){return Err(Error::CorruptRecord)}
        let dir=fs::canonicalize(path).map_err(io_error)?;
        let lock=lock_file(&dir.join(LOCK),false)?;
        let state=Self::load(&dir,anchor,installation)?;
        if state.limits!=limits {return Err(Error::Conflict)}
        let mut s=Self{dir,_lock:lock,state,boot,poisoned:false,#[cfg(test)]cut:None};
        let head=OpenOptions::new().read(true).write(true).open(s.dir.join(HEAD)).map_err(io_error)?;
        file_barrier(&head)?;dir_barrier(&s.dir)?;file_barrier(&head)?;
        s.remove_pending()?; // only after a valid settled head, never fallback
        match s.state.phase {
            Phase::Empty=>if s.dir.join(DATA).try_exists().map_err(io_error)? {return Err(Error::CorruptRecord)},
            Phase::Staging=>s.recover_prefix()?,
            Phase::Sealed|Phase::Published=>{drop(s.checked_file()?);},
            Phase::Deleting=>s.finish_delete()?,
        }
        Ok(s)
    }
    fn load(dir:&Path,anchor:u64,installation:u64)->Result<Snapshot,Error> {
        let path=dir.join(HEAD);regular(&path)?;
        let mut data=Vec::with_capacity(RECORD_BYTES+1);
        File::open(path).map_err(io_error)?.take((RECORD_BYTES+1) as u64).read_to_end(&mut data).map_err(io_error)?;
        codec::decode(&data,anchor,installation)
    }
    fn live(&self)->Result<(),Error> {if self.poisoned {Err(Error::CommitUncertain)} else {Ok(())}}
    fn scope(&self,m:Manifest,caller:Caller,ticket:u64,action:Action)->Scope {Scope{manifest:m,caller,boot:self.boot,ticket,action}}
    fn auth(&self,e:&mut impl Evidence,m:Manifest,c:Caller,t:u64,a:Action)->Result<(),Error> {
        if c.owner==0 || c.incarnation==0 || e.authorize(self.scope(m,c,t,a))!=Verdict::Valid {return Err(Error::Authority)}
        Ok(())
    }
    fn current_ticket(&self)->Ticket {Ticket{anchor:self.state.anchor,installation:self.state.installation,serial:self.state.ticket,caller:self.state.caller}}
    fn bound(&self,t:Ticket)->Result<Manifest,Error> {
        self.live()?;
        if self.state.phase==Phase::Empty || t!=self.current_ticket() {return Err(Error::Authority)}
        self.state.manifest.ok_or(Error::CorruptRecord)
    }
    pub(crate) fn usage(&self)->Result<Usage,Error> {
        self.live()?;Ok(Usage{candidate:self.state.charge,service:if self.state.phase==Phase::Empty {self.state.limits.fixed().ok_or(Error::CorruptRecord)?} else {0},other:self.state.limits.other_bytes})
    }
    /// Current authorized resume position; observation never replenishes work.
    pub(crate) fn upload_progress(&self,t:Ticket,e:&mut impl Evidence)->Result<(u64,bool,u64),Error> {
        let m=self.bound(t)?;self.auth(e,m,t.caller,t.serial,Action::Upload)?;
        if !matches!(self.state.phase,Phase::Staging|Phase::Sealed) {return Err(Error::Conflict)}
        Ok((self.state.cursor,self.state.phase==Phase::Sealed,self.state.limits.window.min(4096)))
    }
    /// Recover an exact published outcome after a lost acknowledgement. This
    /// never treats a different request or publication as an upload to resume.
    pub(crate) fn publication_outcome(&mut self,m:Manifest,c:Caller,request:u64,expected:u64,
        e:&mut impl Evidence)->Result<Option<Selection>,Error>
    {
        self.live()?;
        if !m.valid() || request==0 {return Err(Error::InvalidRequest)}
        if (m.anchor,m.installation)!=(self.state.anchor,self.state.installation) {return Err(Error::Authority)}
        self.auth(e,m,c,self.state.ticket,Action::Publish)?;
        if self.state.phase!=Phase::Published {return Ok(None)}
        if self.state.manifest!=Some(m) || self.state.caller!=c {return Err(Error::Conflict)}
        let mut file=self.checked_file()?;self.validate(&mut file,m,e)?;
        self.publish(self.current_ticket(),request,expected,e).map(Some)
    }
    pub(crate) fn reserve(&mut self,m:Manifest,c:Caller,e:&mut impl Evidence)->Result<Ticket,Error> {
        self.live()?;
        if !m.valid() {return Err(Error::InvalidRequest)}
        if (m.anchor,m.installation)!=(self.state.anchor,self.state.installation) {return Err(Error::Authority)}
        self.auth(e,m,c,if self.state.phase==Phase::Empty {0} else {self.state.ticket},Action::Upload)?;
        // Exact reservation resumption after lost acknowledgement/reopen.
        if self.state.phase!=Phase::Empty {
            if matches!(self.state.phase,Phase::Staging|Phase::Sealed) && self.state.manifest==Some(m) && self.state.caller==c {
                return Ok(self.current_ticket())
            }
            return Err(Error::Conflict)
        }
        if (m.artifact,m.generation)==(self.state.selected.artifact,self.state.selected.generation) {return Err(Error::Conflict)}
        let charge=self.state.limits.charge(m)?;
        let serial=self.state.high.checked_add(1).ok_or(Error::Exhausted)?;
        let mut next=self.state.clone();next.phase=Phase::Staging;next.high=serial;next.ticket=serial;
        next.caller=c;next.manifest=Some(m);next.charge=charge;next.remaining=next.limits.work;
        self.commit(next)?; // durable watermark before any handle or payload
        Ok(self.current_ticket())
    }
    pub(crate) fn append(&mut self,t:Ticket,offset:u64,bytes:&[u8],e:&mut impl Evidence)->Result<(),Error> {
        let m=self.bound(t)?;self.auth(e,m,t.caller,t.serial,Action::Upload)?;
        if self.state.phase!=Phase::Staging {return Err(Error::Conflict)}
        let n=u64::try_from(bytes.len()).map_err(|_|Error::Capacity)?;
        if n==0 || n>self.state.limits.window || self.state.remaining==0 {return Err(Error::Capacity)}
        let mut next=self.state.clone();next.remaining-=1;
        if offset==self.state.cursor {
            if offset.checked_add(n).is_none_or(|end|end>m.size) {return Err(Error::InvalidRequest)}
            let path=self.dir.join(DATA);
            let mut file=if path.try_exists().map_err(io_error)? {
                regular(&path)?;OpenOptions::new().read(true).write(true).open(&path).map_err(io_error)?
            } else {
                if offset!=0 {return Err(Error::CorruptRecord)}
                OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).map_err(io_error)?
            };
            if file.metadata().map_err(io_error)?.len()<offset {return Err(Error::CorruptRecord)}
            self.poisoned=true;
            file.set_len(offset).map_err(|_|Error::CommitUncertain)?;
            file.seek(SeekFrom::Start(offset)).map_err(|_|Error::CommitUncertain)?;
            file.write_all(bytes).map_err(|_|Error::CommitUncertain)?;
            file_barrier(&file).map_err(|_|Error::CommitUncertain)?;dir_barrier(&self.dir).map_err(|_|Error::CommitUncertain)?;
            #[cfg(test)] self.checkpoint(Cut::PayloadWritten)?;
            self.poisoned=false;
            next.cursor=offset+n;next.last_off=offset;next.last_n=n;
        } else if self.state.last_n==n && self.state.last_off==offset {
            // Compare actual bytes; no client-provided checksum can authorize retry.
            let mut file=self.payload_file()?;file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
            let mut old=vec![0;bytes.len()];file.read_exact(&mut old).map_err(io_error)?;
            if old.as_slice()!=bytes {return Err(Error::Conflict)}
        } else {return Err(Error::Conflict)}
        self.auth(e,m,t.caller,t.serial,Action::Upload)?;
        self.commit(next)
    }
    pub(crate) fn seal(&mut self,t:Ticket,e:&mut impl Evidence)->Result<(),Error> {
        let m=self.bound(t)?;self.auth(e,m,t.caller,t.serial,Action::Upload)?;
        if !matches!(self.state.phase,Phase::Staging|Phase::Sealed) || self.state.cursor!=m.size {return Err(Error::Conflict)}
        let mut file=self.payload_file()?;
        self.validate(&mut file,m,e)?;
        let crc=self.payload_checksum(&mut file)?;
        file_barrier(&file)?;dir_barrier(&self.dir)?;
        self.auth(e,m,t.caller,t.serial,Action::Upload)?;
        let mut next=self.state.clone();next.phase=Phase::Sealed;next.payload_crc=crc;
        if self.state.phase==Phase::Sealed {
            if self.state.payload_crc!=crc {return Err(Error::CorruptRecord)}
            return Ok(())
        }
        self.commit(next)
    }
    pub(crate) fn publish(&mut self,t:Ticket,request:u64,expected:u64,e:&mut impl Evidence)->Result<Selection,Error> {
        let m=self.bound(t)?;self.auth(e,m,t.caller,t.serial,Action::Publish)?;
        if request==0 {return Err(Error::InvalidRequest)}
        if self.state.phase==Phase::Published {
            if (request,expected)!=(self.state.request,self.state.expected) {return Err(Error::Conflict)}
            self.checked_file()?;self.auth(e,m,t.caller,t.serial,Action::Publish)?;
            return Ok(self.state.selected)
        }
        if self.state.phase!=Phase::Sealed || expected!=self.state.selected.revision {return Err(Error::Conflict)}
        let revision=expected.checked_add(1).ok_or(Error::Exhausted)?;
        let mut file=self.checked_file()?;self.validate(&mut file,m,e)?;
        self.auth(e,m,t.caller,t.serial,Action::Publish)?;
        let mut next=self.state.clone();next.phase=Phase::Published;next.request=request;next.expected=expected;
        next.selected=Selection{revision,artifact:m.artifact,generation:m.generation};self.commit(next)?;
        // Durable effect remains even if current evidence is revoked at disclosure.
        self.auth(e,m,t.caller,t.serial,Action::Publish)?;
        Ok(self.state.selected)
    }
    pub(crate) fn read(&mut self,c:Caller,offset:u64,len:usize,e:&mut impl Evidence)->Result<Vec<u8>,Error> {
        self.live()?;
        if self.state.phase!=Phase::Published {return Err(Error::Conflict)}
        let m=self.state.manifest.ok_or(Error::CorruptRecord)?;
        self.auth(e,m,c,self.state.ticket,Action::Read)?;
        let n=u64::try_from(len).map_err(|_|Error::Capacity)?;
        if n==0 || n>self.state.limits.window || offset.checked_add(n).is_none_or(|end|end>m.size) {return Err(Error::InvalidRequest)}
        let mut file=self.checked_file()?;self.validate(&mut file,m,e)?;
        file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
        let mut bytes=vec![0;len];file.read_exact(&mut bytes).map_err(io_error)?;
        self.auth(e,m,c,self.state.ticket,Action::Read)?;
        Ok(bytes)
    }
    pub(crate) fn discard(&mut self,t:Ticket,e:&mut impl Evidence)->Result<(),Error> {
        let m=self.bound(t)?;self.auth(e,m,t.caller,t.serial,Action::Upload)?;
        self.start_delete()
    }
    pub(crate) fn reap(&mut self,t:Ticket,e:&mut impl Evidence)->Result<(),Error> {
        let m=self.bound(t)?;
        if e.retired(self.scope(m,t.caller,t.serial,Action::Retire))!=Verdict::Valid {return Err(Error::Authority)}
        self.start_delete()
    }
    fn start_delete(&mut self)->Result<(),Error> {
        if !matches!(self.state.phase,Phase::Staging|Phase::Sealed) {return Err(Error::Conflict)}
        // Synchronous exclusive methods issue no external DMA/work handles; all
        // readers/validators have returned before deletion begins (active=0).
        let mut next=self.state.clone();next.phase=Phase::Deleting;self.commit(next)?;
        #[cfg(test)] self.checkpoint(Cut::CleanupIntent)?;
        self.finish_delete()
    }
    fn finish_delete(&mut self)->Result<(),Error> {
        self.poisoned=true;
        let path=self.dir.join(DATA);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_file()=>fs::remove_file(&path).map_err(|_|Error::CommitUncertain)?,
            Ok(_)=>return Err(Error::CorruptRecord),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>(),
            Err(_)=>return Err(Error::CommitUncertain),
        }
        dir_barrier(&self.dir).map_err(|_|Error::CommitUncertain)?;
        #[cfg(test)] self.checkpoint(Cut::PayloadDeleted)?;
        self.poisoned=false;
        let next=self.state.cleared();self.commit(next)
    }
    fn payload_file(&self)->Result<File,Error> {
        let path=self.dir.join(DATA);regular(&path)?;
        OpenOptions::new().read(true).write(true).open(path).map_err(io_error)
    }
    fn recover_prefix(&mut self)->Result<(),Error> {
        let path=self.dir.join(DATA);
        if !path.try_exists().map_err(io_error)? {
            return if self.state.cursor==0 {Ok(())} else {Err(Error::CorruptRecord)}
        }
        let f=self.payload_file()?;
        let n=f.metadata().map_err(io_error)?.len();
        if n<self.state.cursor || n>self.state.manifest.ok_or(Error::CorruptRecord)?.size {return Err(Error::CorruptRecord)}
        // Only private, unacknowledged suffixes are discarded; committed prefix remains.
        f.set_len(self.state.cursor).map_err(io_error)?;file_barrier(&f)?;Ok(())
    }
    fn payload_checksum(&self,file:&mut File)->Result<u64,Error> {
        file.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let mut buffer=vec![0;usize::try_from(self.state.limits.window).map_err(|_|Error::Capacity)?];
        let mut crc=0u64;
        loop {let n=file.read(&mut buffer).map_err(io_error)?;if n==0 {break}
            for &b in &buffer[..n] {crc^=(b as u64)<<56;for _ in 0..8 {crc=if crc&(1<<63)!=0 {(crc<<1)^0x42f0_e1eb_a9ea_3693}else{crc<<1};}}
        }
        Ok(crc)
    }
    fn checked_file(&self)->Result<File,Error> {
        let mut file=self.payload_file()?;
        let m=self.state.manifest.ok_or(Error::CorruptRecord)?;
        if file.metadata().map_err(io_error)?.len()!=m.size || self.payload_checksum(&mut file)?!=self.state.payload_crc {return Err(Error::CorruptRecord)}
        Ok(file)
    }
    fn validate(&self,file:&mut File,m:Manifest,e:&mut impl Evidence)->Result<(),Error> {
        if file.metadata().map_err(io_error)?.len()!=m.size {return Err(Error::CorruptRecord)}
        file.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let mut bounded=std::io::Read::by_ref(file).take(m.size);
        let actual=e.inspect(&mut bounded)?;
        if bounded.limit()!=0 || actual!=m {return Err(Error::CorruptRecord)}
        Ok(())
    }
    fn remove_pending(&self)->Result<(),Error> {
        let path=self.dir.join(PENDING);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_file()=>fs::remove_file(path).map_err(io_error),
            Ok(_)=>Err(Error::CorruptRecord),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(()),
            Err(e)=>Err(io_error(e)),
        }
    }
    fn commit(&mut self,next:Snapshot)->Result<(),Error> {
        self.live()?;
        if Self::load(&self.dir,self.state.anchor,self.state.installation)?!=self.state {return Err(Error::Conflict)}
        let bytes=codec::encode(&next)?;
        #[cfg(test)] self.checkpoint(Cut::BeforeLedger)?;
        self.poisoned=true;
        self.remove_pending().map_err(|_|Error::CommitUncertain)?;
        let path=self.dir.join(PENDING);
        let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).map_err(|_|Error::CommitUncertain)?;
        f.write_all(&bytes[..RECORD_BYTES/2]).map_err(|_|Error::CommitUncertain)?;
        #[cfg(test)] self.checkpoint(Cut::PartialLedger)?;
        f.write_all(&bytes[RECORD_BYTES/2..]).map_err(|_|Error::CommitUncertain)?;file_barrier(&f).map_err(|_|Error::CommitUncertain)?;
        #[cfg(test)] self.checkpoint(Cut::LedgerSynced)?;
        fs::rename(path,self.dir.join(HEAD)).map_err(|_|Error::CommitUncertain)?;
        #[cfg(test)] self.checkpoint(Cut::Renamed)?;
        dir_barrier(&self.dir).map_err(|_|Error::CommitUncertain)?;file_barrier(&f).map_err(|_|Error::CommitUncertain)?;
        #[cfg(test)] self.checkpoint(Cut::DirectorySynced)?;
        self.state=next;self.poisoned=false;Ok(())
    }
    #[cfg(test)]
    fn checkpoint(&mut self,cut:Cut)->Result<(),Error> {
        if self.cut==Some(cut) {self.poisoned=true;Err(Error::CommitUncertain)} else {Ok(())}
    }
}

#[cfg(test)]
#[path="artifact/tests.rs"]
mod tests;
