//! SR110 first Rust slice: bounded host-file reception and canonical CS110 view.
//! No network read opcode, local executable objects or execute authority here.
use super::*;
use std::time::{Duration, Instant};

pub(crate) const ENVELOPE_HEADER: usize = 136;
pub(crate) const DEPENDENCY_BYTES: usize = 40;
const MAX_DEPENDENCIES: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredDependency {
    pub anchor: u64, pub installation: u64, pub artifact: u64,
    pub generation: u64, pub provenance: u64,
}

/// Borrowed immutable bytes, NOT a receipt, pointer capability or executable.
/// Every field and extent is checked by decode; identities still require a
/// trusted independent validator, not equality to caller-supplied digest words.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StoredEnvelope<'a> {
    manifest: Manifest,
    bytes: &'a [u8],
    image_start: usize,
    count: usize,
    code: u64, lit: u64, entry: u64,
}
fn word(bytes: &[u8], offset: usize) -> u64 {
    // All callers have already checked the enclosing fixed extent.
    u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap())
}
impl<'a> StoredEnvelope<'a> {
    pub(crate) fn decode(bytes: &'a [u8], expected: Manifest) -> Result<Self, Error> {
        if bytes.len()<ENVELOPE_HEADER || bytes.get(..8)!=Some(b"ANKACS01".as_slice()) {
            return Err(Error::CorruptRecord)
        }
        let w=|i:usize| word(bytes,8+i*8);
        if w(0)!=1 || w(1)!=2 || !matches!(w(2),1|2) {return Err(Error::CorruptRecord)}
        let image=w(10);let count=w(11);
        if count==0 || count>MAX_DEPENDENCIES || image==0 {return Err(Error::CorruptRecord)}
        let start=(ENVELOPE_HEADER as u64).checked_add(count.checked_mul(DEPENDENCY_BYTES as u64)
            .ok_or(Error::CorruptRecord)?).ok_or(Error::CorruptRecord)?;
        let size=start.checked_add(image).ok_or(Error::CorruptRecord)?;
        if u64::try_from(bytes.len()).map_err(|_|Error::Capacity)?!=size {return Err(Error::CorruptRecord)}
        let code=w(7);let lit=w(8);let entry=w(9);
        if code==0 || code%4!=0 || code>lit || lit>image || entry>=code || entry%4!=0 {
            return Err(Error::CorruptRecord)
        }
        let manifest=Manifest{anchor:w(3),installation:w(4),artifact:w(5),generation:w(6),
            role:w(1),profile:w(2),size,image:w(12),metadata:w(13),dependencies:w(14),provenance:w(15)};
        if !manifest.valid() || manifest.dependencies==0 || manifest!=expected {return Err(Error::Authority)}
        let result=Self{manifest,bytes,image_start:usize::try_from(start).map_err(|_|Error::Capacity)?,
            count:usize::try_from(count).map_err(|_|Error::Capacity)?,code,lit,entry};
        for i in 0..result.count {
            let d=result.dependency(i).ok_or(Error::CorruptRecord)?;
            if d.anchor!=manifest.anchor || d.installation!=manifest.installation || d.artifact==0
                || d.generation==0 || d.provenance==0 {return Err(Error::Authority)}
        }
        Ok(result)
    }
    pub(crate) fn manifest(self)->Manifest {self.manifest}
    pub(crate) fn image(self)->&'a [u8] {&self.bytes[self.image_start..]}
    pub(crate) fn code_size(self)->u64 {self.code}
    pub(crate) fn literal_start(self)->u64 {self.lit}
    pub(crate) fn entry(self)->u64 {self.entry}
    pub(crate) fn dependency_count(self)->usize {self.count}
    pub(crate) fn dependency(self,index:usize)->Option<StoredDependency> {
        if index>=self.count {return None}
        let offset=ENVELOPE_HEADER+index*DEPENDENCY_BYTES;
        Some(StoredDependency{anchor:word(self.bytes,offset),installation:word(self.bytes,offset+8),
            artifact:word(self.bytes,offset+16),generation:word(self.bytes,offset+24),provenance:word(self.bytes,offset+32)})
    }
}

/// Trusted policy must validate exact received image and metadata, and CURRENT
/// retention/binding of the ordered dependencies and provenance. A CRC or a
/// matching header is insufficient. The policy runs under exclusive custody;
/// callbacks must not reenter or change the storage namespace behind this lane.
pub(crate) trait RetrievalPolicy: Evidence {
    fn validate_retrieved(&mut self,_scope:Scope,_envelope:StoredEnvelope<'_>)->Verdict {Verdict::Unknown}
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct RetrievalLimits {
    pub max_bytes:u64, pub work:u64, pub timeout:Duration,
}
/// One cumulative budget, never reset by an IO chunk or validation callback.
/// Checks bound cooperative work; blocking host IO/providers are not preempted.
pub(crate) struct RetrievalBudget {remaining:u64,deadline:Instant}
impl RetrievalLimits {
    pub(crate) fn start(self,size:u64)->Result<RetrievalBudget,Error> {
        if size==0 || size>self.max_bytes || self.work==0 || self.timeout.is_zero() {
            return Err(Error::Capacity)
        }
        Ok(RetrievalBudget{remaining:self.work,deadline:Instant::now().checked_add(self.timeout).ok_or(Error::Capacity)?})
    }
}
impl RetrievalBudget {
    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self){self.deadline=Instant::now();}

    /// Move remaining work and the ORIGINAL deadline to the next custody phase.
    /// The source is exhausted, so retaining it cannot create a second budget.
    pub(crate) fn transfer(&mut self)->Result<Self,Error> {
        self.check()?;
        Ok(Self{remaining:std::mem::replace(&mut self.remaining,0),deadline:self.deadline})
    }

    pub(crate) fn check(&self)->Result<(),Error> {
        if Instant::now()>=self.deadline {Err(Error::ExpiredRequest)}else{Ok(())}
    }
    pub(crate) fn spend(&mut self,units:u64)->Result<(),Error> {
        self.check()?;
        self.remaining=self.remaining.checked_sub(units).ok_or(Error::Capacity)?;
        Ok(())
    }
    pub(crate) fn bytes(&mut self,size:u64)->Result<(),Error> {
        // Work is 4-KiB scan units plus explicit callback/chunk units.
        self.spend(size/4096+u64::from(size%4096!=0))
    }
}
impl ArtifactStore {
    /// Caller has already reserved/initialized exact output storage. One fixed
    /// file descriptor and immutable manifest are held throughout this read.
    /// Full checksum/independent validation is done once, not once per chunk.
    pub(crate) fn read_published_into(&mut self,expected:Manifest,caller:Caller,out:&mut[u8],
        evidence:&mut impl Evidence,budget:&mut RetrievalBudget)->Result<Scope,Error>
    {
        self.live()?;
        if self.state.phase!=Phase::Published {return Err(Error::Conflict)}
        if self.state.manifest!=Some(expected) || out.len() as u64!=expected.size {return Err(Error::Authority)}
        budget.spend(1)?;
        self.auth(evidence,expected,caller,self.state.ticket,Action::Read)?;
        budget.check()?;
        budget.bytes(expected.size)?;
        let mut file=self.checked_file()?;
        budget.check()?;
        budget.bytes(expected.size)?;
        self.validate(&mut file,expected,evidence)?;
        budget.check()?;
        self.auth(evidence,expected,caller,self.state.ticket,Action::Read)?;
        budget.check()?;
        file.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let window=usize::try_from(self.state.limits.window.min(4096)).map_err(|_|Error::Capacity)?;
        if window==0 {return Err(Error::CorruptRecord)}
        for chunk in out.chunks_mut(window) {
            budget.spend(1)?;
            self.auth(evidence,expected,caller,self.state.ticket,Action::Read)?;
            budget.check()?;
            file.read_exact(chunk).map_err(|_|Error::CorruptRecord)?;
            budget.check()?;
            self.auth(evidence,expected,caller,self.state.ticket,Action::Read)?;
            budget.check()?;
        }
        let mut tail=[0];
        if file.read(&mut tail).map_err(io_error)?!=0 {return Err(Error::CorruptRecord)}
        let scope=self.scope(expected,caller,self.state.ticket,Action::Read);
        self.recheck_retrieval(scope,evidence,budget)?;
        Ok(scope)
    }
    pub(crate) fn recheck_retrieval(&self,scope:Scope,evidence:&mut impl Evidence,budget:&mut RetrievalBudget)->Result<(),Error> {
        self.live()?;budget.spend(1)?;
        if self.state.phase!=Phase::Published || self.state.manifest!=Some(scope.manifest)
            || scope!=self.scope(scope.manifest,scope.caller,self.state.ticket,Action::Read) {return Err(Error::Authority)}
        self.auth(evidence,scope.manifest,scope.caller,scope.ticket,Action::Read)?;
        budget.check()
    }
}
#[cfg(test)]
#[path="retrieval/tests.rs"]
mod tests;
