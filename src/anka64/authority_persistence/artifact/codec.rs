use super::*;
const MAGIC:&[u8;8]=b"ANKAAS1\0";
const WORDS:usize=40;
pub(super) const RECORD_BYTES:usize=8+8*WORDS+8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {Empty,Staging,Sealed,Published,Deleting}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub anchor:u64,pub installation:u64,pub limits:Limits,pub high:u64,pub phase:Phase,
    pub selected:Selection,pub ticket:u64,pub caller:Caller,pub cursor:u64,pub charge:u64,
    pub remaining:u64,pub last_off:u64,pub last_n:u64,pub request:u64,pub expected:u64,
    pub payload_crc:u64,pub manifest:Option<Manifest>,
}
impl Snapshot {
    pub fn empty(anchor:u64,installation:u64,limits:Limits,selected:Selection)->Self {
        Self{anchor,installation,limits,high:0,phase:Phase::Empty,selected,ticket:0,
            caller:Caller{owner:0,incarnation:0},cursor:0,charge:0,remaining:0,last_off:0,last_n:0,
            request:0,expected:0,payload_crc:0,manifest:None}
    }
    pub fn cleared(&self)->Self {
        let mut s=Self::empty(self.anchor,self.installation,self.limits,self.selected);s.high=self.high;s
    }
    fn valid(&self)->bool {
        if self.anchor==0 || self.installation==0 || !self.limits.valid() || !self.selected.valid() {return false}
        if self.phase==Phase::Empty {return self==&self.cleared()}
        let Some(m)=self.manifest else{return false};
        if !m.valid() || (m.anchor,m.installation)!=(self.anchor,self.installation)
            || self.ticket==0 || self.ticket!=self.high || self.caller.owner==0 || self.caller.incarnation==0
            || self.limits.charge(m)!=Ok(self.charge) || self.cursor>m.size || self.remaining>self.limits.work
            || self.last_n>self.limits.window {return false}
        if self.cursor==0 {
            if self.last_off!=0 || self.last_n!=0 {return false}
        } else if self.last_n==0 || self.last_off.checked_add(self.last_n)!=Some(self.cursor) {return false}
        if self.phase==Phase::Published {
            self.cursor==m.size && self.request!=0 && self.expected.checked_add(1)==Some(self.selected.revision)
                && (m.artifact,m.generation)==(self.selected.artifact,self.selected.generation)
        } else {
            self.request==0 && self.expected==0
                && (m.artifact,m.generation)!=(self.selected.artifact,self.selected.generation)
                && (self.phase!=Phase::Sealed || self.cursor==m.size)
                && (self.phase!=Phase::Staging || self.payload_crc==0)
        }
    }
}
pub(super) fn encode(s:&Snapshot)->Result<[u8;RECORD_BYTES],Error> {
    if !s.valid() {return Err(Error::CorruptRecord)}
    let l=s.limits;
    let mut w=[0u64;WORDS];
    w[..25].copy_from_slice(&[1,s.anchor,s.installation,l.max_payload,l.window,l.owner_bytes,l.total_bytes,l.other_bytes,l.work,
        s.high,match s.phase{Phase::Empty=>0,Phase::Staging=>1,Phase::Sealed=>2,Phase::Published=>3,Phase::Deleting=>4},
        s.selected.revision,s.selected.artifact,s.selected.generation,s.ticket,s.caller.owner,s.caller.incarnation,
        s.cursor,s.charge,s.remaining,s.last_off,s.last_n,s.request,s.expected,s.payload_crc]);
    if let Some(m)=s.manifest {
        w[25..36].copy_from_slice(&[m.anchor,m.installation,m.artifact,m.generation,m.role,m.profile,m.size,m.image,m.metadata,m.dependencies,m.provenance]);
    }
    let mut out=[0;RECORD_BYTES];out[..8].copy_from_slice(MAGIC);
    for (i,n) in w.iter().enumerate(){out[8+i*8..16+i*8].copy_from_slice(&n.to_le_bytes());}
    let crc=checksum(&out[..RECORD_BYTES-8]);out[RECORD_BYTES-8..].copy_from_slice(&crc.to_le_bytes());Ok(out)
}
pub(super) fn decode(bytes:&[u8],anchor:u64,installation:u64)->Result<Snapshot,Error> {
    if bytes.len()!=RECORD_BYTES || &bytes[..8]!=MAGIC {return Err(Error::CorruptRecord)}
    let word=|i:usize|u64::from_le_bytes(bytes[i..i+8].try_into().unwrap());
    if checksum(&bytes[..RECORD_BYTES-8])!=word(RECORD_BYTES-8) {return Err(Error::CorruptRecord)}
    let mut w=[0;WORDS];for (i,n) in w.iter_mut().enumerate(){*n=word(8+i*8);}
    if w[0]!=1 || w[36..].iter().any(|&n|n!=0) {return Err(Error::CorruptRecord)}
    if (w[1],w[2])!=(anchor,installation) {return Err(Error::Authority)}
    let phase=match w[10]{0=>Phase::Empty,1=>Phase::Staging,2=>Phase::Sealed,3=>Phase::Published,4=>Phase::Deleting,_=>return Err(Error::CorruptRecord)};
    let manifest=if phase==Phase::Empty {
        if w[25..36].iter().any(|&n|n!=0) {return Err(Error::CorruptRecord)}
        None
    } else {Some(Manifest{anchor:w[25],installation:w[26],artifact:w[27],generation:w[28],role:w[29],profile:w[30],size:w[31],image:w[32],metadata:w[33],dependencies:w[34],provenance:w[35]})};
    let s=Snapshot{anchor:w[1],installation:w[2],limits:Limits{max_payload:w[3],window:w[4],owner_bytes:w[5],total_bytes:w[6],other_bytes:w[7],work:w[8]},
        high:w[9],phase,selected:Selection{revision:w[11],artifact:w[12],generation:w[13]},ticket:w[14],caller:Caller{owner:w[15],incarnation:w[16]},
        cursor:w[17],charge:w[18],remaining:w[19],last_off:w[20],last_n:w[21],request:w[22],expected:w[23],payload_crc:w[24],manifest};
    if !s.valid(){return Err(Error::CorruptRecord)}
    Ok(s)
}
