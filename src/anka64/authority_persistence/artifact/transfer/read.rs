//! AR110 read extension. Upload-only decode/dispatch remain unchanged.
//! Fixed response custody is covered by the transport's preallocated slot.
use super::*;
#[path="read/client.rs"]
pub(crate) mod client;
pub(crate) const READ_REPLY_PREFIX:usize=200;
pub(crate) const MAX_READ_REPLY:usize=READ_REPLY_PREFIX+4096;
const _:()=assert!(MAX_READ_REPLY<=MAX_REPLY);
const MAGIC:&[u8;8]=b"ANKARD01";
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct ReadRequest {pub correlation:u64,pub offset:u64,pub count:u64,pub manifest:Manifest}
fn word(b:&[u8],i:usize)->u64 {u64::from_le_bytes(b[8+8*i..16+8*i].try_into().unwrap())}
fn valid(r:ReadRequest)->bool {
    let m=r.manifest;
    r.correlation!=0 && m.valid() && m.role==2 && matches!(m.profile,1|2) && m.dependencies!=0
        && (1..=4096).contains(&r.count) && r.offset<=m.size && r.count<=m.size-r.offset
}
pub(crate) fn decode_read(b:&[u8],eof:bool)->Result<ReadRequest,Error> {
    if !eof || b.len()!=HEADER || &b[..8]!=b"ANKAUP01" || word(b,0)!=1 || word(b,1)!=7
        || word(b,3)!=0 || word(b,6)!=0 || word(b,7)!=0 || word(b,19)!=0 {return Err(Error::InvalidRequest)}
    let r=ReadRequest{correlation:word(b,2),offset:word(b,4),count:word(b,5),manifest:Manifest{
        anchor:word(b,8),installation:word(b,9),artifact:word(b,10),generation:word(b,11),role:word(b,12),
        profile:word(b,13),size:word(b,14),image:word(b,15),metadata:word(b,16),dependencies:word(b,17),provenance:word(b,18)}};
    if !valid(r) {return Err(Error::InvalidRequest)}Ok(r)
}
pub(crate) fn encode_read(r:ReadRequest)->Result<[u8;HEADER],Error> {
    if !valid(r) {return Err(Error::InvalidRequest)}
    let m=r.manifest;let mut b=[0;HEADER];b[..8].copy_from_slice(b"ANKAUP01");
    for(i,w)in [1,7,r.correlation,0,r.offset,r.count,0,0,m.anchor,m.installation,m.artifact,m.generation,
        m.role,m.profile,m.size,m.image,m.metadata,m.dependencies,m.provenance,0].iter().enumerate() {
        b[8+i*8..16+i*8].copy_from_slice(&w.to_le_bytes());
    }Ok(b)
}
/// Routing hint only. Malformed read headers still go through full read decode;
/// an unknown opcode never falls through to an authorized read.
pub(super) fn is_read(b:&[u8])->bool {b.len()>=24 && word(b,1)==7}
pub(super) fn validate_frame(b:&[u8],eof:bool)->Result<(),Error> {
    if is_read(b) {decode_read(b,eof).map(|_|())}else{decode(b,eof).map(|_|())}
}
/// Trusted adapter binds actual stream, current server/read evidence and exact
/// immutable content. These callbacks must be bounded and serialized with IO.
pub(crate) trait ReadServerEvidence {
    fn before_send(&mut self,_connection:u64,_request:&ReadRequest)->Verdict {Verdict::Unknown}
    fn current(&mut self,_connection:u64,_request:&ReadRequest,_reply:&[u8])->Verdict {Verdict::Unknown}
}
pub(crate) fn accept_read_reply<'a>(frame:&[u8],reply:&'a[u8],eof:bool,connection:u64,
    proof:&mut impl ReadServerEvidence)->Result<&'a[u8],Error>
{
    let r=decode_read(frame,true)?;
    if !eof || connection==0 || reply.len()!=READ_REPLY_PREFIX+r.count as usize || reply.len()>MAX_READ_REPLY
        || &reply[..8]!=MAGIC || word(reply,0)!=1 || word(reply,1)!=HEADER as u64 || word(reply,2)!=r.count
        || &reply[32..READ_REPLY_PREFIX]!=frame {return Err(Error::InvalidRequest)}
    if proof.current(connection,&r,reply)!=Verdict::Valid {return Err(Error::Authority)}
    Ok(&reply[READ_REPLY_PREFIX..])
}
/// Rechecks the saved backend ticket as well as exact manifest and actual caller.
/// The ticket is local custody; no upload ticket is accepted from the read wire.
pub(crate) fn authorize_read(store:&ArtifactStore,connection:u64,r:&ReadRequest,
    saved:Option<(Caller,u64)>,e:&mut impl TransferEvidence)->Result<Caller,Error>
{
    store.live()?;
    let caller=e.read_caller(connection,r)?;
    if connection==0 || caller.owner==0 || caller.incarnation==0 {return Err(Error::Authority)}
    if store.state.phase!=Phase::Published || store.state.manifest!=Some(r.manifest) {return Err(Error::Authority)}
    if saved.is_some_and(|(c,t)|c!=caller || t!=store.state.ticket) {return Err(Error::Authority)}
    store.auth(e,r.manifest,caller,store.state.ticket,Action::Read)?;
    Ok(caller)
}
pub(crate) fn dispatch_read(store:&mut ArtifactStore,connection:u64,frame:&[u8],eof:bool,
    budget:&mut Budget,e:&mut impl TransferEvidence)->Result<Reply,Error>
{
    budget.spend(frame.len())?;
    let r=decode_read(frame,eof)?;
    let caller=authorize_read(store,connection,&r,None,e)?;let ticket=store.state.ticket;
    if r.count>store.state.limits.window {return Err(Error::InvalidRequest)}
    // Charge both full-file scans before IO. Never retry a scan on a fresh
    // dispatch budget. Blocking host IO/callbacks remain cooperative obligations.
    budget.scan(r.manifest.size)?;
    let mut file=store.checked_file()?;store.validate(&mut file,r.manifest,e)?;
    authorize_read(store,connection,&r,Some((caller,ticket)),e)?;
    let mut out=Reply{bytes:[0;MAX_REPLY],len:READ_REPLY_PREFIX+r.count as usize};
    out.bytes[..8].copy_from_slice(MAGIC);
    for(i,w)in [1,HEADER as u64,r.count].iter().enumerate(){out.bytes[8+i*8..16+i*8].copy_from_slice(&w.to_le_bytes());}
    out.bytes[32..READ_REPLY_PREFIX].copy_from_slice(frame);
    file.seek(SeekFrom::Start(r.offset)).map_err(io_error)?;
    file.read_exact(&mut out.bytes[READ_REPLY_PREFIX..out.len]).map_err(io_error)?;
    authorize_read(store,connection,&r,Some((caller,ticket)),e)?;
    Ok(out)
}
#[cfg(test)]
#[path="read/tests.rs"]
pub(super) mod tests;
