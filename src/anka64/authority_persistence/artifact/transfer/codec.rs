use super::*;
pub(crate) const HEADER:usize=168;
pub(crate) const MAX_REQUEST:usize=HEADER+4096;
pub(crate) const MAX_REPLY:usize=72+MAX_REQUEST;
const REQUEST_MAGIC:&[u8;8]=b"ANKAUP01";
const REPLY_MAGIC:&[u8;8]=b"ANKAUR01";
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u64)]
pub(crate) enum Operation {Begin=1,Append=2,Seal=3,Publish=4,Progress=5,Outcome=6}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct Request<'a> {
    pub operation:Operation,pub correlation:u64,pub ticket:u64,pub offset:u64,
    pub publish_request:u64,pub expected:u64,pub manifest:Manifest,pub payload:&'a[u8],
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct Outcome {pub ticket:u64,pub cursor:u64,pub phase:u64,pub revision:u64,pub artifact:u64,pub generation:u64}
impl Outcome {
    pub(super) fn private(ticket:u64,cursor:u64,sealed:bool)->Self {Self{ticket,cursor,phase:if sealed{2}else{1},revision:0,artifact:0,generation:0}}
    pub(super) fn published(ticket:u64,cursor:u64,s:Selection)->Self {Self{ticket,cursor,phase:3,revision:s.revision,artifact:s.artifact,generation:s.generation}}
}
pub(crate) struct Reply {pub(super) bytes:[u8;MAX_REPLY],pub(super) len:usize}
impl Reply {pub(crate) fn bytes(&self)->&[u8] {&self.bytes[..self.len]}}
impl Drop for Reply {fn drop(&mut self){
    // Private response bytes may contain code or metadata. Scrub before the
    // transport refunds custody, including errors and unwinding.
    for b in &mut self.bytes {unsafe {std::ptr::write_volatile(b,0)}}
    self.len=0;
}}
fn word(bytes:&[u8],index:usize)->u64 {u64::from_le_bytes(bytes[8+index*8..16+index*8].try_into().unwrap())}
fn put(bytes:&mut[u8],index:usize,n:u64) {bytes[8+index*8..16+index*8].copy_from_slice(&n.to_le_bytes());}
fn valid(r:&Request<'_>)->bool {
    let m=r.manifest;
    if r.correlation==0 || !m.valid() || m.role!=2 || !matches!(m.profile,1|2) || m.dependencies==0 || r.payload.len()>4096 {return false}
    let empty=r.offset==0 && r.payload.is_empty();let no_publish=r.publish_request==0 && r.expected==0;
    match r.operation {
        Operation::Begin=>r.ticket==0 && empty && no_publish,
        Operation::Append=>r.ticket!=0 && !r.payload.is_empty() && no_publish
            && r.offset.checked_add(r.payload.len() as u64).is_some_and(|end|end<=m.size),
        Operation::Seal|Operation::Progress=>r.ticket!=0 && empty && no_publish,
        Operation::Publish=>r.ticket!=0 && empty && r.publish_request!=0 && r.expected!=0,
        Operation::Outcome=>r.ticket==0 && empty && r.publish_request!=0 && r.expected!=0,
    }
}
pub(crate) fn decode(bytes:&[u8],eof:bool)->Result<Request<'_>,Error> {
    if !eof || bytes.len()<HEADER || bytes.len()>MAX_REQUEST || &bytes[..8]!=REQUEST_MAGIC || word(bytes,0)!=1 || word(bytes,19)!=0 {return Err(Error::InvalidRequest)}
    let n=word(bytes,5);
    if n>4096 || bytes.len()!=HEADER+n as usize {return Err(Error::InvalidRequest)}
    let operation=match word(bytes,1) {1=>Operation::Begin,2=>Operation::Append,3=>Operation::Seal,4=>Operation::Publish,5=>Operation::Progress,6=>Operation::Outcome,_=>return Err(Error::InvalidRequest)};
    let m=Manifest{anchor:word(bytes,8),installation:word(bytes,9),artifact:word(bytes,10),generation:word(bytes,11),role:word(bytes,12),profile:word(bytes,13),size:word(bytes,14),image:word(bytes,15),metadata:word(bytes,16),dependencies:word(bytes,17),provenance:word(bytes,18)};
    let r=Request{operation,correlation:word(bytes,2),ticket:word(bytes,3),offset:word(bytes,4),publish_request:word(bytes,6),expected:word(bytes,7),manifest:m,payload:&bytes[HEADER..]};
    if !valid(&r) {return Err(Error::InvalidRequest)}Ok(r)
}
pub(crate) fn encode(r:&Request<'_>,out:&mut[u8])->Result<usize,Error> {
    if !valid(r) {return Err(Error::InvalidRequest)}
    let n=HEADER+r.payload.len();if out.len()<n {return Err(Error::Capacity)}
    let m=r.manifest;
    let words=[1,r.operation as u64,r.correlation,r.ticket,r.offset,r.payload.len() as u64,r.publish_request,r.expected,
        m.anchor,m.installation,m.artifact,m.generation,m.role,m.profile,m.size,m.image,m.metadata,m.dependencies,m.provenance,0];
    out[..8].copy_from_slice(REQUEST_MAGIC);for(i,w)in words.iter().enumerate(){put(out,i,*w);}
    out[HEADER..n].copy_from_slice(r.payload);Ok(n)
}
fn valid_outcome(r:&Request<'_>,o:Outcome)->bool {
    if o.ticket==0 || (r.ticket!=0 && o.ticket!=r.ticket) || o.cursor>r.manifest.size {return false}
    if matches!(r.operation,Operation::Publish|Operation::Outcome) {
        return o.phase==3 && o.cursor==r.manifest.size && r.expected.checked_add(1)==Some(o.revision)
            && o.artifact==r.manifest.artifact && o.generation==r.manifest.generation
    }
    if !matches!(o.phase,1|2) || o.revision!=0 || o.artifact!=0 || o.generation!=0 || (o.phase==2 && o.cursor!=r.manifest.size) {return false}
    match r.operation {
        Operation::Seal=>o.phase==2,
        Operation::Append=>o.phase==1 && r.offset.checked_add(r.payload.len()as u64)==Some(o.cursor),
        Operation::Begin|Operation::Progress=>true,
        _=>false,
    }
}
pub(super) fn reply(frame:&[u8],r:&Request<'_>,o:Outcome)->Result<Reply,Error> {
    if !valid_outcome(r,o) || frame.len()>MAX_REQUEST {return Err(Error::Conflict)}
    let mut reply=Reply{bytes:[0;MAX_REPLY],len:72+frame.len()};
    reply.bytes[..8].copy_from_slice(REPLY_MAGIC);
    for(i,w)in [1,frame.len()as u64,o.ticket,o.cursor,o.phase,o.revision,o.artifact,o.generation].iter().enumerate(){put(&mut reply.bytes,i,*w);}
    reply.bytes[72..reply.len].copy_from_slice(frame);Ok(reply)
}
/// The caller must validate storage-server authority before sending request
/// bytes as well. This boundary validates it again at final reply admission.
pub(crate) trait ServerEvidence {
    fn current(&mut self,_connection:u64,_request:&Request<'_>,_reply:&[u8])->Verdict {Verdict::Unknown}
}
pub(crate) fn accept_reply(request:&[u8],reply:&[u8],eof:bool,connection:u64,e:&mut impl ServerEvidence)->Result<Outcome,Error> {
    let r=decode(request,true)?;
    if !eof || connection==0 || reply.len()!=72+request.len() || reply.len()>MAX_REPLY || &reply[..8]!=REPLY_MAGIC
        || word(reply,0)!=1 || word(reply,1)!=request.len()as u64 || &reply[72..]!=request {return Err(Error::InvalidRequest)}
    let o=Outcome{ticket:word(reply,2),cursor:word(reply,3),phase:word(reply,4),revision:word(reply,5),artifact:word(reply,6),generation:word(reply,7)};
    if !valid_outcome(&r,o) {return Err(Error::InvalidRequest)}
    if e.current(connection,&r,reply)!=Verdict::Valid {return Err(Error::Authority)}Ok(o)
}
