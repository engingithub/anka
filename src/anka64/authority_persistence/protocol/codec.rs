use super::{Operation,Outcome,Request};
pub(crate) const REQUEST_BYTES:usize=112;
pub(crate) const REPLY_BYTES:usize=144;
const REQUEST_MAGIC:&[u8;8]=b"ANKAPQ1\0";
const REPLY_MAGIC:&[u8;8]=b"ANKAPR1\0";
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum WireError { Length,Incomplete,Header,Shape,Binding,Outcome }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct Envelope { pub correlation:u64,pub request:Request }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u64)]
pub(crate) enum Status { Success=0,Denied=1,Conflict=2,Exhausted=3,Unavailable=4,Uncertain=5,Invalid=6 }
impl Status {
    fn decode(word:u64)->Result<Self,WireError> {match word {
        0=>Ok(Self::Success),1=>Ok(Self::Denied),2=>Ok(Self::Conflict),3=>Ok(Self::Exhausted),
        4=>Ok(Self::Unavailable),5=>Ok(Self::Uncertain),6=>Ok(Self::Invalid),_=>Err(WireError::Header),
    }}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct Reply { envelope:Envelope,status:Status,outcome:Option<Outcome> }
fn get(bytes:&[u8],offset:usize)->u64 {
    // Every caller has checked the exact envelope size before these fixed offsets.
    let mut word=[0;8];word.copy_from_slice(&bytes[offset..offset+8]);u64::from_le_bytes(word)
}
fn put(bytes:&mut [u8],offset:usize,value:u64){bytes[offset..offset+8].copy_from_slice(&value.to_le_bytes());}
fn valid(r:Request)->bool {
    r.anchor!=0 && r.installation!=0 && r.caller!=0 && r.incarnation!=0 && r.sequence!=0 && r.argument!=0 &&
        match r.operation {Operation::Select=>r.attempt==0,Operation::ReserveBoot=>r.attempt!=0}
}
fn header(bytes:&[u8],expected:usize,magic:&[u8;8],ended:bool)->Result<(),WireError> {
    if bytes.len()!=expected{return Err(WireError::Length)}
    if !ended{return Err(WireError::Incomplete)}
    if &bytes[..8]!=magic || get(bytes,8)!=1 || get(bytes,16)!=0 {return Err(WireError::Header)}
    Ok(())
}
fn read_body(bytes:&[u8])->Result<Envelope,WireError> {
    let r=Request {anchor:get(bytes,32),installation:get(bytes,40),policy:get(bytes,48),caller:get(bytes,56),
        incarnation:get(bytes,64),sequence:get(bytes,72),expected:get(bytes,80),
        operation:match get(bytes,88){1=>Operation::Select,2=>Operation::ReserveBoot,_=>return Err(WireError::Shape)},
        argument:get(bytes,96),attempt:get(bytes,104)};
    let e=Envelope{correlation:get(bytes,24),request:r};
    if e.correlation==0 || !valid(r){return Err(WireError::Shape)}
    Ok(e)
}
fn write_body(bytes:&mut [u8],e:Envelope) {
    put(bytes,8,1);put(bytes,24,e.correlation);
    let r=e.request;
    for (i,w) in [r.anchor,r.installation,r.policy,r.caller,r.incarnation,r.sequence,r.expected,
        match r.operation {Operation::Select=>1,Operation::ReserveBoot=>2},r.argument,r.attempt].iter().enumerate(){put(bytes,32+i*8,*w);}
}
impl Envelope {
    pub(crate) fn decode(bytes:&[u8],ended:bool)->Result<Self,WireError>{
        header(bytes,REQUEST_BYTES,REQUEST_MAGIC,ended)?;read_body(bytes)
    }
    pub(crate) fn encode(self)->Result<[u8;REQUEST_BYTES],WireError>{
        if self.correlation==0 || !valid(self.request){return Err(WireError::Shape)}
        let mut bytes=[0;REQUEST_BYTES];bytes[..8].copy_from_slice(REQUEST_MAGIC);write_body(&mut bytes,self);Ok(bytes)
    }
}
fn valid_outcome(e:Envelope,o:Outcome)->bool {
    e.request.expected.checked_add(1)==Some(o.revision) && o.value==e.request.argument &&
        (e.request.operation==Operation::Select || o.boot!=0)
}
impl Reply {
    pub(crate) fn success(envelope:Envelope,outcome:Outcome)->Result<Self,WireError>{
        if envelope.correlation==0 || !valid(envelope.request) || !valid_outcome(envelope,outcome){return Err(WireError::Outcome)}
        Ok(Self{envelope,status:Status::Success,outcome:Some(outcome)})
    }
    pub(crate) fn failure(envelope:Envelope,status:Status)->Result<Self,WireError>{
        if status==Status::Success || envelope.correlation==0 || !valid(envelope.request){return Err(WireError::Shape)}
        Ok(Self{envelope,status,outcome:None})
    }
    pub(crate) fn encode(self)->[u8;REPLY_BYTES]{
        let mut bytes=[0;REPLY_BYTES];bytes[..8].copy_from_slice(REPLY_MAGIC);write_body(&mut bytes,self.envelope);
        put(&mut bytes,112,self.status as u64);
        if let Some(o)=self.outcome {put(&mut bytes,120,o.revision);put(&mut bytes,128,o.value);put(&mut bytes,136,o.boot);}
        bytes
    }
    pub(crate) fn decode(bytes:&[u8],ended:bool,expected:Envelope)->Result<Self,WireError>{
        header(bytes,REPLY_BYTES,REPLY_MAGIC,ended)?;
        let envelope=read_body(bytes)?;
        if envelope!=expected{return Err(WireError::Binding)}
        let status=Status::decode(get(bytes,112))?;
        let o=Outcome{revision:get(bytes,120),value:get(bytes,128),boot:get(bytes,136)};
        if status==Status::Success {Self::success(envelope,o)} else {
            if (o.revision,o.value,o.boot)!=(0,0,0){return Err(WireError::Outcome)}
            Self::failure(envelope,status)
        }
    }
    pub(crate) fn status(&self)->Status{self.status}
    pub(crate) fn outcome(&self)->Option<Outcome>{self.outcome}
}
