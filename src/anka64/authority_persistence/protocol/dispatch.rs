use super::*;
/// Trusted service extension point, never caller-supplied wire evidence. Implementors
/// bind Peer to actual possession/connection identity and obtain CURRENT context.
/// The host must serialize policy observation and commit in one authority lane.
/// The default denies. No loopback-address or claimed-caller allow-all fallback.
pub(crate) trait Verifier {
    type Peer;
    fn verify(&mut self,_peer:&Self::Peer,_request:Request)->Option<(Context,Access)>{None}
}
pub(crate) struct DenyAll;
impl Verifier for DenyAll {type Peer=();}
/// Pre-acquire snapshot of an OWNED service reservation plus current time/work.
/// Codec/dispatcher do not allocate sockets or implement the reservation owner.
/// The future transport must reserve once, retain ownership and refund once.
/// This struct must never be populated from request bytes.
#[derive(Clone,Copy,Debug)]
pub(crate) struct DispatchBudget {
    pub slots:u64,pub slot_limit:u64,pub bytes:u64,pub byte_limit:u64,
    pub work:u64,pub now:u64,pub deadline:u64,
}
impl DispatchBudget {
    pub(crate) fn admissible(self)->bool {
        self.slot_limit>0 && self.slot_limit<=64 && self.slots<self.slot_limit &&
        self.byte_limit.checked_sub(self.bytes).is_some_and(|n|n>=384) &&
        self.work>0 && self.work<=512 && self.now<self.deadline
    }
}
pub(super) fn checked<V:Verifier>(v:&mut V,peer:&V::Peer,r:Request)->Option<(Context,Access)> {
    let (c,a)=v.verify(peer,r)?;
    if authorized(c,r,a){Some((c,a))}else{None}
}
fn status(e:Error)->Status {match e {
    Error::Authority|Error::BootDenied=>Status::Denied,
    Error::Conflict|Error::ExpiredRequest=>Status::Conflict,
    Error::Capacity|Error::Exhausted=>Status::Exhausted,
    Error::InvalidRequest=>Status::Invalid,
    Error::CommitUncertain=>Status::Uncertain,
    Error::BackendUnavailable|Error::BackendBusy|Error::CorruptRecord=>Status::Unavailable,
}}
/// One complete frame only. Malformed data cannot call the verifier or backend.
/// Dispatch is synchronous; a durable success still requires delivery. An error
/// reply never proves a previous invocation did not commit. No boot admission.
pub(crate) fn dispatch<B:DurableRecord,V:Verifier>(backend:&mut B,verifier:&mut V,peer:&V::Peer,
    bytes:&[u8],ended:bool,budget:DispatchBudget,capacity:bool)->Result<[u8;REPLY_BYTES],WireError>
{
    let e=Envelope::decode(bytes,ended)?;
    if !budget.admissible(){return Ok(Reply::failure(e,Status::Exhausted)?.encode())}
    let Some((c,a))=checked(verifier,peer,e.request) else {return Ok(Reply::failure(e,Status::Denied)?.encode())};
    let result=transact(backend,c,e.request,a,capacity);
    // Revalidate before releasing an outcome or backend diagnostic. Revocation
    // after commit suppresses disclosure; it MUST NOT roll back persisted state.
    if checked(verifier,peer,e.request).is_none(){return Ok(Reply::failure(e,Status::Denied)?.encode())}
    match result {
        Ok(o)=>match Reply::success(e,o) {
            Ok(r)=>Ok(r.encode()),
            // A faulty backend result is not safely a definite abort.
            Err(_)=>Ok(Reply::failure(e,Status::Uncertain)?.encode()),
        },
        Err(e2)=>Ok(Reply::failure(e,status(e2))?.encode()),
    }
}
/// Trusted client observations, not fields in an incoming frame. Real peer
/// authentication and connection-incarnation tracking are transport obligations.
pub(crate) struct ClientEvidence {pub server:Verdict,pub pending_current:bool}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum ClientResult { Success(Outcome),Rejected(Status),Unknown }
/// Invalid, incomplete, foreign or unbound replies remain unknown outcomes.
/// Rejected refers to this dispatch, not the absence of an earlier durable effect.
pub(crate) fn accept_reply(bytes:&[u8],ended:bool,expected:Envelope,evidence:ClientEvidence)->ClientResult {
    if evidence.server!=Verdict::Valid || !evidence.pending_current{return ClientResult::Unknown}
    let Ok(r)=Reply::decode(bytes,ended,expected) else{return ClientResult::Unknown};
    match r.status() {
        Status::Success=>r.outcome().map_or(ClientResult::Unknown,ClientResult::Success),
        Status::Uncertain=>ClientResult::Unknown,
        s=>ClientResult::Rejected(s),
    }
}
