//! Phase 10.10 reference transition core for the Phase 10.9 T2 model.
//!
//! Not wired into Kernel boot, sockets, or grant admission. Context/Access and
//! BootEvidence must come from trusted validators; this module verifies their
//! bindings, not cryptography. Value is an opaque persistent envelope identity,
//! never a Fabric ObjectId or proof of artifact validity. One store instance is
//! scoped to one installation; the backend must reject cross-instance access.
//!
//! Backend atomic commit is a REQUIRED refinement boundary. The included test
//! backend models durable state/faults. The optional host-local file backend
//! implements the contract under explicit Linux/macOS filesystem assumptions.
//! One retained successful outcome is bounded storage: older requests expire and
//! cannot execute again. Exhausted counters fail closed; they never reset.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict { Unknown, Invalid, Valid }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation { Select, ReserveBoot }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Context {
    pub anchor: u64, pub installation: u64, pub policy: u64,
    pub challenge: u64, pub now: u64, pub selected: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Access {
    pub anchor: u64, pub installation: u64, pub policy: u64,
    pub caller: u64, pub incarnation: u64, pub operation: Operation,
    pub first: u64, pub until: u64, pub authentic: Verdict, pub status: Verdict,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub anchor: u64, pub installation: u64, pub policy: u64,
    pub caller: u64, pub incarnation: u64, pub sequence: u64,
    pub expected: u64, pub operation: Operation, pub argument: u64, pub attempt: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct State {
    pub revision: u64, pub value: u64, pub boot: u64,
    // Immutable namespace binding belongs to the backend envelope. The latest
    // request is persisted with the result, including policy and caller identity.
    pub last: Option<Request>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Outcome { pub revision: u64, pub value: u64, pub boot: u64 }
impl State {
    fn outcome(&self) -> Outcome { Outcome { revision:self.revision,value:self.value,boot:self.boot } }
    fn sequence(&self) -> u64 { self.last.map_or(0, |r| r.sequence) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Authority, Conflict, ExpiredRequest, Capacity, Exhausted, InvalidRequest,
    BackendUnavailable, BackendBusy, CorruptRecord, CommitUncertain, BootDenied,
}

/// Implementations must bind the durable record to anchor+installation, serialize
/// compare-and-commit against all writers, and atomically persist the whole State.
/// Ok means recoverable durability, not just visibility. An uncertain error may
/// have committed; the caller must reload, not rollback or blindly issue a new ID.
pub(crate) trait DurableRecord {
    fn load(&mut self, anchor:u64, installation:u64) -> Result<State,Error>;
    fn commit(&mut self, anchor:u64, installation:u64, before:&State, after:&State) -> Result<(),Error>;
}

fn authorized(c:Context,r:Request,a:Access) -> bool {
    c.selected && c.anchor!=0 && c.installation!=0
        && r.anchor==c.anchor && r.installation==c.installation && r.policy==c.policy
        && a.anchor==r.anchor && a.installation==r.installation && a.policy==r.policy
        && r.caller!=0 && r.incarnation!=0
        && a.caller==r.caller && a.incarnation==r.incarnation && a.operation==r.operation
        && a.authentic==Verdict::Valid && a.status==Verdict::Valid
        && a.first<a.until && a.first<=c.now && c.now<a.until
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Decision { Replay(Outcome), Commit(State) }
fn prepare(c:Context,s:&State,r:Request,a:Access,capacity:bool) -> Result<Decision,Error> {
    if !authorized(c,r,a) {return Err(Error::Authority)}
    if s.last==Some(r) && r.sequence!=0 {return Ok(Decision::Replay(s.outcome()))}
    if r.sequence<s.sequence() {return Err(Error::ExpiredRequest)}
    if r.sequence==s.sequence() {return Err(Error::Conflict)}
    let sequence=s.sequence().checked_add(1).ok_or(Error::Exhausted)?;
    let revision=s.revision.checked_add(1).ok_or(Error::Exhausted)?;
    if r.sequence!=sequence || r.expected!=s.revision {return Err(Error::Conflict)}
    if !capacity {return Err(Error::Capacity)}
    if r.argument==0 {return Err(Error::InvalidRequest)}
    let (value,boot)=match r.operation {
        Operation::Select if r.attempt==0 => (r.argument,s.boot),
        Operation::ReserveBoot if r.attempt!=0 && r.argument==s.value =>
            (s.value,s.boot.checked_add(1).ok_or(Error::Exhausted)?),
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Decision::Commit(State {revision,value,boot,last:Some(r)}))
}

/// Each invocation obtains current trusted evidence and reloads durable state.
/// A result says committed/recovered; a missing response never means rollback.
/// The caller must keep validation and commit in one authority-serialized lane.
pub(crate) fn transact<B:DurableRecord>(b:&mut B,c:Context,r:Request,a:Access,capacity:bool)
    -> Result<Outcome,Error>
{
    // Reject unauthorized requests before accessing the store at all.
    if !authorized(c,r,a) {return Err(Error::Authority)}
    let before=b.load(c.anchor,c.installation)?;
    match prepare(c,&before,r,a,capacity)? {
        Decision::Replay(o)=>Ok(o),
        Decision::Commit(after)=>{
            b.commit(c.anchor,c.installation,&before,&after)?;
            Ok(after.outcome())
        }
    }
}

#[derive(Clone,Copy,Debug)]
pub(crate) struct Enrollment {
    pub anchor:u64,pub installation:u64,pub person:u64,pub revision:u64,pub enrolled:bool,
}
#[derive(Clone,Copy,Debug)]
pub(crate) struct BootEvidence {
    pub head:u64,pub boot:u64,pub freshness:Verdict,pub artifact:Verdict,
}
/// Volatile execution latch. A crash drops it. A replacement latch alone cannot
/// justify boot: the trusted challenge must change across restart/snapshot restore.
#[derive(Default)]
pub(crate) struct BootLatch { active:Option<u64> }
impl BootLatch {
    pub(crate) fn admit(&mut self,c:Context,s:&State,r:Request,a:Access,e:Enrollment,f:BootEvidence)
        -> Result<u64,Error>
    {
        if self.active.is_some() || !authorized(c,r,a) || s.last!=Some(r) || r.sequence==0
            || r.operation!=Operation::ReserveBoot
            || !e.enrolled || e.revision==0 || e.person==0 || e.anchor!=c.anchor || e.installation!=c.installation
            || s.revision!=f.head || s.boot!=f.boot || f.boot==0
            || c.challenge==0 || r.attempt!=c.challenge || s.value!=r.argument || s.value==0
            || f.freshness!=Verdict::Valid || f.artifact!=Verdict::Valid {
            return Err(Error::BootDenied)
        }
        self.active=Some(s.boot);
        Ok(s.boot)
    }
    pub(crate) fn accepts_saved_context(&self,boot:u64)->bool {
        boot!=0 && self.active==Some(boot)
    }
}

#[cfg(test)]
#[path="authority_persistence/tests.rs"]
mod tests;

#[cfg(any(target_os="linux", target_os="macos"))]
#[path="authority_persistence/file_backend.rs"]
pub(crate) mod file_backend;

#[path="authority_persistence/protocol.rs"]
pub(crate) mod protocol;

/// Technology-neutral trusted evidence admission (E1/E2); no credential parser.
#[path="authority_persistence/evidence.rs"]
pub(crate) mod evidence;
