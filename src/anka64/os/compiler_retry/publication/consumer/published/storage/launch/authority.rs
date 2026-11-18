//! Execute-only refinement of a109_recognize/a109_grant_allowed. These records
//! are trusted verifier outputs, never parsed from guest fields. Purpose 3 and
//! artifact kind 3 are semantic T1 labels, NOT Fabric permission masks.
use super::*;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct Context {
    pub anchor:u64,pub installation:u64,pub epoch:u64,pub challenge:u64,pub now:u64,pub selected:bool,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct Identity {
    pub issuer:u64,pub subject:u64,pub kind:u64,pub audience:u64,pub epoch:u64,pub challenge:u64,
    pub first:u64,pub until:u64,pub authentic:Verdict,pub possession:Verdict,pub status:Verdict,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct Enrollment {pub anchor:u64,pub installation:u64,pub enrolled:bool}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct Grant {
    pub issuer:u64,pub subject:u64,pub kind:u64,pub installation:u64,pub epoch:u64,
    pub purpose:u64,pub resource:u64,pub generation:u64,pub resource_kind:u64,
    pub offset:u64,pub length:u64,pub rights:u8,pub first:u64,pub until:u64,
    pub authentic:Verdict,pub status:Verdict,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct ExecuteEvidence {
    pub context:Context,pub identity:Identity,pub enrollment:Enrollment,pub grant:Grant,
    /// Independently verified principal -> actual live Kernel custodian binding.
    /// Neither a storage Caller number nor a process slot is an identity proof.
    pub owner:AllocationOwner,pub boot:u64,pub owner_binding:Verdict,
}
fn window(now:u64,first:u64,until:u64)->bool {first<until && first<=now && now<until}
pub(super) fn allowed(scope:LaunchScope,state:&LaunchState,e:ExecuteEvidence,now:u64)->bool {
    let c=e.context;let i=e.identity;let g=e.grant;let n=e.enrollment;let m=scope.manifest;
    c.selected && c.anchor!=0 && c.installation!=0 && c.epoch!=0 && c.challenge!=0
        && c.anchor==m.anchor && c.installation==m.installation && c.now==now
        && e.owner==scope.owner && e.boot==scope.id.boot && e.owner_binding==Verdict::Valid
        && i.subject!=0 && matches!(i.kind,1|2|3)
        && i.issuer==c.anchor && i.audience==c.installation && i.epoch==c.epoch && i.challenge==c.challenge
        && window(now,i.first,i.until) && i.authentic==Verdict::Valid
        && i.possession==Verdict::Valid && i.status==Verdict::Valid
        && n.enrolled && n.anchor==c.anchor && n.installation==c.installation
        && g.issuer==c.anchor && g.subject==i.subject && g.kind==i.kind
        && g.installation==c.installation && g.epoch==c.epoch
        && window(now,g.first,g.until) && g.authentic==Verdict::Valid && g.status==Verdict::Valid
        && g.purpose==3 && g.resource_kind==3 && g.resource==m.artifact && g.generation==m.generation
        && m.artifact!=0 && m.generation!=0 && g.offset==0 && g.length==0 && g.rights==0
        && scope.id.boot!=0 && scope.id.boot==state.boot && scope.id.serial==state.high
        && !state.active && scope.expected_revision==state.revision && state.revision<u64::MAX
        && c.challenge>state.challenge
}
