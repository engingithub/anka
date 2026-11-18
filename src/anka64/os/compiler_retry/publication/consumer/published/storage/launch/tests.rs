use super::*;
use authority::*;
use crate::anka64::state::{ProcessKey,DomainId};
/// Fixture evidence is deliberately test-only; no production allow-all provider.
pub(crate) struct Policy {
    pub manifest:Manifest,pub bytes:Vec<u8>,pub challenge:u64,pub valid:bool,
    pub panic_execute:bool,pub advance_clock:bool,pub revoke_on_execute:bool,now:u64,
}
impl Policy {
    pub(crate) fn new(manifest:Manifest,bytes:Vec<u8>,challenge:u64)->Self {
        Self{manifest,bytes,challenge,valid:true,panic_execute:false,advance_clock:false,revoke_on_execute:false,now:100}
    }
}
impl LaunchPolicy for Policy {
    fn now(&mut self)->Option<u64>{Some(self.now)}
    fn validate_image(&mut self,s:LaunchScope,e:StoredEnvelope<'_>)->Verdict {
        let origin=match s.origin {
            ReadOrigin::File(f)=>f.manifest==self.manifest && f.caller==(Caller{owner:30,incarnation:4})
                && f.action==crate::anka64::authority_persistence::artifact::Action::Read && f.boot!=0 && f.ticket!=0,
            ReadOrigin::Guest{binding,request}=>binding.connection!=0 && request.manifest==self.manifest,
        };
        if self.valid && origin && s.manifest==self.manifest && e.manifest()==self.manifest
            && self.bytes.get(176..)==Some(e.image()) && e.dependency_count()==1
            && e.dependency(0).map(|d|(d.anchor,d.installation,d.artifact,d.generation,d.provenance))==Some((10,20,800,2,804)) {
            Verdict::Valid
        }else{Verdict::Invalid}
    }
    fn execute(&mut self,s:LaunchScope,now:u64)->Option<ExecuteEvidence> {
        if self.panic_execute {panic!("injected stored launch provider unwind")}
        if !self.valid {return None}
        if self.advance_clock {self.now+=1;}
        if self.revoke_on_execute {self.valid=false;}
        Some(evidence(s,self.challenge,now))
    }
}
fn evidence(s:LaunchScope,challenge:u64,now:u64)->ExecuteEvidence {
    ExecuteEvidence {
        context:Context{anchor:s.manifest.anchor,installation:s.manifest.installation,epoch:3,challenge,now,selected:true},
        identity:Identity{issuer:10,subject:30,kind:1,audience:20,epoch:3,challenge,first:90,until:110,
            authentic:Verdict::Valid,possession:Verdict::Valid,status:Verdict::Valid},
        enrollment:Enrollment{anchor:10,installation:20,enrolled:true},
        grant:Grant{issuer:10,subject:30,kind:1,installation:20,epoch:3,purpose:3,
            resource:s.manifest.artifact,generation:s.manifest.generation,resource_kind:3,
            offset:0,length:0,rights:0,first:90,until:110,authentic:Verdict::Valid,status:Verdict::Valid},
        owner:s.owner,boot:s.id.boot,owner_binding:Verdict::Valid,
    }
}
fn fixture()->(LaunchScope,LaunchState,ExecuteEvidence) {
    let manifest=Manifest{anchor:10,installation:20,artifact:900,generation:3,role:2,profile:1,
        size:256,image:901,metadata:902,dependencies:903,provenance:904};
    let state=LaunchState{boot:9,high:1,revision:0,challenge:0,active:false,last:None};
    let s=LaunchScope{id:LaunchId{boot:9,serial:1},owner:AllocationOwner{
        process:ProcessKey{slot:0,generation:0},context:11,domain:DomainId(1)},manifest,
        origin:ReadOrigin::File(Scope{manifest,caller:Caller{owner:30,incarnation:4},boot:2,ticket:8,
            action:crate::anka64::authority_persistence::artifact::Action::Read}),expected_revision:0};
    (s,state,evidence(s,7,100))
}
#[test]
fn sr110_live_t1_exact_execute_allows_actual_zero_incarnation() {
    let(s,state,e)=fixture();assert!(allowed(s,&state,e,100));
}
#[test]
fn sr110_live_t1_each_identity_and_grant_binding_denies() {
    let(s,state,e)=fixture();
    let mutations:&[fn(&mut ExecuteEvidence)]=&[
        |e|e.context.selected=false,|e|e.context.anchor+=1,|e|e.context.installation+=1,
        |e|e.context.epoch+=1,|e|e.context.challenge=0,|e|e.context.now-=1,
        |e|e.identity.issuer+=1,|e|e.identity.subject=0,|e|e.identity.kind=4,|e|e.identity.audience+=1,
        |e|e.identity.epoch+=1,|e|e.identity.challenge+=1,|e|e.identity.first=101,|e|e.identity.until=100,
        |e|e.identity.authentic=Verdict::Unknown,|e|e.identity.possession=Verdict::Invalid,|e|e.identity.status=Verdict::Unknown,
        |e|e.enrollment.enrolled=false,|e|e.enrollment.anchor+=1,|e|e.enrollment.installation+=1,
        |e|e.grant.issuer+=1,|e|e.grant.subject+=1,|e|e.grant.kind+=1,|e|e.grant.installation+=1,
        |e|e.grant.epoch+=1,|e|e.grant.purpose=1,|e|e.grant.resource+=1,|e|e.grant.generation+=1,
        |e|e.grant.resource_kind=1,|e|e.grant.offset=1,|e|e.grant.length=1,|e|e.grant.rights=4,
        |e|e.grant.first=101,|e|e.grant.until=100,|e|e.grant.authentic=Verdict::Unknown,|e|e.grant.status=Verdict::Invalid,
        |e|e.owner.process.generation+=1,|e|e.owner.context+=1,|e|e.owner.domain=DomainId(2),
        |e|e.boot+=1,|e|e.owner_binding=Verdict::Unknown,
    ];
    for (index,mutate) in mutations.iter().enumerate(){let mut bad=e;mutate(&mut bad);assert!(!allowed(s,&state,bad,100),"mutation {index}");}
}
#[test]
fn sr110_live_t1_replay_revision_and_identity_exhaustion_deny() {
    let(s,mut state,e)=fixture();state.challenge=7;assert!(!allowed(s,&state,e,100));
    state.challenge=0;state.active=true;assert!(!allowed(s,&state,e,100));
    state.active=false;state.revision=1;assert!(!allowed(s,&state,e,100));
    let mut s=s;s.expected_revision=u64::MAX;state.revision=u64::MAX;assert!(!allowed(s,&state,e,100));
    state.revision=0;s.expected_revision=0;state.high+=1;assert!(!allowed(s,&state,e,100));
}
#[test]
fn sr110_live_t1_old_boot_and_stale_clock_deny() {
    let(s,mut state,e)=fixture();assert!(!allowed(s,&state,e,101));state.boot+=1;assert!(!allowed(s,&state,e,100));
}
