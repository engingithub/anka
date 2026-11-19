//! Explicit bounded fixture authority. Never used by production integration.
use super::*;
use crate::anka64::authority_persistence::artifact::transfer::read::ReadRequest;
use super::super::launch::tests::Policy as ExecutePolicy;
use std::collections::BTreeMap;
pub(crate) struct Policy {
    pub bootstrap_manifest:Manifest,pub bootstrap_bytes:Arc<Vec<u8>>,pub manifest:Manifest,pub bytes:Arc<Vec<u8>>,
    pub attempt:u64,pub consumed:u64,pub current:Option<BootIdentity>,pub service:u64,
    pub valid:bool,pub read_valid:bool,pub bootstrap_valid:bool,pub challenge:u64,
    pub inspections:usize,pub read_calls:usize,pub boot_fault:u8,pub panic_bootstrap:bool,pub revoke_execute:bool,
    bindings:BTreeMap<u64,(Binding,ReadRequest)>,execute:ExecutePolicy,
}
impl Policy {
    pub(crate) fn new(bootstrap_manifest:Manifest,bootstrap_bytes:Arc<Vec<u8>>,manifest:Manifest,bytes:Arc<Vec<u8>>)->Self{
        Self{bootstrap_manifest,bootstrap_bytes,manifest,execute:ExecutePolicy::new(manifest,(*bytes).clone(),80),bytes,
            attempt:72,consumed:0,current:None,service:301,valid:true,read_valid:true,bootstrap_valid:true,challenge:80,
            inspections:0,read_calls:0,boot_fault:0,panic_bootstrap:false,revoke_execute:false,bindings:BTreeMap::new()}
    }
    fn exact(e:StoredEnvelope<'_>,m:Manifest,b:&[u8])->bool{
        e.manifest()==m && b.get(176..)==Some(e.image()) && e.dependency_count()==1
            && e.dependency(0).map(|d|(d.anchor,d.installation,d.artifact,d.generation,d.provenance))==Some((10,20,800,2,804))
    }
}
impl RestartEvidence for Policy {
    fn reservation(&mut self,r:Request)->Option<(ap::Context,ap::Access)>{
        Some((ap::Context{anchor:10,installation:20,policy:3,challenge:self.attempt,now:100,selected:true},
            ap::Access{anchor:10,installation:20,policy:3,caller:30,incarnation:4,operation:r.operation,
                first:90,until:110,authentic:Verdict::Valid,status:if self.valid{Verdict::Valid}else{Verdict::Invalid}}))
    }
    fn boot(&mut self,r:Request,h:&State,realm:u64)->Option<BootAuthorization>{
        if !self.valid || r.attempt!=self.attempt || self.attempt<=self.consumed{return None}
        let(c,a)=self.reservation(r)?;
        let mut e=BootAuthorization{context:c,access:a,enrollment:ap::Enrollment{anchor:10,installation:20,person:30,revision:1,enrolled:true},
            evidence:BootEvidence{head:h.revision,boot:h.boot,freshness:Verdict::Valid,artifact:Verdict::Valid},realm,selected:h.value};
        match self.boot_fault{1=>e.realm+=1,2=>e.selected+=1,3=>e.evidence.head+=1,4=>e.evidence.boot+=1,
            5=>e.context.challenge+=1,6=>e.context.policy+=1,7=>e.context.anchor+=1,8=>e.context.installation+=1,
            9=>e.evidence.freshness=Verdict::Unknown,10=>e.evidence.artifact=Verdict::Invalid,
            11=>e.enrollment.enrolled=false,12=>e.access.until=100,_=>{}}Some(e)
    }
    fn bootstrap_access(&mut self,s:Scope)->Verdict{
        if self.valid && self.bootstrap_valid && s.manifest==self.bootstrap_manifest && s.caller==(Caller{owner:30,incarnation:4})
            && s.action==ap::artifact::Action::Read && s.boot!=0 && s.ticket!=0 {Verdict::Valid}else{Verdict::Invalid}
    }
    fn inspect_bootstrap(&mut self,r:&mut dyn Read)->Result<Manifest,ap::Error>{
        self.inspections+=1;let mut b=[0u8;4096];
        for expected in self.bootstrap_bytes.chunks(4096){r.read_exact(&mut b[..expected.len()]).map_err(|_|ap::Error::CorruptRecord)?;
            if &b[..expected.len()]!=expected{return Err(ap::Error::CorruptRecord)}}
        if r.read(&mut b[..1]).map_err(|_|ap::Error::CorruptRecord)?!=0{return Err(ap::Error::CorruptRecord)}Ok(self.bootstrap_manifest)
    }
    fn bootstrap(&mut self,id:BootIdentity,e:StoredEnvelope<'_>)->Verdict{
        if self.panic_bootstrap{panic!("injected RR110 bootstrap validator unwind")}
        if self.valid && self.bootstrap_valid && id.selected==self.bootstrap_manifest.artifact
            && Self::exact(e,self.bootstrap_manifest,&self.bootstrap_bytes){Verdict::Valid}else{Verdict::Invalid}
    }
    fn consume_boot(&mut self,id:BootIdentity)->Verdict{
        if !self.valid || id.attempt!=self.attempt || self.attempt<=self.consumed{return Verdict::Invalid}
        self.consumed=self.attempt;self.current=Some(id);Verdict::Valid
    }
    fn current_boot(&mut self,id:BootIdentity)->Verdict{
        if self.valid && self.current==Some(id) && id.attempt==self.attempt{Verdict::Valid}else{Verdict::Invalid}
    }
    fn service(&mut self,id:BootIdentity)->Option<u64>{
        if self.current_boot(id)==Verdict::Valid{Some(self.service)}else{None}
    }
    fn read(&mut self,id:BootIdentity,service:u64,b:Binding,r:ReadRequest)->Verdict{
        self.read_calls+=1;
        if self.current_boot(id)!=Verdict::Valid || !self.read_valid || service!=self.service || b.connection==0
            || r.manifest!=self.manifest || self.bindings.len()>128{return Verdict::Invalid}
        if *self.bindings.entry(b.connection).or_insert((b,r))!=(b,r){Verdict::Invalid}else{Verdict::Valid}
    }
    fn reply(&mut self,id:BootIdentity,service:u64,b:Binding,r:ReadRequest,bytes:&[u8])->Verdict{
        let expected=r.offset.checked_add(r.count).and_then(|end|self.bytes.get(r.offset as usize..end as usize));
        if bytes.get(200..)==expected && self.read(id,service,b,r)==Verdict::Valid{Verdict::Valid}else{Verdict::Invalid}
    }
    fn downloaded(&mut self,id:BootIdentity,service:u64,e:StoredEnvelope<'_>)->Verdict{
        if self.current_boot(id)==Verdict::Valid && self.read_valid && service==self.service
            && Self::exact(e,self.manifest,&self.bytes){Verdict::Valid}else{Verdict::Invalid}
    }
    fn now(&mut self)->Option<u64>{Some(100)}
    fn execute(&mut self,id:BootIdentity,s:LaunchScope,now:u64)->Option<ExecuteEvidence>{
        if self.current_boot(id)!=Verdict::Valid || s.id.boot!=id.realm{return None}
        self.execute.challenge=self.challenge;
        let e=self.execute.execute(s,now);
        if self.revoke_execute{self.read_valid=false;}e
    }
}
pub(crate) struct Memory {pub state:State,pub loads:usize,pub commits:usize,pub uncertain:bool}
impl DurableRecord for Memory {
    fn load(&mut self,a:u64,i:u64)->Result<State,ap::Error>{assert_eq!((a,i),(10,20));self.loads+=1;Ok(self.state.clone())}
    fn commit(&mut self,a:u64,i:u64,b:&State,t:&State)->Result<(),ap::Error>{
        assert_eq!((a,i),(10,20));if b!=&self.state{return Err(ap::Error::Conflict)}self.state=t.clone();self.commits+=1;
        if self.uncertain{self.uncertain=false;Err(ap::Error::CommitUncertain)}else{Ok(())}
    }
}
pub(crate) fn initial(value:u64)->Memory{Memory{state:State{revision:7,value,boot:0,last:None},loads:0,commits:0,uncertain:false}}
pub(crate) fn request(h:&State,attempt:u64)->Request{Request{anchor:10,installation:20,policy:3,caller:30,incarnation:4,
    sequence:h.last.map_or(1,|r|r.sequence+1),expected:h.revision,operation:ap::Operation::ReserveBoot,argument:h.value,attempt}}
fn evidence(r:Request)->(ap::Context,ap::Access){
    (ap::Context{anchor:10,installation:20,policy:3,challenge:r.attempt,now:100,selected:true},
    ap::Access{anchor:10,installation:20,policy:3,caller:30,incarnation:4,operation:ap::Operation::ReserveBoot,
        first:90,until:110,authentic:Verdict::Valid,status:Verdict::Valid})
}
#[test]
fn rr110_reservation_lost_reply_recovers_one_boot_and_preserves_selection(){
    let mut m=initial(55);m.uncertain=true;let r=request(&m.state,72);let(c,a)=evidence(r);
    assert_eq!(ap::reserve_restart_boot(&mut m,c,r,a),Err(ap::Error::CommitUncertain));
    let result=ap::reserve_restart_boot(&mut m,c,r,a).unwrap();assert_eq!((result.value,result.boot,result.revision),(55,1,8));
    assert_eq!(m.commits,1);
}
#[test]
fn rr110_reservation_new_sequence_cannot_reuse_challenge(){
    let mut m=initial(55);let r=request(&m.state,72);let(c,a)=evidence(r);ap::reserve_restart_boot(&mut m,c,r,a).unwrap();
    let r2=request(&m.state,72);assert!(ap::reserve_restart_boot(&mut m,c,r2,a).is_err());assert_eq!(m.commits,1);
    let r3=request(&m.state,73);let(c,a)=evidence(r3);assert_eq!(ap::reserve_restart_boot(&mut m,c,r3,a).unwrap().boot,2);
}
#[test]
fn rr110_reservation_default_revoked_expired_and_foreign_deny_before_store(){
    for n in 0..8{let mut m=initial(55);let mut r=request(&m.state,72);let(mut c,mut a)=evidence(r);
        match n{0=>a.authentic=Verdict::Unknown,1=>a.status=Verdict::Invalid,2=>a.until=100,3=>r.installation=21,
            4=>c.challenge=0,5=>c.challenge=73,6=>r.operation=ap::Operation::Select,_=>r.caller=31}
        assert!(ap::reserve_restart_boot(&mut m,c,r,a).is_err());assert_eq!((m.loads,m.commits),(0,0));}
}
#[test]
fn rr110_reservation_exhaustion_never_wraps(){
    for field in 0..3{let mut m=initial(55);let mut r=request(&m.state,72);
        match field{0=>{m.state.revision=u64::MAX;r.expected=u64::MAX},1=>m.state.boot=u64::MAX,
            _=>{let mut old=r;old.sequence=u64::MAX;old.attempt=71;m.state.last=Some(old);r.sequence=0}}
        let before=m.state.clone();let(c,a)=evidence(r);assert!(ap::reserve_restart_boot(&mut m,c,r,a).is_err());
        assert_eq!(m.state,before);assert_eq!(m.commits,0);}
}
fn session_fixture()->(Authority<Policy>,Binding,ReadRequest){
    let m=Manifest{anchor:10,installation:20,artifact:900,generation:3,role:2,profile:1,size:256,image:901,metadata:902,dependencies:903,provenance:904};
    let bytes=Arc::new(vec![0;256]);let mut p=Policy::new(m,bytes.clone(),m,bytes);
    let id=BootIdentity{anchor:10,installation:20,policy:3,head:8,selected:1900,boot:1,attempt:72,realm:100};
    p.current=Some(id);p.consumed=72;
    let mut a=Authority::new(p);a.active=Some(id);a.session=Some(Session{boot:id,service:301,manifest:m});
    let b=Binding{connection:10,local:"127.0.0.1:1010".parse().unwrap(),remote:"127.0.0.1:2020".parse().unwrap()};
    let r=ReadRequest{manifest:m,correlation:1,offset:0,count:64};(a,b,r)
}
#[test]
fn rr110_session_rejects_old_service_boot_and_recycled_local_channel(){
    let(mut a,b,r)=session_fixture();assert_eq!(a.verify_read(b,r),Verdict::Valid);
    a.update(|p|p.service=302);assert_eq!(a.verify_read(b,r),Verdict::Invalid);
    a.session.as_mut().unwrap().service=302;a.bound=None;
    assert_eq!(a.verify_read(b,r),Verdict::Invalid); // old local channel cannot become new
    let new=Binding{connection:11,..b};assert_eq!(a.verify_read(new,r),Verdict::Valid);
    a.update(|p|p.attempt=73);assert_eq!(a.verify_read(new,r),Verdict::Invalid);
    assert_eq!(a.connection_high,11);
}
#[test]
fn rr110_session_pins_channel_request_owner_boot_and_manifest(){
    for mutation in 0..5{let(mut a,b,r)=session_fixture();assert_eq!(a.verify_read(b,r),Verdict::Valid);let mut q=r;
        match mutation{0=>q.correlation+=1,1=>q.offset+=1,2=>q.manifest.artifact+=1,
            3=>a.session.as_mut().unwrap().boot.realm+=1,_=>a.session.as_mut().unwrap().boot.boot+=1}
        assert_eq!(a.verify_read(b,q),Verdict::Invalid);}
}
#[test]
fn rr110_default_evidence_cannot_reserve_or_authenticate_session(){
    struct Deny;impl RestartEvidence for Deny{}
    let mut a=Authority::new(Deny);let mut m=initial(55);let r=request(&m.state,72);
    assert!(a.reserve(&mut m,r).is_err());assert_eq!(m.loads,0);
    let(_,b,q)=session_fixture();assert_eq!(a.verify_read(b,q),Verdict::Invalid);
}
