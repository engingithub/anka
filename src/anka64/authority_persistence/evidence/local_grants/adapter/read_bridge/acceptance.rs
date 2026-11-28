//! LK110 disposable-lab acceptance embedding. Compiled only with cfg(test).
//! No synthetic Completion/PreparedUse/identity verdicts: ordinary-client LA110
//! workers verify real tokens and signatures. Administrative fault injection is
//! a separate parent test driver. This is not a deployment credential loader.
use super::*;
use crate::anka64::authority_persistence::{protocol::client::{Binding,ServerVerifier},
    artifact::retrieval::StoredEnvelope};
use std::{path::Path, process::Command, sync::Arc};

pub(crate) const CASES: [&str; 10] = ["positive", "outage_fresh", "outage_stale",
    "inactive", "grant_expiry", "token_expiry", "changed_input", "suffix_revoked",
    "final_revoked", "content_denied"];

/// Fixed vocabulary over the test process's private parent-owned pipes. Never
/// print token/claims/worker output. A parent timeout bounds the complete suite.
pub(crate) fn event(name: &str) {
    assert!(CASES.contains(&name) || matches!(name,"issued"|"fault"|"restore"));
    println!("LK110 EVENT {name}");std::io::stdout().flush().unwrap();
    let mut answer=String::new();std::io::stdin().take(16).read_line_bounded(&mut answer);
    assert_eq!(answer,"continue\n","LK110 parent protocol failed");
}
// Read a bounded line without waiting for EOF on the still-owned input pipe.
trait Line { fn read_line_bounded(&mut self,out:&mut String); }
impl<R:Read> Line for R {
    fn read_line_bounded(&mut self,out:&mut String) {
        for _ in 0..16 {let mut b=[0];if self.read(&mut b).unwrap()!=1{break}
            out.push(b[0] as char);if b[0]==b'\n'{break}}
    }
}
fn wall()->u64 {std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()}
fn profile(root:&Path)->Profile {
    // Only the disposable harness provisions these explicit local mappings.
    // The returned profile is input, never evidence; Adapter::refresh must verify it.
    let helper=Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/keycloak/bridge_acceptance.py");
    let mut cmd=Command::new("python3");cmd.arg("-I").arg(helper).arg("profile").arg("--state").arg(root);
    let raw=process::capture(cmd,&[],24576,Instant::now()+Duration::from_secs(10)).expect("LK110 private profile");
    assert_eq!(&raw[..8],b"LK110P1\0");let holder=raw[8..40].try_into().unwrap();let mut at=40;
    let mut blob=||{let n=u32::from_le_bytes(raw[at..at+4].try_into().unwrap())as usize;at+=4;
        assert!(n>0 && at+n<=raw.len());let v=raw[at..at+n].to_vec();at+=n;v};
    let token=blob();let issuer=String::from_utf8(blob()).unwrap();let audience=String::from_utf8(blob()).unwrap();
    let client=String::from_utf8(blob()).unwrap();let subject=String::from_utf8(blob()).unwrap();
    assert!(raw[at..].iter().all(|b|*b==0));
    Profile{config_path:root.join("config.json"),token,issuer,audience,client,subject,holder,
        subject_id:31,holder_id:32,max_age:5}
}
struct Content { manifest:store::Manifest,caller:store::Caller,bytes:Arc<Vec<u8>>,allow:bool,inspections:u64 }
impl store::Evidence for Content {
    fn authorize(&mut self,s:store::Scope)->ap::Verdict {
        if self.allow && s.manifest==self.manifest && s.caller==self.caller && s.action==store::Action::Read {
            ap::Verdict::Valid
        } else {ap::Verdict::Invalid}
    }
    fn inspect(&mut self,r:&mut dyn Read)->Result<store::Manifest,ap::Error>{
        self.inspections+=1;let mut bytes=vec![0;self.bytes.len()+1];let mut used=0;
        loop{let n=r.read(&mut bytes[used..]).map_err(|_|ap::Error::CorruptRecord)?;
            if n==0{break}used+=n;if used==bytes.len(){return Err(ap::Error::CorruptRecord)}}
        if bytes[..used]!=self.bytes[..]{return Err(ap::Error::CorruptRecord)}Ok(self.manifest)
    }
}
/// Shared directly as the ServerLane. All changes (including local revocation)
/// require &mut self through that same lane; no external Revoker escapes.
/// ServerVerifier callbacks do no introspection or administrative work. Holder
/// crypto runs before the LG110 owner guard; it is deliberately expensive here.
pub(crate) struct Session {
    bridge:ReadBridge<HostClock,HostedTransport>, client:HostedClient,content:Content,
    request:ReadRequest, binding:Option<Binding>,local:std::net::SocketAddr,remote:std::net::SocketAddr,
    case:usize, initial:View, fault_seen:bool, pub(crate) final_seen:bool,
    pub(crate) denied:bool, pub(crate) sent:usize,
}
impl Session {
    pub(crate) fn new(root:&Path,r:ReadRequest,caller:store::Caller,bytes:Arc<Vec<u8>>,
        local:std::net::SocketAddr,remote:std::net::SocketAddr,case:usize)->Self {
        assert!(case<CASES.len());assert_eq!(r.offset,0);assert_eq!(r.count,r.manifest.size);
        let profile=profile(root);let now=wall();
        let scope=Scope{installation:r.manifest.installation,policy:3,peer:caller.owner,kind:1,
            artifact:r.manifest.artifact,generation:r.manifest.generation,request:r.correlation,
            operation:1,role:1,runtime:6,connection:7,binding:8,local:9,incarnation:caller.incarnation,serial:10,challenge:11};
        let config=Config{domain:500,incarnation:caller.incarnation,grant_id:600+case as u64,work:512,deadline:30,boot:1,
            identity:Configuration{issuer:10,audience:21,client:22,installation:scope.installation,policy:3,keyset:4,
                profile:1,max_age:5,max_bytes:16384,selected:Verdict::Valid},scope,
            grant:Grant{token:101,scope,first:now,until:now+if case==4{12}else{120},permission:Verdict::Valid}};
        let mut adapter=Adapter::new(config,profile,HostClock::new()).unwrap();
        assert_eq!(adapter.refresh(),Ok(Refresh::Issued),"LK110 real initial observation");
        let initial=adapter.view().unwrap();
        let registration=Registration{domain:config.domain,grant_id:config.grant_id,request:r,caller,boot:1,ticket:1};
        let(bridge,client)=ReadBridge::hosted(adapter,registration).unwrap();
        client.0.set_nonblocking(false).unwrap();client.0.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.0.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        Self{bridge,client,content:Content{manifest:r.manifest,caller,bytes,allow:true,inspections:0},request:r,
            binding:None,local,remote,case,initial,fault_seen:false,final_seen:false,denied:false,sent:0}
    }
    /// Stage a correlated query under the lane, then release BOTH the lane and
    /// LG110 owner before remote IO. Reacquisition consumes the original query.
    fn refresh_shared(wire:&Arc<Mutex<Self>>)->Result<Refresh,Error>{
        let (q,record,path,deadline,reply_size)={
            let mut s=wire.lock().unwrap();let a=&mut s.bridge.adapter;
            a.sample()?;a.clear()?;let q=a.owner.begin_query()?;
            let record=codec::record(1,a.session,codec::query(q),a.config.scope,a.profile.holder,
                [0;32],a.input_binding,&a.profile);
            a.workers=a.workers.checked_sub(1).ok_or(Error::Exhausted)?;
            let size=record.len()+72;(q,record,a.profile.config_path.clone(),a.worker_deadline,size)
        };
        let reply=codec::request(&record,&[]).and_then(|raw|process::worker(&path,&raw,reply_size,deadline))
            .and_then(|raw|codec::decode(&record,&raw));
        let mut s=wire.lock().unwrap();let result=s.bridge.adapter.complete_refresh(q,reply);s.retained();result
    }
    pub(crate) fn renew(wire:&Arc<Mutex<Self>>){
        assert_eq!(Self::refresh_shared(wire),Ok(Refresh::Refreshed),"LK110 real refresh");
    }
    /// The host reply can require many signed 64-byte writes. Renew the SAME
    /// grant before handing its next frame to the virtual NIC, outside both
    /// authority lanes. Never renew after an intentionally injected fault.
    pub(crate) fn before_delivery(wire:&Arc<Mutex<Self>>){
        let enabled=!wire.lock().unwrap().fault_seen;
        if enabled {Self::renew(wire)}
    }
    fn retained(&self){let v=self.bridge.view().unwrap();
        assert_eq!((v.owner,v.grant_id,v.deadline,v.boot),(self.initial.owner,self.initial.grant_id,self.initial.deadline,self.initial.boot));
        assert!(v.remaining<=self.initial.remaining);assert!(v.next_seq>=self.initial.next_seq);
    }
    fn proof(&mut self)->Result<PreparedUse,BridgeError>{
        // Seconds-clock boundary crossing during expensive crypto is not an
        // authorization. Discard it and spend another bounded preparation.
        // No retries after an effect, no owner or deadline replacement.
        for _ in 0..3 {
            let a=&mut self.bridge.adapter;let challenge=a.prepare(self.bridge.channel)?;
            a.workers=a.workers.checked_sub(1).ok_or(Error::Exhausted)?;
            let sig=process::hosted_holder(&a.profile.config_path,challenge.bytes(),a.worker_deadline)
                .map_err(|_|BridgeError::Authority(Error::Denied))?;
            let p=a.verify_use(self.bridge.channel,challenge,&sig)?;
            if a.sample()?.tick==p.proposal.at_tick{return Ok(p)}
        }
        Err(BridgeError::Authority(Error::Denied))
    }
    pub(crate) fn push(&mut self,bytes:&[u8])->Result<(),String>{
        let target=self.bridge.received+bytes.len();
        self.client.write_all(bytes).map_err(|_|"LK110 send")?;
        // Wait outside the owner guard; each actual read spends another proof.
        while self.bridge.received<target {
            tests::readable(self.bridge.stream.as_ref().ok_or("LK110 closed")?);
            let p=self.proof().map_err(|_|"LK110 possession")?;
            self.bridge.intake(p).map_err(|_|"LK110 intake")?;
        }Ok(())
    }
    pub(crate) fn finish(&mut self,backend:&mut store::ArtifactStore)->Result<Vec<u8>,String>{
        self.client.finish_request().map_err(|_|"LK110 FIN")?;
        for _ in 0..8 {
            tests::readable(self.bridge.stream.as_ref().ok_or("LK110 closed")?);
            let p=self.proof().map_err(|_|"LK110 possession")?;
            if self.bridge.intake(p).map_err(|_|"LK110 EOF")?{break}
        }
        let frame=read::encode_read(self.request).unwrap();let mut budget=transfer::Budget::new(128,10000,32768).unwrap();
        let p=self.proof().map_err(|_|"LK110 dispatch proof")?;
        let mut reply=self.bridge.dispatch(p,backend,&frame,true,&mut budget,&mut self.content).map_err(|_|"LK110 dispatch")?;
        assert_eq!(self.content.inspections,1);
        for _ in 0..80{
            let p=self.proof().map_err(|_|"LK110 write proof")?;
            if self.case==7 && reply.sent>=64 {
                self.bridge.revoker().revoke().unwrap();self.fault_seen=true;
            }
            let result=self.bridge.write(p,&mut reply,backend,&mut self.content);self.sent=reply.sent;
            if self.case==7 && self.fault_seen {
                assert!(result.is_err());assert_eq!(reply.sent,64);assert!(self.bridge.stream.is_none());
                let mut raw=Vec::new();self.client.read_to_end(&mut raw).unwrap();
                assert_eq!(raw,&reply.bytes[..64]);self.denied=true;return Err("LK110 suffix revoked".into())
            }
            if result.map_err(|_|"LK110 write")? {
                let mut bytes=Vec::new();self.client.read_to_end(&mut bytes).map_err(|_|"LK110 reply")?;
                assert_eq!(bytes.len(),200+self.request.count as usize);return Ok(bytes)
            }
        }Err("LK110 write budget".into())
    }
    /// Fault coordination and HTTP never hold the E11 lane or owner guard.
    /// The same Arc retains the exact owner through the wait and completion.
    pub(crate) fn fault(wire:&Arc<Mutex<Self>>){
        let case=wire.lock().unwrap().case;
        if !(1..=6).contains(&case){return}
        Self::renew(wire);event("fault");wire.lock().unwrap().fault_seen=true;
        match case {
            1|2=>{assert_eq!(Self::refresh_shared(wire),Ok(Refresh::Unavailable));
                if case==2{std::thread::sleep(Duration::from_secs(5));}},
            3=>assert_eq!(Self::refresh_shared(wire),Ok(Refresh::Revoked)),
            4|5=>{
                let until={let s=wire.lock().unwrap();if case==4{s.bridge.adapter.config.grant.until}else{
                    let owner=s.bridge.adapter.owner.lock().unwrap();owner.observation.unwrap().token.until}};
                while wall()<until.saturating_sub(2) {std::thread::sleep(Duration::from_millis(50));}
                Self::renew(wire);
                while wall()<until {std::thread::sleep(Duration::from_millis(20));}
                // Isolate exclusive expiry from freshness/deadline exhaustion.
                let mut s=wire.lock().unwrap();let now=s.bridge.adapter.sample().unwrap();
                let state=s.bridge.adapter.owner.lock().unwrap();
                assert!(now.tick-state.observation.unwrap().status.started<5);
                assert!(now.tick<state.state.deadline && state.state.remaining>0);
            },
            6=>assert_eq!(Self::refresh_shared(wire),Ok(Refresh::Revoked)),_=>unreachable!()
        }
        wire.lock().unwrap().retained();
    }
    fn deny(&mut self,stage:&str,eligible:bool,error:&BridgeError){
        if !self.denied {
            let now=self.bridge.adapter.clock.now();
            let owner=self.bridge.adapter.owner.lock().unwrap();
            let age=owner.observation.map(|o|now.tick.saturating_sub(o.status.started));
            eprintln!("LK110 DENY stage={stage} error={error:?} eligible={eligible} mode={:?} tick={} deadline={} observation_age={age:?} remaining={} workers={} preparations={} sent={} closed={}",
                owner.state.mode,now.tick,owner.state.deadline,owner.state.remaining,
                self.bridge.adapter.workers,self.bridge.adapter.preparations,self.sent,self.bridge.closed);
        }
        self.denied=true;
    }
    fn guard(&mut self,stage:&str,eligible:bool)->Verdict{
        let result=self.proof().and_then(|p|self.bridge.adapter.submit(p,|_|eligible,||Ok(())).map_err(BridgeError::Authority));
        self.retained();match result{Ok(())=>Verdict::Valid,Err(error)=>{self.deny(stage,eligible,&error);Verdict::Invalid}}
    }
    pub(crate) fn assert_outcome(&self){
        self.retained();
        if matches!(self.case,0|1){assert!(self.final_seen && !self.denied)}
        else {assert!(self.denied,"LK110 expected authority/content denial");}
        if (1..=7).contains(&self.case){assert!(self.fault_seen,"LK110 fault was not reached")}
        if self.case>=8 {assert!(self.final_seen,"LK110 final check was not reached")}
    }
}
impl ServerVerifier for Session {
    fn verify_read(&mut self,b:Binding,r:ReadRequest)->Verdict{
        let eligible=b.connection!=0 && b.local==self.local && b.remote==self.remote && r==self.request &&
            self.binding.is_none_or(|old|old==b);
        let result=self.guard("read",eligible);if result==Verdict::Valid {self.binding=Some(b)}result
    }
    fn verify_read_reply(&mut self,b:Binding,r:ReadRequest,reply:&[u8])->Verdict{
        let frame=read::encode_read(r).ok();
        let eligible=self.bridge.closed && self.bridge.dispatched && self.sent==200+self.request.count as usize &&
            self.binding==Some(b) && r==self.request && self.content.allow &&
            reply.len()==200+self.content.bytes.len() && reply.get(..8)==Some(&b"ANKARD01"[..]) &&
            frame.as_ref().is_some_and(|f|reply.get(32..200)==Some(f.as_slice())) &&
            reply.get(200..)==Some(self.content.bytes.as_slice());
        self.guard("reply",eligible)
    }
    fn verify_download(&mut self,e:StoredEnvelope<'_>)->Verdict{
        self.final_seen=true;
        let p=match self.proof(){Ok(p)=>p,Err(error)=>{self.deny("final_proof",false,&error);return Verdict::Invalid}};
        if self.case==8 {self.bridge.revoker().revoke().unwrap()}
        if self.case==9 {self.content.allow=false}
        let eligible=self.bridge.closed && self.bridge.dispatched && self.sent==200+self.request.count as usize &&
            self.binding.is_some() && self.content.allow && e.manifest()==self.request.manifest &&
            e.image()==&self.content.bytes[176..] && e.dependency_count()==1 &&
            e.dependency(0).map(|d|(d.artifact,d.generation,d.provenance))==Some((800,2,804));
        let result=self.bridge.adapter.submit(p,|_|eligible,||Ok(()));self.retained();
        match result{Ok(())=>Verdict::Valid,Err(error)=>{self.deny("final",eligible,&BridgeError::Authority(error));Verdict::Invalid}}
    }
}
