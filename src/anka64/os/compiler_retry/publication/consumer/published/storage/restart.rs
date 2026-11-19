//! RR110 bounded restartable guest. The owned Kernel is private; no saved
//! compiler receipt, process, pointer, socket or admission is restored. The
//! selected bootstrap is a precompiled CS110 download pump read from durable
//! storage. Targets still arrive through GD110's actual guest/socket/NIC path.
//! Providers are trusted validators, not wire data. All current evidence and
//! updates serialize on the one Authority mutex, including launch commitment.
use super::*;
use super::{download::{DownloadConfig,DownloadTransport,GuestReadPump},retrieval::RetrievedCompilerImage,
    launch::{LaunchPolicy,LaunchScope,StoredLaunchReport,authority::ExecuteEvidence}};
use crate::anka64::{authority_persistence::{self as ap,DurableRecord,Request,State,BootLatch,BootEvidence,
    artifact::retrieval::{StoredEnvelope,RetrievalLimits,RetrievalPolicy},protocol::client::{Binding,ServerVerifier}},
    dev_runner::{self,DeveloperInputAuthority,DevelopmentRunConfig,DevelopmentRunReport},
    os::compiler_retry::service::frame_port::{DeveloperFrameAuthority,tcp::outbound::SelectStream},
    dev_shell::DevelopmentArtifactRegistry,placement::PhysicalPlacementManager};
use std::sync::{Arc,Mutex};
fn err(e:impl std::fmt::Debug)->String {format!("{e:?}")}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct BootIdentity {
    pub anchor:u64,pub installation:u64,pub policy:u64,pub head:u64,pub selected:u64,
    pub boot:u64,pub attempt:u64,pub realm:u64,
}
#[derive(Clone,Copy,Debug)]
pub(crate) struct BootAuthorization {
    pub context:ap::Context,pub access:ap::Access,pub enrollment:ap::Enrollment,
    pub evidence:BootEvidence,pub realm:u64,pub selected:u64,
}
/// Freshness/consume_boot must be backed by an authority OUTSIDE any rollback
/// of the guest and file store. A process-local counter is only a realm label.
/// current_boot must validate the complete admitted binding and current policy.
/// read/execute callbacks bind independent evidence to the actual passed scope;
/// a CRC, matching manifest or localhost connection is never authentication.
/// Methods default to denial. Callbacks must be bounded and must not reenter.
pub(crate) trait RestartEvidence:Send {
    fn reservation(&mut self,_request:Request)->Option<(ap::Context,ap::Access)>{None}
    fn boot(&mut self,_request:Request,_head:&State,_realm:u64)->Option<BootAuthorization>{None}
    fn bootstrap_access(&mut self,_scope:Scope)->Verdict{Verdict::Unknown}
    fn inspect_bootstrap(&mut self,_input:&mut dyn Read)->Result<Manifest,ap::Error>{Err(ap::Error::Authority)}
    fn bootstrap(&mut self,_boot:BootIdentity,_image:StoredEnvelope<'_>)->Verdict{Verdict::Unknown}
    /// Atomically consume this externally fresh boot attempt for this realm.
    /// No fallible adapter work follows success. An uncertain provider result
    /// denies; it must never cause the attempt to become reusable.
    fn consume_boot(&mut self,_boot:BootIdentity)->Verdict{Verdict::Unknown}
    fn current_boot(&mut self,_boot:BootIdentity)->Verdict{Verdict::Unknown}
    fn service(&mut self,_boot:BootIdentity)->Option<u64>{None}
    fn read(&mut self,_boot:BootIdentity,_service:u64,_binding:Binding,
        _request:ap::artifact::transfer::read::ReadRequest)->Verdict{Verdict::Unknown}
    fn reply(&mut self,_boot:BootIdentity,_service:u64,_binding:Binding,
        _request:ap::artifact::transfer::read::ReadRequest,_bytes:&[u8])->Verdict{Verdict::Unknown}
    fn downloaded(&mut self,_boot:BootIdentity,_service:u64,_image:StoredEnvelope<'_>)->Verdict{Verdict::Unknown}
    fn now(&mut self)->Option<u64>{None}
    fn execute(&mut self,_boot:BootIdentity,_scope:LaunchScope,_now:u64)->Option<ExecuteEvidence>{None}
}
#[derive(Clone,Copy)]
struct Session {boot:BootIdentity,service:u64,manifest:Manifest}
/// One lane shared by read validation and T1 commit. Trusted updates MUST take
/// this mutex (through update); no independently mutable allow bits are supplied.
pub(crate) struct Authority<P> {
    provider:P,active:Option<BootIdentity>,session:Option<Session>,
    // Monotone LOCAL connection watermark. External service/boot freshness is
    // still mandatory; this only prevents recycling handles in this process.
    connection_high:u64,bound:Option<(Binding,ap::artifact::transfer::read::ReadRequest)>,
}
impl<P:RestartEvidence> Authority<P> {
    pub(crate) fn new(provider:P)->Self {Self{provider,active:None,session:None,connection_high:0,bound:None}}
    pub(crate) fn update<T>(&mut self,update:impl FnOnce(&mut P)->T)->T {update(&mut self.provider)}
    pub(crate) fn reserve(&mut self,record:&mut impl DurableRecord,request:Request)->Result<ap::Outcome,String> {
        if self.active.is_some(){return Err("guest is already admitted".into())}
        let (c,a)=self.provider.reservation(request).ok_or("boot reservation evidence unavailable")?;
        ap::reserve_restart_boot(record,c,request,a).map_err(err)
    }
    #[cfg(test)] pub(crate) fn test_binding(&self)->Option<(Binding,ap::artifact::transfer::read::ReadRequest)>{self.bound}
    fn current(&mut self)->Option<Session> {
        let s=self.session?;
        if self.active!=Some(s.boot) || self.provider.current_boot(s.boot)!=Verdict::Valid
            || self.provider.service(s.boot)!=Some(s.service) || s.service==0 {return None}
        Some(s)
    }
}
impl<P:RestartEvidence> ServerVerifier for Authority<P> {
    fn verify_read(&mut self,b:Binding,r:ap::artifact::transfer::read::ReadRequest)->Verdict {
        let Some(s)=self.current() else{return Verdict::Invalid};
        if b.connection==0 || r.manifest!=s.manifest {return Verdict::Invalid}
        if self.bound!=Some((b,r)) {
            if b.connection<=self.connection_high{return Verdict::Invalid}
            self.connection_high=b.connection;self.bound=Some((b,r));
        }
        let v=self.provider.read(s.boot,s.service,b,r);
        if v==Verdict::Valid && self.current().is_some(){Verdict::Valid}else{Verdict::Invalid}
    }
    fn verify_read_reply(&mut self,b:Binding,r:ap::artifact::transfer::read::ReadRequest,bytes:&[u8])->Verdict {
        if self.verify_read(b,r)!=Verdict::Valid{return Verdict::Invalid}
        let s=self.session.unwrap();let v=self.provider.reply(s.boot,s.service,b,r,bytes);
        if v==Verdict::Valid && self.verify_read(b,r)==Verdict::Valid{Verdict::Valid}else{Verdict::Invalid}
    }
    fn verify_download(&mut self,image:StoredEnvelope<'_>)->Verdict {
        let Some(s)=self.current() else{return Verdict::Invalid};
        if image.manifest()!=s.manifest{return Verdict::Invalid}
        let v=self.provider.downloaded(s.boot,s.service,image);
        if v==Verdict::Valid && self.current().is_some(){Verdict::Valid}else{Verdict::Invalid}
    }
}
impl<P:RestartEvidence> LaunchPolicy for Authority<P> {
    fn now(&mut self)->Option<u64>{
        self.current()?;let now=self.provider.now()?;let(b,r)=self.bound?;
        if self.verify_read(b,r)==Verdict::Valid{Some(now)}else{None}
    }
    fn validate_image(&mut self,scope:LaunchScope,image:StoredEnvelope<'_>)->Verdict {
        let Some(s)=self.current() else{return Verdict::Invalid};
        if scope.id.boot!=s.boot.realm || scope.manifest!=s.manifest {return Verdict::Invalid}
        self.verify_download(image)
    }
    fn execute(&mut self,scope:LaunchScope,now:u64)->Option<ExecuteEvidence> {
        let s=self.current()?;
        if scope.id.boot!=s.boot.realm || scope.manifest!=s.manifest{return None}
        self.provider.execute(s.boot,scope,now)
    }
}
struct Bootstrap {bytes:Vec<u8>,manifest:Manifest,charge:HostStorageReservation}
struct BootstrapReader<'a,P>{provider:&'a mut P,boot:BootIdentity}
impl<P:RestartEvidence> Evidence for BootstrapReader<'_,P> {
    fn authorize(&mut self,s:Scope)->Verdict{self.provider.bootstrap_access(s)}
    fn inspect(&mut self,r:&mut dyn Read)->Result<Manifest,ap::Error>{self.provider.inspect_bootstrap(r)}
}
impl<P:RestartEvidence> RetrievalPolicy for BootstrapReader<'_,P> {
    fn validate_retrieved(&mut self,_s:Scope,e:StoredEnvelope<'_>)->Verdict{self.provider.bootstrap(self.boot,e)}
}
/// Exclusive ownership prevents a caller from attaching saved runtime objects.
/// Dropping a guest destroys its root and all private backing. There is no
/// serialized Kernel image, no general process migration, and no compiler here.
pub(crate) struct RestartGuest<P:RestartEvidence> {
    kernel:Kernel,bootstrap:Option<Bootstrap>,identity:BootIdentity,
    authority:Arc<Mutex<Authority<P>>>,_storage:HostStorageReservation,
}
impl<P:RestartEvidence+'static> RestartGuest<P> {
    pub(crate) fn open(record:&mut impl DurableRecord,request:Request,store:&mut ArtifactStore,
        manifest:Manifest,caller:Caller,limits:RetrievalLimits,authority:Arc<Mutex<Authority<P>>>)
        ->Result<Self,String>
    {
        if manifest.size>2*1024*1024 || limits.max_bytes>2*1024*1024 || limits.work>100_000_000
            || limits.timeout>std::time::Duration::from_secs(120) || std::mem::size_of::<Authority<P>>()>16384 {
            return Err("bootstrap limits".into())
        }
        let mut lane=authority.try_lock().map_err(err)?;
        if lane.active.is_some(){return Err("boot lane already occupied".into())}
        let (c,a)=lane.provider.reservation(request).ok_or("boot authority unavailable")?;
        if !ap::authorized(c,request,a) || request.operation!=ap::Operation::ReserveBoot
            || c.policy==0 || c.challenge==0 || c.challenge!=request.attempt
            || manifest.anchor!=c.anchor || manifest.installation!=c.installation {return Err("current boot request denied".into())}
        let head=record.load(c.anchor,c.installation).map_err(err)?;
        let (kernel,storage,_)=crate::anka64::os::compiler_retry::service::realm()?;
        let realm=kernel.stored_launch_realm();
        if realm==0{return Err("local realm identity exhausted".into())}
        let identity=BootIdentity{anchor:c.anchor,installation:c.installation,policy:c.policy,
            head:head.revision,selected:head.value,boot:head.boot,attempt:request.attempt,realm};
        let mut guest=Self{kernel,bootstrap:None,identity,authority:authority.clone(),_storage:storage};
        // Verify reservation/freshness before reading bootstrap bytes. A fresh
        // BootLatch is private until final validation and external consumption.
        check_boot(&mut lane.provider,request,&head,identity)?;
        let view={
            let mut reader=BootstrapReader{provider:&mut lane.provider,boot:identity};
            guest.kernel.retrieve_stored_compiler_image(store,manifest,caller,limits,&mut reader).map_err(err)?
        };
        let mut view=view;
        let e=view.envelope().map_err(err)?;
        let limit=if manifest.profile==1{0x100000}else{0x200000};
        if e.entry()!=0 || e.code_size()!=e.literal_start() || e.literal_start()>=e.image().len()as u64 || e.image().len()>limit {
            return Err("bootstrap executable geometry".into())
        }
        // Move charged immutable custody, never a compiler publication receipt.
        let mut budget=view.budget.take().ok_or("missing bootstrap budget")?;
        let charge=view.charge.take().ok_or("missing bootstrap custody")?;
        let bootstrap=Bootstrap{bytes:std::mem::take(&mut view.bytes),manifest,charge};
        drop(view);guest.bootstrap=Some(bootstrap);
        budget.spend(manifest.size.div_ceil(4096)+4097).map_err(err)?;
        let actual=record.load(c.anchor,c.installation).map_err(err)?;
        if actual!=head{return Err("boot head changed while loading bootstrap".into())}
        check_boot(&mut lane.provider,request,&actual,identity)?;
        let boot=guest.bootstrap.as_ref().unwrap();
        if lane.provider.bootstrap(identity,StoredEnvelope::decode(&boot.bytes,manifest).map_err(err)?)!=Verdict::Valid {
            return Err("bootstrap revoked at admission".into())
        }
        // Last trusted freshness check follows content-provider work. On an
        // uncertain consume result this guest is destroyed; retry needs current
        // external evidence, never an automatic rollback of the durable record.
        check_boot(&mut lane.provider,request,&actual,identity)?;
        budget.check().map_err(err)?;
        if lane.provider.consume_boot(identity)!=Verdict::Valid{return Err("boot attempt consumption denied".into())}
        lane.active=Some(identity);lane.session=None;lane.bound=None;
        drop(lane);Ok(guest)
    }
    pub(crate) fn identity(&self)->BootIdentity{self.identity}
    pub(crate) fn launch_revision(&self)->u64{self.kernel.stored_launch_revision()}
    pub(crate) fn download<'k>(&'k mut self,manifest:Manifest,input:&DeveloperInputAuthority,net:&DeveloperFrameAuthority,
        transport:&mut impl DownloadTransport,config:DownloadConfig)->Result<RetrievedCompilerImage<'k>,String> {
        {
            let mut p=self.authority.try_lock().map_err(err)?;
            if p.active!=Some(self.identity) || p.provider.current_boot(self.identity)!=Verdict::Valid
                || manifest.anchor!=self.identity.anchor || manifest.installation!=self.identity.installation {
                return Err("current restart guest denied".into())
            }
            let service=p.provider.service(self.identity).filter(|n|*n!=0).ok_or("current service identity unavailable")?;
            p.session=Some(Session{boot:self.identity,service,manifest});p.bound=None;
        }
        let verifier:crate::anka64::os::typed_socket::select::ServerLane=self.authority.clone();
        let mut pump=Pump{bootstrap:self.bootstrap.as_ref().ok_or("missing bootstrap")?,identity:self.identity,authority:&self.authority};
        self.kernel.download_with_pump(&mut pump,manifest,input,net,verifier,transport,config)
    }
    pub(crate) fn download_and_launch<'k>(&'k mut self,manifest:Manifest,input:&DeveloperInputAuthority,net:&DeveloperFrameAuthority,
        transport:&mut impl DownloadTransport,config:DownloadConfig,expected_revision:u64,run:DevelopmentRunConfig)
        ->Result<StoredLaunchReport<'k>,String> {
        let lane=self.authority.clone();
        self.download(manifest,input,net,transport,config)?.launch_shared(&lane,expected_revision,run)
    }
    #[cfg(test)] pub(crate) fn test_kernel(&mut self)->&mut Kernel{&mut self.kernel}
}
fn check_boot<P:RestartEvidence>(p:&mut P,r:Request,h:&State,id:BootIdentity)->Result<(),String>{
    let a=p.boot(r,h,id.realm).ok_or("current boot evidence unavailable")?;
    if id.policy==0 || id.head==0 || a.realm!=id.realm || a.selected!=id.selected || a.context.anchor!=id.anchor
        || a.context.installation!=id.installation || a.context.policy!=id.policy
        || a.context.challenge!=id.attempt || a.evidence.head!=id.head || a.evidence.boot!=id.boot {
        return Err("boot evidence scope mismatch".into())
    }
    let mut latch=BootLatch::default();
    latch.admit(a.context,h,r,a.access,a.enrollment,a.evidence).map_err(err)?;Ok(())
}
impl<P:RestartEvidence> Drop for RestartGuest<P>{
    fn drop(&mut self){
        if let Ok(mut p)=self.authority.try_lock(){if p.active==Some(self.identity){p.active=None;p.session=None;p.bound=None;}}
        if let Some(mut b)=self.bootstrap.take(){
            crate::anka64::os::typed_socket::select::download::scrub(&mut b.bytes);
            drop(b.bytes);
            let _=self.kernel.fabric.scoped_pointers.release_host_storage(b.charge);
        }
        self.kernel.fabric.scrub_retired_private_memory();
    }
}
mod pump;
use pump::Pump;
#[cfg(test)] pub(crate) mod tests;
