//! GD110: actual guest read pump -> immutable, Kernel-accounted private image.
//! No file access, host payload injection, receipt publication or execute grant.
use super::*;
use super::retrieval::RetrievedCompilerImage;
use crate::anka64::{authority_persistence::artifact::{retrieval::{RetrievalLimits,StoredEnvelope},transfer::read::ReadRequest},
    dev_runner::{DeveloperInputAuthority,DevelopmentRunConfig},os::ProcessResult,
    os::typed_socket::{SocketCapacity,select::{ServerLane,download::{Download,DownloadLane}}},
    os::compiler_retry::service::frame_port::{DeveloperFrameAuthority,tcp::outbound::{SelectPeer,SelectStream,StorageRequest}}};
use std::sync::{Arc,Mutex};
const SCRATCH:u64=65536;
fn err(e:impl std::fmt::Debug)->String{format!("{e:?}")}
#[derive(Clone,Copy,Debug)]
pub(crate) struct DownloadConfig{pub limits:RetrievalLimits,pub window:usize,pub retries:u8,pub run:DevelopmentRunConfig}
/// A trusted transport owns its actual peer/stream until drop. It may translate
/// committed virtual frames to a real remote transport; it gets no Kernel or
/// private image buffer. Dropping a connection must terminate its actual stream.
pub(crate) struct DownloadConnection<'a>{pub capacity:SocketCapacity,pub peer:Box<dyn SelectPeer+'a>}
pub(crate) trait DownloadTransport{
    fn connect(&mut self,request:ReadRequest)->Result<DownloadConnection<'_>,String>;
}
// Both pump sources use the same GD110 exchange/custody/budget implementation.
// A restarted bootstrap is admitted separately; it never fabricates a compiler
// receipt or bypasses the typed socket path.
pub(super) trait GuestReadPump {
    fn validation_work(&self)->u64{0}
    fn validate(&mut self,kernel:&mut Kernel)->Result<(),String>;
    fn run<'k>(&mut self,kernel:&'k mut Kernel,stream:SelectStream<'_>,config:DevelopmentRunConfig)
        ->Result<super::super::execution::LinkedCompilerRunReport<'k>,String>;
}
struct CompiledPump<'a>{epoch:u64,exec:&'a DeveloperExecutionAuthority}
impl GuestReadPump for CompiledPump<'_>{
    fn validate(&mut self,k:&mut Kernel)->Result<(),String>{k.validate_linked_compiler_publication(self.epoch).map_err(err)}
    fn run<'k>(&mut self,k:&'k mut Kernel,stream:SelectStream<'_>,config:DevelopmentRunConfig)
        ->Result<super::super::execution::LinkedCompilerRunReport<'k>,String>{
        k.run_linked_compiler_publication_with_select(self.epoch,self.exec,stream,config).map_err(err)
    }
}
struct Guard<'k>{image:Option<RetrievedCompilerImage<'k>>,scratch:Option<HostStorageReservation>,state:Option<DownloadLane>}
impl Guard<'_>{
    fn release_scratch(&mut self)->Result<(),String>{
        if self.state.as_ref().is_some_and(|d|Arc::strong_count(d)!=1){return Err("download exchange still borrowed".into())}
        drop(self.state.take());
        if let Some(c)=self.scratch {
            self.image.as_mut().unwrap().kernel.fabric.scoped_pointers.release_host_storage(c).map_err(err)?;
            self.scratch=None;
        }Ok(())
    }
}
impl Drop for Guard<'_>{fn drop(&mut self){let _=self.release_scratch();}}
impl Kernel{
    /// pump_epoch is a CURRENT compiled local read-pump receipt, not the stored
    /// image being downloaded. Its child output must match authenticated AR110
    /// custody exactly. The stored image is never compiled or executed here.
    pub(crate) fn download_stored_compiler_image<'k>(&'k mut self,pump_epoch:u64,manifest:Manifest,
        exec:&DeveloperExecutionAuthority,input:&DeveloperInputAuthority,net:&DeveloperFrameAuthority,
        verifier:ServerLane,transport:&mut impl DownloadTransport,config:DownloadConfig)
        ->Result<RetrievedCompilerImage<'k>,String>
    {
        self.download_with_pump(&mut CompiledPump{epoch:pump_epoch,exec},manifest,input,net,verifier,transport,config)
    }
    pub(super) fn download_with_pump<'k>(&'k mut self,pump:&mut impl GuestReadPump,manifest:Manifest,
        input:&DeveloperInputAuthority,net:&DeveloperFrameAuthority,
        verifier:ServerLane,transport:&mut impl DownloadTransport,config:DownloadConfig)
        ->Result<RetrievedCompilerImage<'k>,String>
    {
        if !(1..=4096).contains(&config.window) || config.retries>8 || config.limits.max_bytes>2*1024*1024
            || config.limits.work>100_000_000 || config.limits.timeout>std::time::Duration::from_secs(120)
            || std::mem::size_of::<Download>()as u64+4096>SCRATCH {return Err("invalid bounded download configuration".into())}
        let mut budget=config.limits.start(manifest.size).map_err(err)?;
        budget.spend(pump.validation_work()).map_err(err)?;
        pump.validate(self)?;
        let image=RetrievedCompilerImage::reserve(self,manifest).map_err(err)?;
        let mut guard=Guard{image:Some(image),scratch:None,state:None};
        let image=guard.image.as_mut().unwrap();
        let (_,account)=image.kernel.compiler_candidate_account().map_err(err)?;
        let verifier_bytes=std::mem::size_of_val(&*verifier.try_lock().map_err(err)?)as u64;
        // The returned image retains this provider handle. Its fixed provider
        // metadata must fit the already charged private-retrieval overhead.
        if verifier_bytes>16384 {return Err("retained read verifier exceeds private metadata budget".into())}
        let charge=SCRATCH.checked_add(verifier_bytes).ok_or("download scratch overflow")?;
        guard.scratch=Some(image.kernel.fabric.scoped_pointers.reserve_host_storage(account,charge,
            image.kernel.fabric.scoped_pointers.revision()).map_err(err)?);
        // Reserve before allocating the Arc/mutex and retained response bytes.
        guard.state=Some(Arc::new(Mutex::new(Download::with_budget(manifest,budget).map_err(err)?)));
        while guard.state.as_ref().unwrap().try_lock().map_err(err)?.cursor()<manifest.size {
            let mut attempts=0;
            loop {
                guard.image.as_ref().unwrap().recheck().map_err(err)?;
                let state=guard.state.as_ref().unwrap();
                let request=state.try_lock().map_err(err)?.prepare(config.window).map_err(err)?;
                let mut connection=match transport.connect(request){
                    Ok(c)=>c,
                    Err(e)=>{
                        if attempts>=config.retries{return Err(e)}
                        state.try_lock().map_err(err)?.transport_lost().map_err(err)?;attempts+=1;continue
                    }
                };
                state.try_lock().map_err(err)?.check().map_err(err)?;
                let failure={
                state.try_lock().map_err(err)?.spend(pump.validation_work()).map_err(err)?;
                let image=guard.image.as_mut().unwrap();
                let result=pump.run(image.kernel,
                    SelectStream{capacity:connection.capacity,request:StorageRequest::Download(request,input,state.clone()),
                        verifier:verifier.clone(),authority:net,peer:&mut *connection.peer},config.run);
                match result {
                    Ok(report)=>{
                        let run=report.execution();
                        if run.child_result!=ProcessResult::Exited(0){return Err(format!("download guest failed: {:?}",run.child_result))}
                        // One provider guard serializes final read evidence and
                        // byte comparison/copy. The report remains charged here.
                        let mut policy=verifier.try_lock().map_err(err)?;
                        state.try_lock().map_err(err)?.commit(&run.byte_output,&mut image.bytes,&mut *policy).map_err(err)?;
                        drop(policy);drop(report);None
                    }
                    Err(e)=>Some(e),
                }
                };
                // Realm/driver destruction precedes peer close, then retry. No
                // new child can inherit an old live socket or partial response.
                drop(connection);
                guard.image.as_ref().unwrap().recheck().map_err(err)?;
                if let Some(e)=failure {
                    if attempts>=config.retries{return Err(e)}
                    state.try_lock().map_err(err)?.transport_lost().map_err(err)?;attempts+=1;
                }else{break}
            }
        }
        let mut policy=verifier.try_lock().map_err(err)?;
        {
            let state=guard.state.as_ref().unwrap();let image=guard.image.as_ref().unwrap();
            image.recheck().map_err(err)?;
            state.try_lock().map_err(err)?.complete().map_err(err)?;
            // Charge scan/dependency work before parsing and provider validation.
            state.try_lock().map_err(err)?.spend(manifest.size.div_ceil(4096)+4097).map_err(err)?;
            let envelope=StoredEnvelope::decode(&image.bytes,manifest).map_err(err)?;
            if policy.verify_download(envelope)!=Verdict::Valid{return Err("download final read/content/dependency validation denied".into())}
            state.try_lock().map_err(err)?.check().map_err(err)?;
            image.recheck().map_err(err)?;
        }
        // Transfer, never restart, the exchange budget into private custody.
        let (budget,binding,request)=guard.state.as_ref().unwrap().try_lock().map_err(err)?.finish().map_err(err)?;
        let image=guard.image.as_mut().unwrap();
        image.budget=Some(budget);
        image.origin=Some(super::launch::ReadOrigin::Guest{binding,request});
        image.read_verifier=Some(verifier.clone());
        guard.release_scratch()?;
        // The returned guard keeps the exact private image charged until drop.
        // No runtime object, publication epoch or execution authority is minted.
        let image=guard.image.take().unwrap();image.recheck().map_err(err)?;
        drop(policy);Ok(image)
    }
}
