//! GD110 private exchange custody. Constructed only after Kernel reservation.
//! One budget/deadline/correlation space survives all child realms and retries.
use super::*;
use crate::anka64::authority_persistence::{Error,artifact::{Manifest,retrieval::{RetrievalLimits,RetrievalBudget},transfer::read::{self,ReadRequest}}};
pub(crate) type DownloadLane=Arc<Mutex<Download>>;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum State{Idle,Prepared,Active,Validated,Committed,Retry,Failed}
pub(crate) struct Download{
    manifest:Manifest,budget:RetrievalBudget,cursor:u64,correlation:u64,
    request:Option<ReadRequest>,binding:Option<Binding>,last_channel:u64,
    reply:[u8;read::MAX_READ_REPLY],len:usize,state:State,
}
pub(crate) fn scrub(bytes:&mut[u8]){for b in bytes {unsafe{std::ptr::write_volatile(b,0)}}}
impl Download{
    pub(crate) fn new(manifest:Manifest,limits:RetrievalLimits)->Result<Self,Error>{
        Self::with_budget(manifest,limits.start(manifest.size)?)
    }
    pub(crate) fn with_budget(manifest:Manifest,budget:RetrievalBudget)->Result<Self,Error>{
        budget.check()?;
        read::encode_read(ReadRequest{manifest,correlation:1,offset:0,count:1})?;
        Ok(Self{manifest,budget,cursor:0,correlation:0,request:None,binding:None,
            last_channel:0,reply:[0;read::MAX_READ_REPLY],len:0,state:State::Idle})
    }
    pub(crate) fn spend(&mut self,n:u64)->Result<(),Error>{
        if self.state==State::Failed{return Err(Error::Authority)}
        if let Err(e)=self.budget.spend(n){self.fail();return Err(e)}Ok(())
    }
    pub(crate) fn check(&mut self)->Result<(),Error>{
        if self.state==State::Failed{return Err(Error::Authority)}
        if let Err(e)=self.budget.check(){self.fail();return Err(e)}Ok(())
    }
    pub(crate) fn fail(&mut self){scrub(&mut self.reply);self.len=0;self.state=State::Failed;}
    pub(crate) fn cursor(&self)->u64{self.cursor}
    pub(crate) fn prepare(&mut self,window:usize)->Result<ReadRequest,Error>{
        self.spend(1)?;
        if !(1..=4096).contains(&window) || self.cursor>=self.manifest.size
            || !matches!(self.state,State::Idle|State::Committed|State::Retry){self.fail();return Err(Error::Conflict)}
        let count=(self.manifest.size-self.cursor).min(window as u64);
        if self.state==State::Retry && self.request.is_none_or(|r|r.offset!=self.cursor || r.count!=count){self.fail();return Err(Error::Authority)}
        self.correlation=match self.correlation.checked_add(1){Some(c)=>c,None=>{self.fail();return Err(Error::Exhausted)}};
        let r=ReadRequest{manifest:self.manifest,correlation:self.correlation,offset:self.cursor,count};
        read::encode_read(r)?;self.request=Some(r);self.binding=None;self.state=State::Prepared;Ok(r)
    }
    pub(crate) fn bind(&mut self,r:ReadRequest,b:Binding)->Result<(),Error>{
        self.spend(1)?;
        if self.state!=State::Prepared || self.request!=Some(r) || b.connection==0 || b.connection==self.last_channel {
            self.fail();return Err(Error::Authority)
        }
        self.last_channel=b.connection;self.binding=Some(b);self.state=State::Active;Ok(())
    }
    pub(crate) fn matches(&self,r:ReadRequest,b:Binding)->bool{
        matches!(self.state,State::Active|State::Validated) && self.request==Some(r) && self.binding==Some(b)
    }
    pub(crate) fn capture(&mut self,r:ReadRequest,b:Binding,reply:&[u8])->Result<(),Error>{
        self.spend(1)?;
        if self.state!=State::Active || !self.matches(r,b) || reply.len()!=read::READ_REPLY_PREFIX+r.count as usize
            || reply.len()>self.reply.len(){self.fail();return Err(Error::Authority)}
        // Only Select calls this, after canonical framing and trusted evidence,
        // under the SAME provider guard as the actual FIN acknowledgement.
        self.reply[..reply.len()].copy_from_slice(reply);self.len=reply.len();self.state=State::Validated;Ok(())
    }
    /// Called only after the isolated realm, NIC driver and owned peer are gone.
    /// A validated result cannot be retried. Policy/budget failures are terminal.
    pub(crate) fn transport_lost(&mut self)->Result<(),Error>{
        self.spend(1)?;
        if !matches!(self.state,State::Prepared|State::Active){self.fail();return Err(Error::Conflict)}
        scrub(&mut self.reply);self.len=0;self.binding=None;self.state=State::Retry;Ok(())
    }
    /// v is locked by the caller for current evidence through the private copy.
    /// Guest output is compared with authenticated receive custody, not trusted.
    pub(crate) fn commit(&mut self,guest:&[u8],out:&mut[u8],v:&mut dyn ServerVerifier)->Result<(),Error>{
        self.spend(2)?;
        if self.state!=State::Validated || out.len()as u64!=self.manifest.size {self.fail();return Err(Error::Conflict)}
        let r=self.request.ok_or(Error::Authority)?;let b=self.binding.ok_or(Error::Authority)?;
        if r.offset!=self.cursor || v.verify_read(b,r)!=Verdict::Valid
            || v.verify_read_reply(b,r,&self.reply[..self.len])!=Verdict::Valid {self.fail();return Err(Error::Authority)}
        self.check()?;
        let payload=&self.reply[read::READ_REPLY_PREFIX..self.len];
        if guest!=payload {self.fail();return Err(Error::CorruptRecord)}
        let start=usize::try_from(self.cursor).map_err(|_|Error::Capacity)?;
        let end=start.checked_add(guest.len()).filter(|&end|end<=out.len()).ok_or(Error::Capacity)?;
        out[start..end].copy_from_slice(guest);self.cursor=end as u64;
        scrub(&mut self.reply);self.len=0;self.state=State::Committed;Ok(())
    }
    pub(crate) fn finish(&mut self)->Result<(RetrievalBudget,Binding,ReadRequest),Error>{
        self.complete()?;
        let binding=self.binding.ok_or(Error::Authority)?;
        let request=self.request.ok_or(Error::Authority)?;
        let budget=self.budget.transfer()?;
        self.fail();
        Ok((budget,binding,request))
    }
    pub(crate) fn complete(&mut self)->Result<(),Error>{
        self.spend(1)?;
        if self.state!=State::Committed || self.cursor!=self.manifest.size{self.fail();return Err(Error::Conflict)}Ok(())
    }

}
impl Drop for Download{fn drop(&mut self){self.fail();}}

#[cfg(test)]
mod tests{
    use super::*;
    fn manifest()->Manifest{Manifest{anchor:10,installation:20,artifact:40,generation:2,role:2,profile:1,size:5000,image:101,metadata:102,dependencies:103,provenance:104}}
    fn limits(work:u64)->RetrievalLimits{RetrievalLimits{max_bytes:5000,work,timeout:Duration::from_secs(20)}}
    fn binding(c:u64)->Binding{Binding{connection:c,local:"127.0.0.1:1".parse().unwrap(),remote:"127.0.0.1:2".parse().unwrap()}}
    fn reply(r:ReadRequest)->Vec<u8>{
        let mut b=vec![42;read::READ_REPLY_PREFIX+r.count as usize];b[..8].copy_from_slice(b"ANKARD01");
        for (i,w) in [1,168,r.count].iter().enumerate(){b[8+i*8..16+i*8].copy_from_slice(&w.to_le_bytes());}
        b[32..200].copy_from_slice(&read::encode_read(r).unwrap());b
    }
    struct Yes{valid:bool}
    impl ServerVerifier for Yes{
        fn verify_read(&mut self,_:Binding,_:ReadRequest)->Verdict{if self.valid{Verdict::Valid}else{Verdict::Invalid}}
        fn verify_read_reply(&mut self,_:Binding,_:ReadRequest,_:&[u8])->Verdict{if self.valid{Verdict::Valid}else{Verdict::Invalid}}
    }
    fn active(work:u64)->(Download,ReadRequest){let mut d=Download::new(manifest(),limits(work)).unwrap();let r=d.prepare(4096).unwrap();d.bind(r,binding(1)).unwrap();(d,r)}
    #[test] fn gd110_download_mode_exact_geometry_and_default_denial(){
        struct Upload;impl ServerVerifier for Upload{fn verify_artifact(&mut self,_:Binding,_:&[u8])->Verdict{Verdict::Valid}}
        let mut d=Download::new(manifest(),limits(100)).unwrap();let r=d.prepare(4096).unwrap();
        let lane=Arc::new(Mutex::new(d));let mut s=Select::new_download(binding(1).local,binding(1).remote,r,Arc::new(Mutex::new(Upload)),lane.clone()).unwrap();
        assert_eq!((s.request_len,s.reply_len),(168,4296));assert!(s.current().is_none());assert_eq!(lane.lock().unwrap().state,State::Failed);
    }
    #[test] fn gd110_download_request_rejects_upload_codec(){
        let mut d=Download::new(manifest(),limits(100)).unwrap();let r=d.prepare(4096).unwrap();
        assert!(artifact::decode(&read::encode_read(r).unwrap(),true).is_err());
        assert!(Select::new_artifact(binding(1).local,binding(1).remote,&read::encode_read(r).unwrap(),Arc::new(Mutex::new(Yes{valid:true}))).is_err());
    }
    #[test] fn gd110_download_output_requires_complete_receive_current_read_and_exact_bound(){
        let mut d=Download::new(manifest(),limits(100)).unwrap();let r=d.prepare(4096).unwrap();
        let lane=Arc::new(Mutex::new(d));let policy=Arc::new(Mutex::new(Yes{valid:true}));
        let mut s=Select::new_download(binding(1).local,binding(1).remote,r,policy.clone(),lane.clone()).unwrap();
        assert!(!s.allow_download_output(0,1));
        let bytes=reply(r);s.reply[..bytes.len()].copy_from_slice(&bytes);s.received=bytes.len();s.phase=Phase::Reply;
        lane.lock().unwrap().capture(r,s.binding,&bytes).unwrap();
        assert!(!s.allow_download_output(0,1));s.delivered=s.reply_len;
        assert!(s.allow_download_output(0,1024));assert!(s.allow_download_output(4095,1));
        assert!(!s.allow_download_output(4096,1));assert!(!s.allow_download_output(usize::MAX,u64::MAX));
        policy.lock().unwrap().valid=false;assert!(!s.allow_download_output(0,1));
        let mut upload=Select::create(binding(1).local,binding(1).remote,None,&[],72,policy).unwrap();
        upload.phase=Phase::Reply;upload.delivered=72;assert!(!upload.allow_download_output(0,1));
    }
    #[test] fn gd110_download_retry_keeps_range_work_deadline_and_correlation(){
        let (mut d,r)=active(9);let deadline=d.budget.check();assert!(deadline.is_ok());
        d.transport_lost().unwrap();let next=d.prepare(4096).unwrap();
        assert_eq!((next.offset,next.count,next.manifest),(r.offset,r.count,r.manifest));assert_eq!(next.correlation,2);
        d.bind(next,binding(2)).unwrap();d.spend(4).unwrap();assert!(d.spend(1).is_err());assert_eq!(d.cursor,0);
    }
    #[test] fn gd110_download_retry_rejects_range_change_and_old_channel(){
        let (mut d,_)=active(100);d.transport_lost().unwrap();assert!(d.prepare(2048).is_err());
        let (mut d,_)=active(100);d.transport_lost().unwrap();let r=d.prepare(4096).unwrap();assert!(d.bind(r,binding(1)).is_err());
    }
    #[test] fn gd110_download_deadline_and_correlation_never_reset(){
        // Construct under a live budget, then expire it explicitly. A 1-ns
        // timeout can expire inside new(), before this test reaches prepare().
        let mut d=Download::new(manifest(),limits(100)).unwrap();
        d.budget.expire_for_test();
        assert_eq!(d.prepare(4096),Err(Error::ExpiredRequest));
        assert_eq!((d.state,d.cursor,d.correlation),(State::Failed,0,0));
        assert_eq!(d.prepare(4096),Err(Error::Authority));

        // A lost transport does not acquire a fresh deadline on retry.
        let (mut d,r)=active(100);d.transport_lost().unwrap();
        d.budget.expire_for_test();
        assert_eq!(d.prepare(4096),Err(Error::ExpiredRequest));
        assert_eq!((d.state,d.cursor,d.correlation),(State::Failed,0,r.correlation));
        assert_eq!(d.request,Some(r));
        assert_eq!(d.transport_lost(),Err(Error::Authority));

        let mut d=Download::new(manifest(),limits(100)).unwrap();d.correlation=u64::MAX;
        assert_eq!(d.prepare(4096),Err(Error::Exhausted));
        assert_eq!((d.state,d.cursor,d.correlation),(State::Failed,0,u64::MAX));
    }
    #[test] fn gd110_download_full_buffer_without_eof_cannot_commit(){
        let (mut d,_)=active(100);let mut out=vec![0;5000];
        assert!(d.commit(&[42;4096],&mut out,&mut Yes{valid:true}).is_err());assert!(out.iter().all(|b|*b==0));
    }
    #[test] fn gd110_download_zero_progress_poll_rechecks_read_authority(){
        let mut d=Download::new(manifest(),limits(100)).unwrap();let r=d.prepare(4096).unwrap();
        let lane=Arc::new(Mutex::new(d));let policy=Arc::new(Mutex::new(Yes{valid:true}));
        let mut s=Select::new_download(binding(1).local,binding(1).remote,r,policy.clone(),lane.clone()).unwrap();
        s.phase=Phase::Fin;assert_eq!(s.read_ready(&mut *policy.lock().unwrap()),Some(false));
        policy.lock().unwrap().valid=false;assert_eq!(s.read_ready(&mut *policy.lock().unwrap()),None);
        assert_eq!(lane.lock().unwrap().state,State::Failed);
    }
    #[test] fn gd110_download_validated_result_cannot_retry(){
        let (mut d,r)=active(100);d.capture(r,binding(1),&reply(r)).unwrap();assert!(d.transport_lost().is_err());
        assert!(d.reply.iter().all(|b|*b==0));assert_eq!(d.cursor,0);
    }
    #[test] fn gd110_download_current_authority_and_exact_guest_output_before_copy(){
        for revoke in [false,true]{let(mut d,r)=active(100);d.capture(r,binding(1),&reply(r)).unwrap();let mut out=vec![0;5000];
            assert!(d.commit(&vec![if revoke{42}else{41};4096],&mut out,&mut Yes{valid:!revoke}).is_err());
            assert!(out.iter().all(|b|*b==0));assert_eq!(d.cursor,0);assert_eq!(d.len,0);}
    }
    #[test] fn gd110_download_contiguous_private_ranges_and_no_duplicate_commit(){
        let (mut d,r)=active(100);let mut out=vec![0;5000];let mut policy=Yes{valid:true};
        d.capture(r,binding(1),&reply(r)).unwrap();d.commit(&[42;4096],&mut out,&mut policy).unwrap();assert_eq!(d.cursor,4096);
        let r=d.prepare(4096).unwrap();assert_eq!((r.offset,r.count,r.correlation),(4096,904,2));d.bind(r,binding(2)).unwrap();
        d.capture(r,binding(2),&reply(r)).unwrap();d.commit(&[42;904],&mut out,&mut policy).unwrap();d.complete().unwrap();
        assert!(out.iter().all(|b|*b==42));assert!(d.commit(&[42;904],&mut out,&mut policy).is_err());
    }
    #[test] fn gd110_download_cancelled_client_preserves_independent_exchange(){
        let (mut a,ar)=active(100);let (mut b,br)=active(100);
        a.capture(ar,binding(1),&reply(ar)).unwrap();a.fail();
        let mut out=vec![0;5000];b.capture(br,binding(1),&reply(br)).unwrap();
        b.commit(&[42;4096],&mut out,&mut Yes{valid:true}).unwrap();
        assert_eq!(a.cursor,0);assert!(a.reply.iter().all(|b|*b==0));assert_eq!(b.cursor,4096);
    }
    #[test] fn gd110_download_bad_echo_tail_and_corrupt_count_fail_validation(){
        for damage in 0..4{
            let mut d=Download::new(manifest(),limits(100)).unwrap();let r=d.prepare(4096).unwrap();
            let mut s=Select::new_download(binding(1).local,binding(1).remote,r,Arc::new(Mutex::new(Yes{valid:true})),Arc::new(Mutex::new(d))).unwrap();
            let bytes=reply(r);s.reply[..bytes.len()].copy_from_slice(&bytes);
            match damage{0=>s.reply[48]^=1,1=>s.reply[24]^=1,2=>s.reply[0]^=1,_=>{}}
            assert!(!s.validate_reply(if damage==3{4297}else{4296}));
        }
    }
}
