//! LT110 scoped, read-only transport/provider bridge. No ambient E9/E11 permit.
//! The embedding supplies an independently authenticated channel, explicit local
//! trust registration and independent content/retention policy. Loopback alone
//! is never authentication. No upload, publication, execution or boot projection.
use super::*;
use crate::anka64::authority_persistence::{self as ap, artifact::{self as store,
    transfer::{self as transfer, read::{self, ReadRequest}}}};
use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};

/// Trusted transport implementation, independent of request bytes and holder
/// assertions. Called under the owner guard: bounded, nonblocking, non-reentrant.
/// Must check the actual owned stream, direction, liveness and full binding.
pub(crate) trait Transport {
    fn current(&mut self, _stream: &TcpStream) -> Option<Channel> { None }
}
/// An explicit installation decision associating a local domain/grant with a
/// storage namespace and ONE complete read range. This is not decoded peer data.
/// Independent store::Evidence still decides read permission and content validity.
#[derive(Clone, Copy)]
pub(crate) struct Registration {
    pub domain: u64, pub grant_id: u64, pub request: ReadRequest,
    pub caller: store::Caller, pub boot: u64, pub ticket: u64,
}
impl Registration {
    fn matches(self, config: Config) -> bool {
        let s=config.scope; let m=self.request.manifest;
        self.domain==config.domain && self.grant_id==config.grant_id &&
        self.boot==config.boot && self.ticket!=0 &&
        self.caller.owner==s.peer && self.caller.incarnation==s.incarnation &&
        m.installation==s.installation && m.artifact==s.artifact && m.generation==s.generation &&
        self.request.correlation==s.request && s.operation==1 && s.role==1 &&
        read::encode_read(self.request).is_ok()
    }
}
/// No bytes() accessor: disclosure requires another guarded write. Identity
/// fields prevent moving buffered results between owners, grants or transports.
pub(crate) struct PendingReply {
    owner: u64, channel: Channel, registration: Registration,
    bytes: Vec<u8>, sent: usize,
}
impl Drop for PendingReply {
    fn drop(&mut self) { for b in &mut self.bytes { unsafe { std::ptr::write_volatile(b,0) } } }
}
#[derive(Debug)]
pub(crate) enum BridgeError { Authority(Error), Configuration, Storage(ap::Error), Io, Closed }
impl From<Error> for BridgeError { fn from(e: Error) -> Self { Self::Authority(e) } }

/// Owns the actual stream. No raw descriptor, provider or reusable positive
/// verdict escapes. Crypto preparation stays outside the transport/file guard.
pub(crate) struct ReadBridge<C: Clock,T: Transport> {
    adapter: Adapter<C>, stream: Option<TcpStream>, transport: T, channel: Channel,
    registration: Registration, owner: u64, dispatched: bool, closed: bool,
    input: [u8; transfer::HEADER+1], received: usize, eof: bool,
}
impl<C: Clock,T: Transport> ReadBridge<C,T> {
    pub(crate) fn new(adapter: Adapter<C>, stream: TcpStream, mut transport: T,
        registration: Registration) -> Result<Self,BridgeError>
    {
        if !registration.matches(adapter.config) { return Err(BridgeError::Configuration); }
        let channel=transport.current(&stream).ok_or(BridgeError::Configuration)?;
        if channel.scope!=adapter.config.scope || channel.holder!=adapter.profile.holder {
            return Err(BridgeError::Configuration);
        }
        stream.set_nonblocking(true).map_err(|_| BridgeError::Io)?;
        let owner=adapter.view()?.owner;
        Ok(Self {adapter,stream:Some(stream),transport,channel,registration,owner,dispatched:false,closed:false,input:[0;transfer::HEADER+1],received:0,eof:false})
    }
    /// Terminal custody release, not merely a best-effort shutdown request.
    /// Closing after request EOF must not depend on the bridge itself dropping.
    /// Take exactly once so a retained diagnostic object owns no live descriptor.
    fn close(&mut self) {
        self.closed=true;
        if let Some(stream)=self.stream.take() {
            let _=stream.shutdown(Shutdown::Write);
            let _=stream.shutdown(Shutdown::Both);
            drop(stream);
        }
    }
    pub(crate) fn revoker(&self) -> Revoker<C> { self.adapter.revoker() }
    pub(crate) fn view(&self) -> Result<View,Error> { self.adapter.view() }
    pub(crate) fn refresh(&mut self) -> Result<Refresh,Error> { self.adapter.refresh() }
    pub(crate) fn prepare(&mut self) -> Result<Challenge,BridgeError> {
        if self.closed { return Err(BridgeError::Closed); }
        Ok(self.adapter.prepare(self.channel)?)
    }
    pub(crate) fn verify(&mut self, challenge: Challenge, signature: &[u8]) -> Result<PreparedUse,BridgeError> {
        Ok(self.adapter.verify_use(self.channel,challenge,signature)?)
    }
    /// One guarded nonblocking intake fragment. Exact request bytes on the
    /// owned stream and real EOF must precede all file inspection.
    pub(crate) fn intake(&mut self, prepared: PreparedUse) -> Result<bool,BridgeError> {
        let channel=self.channel;
        let eligible=!self.closed && !self.dispatched && !self.eof &&
            self.received<self.input.len() && prepared.channel==channel &&
            prepared.proposal.owner==self.owner;
        let stream=self.stream.as_ref().ok_or(BridgeError::Closed)?; let transport=&mut self.transport;
        let input=&mut self.input; let received=&mut self.received; let eof=&mut self.eof;
        let result=self.adapter.submit(prepared,
            |_| eligible && transport.current(stream)==Some(channel),
            || {
                let end=(*received+64).min(input.len());
                match (&*stream).read(&mut input[*received..end]) {
                    Ok(0)=>{*eof=true;Ok(true)},
                    Ok(n)=>{*received+=n;if *received>transfer::HEADER {Err(())}else{Ok(false)}},
                    Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)=>Ok(false),
                    Err(_)=>Err(()),
                }
            });
        if result.is_err() {self.close();}
        result.map_err(BridgeError::Authority)
    }
    /// Complete framing + true EOF are mandatory. Both dispatch and backend
    /// authorize/inspect checks execute under the SAME LG110 guard. Host file
    /// reads are cooperative bounded IO, as in AR110; no network wait is allowed.
    /// The result stays private until write() separately rechecks current grant.
    pub(crate) fn dispatch(&mut self, prepared: PreparedUse, backend: &mut store::ArtifactStore,
        frame: &[u8], eof: bool, budget: &mut transfer::Budget, content: &mut impl store::Evidence)
        -> Result<PendingReply,BridgeError>
    {
        let r=self.registration; let channel=self.channel; let owner=self.owner;
        let eligible=!self.closed && !self.dispatched && prepared.channel==channel &&
            prepared.proposal.owner==owner && self.eof && eof &&
            &self.input[..self.received]==frame && read::decode_read(frame,eof).ok()==Some(r.request);
        let transport=&mut self.transport; let stream=self.stream.as_ref().ok_or(BridgeError::Closed)?;
        let dispatched=&mut self.dispatched; let mut failure=None;
        let result=self.adapter.submit(prepared,
            |_| eligible && transport.current(stream)==Some(channel),
            || {
                *dispatched=true; // Never redispatch, even after panic/uncertain IO.
                let mut proof=ReadProjection {registration:r,channel:channel.scope.connection,content};
                let reply=read::dispatch_read(backend,channel.scope.connection,frame,eof,budget,&mut proof)
                    .map_err(|e| {failure=Some(e);()})?;
                Ok(PendingReply {owner,channel,registration:r,bytes:reply.bytes().to_vec(),sent:0})
            });
        if result.is_err() { self.close(); }
        result.map_err(|e|failure.map(BridgeError::Storage).unwrap_or(BridgeError::Authority(e)))
    }
    /// One nonblocking write of at most 64 bytes, matching AG110's fragment cap.
    /// Short writes and WouldBlock spend this attempt; they never replay prefix.
    pub(crate) fn write(&mut self, prepared: PreparedUse, reply: &mut PendingReply,
        backend:&store::ArtifactStore, content:&mut impl store::Evidence) -> Result<bool,BridgeError> {
        let channel=self.channel; let r=self.registration;
        let eligible=!self.closed && self.dispatched && reply.owner==self.owner &&
            reply.channel==channel && reply.registration.same(r) && reply.sent<reply.bytes.len() &&
            prepared.channel==channel && prepared.proposal.owner==self.owner;
        let transport=&mut self.transport;
        // The gate and submission access the same immutable owned descriptor;
        // try_clone is deliberately unnecessary (no descriptor substitution).
        let stream=self.stream.as_ref().ok_or(BridgeError::Closed)?;
        let result=self.adapter.submit(prepared,
            |_| {
                if !eligible || transport.current(stream)!=Some(channel){return false}
                let mut proof=ReadProjection{registration:r,channel:channel.scope.connection,content};
                read::authorize_read(backend,channel.scope.connection,&r.request,None,&mut proof).is_ok()
            },
            || {
                let end=(reply.sent+64).min(reply.bytes.len());
                match (&*stream).write(&reply.bytes[reply.sent..end]) {
                    Ok(0)=>Err(()),
                    Ok(n)=>{reply.sent+=n;Ok(reply.sent==reply.bytes.len())},
                    Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)=>Ok(false),
                    Err(_)=>Err(()),
                }
            });
        match result {
            Ok(done)=>{if done {self.close();} Ok(done)},
            Err(e)=>{self.close();Err(e.into())},
        }
    }
}
impl Registration {
    fn same(self,other:Self)->bool {
        self.domain==other.domain && self.grant_id==other.grant_id && self.request==other.request &&
        self.caller==other.caller && self.boot==other.boot && self.ticket==other.ticket
    }
}
impl<C:Clock,T:Transport> Drop for ReadBridge<C,T> {
    fn drop(&mut self) { self.close(); }
}
/// Exists only on the stack of a guarded dispatch. No snapshot, Access or permit
/// is returned. Explicit read scope AND the independent content policy must pass.
struct ReadProjection<'a,E> { registration: Registration, channel:u64, content:&'a mut E }
impl<E:store::Evidence> store::Evidence for ReadProjection<'_,E> {
    fn authorize(&mut self,s:store::Scope)->ap::Verdict {
        let r=self.registration;
        if s.manifest!=r.request.manifest || s.caller!=r.caller || s.boot!=r.boot ||
            s.ticket!=r.ticket || s.action!=store::Action::Read { return ap::Verdict::Invalid; }
        self.content.authorize(s)
    }
    fn inspect(&mut self,bytes:&mut dyn std::io::Read)->Result<store::Manifest,ap::Error> {
        let m=self.content.inspect(bytes)?;
        if m!=self.registration.request.manifest {return Err(ap::Error::Authority);} Ok(m)
    }
}
impl<E:store::Evidence> transfer::TransferEvidence for ReadProjection<'_,E> {
    fn read_caller(&mut self,connection:u64,r:&ReadRequest)->Result<store::Caller,ap::Error> {
        if connection!=self.channel || *r!=self.registration.request {return Err(ap::Error::Authority);}
        Ok(self.registration.caller)
    }
}
#[cfg(test)]
#[path="read_bridge/tests.rs"] pub(crate) mod tests;

/// Hosted transport authentication is local custody: the trusted installation
/// creates BOTH endpoints and selects the represented holder. This is not TLS,
/// an accepted arbitrary loopback peer, or a claim made by a guest. Channel
/// entropy binds LA110 signatures to this owned pair; socket addresses only
/// detect substitution after construction. Native/remote producers are separate.
pub(crate) struct HostedTransport {
    channel:Channel, local:std::net::SocketAddr, peer:std::net::SocketAddr,
    descriptor:std::os::fd::RawFd,
}
impl Transport for HostedTransport {
    fn current(&mut self,stream:&TcpStream)->Option<Channel>{
        use std::os::fd::AsRawFd;
        (stream.as_raw_fd()==self.descriptor && stream.local_addr().ok()==Some(self.local) &&
            stream.peer_addr().ok()==Some(self.peer) && stream.take_error().is_ok_and(|e|e.is_none()))
            .then_some(self.channel)
    }
}
pub(crate) struct HostedClient(TcpStream);
impl Read for HostedClient {fn read(&mut self,b:&mut[u8])->io::Result<usize>{self.0.read(b)}}
impl Write for HostedClient {
    fn write(&mut self,b:&[u8])->io::Result<usize>{self.0.write(b)}
    fn flush(&mut self)->io::Result<()>{self.0.flush()}
}
impl HostedClient {pub(crate) fn finish_request(&self)->io::Result<()>{self.0.shutdown(Shutdown::Write)}}
impl Drop for HostedClient {fn drop(&mut self){let _=self.0.shutdown(Shutdown::Both);}}
impl<C:Clock> ReadBridge<C,HostedTransport> {
    /// Explicit hosted holder delegation. The separate signer signs only the
    /// bridge-created challenge through private pipes. LA110 still independently
    /// verifies it; preparation performs no socket/file effect and holds no owner guard.
    pub(crate) fn prepare_verified(&mut self)->Result<PreparedUse,BridgeError>{
        let challenge=self.prepare()?;
        self.adapter.workers=self.adapter.workers.checked_sub(1).ok_or(Error::Exhausted)?;
        let signature=process::hosted_holder(&self.adapter.profile.config_path,challenge.bytes(),self.adapter.worker_deadline)
            .map_err(|_|BridgeError::Authority(Error::Denied))?;
        self.verify(challenge,&signature)
    }

    /// Only the trusted hosted adapter may own the client half. Passing it to an
    /// arbitrary host process would violate this profile's custody assumption.
    pub(crate) fn hosted(adapter:Adapter<C>,registration:Registration)->Result<(Self,HostedClient),BridgeError>{
        use std::os::fd::AsRawFd;
        let listener=std::net::TcpListener::bind("127.0.0.1:0").map_err(|_|BridgeError::Io)?;
        // The honest-host profile excludes another local process racing accept.
        // Still require the exact newly connected pair; no retry/adopt fallback.
        let client=TcpStream::connect_timeout(&listener.local_addr().map_err(|_|BridgeError::Io)?,Duration::from_secs(2)).map_err(|_|BridgeError::Io)?;
        let(stream,_)=listener.accept().map_err(|_|BridgeError::Io)?;
        if stream.peer_addr().ok()!=client.local_addr().ok() || stream.local_addr().ok()!=client.peer_addr().ok(){
            return Err(BridgeError::Configuration);
        }
        client.set_nonblocking(true).map_err(|_|BridgeError::Io)?;
        let mut binding=[0;32];std::fs::File::open("/dev/urandom").and_then(|mut f|f.read_exact(&mut binding)).map_err(|_|BridgeError::Io)?;
        let channel=Channel::from_authenticated_transport(adapter.config.scope.peer,adapter.config.scope,adapter.profile.holder,binding)?;
        let transport=HostedTransport{channel,local:stream.local_addr().map_err(|_|BridgeError::Io)?,
            peer:stream.peer_addr().map_err(|_|BridgeError::Io)?,descriptor:stream.as_raw_fd()};
        Ok((Self::new(adapter,stream,transport,registration)?,HostedClient(client)))
    }
}

#[cfg(test)]
#[path="read_bridge/acceptance.rs"]
pub(crate) mod acceptance;
