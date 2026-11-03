//! Host-provided ingress and scheduling only. All TCP/HTTP bytes are produced
//! by the guest publications. Capture format: repeated u16-BE length + TX bytes.
use super::*;
use crate::anka64::os::compiler_retry::service::frame_port::DeveloperFrameAuthority;
enum Event { Rx(Vec<u8>), Serve }
pub(super) struct Replay(Vec<Event>);
impl Replay {
    pub(super) fn load(path:&str)->Result<Self,String>{
        let mut txt=String::new();
        std::fs::File::open(path).map_err(fail)?.take(65537).read_to_string(&mut txt).map_err(fail)?;
        Self::parse(&txt)
    }
    fn parse(txt:&str)->Result<Self,String>{
        if txt.len()>65536{return Err("replay exceeds 64 KiB".into());}
        let mut events=Vec::new();let mut rx=0;let mut serve=false;
        for line in txt.lines().map(str::trim).filter(|l|!l.is_empty() && !l.starts_with('#')){
            if line=="serve" && !serve && rx>0 {serve=true;events.push(Event::Serve);continue;}
            let h=line.strip_prefix("rx ").ok_or("expected rx HEX or one serve")?;
            if rx==16 || h.is_empty() || h.len()>3028 || h.len()%2!=0 || !h.bytes().all(|v|v.is_ascii_hexdigit()){
                return Err("invalid replay frame/count".into());
            }
            let mut bytes=Vec::with_capacity(h.len()/2);
            for i in (0..h.len()).step_by(2){bytes.push(u8::from_str_radix(&h[i..i+2],16).map_err(fail)?);}
            rx+=1;events.push(Event::Rx(bytes));
        }
        if !serve{return Err("missing application scheduling point".into());}Ok(Self(events))
    }
    pub(super) fn run(self,s:&mut RebuildService,tcp:u64,http:u64,exec:&dev_runner::DeveloperExecutionAuthority)->Result<(),String>{
        s.with_tcp_session(tcp,http,exec,&dev_runner::DeveloperInputAuthority::provision(),
            &dev_runner::DeveloperSocketAuthority::provision(),&DeveloperFrameAuthority::provision(),|sess|{
                let mut wire=[0u8;1514];let mut out=std::io::stdout().lock();
                for event in self.0 {
                    let n=match event{Event::Rx(b)=>sess.receive(&b,&mut wire)?,Event::Serve=>sess.serve_http(&mut wire)?};
                    if n>0{out.write_all(&(n as u16).to_be_bytes()).map_err(fail)?;out.write_all(&wire[..n]).map_err(fail)?;}
                }
                out.flush().map_err(fail)
            })
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test] fn s4_tcp_replay_rejects_ambiguous_or_overbudget_input(){
        assert!(Replay::parse("rx aa\nserve\nrx bb").is_ok());
        for s in ["rx aa","serve","rx aa\nserve\nserve","rx a\nserve","rx éx\nserve","rx 0g\nserve"]{assert!(Replay::parse(s).is_err());}
        assert!(Replay::parse(&("rx aa\n".repeat(17)+"serve")).is_err());
    }
}
