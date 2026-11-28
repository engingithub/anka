//! Private bounded worker transport; no shell, token arguments, logs or retries.
use super::*;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
struct Group(Child);
impl Drop for Group {
    fn drop(&mut self) {
        unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL); }
        let _ = self.0.wait();
    }
}
fn nonblocking(fd: i32) -> Result<(), ()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 { Err(()) } else { Ok(()) }
}
pub(super) fn worker(config: &Path, request: &[u8], reply_size: usize, deadline: Instant) -> Result<Vec<u8>, ()> {
    let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/keycloak/adapter.py");
    if !helper.is_file() { return Err(()); }
    let mut command = Command::new("python3");
    command.arg("-I").arg(helper).arg("--config").arg(config);
    capture(command, request, reply_size, deadline)
}
/// Separate, explicitly delegated hosted holder; the verifier worker never signs.
pub(super) fn hosted_holder(config:&Path,record:&[u8],deadline:Instant)->Result<Vec<u8>,()>{
    let helper=Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/keycloak/holder.py");
    if !helper.is_file(){return Err(())}
    let mut command=Command::new("python3");command.arg("-I").arg(helper).arg("--config").arg(config);
    let output=capture(command,record,516,deadline)?;
    let n=u32::from_le_bytes(output[..4].try_into().map_err(|_|())?)as usize;
    if !(256..=512).contains(&n) || output[4+n..].iter().any(|b|*b!=0){return Err(())}
    Ok(output[4..4+n].to_vec())
}

pub(super) fn capture(mut command: Command, request: &[u8], reply_size: usize, deadline: Instant) -> Result<Vec<u8>, ()> {
    if Instant::now() >= deadline || request.len() > codec::LIMIT || reply_size > codec::LIMIT + 72 { return Err(()); }
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    unsafe { command.pre_exec(|| {
        if libc::setpgid(0, 0) == -1 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
    }); }
    let mut group = Group(command.spawn().map_err(|_| ())?);
    let mut input = Some(group.0.stdin.take().ok_or(())?);
    let mut output = group.0.stdout.take().ok_or(())?;
    nonblocking(input.as_ref().ok_or(())?.as_raw_fd())?; nonblocking(output.as_raw_fd())?;
    let mut sent = 0; let mut eof = false; let mut bytes = Vec::with_capacity(reply_size);
    loop {
        if Instant::now() >= deadline { return Err(()); }
        if let Some(pipe) = input.as_mut() {
            match pipe.write(&request[sent..]) {
                Ok(0) if sent < request.len() => return Err(()),
                Ok(n) => sent += n,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => (),
                Err(_) => return Err(()),
            }
            if sent == request.len() { input.take(); } // Real EOF before verification.
        }
        if !eof {
            let mut block = [0u8; 1024];
            match output.read(&mut block) {
                Ok(0) => eof = true,
                Ok(n) => { if bytes.len() + n > reply_size { return Err(()); } bytes.extend_from_slice(&block[..n]); }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => (),
                Err(_) => return Err(()),
            }
        }
        if let Some(status) = group.0.try_wait().map_err(|_| ())? {
            if !status.success() { return Err(()); }
            if eof { return if sent == request.len() && bytes.len() == reply_size { Ok(bytes) } else { Err(()) }; }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn python(code: &str) -> Command { let mut c=Command::new("python3");c.arg("-I").arg("-c").arg(code);c }
    #[test]
    fn la110_process_full_input_exact_output_and_success_required() {
        let req=vec![7;20000];
        let good="import sys; b=sys.stdin.buffer.read(); sys.stdout.buffer.write(bytes([len(b)//1000])*80)";
        assert_eq!(capture(python(good),&req,80,Instant::now()+Duration::from_secs(5)),Ok(vec![20;80]));
        for bad in ["import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'x'*81)",
                    "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'x'*79)",
                    "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'x'*80);sys.exit(1)"] {
            assert_eq!(capture(python(bad),&req,80,Instant::now()+Duration::from_secs(5)),Err(()));
        }
    }
    #[test]
    fn la110_process_blocked_stdin_and_descendant_eof_are_deadline_bounded() {
        for code in ["import time;time.sleep(30)",
                     "import os,sys,time\nsys.stdin.buffer.read()\nif os.fork()==0: time.sleep(30);os._exit(0)\nsys.stdout.buffer.write(b'x'*80);sys.stdout.flush();os._exit(0)"] {
            assert_eq!(capture(python(code),&vec![0;24000],80,Instant::now()+Duration::from_millis(300)),Err(()));
        }
    }
    #[test]
    fn la110_process_expired_deadline_does_not_spawn() {
        assert_eq!(capture(Command::new("/must-not-run"),&[],80,Instant::now()),Err(()));
    }
}
