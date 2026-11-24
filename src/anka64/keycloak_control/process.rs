//! Fixed helper, private pipes, bounded stdout and process-group lifetime.
use super::*;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Group(Child);
impl Drop for Group {
    fn drop(&mut self) {
        // pre_exec made this child its own group. Also reap on every error path.
        unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL); }
        let _ = self.0.wait();
    }
}
pub(super) fn worker(state: &Path, request: Request, deadline: Instant) -> Result<Vec<u8>, ()> {
    let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/keycloak/control.py");
    if !helper.is_file() || !request.valid() || Instant::now() >= deadline { return Err(()); }
    let mut command = Command::new("python3");
    command.arg("-I").arg(helper).arg("--state").arg(state);
    capture(command, &request.encode(), deadline)
}
fn capture(mut command: Command, request: &[u8; REQUEST_LEN], deadline: Instant) -> Result<Vec<u8>, ()> {
    if Instant::now() >= deadline { return Err(()); }
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    unsafe { command.pre_exec(|| {
        if libc::setpgid(0, 0) == -1 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
    }); }
    let mut child = Group(command.spawn().map_err(|_| ())?);
    // A single small request fits an initially empty pipe. Closing stdin makes
    // the worker require actual EOF before any credential read or mutation.
    let mut input = child.0.stdin.take().ok_or(())?;
    input.write_all(request).map_err(|_| ())?; drop(input);
    let mut output = child.0.stdout.take().ok_or(())?;
    let fd = output.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 { return Err(()); }
    let mut bytes = Vec::with_capacity(REPLY_LEN); let mut eof = false;
    loop {
        if Instant::now() >= deadline { return Err(()); }
        if !eof {
            let mut block = [0u8; REPLY_LEN + 1];
            match output.read(&mut block) {
                Ok(0) => eof = true,
                Ok(n) => { if bytes.len() + n > REPLY_LEN { return Err(()); } bytes.extend_from_slice(&block[..n]); }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => (),
                Err(_) => return Err(()),
            }
        }
        if let Some(status) = child.0.try_wait().map_err(|_| ())? {
            if !status.success() { return Err(()); }
            if eof { return if bytes.len() == REPLY_LEN { Ok(bytes) } else { Err(()) }; }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn python(code: &str) -> Command {
        let mut c=Command::new("python3");c.arg("-I").arg("-c").arg(code);c
    }
    #[test]
    fn ac110_process_requires_exact_stdout_and_successful_exit() {
        let command=python("import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'x'*120)");
        assert_eq!(capture(command,&[0;80],Instant::now()+Duration::from_secs(5)),Ok(vec![b'x';120]));
        for code in ["import sys;sys.stdout.buffer.write(b'x'*119)",
                     "import sys;sys.stdout.buffer.write(b'x'*121)",
                     "import sys;sys.stdout.buffer.write(b'x'*120);sys.exit(1)"] {
            assert_eq!(capture(python(code),&[0;80],Instant::now()+Duration::from_secs(5)),Err(()));
        }
    }
    #[test]
    fn ac110_process_full_frame_without_eof_cannot_beat_original_deadline() {
        let code="import sys,time;sys.stdout.buffer.write(b'x'*120);sys.stdout.flush();time.sleep(30)";
        assert_eq!(capture(python(code),&[0;80],Instant::now()+Duration::from_secs(1)),Err(()));
    }
    #[test]
    fn ac110_process_expired_deadline_never_spawns() {
        let c=Command::new("/this-command-must-not-be-executed");
        assert_eq!(capture(c,&[0;80],Instant::now()),Err(()));
    }
    #[test]
    fn ac110_process_descendant_holding_pipe_is_bounded_by_group_deadline() {
        let code="import os,sys,time\npid=os.fork()\nif pid==0: time.sleep(30);os._exit(0)\nsys.stdout.buffer.write(b'x'*120)\nsys.stdout.flush()\nos._exit(0)";
        assert_eq!(capture(python(code),&[0;80],Instant::now()+Duration::from_secs(1)),Err(()));
    }
}
