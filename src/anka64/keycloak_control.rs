//! AC110 host control-path integration, not exclusive writer mediation.
//! A real SA110 barrier closes before a bounded private worker changes the
//! disposable Podman realm. Only a fully correlated reply can clear pending.
//! The lab source NEVER attests control or supplies a candidate/grant/holder
//! proof; successful administration therefore cannot open live admission.
use super::authority_persistence::Verdict;
use super::authority_persistence::evidence::serialized_authority::{
    Change, Clock, Completion, Config, Coordinator, Error, Evidence, Mode, Now,
};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

const QMAGIC: &[u8; 8] = b"AC110Q1\0";
const RMAGIC: &[u8; 8] = b"AC110R1\0";
const REQUEST_LEN: usize = 80;
const REPLY_LEN: usize = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Request { action: u64, change: Change, nonce: [u64; 4] }
impl Request {
    fn encode(self) -> [u8; REQUEST_LEN] {
        let mut bytes = [0u8; REQUEST_LEN]; bytes[..8].copy_from_slice(QMAGIC);
        let words = [self.action, self.change.domain, self.change.incarnation, self.change.revision,
            self.change.command, self.nonce[0], self.nonce[1], self.nonce[2], self.nonce[3]];
        for (word, dest) in words.iter().zip(bytes[8..].chunks_exact_mut(8)) {
            dest.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
    fn valid(self) -> bool {
        matches!(self.action, 1 | 2) && self.change.domain != 0 && self.change.incarnation != 0 &&
        self.change.revision != 0 && self.change.command != 0 && self.nonce.iter().any(|n| *n != 0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reply { original: u64, target: u64, restored: u64, flags: u64 }
fn decode(request: Request, raw: &[u8]) -> Result<Reply, ()> {
    if !request.valid() || raw.len() != REPLY_LEN || &raw[..8] != RMAGIC || raw[8..80] != request.encode()[8..] {
        return Err(());
    }
    let word = |offset: usize| u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
    let value = Reply { original: word(88), target: word(96), restored: word(104), flags: word(112) };
    if word(80) != request.action || value.target > 2_147_483_647 || value.original >= value.target ||
        value.restored != value.original || value.flags != if request.action == 1 {31} else {8} {
        return Err(());
    }
    Ok(value)
}

/// One private completion slot; not a JSON authority or a bearer capability.
struct Mailbox(Rc<RefCell<Option<Completion>>>);
impl Evidence for Mailbox {
    type Peer = ();
    fn completion(&mut self, change: Change) -> Option<Completion> {
        self.0.borrow_mut().take().filter(|c| c.change == change)
    }
    // attest, candidate and fresh_incarnation retain their denying defaults.
}

fn exchange<C: Clock>(lane: &Coordinator<Mailbox, C>, slot: &Rc<RefCell<Option<Completion>>>,
    action: u64, nonce: [u64; 4], remote: impl FnOnce(Request) -> Result<Vec<u8>, ()>) -> Result<Reply, ()>
{
    if !matches!(action, 1 | 2) || nonce.iter().all(|n| *n == 0) { return Err(()); }
    let before = lane.view().map_err(|_| ())?;
    if before.mode != Mode::Closed || before.controlled != Verdict::Unknown || before.pending != 0 ||
        before.effects != 0 || before.remaining < 2 || slot.borrow().is_some() { return Err(()); }
    let change = lane.barrier(1).map_err(|_| ())?;
    let request = Request { action, change, nonce };
    // No guard is held across remote HTTP/subprocess work. Barrier has completed.
    let outcome = remote(request).and_then(|raw| decode(request, &raw));
    let Ok(reply) = outcome else { let _ = lane.invalidate(); return Err(()); };
    *slot.borrow_mut() = Some(Completion { change, policy: before.policy, keyset: before.keyset,
        checked: Verdict::Valid, enabled: Verdict::Unknown });
    let completed = lane.complete(change);
    let after = lane.view().map_err(|_| ())?;
    // SA110 correctly returns Denied because no exclusive control was attested.
    // This probe accepts only consumption of the exact completion while CLOSED.
    if completed != Err(Error::Denied) || after.pending != 0 || after.mode != Mode::Closed ||
        after.controlled != Verdict::Unknown || after.effects != before.effects || after.boot != before.boot ||
        after.deadline != before.deadline || after.remaining != before.remaining - 2 ||
        after.next_seq != before.next_seq + 2 || slot.borrow().is_some() {
        let _ = lane.invalidate(); return Err(());
    }
    Ok(reply)
}

struct HostClock { start: Instant }
impl Clock for HostClock {
    fn now(&mut self) -> Now {
        Now { tick: self.start.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            wall: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0) }
    }
}

#[cfg(unix)]
#[path="keycloak_control/process.rs"]
mod process;

/// Public only as a host binary entry point. No guest or Kernel API is exposed.
pub fn command(args: &[String]) -> i32 {
    if args.len() == 1 && args[0] == "--help" {
        println!("Usage: anka keycloak-control-lab --state PRIVATE_LAB_DIRECTORY [--recover]\n\
            Probes realm not-before revocation and restores it; no live/boot authority.\n\
            --recover only reconciles an existing private control-recovery.json.");
        return 0;
    }
    let valid = (args.len() == 2 || (args.len() == 3 && args[2] == "--recover")) &&
        args.first().is_some_and(|a| a == "--state") && !args[1].is_empty();
    if !valid {
        eprintln!("Invalid control-lab arguments; use --help."); return 2;
    }
    #[cfg(unix)]
    {
        let result = run(std::path::Path::new(&args[1]), args.len() == 3);
        if result.is_ok() {
            println!("{{\"schema\":1,\"status\":\"control_probe_valid\",\"action\":\"{}\",\"coordinator\":\"closed\",\"current_authority\":\"unknown\",\"live_admission\":false,\"boot_authorized\":false}}",
                if args.len() == 3 {"recover"} else {"probe"});
            return 0;
        }
    }
    println!("{{\"schema\":1,\"status\":\"control_probe_failed\",\"current_authority\":\"unknown\",\"live_admission\":false,\"boot_authorized\":false}}");
    eprintln!("Control probe failed. Inspect private control-failure-*.json if present. If control-recovery.json exists, use --recover before another probe. No automatic retry was performed.");
    1
}

#[cfg(unix)]
fn run(state: &std::path::Path, recover: bool) -> Result<Reply, ()> {
    use std::io::Read;
    let start = Instant::now();
    let mut random = [0u8; 32];
    std::fs::File::open("/dev/urandom").map_err(|_| ())?.read_exact(&mut random).map_err(|_| ())?;
    let nonce = std::array::from_fn(|i| u64::from_le_bytes(random[i * 8..i * 8 + 8].try_into().unwrap()));
    let slot = Rc::new(RefCell::new(None));
    // These IDs are laboratory handles only; no identity mapping is installed.
    let lane = Coordinator::new(Config { installation: 1, issuer: 1, policy: 1, keyset: 1,
        incarnation: 1, work: 8, deadline: 45_000, boot: 0 }, Mailbox(slot.clone()), HostClock { start }).map_err(|_| ())?;
    let deadline = start + std::time::Duration::from_secs(45);
    exchange(&lane, &slot, if recover {2} else {1}, nonce, |request| {
        process::worker(state, request, deadline)
    })
}

#[cfg(test)]
#[path="keycloak_control/tests.rs"]
mod tests;
