//! Reuse the existing fixed-point witness. All accepted producer bytes come
//! from guest CC2 and guest ankald, never the host-side source diagnostic.
use super::*;
use crate::anka64::ankald::AnkaldLinkedImage;
use crate::anka64::cc2_fixed_point::Cc2FixedPointWitness;
use crate::anka64::compiler_adapter::{producer, resources::{
    CompilerResourceBindings, OutputGrowthSupport, OutputRetryPolicy,
}};
use crate::anka64::dev_runner::DeveloperExecutionAuthority;
use crate::anka64::guest_compiler::{install_trap_handler, seal_code_object};
use crate::anka64::pointer_frames::ValidatedPointerProgram;
use std::time::{Duration, Instant};

// Heap authentication and PFRAME exclusion both inspect the legacy transaction
// vector. Retaining every completed fetch makes this fixture progressively
// slower. Bound *diagnostic history*, not authorization or guest work.
const PRODUCER_QUANTUM: usize = 256;
const PRODUCER_WORK_LIMIT: u64 = 1_000_000_000;

fn collect_producer_trace(k: &mut Kernel) -> bool {
    // This helper is test-only and restricted to the synchronous CPU fixture.
    // A controller may retain terminal vector indices: never collect its trace.
    if !k.device_registry.devices.is_empty()
        || k.fabric.agents.values().any(|a| !matches!(a.kind, AgentKind::Cpu(_)))
    {
        return false;
    }
    // Refuses ALL collection if any transaction is still nonterminal; retains
    // monotonic transaction IDs, fault_log, protected kinds and heap tickets.
    k.fabric.discard_completed_compiler_trace()
}

struct ProducerProgress {
    label: &'static str,
    started: Instant,
    reported: Duration,
    timeout: Duration,
    dispatched: u64,
}

impl ProducerProgress {
    fn new(label: &'static str) -> Self {
        let seconds = match std::env::var("ANKA_PRODUCER_TIMEOUT_SECS") {
            Ok(value) => value.parse::<u64>()
                .expect("ANKA_PRODUCER_TIMEOUT_SECS must be a positive integer"),
            Err(std::env::VarError::NotPresent) => 300,
            Err(error) => panic!("ANKA_PRODUCER_TIMEOUT_SECS: {error}"),
        };
        assert!(seconds > 0, "ANKA_PRODUCER_TIMEOUT_SECS must be positive");
        eprintln!("protected CC2 [{label}]: starting; diagnostic timeout={seconds}s");
        Self { label, started: Instant::now(), reported: Duration::ZERO,
            timeout: Duration::from_secs(seconds), dispatched: 0 }
    }

    fn check(&mut self, k: &Kernel, key: ProcessKey, quantum: usize) {
        self.dispatched += quantum as u64;
        let elapsed = self.started.elapsed();
        let process = &k.processes[key.slot];
        if elapsed.saturating_sub(self.reported) >= Duration::from_secs(5) {
            eprintln!("protected CC2 [{}]: {:.1}s dispatched_budget={} pc={:#x} state={:?}",
                self.label, elapsed.as_secs_f64(), self.dispatched,
                process.core.pc, process.state);
            self.reported = elapsed;
        }
        assert!(elapsed < self.timeout,
            "protected CC2 [{}] diagnostic timeout after {:.1}s; dispatched_budget={} pc={:#x} state={:?} registers={:x?}. This is not proof of guest nontermination. ANKA_PRODUCER_TIMEOUT_SECS controls the per-stage wall limit.",
            self.label, elapsed.as_secs_f64(), self.dispatched, process.core.pc,
            process.state, process.core.r);
    }

    fn done(&self) {
        eprintln!("protected CC2 [{}]: completed in {:.2}s; dispatched_budget={}",
            self.label, self.started.elapsed().as_secs_f64(), self.dispatched);
    }
}

fn machine(image: &AnkaldLinkedImage) -> (Kernel, ProcessKey) {
    // The tiny loader transport fixtures use 64 shared identity slots. A real
    // compiler also registers every live local/temporary, in addition to its
    // five heap regions. Reuse the existing bounded application profile.
    machine_with_fabric(image, Fabric::with_application_heap(0x1000000).unwrap())
}

fn machine_with_fabric(image: &AnkaldLinkedImage, fabric: Fabric) -> (Kernel, ProcessKey) {
    let mut k = Kernel::new(fabric);
    k.enable_heap_service(0x200000).unwrap();
    let domain = k.fabric.create_domain();
    let agent = AgentId(200);
    k.fabric.register_agent(agent, AgentKind::Cpu(CoreId(0)), domain);
    let code = &image.bytes[..image.code_size as usize];
    let program = ValidatedPointerProgram::from_image(code,
        &image.bytes[image.lit_start as usize..]).unwrap().unwrap();
    let size = (image.code_size + 16 + 4095) & !4095;
    assert!(size < 0x100000);
    let object = k.fabric.alloc_object("protected-cc2", size, ObjectKind::Memory);
    k.fabric.place_object(object, 0x10000);
    k.fabric.write_physical(0x10000, code);
    install_trap_handler(&mut k.fabric, 0x10000, size);
    seal_code_object(&mut k.fabric, object, domain);
    let mut core = Anka64Core::new(agent, domain);
    core.address_map.add(0, size, object);
    core.trap_vector = size - 16;
    let stack = k.fabric.alloc_object("protected-cc2-stack", 0x100000, ObjectKind::Memory);
    k.fabric.place_object(stack, 0x200000);
    k.fabric.grant(domain, stack, 0, 0x100000, Permissions::RW);
    core.address_map.add(0x1000000, 0x100000, stack);
    core.admit_pointer_program(&mut k.fabric, program, 0, 0x1000000, 0x1100000).unwrap();
    let key = k.spawn(core);
    (k, key)
}

fn budget(source: &[u8], capacity: u64) -> OutputRetryBudget {
    OutputRetryPolicy::new(0x100000, 8, PRODUCER_WORK_LIMIT).unwrap().start(
        CompilerReplyContext::new(71, 1, CompilerResourceBindings {
            source: 21, tools: 22, profile: 23, dependencies: 24, plan: 25,
        }, source.len() as u64, capacity, OutputGrowthSupport::CompilerOutput).unwrap()
    ).unwrap()
}

// Test-only output capture. Fabric reads are bounded to 4096 bytes even when
// the allocation and the successful artifact are larger. Derive every chunk
// from the original protected token and reauthenticate each read.
fn read_producer_output(k: &Kernel, attempt: &CompilerOutputAttempt, used: u64)
    -> Result<Vec<u8>, HeapError>
{
    k.fabric.authenticate_heap_token(attempt.owner, attempt.agent, attempt.output)?;
    let capacity = attempt.budget.as_ref().ok_or(HeapError::Size)?
        .context().output_capacity();
    if used > capacity { return Err(HeapError::Size); }
    let length = usize::try_from(used).map_err(|_| HeapError::Size)?;
    let mut output = vec![0; length];
    for (index, chunk) in output.chunks_mut(4096).enumerate() {
        let offset = i64::try_from(index * 4096).map_err(|_| HeapError::Size)?;
        let pointer = k.fabric.scoped_pointers.add_heap_pointer(
            attempt.output, attempt.owner, offset)?;
        k.fabric.read_heap_bytes(attempt.owner, attempt.agent, pointer, chunk)?;
    }
    Ok(output)
}

// Test-only observation at the authenticated exit boundary, before the ordinary
// bridge retires the owner. C2.5 must implement production artifact capture and
// admission; this helper does not pretend that terminal metadata publishes it.
fn observe(label: &'static str, image: &AnkaldLinkedImage, source: &[u8], capacity: u64)
    -> (CompilerReplyMetadata, Vec<u8>)
{
    let (mut k, key) = machine(image);
    let mut attempt = k.load_compiler_request(key, budget(source, capacity), source).unwrap();
    let context = attempt.budget.as_ref().unwrap().context();
    let mut stopped = false;
    let mut progress = ProducerProgress::new(label);
    assert!(collect_producer_trace(&mut k));
    for _ in 0..PRODUCER_WORK_LIMIT / PRODUCER_QUANTUM as u64 {
        attempt.budget.as_mut().unwrap().reserve_work(PRODUCER_QUANTUM as u64).unwrap();
        let at_exit = k.run_process_with_exit_stop(key.slot, PRODUCER_QUANTUM, true);
        progress.check(&k, key, PRODUCER_QUANTUM);
        assert!(collect_producer_trace(&mut k), "producer trace has live work or device handles");
        if at_exit { stopped = true; break; }
        assert_eq!(k.processes[key.slot].state, ProcessState::Running,
            "ABI-2 producer faulted: pc={:#x}", k.processes[key.slot].core.pc);
    }
    assert!(stopped, "ABI-2 producer exhausted its work budget");
    let (words, kinds) = k.processes[key.slot].core.protected_syscall_image().unwrap();
    assert_eq!(&words[..2], &[SYS_EXIT, 0]);
    assert!(kinds[0].is_none());
    let reply = k.fabric.read_compiler_capacity_reply(attempt.owner, attempt.agent,
        attempt.output, attempt.reply, capacity).unwrap();
    let report = context.decode(&reply).unwrap();
    let mut output = Vec::new();
    if let CompilerReplyMetadata::SuccessMetadata { used_output } = report {
        output = read_producer_output(&k, &attempt, used_output)
            .expect("capture successful producer output through bounded authenticated reads");
    }
    k.finish_process(key.slot, ProcessResult::Exited(0));
    assert!(k.fabric.read_heap_bytes(attempt.owner, attempt.agent, attempt.output, &mut [0;8]).is_err());
    progress.done();
    (report, output)
}

pub(crate) fn check_protected_producer(lineage: &Cc2FixedPointWitness,
    authority: &DeveloperExecutionAuthority)
{
    let image = producer::build(lineage, authority)
        .unwrap_or_else(|error| panic!("build protected ABI-2 CC2: {error}"));
    eprintln!("protected CC2 producer: code={} backing={} entry={}",
        image.code_size, image.bytes.len(), image.entry);
    let program = ValidatedPointerProgram::from_image(&image.bytes[..image.code_size as usize],
        &image.bytes[image.lit_start as usize..]).unwrap().unwrap();
    let entry = program.frames.iter().find(|frame| frame.entry == 0).unwrap();
    eprintln!("protected CC2 frame budget: entry_locals={} largest_frame_locals={} ABI_regions=5 registry_slots=4096",
        entry.locals.len(), program.frames.iter().map(|frame| frame.locals.len()).max().unwrap());
    let source = b"int main(){int x=41;int *p=&x;return *p+1;}";
    let (report, output) = observe("exact AOM", &image, source, 65536);
    assert!(matches!(report, CompilerReplyMetadata::SuccessMetadata { .. }));
    let (compiler, _, _) = lineage.application_tools().unwrap();
    eprintln!("protected CC2: compiling reference AOM with accepted lineage");
    let reference = crate::anka64::dev_compiler::compile_protected_application_aom_with_linked_compiler(
        compiler, source, authority).unwrap();
    assert_eq!(output, reference.bytes, "ABI-2 must preserve exact protected AOM bytes");
    crate::anka64::pointer_frames::ValidatedPointerModule::from_aom(&output).unwrap();

    let (_, adequate) = observe("capacity independence", &image, source, 131072);
    assert_eq!(output, adequate, "adequate arena capacity must not affect artifact bytes");
    let mut larger = String::from("int main(){int x=0;");
    larger.push_str(&"x=x+1;".repeat(70));
    larger.push_str("return x;}");
    let (mut k, key) = machine(&image);
    let mut attempt = k.load_compiler_request(key, budget(larger.as_bytes(), 4096), larger.as_bytes()).unwrap();
    let mut progress = ProducerProgress::new("NeedCapacity");
    assert!(collect_producer_trace(&mut k));
    let mut pending = loop {
        let slice = k.run_compiler_retry_slice(&mut attempt, PRODUCER_QUANTUM).unwrap();
        progress.check(&k, key, PRODUCER_QUANTUM);
        assert!(collect_producer_trace(&mut k), "producer trace has live work or device handles");
        match slice {
            CompilerSlice::Running => {},
            CompilerSlice::AwaitingCleanup(pending) => break pending,
        }
    };
    progress.done();
    let mut progress = ProducerProgress::new("owner cleanup");
    let mut released = None;
    for _ in 0..200_000 {
        released = k.poll_compiler_retry(&mut pending).unwrap();
        progress.check(&k, key, 0);
        if released.is_some() { break; }
    }
    let next = released.expect("actual owner cleanup must release the next budget");
    progress.done();
    assert!(next.context().output_capacity() > 4096);
    let (report, larger_output) = observe("adequate output", &image, larger.as_bytes(), 65536);
    assert!(matches!(report, CompilerReplyMetadata::SuccessMetadata { .. }));
    // The ABI-1 reference retains the original ordinal-search algorithm.
    // Compare the multi-local case too: this covers ABI-2's linear traversal,
    // not just the one-local/tiny-source path above.
    eprintln!("protected CC2: comparing multi-local AOM with accepted lineage");
    let reference = crate::anka64::dev_compiler::compile_protected_application_aom_with_linked_compiler(
        compiler, larger.as_bytes(), authority).unwrap();
    assert_eq!(larger_output, reference.bytes,
        "linear local-metadata traversal must preserve exact protected AOM bytes");
    crate::anka64::pointer_frames::ValidatedPointerModule::from_aom(&larger_output).unwrap();

    let (report, bytes) = observe("source rejection", &image, b"int main(){return missing;}", 65536);
    assert!(matches!(report, CompilerReplyMetadata::SourceRejected { .. }));
    assert!(bytes.is_empty());
    let mut tables = String::new();
    for i in 0..65 { tables.push_str(&format!("int f{i}(){{return 0;}}")); }
    let (report, bytes) = observe("table exhaustion", &image, tables.as_bytes(), 65536);
    assert!(matches!(report, CompilerReplyMetadata::RepresentationRejected { diagnostic: 8, .. }));
    assert!(bytes.is_empty(), "table exhaustion must not become an output retry");
    eprintln!("protected CC2 ABI 2: exact AOM, capacity independence, real NeedCapacity/cleanup and terminal rejection passed");
}

#[path = "producer_entry_tests.rs"]
mod entry_tests;
