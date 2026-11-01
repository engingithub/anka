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
    workspace: Option<(AllocationOwner,AgentId,ScopedPointer)>,
    source_length: u64,
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
            timeout: Duration::from_secs(seconds), dispatched: 0, workspace: None, source_length: 0 }
    }

    // Observe the authentic workspace token captured from the loaded request,
    // not guessed physical memory or whichever register currently holds cx.
    // Only diagnostic reports read it; no scan on every dispatch slice.
    fn source_cursor(&self,k:&Kernel) -> Option<u64> {
        let (owner,agent,pointer)=self.workspace?;
        let mut bytes=[0u8;8];
        k.fabric.read_heap_bytes(owner,agent,pointer,&mut bytes).ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    fn check(&mut self, k: &Kernel, key: ProcessKey, quantum: usize) {
        self.dispatched += quantum as u64;
        let elapsed = self.started.elapsed();
        let process = &k.processes[key.slot];
        if elapsed.saturating_sub(self.reported) >= Duration::from_secs(5) {
            eprintln!("protected CC2 [{}]: {:.1}s dispatched_budget={} pc={:#x} state={:?} source_cursor={:?}/{}",
                self.label, elapsed.as_secs_f64(), self.dispatched,
                process.core.pc, process.state,self.source_cursor(k),self.source_length);
            self.reported = elapsed;
        }
        assert!(elapsed < self.timeout,
            "protected CC2 [{}] diagnostic timeout after {:.1}s; dispatched_budget={} pc={:#x} state={:?} registers={:x?} source_cursor={:?}/{}. This is not proof of guest nontermination. ANKA_PRODUCER_TIMEOUT_SECS controls the per-stage wall limit.",
            self.label, elapsed.as_secs_f64(), self.dispatched, process.core.pc,
            process.state, process.core.r,self.source_cursor(k),self.source_length);
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

// Exercise production capture, independent retention and real cleanup. Only the diagnostic
// comparison Vec escapes: it is test-owned, never publication authority.
fn observe(label: &'static str, image: &AnkaldLinkedImage, source: &[u8], capacity: u64)
    -> (CompilerReplyMetadata, Vec<u8>)
{
    observe_workspace(label,image,source,capacity,None)
}

fn observe_workspace(label: &'static str,image: &AnkaldLinkedImage,source: &[u8],capacity: u64,
    directory: Option<crate::anka64::compiler_adapter::resources::growth::workspace::WorkspaceDirectory>)
    -> (CompilerReplyMetadata,Vec<u8>)
{
    use super::capture::{CompilerCaptureError, CompilerCaptureSlice};
    use crate::anka64::compiler_adapter::RebuildAdmissionRole;
    let (mut k, key) = machine(image);
    let input=if directory.is_some() { k.ingest_compiler_directory_source(source) }
        else { k.ingest_compiler_input(super::inputs::CompilerInputRole::EffectiveSource,source) }.unwrap();
    let loaded=match directory {
        Some(d)=>k.load_compiler_input_with_workspace(key,budget(source,capacity),&input,d),
        None=>k.load_compiler_request_from_input(key,budget(source,capacity),&input),
    };
    k.discard_compiler_input(&input).unwrap();
    let mut attempt=loaded.unwrap();
    let mut progress = ProducerProgress::new(label);
    let request=k.processes[key.slot].core.authenticated_pointer(&k.fabric,R0).unwrap().unwrap();
    let cell=k.fabric.scoped_pointers.add_heap_pointer(request,attempt.owner,288).unwrap();
    let workspace=k.fabric.load_heap_pointer_cell(attempt.owner,attempt.agent,cell).unwrap().unwrap();
    progress.workspace=Some((attempt.owner,attempt.agent,workspace));
    progress.source_length=source.len() as u64;
    assert!(collect_producer_trace(&mut k));
    for _ in 0..PRODUCER_WORK_LIMIT / PRODUCER_QUANTUM as u64 {
        let result = match k.run_compiler_capture_slice(&mut attempt, PRODUCER_QUANTUM,
            RebuildAdmissionRole::RelocatableModule) {
            Ok(CompilerCaptureSlice::Running) => None,
            Ok(CompilerCaptureSlice::Captured(capture)) => {
                // Retain first; capture's Drop then closes the producer owner.
                Some(Ok(capture.retain().expect("independent candidate reservation")))
            }
            Err(CompilerCaptureError::Runtime(CompilerRuntimeError::TerminalMetadata(report))) =>
                Some(Err(report)),
            Ok(CompilerCaptureSlice::AwaitingCleanup(_)) => panic!("adequate-output observer unexpectedly needs capacity"),
            Err(error) => panic!("production capture/admission failed: {error:?}"),
        };
        progress.check(&k, key, PRODUCER_QUANTUM);
        assert!(collect_producer_trace(&mut k), "producer trace has live work or device handles");
        if let Some(result) = result {
            assert!(k.fabric.read_heap_bytes(attempt.owner, attempt.agent, attempt.output, &mut [0;8]).is_err());
            let result = match result {
                Err(report) => (report, Vec::new()),
                Ok(handle) => {
                    let mut ready = false;
                    for _ in 0..200_000 {
                        if k.poll_compiler_candidate(&handle).unwrap() { ready = true; break; }
                        progress.check(&k, key, 0);
                    }
                    assert!(ready, "retained candidate requires exact producer cleanup");
                    let view = k.compiler_candidate(&handle).unwrap().unwrap();
                    assert_eq!(view.producer, attempt.owner);
                    assert_eq!(view.role, RebuildAdmissionRole::RelocatableModule);
                    let bytes = view.bytes.to_vec(); // Test-owned comparison only.
                    k.discard_compiler_candidate(&handle).unwrap();
                    (CompilerReplyMetadata::SuccessMetadata { used_output: bytes.len() as u64 }, bytes)
                }
            };
            progress.done();
            return result;
        }
        assert_eq!(k.processes[key.slot].state, ProcessState::Running,
            "ABI-2 producer faulted: pc={:#x}", k.processes[key.slot].core.pc);
    }
    panic!("ABI-2 producer exhausted its work budget");
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
    publication_tests::check(&image,lineage,authority);

    let (report, bytes) = observe("source rejection", &image, b"int main(){return missing;}", 65536);
    assert!(matches!(report, CompilerReplyMetadata::SourceRejected { .. }));
    assert!(bytes.is_empty());
    let mut tables = String::new();
    for i in 0..65 { tables.push_str(&format!("int f{i}(){{return 0;}}")); }
    let (report, bytes) = observe("table exhaustion", &image, tables.as_bytes(), 65536);
    assert!(matches!(report, CompilerReplyMetadata::RepresentationRejected { diagnostic: 8, .. }));
    assert!(bytes.is_empty(), "table exhaustion must not become an output retry");
    eprintln!("protected CC2 ABI 2: real retry/publication integration and terminal rejection passed");
}

#[path = "producer_entry_tests.rs"]
mod entry_tests;

#[path = "producer_publication_tests.rs"]
mod publication_tests;

#[path = "workspace_producer_tests.rs"]
mod workspace_tests;
