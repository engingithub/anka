# Anka Project and Anka64 Architectural Principles

## 1. Project Purpose

**Anka** is a vertically integrated computer architecture project built from the bottom up.

The project began as an MC68000 emulator written in Rust and quickly grew into a complete experimental computing stack:

- MC68000 CPU emulator
- Memory and MMIO bus
- Console device
- ROM monitor
- Programmatic machine-code assembler backend
- Textual assembler (**AnkaASM**)
- Motorola S-record loader/writer
- Calling convention (**ACC v0**)
- Tiny C compiler (**AnkaCC**)
- Timer interrupts
- Supervisor/user mode
- Preemptive multitasking
- Capability-based memory protection
- Object table and generation-based revocation
- DMA agent support
- Secure OS experiments
- Hostile guest programs
- Kleis/Z3 formal verification of protection invariants

The long-term goal is not to reproduce the MC68000 indefinitely.

The 68000 is the experimental scaffold used to discover which architectural ideas survive contact with a real compiler, real operating-system code, asynchronous events, hostile software, and formal verification.

The eventual architecture is **Anka64**: a clean 64-bit machine designed from those lessons rather than inherited historical conventions.

---

## 2. Development Philosophy

The central development rule is:

> **Every architectural feature should acquire a demanding client above it.**

Unit tests exercise behaviors the implementer imagined.

Real software exercises behaviors the machine actually encounters.

The project repeatedly demonstrated this distinction.

A one-bit MOVEM decoder error survived dozens of tests, a working assembler, a working compiler, and ordinary guest programs. It was exposed only when the operating system became the first real client requiring MOVEM-to-registers for context switching.

The working methodology is therefore:

```text
design
  ↓
implement
  ↓
build a real client
  ↓
let the client break the abstraction
  ↓
fix the architecture
  ↓
turn the failure into a regression test
  ↓
formalize the invariant
```

A design is not considered strong merely because it looks elegant in isolation.

It must survive:

1. real software,
2. hostile software,
3. implementation tests,
4. symbolic/formal adversaries.

---

## 3. Current Vertical Stack

The current stack is the Anka64 self-hosted toolchain:

```text
Canonical Anka source (~17 KB, 46 functions)
          │
          ▼
  Self-hosted AnkaCC64 (63,808-byte fixed-point compiler)
          │
          ▼
  29-instruction Anka64 ISA
          │
          ▼
  Protected capability fabric
          │
    ┌─────┴─────┐
    ▼           ▼
 CPU cores    DMA / agents
    │           │
    └─────┬─────┘
          ▼
     Secure OS (SYS_EXIT, SYS_WRITE, SYS_SEAL, SYS_EXEC)
```

The compiler is self-hosting.  The bootstrap relation is:

```text
CC_A (bootstrap seed, 45 functions) ──compile──→ CC_B (63,808 bytes, 46 functions)
CC_B (authoritative compiler)       ──compile──→ CC_C (63,808 bytes, 46 functions)
                                                 CC_B == CC_C  (fixed point)
```

CC_A is a frozen bootstrap seed.  It compiles canonical source but does
not itself implement every compiler semantic.  CC_B is the authoritative
compiler artifact.  CC_C proves CC_B is correct.  New compiler features
go into canonical source and are tested through CC_B, not by modifying
CC_A.

The MC68000 stack (AnkaCC, AnkaASM, S-record loader, ROM monitor)
remains in the codebase as the experimental scaffold from which the
Anka64 architecture was derived.  It is no longer the primary development
target.

Formal verification sits beneath and beside the implementation:

```text
Hostile guest programs
        ↓
Rust implementation
        ↓
Kleis / Z3 model
```

Each layer answers a different question.

### Hostile programs

> Can a constructible program violate the implementation?

### Rust implementation and tests

> Does the code correctly implement the intended architecture?

### Kleis / Z3

> Can any representable transaction violate the abstract invariant?

None of these layers replaces the others.

---

## 4. Major Milestones

The project evolved through several major stages.

### Stage 1 — CPU execution

The initial machine executed:

```text
42 + 10 = 52
```

This established instruction fetch, decode, register state, arithmetic, program counter evolution, and cycle accounting.

### Stage 2 — Observable I/O

A memory-mapped console established:

```text
CPU
 → effective address
 → bus
 → MMIO
 → device
 → stdout
```

The machine was no longer merely manipulating invisible register state.

### Stage 3 — ROM monitor

The monitor allowed guest code to:

- inspect memory,
- modify memory,
- jump to arbitrary guest addresses.

A user could enter machine code byte-by-byte and execute it.

This established a primitive development environment *inside the emulated machine*.

### Stage 4 — ABI and object representation

ACC v0 established register and stack conventions.

Motorola S-record support separated object representation from emulator internals.

### Stage 5 — AnkaASM

A textual assembler was layered over the shared machine-code backend.

The same backend was used by:

- built-in programs,
- the monitor,
- external assembly,
- later, the compiler.

The Asm builder therefore became a machine-code intermediate representation rather than merely a convenience API.

### Stage 6 — AnkaCC

A C compiler established:

```text
C
 → compiler
 → machine code
 → S-record
 → CPU
```

The compiler exercised stack frames, function calls, ABI behavior, arithmetic, control flow, pointers, and strings.

### Stage 7 — Preemptive AnkaOS

Timer interrupts introduced asynchronous events.

The machine ceased to be merely:

```text
S[n+1] = I(S[n])
```

and became conceptually:

```text
S[n+1] = F(S[n], I[n], E[n])
```

where `E_n` includes external asynchronous events such as interrupts.

Two independent C programs were preemptively scheduled without yielding.

This stage exposed the MOVEM decoder bug that previous layers had missed.

### Stage 8 — Hostile-world protection

User/supervisor separation and capability-based protection were added.

Hostile programs attempted:

- writing another process's stack,
- rewriting exception vectors,
- rewriting scheduler state,
- changing the active protection domain,
- executing privileged instructions,
- crafting RTE frames.

The protection boundary was hardened until all hostile vectors were rejected.

### Stage 9 — Object lifecycle and DMA

The protection model was extended with:

- named objects,
- generation counters,
- capability attenuation,
- revocation,
- DMA access through the same protection fabric.

A device retained a stale capability after process death and repeatedly attempted access.

Every stale access was rejected.

### Stage 10 — Formal protection theory

Kleis/Z3 was used to formalize and prove the protection rules.

The formal work exposed specification and implementation weaknesses including:

- zero-length/zero-operation transactions,
- control-plane exclusion semantics,
- order-dependent capability scans,
- excessive kernel-data delegation,
- capability-forgery boundaries.

Each discovered weakness was fixed in the implementation and converted into a regression test.

### Stage 11 — Anka64 state and ISA

A clean 64-bit architecture was designed from the lessons of Stages 1–10.  The ISA uses a table-driven description (`desc.rs`) that serves as the single source of truth for the decoder, assembler, disassembler, and Kleis theory generator.  29 instructions.

### Stage 12 — Single-source ISA and compiler/OS bring-up

AnkaCC64 was built as a Rust AST-to-machine-code compiler targeting the 29-instruction ISA.  The OS kernel (syscalls, process lifecycle, trap handling) was co-developed.  The table-driven ISA description ensured the compiler and CPU agreed on encodings.

### Stage 13 — Multicore, sequential consistency, and atomics

Multiple CPU cores and DMA agents share the capability fabric.  The consistency model is sequential consistency.  XCHG provides atomic read-modify-write.  Per-transaction access context (Rule 20) was implemented.

### Stage 14 — Executable object lifecycle, W⊕X, protected returns

- W⊕X enforcement: Active objects reject EXECUTE grants; Sealed objects reject WRITE grants.  No object is simultaneously writable and executable.
- SYS_SEAL transitions Active → Sealed with generation bump.
- Protected return authority: CALL mints a return-stack entry; RET validates against it.  Corrupted LR faults with ControlFlowViolation.  An executable address is not control-flow authority (Rule 29).

### Stage 15 — Guest compiler (Phase 6A–6B.4)

The host compiler compiled user programs to machine code entirely within Anka64.  `int main() { return 42; }` was compiled and executed as a guest process.  The compiler grew through variables, if/else, while, user-defined functions, parameter ABI, recursion, and factorial.

### Stage 16 — Canonical compiler source (Phase 6B.5.0)

All 42 compiler functions were rewritten as canonical Anka source text — ordinary programs in the language the compiler compiles.  The lexer, tokenizer, encoding layer, symbol/function/fixup tables, expression compiler, statement/control-flow compiler, and compiler main all exist as source.

### Stage 17 — Self-hosting fixed point (Phase 6B.5.1)

CC_A compiled canonical source → CC_B (57,176 bytes).  CC_B compiled canonical source → CC_C (57,176 bytes).  CC_B and CC_C are byte-identical.  CC_C passes a permanent 22-program semantic regression corpus.  The compiler is a fixed point of itself.

### Stage 18 — UTF-8 text literals and byte-buffer I/O (Phase 7)

Phase 7 established the complete text pipeline:

```text
UTF-8 source → validated string literal → immutable R-only object
→ pointer + explicit byte length → buffer SYS_WRITE → external UTF-8 bytes
```

The semantic boundaries are:

- **Bytes ≠ Text**.  String literals are validated RFC 3629 UTF-8.
- **byte length ≠ codepoint count ≠ grapheme count**.  Only byte length is tracked.
- **No NUL termination**.  Explicit byte length, embedded NUL is legal.
- **Validation is a gate, not a transcoder**.  No normalization, no replacement characters.  Input bytes = output bytes.

Key sub-phases:

- **7.0**: String literal tokenization (TOK_STRING, source-slice name representation).
- **7.1**: Literal object representation (separate R-only buffer, write_byte RMW, store_literal with length header).
- **7.2**: Two-ended executable image allocator (code grows upward, literals grow downward, disjoint authority via SYS_EXEC).
- **7.3**: Buffer-based SYS_WRITE with single-capability range authorization, sequential observation, and output-atomic commit.
- **7.4**: UTF-8 validation gate in canonical source only.  CC_A frozen as bootstrap seed.

Phase 7.4 established a post-self-hosting development process: new compiler semantics are implemented in canonical source and tested through CC_B, without modifying the CC_A bootstrap seed.  This was the first phase to fully embrace the distinction between CC_A (bootstrap seed) and CC_B (authoritative compiler).

At the current stage, the project has **393 tests with zero failures**.

---

# 5. The Anka64 Design Goal

Anka64 is not intended to be “a 64-bit 68000.”

The MC68000 provides useful inspiration:

- orthogonal instruction design,
- explicit operand sizes,
- readable assembly,
- clean register structure,
- supervisor/user distinction,
- exception-driven control transfer.

But Anka64 should not inherit historical constraints merely for compatibility.

The architectural question is:

> **What machine would we design today if the compiler, OS, protection model, devices, and formal semantics were co-designed from the beginning?**

---

# 6. Fundamental Anka64 Principles

## Rule 1 — Authority, placement, and consistency are separate concerns

Anka64 must not conflate:

```text
authority     = may this agent perform this operation?
placement     = where are the bytes physically located?
consistency   = when do other agents observe the operation?
```

Formally:

```text
authority != translation != coherence/consistency
```

Traditional paging often entangles all three.

Anka64 should keep them architecturally distinct.

---

## Rule 2 — The memory transaction is the unit of authorization

Protection must be applied to the **entire transaction before decomposition into bus beats**.

The core request shape is:

```rust
struct MemoryRequest {
    context: AccessContext,
    object: ObjectId,
    generation: Generation,
    offset: u64,
    width: Width,
    kind: AccessKind,
}
```

where:

```rust
struct AccessContext {
    agent: AgentId,
    domain: DomainId,
    privilege: Privilege,
}
```

The authorization function is conceptually:

```text
authorize(R) in {allow, deny}
```

before translation or physical access occurs.

---

## Rule 3 — Denied transactions have no side effects

The central noninterference invariant is:

```text
if !authorize(R):
    ordinary_state_after(R) = ordinary_state_before(R)
```

except for fault metadata.

More explicitly:

```text
if !authorize(R):
    M' = M
    D' = D
    O' = O
    C' = C
    L' = L ++ [fault(R)]
```

where:

- `M` = memory state,
- `D` = device state,
- `O` = object/translation state,
- `C` = architectural control state,
- `L` = fault log.

This property is foundational.

Everything above the protection fabric should be able to assume it.

---

## Rule 4 — Every bus master is an agent

CPUs are not privileged conceptually simply because they are CPUs.

Every entity capable of initiating memory transactions is an **agent**:

```text
CPU core
DMA engine
GPU
storage controller
network controller
accelerator
future coprocessor
```

The same authority model must apply to all of them.

A device must not gain omnipotent memory access merely because it performs DMA.

---

## Rule 5 — Protection belongs to domains, not CPU cores

A process or protection domain may migrate between cores.

Authority therefore belongs to the executing domain, not to a particular physical core.

Conceptually:

```text
Core 0 runs Domain 7
Core 3 later runs Domain 7
```

The authority remains the same.

A scheduler should not need to rebuild the protection universe during migration.

---

## Rule 6 — Capabilities represent authority

A capability identifies authority over an object.

Conceptually:

```text
C = (O, g, o, length, permissions)
```

where:

- `O` = object identity,
- `g` = generation / revocation epoch,
- `o` = offset within the object,
- `length` = extent,
- `permissions` = permissions.

Permissions include at least:

```text
Read
Write
Execute
```

and may later include domain-specific rights.

---

## Rule 7 — Capabilities may be attenuated, never amplified

Delegation must obey:

```text
Authority(C_child) <= Authority(C_parent)
```

A derived capability may:

- narrow its range,
- reduce permissions,
- possibly shorten lifetime.

It may not:

- widen range,
- add permissions,
- change object identity,
- resurrect a revoked generation.

The formal principle is:

```text
C' <- derive(C)
therefore Authority(C') <= Authority(C)
```

---

## Rule 8 — Authority cannot arise from nowhere

No user or device may manufacture new authority merely by constructing bit patterns.

Capability creation must be controlled.

The architectural invariant is:

> **Authority cannot arise from nowhere.**

Capability construction must therefore be mediated by trusted minting/derivation operations or by hardware-backed unforgeable representations.

---

## Rule 9 — Revocation is generation-based

Objects possess generations.

A capability is valid only when:

```text
g_C = g_O
```

Revocation changes the object's generation:

```text
g_O <- g_O + 1
```

making all old capabilities stale.

Thus:

```text
if g_C != g_O:
    access denied
```

This rule applies equally to:

- CPU references,
- shared memory,
- DMA,
- future GPU/accelerator queues.

---

## Rule 10 — Object identity is not physical address

An object should remain conceptually the same object when moved.

Authority should therefore reference logical object identity.

Translation later resolves:

```text
(O, offset) -> physical location
```

Physical placement is not itself authority.

---

## Rule 11 — User code cannot access control-plane state merely by address

Control-plane resources include things such as:

- active protection domain,
- capability/object-management registers,
- interrupt-controller state,
- scheduler-critical machine state,
- privileged device-control regions.

A broad ordinary memory capability must not accidentally imply control-plane authority.

Control-plane exclusion is part of the definition of authorization.

---

## Rule 12 — Kernel policy is separate from protection mechanism

A correct capability mechanism can faithfully enforce a bad policy.

Therefore:

```text
mechanism correctness !=> policy correctness
```

The OS must be tested for what authority it actually delegates.

For example, kernel scheduler state must never be delegated writable to ordinary user processes.

---

## Rule 13 — Capability collections have set semantics

If a domain contains multiple capabilities, authorization is existential:

```text
authorize(D, R) iff there exists C in D such that:
    valid(C) and C authorizes R
```

Capability ordering must not change authority.

Adding a capability must not revoke authority granted by another valid capability.

Monotonicity should hold:

```text
Authority(D1) <= Authority(D2)
    implies
Allowed(D1) <= Allowed(D2)
```

unless an explicit deny/revocation mechanism is separately defined.

---

## Rule 14 — A request must be real

A transaction must have a nonzero width and a real operation.

For the current model:

```text
width > 0 and operation != none
```

Zero-length or zero-operation accesses are rejected before range checking.

There is no architectural “empty memory transaction.”

---

## Rule 15 — Fetch, read, and write are distinct operations

Instruction fetch must not be modeled as ordinary data read.

Anka64 should distinguish:

```rust
enum AccessKind {
    Fetch,
    Read,
    Write,
}
```

This enables real execute permission and meaningful W⊕X policy.

---

## Rule 16 — Privilege and authority checks happen before operand effects

The architectural invariant is:

> **Privilege/authority validation precedes all architecturally visible operand access.**

A faulting or privileged instruction must not partially alter state before the fault is recognized.

This is required for precise, restartable faults.

---

## Rule 17 — Faults should be precise and forensic

Protection faults should carry enough information to reconstruct the attempted transaction.

A future fault record should include at least:

```text
agent
domain
privilege
object
generation
offset/address
width
operation
program counter
fault reason
```

Possible reasons include:

```text
NoCapability
WrongPermission
StaleGeneration
InvalidObject
ControlPlaneDenied
ExecuteDenied
OutOfBounds
DeviceAccessDenied
```

---

## Rule 18 — DMA uses the same protection ontology as CPUs

DMA must not bypass CPU protection.

A device receives delegated authority to a buffer/object.

Example:

```text
C_DMA = (O_buffer, g, 0, 4096, {Write})
```

The device may write only through that capability.

This provides IOMMU-like security without inventing a separate protection philosophy for devices.

---

## Rule 19 — Device access itself is capability-mediated

Knowing an MMIO address must not automatically grant device authority.

User-space drivers should receive capabilities for specific device objects or register regions.

This supports:

- user-space drivers,
- fault containment,
- least privilege,
- device isolation.

---

## Rule 20 — Multicore protection must be per transaction

Global bus fields such as:

```text
current_domain
supervisor
```

cannot represent multiple simultaneous CPU cores.

Every request must therefore carry its own access context.

For example:

```text
CPU0: supervisor, kernel domain
CPU1: user, process 7
DMA0: delegated buffer capability
```

may all coexist simultaneously.

---

## Rule 21 — Concurrency must not create authority

The eventual concurrent invariant is stronger than single-core protection:

> **No agent can increase its authority through concurrency.**

In particular, Anka64 must define the interaction between:

```text
authorize transaction
        │
        └── races with ── revoke object
```

The architecture must explicitly choose whether an already-authorized in-flight transaction:

- commits,
- aborts,
- or participates in a generation/epoch protocol.

That choice must then be formalized.

---

## Rule 22 — No transaction may commit under stale authority

A likely target invariant is:

> **No transaction authorized under generation `g` may commit after revocation to `g + 1`.**

unless the architecture explicitly defines grandfathered in-flight transactions.

This is a central future concurrency theorem.

---

# 7. Secure OS Principles

Anka Secure OS should consume hardware authority explicitly rather than reconstructing it from raw addresses.

## Process creation

Process creation should allocate objects and initial capabilities.

It should not merely assign address ranges.

## Syscalls

Syscalls are controlled transitions into privileged authority.

User code should request authority or services through explicit system calls rather than direct access to kernel state.

## IPC

IPC must answer:

> What authority is transferred with this message?

Authority transfer should be explicit.

## Shared memory

Shared memory is explicit shared authority over an object.

Different participants may receive different permissions.

For example:

```text
Process A: RW
Process B: R
Device C: W
```

## File handles and services

Handles should represent capabilities to objects or services, not merely integer indices without authority semantics.

## Drivers

Drivers should ideally operate as user-space services holding narrowly scoped device capabilities.

## Process exit

Process death must trigger object lifecycle handling:

- revoke owned objects where appropriate,
- invalidate stale generations,
- prevent late DMA from reaching recycled memory.

---

# 8. Formal Verification Rules

Formal verification is not an afterthought.

The protection architecture should be designed so its important invariants are small enough to state and prove.

## Formal model rule

Important security properties should be **theorems/proof obligations**, not assumptions.

Avoid proving desired behavior by first declaring the desired behavior as an axiom.

## Bitvector fidelity

Machine-level concepts should be modeled using machine-level representations when practical.

For example:

```text
BitVec1
BitVec3
BitVec24
BitVec64
```

rather than abstract mathematical integers or Booleans when the hardware representation itself matters.

## Zero-axiom goal

For core protection invariants, prefer:

```text
definitions
+
proof obligations
```

with no Anka-specific axioms.

## Current proven themes

The Kleis/Z3 protection theories currently establish properties including:

- no authority from an empty capability,
- read does not grant write,
- write does not grant execute,
- stale generations are denied,
- supervisor bypass semantics,
- control-plane denial for users,
- no cross-capability stitching,
- one-past-end denial,
- valid read/write reachability,
- capability attenuation,
- delegation non-amplification,
- denied-transaction noninterference,
- fault recording behavior.

---

# 9. Testing Rules

Every formal property that exposed a real implementation bug should become a regression test.

Every architectural feature should eventually have:

```text
unit test
integration test
hostile/adversarial test
formal invariant
```

where appropriate.

Examples already established include:

- hostile cross-stack write,
- privilege escalation through SR/RTE,
- vector-table rewriting,
- scheduler-state modification,
- protection-domain switching,
- stale capability access,
- capability ordering,
- forged range validation,
- degenerate zero-width request.

---

# 10. Security Model

The system should assume that hostile software knows:

- every opcode,
- every MMIO address,
- every ABI convention,
- every kernel data structure,
- every capability encoding,
- every syscall number,
- every timing behavior that is architecturally observable.

No security property should depend on obscurity.

The attacker may be:

- hand-written hostile code,
- fuzz-generated code,
- compiler-generated code,
- symbolic code,
- LLM-generated adversarial software.

The goal is not to make exploitation difficult.

The goal is to make forbidden state transitions **architecturally impossible**.

---

## Current Host Trust Boundary

The present Anka64 implementation runs as software on a host operating system. Therefore the host is currently part of the trusted computing base. Anka can enforce its architectural rules among modeled agents only so long as the host faithfully executes the emulator/runtime.

Inside the Anka model, requests follow the intended chain:

```text
Core / DMA / Agent
        -> Fabric
        -> Capability and generation checks
        -> Commit or fault
```

But the host sits outside that model. A hostile or compromised host can potentially inspect or modify Anka process memory, patch the emulator, alter generated code, forge device input, bypass a guard, roll back state, or otherwise change execution without Anka being able to observe the violation.

Therefore the current security claim must be stated precisely:

> **Current Anka64 proves/enforces its architecture under an honest-host assumption.**

This does **not** invalidate the internal authority model. It identifies the present lower boundary of enforcement. An additional check inside Anka cannot solve this problem, because a hostile host can bypass the check itself. The enforcement point must eventually move below the host's authority.

A natural progression is:

```text
ordinary host process
    -> confidential VM / TEE
    -> native Anka hardware
```

A confidential-computing environment can protect the Anka runtime from an untrusted host or hypervisor, while Anka continues to protect its own agents from one another. The composition is conceptually:

```text
TEE protects Anka from the host
+
Anka protects agents through explicit authority
```

The strongest realization is native hardware in which every CPU, DMA, or accelerator transaction must pass through the capability fabric before memory commit. At that point a compromised kernel cannot simply skip the authorization function because authorization is below software.

This yields three distinct implementation stages:

| Stage | Security meaning |
| --- | --- |
| Current Anka | Architectural security model under a trusted host |
| Anka in a TEE | Host-isolated realization of that model |
| Anka hardware | Hardware-enforced realization of the model |

The long-term confidential-computing opportunity is therefore not merely an enclave. It is the composition of host isolation, measured/attested execution, and Anka's fine-grained object authority:

```text
capability fabric
+ memory confidentiality
+ measured execution
+ remote attestation
```

The architectural lesson is:

> **A security invariant is only as strong as the lowest layer capable of bypassing its enforcement point.**

---

# 11. What Anka64 Should Avoid

Anka64 should avoid inheriting complexity without evidence that the software needs it.

In particular, avoid assuming that the machine must reproduce:

- conventional page-table semantics,
- TLB behavior,
- Unix process semantics,
- omnipotent DMA,
- kernel-only drivers,
- raw-address authority,
- hidden privilege side channels,
- separate CPU and device protection models.

Compatibility may eventually require adaptation layers.

It should not dictate the fundamental architecture.

---

# 12. Design Heuristics

## Prefer explicit state

If a property matters, represent it explicitly.

Examples:

```text
agent
domain
generation
operation kind
object identity
fault reason
```

Do not infer important security state indirectly from unrelated structures.

## Prefer one semantic source of truth

The same definitions should guide:

- CPU behavior,
- bus behavior,
- OS policy,
- compiler assumptions,
- formal proofs.

## Prefer monotone authority

Ordinary delegation should attenuate authority.

Adding unrelated authority should not invalidate existing authority.

## Prefer compositional security

A subsystem should be able to rely on guarantees of the layer below it.

For example:

> If the protection fabric denies a transaction, higher software may assume that ordinary machine state was untouched.

## Prefer demanding clients over decorative demos

A feature is not mature when it produces a pleasing example.

It is mature when an adversarial client depends on its exact semantics and fails safely.

---

# 13. Anka64 Research Questions

Design questions, with current status.

### Implemented

4. **Multicore memory consistency** — Sequential consistency model.  DMA participates through the same capability fabric.
5. **Atomic operations** — XCHG (atomic exchange) authorized through the standard capability mechanism.
8. **Executable authority** — W⊕X enforced structurally: Active ⇒ ¬Execute, Sealed ⇒ ¬Write.  SYS_SEAL transitions Active → Sealed with generation bump.  CALL mints return-stack authority; RET validates it.  Code capabilities are attenuated through `derive()`.
10. **Formal architecture specification (partial)** — Table-driven ISA description (`desc.rs`) is the single source of truth for decoder, assembler, disassembler, and Kleis theory generator.  Compiler backend and full architecture generation remain future work.

### Open

1. **Concurrent authorization and revocation** — What happens if an object is revoked while a memory transaction is in flight?
2. **Physical translation** — How should `(ObjectId, offset)` map to physical memory?  Is a TLB needed?  Can translation caching remain independent of authority?
3. **Capability representation** — How are capabilities made unforgeable in hardware?  Tagged memory, capability registers, object handles plus protected metadata, or hybrid approaches?
6. **Interrupt and exception model** — How are asynchronous events represented per core?  How are privilege changes made precise and restartable?
7. **Device model** — How are device capabilities delegated?  How are command queues protected?  How are user-space drivers isolated?
9. **Capability transfer through IPC** — How does the kernel prove that transferred authority was possessed by the sender?

### New (post-self-hosting)

11. **Text and string semantics** — **Resolved in Phase 7.**  `Bytes ≠ UTF8Text`.  UTF-8 string literals are validated at compile time (RFC 3629 scalar-value legality).  Representation: explicit byte length, no NUL termination, immutable R-only literal object.  Validation is a gate (not a transcoder): input bytes = output bytes.  Codepoint count and grapheme count are not tracked; only byte length.  No normalization, escapes, or Unicode identifiers yet.
12. **Host independence** — Reducing host-side orchestration for loading, sealing, and launching the self-hosted compiler.  The self-hosted compiler currently depends on a Rust test harness for process setup.  The next step (Phase 8) is native process/service orchestration: the host boots Anka once; Anka itself launches programs without host harness involvement.

---

# 14. Long-Term Direction

### Single-source ISA — current state

The table-driven ISA description (`desc.rs`) already generates:

```text
         Anka64 ISA description (desc.rs)
              /       |       \
             ▼        ▼        ▼
         decoder  assembler  Kleis theory
                disassembler  generator
```

### Single-source ISA — target state

The eventual goal is full toolchain generation from one description:

```text
         Anka machine description
          /       |       |      \
         ▼        ▼       ▼       ▼
      decoder  assembler compiler Kleis semantics
             disassembler backend

```

The remaining gap is the compiler backend: the self-hosted compiler currently encodes instructions using its own `enci`/`encr`/`encs`/`encb` functions rather than deriving encodings from the ISA table.  Closing this gap would make the ISA table the single source of truth for all consumers.

---

# 15. Project Identity

Anka is not fundamentally a retrocomputing project.

The MC68000 implementation is a laboratory.

The project is exploring whether a computer architecture can be developed by allowing:

- real software,
- hostile software,
- operating-system requirements,
- compiler requirements,
- peripheral requirements,
- and formal proofs

to shape the hardware model together.

The guiding principle is:

> **Build the software early enough that it can tell you what the hardware should be.**

And the security counterpart is:

> **Design forbidden state transitions so they cannot occur, rather than merely making them difficult to exploit.**

---

# 16. Current Core Rules — Compact Form

For quick reference:

1. **Every architectural feature gets a demanding client.**
2. **Authority, placement, and consistency are separate.**
3. **The full memory transaction is the unit of authorization.**
4. **Denied transactions have no side effects except fault metadata.**
5. **Every bus master is an agent.**
6. **Protection domains are independent of physical CPU cores.**
7. **Capabilities carry authority over named objects.**
8. **Delegation may attenuate authority, never amplify it.**
9. **Authority cannot arise from nowhere.**
10. **Revocation is generation-based.**
11. **Object identity is independent of physical placement.**
12. **Control-plane authority is explicit.**
13. **Mechanism correctness and policy correctness are separate.**
14. **Capability collections have set semantics.**
15. **Zero-width and zero-operation requests are invalid.**
16. **Fetch, read, and write are distinct transaction types.**
17. **Privilege and authority checks precede architecturally visible effects.**
18. **Faults are precise and forensic.**
19. **DMA uses the same authority model as CPUs.**
20. **Device control is capability-mediated.**
21. **Multicore protection state is carried per transaction.**
22. **Concurrency must not create authority.**
23. **Revoked authority must not commit new transactions.**
24. **Security invariants should be proved, not assumed.**
25. **Formal counterexamples become implementation regression tests.**
26. **The architecture assumes fully informed hostile software.**
27. **Build vertically; let higher layers adversarially test lower ones.**
28. **One semantic fact has one authoritative definition.**
29. **Data that names executable code is not authority to transfer control to it.**
30. **A security invariant is only as strong as the lowest layer capable of bypassing its enforcement point.**

---

# 17. Phase 6B Self-Hosting Result

The canonical Anka compiler source is compiled by the bootstrap compiler into CC_B.  CC_B recompiles the same source into CC_C.  CC_B and CC_C are byte-identical.  CC_C passes the permanent semantic compiler corpus.

```text
CC_A(source_CC) → CC_B     (bootstrap seed compiles canonical source)
CC_B(source_CC) → CC_C     (authoritative compiler compiles canonical source)
assert(CC_B == CC_C)        (binary fixed point)
```

### Key facts (as of Phase 6B; see Section 18 for current numbers)

- **42** canonical functions at Phase 6B (now 46 after Phase 7)
- **15,030** bytes of canonical source text at Phase 6B (now ~17 KB)
- **57,176** bytes — fixed-point compiler binary at Phase 6B (now 63,808)
- **29** ISA instructions — no expansion was needed for self-hosting
- **Stage-2/stage-3 binary identity** — hard assertion, not advisory
- **22-program permanent semantic corpus** — literals, arithmetic, variables, if/else, while, function calls, recursion, pointer dereference, bitwise, comparisons

### Bugs self-hosting exposed

Self-hosting was the demanding client that exposed two latent bugs:

1. **`encr(0, ...)` — illegal opcode in canonical epilogue**.  Three functions used opcode 0 (illegal) instead of OP_MOV (10) for register moves in the return epilogue.  The code compiled successfully but generated illegal instructions in the grandchild.  The bug only manifested when CC_B's output was executed as real machine code.

2. **Code/data address overlap**.  CC_B (57KB) exceeded TEXT_SIZE (24KB), so loading it at virtual address 0 overlapped with data regions at LAYOUT_SRC (0x6000).  The fix exploited a structural ISA property: CALL and BCC use PC-relative displacements, so the compiler binary is position-independent for code.  CC_B loads at a high virtual base (0x30000) while data regions remain at their canonical addresses.

Both are exactly the class of bugs that self-hosting is designed to find: code paths that were never exercised as generated machine code, and layout assumptions that broke under a real-sized client.

### What self-hosting does not include (resolved in later phases)

- ~~String literals and UTF-8 text facilities~~ → **resolved in Phase 7**
- Unicode identifiers
- Removal of host-side orchestration (loading, sealing, launching)
- Native execution (still requires Rust host)

---

# 18. Current Implementation Facts

| Property | Status |
|----------|--------|
| ISA instructions | 29 |
| Self-hosted compiler | Fixed point (CC_B == CC_C) |
| CC_A (bootstrap seed) | 45 functions, frozen at Phase 7.3 semantics |
| CC_B = CC_C | 46 functions, 63,808 bytes |
| Canonical source | ~17 KB |
| Tests | 393 |
| Multicore | Implemented (SC + XCHG) |
| DMA | Protected fabric agent |
| W⊕X | Implemented (Active ⇒ ¬X, Sealed ⇒ ¬W) |
| Protected CALL/RET | Implemented (return-stack authority) |
| Table-driven ISA | Decoder, assembler, disassembler, Kleis generator |
| Host trust boundary | Still present (honest-host assumption) |
| UTF-8 text literals | Implemented (RFC 3629 compile-time validation) |
| SYS_WRITE | Buffer-based, capability-checked, output-atomic |
| Literal authority | Immutable R-only, two-ended image allocator |
| Bootstrap development model | CC_A frozen; new features via canonical source + CC_B |

---

## Closing

The 68000 prototype served its main purpose: it forced the project to encounter real architecture rather than hypothetical architecture.

Anka64 preserved the lessons that survived those encounters and discarded the historical constraints that did not.

The self-hosting result (Phase 6B) demonstrated that the 29-instruction ISA is already expressive enough for a nontrivial self-hosted software stack: recursion, variables, pointers, control flow, calls, syscalls, code generation, and a self-reproducing fixed-point compiler.

Phase 7 demonstrated that the self-hosted compiler can evolve semantically (UTF-8 validation, buffer I/O) without expanding the ISA or modifying the bootstrap seed.  The canonical compiler is now the authoritative compiler; CC_A is a frozen seed sufficient to construct it.

The project continues to evolve by the same rule that produced its strongest results:

```text
design
→ implement
→ run real software
→ attack it
→ formalize the failure
→ repair the architecture
→ prove the invariant
→ turn the counterexample into a regression test
```

That process is the Anka design method.
