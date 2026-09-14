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
  Secure OS (SYS_EXIT, SYS_WRITE, SYS_SEAL, SYS_EXEC,
             SYS_SPAWN, SYS_WAIT, SYS_SEND, SYS_RECV,
             SYS_BLOCK_READ, SYS_CAP_DROP, SYS_SEND_CAP, SYS_SEND_KEY)
          │
          ▼
  ankad (native Anka64 supervisor — boot, spawn, wait, restart)
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

At the current stage, the project has **418 tests with zero failures**.

### Stage 19 — Boot contract (Phase 8.0)

Phase 8.0 established the boundary between host machine instantiation and Anka process instantiation.  Before Phase 8, the host test harness performed both: it created objects and also constructed Anka64Core, set up address maps, and called `kernel.spawn()`.

The boot contract draws the line:

- **Host owns machine instantiation**: create Fabric, allocate objects, write and seal code.
- **Anka owns process instantiation**: create domain, grant capabilities, create stack, trap handler, address map, core.

The host calls `kernel.boot(BootInfo)` and then `kernel.run()`.  It never constructs an Anka64Core.

Key design elements:

- **Authority != placement (Rule 1)**: `BootImage` (what to execute), `BootGrant` (additional authority), and `BootMap` (virtual placement) are separate.
- **Shared primitive**: `prepare_process()` is used by both SYS_EXEC and `boot()`.  The only difference is the authority source: SYS_EXEC derives from a parent domain; boot grants from trusted boot state.
- **BootGrant may not overlap BootImage backing range**: preserves Rule 28 (one semantic fact, one definition) and Rule 29 (data is not control authority).
- **BootMap virtual ranges may not overlap**: each other or implicit code/literal/stack/trap mappings.
- **One-success-only**: successful boot sets a permanent flag.  Failed boot is transactional — no domain, capability, mapping, process, or object survives.
- **boot() returns without running**: it installs init as runnable.  The host calls `run()` afterward.  Scheduling is the host's responsibility.

### Stage 20 — Capability-shaped process lifecycle (Phase 8.2)

Phase 8.2 established `SYS_SPAWN` (asynchronous process creation) and `SYS_WAIT` (lifecycle observation).  The decisive design property: **a name is not a capability** (DN-8, Rule 8).  Phase 8.4 extended `SYS_SPAWN` to consume R1–R8, carrying an explicitly delegated initial environment (grants, maps, layout).  See DN-11 for the ABI design.

Key design elements:

- **LifecycleHandle**: parent-local opaque reference `(slot_generation:u32 | slot:u32)`.  Meaningful only within the calling process's kernel-protected lifecycle table.  Returned by SYS_SPAWN, consumed by SYS_WAIT.
- **ProcessKey**: kernel-internal identity `{ slot, generation }`.  Never exposed to user space.  Slot is reusable kernel storage; PID is a separate monotonic public name (see DN-8 Phase 8.3 refinement).
- **Two generations**: `slot_generation` prevents stale lifecycle-slot reuse within a long-lived parent; `ProcessKey.generation` prevents stale slot reuse across the kernel.
- **WaitKind**: distinguishes `Exec` (historical single-register ABI, 0xDEAD for faults) from `Lifecycle` (two-register tagged ABI: R0=tag, R1=detail).
- **Atomic consumption**: handle consumed at moment of result delivery, not before.  Second WAIT on same handle returns invalid.
- **Security property**: full knowledge of a handle's bit representation does not create authority.  Non-owner WAIT is rejected because the handle resolves only in the caller's own table.

Test count at Phase 8.2 close: 418.

### Stage 21 — Supervised process lifecycle and reclamation (Phase 8.3)

Phase 8.3 closed the refinement chain from formal specification through implementation to empirical steady-state validation.  The central result: repeated process death and restart converges to constant resource occupancy.

**Formal model (Kleis Petri net):**

A bounded Petri-net model of the single-slot lifecycle was verified by Z3.  13 places, 4 transitions, 4 reachable markings (M0–M3) as ground axioms.  Three meaningful P-invariants:

- **Lifecycle uniqueness**: R + Z + C + F = 1 (a slot is in exactly one state).
- **Stack extent conservation**: SE + FSE = 1 (stack extents are never leaked or duplicated).
- **Trap extent conservation**: TE + FTE = 1 (trap extents are never leaked or duplicated).

Total token count is *not* a P-invariant — it varies across markings (8, 8, 6, 3).  The meaningful conservation properties are the three above, plus cycle closure: spawn(M3) = M0 — no resources leak across incarnation cycles.  26 verified properties plus 1 intentional falsifiability witness.

**Five-concept separation (now exercised end-to-end):**

- **PID** — monotonic public name (u64, never reused).
- **Process slot** — reusable kernel storage index.
- **ProcessKey(slot, generation)** — incarnation identity.
- **LifecycleHandle** — parent-local observation authority.
- **PhysicalExtent** — physical memory placement.

None of these may be substituted for another.  `resolve_pid()` is the only path from PID to slot, and it only resolves Running processes.

**Process states:**

`Running → Zombie → Free(g+1) → Running` (reuse), or `Free → Retired` when generation reaches `u32::MAX`.  Generation advances on reclaim (not allocation) via `checked_add(1)` — never wraps.

**Reclamation:**

`reclaim_process(slot)` atomically: destroys owned Fabric resources (domain, objects), returns physical extents to pools, clears incarnation metadata (parent, waiting_on, result, exit_code), clears mailbox and lifecycle table, advances generation.  `OwnedResources` (domain, stack_obj, trap_obj, stack_extent, trap_extent) tracks what each incarnation owns.

**Scrubbed physical extent reuse:**

`alloc_stack_extent()` / `alloc_trap_extent()` attempt exact-size pool reuse with scrubbing (zero bytes before reuse), then fall back to bump allocation from `next_phys`.  Stack and trap pools are separate.

**Central death transition:**

All termination paths (SYS_EXIT, user HALT, SupervisorFault, ProtectionFault, unknown syscalls) converge to `finish_process(slot, result)`.  This eliminates partial death states and ensures orphan handling is never skipped.

**Depth-first orphan termination:**

`terminate_orphans(dead_parent_key)` recursively discovers and reclaims descendants: grandchild first, then child, then parent is eventually collected.  No parent relation is erased before its subtree has been discovered.

**Process-slot reuse:**

`spawn()` searches for `Free` slots before appending.  Reuse preserves the existing generation and assigns a fresh PID.  `Retired` slots (generation `u32::MAX`) are skipped.

**ankad — native Anka64 supervisor:**

ankad is an ordinary booted Anka64 process that spawns and supervises other processes using only runtime interfaces (SYS_SPAWN, SYS_WAIT, SYS_WRITE, SYS_EXIT).  The host boots ankad; ankad spawns children.  The host observes a supervisor rather than impersonating one.

**Same-code restart (B₁/B₂):**

ankad restarts a faulting service into the same slot at a new generation: B₁ = (S, 0), B₂ = (S, 1).  Different PIDs, different ProcessKeys, different LifecycleHandles, same sealed executable, same fault behavior, reused scrubbed physical extents.

**100-cycle resource steady state:**

After one warm-up cycle, ankad performs 100 consecutive spawn-fault-collect-reclaim cycles.  Decisive assertions:

- `next_phys` remains constant (no physical memory growth).
- Domain count remains constant.
- Object count remains constant.
- Process table size remains constant.
- The service slot is reused throughout; its generation advances monotonically.

PID growth is intentional (monotonic names), not a leak — a useful negative control.

**Adversarial checks:**

- Stale `ProcessKey` rejected after slot reuse.
- Physical extent scrubbed (no remanence from prior incarnation).
- `SYS_SEND` to a dead process fails cleanly.

Test count: 440 (418 prior + 5 extent allocation + 4 reclaim + 4 finish/orphan + 3 slot reuse + 1 ankad boot + 1 B₁/B₂ restart + 4 steady-state/adversarial).

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
6. **Interrupt and exception model** — **Resolved in Phase 9.0.**  Event entry (TRAP, timer interrupt) pushes a protected `EventFrame` containing `return_pc`, `return_privilege`, `interrupts_were_enabled`, and `cause`.  A single `event_return()` primitive consumes the frame, used by both `ERET` (ISA instruction) and `resume_from_trap()` (host-mediated).  Asynchronous delivery: `deliver_pending()` fires at instruction boundaries when `pending_event.is_some() && interrupts_enabled`.  `FabricTimer` is a machine-global instruction-step timer on `Fabric`.  Generation ≠ routing ≠ pending ≠ delivery.  Formally verified: `anka_interrupts.kleis` (7-place Petri net, 6 reachable markings, 4 conservation invariants, 10 safety proofs, 2 falsifiability witnesses).
7. **Device model** — **Partially resolved in Phase 9.1.**  A block device demonstrates capability-mediated asynchronous I/O.  Device capabilities are delegated as narrow, request-local DMA domains derived at submission time from the submitter's authority.  Command slots are bounded (F + O\_wait + O\_dma + C = N\_slots) with generation-qualified handles.  Completion queues are the source of truth; interrupts are level-triggered notifications (L\_dev := C > 0).  User-space drivers are not yet implemented but the authority model (DMA-DELEGATION: request authority ⊆ explicitly delegated authority) is designed to support them.  Remaining open: user-space driver isolation, device register capabilities, multi-device routing.
9. **Capability transfer through IPC** — **Resolved in Phase 9.2b.**  `SYS_SEND_CAP` resolves the sender's handle via the three-condition check (9.2a), derives a child capability from the exact `AuthorityId` into the receiver's domain using `derive_from_authority_id()`, installs it in the receiver's cap table with a fresh `DelegationId`, and enqueues a cap-bearing message -- all atomically after a complete read-only preflight.  The receiver observes the transferred handle via the extended `SYS_RECV` ABI.  Non-amplification: `C_child ⊆ C_source`.  Memory-only scope in 9.2b; device capabilities deferred to 9.2c.

### New (post-self-hosting)

11. **Text and string semantics** — **Resolved in Phase 7.**  `Bytes ≠ UTF8Text`.  UTF-8 string literals are validated at compile time (RFC 3629 scalar-value legality).  Representation: explicit byte length, no NUL termination, immutable R-only literal object.  Validation is a gate (not a transcoder): input bytes = output bytes.  Codepoint count and grapheme count are not tracked; only byte length.  No normalization, escapes, or Unicode identifiers yet.
12. **Host independence** — **Substantially resolved through Phase 8.5.**  The boot contract (`kernel.boot(BootInfo)`) eliminates host-side process construction (Phase 8.0).  ankad is now a native Anka64 supervisor that spawns, waits on, and restarts children using only runtime interfaces — the host boots ankad, then observes a supervisor rather than impersonating one (Phase 8.3).  Phase 8.4 resolved compiler supervision: ankad spawns CC_B as an ordinary supervised process with an explicitly delegated initial environment, requiring no kernel-side compiler awareness.  Phase 8.5 retired all four compiler-integration harnesses (`run_6b4_harness`, `build_ccb`, `run_ccb_harness`, `compile_with_ccb`), routing every compiler process through `run_supervised_compiler` → boot → SYS_SPAWN → SYS_WAIT.  The Linux x86_64 host binary demonstrates that the same Anka64 guest images produce identical architectural behavior on a different host.  Remaining: package the system image.

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
| Tests | 616 |
| Multicore | Implemented (SC + XCHG) |
| DMA | Protected fabric agent, narrow request-local delegation |
| W⊕X | Implemented (Active ⇒ ¬X, Sealed ⇒ ¬W) |
| Protected CALL/RET | Implemented (return-stack authority) |
| Table-driven ISA | Decoder, assembler, disassembler, Kleis generator |
| Interrupt architecture | Multi-source pending (P\_timer, P\_device), bounded-service arbiter |
| Block I/O | Async capability-mediated: 2-slot controller, completion queue, level-triggered |
| SYS\_BLOCK\_READ | Suspended syscall continuation via EventFrame + IoWait |
| I-format immediates | fits\_imm18() — assembler and compiler share single range predicate |
| Capability table | Per-process 16-slot, generation-qualified handles, AuthorityId-backed |
| Capability transfer | SYS\_SEND\_CAP: atomic preflight-then-commit, Memory-only, DelegationId provenance |
| IPC | SYS\_SEND (legacy PID), SYS\_SEND\_KEY (ProcessKey), SYS\_RECV (extended: tag + cap + sender) |
| Mailbox bound | MAX\_MAILBOX\_SIZE = 16, enforced by all producers |
| Host trust boundary | Still present (honest-host assumption) |
| UTF-8 text literals | Implemented (RFC 3629 compile-time validation) |
| SYS_WRITE | Buffer-based, capability-checked, output-atomic |
| Literal authority | Immutable R-only, two-ended image allocator |
| Bootstrap development model | CC_A frozen; new features via canonical source + CC_B |
| Boot contract | `kernel.boot(BootInfo)` — host owns machine, Anka owns process |
| Shared process primitive | `prepare_process()` used by boot, SYS_EXEC, and SYS_SPAWN |
| Process lifecycle | SYS_SPAWN (R1-R8) / SYS_WAIT with capability-shaped authority |
| Initial environment | SpawnGrant (authority) ≠ SpawnMap (placement) ≠ SpawnLayout (process structure) |
| Process states | Running, Zombie, Free, Retired (non-wrapping generations) |
| Reclamation | Atomic collect/reclaim: domain, objects, extents, metadata |
| Extent reuse | Scrubbed physical stack/trap extents returned to pools |
| Orphan termination | Depth-first recursive on parent death |
| Slot reuse | Free slots reused with advanced generation, fresh PID |
| Supervision | ankad: native Anka64 supervisor (boot → spawn → wait → restart → all compiler paths) |
| System image | Declarative boot manifest: encode → decode → load_into(Fabric, phys_base) → kernel.boot() |
| Steady-state conservation | 100-cycle resource fixed point verified |
| Formal lifecycle model | Kleis Petri net: 3 P-invariants, cycle closure, 26 properties |
| Linux x86_64 binary | Built and tested via Podman (440/440, stripped ELF, ~649 KiB) |

---

## Closing

The 68000 prototype served its main purpose: it forced the project to encounter real architecture rather than hypothetical architecture.

Anka64 preserved the lessons that survived those encounters and discarded the historical constraints that did not.

The self-hosting result (Phase 6B) demonstrated that the 29-instruction ISA is already expressive enough for a nontrivial self-hosted software stack: recursion, variables, pointers, control flow, calls, syscalls, code generation, and a self-reproducing fixed-point compiler.

Phase 7 demonstrated that the self-hosted compiler can evolve semantically (UTF-8 validation, buffer I/O) without expanding the ISA or modifying the bootstrap seed.  The canonical compiler is now the authoritative compiler; CC_A is a frozen seed sufficient to construct it.

Phase 8.0 established the boot contract: the host creates the machine, Anka creates the process.  The test `p80_boot_return_42` proves the boundary — it boots and runs a process without the test ever constructing an Anka64Core.  13 hostile boot descriptor tests verify that invalid descriptors are rejected without corrupting kernel state.

Phase 8.2 established capability-shaped process lifecycle: `SYS_SPAWN` creates a child and returns a `LifecycleHandle` — the only authority to observe that child's termination.  A name (PID) is not a capability (DN-8, Rule 8).

Phase 8.3 closed the refinement chain from formal specification through implementation to empirical steady-state validation.  A Kleis Petri-net model established lifecycle uniqueness, extent conservation, and cycle closure as provable invariants.  The kernel implementation separated five distinct concepts (PID, slot, ProcessKey, lifecycle authority, physical placement), centralized all death transitions through `finish_process()`, terminated orphans depth-first, and reclaimed process-owned resources atomically.  ankad — a native Anka64 supervisor — demonstrated that ordinary process orchestration occurs inside Anka, not on the host.  The decisive result: after warm-up, 100 consecutive restart cycles produce zero resource drift — `next_phys`, domain count, object count, and process table size all remain constant while incarnation identity advances monotonically.  The formal model predicted cycle closure; the implementation confirmed it holds over sustained operation.

The Linux x86_64 portability seal confirmed identical behavior on a different host:

```text
440/440 macOS = 440/440 Linux x86_64
```

The same Anka64 guest images, the same Petri-net invariants, the same steady-state conservation — under a different host executable on a different operating system.

Phase 8.4 extended `SYS_SPAWN` to accept an explicitly delegated initial environment and proved that the self-hosted compiler is an ordinary supervised service.  The canonical ABI now consumes R1–R8:

| Register | Purpose |
|---|---|
| R1 | code_addr |
| R2 | code_size |
| R3 | lit_start |
| R4 | grant_table_addr (ignored when R5=0) |
| R5 | grant_count |
| R6 | map_table_addr (ignored when R7=0) |
| R7 | map_count |
| R8 | layout_addr (0 = default ProcessLayout) |

Three distinct concepts compose the initial environment:

- **SpawnGrant** = initial authority (what the child may access)
- **SpawnMap** = initial placement (where delegated objects appear in child virtual space)
- **SpawnLayout** = process structure (where code, stack, and trap handler reside)

A map never creates authority; every map must be covered by a corresponding grant.  All descriptor validation occurs transactionally before any child resources are allocated — failure is cheap and leaves no partial state.  Once a register acquires syscall meaning, callers must initialize it deliberately at every call site; stale caller state is not part of the ABI.

The decisive Phase 8.4 result: ankad boots as init, constructs SpawnGrant/SpawnMap/SpawnLayout descriptors on its own stack using SP-relative addressing, and calls `SYS_SPAWN(R1–R8)` to launch CC_B with source=R, output=RWS, workspace=RW.  CC_B compiles `int main() { return 42; }`, seals its output, `SYS_EXEC` runs the compiled child, and ankad observes `Exited(42)` via `SYS_WAIT`.  No kernel change was required — the compiler became an ordinary client of the same mechanisms used for general process creation.  The ownership result confirmed the Phase 8.3 resource semantics under delegation: CC_B's process slot is reclaimed to Free while the delegated source, workspace, and output objects survive, because authority held by an incarnation is not resource owned by that incarnation.

Phase 8.5 retired the last host-side compiler construction paths.  `run_6b4_harness`, `build_ccb`, `run_ccb_harness`, and `compile_with_ccb` now delegate to a single `run_supervised_compiler` helper that boots ankad and uses `SYS_SPAWN`/`SYS_WAIT` to execute every compiler invocation.  The closure invariant: compiler/system integration tests ∩ host-side process construction = ∅.  The host still constructs executable artifacts (AST → code bytes); Anka constructs every compiler process.  ankad preserves the structured `SYS_WAIT` result (tag in R10, detail as exit code), so the host can distinguish normal exits from faults without consuming `byte_output`.  The parent-side compiler mapping always uses `SUPERVISOR_COMPILER_VADDR = 0x30000`, while `SpawnLayout.code_vaddr` is parameterized: 0 for CC_A, `CCB_CODE_BASE` for CC_B.

Phase 8.6 packaged the entire initial software object graph as a declarative system image — a deterministic byte stream that the host loads into a Fabric and boots without manually constructing the trusted object graph.  A system image is a boot construction manifest, not a runtime snapshot, filesystem image, or machine configuration.  It carries logical objects, their initial bytes/state, boot authority, and virtual placement.  The host-side loader resolves image-local identity (`ImageObjectRef`) into runtime identity (`ObjectId`) and chooses physical placement; `kernel.boot()` remains the single authority on boot semantics.

Six concepts remain distinct throughout the load path:

- **name** — diagnostic metadata, never identity
- **ImageObjectRef** — image-local index into the object table
- **ObjectId** — runtime identity within a single machine instance
- **authority** — capabilities derived from boot grants
- **virtual placement** — ABI-level addresses in boot maps
- **physical placement** — host-chosen, image-independent

The decisive Phase 8.6 test encodes one image, decodes it, and loads it into two independent machines at different physical bases (0x100000 and 0x300000) with deliberately different ObjectId mappings (a pre-allocated dummy object shifts IDs in machine B).  Both machines boot ankad → CC_B → compiled program → 42.  Same image bytes, different physical placement, different runtime ObjectIds, identical architectural behavior.

`Permissions::from_bits_checked(u64)` is now the single authority for valid permission bits, replacing the previous `VALID_PERMS_MASK` constant.  The wide `u64` parameter prevents silent truncation when validating the SPAWN ABI's native register-width permission field.  The ankad supervisor program has a single authoritative source in `ankad.rs`, used by both the test helper and the production image builder.

Phase 9.0 introduced architectural interrupts and asynchronous event delivery — the first feature of Chapter 9 (Anka64 as an independent architecture).  The design was formalized first in a Kleis/Z3 Petri-net model (`anka_interrupts.kleis`: 7 places, 6 reachable markings, 4 conservation invariants, 10 safety proofs) before any Rust code was written.  The implementation followed the formal model without deviation.

The interrupt architecture introduced three new architectural concepts without expanding the ISA:

- **EventFrame** — protected event-entry record (return_pc, return_privilege, interrupts_were_enabled, cause).  TRAP and interrupt delivery push frames; a unified `event_return()` consumes them.  ERET on an empty stack faults (INT-5).
- **deliver_pending()** — generic architectural gate: if `pending_event ∧ ¬masked`, push EventFrame, enter Supervisor, mask, redirect to trap_vector.  Cause-agnostic (FRAME-UNIFIED-1).
- **FabricTimer** — machine-global instruction-step timer on Fabric.  Knows only how to count and say "I fired."  Generation ≠ routing ≠ pending ≠ delivery.

The machine sequencing rule is:

> Before any instruction fetch, if P ∧ ¬M, delivery gets first refusal.

This handles both post-commit delivery (timer fires after instruction) and post-event_return delivery (pending event preserved through ERET).  Committed instructions tick the timer; faulted instructions do not (INT-6).

The decisive Phase 9.0 test: two infinite-loop processes, each incrementing a counter in its own data memory, preempted by the architectural timer (period 10).  After 200 scheduler rounds, both counters are > 0 (A = 666, B = 666).  The only cause of context switching is the architectural timer path — the host-loop quantum is set to 100,000 (never reached).

The system-image compatibility gate also passed: all 10 Phase 8.6 system-image tests run unchanged on the new event architecture.  Same image + improved machine = same software behavior, confirming that machine state (EventFrame, pending_event, interrupts_enabled) is correctly separated from image state.

Phase 9.1 introduced asynchronous capability-mediated block I/O — the second demanding client of the Chapter 9 event architecture.  The block device was chosen because it attacks every part of the architecture simultaneously: Fabric transactions must span 512 bytes (not just ISA widths), DMA authority must be delegated narrowly and revocable, completion and notification must be separated, multiple interrupt sources must coexist without starvation, and asynchronous identity must survive across the time gap between request submission and completion.

The design was again formalized first (`anka_block_device.kleis`: 2-slot Petri net, 63 properties, 3 falsifiability witnesses).  Before formalization could even begin, the block-device client exposed a Fabric transaction-span bug — authorization was based on ISA width while commitment used payload length — forcing a Fabric hardening phase (9.1-pre) that introduced byte-span authority, an all-or-nothing precommit gate, and checked arithmetic throughout.

The implementation layered five independent concerns: BlockStorage (bytes), BlockController (slot lifecycle and DMA orchestration), Fabric DMA (narrow delegation), multi-source interrupt architecture (independent pending bits with bounded-service arbitration), and kernel integration (level-triggered routing, generation-qualified waking, EventFrame-based syscall continuation).

The decisive test runs a guest program that issues `SYS_BLOCK_READ`, blocks with its syscall EventFrame outstanding while another process executes, receives a device interrupt on DMA completion, undergoes double identity validation (RequesterKey + RequestHandle), resumes via `event_return()`, and verifies all 512 bytes of the DMA buffer word-by-word through its own address space.  Two independent observation paths — guest loads and host physical reads — agree on the result.

A secondary discovery: the block-device test pushed guest buffer addresses beyond the MOVI signed 18-bit immediate range, exposing a silent aliasing bug in the assembler and compiler.  The fix established a shared `fits_imm18()` predicate as the single definition of representability, preventing any code-generation layer from silently manufacturing a different immediate than the programmer requested.

One known limitation was explicitly recorded: the device clock advances only on committed instruction boundaries, so all-processes-blocked-on-I/O produces deadlock.  This is a named architectural pressure point, not a bug to be silently worked around.

### Stage 22 -- Capability-table architecture and protected naming (Phase 9.2a)

Phase 9.2a established the per-process capability table, the naming relationship between user-space handles and Fabric authority, and the resolution and drop semantics that make capabilities a protected interface rather than a raw data structure.

The central architectural contribution is three-condition resolution.  A `CapabilityHandle` resolves to authority iff:

1. The handle's generation matches the slot's current generation (name currency).
2. The backing `AuthorityId` still exists in the Fabric domain (authority currency).
3. The object's generation has not been advanced by revocation (object currency).

These three conditions are independent.  Each tracks a different lifetime.  Together they realize the relationship:

```text
AuthorityId-backed cap-table authority  <=>  valid protected cap-table name
```

`AuthorityId(u64)` is a monotonic, never-reused identifier that distinguishes independently installed capabilities even when they are structurally equal (same object, offset, length, permissions).  This is the decisive design property: `drop(H1)` removes exactly the authority named by H1, not a structurally equal twin.

Handle generation advancement uses `checked_add(1)`, not `wrapping_add(1)`.  When a slot's generation reaches `u32::MAX`, the slot is retired and never reused.  AuthorityId allocation uses the same checked pattern on its `u64` counter.  Neither counter can wrap.  A stale handle can never become current through wraparound resurrection.

`SYS_CAP_DROP` uses a complete preflight: handle valid, AuthorityId exists in Fabric, and slot is recyclable (generation < `u32::MAX`).  Both the cap-table slot and the Fabric authority entry are removed only after all conditions pass.

The entire phase was driven by formal-first methodology: all "correspondence holes" (non-atomic install, missing three-condition check, generation wraparound, non-recyclable drop, retired-slot reuse) were discovered by comparing the Rust implementation against the Kleis specification, not against the test suite.  Every hole became a hostile witness test.

584/584 tests; 29 instructions.

### Stage 23 -- User-space capability-mediated transfer (Phase 9.2b)

Phase 9.2b implemented atomic runtime capability transfer between live processes.  This is the architectural answer to research question 9 ("How does the kernel prove that transferred authority was possessed by the sender?").

Three new syscalls:

- `SYS_SEND_CAP` (11): Atomic capability transfer with checked ABI decode, preflight-then-commit transaction shape, and Memory-only scope restriction.
- `SYS_SEND_KEY` (12): ProcessKey-addressed ordinary send, replacing PID-addressed SYS_SEND for the 9.2 protocol.
- `SYS_RECV` (4): Extended return ABI (R0=value, R1=tag, R2-R5=cap handle and sender ProcessKey).

The transfer transaction has a strict preflight-then-commit structure.  The preflight is a sequence of read-only gates:

```text
gate 0:  decode ABI exactly (u32::try_from, Permissions::from_bits_checked)
gate 1:  destination ProcessKey is current
gate 2:  source handle fully resolves (three-condition)
gate 2b: source is ObjectKind::Memory only
gate 3:  child is a valid attenuation of source
gate 4:  receiver has an allocatable cap slot
gate 5:  mailbox has capacity (MAX_MAILBOX_SIZE = 16)
gate 6:  both AuthorityId and DelegationId spaces have room
```

Only after all gates pass does the commit phase execute: allocate identities, derive into destination domain from the exact source AuthorityId, install in receiver cap table with DelegationId, and enqueue the message.  Preflight rejection consumes no identities.  Unexpected commit failure may burn monotonic identities but cannot leak authority, handles, or messages.

`DelegationId { client: ProcessKey, driver: ProcessKey, incarnation: u64 }` is structured provenance stamped on each transfer.  The Kernel owns DelegationId allocation (because it contains ProcessKeys); the Fabric owns AuthorityId allocation (because it identifies domain entries).  A fresh DelegationId is the identity of the immediate transfer event, not inherited provenance.

`ProcessKey` was moved from `os.rs` to `state.rs` as a neutral generation-qualified identity type, enabling `DelegationId`, `Message`, and future block-request metadata to reference it without circular dependencies.

Cross-domain derivation uses `derive_from_authority_id()`, which locates the source capability by exact AuthorityId rather than structural equality.  This preserves the identity discipline from Phase 9.2a: value-equal twins are never confused during transfer.

The extended `SYS_RECV` returns a unified message envelope.  There is no SYS_RECV_CAP -- capability transfer is message metadata, not a separate IPC channel.  Installation occurs at send time; receive merely reveals the committed handle.  A handle may become stale between send and receive if the underlying object is revoked; this is defined behavior (capabilities do not pin objects).

The ABI treats syscall registers as untrusted input.  Every narrow field uses `u32::try_from()` to reject high-bit aliasing (`0x1_0000_0001` cannot silently become 1).

The entire 9.2 protocol is generation-qualified: SYS_SEND_CAP, SYS_SEND_KEY, and SYS_RECV all use ProcessKey semantics.  Legacy SYS_SEND (PID-addressed) is preserved only for old tests.

616/616 tests; 29 instructions.

Through self-hosting, capabilities, multicore, W⊕X, protected calls/returns, process lifecycle, formal Petri nets, reclamation, a genuine supervisor, an explicitly delegated initial-environment ABI, a compiler managed by Anka rather than merely running inside it, zero host-fabricated compiler processes, a declarative system image, architectural interrupts with preemptive multitasking, asynchronous capability-mediated block I/O with suspended syscall continuations, and now atomic inter-process capability transfer with structured provenance, the ISA still has not demanded instruction 30.  Twenty-nine instructions.  616/616 tests.  The software keeps asking for better abstractions rather than instruction proliferation.

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
