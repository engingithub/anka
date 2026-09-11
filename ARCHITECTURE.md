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

The current stack is approximately:

```text
C source
   │
   ▼
 AnkaCC
   │
   ├──────────────┐
   │              │
Assembly text     │
   │              │
   ▼              │
 AnkaASM          │
   │              │
   └──────┬───────┘
          ▼
     Asm builder
          │
          ▼
     machine code
          │
          ▼
   Motorola S-record
          │
          ▼
      Anka CPU
          │
          ▼
     Protected Bus
          │
    ┌─────┴─────┐
    ▼           ▼
  RAM/MMIO    Devices
    │           │
    └─────┬─────┘
          ▼
       AnkaOS
```

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

\[
S_{n+1} = I(S_n)
\]

and became conceptually:

\[
S_{n+1} = F(S_n, I_n, E_n)
\]

where \(E_n\) includes external asynchronous events such as interrupts.

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

At the current stage, the project has **73 tests with zero failures**.

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

\[
\boxed{
\text{authority}
\neq
\text{translation}
\neq
\text{coherence/consistency}
}
\]

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

\[
\operatorname{authorize}(R)
\in
\{\text{allow},\text{deny}\}
\]

before translation or physical access occurs.

---

## Rule 3 — Denied transactions have no side effects

The central noninterference invariant is:

\[
\boxed{
\neg authorize(R)
\Rightarrow
\text{ordinary state after }R
=
\text{ordinary state before }R
}
\]

except for fault metadata.

More explicitly:

\[
\neg authorize(R)
\Rightarrow
\begin{cases}
M' = M\\
D' = D\\
O' = O\\
C' = C\\
L' = L \mathbin{+\!\!+} [fault(R)]
\end{cases}
\]

where:

- \(M\) = memory state,
- \(D\) = device state,
- \(O\) = object/translation state,
- \(C\) = architectural control state,
- \(L\) = fault log.

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

\[
C = (O,g,o,\ell,\pi)
\]

where:

- \(O\) = object identity,
- \(g\) = generation / revocation epoch,
- \(o\) = offset within the object,
- \(\ell\) = extent,
- \(\pi\) = permissions.

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

\[
\boxed{
Authority(C_{child})
\subseteq
Authority(C_{parent})
}
\]

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

\[
C' \leftarrow derive(C)
\Rightarrow
Authority(C') \subseteq Authority(C)
\]

---

## Rule 8 — Authority cannot arise from nowhere

No user or device may manufacture new authority merely by constructing bit patterns.

Capability creation must be controlled.

The architectural invariant is:

\[
\boxed{\text{authority cannot arise from nowhere}}
\]

Capability construction must therefore be mediated by trusted minting/derivation operations or by hardware-backed unforgeable representations.

---

## Rule 9 — Revocation is generation-based

Objects possess generations.

A capability is valid only when:

\[
g_C = g_O
\]

Revocation changes the object's generation:

\[
g_O \leftarrow g_O + 1
\]

making all old capabilities stale.

Thus:

\[
\boxed{
g_C \neq g_O
\Rightarrow
\text{access denied}
}
\]

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

\[
(O,\text{offset})
\rightarrow
\text{physical location}
\]

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

\[
\boxed{
\text{mechanism correctness}
\not\Rightarrow
\text{policy correctness}
}
\]

The OS must be tested for what authority it actually delegates.

For example, kernel scheduler state must never be delegated writable to ordinary user processes.

---

## Rule 13 — Capability collections have set semantics

If a domain contains multiple capabilities, authorization is existential:

\[
\boxed{
authorize(D,R)
\iff
\exists C\in D:
valid(C)\land C\vdash R
}
\]

Capability ordering must not change authority.

Adding a capability must not revoke authority granted by another valid capability.

Monotonicity should hold:

\[
Authority(D_1)\subseteq Authority(D_2)
\Rightarrow
Allowed(D_1)\subseteq Allowed(D_2)
\]

unless an explicit deny/revocation mechanism is separately defined.

---

## Rule 14 — A request must be real

A transaction must have a nonzero width and a real operation.

For the current model:

\[
\boxed{
width > 0
\land
operation \neq \varnothing
}
\]

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

\[
\boxed{
\text{privilege/authority validation precedes all architecturally visible operand access}
}
\]

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

\[
C_{DMA}
=
(O_{buffer},g,0,4096,\{Write\})
\]

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

\[
\boxed{
\text{No agent can increase its authority through concurrency}
}
\]

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

\[
\boxed{
\text{No transaction authorized under generation }g
\text{ may commit after revocation to }g+1
}
\]

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

# 13. Near-Term Anka64 Research Questions

The next major design questions are:

1. **Concurrent authorization and revocation**
   - What happens if an object is revoked while a memory transaction is in flight?

2. **Physical translation**
   - How should `(ObjectId, offset)` map to physical memory?
   - Is a TLB needed?
   - Can translation caching remain independent of authority?

3. **Capability representation**
   - How are capabilities made unforgeable in hardware?
   - Tagged memory?
   - Capability registers?
   - Object handles plus protected metadata?
   - Hybrid approaches?

4. **Multicore memory consistency**
   - What consistency model does Anka64 expose?
   - How do DMA and accelerators participate?

5. **Atomic operations**
   - Which transaction widths and atomic primitives are required?
   - How are atomics authorized?

6. **Interrupt and exception model**
   - How are asynchronous events represented per core?
   - How are privilege changes made precise and restartable?

7. **Device model**
   - How are device capabilities delegated?
   - How are command queues protected?
   - How are user-space drivers isolated?

8. **Executable authority**
   - How are executable objects created?
   - What is the W⊕X policy?
   - Can code capabilities be attenuated?

9. **Capability transfer through IPC**
   - How does the kernel prove that transferred authority was possessed by the sender?

10. **Formal architecture specification**
    - Can decoder, assembler, compiler backend, and Kleis semantics eventually be generated from one machine description?

---

# 14. Long-Term Direction

A possible long-term Anka toolchain is:

```text
             Anka machine description
              /       |       |      \
             /        |       |       \
            ▼         ▼       ▼        ▼
         decoder   assembler compiler  Kleis semantics
                              backend
```

This would reduce semantic drift between:

- implementation,
- toolchain,
- documentation,
- formal verification.

The machine description itself could become the authoritative specification of the ISA.

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

\[
\boxed{
\text{Build the software early enough that it can tell you what the hardware should be.}
}
\]

And the security counterpart is:

\[
\boxed{
\text{Design forbidden state transitions so they cannot occur, rather than merely making them difficult to exploit.}
}
\]

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

---

## Closing

The 68000 prototype has already served its main purpose: it forced the project to encounter real architecture rather than hypothetical architecture.

Anka64 should preserve the lessons that survived those encounters and discard the historical constraints that did not.

The project should continue to evolve by the same rule that produced its strongest results so far:

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
