# Design Notes

Architectural decisions, alternatives considered, rejected assumptions,
deferred changes, and reasoning about why we chose not to act.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the authoritative current architecture,
rules, milestones, and implementation facts. [README.md](README.md) introduces
the project's purpose and development entry points. Architectural decisions
and future directions belong in these documents rather than separate root notes.

---

## DN-1: Compiler residence and fixed output-image size

**Date:** 2026-09-12 (Phase 7 close)

**Context:**

After Phase 7.4, CC_B is 63,808 bytes and OUTPUT_SIZE is 65,536 bytes
(0x10000), leaving 1,728 bytes of headroom in the compilation output
buffer.  This was initially framed as a system-memory concern.

**Decision:**

The self-hosted compiler is an ordinary Anka process, not a kernel
component and not expected to remain permanently resident.  The current
64 KiB compilation output object is a bootstrap-era implementation
choice, not a system-memory limit.  CC_B approaching that size does not
imply memory pressure for Anka as a system.

When a real client exceeds the current image size, the client should
drive the replacement abstraction.  Possible future solutions include:

- Dynamically sized output objects (compiler asks OS for allocation)
- Larger fixed images with multi-instruction address construction
- Segmented executable objects (code + literal as separate objects)

The MOVI 18-bit signed immediate (max 131,071) is the genuine
addressing constraint for literal offsets.  Simply increasing
OUTPUT_SIZE beyond that range would require multi-instruction address
generation using existing instructions (shift + OR).  No instruction 30
is necessarily required.

**Rule:**

Do not redesign the image format merely to create unused headroom.
Let a real client break the bootstrap assumption.

---

## DN-2: CC_A is a frozen bootstrap seed

**Date:** 2026-09-12 (Phase 7.4)

**Context:**

Phase 7.4 initially implemented `validateutf8()` in both CC_A (the Rust
AST compiler) and canonical source simultaneously.  This caused a
cascade of layout overflows: TEXT_SIZE, SOURCE_SIZE, OUTPUT_SIZE, virtual
layout order, and physical placement all had to change, breaking 17
tests.

**Decision:**

CC_A is frozen as a bootstrap seed.  Its purpose is not to be the best
compiler; its purpose is to be sufficient to construct the authoritative
one.  New compiler semantics go into canonical source and are tested
through CC_B.

This holds when the new feature uses nothing CC_A cannot already
compile, which is the case for `validateutf8()` (it uses only existing
language constructs: functions, while, if/else, comparisons, readbyte).

Future syntax changes that CC_A cannot parse will require staged
bootstrap through an older CC_B:

```text
old CC_B  →  compile new canonical source  →  new CC_B
```

rather than expecting the ancient CC_A seed to understand the new
language.

**Lesson:**

Self-hosting changed where language development happens:

- Before Phase 6B: Rust AST compiler *is* the compiler.
- After Phase 6B: Rust AST compiler = bootstrap seed.  Canonical source = compiler.

---

## DN-3: Lexical error must produce a terminal token

**Date:** 2026-09-12 (Phase 7.4)

**Context:**

The initial `scanstring()` implementation set `WS_ERROR = 1` on invalid
UTF-8 but left the token type stale.  Given prior stale-token parser
bugs, this risked the parser continuing with a partially valid token.

**Decision:**

Lexical failure always produces both properties:

1. **Scanner always makes progress** — advance past the closing quote
   before validation, so the scanner is never stuck at the same quote
   character.

2. **Terminal token on error** — set `TOK_TYPE = TOK_EOF` on failure,
   not just the error flag.  This guarantees the parser's
   `while (tok != EOF && error == 0)` loop terminates.

The sequence is: find closing quote, compute start/len, advance past
closing quote, validate UTF-8, then branch on valid/invalid.

---

## DN-4: Validation is a gate, not a transcoder

**Date:** 2026-09-12 (Phase 7.4)

**Context:**

UTF-8 validation could potentially normalize, replace invalid sequences
with U+FFFD, or perform case folding.

**Decision:**

`validateutf8()` accepts or rejects.  It never modifies bytes.  Valid
input bytes appear identically in the literal output.  This is tested
explicitly: the "Izmir" test verifies `C4 B0 7A 6D 69 72` survives
the full pipeline unchanged.

Unicode noncharacters (U+FFFF, U+FDD0, etc.) are accepted because they
are valid scalar values.  Rejecting them would impose text-content
policy, which is not the validator's job.

Normalization, escapes, grapheme segmentation, and Unicode identifiers
are deferred.  An HTTP server does not need any of them.  It needs
reliable bytes and valid text.

---

## DN-5: Harness inventory and the boot contract boundary

**Date:** 2026-09-12 (Phase 8.0)

**Context:**

Before Phase 8, every test created an Anka64Core directly, wired up
address maps and capabilities by hand, and called `kernel.spawn()`.
This meant the host test harness performed process instantiation — the
host knew how to build a runnable process, not just how to build a
machine.

The existing harnesses perform these responsibilities:

| Step | Responsibility | Owner (pre-8.0) |
|------|---------------|-----------------|
| Allocate physical memory (Fabric) | Machine instantiation | Host |
| Create objects, write code into them | Machine instantiation | Host |
| Seal executable objects | Machine instantiation | Host |
| Create domain + grant capabilities | Process instantiation | Host |
| Create Anka64Core, set up address map | Process instantiation | Host |
| Set PC, SP, trap vector | Process instantiation | Host |
| Call kernel.spawn() | Process instantiation | Host |
| Call kernel.run() | Scheduling | Host |

**Decision:**

The boot contract draws the boundary: host owns machine instantiation
(Fabric, objects, sealing); Anka owns process instantiation (domain,
capabilities, core, address map, stack, trap handler).

After Phase 8.0, the host:

1. Creates the machine (Fabric with physical memory)
2. Creates objects and loads trusted code into them
3. Seals executable objects
4. Calls `kernel.boot(BootInfo)` — Anka takes over process creation
5. Calls `kernel.run()` — Anka schedules

The host never constructs an Anka64Core.  The `p80_boot_return_42` test
proves this: it boots and runs a process without touching Core, Process,
AgentId, or DomainId.

Phase 8.5 retired all four compiler-integration harnesses
(`run_6b4_harness`, `build_ccb`, `run_ccb_harness`, `compile_with_ccb`).
Each now delegates to `run_supervised_compiler`, which boots ankad and
uses SYS_SPAWN/SYS_WAIT to supervise the compiler as an ordinary process.
The host still constructs executable artifacts (AST → code bytes); Anka
constructs every compiler process.  The invariant is:

  compiler/system integration tests ∩ host-side process construction = ∅

---

## DN-6: Boot as root of authority

**Date:** 2026-09-12 (Phase 8.0)

**Context:**

SYS_EXEC derives child authority from a parent domain's capabilities
(Invariant I7: a child capability cannot exceed its parent).  But
the initial process (init) has no parent domain.  Authority must be
established from a different root.

**Decision:**

Boot authority is established from trusted boot state, not derived
from any existing domain.  The boot contract types separate the
concerns:

- **BootImage**: identifies the sealed executable object.  The kernel
  implicitly creates RX authority for code and R authority for
  literals.  This is not derived from any domain — it is the root
  grant.

- **BootGrant**: additional authority (e.g., data objects for I/O
  buffers).  Grants may not overlap the BootImage backing range,
  preserving Rule 28 (one semantic fact, one definition) and Rule 29
  (data that names executable code is not authority to transfer
  control to it).

- **BootMap**: virtual address placement, separate from authority
  (Rule 1: authority != placement).  Maps may not overlap each other
  or implicit code/literal/stack/trap mappings.

The shared primitive `prepare_process()` is used by both SYS_EXEC and
`boot()`.  The only difference is the authority source:

```text
SYS_EXEC:  parent domain → derive child caps → prepare_process()
boot():    trusted boot state → grant root caps → prepare_process()
```

One-success-only semantics: a successful boot sets a permanent flag.
A failed boot leaves no reachable domain, capability, mapping,
runnable process, or live allocated object — the kernel remains
bootable for a subsequent attempt.  This is "one-success-only,
not one-attempt-only."

`boot()` installs init as runnable and returns.  It does not call
`run()`.  Scheduling is the host's responsibility.  This preserves
the separation: Anka creates the process; the host decides when to
start the machine.

---

## DN-7: Fixed point is reproducibility, not provenance

**Date:** 2026-09-12 (Phase 8.1 close)

**Context:**

The bootstrap fixed point CC_B == CC_C is a central result of
Phase 6B.  It proves the compiler is a stable self-reproducing
implementation of whatever semantics the bootstrap lineage has
supplied.  However, a Thompson-style malicious bootstrap compiler
(Reflections on Trusting Trust, Ken Thompson, 1984) could satisfy
the same fixed-point condition:

```text
clean canonical source
        ↓
  malicious CC_A
        ↓
  CC_B containing hidden payload
        ↓
  CC_B compiles clean canonical source
        ↓
  CC_C containing same hidden payload
        ↓
  CC_B == CC_C  ← fixed point still holds
```

**Decision:**

CC_B == CC_C proves bootstrap closure and deterministic
self-reproduction.  It does not defeat the trusting-trust attack.
A compromised bootstrap seed could inject behavior into CC_B that
CC_B subsequently reproduces despite clean canonical source.

Compiler provenance is therefore a separate verification problem
from compiler reproducibility.

**Anka's trust chain:**

```text
host Rust compiler/toolchain
        ↓
Anka emulator/runtime + CC_A (frozen bootstrap seed)
        ↓
CC_B (self-hosted compiler)
        ↓
CC_C == CC_B (fixed point)
```

Because Anka64 is a new ISA with a new compiler lineage, there is
no decades-old ancestral Anka compiler carrying an invisible
infection forward.  The trust problem collapses onto the bootstrap
event: establishing that the initial transition CC_A(source) → CC_B
is trustworthy.

**Future countermeasures:**

- Diverse double compilation (Wheeler, 2005): rebuild the compiler
  through an independently trusted compiler/toolchain and compare.
- Formal validation: the table-driven ISA semantics and Kleis/Z3
  theories can potentially establish that the binary implements the
  canonical source specification.
- Translation correctness and execution correctness are separable:
  does the binary implement the source?  Does the machine execute
  the binary according to the ISA?

**Connection to Phase 8:**

The boot contract and the trust problem meet at the same point:
where does the first trusted state come from?  Phase 8 formalizes
the authority chain from trusted boot root through init to all
subsequent processes.  A mature Anka system reduces the provenance
problem to: verify the ISA, verify the bootstrap translator, verify
the initial sealed image.

**Rule:**

The compiler fixed point establishes closure after bootstrap.  The
remaining provenance problem is establishing the authenticity and
correctness of the bootstrap root and initial compiler image.
Freezing CC_A (DN-2) makes future diverse double compilation
easier: a moving bootstrap compiler would constantly change the
thing whose provenance you are trying to establish.

---

## DN-8: A name is not a capability — lifecycle authority

**Date:** 2026-09-12 (Phase 8.2)

**Context:**

Phase 8.2 adds `SYS_SPAWN` and `SYS_WAIT` as the first
capability-shaped process-lifecycle API in Anka.  A process that spawns
a child receives a `LifecycleHandle` — the only way to observe (wait
on) that child's termination.

The design was initially implemented using a `ProcessHandle(pid, generation)`
that was globally meaningful: any process that knew the bits could call
`SYS_WAIT`.  This violated the architectural principle "authority cannot
arise from nowhere" (Rule 8).  A raw PID is a name, not a capability.

**Decision:**

Replace the globally meaningful handle with a kernel-protected, per-parent
lifecycle authority table.  Four distinct concepts:

- **ProcessKey** `{ pid, generation }` — kernel-internal identity of a
  specific process incarnation.  Never exposed to user space.
- **LifecycleHandle** `(slot_generation:u32 | slot:u32)` — user-facing
  opaque value.  Meaningful only in the lifecycle table of the process
  that received it from `SYS_SPAWN`.
- **LifecycleEntry** `{ slot_generation, child: ProcessKey, collected }` —
  one slot in a parent's table.  Collected slots are recycled with a
  bumped `slot_generation`.
- **WaitState** `{ child: ProcessKey, kind: WaitKind, handle_slot }` —
  suspended observation of a specific child incarnation.

Two deliberate generations prevent two distinct stale-reference hazards:

1. `slot_generation` prevents a consumed (collected) slot in a
   long-lived parent from being confused with a new child that reuses
   the same slot.
2. `ProcessKey.generation` prevents a recycled kernel PID from being
   confused with a former occupant of that process-table slot.

The security property: knowing every bit of a `LifecycleHandle` does
not create authority.  The handle resolves only in the calling
process's own kernel-protected table.  Test `p82_wait_not_owner`
demonstrates this: process B obtains the exact bit pattern of A's
handle via IPC and attempts `SYS_WAIT` — rejected because B's table
has no matching entry.

**Orphan semantics:**

When a parent exits without waiting on a child, the child becomes an
orphan.  Phase 8.2 does not define orphan policy.  Possible policies
(Phase 8.3+):

- **Reparent to init:** orphaned children are adopted by the init
  process, which can collect them.
- **Kill on parent exit:** orphaned children are terminated.
- **Detach (background):** orphans run until they exit, results discarded.

The lifecycle table design supports all three: the table is per-parent,
so orphan detection is simply "parent exited with uncollected entries."

**Rejected alternative: global handle validation.**

The original `validate_handle()` searched the global process table.
This meant any process that knew a PID and generation could observe
any other process.  Rejected because:

- It conflates naming with authority (same flaw as Unix signal(pid)).
- It makes cross-process information leaks possible.
- It is inconsistent with Kleis capability semantics: authority must
  be explicitly granted, not discovered.

**Rule:**

The lifecycle API follows Rule 8 ("authority cannot arise from
nowhere"): `SYS_SPAWN` creates authority and returns it to the parent.
`SYS_WAIT` consumes authority at the moment of result delivery.
No other path creates lifecycle observation rights.

**Phase 8.3 refinement — PID ≠ slot:**

Phase 8.3 introduced real process-slot reclamation and reuse.  This
revealed that the Phase 8.2 description above was imprecise in a way
that did not matter while slots were never reused, but became wrong
afterward.

The corrected definitions:

- **PID** (u64) — a monotonically allocated public name.  Never reused.
  `next_pid` increments on every `spawn()`.  PID is how user space
  refers to a process (e.g., in `SYS_SEND`).
- **Process slot** (usize) — reusable kernel storage.  An index into
  the process table.  A slot may be `Free`, `Running`, `Zombie`, or
  `Retired`.  Free slots are reused by `spawn()`.
- **ProcessKey** `{ slot, generation }` — kernel-internal incarnation
  identity.  The generation advances on reclaim (not allocation) via
  `checked_add(1)` and never wraps.  A slot whose generation reaches
  `u32::MAX` enters the `Retired` state and is never reused.
- **`resolve_pid()`** — the only path from a PID to a slot.  Linear
  scan; resolves only `Running` processes.

The Phase 8.2 text described `ProcessKey { pid, generation }` and
said generation protects "PID reuse."  The correct statement is:
ProcessKey identifies a slot incarnation, PID identifies a public
name, and these are distinct.  The generation protects *slot* reuse,
not PID reuse — PIDs are never reused.

This is exactly the separation the Petri-net model requires:
physical slot placement is a reusable resource; process identity
is not.

---

## DN-9: MOVI loads a signed 18-bit immediate

**Date:** 2026-09-12 (Phase 8.2)

**Context:**

The I-format encoding stores an 18-bit signed immediate field.  The
core sign-extends this to 64 bits before use:

```text
-2^17  <=  I  <=  2^17 - 1
-131072       ...  131071  (0x1FFFF)
```

During Phase 8.2, lifecycle tests mapped a second output buffer at
virtual address `0x30000` and loaded the address via `MOVI R1, 0x30000`.
The value 196608 exceeds 131071.  Bit 17 is set, so the core
sign-extends to `0xFFFF_FFFF_FFFF_0000` — a negative value — producing
an unmapped address and silent misbehavior.

This is the first time a real generated program broke the assumption
that MOVI can represent an arbitrary low virtual address.

**Observation:**

```text
MOVI Rd, 0x1FFFF   ✓   (largest positive representable)
MOVI Rd, 0x20000   ✗   (sign-extended to negative value)
```

**Decision:**

Do not change the encoding.  MOVI loads a signed 18-bit immediate,
not an arbitrary address.  Software requiring constants above 0x1FFFF
must construct them from multiple instructions or obtain them through
an existing base register or pointer.  Do not reinterpret the
encoding as unsigned.

The existing ISA already supports full 64-bit value synthesis:

```asm
MOVI  R4, high_bits
SHL   R4, R4, R5     ; shift left
OR    R4, R4, R6     ; merge low bits
```

The compiler should learn this sequence only when a generated program
actually needs it.  The kernel already sets values such as SP and PC
directly when constructing a process, so high virtual addresses are
not architecturally forbidden — only directly loadable via a single
MOVI.

**What changed:**

Phase 8.2 lifecycle tests were restructured to keep all MOVI-targeted
virtual addresses below `0x20000`.  Physical layout is unaffected
(the kernel sets physical addresses during `prepare_process`, not
through user instructions).

**Rule:**

MOVI is a signed-immediate load, not an address-construction
primitive.  The 18-bit field is part of the ISA encoding contract.
When a client needs a wider constant, the compiler emits a multi-
instruction sequence — the ISA does not grow a new opcode for it.

---

## DN-10: Process collection, reclamation, and supervision

**Date:** 2026-09-12 (Phase 8.3)

**Context:**

Phase 8.2 established SYS_SPAWN and SYS_WAIT but left process
resources permanently allocated.  A spawned child's domain, objects,
stack/trap extents, mailbox, and lifecycle table survived indefinitely
after death.  A supervisor that repeatedly restarts a service would
eventually exhaust all physical memory and kernel data structures.

Phase 8.3 was designed to close this gap: collection observes
a terminated process's result; reclamation destroys its resources
and returns its slot for reuse.

**Decision — collection ≠ reclamation:**

These are two distinct operations, not one:

- **Collection** = the parent observes the child's `ProcessResult`
  via SYS_WAIT.  The result is copied to the parent before anything
  is destroyed.
- **Reclamation** = the kernel destroys the child's owned resources
  (domain, objects, extents) and transitions the slot from Zombie
  to Free(g+1).

Collection must precede reclamation.  The kernel copies the result
before destroying the child.  After reclamation, the slot retains
no trace of the prior incarnation.

**Decision — process lifetime does not migrate implicitly:**

A process's resources belong to its incarnation, not to the slot.
When a slot is reclaimed and reused, the new incarnation gets
fresh resources (new domain, new objects, new extents).  Nothing
is inherited from the prior occupant.

**Decision — five-concept separation:**

Phase 8.3 exercises and enforces the distinction:

1. **PID** — monotonic public name (u64).  Never reused.
2. **Process slot** — reusable kernel storage index.
3. **ProcessKey(slot, generation)** — incarnation identity.
4. **LifecycleHandle** — parent-local observation authority.
5. **PhysicalExtent** — physical memory placement.

These five concepts are distinct.  None may be substituted for
another.  The Phase 8.2 code contained three hidden `pid ≡ slot`
assumptions that would have broken on slot reuse.  Phase 8.3a.1
eliminated them before reclamation was introduced.

**Decision — generation advances on reclaim, never wraps:**

`checked_add(1)` at reclaim time, not at allocation time.
If a slot's generation reaches `u32::MAX`, the slot enters
the `Retired` state and is never reused.  This eliminates
generation-wrap hazards entirely at the cost of eventually
retiring long-lived slots — an acceptable trade because
process-slot exhaustion is defined behavior, not undefined.

**Decision — process-owned resources:**

Each incarnation owns exactly:

- One domain
- One stack object + one stack PhysicalExtent
- One trap object + one trap PhysicalExtent

These are tracked in `OwnedResources`, created during
`prepare_process()`, and consumed during `reclaim_process()`.
Raw-spawned processes (created by the old `spawn()` path
without `prepare_process`) have `resources: None` — reclaim
skips resource destruction for them.

**Decision — scrubbed physical extent reuse:**

Reclaimed stack/trap extents are returned to separate pools.
When a new process needs an extent, the allocator checks for
an exact-size match in the pool.  If found, the extent is
zeroed (scrubbed) before reuse.  This prevents remanence:
a new incarnation never sees stale bytes from a prior one.

If no pooled extent matches, the allocator bumps `next_phys`.

**Decision — central death transition:**

All termination paths converge to `finish_process(slot, result)`:

```text
SYS_EXIT
user HALT
SupervisorFault       →  finish_process()  →  Zombie
ProtectionFault                               + terminate_orphans()
unknown syscall
```

This ensures orphan handling, exit-code recording, and result
installation are never skipped regardless of how a process dies.
Before Phase 8.3, the unknown-syscall path set `state = Zombie`
and `exit_code = 0xBAD` but did not install a `ProcessResult`,
creating a partial death state.  The central gate eliminated it.

**Decision — depth-first orphan termination:**

When a parent dies, its descendants are terminated and reclaimed
recursively: grandchild first, then child, then parent is
eventually collected.

```text
P → C → G  dies as:  G reclaimed → C reclaimed → P collected
```

This guarantees no parent relation is erased before its subtree
has been discovered.  Running children are terminated then
reclaimed; Zombie children are directly reclaimed.

**Decision — unrelated capabilities survive:**

A process's death and reclamation affect only its own resources.
Other processes' domains, capabilities, and objects are
untouched.  This is the set-semantics property of capabilities
(Rule 13): removing one entity's authority does not invalidate
authority held by others.

**Decision — boot remains the root authority:**

The boot contract (DN-6) is unchanged.  The initial process
authority comes from trusted boot state, not from any existing
domain.  ankad is booted via this path and then uses SYS_SPAWN
to create children — deriving their authority from its own
domain, which was originally derived from boot grants.

**Strongest Phase 8.3 result — resource steady state:**

After warm-up, 100 consecutive restart cycles produce zero
resource drift:

- `next_phys` remains constant (extents are reused, not leaked).
- Domain count remains constant.
- Object count remains constant.
- Process table size remains constant.

The Kleis Petri-net model predicted cycle closure:
`spawn(M_Free) → ... → reclaim → M_Free`.  The 100-cycle
test confirmed no hidden state escapes that abstract cycle.

The meaningful conservation properties are *not* total token
count (which varies: 8, 8, 6, 3 across markings).  They are:

- **Lifecycle uniqueness**: R + Z + C + F = 1
- **Stack extent conservation**: SE + FSE = 1
- **Trap extent conservation**: TE + FTE = 1
- **Cycle closure**: spawn(M3) = M0

Total token count is not a P-invariant.  This is an architectural
lesson: "conservation" for a supervisor means *specific resource
classes* are returned, not that some global count is preserved.

**Rejected alternative — implicit orphan reparenting:**

The Petri-net model was initially designed with a `ParentDead`
place and orphan-reparenting transitions.  This made the
single-slot model unbounded (tokens accumulated without limit).
The implemented design terminates orphans immediately rather
than reparenting them.  Reparenting may be revisited when a
real client needs long-lived orphan processes.

**Rule:**

Collection is observation.  Reclamation is resource destruction.
They are sequenced, not conflated.  A supervisor that collects
and restarts reaches a resource fixed point; one that merely
collects without reclaiming leaks.  One that reclaims without
collecting loses the result.

---

## DN-11: Canonical SYS_SPAWN initial-environment ABI

**Date:** 2026-09-13 (Phase 8.4)

**Context:**

Phase 8.2 defined SYS_SPAWN with three input registers (R1=code_addr,
R2=code_size, R3=lit_start).  R4–R8 had no assigned meaning; callers
were free to leave arbitrary values in them.

Phase 8.4 extended SYS_SPAWN to carry an explicitly delegated initial
environment via R4–R8.  The kernel now reads all eight registers:

```
R1  code_addr
R2  code_size
R3  lit_start
R4  grant_table_addr       (ignored when R5=0)
R5  grant_count
R6  map_table_addr         (ignored when R7=0)
R7  map_count
R8  layout_addr            (0 = default ProcessLayout)
```

**Decision — one evolving syscall, not SYS_SPAWN_ENV:**

An initial proposal created a separate SYS_SPAWN_ENV syscall to avoid
breaking "old callers."  This was rejected because there are no
deployed callers — only test fixtures encoding an earlier convention.
A separate syscall would introduce permanent ABI compatibility baggage
to preserve test code, exactly the kind of complexity Anka is designed
to avoid.

Instead: SYS_SPAWN evolves.  Every call site must deliberately
initialize R5, R7, and R8.  The combination R5=R7=R8=0 requests
the default process environment — this is current ABI semantics,
not backward compatibility.

**Decision — three concepts, not one:**

The initial environment separates three orthogonal concerns:

- **SpawnGrant** = initial authority: what the child may access.
  Descriptor: (parent_vaddr, offset, size, perms, reserved).
  The parent's mapping is resolved to an (ObjectId, offset) pair;
  only attenuated permissions are allowed — no escalation.

- **SpawnMap** = initial placement: where delegated objects appear
  in the child's virtual address space.  A map never creates
  authority.  Every map must be covered by a corresponding grant
  in the child's prospective domain.

- **SpawnLayout** = process structure: where kernel-owned process
  resources (code, stack, trap handler) reside.  Layout_addr=0
  selects the default geometry; non-zero reads a SpawnLayout
  descriptor from parent memory.

This three-way split preserves the Anka authority principle:

> authority ≠ placement ≠ process structure

Grants decide *what*; maps decide *where*; layout decides *how*.

**Decision — R4/R6 ignored under zero counts:**

When R5=0 (grant_count=0), R4 (grant_table_addr) has no semantic
effect.  When R7=0 (map_count=0), R6 (map_table_addr) has no
semantic effect.  This is deliberate: the kernel gate checks
counts before reading table pointers.  An adversarial test
(p84b_default_spawn_ignores_r4_r6) verifies that garbage R4/R6
values do not affect default-environment spawns.

**Decision — caller discipline over implicit defaults:**

Once a register acquires syscall meaning, callers must initialize
it deliberately at every call site.  Relying on stale register
values from earlier operations is not part of the ABI contract.

This was discovered during 8.4b.1 implementation: two existing
tests (p83e, p83f) stored LifecycleHandle values in R8 across
consecutive SYS_SPAWN calls.  Under the extended ABI, R8 was
misinterpreted as a layout_addr.  The fix: move persistent handles
to non-ABI registers (R9–R12) and zero R5/R7/R8 at every call site.
A test helper (`emit_spawn_default`) encodes the canonical default
spawn sequence to prevent future drift.

**Decision — transactional validation:**

All descriptor validation occurs before any child resources are
allocated.  The transaction order is:

1. Read R4–R8
2. Validate counts and byte lengths (checked arithmetic)
3. Copy grant + map + layout tables through parent READ authority
4. Parse and resolve descriptors against parent address map
5. Validate authority (attenuation, no stitching, single-entry)
6. Validate map geometry (no overlap, no overflow)
7. Verify every map is covered by prospective child authority
8. Create child domain and derive capabilities
9. `prepare_process()` installs maps and boots the child

Failure before step 8 is free: no resources have been allocated.
Failure during step 8 requires explicit rollback.

**Rule:**

SYS_SPAWN consumes R1–R8.  R5=R7=R8=0 means default environment.
SpawnGrant is authority; SpawnMap is placement; SpawnLayout is
process structure.  A map never creates authority.  Callers initialize
all ABI registers deliberately at every call site.

**Phase 8.4 completion (2026-09-13):**

The decisive test `p84c_ankad_spawns_compiler` proved that the
self-hosted compiler is an ordinary client of the mechanisms described
above, not a privileged execution mode.  ankad constructs all three
descriptor classes on its own stack (SP-relative addressing), calls
`SYS_SPAWN(R1–R8)` with source=R, output=RWS, workspace=RW, and
CC_B compiles, seals, and executes a child program — all without any
kernel-side compiler awareness.  The ownership invariant from Phase 8.3
was confirmed under delegation: CC_B's slot is reclaimed while the
delegated objects survive.  458/458 tests pass; 29 instructions.

**Phase 8.5 completion (2026-09-13):**

Phase 8.5 retired all four compiler-integration harnesses that performed
host-side process construction: `run_6b4_harness`, `build_ccb`,
`run_ccb_harness`, and `compile_with_ccb`.  Each now delegates to
`run_supervised_compiler`, which boots ankad and uses `SYS_SPAWN(R1–R8)`
/ `SYS_WAIT` to execute every compiler invocation.  The closure invariant:

  compiler/system integration tests ∩ host-side process construction = ∅

Key design choices:

- `SUPERVISOR_COMPILER_VADDR = 0x30000` — where ankad maps the compiler
  in its own address space.  `SYS_SPAWN.R1` is always this constant.
  Only `SpawnLayout.code_vaddr` varies (0 for CC_A, `CCB_CODE_BASE` for
  CC_B), preserving the parent placement ≠ child placement distinction.
- ankad preserves the `SYS_WAIT` result tag in R10 (non-ABI register),
  then `SYS_EXIT(R1)` propagates the detail.  The host reads both,
  distinguishing normal exits from faults without consuming `byte_output`.
- Workspace pre-initialization (`WS_LIT_POS = OUTPUT_SIZE`) is always
  performed: required for CC_A, harmless for self-initializing CC_B.

The host still constructs executable artifacts (AST → code bytes), which
is toolchain artifact construction, not process instantiation.  After 8.5,
the compiler lineage is:

  host constructs CC_A bytes → boot ankad → ankad spawns CC_A →
  CC_A(canonical source) → CC_B → ankad spawns CC_B →
  CC_B(canonical source) → CC_C → CC_B = CC_C

No compiler incarnation is fabricated by the host.  458/458; 29 instructions.

---

## DN-12: System Image — Declarative Boot Construction Manifest

**Date:** 2026-09-13 (Phase 8.6)

A system image is a declarative boot construction manifest.  It is not:

- a runtime snapshot (no ObjectIds, generations, process slots, domains)
- a filesystem image (no files, directories, or storage layout)
- a machine configuration (no RAM size, device topology, or physical addresses)

It describes the initial software object graph: logical objects, their
initial bytes/state, boot authority, and virtual placement.  The host
creates the machine (Fabric); the loader resolves image-local identity
and chooses physical placement; `kernel.boot()` establishes authoritative
boot semantics.

**Six-way identity distinction:**

  name ≠ ImageObjectRef ≠ ObjectId ≠ authority ≠ virtual placement ≠ physical placement

- `name`: diagnostic metadata, never identity or authority.
- `ImageObjectRef(u32)`: index into the image's object table.  Exists
  only within the context of a single image.
- `ObjectId`: runtime identity within a single machine instance.
  Two machines loading the same image may assign different ObjectIds.
- Authority: capabilities derived from boot grants, validated by
  `kernel.boot()`.  Not encoded as ObjectIds in the image.
- Virtual placement: ABI-level addresses in boot maps.  Part of the
  software contract between ankad and the compiler.
- Physical placement: chosen by the host-side loader via `phys_base`.
  The image contains no physical addresses.

**Loader API:**

The primary operation is `load_into(fabric, phys_base)` — the host
creates the Fabric (machine instantiation), the loader populates it
(software instantiation).  This preserves the Phase 8.0 boundary:
host owns machine instantiation; Anka owns process instantiation.

Fabric is consumed by value: on error the partially constructed
machine is dropped.  No partially loaded Fabric escapes.

**Sparse payload semantics:**

  initial object bytes = contents || 0^(size - |contents|)

The loader zeros each object's physical extent before initializing
the contents prefix, guaranteeing this semantic regardless of prior
Fabric memory contents.  Output objects carry empty contents; workspace
carries only the WS_LIT_POS initialization bytes.

**Wire format (V1):**

Custom little-endian, no external dependencies.  Explicit wire
encodings for ObjectKind (0/1/2), seal_after_load (0/1), and
permissions (via `from_bits_checked`).  Reserved fields on every
record.  Never transmute.  V1 rejects trailing bytes and nonzero
reserved fields.  Deterministic: `decode(encode(I)) = I` and
`encode(decode(B)) = B` for canonical bytes.

**Permission validation:**

`Permissions::from_bits_checked(u64)` is the single definition of
legal permission bits, replacing `VALID_PERMS_MASK`.  The `u64`
parameter prevents silent truncation when validating the SPAWN ABI's
native register-width field (a `u8` parameter would accept 0x100
via `as u8` → 0x00).

**Phase 8.6 completion (2026-09-13):**

The decisive test `p86_system_image_boot` encodes one image, decodes
it, and loads it into two independent machines at different physical
bases (0x100000, 0x300000) with deliberately different ObjectId mappings
(a pre-allocated dummy shifts ImageObjectRef(0) → ObjectId(1) in
machine B).  Both machines boot ankad → CC_B → 42.

This proves:

  same image bytes + different physical placement + different ObjectIds
  = identical architectural behavior

The ankad supervisor program has a single authoritative source in
`ankad.rs`, used by both `run_supervised_compiler` (test helper)
and `build_compiler_system_image` (production image builder).

468/468 tests; 29 instructions.  Phase 8 is complete.

## DN-13: Unified EventFrame Architecture — Architectural Interrupts

**Phase**: 9.0 (Chapter 9: Anka64 as an Independent Architecture)

**Problem**: Anka64 had a host-side approximation of preemption: `run_process()`
executed at most `quantum` instructions before returning to the scheduler.  This
was adequate for cooperative scheduling (syscall → TRAP → HALT → kernel intervention)
but was not an architectural mechanism.  The machine had no way to transfer control
asynchronously between instruction boundaries.  The architecture document listed
interrupts as an open question (research question 6).

**Design**: Formal-first methodology.  A Kleis/Z3 Petri-net model
(`theories/anka_interrupts.kleis`) was built and verified before any Rust code
was written.  The formal model is the specification; the implementation follows it.

**Formal model**: 7 places, 4 transitions, 6 reachable markings.

Places:

- U (user execution), P (pending event), Q (no pending — complement of P)
- H (handler active), F (EventFrame exists), M (masked), R (return ready)

Transitions:

- T_post (event source fires), T_deliver (pending → handler entry)
- T_handler (handler runs), T_eret (event return)

Conservation invariants (proved structurally, transition-by-transition):

- CONS-1: P + Q = 1 (coalescing: at most one pending event)
- CONS-2: U + F = 1 (execution or frame, never both)
- CONS-3: U + H + R = 1 (exactly one execution phase)
- CONS-4: F = M (frame exists iff interrupts are masked)

Safety proofs (10 properties + 2 falsifiability witnesses):

- INT-1 through INT-10, including the critical INT-6 (delivery requires
  committed instruction boundary, pending, unmasked, non-faulted).

**Key architectural decisions**:

1. **Unified EventFrame**.  A single protected `EventFrame` struct stores
   `return_pc`, `return_privilege`, `interrupts_were_enabled`, and `cause`.
   TRAP and interrupt delivery push frames; a single `event_return()` primitive
   consumes them.  This replaces the old `saved_pc`/`saved_privilege` single-slot
   mechanism.  The stack representation does not hard-code the current
   no-nesting theorem (FRAME-BOUND: depth ≤ 1 in Phase 9.0).

2. **Generic delivery gate**.  `deliver_pending()` is cause-agnostic: it fires
   when `pending_event.is_some() && interrupts_enabled`, regardless of whether
   the cause is a syscall, timer interrupt, or future device interrupt.  Coalescing
   (P+Q=1) is a timer-source property, not a universal interrupt law.

3. **Timer as Fabric device**.  `FabricTimer` lives on `Fabric`, not on
   `Anka64Core`.  It knows only how to count instruction steps and report "I fired."
   Routing a firing to a core's `pending_event` is the scheduler's responsibility.
   This preserves:

       generation ≠ routing ≠ pending ≠ delivery

4. **Precise delivery at instruction boundaries**.  The machine sequence is:

       I_n commits → devices tick → route/post → deliver_pending() → fetch I_{n+1}

   Committed instructions tick the timer; faulted instructions do not.  Before any
   fetch, if `P ∧ ¬M`, delivery gets first refusal.  This handles both post-commit
   delivery and post-event_return delivery (the M3a → M1 → M2 re-fire path).

5. **Masking and unmasking via EventFrame**.  Event entry sets
   `interrupts_enabled = false`.  Event return restores the saved
   `interrupts_were_enabled` from the frame — not unconditionally true.
   This is architecturally exact (INT-8b).

**Negative boundaries** (what SystemImage/EventFrame is NOT):

- EventFrame is not in ordinary memory (not accessible through capabilities).
- Timer generation alone cannot cause control transfer.
- Coalescing is timer-specific, not universal.
- The timer does not know about cores, privilege, or trap vectors.
- The system image does not serialize event infrastructure
  (EventFrame, pending_event, interrupts_enabled are runtime core state).

**Decisive test**: Two infinite-loop processes, each incrementing a counter
in data memory, preempted by the architectural timer (period 10, 200 scheduler
rounds).  Both make progress (A = 666, B = 666).  The host-loop quantum is
100,000 — never reached.  Preemption comes purely from the architectural
timer → pending_event → deliver_pending() → handle_timer_interrupt → round-robin
path.

**Compatibility verification**: All 10 Phase 8.6 system-image tests pass
unchanged on the new event architecture: same image bytes + improved machine
implementation = same software behavior.  Machine state is correctly separated
from image state.

490/490 tests; 29 instructions.  Phase 9.0 is complete.


## DN-14: Asynchronous Capability-Mediated Block I/O

**Phase**: 9.1 (Chapter 9: Anka64 as an Independent Architecture)

**Problem**: Phase 9.0 proved Anka could be interrupted.  Phase 9.1 asks whether
Anka can safely perform asynchronous I/O — where the *cause* (request submission)
and the *consequence* (DMA completion) are separated in time, and every layer must
preserve identity and authority across that gap.

Before any block-device code was written, the block-device client exposed a
concrete Fabric bug: `execute_write` authorized based on `request.width` (at most
8 bytes) but committed based on `write_data.len()` (potentially 512 bytes).  A
request authorized for 8 bytes could silently write 512.  This led to Phase
9.1-pre, which hardened the Fabric before formalization could begin.

**Formal model**: `theories/anka_block_device.kleis` — bounded Petri net with
2 request slots and 2-entry completion queue.  63 intended properties pass; 3
deliberate falsifiability witnesses are rejected by Z3.  The model covers:

- Two-slot request lifecycle: F → O\_wait → O\_dma → C → F
- Conservation: F + O\_wait + O\_dma + C = 2
- Completion truth is the queue; interrupt is notification
- Level-triggered source: L\_dev := (C > 0), derived, not stored
- Multi-source pending state: (P\_timer, P\_device) independent
- Bounded-service arbitration: turn bit guarantees both sources served
  within two eligible delivery opportunities
- DMA delegation: commit ⇒ requested span ⊆ delegated span
- Generation-qualified identity: stale request handle ≢ recycled slot;
  late completion cannot wake a recycled process

**Design — layered decomposition** (no layer does another's job):

1. **BlockStorage** — in-memory byte array.  Knows only blocks and bytes.
   No DMA, no interrupts, no processes.

2. **BlockController** — two-slot lifecycle machine.  Manages request
   submission, latency countdown, DMA transaction orchestration via
   Fabric, and completion ordering.  Does not know about processes
   or interrupt delivery.  `requires_attention()` is the level-triggered
   source predicate.

3. **Fabric DMA** — the existing Fabric transaction lifecycle
   (submit → advance → advance → terminal).  DMA authority is delegated
   at request *acceptance* time as a narrow, request-local domain.  The
   DMA domain is destroyed only after the transaction becomes terminal.

4. **Multi-source interrupt architecture** — `pending_event: Option<EventCause>`
   replaced by independent per-source pending bits `(P_timer, P_device)` with
   a turn-based arbiter.  `deliver_pending()` selects at most one source per
   eligible boundary.  Bounded service: both sources served within two
   opportunities when both are continuously pending.

5. **Kernel integration** — `tick_devices()` advances the block controller,
   collects the level assertion, and posts `P_device` when completions are
   pending.  `drain_block_completions()` consumes completions, validates
   both RequesterKey (process incarnation) and RequestHandle (I/O operation),
   performs `event_return()` to pop the suspended syscall EventFrame, and
   resumes the caller at user PC.

**Key architectural decisions**:

1. **Completion queue is truth; interrupt is notification.**
   Consuming P\_device does not consume completion records.  If C > 0 remains
   true after delivery, the source re-asserts.  No lost notifications.

2. **Per-source pending bits replace `Option<EventCause>`.**
   Timer and device are independent facts.  Both may be simultaneously pending.
   The old single-slot pending model literally could not express this state.

3. **DMA authority is delegated, not inherent.**
   At submission, a 512-byte WRITE-only capability is derived into a fresh
   request-local DMA domain.  DMA-DELEGATION: authority available to the
   request ⊆ authority explicitly delegated for that request.  Revocation
   before or during DMA produces StaleGeneration + error completion + zero
   mutation.

4. **Request identity is device-local and bounded.**
   `RequestHandle { slot: u8, generation: u64 }` uniquely identifies a
   request across the device's lifetime.  `RequesterKey { slot: u32,
   generation: u32 }` identifies the process incarnation.  Both must match
   before the kernel performs `event_return()`.

5. **Suspended syscall continuation via EventFrame.**
   `SYS_BLOCK_READ` leaves the syscall EventFrame outstanding while the
   process is I/O-blocked.  On completion, `event_return()` pops the
   frame — the same primitive used by ERET and resume\_from\_trap().
   The EventFrame architecture from Phase 9.0 becomes the continuation
   mechanism for asynchronous system calls.

6. **IoWait provides double identity protection.**
   `io_wait: Option<IoWait>` replaces the earlier `io_blocked: bool`.
   `IoWait` stores the `RequestHandle`, giving the completion path two
   independent stale-identity checks: RequesterKey (which process?) and
   RequestHandle (which operation?).

7. **Matched completion implies outstanding EventFrame (executable invariant).**
   `drain_block_completions()` uses `.expect()` on `event_return()`.  A
   violation is an immediate panic, not a silently corrupted process.

**Phase 9.1-pre: Fabric hardening** (before formalization):

- `MemoryRequest` carries explicit `length: u64`.  CPU constructors derive it
  from `Width`; DMA sets it directly.  Fabric authority is expressed in bytes,
  not ISA widths.
- All-or-nothing precommit gate: `validate_precommit()` performs generation
  revalidation, length match, physical bounds, and payload validation before
  any memory access.  Both `phase_commit()` and `execute_atomic_xchg()` use
  the same gate.
- Checked arithmetic: `offset+length`, `physical+length`, `base+size` all use
  `checked_add`.  Zero-length requests rejected as InvalidSpan.
- Write with absent payload faults LengthMismatch.
- 15 adversarial DMA-span tests.

**I-format immediate range hardening** (discovered during 9.1e):

The block-device test pushed guest buffer addresses beyond the MOVI signed
18-bit immediate range (0x30000 = 196608 > 131071).  The assembler silently
aliased the value: `encode_i` masked to 18 bits, `decode` sign-extended bit
17, producing a large negative address.  The CPU correctly executed the
ISA-defined encoding; the toolchain accepted an impossible operand.

Fix: `fits_imm18()` in `isa.rs` is the single definition of representability,
shared by both assembler and compiler.  `emit_i_named()` asserts the predicate.
`cc.rs` removes its `v & 0x3FFFF` pre-masking and rejects unmaterializable
literals.  Invariant: no code-generation layer may silently alias an immediate.

**Known architectural limitation — machine-time model**:

The device clock currently advances only on committed instruction boundaries
(`tick_devices()`).  The scheduler skips I/O-blocked processes.  Therefore:

> All runnable processes blocked on I/O ⇒ no committed instructions
> ⇒ devices do not advance ⇒ no completions ⇒ deadlock.

This is a genuine machine-time limitation, not a bug.  The current decisive
test avoids it by having process B run while A waits.  Future resolution
requires either an architectural idle task that generates machine boundaries,
or a device clock that can advance during CPU idle.  This is recorded as a
named pressure point for Phase 9.2 or later.

**Decisive test** (`p91e_decisive_guest_async_read`):

Process A issues `SYS_BLOCK_READ(block=0, buf=0x04000)` and blocks with its
syscall EventFrame outstanding.  Process B runs an infinite counter.  The block
controller completes A's request via narrow DMA delegation.  A device interrupt
fires during B's execution.  The handler drains the completion, validates both
RequesterKey and RequestHandle against A's `io_wait`, performs `event_return()`,
and resumes A at user PC.  A then verifies all 512 bytes of the DMA buffer:

    64 iterations × LD 8-byte word × CMP against expected u64(1)

Two independent observations agree: the guest verifies every word through its
own address space; the host independently verifies the underlying physical buffer.

**What one deliberately primitive fake disk forced into existence**:

- Byte-span Fabric authority (replacing ISA-width authorization)
- Atomic DMA precommit validation (all-or-nothing gate)
- Narrow DMA delegation (request-local domain)
- Multi-source pending interrupts (independent per-source bits)
- Bounded-service arbitration (turn-bit fairness proof)
- Level-triggered notification (completion truth ≠ interrupt)
- Completion queues (bounded, generation-qualified)
- Generation-qualified asynchronous identity (two independent checks)
- Blocked syscall continuations (EventFrame reuse)
- Toolchain immediate correctness (assembler/compiler range invariant)

557/557 tests; 29 instructions.  Phase 9.1 is complete.


## DN-15: Capability-Table Architecture and Protected Naming

**Phase**: 9.2a (Chapter 9: Anka64 as an Independent Architecture)

**Problem**: The Fabric tracks authority as structural equality over
`Capability64` values: `(object, generation, offset, length, permissions)`.
Two independently granted capabilities with identical fields are
indistinguishable.  Dropping one removes an arbitrary matching entry.
This breaks a fundamental requirement of the user-space driver model:
a driver holds delegated authority that must be revocable by exact
identity, not by structural coincidence.

The question that Phase 9.2a answered:

> How does user space name a specific authority entry without
> being able to forge, guess, or confuse it with a structurally
> equal twin?

**Decision -- three-condition resolution**:

A `CapabilityHandle` resolves to authority iff all three conditions
hold simultaneously:

1. `g_handle = g_slot` -- the handle's generation matches the slot's
   current generation (name currency).
2. `AuthorityIdExists(domain, aid)` -- the backing AuthorityId still
   exists in the Fabric domain (authority currency).
3. `g_object = g_current` -- the object's generation has not been
   advanced by revocation (object currency).

Each condition is independent.  Revoking an object invalidates
condition 3 without touching conditions 1 or 2.  Dropping a handle
invalidates conditions 1 and 2 without touching condition 3.
Removing an AuthorityId behind the scenes invalidates condition 2
even if both generations match.

**Decision -- AuthorityId as exact identity**:

`AuthorityId(u64)` is a monotonic, never-reused identifier stamped
on each authority entry at installation time.  Two capabilities with
identical `(object, offset, length, perms)` have different
AuthorityIds if they were installed separately.  This is why
AuthorityId exists:

  A1 = A2 by value  =/=>  drop(H1) removes A2.

The `remove_by_authority_id()` operation removes exactly one entry
by identity, not by structural match.

**Decision -- generation wrap prevention**:

Slot handle generations use `checked_add(1)`, not `wrapping_add(1)`.
If a slot's generation reaches `u32::MAX`, the slot enters a
retired state (`Free(u32::MAX)`) and is never reused.  This
prevents an ancient stale handle from becoming current through
generation wraparound.

AuthorityId allocation uses the same pattern: `checked_add(1)` on
a `u64` counter, returning `None` on exhaustion.  Exhaustion is a
normal resource-failure error, not undefined behavior.

**Decision -- atomic install and drop**:

`install_capability()` preflights that the cap table has an
allocatable slot *before* allocating an AuthorityId or granting
into the Fabric domain.  If the install unexpectedly fails after
granting, the newly created authority is rolled back.  Ordinary
rejection consumes no identities.

`SYS_CAP_DROP` preflights three conditions: valid handle,
AuthorityId exists in the Fabric, and the slot is recyclable
(generation < `u32::MAX`).  Both the cap-table slot and the Fabric
authority entry are removed only after all conditions pass.  The
drop path never calls `.expect()` based on a weaker preflight.

The precise 9.2a invariant:

  AuthorityId-backed cap-table authority <=> valid protected cap-table name.

Legacy untagged Fabric grants (from `grant()`/`derive()`) are
explicitly outside this bijection.

**Decision -- retired slots and allocatable capacity**:

A `Free(u32::MAX)` slot is structurally free but not allocatable.
`free_count()` counts structural free slots; `allocatable_count()`
counts free slots whose generation is not terminal.  The install
preflight uses `allocatable_count()` so a retired slot does not
cause an AuthorityId to be allocated and then rolled back.

  F_structural + O = N (always)
  F_allocatable <= F_structural

**Formal methodology note**:

All 9.2a "formal-correspondence holes" were discovered by comparing
the Rust implementation against the Kleis specification theorem,
not against the test suite.  The tests all passed (577, 580, 582,
583 at successive discovery points), but the model revealed states
the tests had not tried: non-atomic install, missing three-condition
check, generation wraparound, non-recyclable drop, and retired-slot
reuse.  Each was fixed and converted into a hostile witness test.

584/584 tests; 29 instructions.  Phase 9.2a is complete.

---

## DN-16: User-Space Capability Transfer -- Atomic Runtime Delegation

**Phase**: 9.2b (Chapter 9: Anka64 as an Independent Architecture)

**Problem**: Phase 9.2a established the naming and resolution of
capabilities within a single process.  Phase 9.2b moves authority
between live processes atomically without amplifying it.

The formal target:

  successful SEND_CAP =>
    exists unique (A_new, H_new, T_new, M_new)
    such that C_new is a subset of C_source,
    H_new names A_new,
    T_new = (client_key, driver_key, incarnation),
    and the message M_new carries H_new.

Every ordinary rejection satisfies:

  delta(A) = delta(H) = delta(M) = delta(T) = delta(identity_counters) = 0.

**Decision -- DelegationId as structured provenance**:

`DelegationId { client: ProcessKey, driver: ProcessKey, incarnation: u64 }`
is a structured type, not a bare `u64`.  This is driven directly by the
formal model: Phase 9.2e needs `T.client` for DMA quiescence queries
without maintaining a separate global lookup table.  A plain `u64`
would tell you *which* transfer but not *who* transferred, requiring
extra state to reconstruct the answer.

A fresh DelegationId is the identity of the immediate transfer event.
If A transfers to B (producing T1) and B later transfers to C
(producing T2), C carries T2, not T1.  Inherited provenance chains
are a future concern, not something to smuggle into 9.2b.

**Decision -- Kernel owns DelegationId, Fabric owns AuthorityId**:

`AuthorityId` is a Fabric concept (it identifies a domain capability
entry).  `DelegationId` contains `ProcessKey` fields, which are
kernel-layer concepts.  Making Fabric manufacture DelegationIds would
invert the layering.  Therefore:

- Fabric: `can_alloc_authority_id()`, `alloc_authority_id()`
- Kernel: `can_alloc_delegation_id()`, `alloc_delegation_id(client, driver)`

Gate 6 of the transfer preflight checks both read-only.  After the
gate passes, both allocations are guaranteed by single-threaded
exclusion between preflight and commit.

**Decision -- ProcessKey moved to state.rs**:

`ProcessKey` was originally defined in `os.rs` (the kernel module).
Because `DelegationId` in `state.rs` needs it, and it will eventually
travel into block-request metadata (`block.rs`), ProcessKey was moved
to `state.rs` as a neutral generation-qualified identity type.
`RequesterKey` was already there for the same layering reason.  Now
`os.rs`, `block.rs`, and provenance structures all refer to ProcessKey
without circular module dependencies.

**Decision -- extend SYS_RECV, not SYS_RECV_CAP**:

The formal object is one message:

  Message { from: ProcessKey, value: u64, cap: Option<CapabilityHandle> }

not two kinds of queues or receive operations.  A separate SYS_RECV_CAP
creates ugly semantics: if the queue is [ordinary, cap-bearing, ordinary],
does SYS_RECV_CAP skip messages?  Block on a non-cap head?  Use separate
queues?  Each option breaks FIFO ordering or changes the IPC model.

The clean abstraction: receive returns a message; capability transfer is
message metadata.  The extended SYS_RECV ABI uses six registers:

  R0 = value           (preserves old behavior)
  R1 = tag             (0=empty, 1=ordinary, 2=cap-bearing)
  R2 = cap handle slot (u32::MAX if none)
  R3 = cap handle generation (0 if none)
  R4 = sender process slot
  R5 = sender process generation

Existing clients that only inspect R0 continue working.

**Decision -- SYS_SEND_KEY for generation-qualified ordinary send**:

Phase 9.2 committed to ProcessKey-addressed inter-process edges.
Legacy SYS_SEND uses PID addressing, which reintroduces slot-recycling
ambiguity.  SYS_SEND_KEY (syscall 12) provides ProcessKey-addressed
ordinary send: R1=dest_slot (u32), R2=dest_generation (u32), R3=value.
Legacy SYS_SEND (syscall 3) is preserved only for old tests.  The 9.2
protocol is fully generation-qualified:

  SEND_CAP, SEND_KEY, RECV -- all expose ProcessKey semantics.

SYS_SEND_KEY error codes:

  0 = success
  1 = destination not live (malformed register, stale generation, Zombie, absent)
  2 = mailbox full

**Decision -- checked ABI decode as security boundary**:

R1-R4 are 64-bit registers naming architecturally 32-bit fields.
The ABI decoder uses `u32::try_from()` for every narrow field and
`Permissions::from_bits_checked()` for permission encoding.  A
malformed register like `0x1_0000_0001` is rejected rather than
silently aliased to 1 via `as u32`.  This prevents a malicious
guest from aliasing a forged ProcessKey or CapabilityHandle onto
a real one through high-bit smuggling.

**Decision -- Memory-only scope for 9.2b**:

`SYS_SEND_CAP` accepts only `ObjectKind::Memory` source capabilities.
`ObjectKind::Device` exists but its rights representation is
deliberately postponed to 9.2c.  Accepting device capabilities now
risks interpreting device objects through memory `Permissions`.  This
is a scope guard, not a permanent architectural restriction.

**Decision -- MAX_MAILBOX_SIZE bounded**:

`MAX_MAILBOX_SIZE = 16` is enforced by all three producers: SYS_SEND,
SYS_SEND_KEY, and SYS_SEND_CAP.  Without a universal bound, the
mailbox is not actually bounded, and the SYS_SEND_CAP preflight
cannot guarantee capacity.

**Decision -- preflight-then-commit transaction shape**:

The SYS_SEND_CAP handler is structured as:

  Gates 0-6: read-only checks (decode, dest current, source resolves,
             Memory-only, subset valid, receiver slot available,
             mailbox capacity, identity availability)

  then: allocate AuthorityId + DelegationId

  then: derive into destination domain (from exact source AuthorityId)

  then: install in receiver cap table (with DelegationId)

  then: enqueue message (capacity already preflighted)

The key transaction rule: preflight rejection consumes nothing.
Unexpected commit failure (implementation-correspondence error)
may burn monotonic identities but must not leak authority, handles,
or messages.  Structural state is rolled back; monotonic identities
are never rolled back.  No kernel panic is required to maintain
an invariant.

**Decision -- SYS_SEND_CAP error-code ABI**:

  0 = success
  1 = ABI decode failure (malformed register, bad permission bits)
  2 = destination not live (not Running, stale generation, or Zombie)
  3 = source handle does not resolve (three-condition failure)
  4 = subset/attenuation violation (non-Memory, amplification, bad range, zero length)
  5 = receiver has no allocatable cap slot
  6 = receiver mailbox full
  7 = identity space exhausted (AuthorityId or DelegationId)
  8 = internal error (unexpected commit failure; IDs consumed, no authority leaked)

Code 4 deliberately groups non-Memory rejection with subset violations:
both are "the requested capability transfer is not a valid attenuation
of the source."  A guest that needs to distinguish non-Memory from
bad-range can inspect its own capability before calling SEND_CAP.

**Decision -- exact-AuthorityId cross-domain derivation**:

`derive_from_authority_id()` locates the source capability by its
exact AuthorityId rather than by structural equality.  This preserves
the identity discipline established in 9.2a: if two value-equal
capabilities exist with different AuthorityIds, transferring one does
not consume or reference the other.

**Decision -- Zombie processes are not valid IPC destinations**:

`validate_process_key()` accepts Zombie processes because SYS_WAIT
deliberately needs to resolve a zombie child (observation of a dead
child is the purpose of WAIT).  But "generation-current" and "alive
enough to receive authority" are different predicates.

`validate_message_destination()` requires `Running` state.  A Zombie
is generation-current but dead -- delivering authority, cap-table
entries, and messages into a dead process violates the preflight
theorem's premise that the destination is live.

Both SYS_SEND_KEY and SYS_SEND_CAP use `validate_message_destination()`.

**Decision -- stale-while-queued is defined behavior**:

Installation occurs at send time.  SYS_RECV reveals a committed
handle but makes no promise that it remains valid.  If the underlying
object is revoked between send and receive, the handle resolves at
send commit but fails resolution at use time.  This is the intended
capability semantics: possession of a name does not override
subsequent object revocation.  Any actual use (SYS_DEV_SUBMIT,
memory access) re-resolves via the three-condition check.

**Rejected alternative -- SYS_RECV_CAP**:

A separate receive syscall for cap-bearing messages was rejected for
the reasons stated above.  The unified message envelope with an
optional capability handle is simpler and preserves FIFO semantics.

**Rejected alternative -- DelegationId as u64**:

A globally unique u64 tells you *which* transfer but not T.client,
which 9.2e explicitly needs for quiescence queries.  Unless a
persistent global lookup table is added (needless extra state), the
ProcessKeys belong in the provenance token itself.

**Rejected alternative -- Fabric owns DelegationId allocation**:

Rejected because it inverts the layering.  ProcessKey is a kernel
concept; Fabric should not know about processes.

616/616 tests; 29 instructions.  Phase 9.2b is complete.

---

## DN-17: Device Capability and Kind-Sensitive Authority

**Phase**: 9.2c (Chapter 9: Anka64 as an Independent Architecture)

**Problem**: Phase 9.2b moved memory authority between live processes.
Phase 9.2c asks: how does a user-space driver prove to the kernel
that it may invoke a specific device using a specific buffer — and
how does the kernel ensure no ambient authority can rescue a
deficient presented handle?

The formal target:

  Accepted(R) =>
    A_d = exact(H_d) and SubmitRead in A_d
    and A_b = exact(H_b) and WRITE in A_b
    and A_DMA is a subset of A_b
    and T_R = T(H_b).

No ambient authority may repair either presented handle.

**Decision -- kind-sensitive capability slot state**:

Memory and device capabilities carry fundamentally different rights.
`Permissions` (R/W/X/S) is meaningful for memory; `DeviceRights`
(SubmitRead, future SubmitWrite) is meaningful for devices.  Allowing
both in the same representation creates nonsensical states such as
executable devices or SubmitRead memory.

`CapabilitySlotState` is now a sum type:

  Free { handle_generation }
  Memory { object, object_generation, offset, length, perms, authority_id, delegation_id }
  Device { object, object_generation, rights, authority_id, delegation_id }

`ResolvedCapability` is similarly restructured as `Memory { ... } | Device { ... }`
with accessor methods for common fields (`authority_id()`, `object()`,
`object_generation()`, `delegation_id()`).

Illegal combinations are structurally impossible.  Pattern matching
enforces kind-sensitivity at every consumer:

  Memory authority carries Permissions.
  Device authority carries DeviceRights.

`DeviceRights` is a bitfield type with `contains()` for compositional
right checking.  Currently only `SUBMIT_READ` is defined.

**Decision -- separate Fabric device-authority collection**:

Memory authority uses the existing `Vec<CapabilityEntry>` in each
`DomainState`.  Device authority uses a new `Vec<DeviceAuthorityEntry>`.
The two collections are separate because their protected fields differ:
memory entries carry (object, generation, offset, length, permissions);
device entries carry (object, generation, rights).

Operations that generalize across kinds:

- `has_authority_id()` -- searches both collections.
- `remove_by_authority_id()` -- searches both collections.

Operations that are kind-specific:

- `grant_with_authority_id()` -- requires `ObjectKind::Memory`.
- `grant_device_with_authority_id()` -- requires `ObjectKind::Device`.
- `validate_device_authority()` -- searches device-authority collection.
- `delegate_dma_span()` and `delegate_dma_span_from_authority_id()` --
  memory-only.

Every tagged insertion boundary enforces:

  AuthorityId may occur at most once in a domain -- across both kinds.

The global monotonic allocator makes collisions impossible through
normal operation, but the grant functions accept AuthorityId as an
argument and refuse an already-present ID rather than trusting
callers blindly.

**Decision -- positive kind boundary enforcement**:

Memory-authority paths require `object.kind == ObjectKind::Memory`,
not merely "not Device."  Device-authority paths require
`object.kind == ObjectKind::Device`.  This prevents a future object
kind (e.g., `ObjectKind::Ipc`) from accidentally receiving memory
or device semantics:

  Memory authority => ObjectKind::Memory.
  Device authority => ObjectKind::Device.

The hardened paths include: `grant()`, `grant_with_authority_id()`,
`derive()`, `derive_from_authority_id()`, `delegate_dma_span()`,
`delegate_dma_span_from_authority_id()`, `grant_device_with_authority_id()`,
`install_capability()`, and `install_device_capability()`.

**Decision -- device object lifecycle without physical placement**:

A Device object is allocated via `alloc_object(ObjectKind::Device)`
and placed via `place_object()` with a zero-size span.  This
transitions the object to Active without consuming physical memory.
The object table supplies identity, generation, kind, and lifecycle
-- not a physical address.  A device object's "placement" is its
binding to the kernel's block controller, not a physical memory
region.

  object identity != memory placement.

**Decision -- generation-qualified one-shot device binding**:

`install_block_device()` allocates a `Device` object, binds it to the
existing `BlockController`, and records the binding in
`Kernel.block_device_binding: Option<DeviceBinding>`.  The binding
stores both `ObjectId` and the object's `Generation` at bind time.

The operation is one-shot: a second call returns `None`.  This
prevents rebinding a device to a different object or controller.

**Decision -- two-predicate device authority validation**:

`validate_device_authority()` takes both `exact_slot_rights` and
`required_rights`:

  A_Fabric.rights = H_device.rights  (exact match: slot matches backing)
  and H_device.rights >= SubmitRead  (capability has the needed right)

These predicates are distinct.  The exact-match predicate prevents
a backing entry from being silently widened.  The required-rights
predicate ensures the capability actually authorizes the operation.
When device rights become compositional (SubmitRead + SubmitWrite),
an equality check against SubmitRead alone would incorrectly reject
a broader capability.

**Decision -- exact-authority DMA delegation**:

`SYS_DEV_SUBMIT` does not use ambient-domain delegation.  It uses
`delegate_dma_span_from_authority_id()`, which locates the exact
authority entry named by the buffer handle's AuthorityId and derives
the DMA span only from that entry.

The primitive independently re-validates: the found entry still names
the expected object and generation, and the underlying object generation
is current.  This makes the primitive safe regardless of its caller's
earlier checks.

The causal chain:

  H_b -> A_b^exact -> A_DMA.

Not:

  H_b -> ambient domain search -> A_DMA.

This is proved by the centerpiece test: a driver holds a READ-only
buffer handle alongside an unrelated ambient WRITE capability over
the same object span.  SYS_DEV_SUBMIT fails.  The ambient authority
cannot rescue the deficient presented handle.

**Decision -- DelegationId propagation, not creation**:

SYS_DEV_SUBMIT does not allocate a DelegationId.  It copies the
buffer handle's `delegation_id` (which may be `None` for directly
provisioned authority) into the `BlockRequest` and ultimately into
the `BlockCompletion`.  This implements:

  9.2c propagates T;  9.2c never creates T.

**Decision -- request-metadata consistency invariant**:

  source_authority_id = None => delegation_id = None.

The legacy ambient-domain path may not carry asserted provenance.
This prevents an internally constructed request from using ambient
authority while attaching an arbitrary DelegationId.  The converse
need not hold: `source_authority_id = Some(A), delegation_id = None`
is valid for directly provisioned buffer capability.

This gives a clean representation invariant:

  T != None => the request used exact-authority delegation.

**Decision -- SYS_DEV_SUBMIT ABI and preflight**:

Syscall 13.  Register encoding:

  R1 = device handle slot (u32)
  R2 = device handle generation (u32)
  R3 = block number (u64)
  R4 = buffer handle slot (u32)
  R5 = buffer handle generation (u32)

R1/R2/R4/R5 use `u32::try_from()` for checked decode.

Preflight gates:

  0. ABI fields decode exactly
  1. caller is not already in IoWait
  2. H_d resolves as Device
  3. H_d has SubmitRead in Fabric and cap table
  4. H_d.object is bound to the installed BlockController
  5. H_b resolves as Memory
  6. H_b.perms >= WRITE
  7. T.driver = current ProcessKey (if T exists)

On success, the process enters IoWait with the EventFrame outstanding.
On completion, the existing timer/device interrupt → `drain_block_completions()`
→ `event_return()` path resumes the driver.

SYS_DEV_SUBMIT error codes:

  0 = success (driver enters IoWait)
  1 = ABI decode failure (malformed register, high-bit aliasing)
  2 = caller already in IoWait
  3 = device handle resolution failure (does not resolve, or not Device kind)
  4 = device authority validation failure (wrong rights, wrong binding)
  5 = no block controller or no device binding
  6 = buffer handle resolution failure (does not resolve, or not Memory kind)
  7 = buffer handle missing WRITE permission
  8 = provenance violation (T.driver != current ProcessKey)
  9 = controller rejected submission (bad block, busy slot, DMA failure)

**Decision -- legacy SYS_BLOCK_READ unchanged**:

The existing `SYS_BLOCK_READ` path uses ambient-domain delegation
with `source_authority_id: None` and `delegation_id: None`.  It
remains the kernel-mediated read path for old tests and does not
require a device capability.  SYS_DEV_SUBMIT is the new
authority-checked path.

**Phase boundary -- explicitly excluded from 9.2c**:

- No user-space interrupt delivery.
- No Device-cap transfer over SYS_SEND_CAP.
- No blocking SYS_RECV_WAIT.
- No PeerDied notification.
- No driver-death handling.
- No idle-progress change.
- No multi-device routing.
- No full client+driver guest program.

These belong to 9.2d–f.

**Hostile correspondence tests (19 witnesses)**:

The decisive tests prove both layers of the exact-authority chain:

  H_b(READ) + A_ambient(WRITE)  =>  syscall rejects
  (centerpiece: `read_handle_fails_despite_ambient_write`)

  Memory handle as Device  =>  kind gate rejects
  Device handle as buffer  =>  kind gate rejects
  High-bit handle fields   =>  ABI decode rejects

Together these establish:

  H_d -> A_d^exact -> SubmitRead checked
  H_b -> A_b^exact -> A_DMA

rather than merely proving two independent permission checks.

**Formal methodology note**:

Like 9.2a and 9.2b, the 9.2c plan was developed by comparing the
intended implementation against the Kleis specification and the
architectural thesis statement before writing any Rust code.  The
centerpiece test was designed before implementation, not discovered
afterward.

635/635 tests; 29 instructions.  Phase 9.2c is complete.

---

## DN-18: Client-Driver-Device Composition

**Phase**: 9.2d (Chapter 9: Anka64 as an Independent Architecture)

**Problem**: Phases 9.2a-c established naming (handles), transfer
(SYS_SEND_CAP), and consumption (SYS_DEV_SUBMIT) as independent
mechanisms.  Phase 9.2d asks whether they compose: can an ordinary
client delegate narrow buffer authority to an untrusted user-space
driver, which combines it with its own device authority, completes
I/O, and returns the result — without either process acquiring any
authority not explicitly given to it?

The decisive composition test uses real Asm64 guest programs — the
first time SYS_SEND_CAP and SYS_DEV_SUBMIT are issued by guest code
rather than test-harness kernel API calls.

**Decision -- formal composition theory before implementation**:

`theories/anka_driver_composition.kleis` was written and verified
before any Rust composition test.  It derives 9 composition
properties and 4 falsifiability witnesses from the already-
established 9.2a-c predicates, with no new axioms:

- COMP-1: successful SEND_CAP gives exact derived driver buffer authority.
- COMP-2: accepted composition requires device authority AND exact
  transferred buffer authority (independent conjuncts).
- COMP-3: A_DMA is a subset of exact transferred driver buffer authority.
- COMP-4: end-to-end non-amplification A_DMA ⊆ A_driver_buffer ⊆ A_client_buffer.
- COMP-5: DelegationId preserved from SEND_CAP through request and completion.
- COMP-6: composition leaves client device authority unchanged.
- COMP-7: dropping driver transferred handle after acceptance does not
  destroy request-local DMA authority.
- COMP-8: terminal completion + CAP_DROP leaves driver device authority
  but not client buffer authority.
- COMP-TIME-1: polling client keeps composition outside the known
  all-blocked dead state.

The 4 false witnesses verify: device authority alone is insufficient,
ambient WRITE cannot substitute for exact transferred authority, DMA
cannot exceed transferred authority, and DEV_SUBMIT cannot replace
DelegationId with a fresh one.  Z3 rejects all four.

**Decision -- no new mechanism**:

The entire composition path uses exactly four existing syscalls:

  SYS_SEND_CAP → SYS_RECV → SYS_DEV_SUBMIT → SYS_SEND_KEY.

No new syscall, no kernel code change, no new type.  The only
implementation addition is test code.  This validates the
architectural thesis: if 9.2a-c are really complete, 9.2d requires
no new mechanism.

The one non-test addition: `BlockController::in_flight_requests()`
accessor to allow hostile tests to verify request metadata.

**Decision -- real guest programs, not kernel API calls**:

The decisive test builds two Asm64 programs:

Client (46 words):
  1. Write sentinel values around a 512-byte buffer region.
  2. SYS_SEND_CAP: transfer a 512-byte WRITE capability to the driver.
  3. Poll SYS_RECV for the driver's completion message.
  4. Verify sentinels untouched and DMA data arrived.
  5. SYS_EXIT(200) on success; distinct error codes on failure.

Driver (30 words):
  1. Poll SYS_RECV for client request (cap-bearing message).
  2. Save sender ProcessKey and buffer handle in high registers.
  3. SYS_DEV_SUBMIT with device cap (slot 0) + received buffer cap.
  4. Block in IoWait, resume on device completion.
  5. SYS_SEND_KEY completion to exact client ProcessKey.
  6. SYS_EXIT(200).

The kernel schedules both processes via round-robin with timer
preemption.  The client polls while the driver is in IoWait, keeping
the composition outside the known machine-time dead state.

Verification is two-sided: guest-side (both exit with code 200) and
host-side (physical memory contains exact block data at the DMA
target, sentinels untouched).

**Decision -- hostile composition tests attack the joins**:

The hostile suite does not re-test individual mechanisms.  Each test
attacks a specific composition joint:

1. Driver cannot DEV_SUBMIT before receiving client's buffer cap.
2. Client has no device authority at any point in the composition.
3. DelegationId end-to-end: T created by SYS_SEND_CAP is the same T
   in the accepted block request (COMP-5).
4. Authority postconditions: after completion + CAP_DROP, driver retains
   device authority but not client buffer authority (COMP-8).
5. Ambient driver WRITE irrelevant: READ-only transferred handle fails
   DEV_SUBMIT despite ambient WRITE over the same span (FALSE-COMP-2).
6. CAP_DROP after acceptance does not cancel request-local DMA (COMP-7).
7. Stale client incarnation rejected by completion SEND_KEY.
8. Non-amplification chain: narrow 512-byte transferred handle is the
   exact authority used for DEV_SUBMIT.

**The authority lifecycle across the composition**:

  Before:   client = buffer authority; driver = device authority.
  During:   driver += delegated narrow buffer authority; DMA = narrower.
  After:    driver = device authority only; DMA = gone.

Authority temporarily crosses the trust boundary and then disappears.

644/644 tests; 29 instructions.  Phase 9.2d is complete.

## DN-19: Blocking IPC, Idle Progress, and the PeerDied Causal Barrier

**Phase**: 9.2e (Chapter 9: Anka64 as an Independent Architecture)

**Problem**: The 9.2d composition works, but the client busy-polls
`SYS_RECV` while the driver is in IoWait.  That keeps at least one
process schedulable, hiding a latent liveness question: what happens
when *every* guest process is blocked and only autonomous DMA remains?

The prior scheduler treated "all exited" as the termination condition.
With autonomous I/O, a driver can die after the controller has accepted
an operation.  The correct stopping condition is:

    ¬Runnable ∧ ¬Resolvable ∧ ¬AutonomousIO ⇒ Stop.

**Decision -- SYS_RECV_WAIT (syscall 14) is a scheduling field, not
a state**: A process in RecvWait remains `ProcessState::Running` —
just not schedulable.  The `recv_wait: Option<RecvWait>` field joins
`waiting_on` and `io_wait` as the third scheduling blocker,
consolidated under a single `is_schedulable()` predicate:

```rust
fn is_schedulable(&self) -> bool {
    self.state == ProcessState::Running
        && self.waiting_on.is_none()
        && self.io_wait.is_none()
        && self.recv_wait.is_none()
}
```

**Decision -- exact-peer blocking receive with message-before-death
ordering**: SYS_RECV_WAIT takes a generation-qualified ProcessKey.
The decision order is:

  1. Search mailbox for exact-peer message (queued history first).
  2. Inspect peer incarnation state.
  3. Return immediately or install RecvWait.

A queued message from a dead or recycled peer wins over stale-key
error.  This preserves successfully delivered history.

**Decision -- single internal delivery operation**: All three message
producers (SYS_SEND, SYS_SEND_KEY, SYS_SEND_CAP) route through one
`deliver_message()` function using a `DeliveryRoute` enum:

  - **Direct**: destination has RecvWait(sender) — bypasses mailbox.
  - **Enqueue**: mailbox has room.
  - **Full**: mailbox full, no direct route — reject.

Direct delivery bypasses mailbox capacity only; all other validations
remain intact.  SYS_SEND_CAP preserves atomic preflight ordering:
cap-slot/authority checks first, then authority+handle installation,
then receive completion.

**Decision -- idle progress is a kernel machine boundary, not a
synthetic process**: No domain, no identity, no capabilities.  The
scheduler becomes a four-phase selector:

  Resolvable                              ⇒ Resolve
  ¬Resolvable ∧ Runnable                  ⇒ Run
  ¬Resolvable ∧ ¬Runnable ∧ AutonomousIO  ⇒ Idle
  ¬Resolvable ∧ ¬Runnable ∧ ¬AutonomousIO ⇒ Stop

The Resolve phase drains completed block I/O, reevaluates RecvWaits,
and wakes child waiters — in that order.  Idle progress advances the
block controller once, drains resulting completions, and reevaluates
RecvWaits.  Timer does NOT advance during idle: "committed instruction
⇒ timer tick" is preserved.

`BlockController::has_autonomous_work()` returns true for Waiting,
DmaReady, or DmaInFlight.  Completed is *not* autonomous work — it
is immediately serviceable kernel work.

**Decision -- quiescence-gated PeerDied keyed by ProcessKey pair**:
`has_nonterminal_pair_request(client, driver)` scans Waiting,
DmaReady, and DmaInFlight slots using pair-level matching (client +
driver ProcessKey, ignoring DelegationId incarnation).

When a peer dies:
  - If the pair has nonterminal requests: RecvWait stays installed.
  - If the pair is quiescent: PeerDied(peer_key) is delivered.

`reevaluate_recv_waits()` is called after every completion drain
(resolve phase, idle progress, device interrupt).  The death predicate
is incarnation-based: a generation mismatch means the awaited
incarnation was reclaimed.  Only Running clients receive PeerDied.

This establishes the causal barrier:

    PeerDied(C,D) ⇒ no accepted nonterminal work attributable
                     to (C,D) can subsequently mutate client-visible
                     DMA state.

    t ≥ t_PeerDied ⇒ M_target(t) = M_target(t_PeerDied).

**Formal basis**:

- `theories/anka_blocking_receive.kleis`:
  45/45 positive claims verified, 0 new axioms;
  imports only `anka_userspace_driver.kleis`;
  kleis check: 63 functions, 0 data types, 0 structures.

- `theories/anka_blocking_receive_false_witnesses.kleis`:
  0/7 claims pass — all seven deliberately false architectural
  statements are rejected (nonzero exit, as intended).

**Hostile coverage** (42 p92e_ tests):

  1. Unrelated sender cannot wake exact wait.
  2. Queued exact-peer message beats later peer death and recycling.
  3. Direct message before death — Message wins over PeerDied.
  4. Recycled generation cannot satisfy old wait.
  5. Cap-bearing direct delivery works.
  6. Zombie/quiescent peer produces immediate PeerDied.
  7. All-blocked/no-async state stops, does not spin.
  8. Full mailbox does not block exact direct delivery (all 3 producers).
  9. SEND_CAP direct route with full cap table is atomic failure.
 10. All-exited + autonomous DMA does not terminate early.
 11. Completed-but-undrained I/O resolved before Stop.
 12. Reclaimed peer incarnation still yields PeerDied for stored old key.
 13. Dead waiting client receives no IPC completion.
 14. Nonterminal pair request prevents premature PeerDied.
 15. Post-PeerDied DMA mutation impossible (unit + guest integration).

**Decisive composition witnesses**:

  - `p92e6_blocking_composition`: Client SEND_CAP → RECV_WAIT,
    Driver RECV → DEV_SUBMIT → IoWait.  Explicit all-blocked state
    witnessed.  Idle progress resolves DMA, driver SEND_KEYs client
    via direct delivery.  Both exit 200.

  - `p92e7_death_quiescence_integration`: Same guest setup, but
    driver is killed while DMA is nonterminal.  Quiescence gate
    holds.  Idle progress completes DMA.  PeerDied fires with exact
    block data committed.  Post-notification memory frozen.

690/690 tests; 29 instructions.  Phase 9.2e is complete.

## DN-20: Multi-Request Pair Quiescence (Phase 9.2f)

Phase 9.2e's quiescence gate was per-pair but implicitly single-request:
the test witness was always one-request-goes-terminal → PeerDied.

Phase 9.2f extends this to multiple concurrent requests per (C,D) pair,
proving that PeerDied is gated on the terminality of *all* accepted
requests attributed to that pair, not just one.

### Three-lifetime separation

The architecture enforces three genuinely independent lifetimes:

  1. **Accepted hardware request lifetime** — begins at controller
     acceptance, ends when the slot reaches Completed/Free.
  2. **Process incarnation lifetime** — begins at spawn(), ends at
     finish_process() (Zombie) and reclaim_process() (Free/Retired).
  3. **Software completion-record lifetime** — begins when
     `drain_block_completions()` fills the per-process async ledger
     entry, ends when `SYS_DEV_WAIT` reaps it or reclaim clears it.

These three lifetimes can overlap arbitrarily:

  - A completion record can outlive the hardware slot it came from
    (the slot is reused with a new generation while the old completion
    remains in the ledger).
  - A hardware request can outlive its submitting process (the driver
    dies while DMA is in flight; the request becomes terminal
    autonomously).
  - A completion record can outlive its process incarnation (but only
    until `reclaim_process()` clears it — the new incarnation starts
    with an empty ledger).

### Async submission ABI

Two new syscalls:

  - `SYS_DEV_SUBMIT_ASYNC` (15): same preflight as `SYS_DEV_SUBMIT`,
    returns immediately with `R0=0, R1=handle.slot, R2=handle.generation`.
    Records an `AsyncDeviceRequest` in the per-process ledger.
  - `SYS_DEV_WAIT` (16): wait for a specific `RequestHandle`.
    Immediate return if completed; blocks via IoWait if pending;
    error 1 for stale/unknown; error 2 if already in IoWait.

Transactional order (frozen):

    io_wait gate → pure preflight → ledger capacity →
    controller capacity → mint DMA → submit → publish

`preflight_dev_submit(&self)` is side-effect free: no DMA domains
created, no authority IDs consumed.  Failure at any gate implies
zero side effects on controller, ledger, domains, and authority IDs.

### Completion drain routing

Two-guard routing in `drain_block_completions()`:

  1. Exact-incarnation match: `current_process_key(slot) == requester`.
  2. Process must be Running.

A dead or recycled incarnation's completion is consumed at the
controller level (making the request terminal for pair-quiescence)
but does not mutate registers, EventFrames, io_wait, or async ledger.

Within the exact Running incarnation:

    IoWait(h) ∧ Ledger(h) ⇒ wake caller AND consume Ledger(h).

### Quantitative pair quiescence

`nonterminal_pair_request_count(C, D)` replaces the old Boolean
predicate.  `has_nonterminal_pair_request(C, D) ≡ count ≠ 0`.

The decisive requirement is:

    PairCount(C,D): 2 → [1] → 0

with RecvWait(C,D) explicitly surviving at counts 2 and 1, and
PeerDied delivered only at count 0.

### PeerDied predicate (final form)

    PeerDied(C, D_g) ⟺ Dead(D_g) ∧ PairCount(C, D_g) = 0

Controller-slot reuse, unread software completions, and D_{g+1}'s
active work are all irrelevant to this predicate.

### Formal basis

- `theories/anka_multi_request_quiescence.kleis`:
  11/11 positive claims verified; imports `anka_blocking_receive.kleis`.

- `theories/anka_multi_request_quiescence_false_witnesses.kleis`:
  0/5 claims pass — all five deliberately false statements rejected.

### Hostile coverage (10 p92f_ tests)

  1. Two async submissions produce distinct full handles.
  2. Completion(h_A) cannot wake IoWait(h_B) — staggered decisive state.
  3. Completed A reapable after controller slot reused by B
     (RequestHandle lifetime < CompletionRecord lifetime).
  4. Stale generation cannot alias recycled controller request.
  5. Recycled incarnation D_{g+1} cannot consume D_g's completion.
  6. Dead requester: ΔRegisters = ΔEventFrames = ΔIoWait = ΔLedger = 0.
  7. Third request on occupied slots: ΔDomain = ΔAuthority = ΔLedger
     = ΔController = 0.
  8. 17th unreaped async result: ledger full, atomic rejection.

### Decisive integration witnesses

  - `p92f6_two_request_pair_quiescence` + `9.2f.7` extensions:
    PairCount 2 → [1] → 0, with four-point domain count
    (D_0 → D_0+2 → D_0+1 → D_0), two-buffer causal barrier
    ((A_0,B_0) ≠ (A_P,B_P) = (A_∞,B_∞)), and non-vacuous
    intermediate memory witness at count=1.

  - `p92f8_recycled_driver_concurrency_adversary`:
    PairCount(C,D_g)=0 ∧ PairCount(C,D_{g+1})=1 ⇒ PeerDied(C,D_g)
    despite AutonomousIO=true globally.  Proves pair quiescence is
    per-generation, not global.

700/700 tests; 29 instructions.  Phase 9.2f is complete.
The 9.2 umbrella (capabilities → device authority → composition →
blocking IPC → multi-request quiescence) is closed.


## DN-21: Runtime Device-Capability Transfer (Phase 9.3a)

Phase 9.3a removes the last special-case kernel-to-driver device provisioning
path.  After this phase, device authority reaches a driver through ordinary
`SYS_SEND_CAP` capability transfer — the same mechanism used for memory
capabilities since Phase 9.2b.

### Kind-sensitive SYS_SEND_CAP

The ABI now resolves the source capability kind before interpreting R5/R6/R7:

```text
resolve destination → resolve presented source →
Kind(source) → Interpretation(R5, R6, R7) →
kind-specific attenuation → receiver-cap capacity →
delivery route → identity availability →
derive child authority → install child handle + provenance → deliver.
```

**Memory source:** R5=offset, R6=length, R7=Permissions (unchanged).
**Device source:** R5=0 R6=0 required (non-spatial authority), R7=DeviceRights.

This ordering protects the ABI from accidental cross-kind interpretation:
R7=0x02 is valid `Permissions::WRITE` but undefined `DeviceRights`, and is
correctly rejected with error 1 only because R7 is decoded *after* the source
kind is known.

### Dual attenuation check

Two independent subset checks enforce the exact-presented-authority principle:

  1. **Gate 2b (handle_send_cap):** `child_rights ⊆ presented_rights`
  2. **Fabric primitive:** `child_rights ⊆ backing_rights`

The Fabric `derive_device_from_authority_id()` independently verifies that the
backing entry matches the presented object, generation, and rights exactly,
then checks `child_rights ⊆ backing_rights`.  This prevents a backing
authority from ever "rescuing" an insufficient presented capability — the
same rule that governed the 9.2c exact-presented-authority design.

### Attenuation lattice

`DeviceRights::NONE` is the bottom element:

```text
∅ ⊆ SUBMIT_READ ⊆ …
```

A `SUBMIT_READ → NONE` transfer succeeds, but the resulting child capability
cannot authorize `SYS_DEV_SUBMIT`.  Possession of a device capability is
not itself authority to operate the device.

### Rollback symmetry

Commit creates two artifacts: a Fabric `DeviceAuthorityEntry` and a receiver
`CapabilityEntry::Device`.  If an unexpected error occurs after both are
created, rollback removes both:

```text
Error(8) ⇒ ΔLiveAuthority = ΔLiveCapability = ΔMessage = 0
```

Preflight-failure is stronger:

```text
ΔAuthorityIdCounter = ΔDelegationIdCounter = 0
```

### Error ABI (generalized)

  1. Malformed ABI / invalid kind-specific rights bits
  2. Destination not live
  3. Source handle does not resolve
  4. Kind-specific attenuation/shape violation
  5. Receiver cap table full
  6. Receiver mailbox full
  7. Identity space exhausted
  8. Internal error (IDs consumed, no live authority leaked)

### Formal gate

```text
anka_device_capability_transfer.kleis:       12/12 positive examples
anka_device_capability_transfer_false_witnesses.kleis: 0/5 pass (all rejected)
```

### Hostile suite (15 tests)

  1. Successful transfer preserves ObjectId, Generation, Kind=Device.
  2. Non-amplification: NONE→SUBMIT_READ rejects.
  3. SUBMIT_READ→NONE succeeds; child cannot DEV_SUBMIT.
  4. R5≠0 rejects (error 4).
  5. R6≠0 rejects (error 4).
  6. R7=0x02 undefined DeviceRights → error 1 (Kind→Decode witness).
  7. Fresh AuthorityId + DelegationId(client,driver) in receiver.
  8. Transferred device cap usable for DEV_SUBMIT.
  9. Sender CAP_DROP ⇏ child revocation.
  10. Sender death ⇏ child revocation.
  11. Kind preservation: Device child in device_authorities, not memory caps.
  12. Receiver-table-full: ΔAuthority = ΔHandle = ΔMessage = 0.
  13. Direct delivery via SYS_RECV_WAIT: full ABI (R1=2, cap handle,
      sender ProcessKey, mailbox unchanged).
  14. Fabric derive rejects presented/backing object mismatch.
  15. Delivery-Full (full mailbox, no RecvWait): error 6,
      ΔAuthorityId = ΔDelegationId = ΔDeviceAuthority = ΔCapSlot = ΔMailbox = 0.

### Decisive integration witness

`p93a_4_supervisor_to_driver_integration`:

```text
KernelBootstrap → Supervisor → SYS_SEND_CAP → Driver → SYS_DEV_SUBMIT → Device
```

The kernel bootstraps root device authority to the supervisor.  The supervisor
delegates via ordinary `SYS_SEND_CAP`.  The driver uses the transferred
capability for `SYS_DEV_SUBMIT`.  Supervisor then drops its cap; the driver's
authority survives.  DMA commits 512 bytes through the delegated authority
chain.  No special kernel-to-driver provisioning path exists.

716/716 tests; 29 instructions.  Phase 9.3a is complete.

## DN-22: Multiple Device Instances and Routing (Phase 9.3b)

Phase 9.3b generalizes the device architecture from a single block controller
to a registry of multiple independently addressable devices.

### Identity Hierarchy

The identity hierarchy established by 9.3b is:

```text
ProcessIdentity        = (slot, generation)
DeviceIdentity         = (ObjectId, Generation)     — DeviceBinding
LocalRequestIdentity   = (slot, generation)         — RequestHandle
MachineRequestIdentity = (DeviceIdentity, LocalRequestIdentity) — DeviceRequestKey
```

`DeviceBinding = (ObjectId, Generation)` is the generation-qualified device
identity.  `RequestHandle` is controller-local: two controllers may
independently issue `(slot=0, gen=0)`.  `DeviceRequestKey` resolves this
ambiguity by qualifying the controller-local handle with the device identity.

### Architecture

**DeviceRegistry.**  `Vec<DeviceSlot>` replaces the singleton
`block_controller` and `block_device_binding`.  Each slot holds a
`DeviceBinding` and a `BlockController`.  The vector index is storage location
only:

```text
RegistryIndex ≠ DeviceBinding ≠ Authority
```

**Routing.**  The presented Device capability selects the controller.
`preflight_dev_submit` resolves `DeviceBinding` from the capability and looks
up the registry by exact `(ObjectId, Generation)` match.  There is no way to
use `H_A` to name controller B.

**Aggregate interrupt.**  One machine tick calls `tick()` on every registered
controller.  If any controller requires attention, one generic device interrupt
is posted.  The handler drains all controllers:

```text
tick A; tick B; …
if any attention: post generic device interrupt
handle interrupt: drain A; drain B; …; reevaluate recv_waits
```

**Completion routing.**  `drain_block_completions` qualifies each controller-
local completion as `DeviceRequestKey` before matching against process state.
`InterruptTarget ≠ CompletionOwner`: the process that took the interrupt does
not select whose I/O completed.

**Registry-wide quiescence.**

```text
Count_registry(C,D) = Σ Count_device(C,D) over all registered devices
```

`PeerDied(C,D)` requires `Count_registry(C,D) = 0`.  Work on device B for the
same pair blocks `PeerDied` even if device A is quiescent.  Work on device B
for an unrelated pair `(X,D)` does not block `PeerDied(C,D)`.

**Extended ABI.**

```text
SYS_DEV_SUBMIT_ASYNC success: R0=0, R1=slot, R2=gen, R3=device.object, R4=device.generation
SYS_DEV_WAIT input:           R1=slot, R2=gen, R3=device.object, R4=device.generation
```

The `(R3, R4)` ticket is namespace qualification, not renewed authority.  An
accepted request outlives possession of the device capability:

```text
Submit(H_A) → Drop(H_A) → DEV_WAIT(A, handle) = success
```

**Legacy compatibility.**  `SYS_BLOCK_READ` resolves through
`legacy_block_device: Option<DeviceBinding>`, set once when the first block
device is registered.  This is a compatibility routing alias, not device
identity or authority.

### Formal Basis

```text
anka_multi_device_routing.kleis              — 14/14 positive
anka_multi_device_routing_false_witnesses.kleis — 0/5 false claims pass
```

### Hostile Suite (11 tests)

| # | Test | Property |
|---|------|----------|
| 1 | exact_device_routing | Present(H_A) → 0xAA, ΔController_B = 0 |
| 2 | transferred_cap_routes_same_device | child of H_A still routes A |
| 3 | stale_binding_rejected | wrong generation → submission fails |
| 4 | cross_completion_isolation | Completion(B,0,0) cannot wake IoWait(A,0,0) |
| 5 | dual_ledger_coexistence | (A,0,0) + (B,0,0) coexist; reap A leaves B |
| 6 | registry_pair_count | Count_A=1, Count_B=1 → Count_registry=2 |
| 7 | cross_device_quiescence | B's same-pair work blocks PeerDied |
| 8 | unrelated_device_autonomy | B's unrelated-pair work permits PeerDied |
| 9 | aggregate_interrupt_three_process | Completion_A→P1, Completion_B→P2, ΔP3=0 |
| 10 | capability_drop_lifetime | Submit→Drop→DEV_WAIT = success |
| 11 | dev_wait_ticket_hardening | R1 overflow + unknown R3/R4 → error 1, Δ=0 |

The decisive collision is tests 4–5: `h_A = h_B = (0,0)` but
`DeviceRequestKey_A ≠ DeviceRequestKey_B`.  This is the identity alias that
was safe with one controller but would silently corrupt two-device operation.

727/727 tests; 29 instructions.  Phase 9.3b is complete.

---

## DN-23: Generic Device Substrate (Phase 9.3c)

### Central Theorem

```text
Generic(Block) = Block
```

Genericization may change representation, but not semantics.  Every
pre-9.3c observable remains unchanged through the generic substrate.

### Architecture

Phase 9.3c extracts the device-type-agnostic machinery from the
block-specific implementation by introducing:

```text
enum DeviceController {
    Block(BlockController),
}
```

with a **generic surface** for kernel device machinery:

| Method | GENDEV | Purpose |
|--------|--------|---------|
| `tick` | 1 | Advance device by one machine tick |
| `has_autonomous_work` | 2 | In-flight DMA / device activity |
| `requires_attention` | 3 | Serviceable completions exist |
| `nonterminal_pair_request_count` | 4 | Pair-attributed quiescence (quantitative) |
| `has_nonterminal_pair_request` | — | Derived: `count != 0` (never independently dispatched) |
| `completion_count` | — | Number of ready completions |
| `consume_completion` | — | Pop as lossless `DeviceCompletion` envelope |
| `free_slot_count` | — | Request-slot capacity |

**Block-specific operations** (`submit`, `storage_ref`, `storage_mut`,
`in_flight_requests`) require explicit unwrapping via `as_block()` /
`as_block_mut()`.  When the NIC variant arrives, Rust's exhaustive
matching will force each block-specific call site to be revisited.

### Lossless Completion Envelope

```text
enum DeviceCompletion {
    Block(BlockCompletion),
}
```

The generic completion wraps rather than projects:

- **Generic accessors** (`handle()`, `requester()`, `status()`) used
  by `drain_completions()` for routing.
- **Block-specific payload** (`block_number`, `delegation_id`) preserved
  inside the envelope.  Pattern match to unwrap.

This avoids prematurely impoverishing the completion type.  A future
NIC completion (packet length, descriptor, RX/TX) simply adds:

```text
enum DeviceCompletion {
    Block(BlockCompletion),
    Nic(NicCompletion),
}
```

### Derived Boolean Invariant

```text
HasNonterminal(C,D) <=> Count(C,D) != 0
```

`has_nonterminal_pair_request` is defined in terms of
`nonterminal_pair_request_count`, not independently dispatched.
This prevents the Boolean and the count from diverging when a second
device implementation arrives.

### Formal Basis

```text
anka_generic_device_refinement.kleis              — 13/13 positive
anka_generic_device_refinement_false_witnesses.kleis — 0/5 false claims pass
```

### GENDEV Traceability

| GENDEV | Claim | Runtime Witness |
|--------|-------|-----------------|
| 1–4 | Block wrapper preserves tick/autonomous/attention/pair-count | `p93c_generic_block_observables_preserved` |
| 5 | DeviceBinding identity preserved | `p93c_generic_binding_identity_preserved` |
| 6 | All-Block registry pair count = block aggregate | `p93c_generic_registry_pair_count_equals_block` |
| 7 | PeerDied conservative extension | `p93b4_7_cross_device_quiescence_blocks_peer_died` (9.3b) |
| 8 | Request-handle collision isolation | `p93b4_4_cross_completion_isolation` (9.3b) |
| 9–10 | InterruptTarget ≠ CompletionOwner | `p93b4_9_aggregate_interrupt_three_process` (9.3b) |
| 11 | Ambient rights cannot rescue | 9.3a exact-presented-authority hostile suite |
| 12 | Exact generation-qualified routing | `p93b4_1_exact_device_routing` (9.3b) |
| 13 | Registry-order independence | `p93c_generic_registry_order_independent` |
| — | Lossless completion round-trip | `p93c_block_completion_round_trip_preserves_payload` |

### What 9.3c Does Not Do

- No NIC variant.  `DeviceController` has only `Block`.
- No trait-based polymorphism.  The enum is sufficient.
- No generic request payload.  `BlockRequest` stays block-specific.
- No device unregister/recycling.

### Generic/Specific Boundary

```text
Generic:  tick, attention, autonomy, completion, pair quiescence
Specific: submit payload, storage, block/NIC operation
```

That is the boundary the NIC should challenge.

732/732 tests; 29 instructions.  Phase 9.3c is complete.

## DN-24: User-Space Device Event Delivery (Phase 9.3d)

### Central Theorem

```text
Delivery = AcceptedWait ∧ ExactProcessIncarnation ∧ ExactDeviceBinding ∧ EpochChanged
```

Three things are intentionally excluded from delivery:

```text
CapabilityPossession ∉ Delivery
InterruptTarget      ∉ Delivery
CompletionExistence  ∉ Delivery
```

### Architecture

Phase 9.3d adds a generic device event mechanism: a process can
subscribe to learn that a device has produced new activity since
a given epoch, without knowing what the activity was.

The event means only:

```text
"this exact DeviceBinding's activity epoch has advanced since e_o."
```

It carries no device-specific payload.  A future NIC-specific API
decides whether the activity means RX data, TX completion, or
link-state change.  This keeps the generic substrate from learning
NIC vocabulary.

### Rights Encoding

```text
DeviceRights::EVENT_WAIT = 0x04
DeviceRights::ALL_BITS   = 0x05  (SUBMIT_READ | EVENT_WAIT)
0x02 remains undefined — hostile decoder witness preserved from 9.3a.
```

The authority rule:

```text
EventWaitAllowed = ExactBinding ∧ PresentedRights ⊇ EVENT_WAIT
```

SUBMIT_READ alone is insufficient.  Ambient EVENT_WAIT authority
elsewhere in the process cannot rescue the presented capability.

### Syscall ABI

```text
SYS_DEV_EVENT_WAIT = 17

R1 in  = device capability slot      (u32 checked)
R2 in  = device capability generation (u32 checked)
R3 in  = observed activity epoch

R0 out = status (0 = epoch advanced, 1 = handle error, 4 = no EVENT_WAIT)
R1 out = current/new activity epoch
```

### Check-or-Block Protocol

The syscall is atomic — no scheduler-visible point between ReadSeq
and InstallWait:

```text
DecodeHandle
  → ResolveExactDeviceCap
  → ValidateExactBackingAuthority(EVENT_WAIT)
  → LookupExactDeviceBinding
  → ReadEpoch
  → { Return(current) if current ≠ observed
     | InstallWait    if current = observed }
```

On immediate return: `resume_from_trap(idx)`.
On block: `event_wait = Some(DeviceEventWait { binding, observed })`,
no `resume_from_trap`, EventFrame outstanding — exactly like RecvWait.

The syscall is a cursor operation:

```text
e_next = DEV_EVENT_WAIT(H, e_observed)
```

Userspace can repeat forever.

### Activity Epoch

`event_sequence` is a `u64` in `BlockController` (and generically
accessible via `DeviceController::event_sequence()`).

Increment rule: exactly once on the `Nonterminal → CompletionReady`
transition, never per-tick while a completion remains ready.

```text
self.event_sequence = self.event_sequence
    .checked_add(1)
    .expect("device event sequence exhausted");
```

No silent wrapping — prevents ABA across device recycling.
Later device recycling can turn exhaustion into a new DeviceBinding.

### Blocking State

```text
struct DeviceEventWait {
    device: DeviceBinding,
    observed_sequence: u64,
}
```

Invariant: `IoWait + RecvWait + DeviceEventWait ≤ 1` for any process.
`event_wait.is_some()` makes the process unschedulable through the
same predicate as existing waits.

Process death clears the event wait:
- `finish_process()` sets `event_wait = None` when state → Zombie.
- `reclaim_process()` sets `event_wait = None` before reuse.

An accepted wait belongs to the exact incarnation.  Lifecycle erasure
before slot reuse structurally enforces ExactProcessKey without
redundantly storing a ProcessKey inside the wait record.

### Broadcast Event Delivery

`reevaluate_event_waits()` scans all Running processes with
`event_wait.is_some()`.  If the device's current epoch differs from
the observed epoch, the process wakes with R0=0, R1=current_epoch.

Delivery is broadcast: if P1 and P2 both wait on (A, e) and A
advances, both wake.  The sequence is device state, not a queued
event token — one waiter waking does not consume anything.

```text
Wait(P1,A,e) ∧ Wait(P2,A,e) ∧ Seq_A ≠ e ⇒ Wake(P1) ∧ Wake(P2)
```

### Service Path Integration

`reevaluate_event_waits()` is called from all three service paths:

1. Main run loop — after `drain_completions` + `reevaluate_recv_waits`
2. `idle_progress_once` — after drain + reevaluate_recv_waits
3. `handle_async_interrupt` — after drain + reevaluate_recv_waits

Crucially: runs even when `drain_completions` drains zero completions.

```text
EventWake ≠> CompletionExists
```

This is the preparation for unsolicited NIC RX.

### Formal Basis

```text
anka_user_device_events.kleis              — 16/16 positive
anka_user_device_events_false_witnesses.kleis — 0/8 false claims pass
```

### DEVEVENT Traceability

| DEVEVENT | Claim | Runtime Witness |
|----------|-------|-----------------|
| 3 | EVENT_WAIT right required | `p93d_event_wait_requires_event_wait_right` |
| 4 | No ambient rescue | `p93d_event_wait_no_ambient_rescue` |
| 5 | Epoch changed → immediate return | `p93d_event_wait_immediate_return` |
| 6 | Epoch unchanged → block | `p93d_event_wait_blocks_on_same_epoch` |
| 8 | Completion advances epoch → wake | `p93d_event_wait_wakes_on_completion` |
| 9 | Transfer preserves EVENT_WAIT | `p93d_event_wait_transfer_blocks_and_wakes` |
| 10 | IRQ target ≠ event owner | `p93d_event_wait_irq_target_not_owner` |
| 11 | Broadcast delivery | `p93d_event_wait_broadcast_two_waiters` |
| 13 | 0x02 remains invalid | `p93d_event_wait_0x02_remains_invalid` |
| 14 | Cross-device isolation | `p93d_event_wait_cross_device_isolation` |
| — | Cursor loop | `p93d_event_wait_cursor_loop` |
| — | Incarnation isolation | `p93d_event_wait_incarnation_isolation` |

### What 9.3d Does Not Do

- No device-specific event payload.  The event is "epoch advanced."
- No NIC variant.  `BlockController` is the only event source.
- No revocation.  Capability drop cannot retroactively cancel an
  accepted event wait (and no reachable trace produces this).
- No device unregister/recycling.
- No multiple event sources per device (future: NIC RX vs TX vs link).

### Generic Event Contract

```text
DeviceEventIdentity = (DeviceBinding, EventSequence)
```

The same numerical sequence on devices A and B is not the same
occurrence.  Neither is the same ObjectId/sequence across different
device generations.

The resulting generic event substrate:

```text
event_sequence()          — DeviceController generic accessor
DeviceEventWait           — kernel wait record
SYS_DEV_EVENT_WAIT        — guest syscall (check-or-block)
reevaluate_event_waits()  — broadcast delivery (all service paths)
```

744/744 tests; 30 instructions.  Phase 9.3d is complete.

---

## DN-25: User-Space NIC — Unsolicited Arrival Semantics (Phase 9.3e.3)

**Date:** 2026-09-15

**Context:**

The block device produces completions in response to guest-initiated
requests.  A NIC produces unsolicited packet arrivals that have no
guest-side antecedent.  This is the first architectural occurrence of
host-initiated device-private state change.

**The decisive separation:**

```text
PacketArrival ≠ DeviceRequest
```

An arriving packet enters a bounded device-private queue.  It does not
create a `DeviceRequestKey`, does not produce a delegation, does not
mutate guest memory, and does not count as pair-attributed work or
autonomous machine progress.

This means:

1. **No DMA on arrival.**  The packet sits in controller-private storage
   until a future authorized `SYS_NIC_RX` operation (9.3e.4) moves it
   into guest memory.  The driver must present both NIC_RX authority and
   a writable memory capability.

2. **No request model.**  `inject_rx` is host-to-controller, not
   guest-to-controller.  There is no `RequestHandle`, no slot lifecycle,
   no completion.  The NIC's only observable state change from the
   guest's perspective is the epoch advancing and attention latching.

3. **No quiescence impact.**  Queued private RX does not contribute to
   `nonterminal_pair_request_count`, so it cannot delay `PeerDied`.
   The causal barrier from 9.2e is unaffected.

**Attention latch:**

Attention is a latched boolean, distinct from queue occupancy.
`inject_rx` sets it; `acknowledge_attention` clears it.  After
acknowledgement the queue may still be non-empty but
`requires_attention` returns false.  The law:

```text
Ack(Q, e, true)  = (Q, e, false)
Ack(Q, e, false) = (Q, e, false)
```

Neither the queue nor the epoch is modified.

**Production acknowledgement path (9.3e.3 closure fix):**

The initial implementation exposed `acknowledge_attention()` only to controller
clients and tests; the kernel never called it. After the first RX arrival,
`tick_devices()` therefore reposted a device interrupt on every committed
instruction, even after the interrupt handler had serviced the event.

The generic `DeviceController::acknowledge_attention()` now delegates to the
NIC latch operation and is a no-op for Block, whose attention is level-derived
from its completion queue. The device interrupt handler follows this ordering:

```text
drain_completions → reevaluate_recv_waits → reevaluate_event_waits
→ acknowledge sources still requiring attention → resume interrupted process
```

Acknowledgement follows service. It neither consumes an RX frame nor resets the
epoch. The machine-level regression witness fails on the original implementation
and passes with this path: guest NOP → pending device interrupt → actual delivery
and service → unchanged queue/epoch with attention cleared. Eight further guest
instructions produce no new device interrupt. A second injection repeats the
notification cycle, and the guest exits with both frames still queued.

**Checked epoch advancement:**

`inject_rx` uses `checked_add(1)`.  If `event_sequence == u64::MAX`,
the injection is atomically rejected — no queue mutation, no attention
change.  Silent wraparound is a forbidden state transition.

**Kind-sensitive rights:**

`DeviceRights::ALL_BITS` expanded to 0x1D to decode the new NIC_RX
(0x08) and NIC_TX (0x10) bits.  But "defined encoding" does not mean
"valid for every device kind."  `install_device_capability` enforces
kind-valid subsets at install time:

```text
Allowed(Block) = SUBMIT_READ | EVENT_WAIT           = 0x05
Allowed(NIC)   = EVENT_WAIT  | NIC_RX    | NIC_TX   = 0x1C
```

`install_device_capability(Block, NIC_RX)` fails for a registered Block.
The enforcement is at the kernel provisioning gate. Precisely:

```text
RegisteredDevice(d, k) ⇒ Rights(d) ⊆ Allowed(k)
```

An unregistered generic `ObjectKind::Device` uses `ALL_BITS` for compatibility
with generic device-capability transfer fixtures. It has no controller kind
and cannot route an operation until registered; the kind-mask theorem applies
to registered devices.

**Injection ordering:**

```text
1. frame.len() > NIC_MAX_FRAME_SIZE? → reject
2. rx_queue.len() >= NIC_RX_QUEUE_CAPACITY? → reject
3. event_sequence.checked_add(1) → None? → reject
4. [mutation zone]
   rx_queue.push_back(frame.to_vec());
   event_sequence = next_epoch;
   attention_pending = true;
```

All semantic failure checks precede architectural mutation.  A rejected
injection is an atomic no-op over controller-observable state.

**Host injection and event wake:**

`Kernel::inject_nic_rx(binding, frame)` routes by exact `DeviceBinding`
and requires the NIC kind.  After successful `inject_rx`, it calls
`reevaluate_event_waits()`, which wakes any process blocked in
`SYS_DEV_EVENT_WAIT` on this NIC with an older epoch.  This is the
same broadcast mechanism that Block completions use.

Wrong binding, wrong kind (Block), stale generation, oversize frame,
full queue, and epoch exhaustion all produce zero state mutation.

**What 9.3e.3 does not do:**

- No `SYS_NIC_RX` or `SYS_NIC_TX` syscall.
- No guest DMA (no movement of bytes into guest memory).
- No `NicCompletion` type (no completion model).
- No `pop_rx()` (dequeue deferred to 9.3e.4 authorized operation).
- No finite DMA admission for NIC.
- No Ethernet parsing, ARP, or protocol awareness.

**Formal basis:**

```text
anka93e3_nic_controller.kleis              — 32/32 positive
anka93e3_nic_controller_false_witnesses.kleis — 0/10 false claims pass
anka_userspace_nic.kleis                   — 24/24 positive (broad 9.3e)
```

No new axioms.  The false theory rejects: arrival mutating guest memory,
queued RX delaying quiescence, cross-NIC routing, ACK consuming/resetting
state, partial mutation on failed injection, and expanded ALL_BITS making
NIC rights valid for Block.

**Future direction (9.3e.4):**

```text
PrivateFrame + NIC_RX + MemoryWRITE → FiniteDMA
MemoryREAD   + NIC_TX               → FiniteDMA → TXSink
```

The driver will present three authorities: NIC capability (for the
operation), the queued private frame (via the NIC), and a writable
memory target (for placement).  Only the conjunction of all three
produces guest-visible state change.

787/787 tests; 29 instructions.  Phase 9.3e.3 is complete.

---

## DN-26: Finite NIC DMA — Exact RX/TX Authority and Committed Observations (Phase 9.3e.4)

**Date:** 2026-09-16

**Context:**

Phase 9.3e.3 deliberately stopped at device-private unsolicited RX.  A queued
frame could advance the NIC event epoch and wake a user-space driver, but no
packet bytes could cross into or out of guest memory.  Phase 9.3e.4 adds that
crossing as a finite, capability-mediated DMA operation rather than as an
ambient property of packet arrival.

### Direction is authority

The two operations use distinct device rights and opposite memory authority:

```text
SYS_NIC_RX = 18:  NIC_RX + Memory.WRITE
SYS_NIC_TX = 19:  NIC_TX + Memory.READ
```

The direction is from the point of view of guest memory:

```text
RX: NIC-private frame -> Fabric WRITE -> guest buffer
TX: guest buffer       -> Fabric READ  -> host-visible TX sink
```

`NIC_RX` cannot authorize TX, `NIC_TX` cannot authorize RX, WRITE cannot be
used as READ, and ambient authority cannot repair an insufficient presented
handle.

### Admission is exact and finite

Each operation is admitted only after side-effect-free validation of:

```text
exact generation-qualified Device capability
exact backing Device authority
required NIC operation right
exact registered NIC DeviceBinding
exact generation-qualified Memory capability
required memory permission
exact delegated-driver provenance when present
finite byte span inside the presented capability
finite controller capacity
```

Only after these gates pass may the controller derive a narrow DMA domain.
The exact span is delegated from the presented backing `AuthorityId`; two
adjacent capabilities cannot be stitched into one request.

For RX, the private queue head is not removed until exact DMA delegation has
succeeded:

```text
pre-admission failure => Delta RXQueue = 0 and Delta DMA domains = 0
```

Once accepted, the request owns the packet.  A later commit-time fault does not
requeue it.  This intentionally avoids introducing implicit retry/reordering
semantics.

### Accepted work owns derived authority

After admission, the original source handle is no longer the lifetime of the
request.  The finite request owns its narrow derived DMA authority:

```text
accepted request + source capability dropped -> request may still commit
```

Underlying object generation/authority is nevertheless revalidated by Fabric
at commit, so revoking/recycling the object faults the request.

Queued private RX remains outside pair quiescence.  An accepted nonterminal
RX or TX request with `DelegationId(client, driver, ...)` contributes exactly
one unit to that pair until terminal completion.

### Fabric READ captures the committed observation

TX exposed a missing asynchronous-Fabric primitive.  Authorization alone is
not enough: an asynchronous reader needs the bytes that were observed at the
actual commit point.  `Transaction` therefore carries:

```text
read_data: Option<Vec<u8>>
```

For READ/Fetch, Fabric populates `read_data` only in the commit phase, after
commit-time generation, authority, translation, and physical-span
revalidation.  Synchronous `execute_read` consumes the same captured result.
NIC TX therefore never performs a direct physical-memory peek after an earlier
authorization decision.

The conservation law is:

```text
Committed READ -> read_data = exact authorized committed observation
Faulted READ   -> read_data = None
```

and the NIC law is:

```text
Committed NIC TX READ -> TXSink += read_data
Faulted NIC TX READ   -> Delta TXSink = 0
```

### Completion ABI

Both finite NIC operations return through the generic lossless completion
envelope:

```text
R0 = 0        on success
R0 = u64::MAX on commit-time DMA fault
R1 = committed byte count (zero on fault)
```

RX/TX completion does **not** advance the unsolicited-arrival epoch.  The event
epoch continues to mean one thing only: a successful host-to-private-RX
arrival occurred.

### Raw NIC frame bound versus Ethernet syntax

The raw NIC TX syscall accepts a nonzero opaque byte sequence up to 1514 bytes.
It intentionally does not require the 14-byte Ethernet header minimum.  The
next user-space layer owns that syntax rule:

```text
raw NIC transport: 1..1514 bytes
Ethernet parser:    14..1514 bytes
```

This keeps packet transport and protocol parsing separate.

### Formal gate

```text
anka93e4_finite_nic_dma.kleis                   19/19 positive
anka93e4_finite_nic_dma_false_witnesses.kleis   0/11 false claims pass
```

No new axioms.  The false witnesses include permission-direction confusion,
ambient rescue, premature RX dequeue, invalid TX length, pair attribution of
queued RX, faulted-TX sink mutation, and finite completion falsely advancing
the unsolicited-RX epoch.

9.3e.4a RX closed locally at **802/802 Rust tests**.  The integrated 9.3e.4b TX/9.3f candidate contains **822 Rust tests**; it
requires the normal local Rust gate before closure.

---

## DN-27: Host-Controlled Virtual Ethernet Boundary and Formal-First Networking (Phase 9.3f / 9.4)

**Date:** 2026-09-16

**Context:**

Once finite TX exists, the next question is where a transmitted frame goes.
Anka must be able to develop and test a real Ethernet stack without granting a
guest process ambient control of the host's physical network interface.

The answer is a host/emulator policy boundary outside Anka's capability model.

### Connectivity policy is not NIC semantics

The guest sees a virtual NIC that produces and consumes opaque frame bytes.
The host decides what happens beyond that boundary:

```text
Anka userspace
    -> NicController
        -> HostNicBackend
            -> loopback | synthetic LAN | another VM | future external bridge
```

The central laws are:

```text
Guest TX completion != external-network transmission
Host RX offer       != guest-memory mutation
Loopback            != NicController semantics
```

A committed TX frame must first be explicitly extracted from the exact
`DeviceBinding`.  A backend may record, drop, loop, synthesize a peer response,
or eventually forward it according to host policy.

Likewise, `HostNicBackend::poll_rx` merely offers an opaque frame.  It enters
Anka only when the host explicitly calls `Kernel::inject_nic_rx`, at which point
it enters the bounded NIC-private RX queue.  Even then, guest memory remains
unchanged until an authorized `SYS_NIC_RX` finite DMA request succeeds.

### The backend is environment policy, not an Anka principal

`HostNicBackend` does not receive `AuthorityId`, `DelegationId`, or a guest
capability.  It represents the machine environment itself.  Anka's authority
proof has already ended at successful finite TX; a future bridge to a physical
host interface is governed by host policy, not by inventing a guest authority
that claims to represent the host OS.

The backend nevertheless preserves exact virtual-device identity:

```text
HostNicFrame = (DeviceBinding, bytes)
```

so two virtual NICs cannot alias merely because they emit identical bytes.

### Deterministic loopback is the first policy

`LoopbackBackend` records a committed guest TX and queues the same
`(DeviceBinding, bytes)` as a future host RX offer.  It does **not** inject the
frame automatically.  This gives tests an explicit causal trace:

```text
Guest TX
 -> host extracts committed frame
 -> loopback policy creates RX offer
 -> host chooses to inject
 -> NIC-private RX queue
 -> event wake
 -> authorized SYS_NIC_RX
 -> guest memory
```

That separation lets later backends replace loopback without changing the NIC
or guest protocol stack.

The current in-memory TX sink/backend queues are deliberately emulator test
state rather than a final flow-control design.  If a real external backend can
stop draining, bounded backend queues/backpressure become a separate host-side
policy problem; they must not silently change Anka's finite-DMA authority laws.

### Formal-first protocol boundary

Before writing guest protocol parsers, the protocol contracts are frozen in
Kleis.  Frames remain opaque at the host backend; Ethernet interpretation
belongs in user space.

**Ethernet (9.4a):**

```text
dst MAC[6] | src MAC[6] | EtherType[2] | payload
```

Virtual-NIC frames exclude preamble/SFD/IFG and guest-visible FCS.  Ordinary
untagged Ethernet is limited to 14..1514 bytes; VLAN is deferred.  EtherType is
network byte order from bytes 12 and 13.  Unknown EtherTypes are syntactically
valid and may be ignored safely.

**ARP (9.4b):** first support is Ethernet/IPv4 ARP only.  A reply is produced
only for a structurally valid request naming the local IPv4 target, and the
reply preserves the request sender's MAC/IP as the reply target identity.

**IPv4 + ICMP echo (9.4c):** the first stack accepts only fixed-IHL
(20-byte-header), structurally valid, checksum-valid, nonfragmented IPv4
addressed locally.  IPv4 options and fragment reassembly are deferred.  ICMP
echo requires at least its fixed 8-byte header; replies preserve identifier,
sequence, and opaque payload.

Formal package:

```text
anka93f_host_nic_backend.kleis                    13/13 positive
anka93f_host_nic_backend_false_witnesses.kleis     0/8 false claims pass
anka94a_ethernet_contract.kleis                     8/8 positive
anka94a_ethernet_contract_false_witnesses.kleis     0/4 false claims pass
anka94b_arp_contract.kleis                          9/9 positive
anka94b_arp_contract_false_witnesses.kleis          0/4 false claims pass
anka94c_ipv4_icmp_contract.kleis                   14/14 positive
anka94c_ipv4_icmp_contract_false_witnesses.kleis    0/7 false claims pass
```

Together with DN-26's finite-DMA gate, the new formal package is **63/63
positive assertions verified and 0/34 deliberately false claims pass**, with
no new axioms.

The next runtime witness after the finite-TX/host-backend Rust gate is green is
not a kernel Ethernet parser.  It is a CC_B-compiled user-space driver/stack
that uses the frozen boundary to construct and parse Ethernet, beginning with a
deterministic synthetic/loopback peer and ARP.

---

## DN-28: Placement Manager Closure Before the User-Space Network Stack (Phase 9.3g)

**Date:** 2026-09-16

**Decision:**

Stop assigning physical and per-process structural addresses by hand before
writing Ethernet/ARP/IPv4 guest programs.  The first network stack will create
enough independently sized objects that manual hexadecimal placement would
recreate the same class of overlap/layout failures encountered while growing
the guest compiler.

The threshold is:

```text
multiple dynamic objects / NIC-driver complexity -> placement management
```

This is intentionally smaller than a conventional memory manager.

### Two layers, two different questions

The physical manager answers only:

```text
where may this ObjectId occupy physical memory?
```

`PhysicalPlacementManager` therefore owns a bounded page-aligned pool and uses
first-fit allocation.  Its owner key is `ObjectId`, not generation, because a
seal transition changes authority generation without changing physical
location.

The virtual builder answers only:

```text
where should this process region appear in its virtual address space?
```

`VirtualLayoutBuilder` monotonically appends page-rounded extents after the
image.  It has no capability, domain, DMA, or physical-memory semantics.

Thus:

```text
authority != virtual layout != physical placement
```

### Fabric remains the correctness firewall

Normal allocation is a two-party transaction:

```text
PM reserve -> Fabric place -> commit
                         -> reject -> PM rollback
```

The manager makes normal placement convenient; Fabric remains the final
non-overlap/provenance enforcement boundary.

The teardown side must have the same discipline.  The Fabric-blind reservation
release primitive is internal, so architectural callers cannot bypass the
composition check.  A placement created by `allocate_and_place_object()` must
not return to the free pool while Fabric still carries a translation.
`release_unplaced()` therefore rejects that state without mutation:

```text
FabricPlaced(O) -> CheckedRelease(O) = reject
!FabricPlaced(O) && PMOwns(O) -> CheckedRelease(O) = success
```

This is the teardown analogue of allocation rollback and prevents
allocator/Fabric ownership drift.  The manager's physical pool is correspondingly
exclusive to manager-mediated placement; direct unmanaged Fabric placements
inside that pool are outside the placement-manager contract.

### Runtime P5/P8 witnesses

The formal composition theory already stated that placement creates no
authority and that physical reuse cannot resurrect stale authority.  9.3g now
has direct Rust witnesses for both.

**P8:** after PM places a Memory object, an empty domain still receives
`NoCapability`.  Placement does not mint a Fabric capability, AuthorityId, or
delegation.

**P5:** an old object is granted READ authority and placed at extent `P`; the
object is destroyed, the composed reservation is checked-released, and a fresh
ObjectId receives the same first-fit physical extent `P`.  The old request is
still rejected as `StaleGeneration`, and the old domain has `NoCapability` for
the new owner.

Physical byte identity therefore never becomes object authority.

### Decisive closure witness: real CC_B output

A placement manager that passes only allocator unit tests is not enough.  The
project method requires running real software.

The closure test compiles:

```c
int main() { return 42; }
```

with the canonical self-hosted `CC_B`, then constructs a fresh machine in which:

```text
PM chooses supervisor physical placement
PM chooses child physical placement
VLB chooses supervisor child-map/stack/trap regions
VLB chooses child stack/trap regions
```

A tiny supervisor writes the VLB-generated `SpawnLayout` on its own stack and
uses the ordinary `SYS_SPAWN` + `SYS_WAIT` path.  The CC_B-produced child exits
42.  The test supplies only allocator pool/virtual-limit policy; it does not
supply per-object physical bases or stack/trap addresses.

This is the 9.3g constructive witness:

```text
CC_B artifact
 -> automatic physical placement
 -> automatic virtual structure
 -> ordinary Anka spawn
 -> 42
```

### Formal delta

`anka93g3_placement_composition.kleis` gains two teardown laws, bringing the
9.3g.3 source to 14 positive examples.  Its false-witness companion gains the
opposite two claims, bringing it to 12 deliberate false examples.  No new
axioms are introduced.

The complete 9.3g source set is now 47 positive examples and 34 deliberate
false witnesses.  These counts describe the candidate sources; they must pass
the normal local Kleis gate before branch closure.

### Scope boundary

Do not use this phase as an excuse to build:

- guest `malloc`;
- paging or swapping;
- demand allocation;
- general VM machinery;
- physical compaction;
- a guest filesystem;
- replacement of the kernel's existing stack/trap lifecycle recycler.

The next consumer is a separate phase, **9.3h — Anka Development Shell**.  Its
job is to keep C/assembly/bytecode artifacts on the host filesystem while using
Anka mechanisms to load, place, compile, and spawn them.  The shell is a
development bridge, not a guest filesystem and not an authority bypass.

That keeps the route to the project acceptance witness clean:

```text
9.3g placement
 -> 9.3h development shell
 -> Ethernet
 -> ARP
 -> IPv4/ICMP
 -> UDP/TCP
 -> Socket
 -> HTTP
 -> GET /alive HTTP/1.1
 -> "Anka64 is alive."
```

---

## DN-29: Explicit Developer Artifact Ingress Before the Development Shell (Phase 9.3h.0)

**Date:** 2026-09-16

**Decision:**

Formalize the host-to-Anka artifact boundary before implementing the Anka
Development Shell.  The shell exists so the developer can keep C, assembly,
and bytecode on the host filesystem while using Anka mechanisms to create,
place, compile, and spawn artifacts.  That convenience must not turn host
filesystem access or the Placement Manager into ambient execution authority.

The human trust statement is:

```text
the developer explicitly authorizes development artifact ingress
```

The architectural statement is narrower:

```text
DeveloperIngressAuthority
  -> may introduce bytes as an Anka artifact

PhysicalPlacementManager
  -> may choose where that artifact is placed

Anka execution authority
  -> separately decides who may spawn/run it
```

Therefore:

```text
import authority != placement authority != execution authority
```

The Placement Manager remains intentionally ignorant of code provenance and
intent.  It does not decide whether an artifact is benign, malicious, CCB
output, or arbitrary bytecode.  Its answer is only a physical extent.  The
same rule applies to the expected Ethernet, ARP, and ICMP programs: Anka does
not need to trust them because they are intended to be benevolent; it can give
them only the authority their jobs require.

### Development mode is explicit, not ambient host privilege

The 9.3h.0 model introduces a distinct development-ingress authority.  It is
modeled separately from Fabric permissions and ordinary process capabilities:

```text
IngressAllowed = DevelopmentMode && DeveloperIngressAuthorityPresent
```

A host pathname, readable host file, or shell registry name is not such an
authority.  A sealed/non-development machine has no artifact-ingress channel
merely because the emulator is running on a host computer.

This creates a future clean distinction such as:

```text
anka --development   -> explicit development ingress may be provisioned
anka --sealed        -> no developer artifact ingress
```

without requiring that exact CLI in 9.3h.

### Transactional artifact ingestion

A direct bytecode import becomes visible in the shell registry only after the
whole pipeline succeeds:

```text
explicit ingress authority
  -> host read
  -> ObjectId allocation
  -> PM/Fabric placement
  -> initialization
  -> seal
  -> registry publication
```

Failure before publication leaves no runnable partial artifact.  Resources
created by the failed attempt are rolled back so caller-visible registry,
allocator, and Fabric state are unchanged by the rejected import.

After ingestion, the host pathname has no architectural identity role.  The
shell artifact key is the exact sealed Anka incarnation:

```text
ArtifactKey = (ObjectId, Generation)
```

A stale generation or unsealed output is not a valid runnable artifact.
Friendly names such as `arp` are development-UI references only:

```text
name exists != capability exists
```

### CCB compilation and run remain ordinary Anka operations

For C source, the shell may introduce source bytes, but a compiled artifact is
valid only after CCB succeeds, the output is sealed, and the recorded
generation is current.  Compiler failure cannot publish a runnable artifact.

Likewise:

```text
load/compile != permission to execute
```

A future `run arp` command is admitted only when all three conditions hold:

```text
valid exact-generation sealed artifact
  + explicitly presented execution authority
  + ordinary Anka spawn admission
```

The shell must not construct a privileged process directly or mutate a live
process capability table as a host shortcut.

This makes intentionally hostile input a useful witness rather than a special
case.  The developer may import `evil.anka`; PM may place it; but without
separately granted capabilities the code has no ambient access to kernel
memory, another process, or devices.  Benign Ethernet/ARP/ICMP code obeys the
same rule.

### Formal package

Phase 9.3h.0 adds:

```text
anka93h0_developer_artifact_ingress.kleis                    15 positive examples
anka93h0_developer_artifact_ingress_false_witnesses.kleis    13 deliberate false claims
```

No new axioms.  The positive theory composes with the closed 9.3g placement
contract rather than re-proving placement, generation, or Fabric authorization.
The false companion attacks ambient host authority, development-mode-only
admission, stale/unsealed artifact identity, placement-as-execution-authority,
compiler-failure publication, ambient imported-code authority, and spawn
bypass.

The runtime implementation should follow this formal boundary in the remaining
9.3h gates:

```text
9.3h.0  developer artifact-ingress contract (Kleis)
9.3h.1  host artifact registry + bytecode loading
9.3h.2  host C source -> CCB -> sealed executable artifact
9.3h.3  run through PM/VLB + ordinary Anka spawn
9.3h.4  minimal interactive development monitor
```

The shell remains a development bridge, not a guest filesystem, package
manager, general Unix shell, or authority bypass.

## DN-30: Transactional Host Bytecode Ingress and Exact Artifact Registry (Phase 9.3h.1)

**Date:** 2026-09-16

**Decision:**

Implement the first runtime consumer of the 9.3h.0 contract as a separate
Anka64 development-ingress module rather than extending the legacy MC68000
monitor.  `DevelopmentArtifactLoader` is configured as Development or Sealed,
and every import additionally requires an explicitly provisioned
`DeveloperIngressAuthority`.  Neither condition implies the other.

A friendly shell name maps only to:

```text
ArtifactKey = (ObjectId, post-seal Generation)
```

plus non-authoritative metadata (logical size and artifact kind).  The host
pathname is deliberately not stored.  Registry resolution revalidates that the
object still exists, is the same generation, is sealed, and is a Memory object.

The bytecode importer is ordered so every recoverable failure occurs before
artifact bytes become committed:

```text
policy/name preflight
 -> host read
 -> nonempty/size preflight
 -> alloc fresh ObjectId
 -> PM/Fabric placement
 -> verify PM extent lies inside Fabric RAM
 -> zero exact object extent
 -> initialize exact bytes
 -> seal
 -> registry publication
```

PM failure rewinds the fresh unpublished Fabric object.  A composed placement
that fails the Fabric-RAM admission check first rolls back Fabric identity and
translation, then uses PM's checked `release_unplaced` path.  To make the
formal failed-import digest claim true for object identity as well as live
objects, Fabric now has the narrow crate-private
`rollback_unpublished_object(ObjectId)` transition.  It succeeds only for the
exact most-recent Active object and refuses any object already named by memory
or device authority or already observed by a Fabric transaction/fault record.

After the physical-range/zero preflight, exact-size `initialize_object` and the
single Active->Sealed transition are internal invariants, not recoverable shell
errors.  Treating an impossible violation there as a bug avoids falsely claiming
transactional rollback after physical bytes have already been mutated.

The loader intentionally does not judge payload intent or semantic correctness.
Benign ARP/ICMP/Ethernet bytecode, malformed bytecode, and intentionally hostile
bytecode have identical ingress semantics.  Successful import grants no Fabric
capability and performs no process construction:

```text
imported + placed + sealed != authorized to execute
```

Execution authority remains Phase 9.3h.3.

Phase 9.3h.1 adds 12 Rust witnesses.  With the preceding 842-test baseline, the
source tree now contains 854 Rust tests; the executable test gate must still be
run in a Rust-enabled environment before declaring the phase closed.

## DN-31: Earned Userspace Namespace and Compile-Only CC_B (Phase 9.3h.2)

**Date:** 2026-09-16

**Decision:**

Before writing Ethernet/ARP/ICMP as real C files, establish a host source tree
that mirrors the future Anka64 logical namespace without copying Unix wholesale.
The development source root is:

```text
userspace/
  system/services/net/
  system/compiler/
  bin/
  lib/
  include/anka/
  etc/
```

These roots are semantic, not historical compatibility aliases.  We do not add
`/usr`, `/sbin`, `/var`, `/home`, or similar structure unless future Anka
software creates a concrete requirement for it.  `examples/` remains for
demonstrations; Ethernet, ARP, IPv4, ICMP, TCP, and HTTP are system software and
belong under `userspace/system/services/net/`.

The host/source mapping is deterministic:

```text
userspace/<relative>.c -> /<relative-without-.c>
```

Thus:

```text
userspace/system/services/net/arp.c -> /system/services/net/arp
```

The three identities remain separate:

```text
host source path
!= logical Anka install path
!= exact runtime ArtifactKey(ObjectId, Generation)
```

Neither pathname is authority.  The logical install path is non-authoritative
registry metadata and is unique within the development registry.

### Compile is not run

Reviewing the existing canonical CC_B exposed an important mismatch with the
9.3h.0 contract: CC_B historically compiled, sealed, and immediately `SYS_EXEC`d
its output because execution was the bootstrap compiler's regression witness.
That behavior is wrong for a development-shell `compile` operation.  Compiling
an arbitrary source file must not execute it.

Add a workspace control word `WS_MODE`:

```text
0 = historical compile + seal + execute
1 = development compile + seal only
```

Mode 0 preserves every existing bootstrap path.  Mode 1 is selected only by the
9.3h.2 development compiler bridge.  The new Kleis theory freezes:

```text
compile command valid -> output was not executed
logical install path -> no authority
```

with 4/4 positive examples and 0/4 deliberate false claims.

### Real CC_B remains inside Anka

`dev_compiler.rs` does not replace CC_B with a host C compiler.  It boots ankad
in a transient Anka64 compilation machine; ankad uses normal `SYS_SPAWN` to
launch the actual self-hosted CC_B with source R, output RWS, and workspace RW.
The workspace requests compile-only mode.  Successful compilation requires:

```text
CC_B success
+ output object Sealed
+ valid code/literal arena geometry
+ no third process slot (no compiled child execution)
```

The bridge then returns the sealed output contents and executable geometry to the
host development layer.  A no-literal image stores only the code prefix.  A
literal-bearing image preserves the full fixed output arena so literal offsets
remain unchanged.  The target `DevelopmentArtifactLoader` reintroduces that
artifact through PM/Fabric, seals it, records exact generation plus
`code_size`/`lit_start`, and grants no capability.

This host-mediated transfer is intentional for the development shell: the host
filesystem is the artifact store described at the start of 9.3h.  Execution is
still a later operation under 9.3h.3 and requires explicit execution authority
and ordinary Anka spawn admission.

The source tree now contains 860 Rust tests (854 prior + 6 Phase 9.3h.2 tests).

Next gate:

```text
9.3h.3  run a registered artifact through PM/VLB + ordinary Anka spawn
```



## DN-32: Explicit Developer Execution Authority Uses Ordinary SYS_SPAWN (Phase 9.3h.3)

**Decision.** A development artifact does not become executable merely because
it was imported, compiled, placed, or named.  Running it requires a second
explicit host-development token, `DeveloperExecutionAuthority`, distinct from
`DeveloperIngressAuthority`.  This token authorizes only the bridge that presents
ordinary Anka authority for the exact current sealed artifact.

The presentation is least-authority:

```text
artifact code     -> RX only
artifact literals -> R only, when literals exist
```

The developer token itself is not a Fabric capability, is never inserted into a
guest capability table, and is not inherited by the child.  Presenting RX/R is
not execution.  A one-shot PM-placed supervisor must still invoke the existing
`SYS_SPAWN` ABI with a `VirtualLayoutBuilder`-generated `SpawnLayout`, then
observe the exact lifecycle handle with `SYS_WAIT`.

This avoids two tempting shortcuts: direct host construction of the target
`Anka64Core`, and live ambient mutation of a running guest domain.  The host
development bridge may establish a trusted one-shot supervisor through the boot
root, but the target program is created only by the ordinary Anka spawn path.

The runner validates the registry's exact `(ObjectId, Generation)`, sealed state,
compiled image geometry, and PM/Fabric placement agreement before allocating
transient state.  VLB places child code/stack/trap and supervisor
code/control/artifact/stack/trap regions without caller-supplied hexadecimal
layout knowledge.  Kernel-owned stack/trap physical extents start above both the PM pool and the
Fabric physical high-water mark, so they cannot collide with existing placement.

After completion the child is collected through `SYS_WAIT`, the transient
supervisor is reclaimed, its PM-managed code/control objects are destroyed and
released, and the caller receives the same Fabric with the registered artifact
unchanged.  Missing execution authority, stale artifact identity, or PM/Fabric
placement disagreement is rejected before any process is spawned.

Formal gate:

```text
anka93h3_execution_authority.kleis                    5/5
anka93h3_execution_authority_false_witnesses.kleis    0/5
```

No new axioms.  Eight Rust witnesses raise the source test count from 860 to
868.  The executable gate closed at **868/868**, with 5/5 positive Kleis
witnesses and 0/5 deliberate false claims passing.


## DN-33: The Development Shell Is a Thin Monitor, Not a New Authority Layer (Phase 9.3h.4)

**Decision.** Finish Phase 9.3h with a minimal line-oriented development
monitor whose only job is parsing and dispatch.  It must not duplicate compiler,
placement, capability, or process-lifecycle logic.

The command surface is intentionally small:

```text
compile <source.c> [name]
load bin <file> [name]
run <name|/logical/path>
artifacts
objects
placements
help
quit | exit
```

There are no pipes, redirection, globbing, variable expansion, or inherited Unix
shell semantics.  `compile` is exactly the 9.3h.2 compile-only operation.
`load bin` is exactly 9.3h.1 transactional ingress.  `run` provisions a
short-lived `DeveloperExecutionAuthority` as the explicit developer act and
then invokes the 9.3h.3 runner; the token is not retained in shell state and is
never guest authority.  `artifacts`, `objects`, and `placements` are read-only
inspection surfaces.

The monitor owns one persistent development Fabric, PM, and artifact registry.
Its PM pool occupies only the lower half of the development machine, leaving a
disjoint upper region for the transient kernel stack/trap allocations required
by the normal run path.  The registered artifact survives each synchronous
run unchanged.

The interactive shell must also be able to obtain CC_B without relying on a
test-only helper or a host C compiler.  The canonical fixed-point source
generator is therefore available to development code.  On the first `compile`,
CC_A (the Rust-AST bootstrap seed) runs under ankad and compiles that canonical
C source in compile-only mode to produce CC_B.  The shell caches the resulting
CC_B bytes for the session; all developer C then goes through the existing
self-hosted CC_B path.  A regression asserts that the development canonical
source is byte-for-byte the same source used by the fixed-point tests.

`run` remains synchronous in 9.3h.4 because the existing runner already uses
`SYS_WAIT` and returns a terminal `ProcessResult`.  We intentionally do not add
`wait` or `ps` commands until Anka has a real persistent-process development
requirement; inventing them now would force a second process-management model.

No new Kleis theory is needed for 9.3h.4.  The phase adds no semantic transition
that is not already covered by 9.3h.0 ingress, 9.3h.2 compile-only, and 9.3h.3
execution-authority/spawn contracts.  Nine Rust witnesses raise the source test
count from 868 to 877.  The executable 877-test gate closes the whole 9.3h
branch before merge.

Next phase after that gate:

```text
9.4a  Ethernet as real Anka C system software
```


## DN-34: Ethernet Belongs in User Space (Phase 9.4a)

**Decision.** Implement the first network protocol layer as real CC_B-compiled
C system software rather than adding an Ethernet decoder to Rust kernel/device
code.

`userspace/system/services/net/ethernet.c` performs one authorized finite RX,
validates the frozen 14..1514-byte untagged Ethernet boundary, and extracts the
EtherType as `(byte12 << 8) | byte13`.  The current one-shot process exits with
a dispatch tag (ARP, IPv4, unknown, malformed) so the runtime tests can observe
the parser without inventing the later ARP/IPv4 service IPC protocol.

The host-side Rust addition is test scaffolding only.  It creates a virtual NIC
and one DMA buffer, boots the compiled C image, installs exact NIC_RX and WRITE
capability handles into the otherwise-empty process cap table, injects opaque
frame bytes, and runs the normal finite-DMA path to completion.  It does not
interpret Ethernet in Rust.

For this first witness the startup ABI is intentionally explicit and tiny:

```text
NIC_RX handle       = slot 0, generation 0
DMA WRITE handle    = slot 1, generation 0
DMA buffer vaddr    = 0x10000
```

These are process-environment conventions, not ambient authority.  Authority
still exists only because the trusted test bootstrap installs the exact device
and memory capabilities.  Logical path `/system/services/net/ethernet` remains
non-authoritative.

CC_B does not yet preprocess `#include`, so the Ethernet source remains a
self-contained translation unit.  Do not create a decorative header hierarchy
that the actual compiler cannot consume.  Shared headers/source composition are
to be introduced when a real compiler/linkage requirement appears.

The existing formal-first Ethernet theory is sufficient: it already freezes
the length bounds, safe fixed-header access, network-order EtherType extraction,
and the rule that unknown EtherTypes are valid Ethernet syntax.  Phase 9.4a
therefore requires no additional Kleis axioms or authority theory.


## DN-35: ARP Owns Reply Semantics in User Space (Phase 9.4b)

**Decision.** Implement ARP request validation, reply construction, and reply
transmission entirely in CC_B-compiled C.  Do not add ARP awareness to the
kernel, NIC controller, or host backend.

`arp.c` receives one opaque virtual-NIC frame using `SYS_NIC_RX`, validates the
minimal Ethernet envelope plus the frozen Ethernet/IPv4 ARP fixed fields, and
answers only an opcode-1 request for its configured local IPv4 address.  The
first executable configuration is MAC `02:00:00:00:00:02`, IPv4 `10.0.0.2`.
That identity is a service-startup fact for the witness, not a protection
primitive.

The same mapped object is deliberately used for RX and TX.  The process is
seeded with one RW memory capability and one NIC device capability containing
NIC_RX|NIC_TX.  This does not weaken the finite-DMA rule: `SYS_NIC_RX` still
requires WRITE on the exact presented buffer authority and `SYS_NIC_TX` still
requires READ on that exact authority.  The combined capability merely allows
this service to perform both explicitly authorized operations.

Reply construction is in-place because the fixed ARP reply is the same size as
the request payload.  Before overwriting sender fields, the C program saves the
request sender MAC/IP in locals.  It then writes Ethernet destination/local
source, opcode 2, local sender MAC/IP, and the saved peer MAC/IP as target.  The
TX length is the original RX length, preserving padding bytes rather than
inventing an Ethernet padding policy inside ARP.

Until a real network-service IPC ABI exists, the one-shot ARP executable checks
the Ethernet EtherType and frame length itself.  This is a temporary
composition seam, not a second Ethernet implementation in the kernel.  The
9.4a service remains the executable witness for generic EtherType dispatch;
9.4b is the executable witness for the ARP branch once selected.

No new Kleis theory is required.  `anka94b_arp_contract.kleis` already freezes
the 28-byte ARP payload safety boundary, supported fixed header, local-target
reply predicate, no reply-to-reply behavior, and preservation of request sender
MAC/IP as reply target identity.  The existing finite NIC RX/TX theories cover
the authority transition.  Runtime byte-serialization tests now witness the
concrete reply layout.


## DN-36: IPv4 Validates the Envelope; ICMP Owns Echo Reply Semantics (Phase 9.4c)

**Decision.** Keep IPv4 and ICMP in CC_B-compiled user space and reject protocol
features that the first stack does not yet structurally support.  Do not add
checksum, fragmentation, or echo semantics to Rust kernel/device code.

`ipv4.c` consumes one frame through `SYS_NIC_RX` and accepts only ordinary
Ethernet carrying IPv4 with version 4, IHL 5, contained total length, a valid
20-byte header checksum, no More-Fragments flag and zero fragment offset.  A
packet must also name the configured local IPv4 address before protocol
selection is considered local delivery.  IPv4 options and fragment reassembly
are deferred rather than silently interpreted.

`icmp.c` is the first Internet-layer bidirectional service.  It repeats the
small Ethernet/IPv4 envelope validation it depends on because CC_B currently
has no linker and Anka does not yet have a network-service IPC/startup ABI.  It
then requires protocol 1, at least the fixed 8-byte ICMP header, a valid ICMP
checksum, type 8, and code 0.  Only that predicate may produce TX.  Incoming
echo replies, other ICMP types/codes, nonlocal traffic, malformed lengths, bad
checksums, IPv4 options, and fragments do not produce a reply.

Reply construction occurs in the same finite DMA buffer.  Before overwriting
addresses, the C code saves the request Ethernet source MAC and IPv4 source.
The reply writes local MAC/IP as source and the saved peer identity as
destination, changes only ICMP type/code/checksum within the ICMP message, and
therefore preserves identifier, sequence, and payload bytes exactly.  IPv4 TTL
is reset to 64 and its checksum is recomputed.  The original RX frame length is
used for TX so Ethernet padding outside IPv4 total length remains untouched.

The checksum routine is intentionally byte-oriented and network-order aware.
It sums 16-bit big-endian words, folds end-around carry, and treats an odd
trailing byte as the high byte of the final word.  Runtime witnesses check both
normal and odd-length echo payloads rather than relying only on a Rust-side
expected checksum.

The authority surface does not change.  The IPv4-only witness receives exact
NIC_RX plus WRITE-buffer capability.  The ICMP echo witness receives exact
NIC_RX|NIC_TX plus RW-buffer capability.  RX and TX remain the same finite-DMA
syscalls proved earlier; protocol validation cannot amplify either authority.
Logical paths `/system/services/net/ipv4` and `/system/services/net/icmp` grant
nothing.

No additional Kleis theory is required.  The pre-existing
`anka94c_ipv4_icmp_contract.kleis` already freezes fixed-IHL length safety,
IPv4 checksum/nonfragment/local-destination support, ICMP fixed-header safety,
echo reply predicate, and exact identifier/sequence/payload conservation.  The
runtime C witnesses concretize byte layout and checksum serialization.


## DN-37: UDP Checksum and Endpoint Semantics Stay in User Space (Phase 9.4d)

**Decision.** Keep UDP framing, endpoint filtering, pseudo-header checksum
validation, and reply serialization entirely in CC_B-compiled C.  The first
endpoint is development port `49152` and reflects opaque payload bytes; it is a
transport witness, not yet a socket table.

UDP length must be at least eight bytes and exactly consume the IPv4 payload.
For IPv4 UDP, checksum zero retains its protocol-defined meaning of "checksum
omitted"; any supplied checksum must validate over the IPv4 pseudo-header and
complete UDP datagram.  Replies always emit a real checksum, mapping a computed
wire value of zero to `0xffff` so zero remains reserved for omission.

No new kernel mechanism or authority is introduced.  The same explicit finite
DMA rights used by ICMP provide RX/WRITE and TX/READ.  Phase 9.4d closes at the
formal gate of 13 positive / five rejected false witnesses and the 901-test
runtime gate.


## DN-38: TCP Begins as One Explicit Passive State Machine, Not a Socket API (Phase 9.4e)

**Decision.** Introduce TCP as a real persistent CC_B process before introducing
sockets.  The first service owns exactly one passive connection and therefore
makes TCP state observable without prematurely inventing file descriptors,
listen queues, process-facing socket IPC, retransmission machinery, or a
multi-connection table.

The supported state graph is:

```text
LISTEN -> SYN_RCVD -> ESTABLISHED -> CLOSED
```

A transition is allowed only after the strict IPv4 envelope, local destination,
protocol 6, fixed 20-byte TCP header, endpoint 49153, and mandatory TCP
pseudo-header checksum have validated.  After SYN, the peer IPv4/port tuple is
saved.  The final ACK, every accepted data segment, and FIN must match that
same tuple and exact `SEQ/ACK` expectations.  The service accepts only in-order
payload; there is intentionally no retransmission or reassembly queue yet.

The deterministic initial send sequence is `0x414e4b41` for the executable
witness.  This makes byte-level tests reproducible and is not the eventual ISN
policy.  SYN and FIN each consume one sequence number; data consumes exactly
its payload length.  These arithmetic laws are frozen in
`anka94e_tcp_contract.kleis` using 32-bit bit-vector addition so wraparound is
part of the formal relation even though the first executable witnesses do not
exercise the wrap boundary.

The C implementation maintains state across repeated finite `SYS_NIC_RX`
attempts.  `SYS_NIC_RX` is deliberately not an arrival wait: when the private
RX queue is empty it returns error 9 with no DMA request.  The persistent TCP
service responds by calling `SYS_DEV_EVENT_WAIT` on the same exact NIC handle
with its last observed activity epoch, then retries `SYS_NIC_RX` after wakeup.
This preserves the finite-DMA contract and avoids polling.  Malformed,
nonlocal, wrong-endpoint, wrong-tuple, bad-checksum, out-of-order, and
wrong-ACK packets produce no TX and do not advance TCP state.

SYN-ACK and pure ACK packets are rebuilt rather than mutating a data packet in
place.  Their IPv4 total length is 40 and TX length is 60 bytes; the six bytes
of Ethernet padding are explicitly zeroed.  This prevents bytes from a
previous received TCP payload from becoming observable padding in a shorter
control reply.

The authority model gains no new mechanism.  Because this is the first
persistent network listener, its exact device handle combines
`EVENT_WAIT|NIC_RX|NIC_TX`; one RW DMA-buffer capability permits the same
finite DMA operations already proved.  `EVENT_WAIT` is independently checked
by the existing Phase 9.3d device-event contract and does not confer RX or TX.
Neither TCP state nor endpoint identity grants capability.  Sockets remain the
next architectural phase that will connect transport state to ordinary user
processes.


## DN-39: Sockets Are a User-Space Process Boundary, Not New Kernel Networking (Phase 9.4f)

**Decision.** Build the first socket abstraction from mechanisms Anka already
has: exact-incarnation IPC, explicitly shared memory, and the Phase 9.4e TCP
service model.  Do not add `socket()`, `accept()`, `recv()`, or `send()` kernel
syscalls and do not move TCP state into Rust.

The first socket service owns exactly one passive TCP connection and one exact
client `ProcessKey`.  The client sees a byte stream through a bounded shared
buffer plus four semantic message forms: CONNECTED, DATA(length), SEND(length),
and CLOSED.  The socket process retains the peer tuple, TCP sequence space,
checksums, and NIC authority.  Therefore an HTTP process in the next phase can
operate on request/response bytes without knowing Ethernet, IPv4, TCP headers,
or SEQ/ACK arithmetic.

The Phase 9.4f bootstrap maps one 1024-byte memory object into both domains but
at independently chosen virtual addresses.  This is explicit shared-memory
authority, not a globally named buffer.  The application capability table is
empty; the service alone receives `EVENT_WAIT|NIC_RX|NIC_TX` and the private RW
DMA-buffer capability.  Shared memory does not imply device authority.

IPC is exact-generation rather than PID-only.  Notifications use
`SYS_SEND_KEY`, and blocking receives use `SYS_RECV_WAIT` against the exact peer
incarnation.  After a validated in-order TCP payload is copied into the shared
buffer, the socket service sends DATA(n) and waits specifically for that
client's SEND(n).  An unrelated mailbox message is not sufficient to complete
the wait.

We intentionally do not introduce wait-any in this phase.  The first HTTP-like
exchange naturally alternates network input and application response: wait for
TCP, deliver DATA, wait for exact client SEND, transmit, then return to TCP.
The NIC side continues to use finite `SYS_NIC_RX` plus
`SYS_DEV_EVENT_WAIT`; the client side uses exact-peer `SYS_RECV_WAIT`.  General
multiplexing should be introduced only when multiple simultaneously live event
sources require it.

The socket service owns `SND.NXT` and `RCV.NXT`.  SEND(n) carries only a byte
count.  Outgoing sequence/acknowledgement fields are selected from owned TCP
state, and successful transmission advances `SND.NXT` by exactly `n`.  This is
the central abstraction boundary: the application can choose bytes, but not
transport coordinates.

The formal contract adds no axioms and freezes 14 positive properties plus
seven hostile false witnesses.  The executable witness adds seven Rust tests
over the 909-test TCP baseline, for an expected 916-test Phase 9.4f gate.


## DN-40: HTTP Is an Ordinary Socket Client, Not a Networking Exception (Phase 9.4g)

**Decision.** Implement the first HTTP service entirely above the Phase 9.4f
process-facing socket boundary. Do not grant the HTTP process a NIC capability,
DMA capability, peer tuple, TCP flags, sequence numbers, acknowledgement
numbers, or checksum responsibilities. HTTP consumes bytes and produces bytes;
the socket service remains the authority and transport boundary.

The first route is intentionally literal: a complete bounded request whose
request line is `GET /alive HTTP/1.1` and whose headers terminate in the HTTP
blank line receives `200 OK` with body `Anka64 is alive.`. The body is exactly
16 bytes and the response carries `Content-Length: 16` plus `Connection: close`.
Other first requests receive a bounded 404 with an empty body. Header contents
are opaque in this phase and therefore create no authority or routing effect.

The current socket protocol alternates one network DATA delivery with one exact
client SEND. Therefore Phase 9.4g deliberately requires the complete HTTP
request to fit in one DATA notification (maximum 1024 bytes). This is a scoped
milestone, not a claim that TCP message boundaries are HTTP message boundaries.
General stream reassembly should be added only by changing the socket/application
protocol explicitly rather than smuggling buffering into the HTTP parser.

`httpd.c` maps only the explicitly shared stream object and has an empty
capability table in the executable witness. It waits on the exact socket-service
`ProcessKey`, writes response bytes into the shared buffer, and requests
`SEND(n)`. The socket service alone chooses TCP `SEQ/ACK`, serializes checksums,
and advances `SND.NXT` by the exact HTTP response byte count.

The formal contract adds no axioms and freezes 15 positive properties plus
eight hostile false witnesses. Phase 9.4g closes at 15/15 positive formal
examples, 0/8 accepted false witnesses, and 923/923 Rust tests over the
916-test socket baseline.

## DN-41: AnkaCC2 Is Earned by Real Userspace Pressure, Not Standards Imitation (Phase 10 plan)

**Date:** 2026-09-18

**Context.** Phase 9.4 reached the original CPU-to-HTTP milestone using the
self-hosted CC_B compiler.  That success changed the compiler problem.  CC_B is
no longer merely proving that Anka64 can self-host; it is now compiling a real
userspace whose structure is being visibly distorted by bootstrap-era language
limits.

The pressure is concrete rather than speculative:

- the scanner/symbol model imposes short identifiers;
- systems code has already had to work around restricted integer literals;
- CC_B compiles one translation unit and has no linker;
- `userspace/include/anka/` exists architecturally but cannot yet serve as a
  normal shared-header surface;
- independently runnable network services sometimes duplicate lower-envelope
  validation because ordinary C module composition does not yet exist;
- the complete Ethernet-to-HTTP stack now provides a demanding regression
  corpus for a better compiler.

This is exactly the project's normal trigger for a new abstraction: real
software has broken the old assumption.

**Decision.** Build a second-generation self-hosted toolchain, **AnkaCC2**, in
Phase 10.  Do not keep stretching CC_B indefinitely and do not replace it with a
host compiler.  CC_B becomes the trusted bootstrap compiler that constructs the
first AnkaCC2 image.

The historical names remain stable.  `CC_C` already means the byte-identical
fixed-point witness for CC_B, so the new compiler does not reuse that name.
AnkaCC2 uses explicit bootstrap generations:

```text
CC_B(source_CC2)  -> CC2_0
CC2_0(source_CC2) -> CC2_1
CC2_1(source_CC2) -> CC2_2
require CC2_1 == CC2_2
```

The initial AnkaCC2 implementation is written in the subset CC_B can already
compile.  That is a bootstrap constraint on the compiler's implementation
language, not a limit on the language AnkaCC2 may accept.  After the fixed point
exists, AnkaCC2 may begin using its own new features by the same staged rule used
for every self-hosting compiler: an older accepted compiler builds a candidate;
the candidate recompiles the same source; only the fixed-point result becomes
authoritative.

**Language decision.** Define an explicit freestanding **Anka C v2 (AC2)**
profile rather than claiming broad ISO C conformance prematurely.  AC2 grows
from requirements already demonstrated by Anka software: practical identifiers,
full target-width integer constants, declarations/prototypes, arrays/pointers,
aggregate/interface types (`struct`, `typedef`, `enum`), separate translation
units, and usable source/header composition.  Additional C features are added
when a real compiler/system/application client requires them.

This intentionally rejects the opposite strategy: importing GCC/Clang surface
area, ELF, POSIX, libc, dynamic linking, a complete historical preprocessor, or
optimization machinery merely because conventional systems have them.  Anka
may eventually support some of those concepts, but each must earn its place.

**Object/link decision.** Separate translation units require an explicit
relocatable artifact.  Phase 10 will define a small versioned **Anka Object
Module (AOM)** containing sections, exports, imports, relocations, bounds, and
alignment metadata sufficient for static composition.  The object format is an
Anka contract, not ELF by default.

A static linker (`ankald`, working name) will be an ordinary Anka user-space
program.  It must reject duplicate/unresolved required symbols and invalid
relocations before publishing output.  Link publication is transactional.
Linking preserves Anka's existing code/read-only/writable separation rather
than weakening W⊕X to match a conventional flat executable.

The central authority rule is:

```text
source name / include name / symbol name / relocation / successful link
    != authority
```

A linker may establish address relationships.  It may not manufacture a device
capability, memory authority, execution authority, or any other protected Anka
right.  A linked executable remains inert until ordinary artifact validation and
explicit execution authority permit `SYS_SPAWN`.

**Source-composition decision.** Do not implement `#include` by secretly asking
the host to preprocess C.  During development the host may package explicitly
selected source/header bytes and their logical names into a read-only source
bundle.  AnkaCC2 performs language-level include/source resolution inside Anka.
The host-side bundle builder is transport/storage plumbing only; it performs no
C parsing, macro expansion, symbol resolution, relocation, or linking.

This keeps the eventual supply-chain statement meaningful:

```text
host stores/packages bytes
Anka compiler interprets C
Anka linker resolves modules
Anka authority admits execution
```

**Formal decision.** Use Kleis to freeze the toolchain protocol where formal
claims are crisp: exact-generation bootstrap provenance, transactional failure,
unique symbol resolution, relocation bounds, permission non-amplification,
path/symbol non-authority, and fixed-point acceptance.  Pair each positive law
with hostile false witnesses.  Do not label those structural proofs a proof of
all C semantics.  Compiler semantics remain under self-hosting, regression,
hostile-program, and real-userspace pressure until stronger semantic proofs are
actually built.

**Acceptance decision.** HTTP becomes the permanent Phase 10 integration gate.
The new compiler is not complete merely because it compiles itself.  Phase 10
closes only when:

```text
CC_B -> CC2_0 -> CC2_1 -> CC2_2
                  CC2_1 == CC2_2

CC2 + ankald -> rebuild real Anka userspace
             -> boot the rebuilt system
             -> GET /alive HTTP/1.1
             -> "Anka64 is alive."
```

No host C compiler, host preprocessor, host linker, or host-side symbol resolver
may participate in that closure path.

**Non-goals for Phase 10.** Full ISO C conformance, aggressive optimization,
dynamic linking, ELF compatibility, hosted libc/POSIX compatibility, C++, JIT
compilation, and a general guest filesystem are not required to close the
phase.  If one becomes necessary for a real client, that client will justify a
later architectural step.

**Consequence.** The compiler/toolchain becomes another ordinary Anka software
stack governed by the same rule as networking and devices: names and successful
computation describe relationships, but authority comes only from explicit
Anka authority.  The supply-chain provenance can therefore be traced from the
bootstrap compiler, through the exact compiler/linker artifacts, to the exact
userspace image that ultimately answers HTTP.

## DN-42: Freeze AC2, Bootstrap Provenance, and Link Authority Before Writing AnkaCC2 (Phase 10.0)

**Date:** 2026-09-18

**Context.** DN-41 established why AnkaCC2 is now necessary.  The next risk is
the inverse of CC_B's bootstrap minimalism: implementing a larger compiler,
object format, and linker before deciding exactly which semantic and authority
boundaries they are allowed to cross.  Separate compilation introduces names,
imports, relocations, and a new linked-artifact publication path.  None of those
may become an accidental second capability system.

**Decision.** Close Phase 10.0 formally before writing AnkaCC2 implementation
code.  Keep the formal surface split into three contracts rather than one large
toolchain theory:

```text
AC2 profile contract
CC2 bootstrap/provenance contract
AOM + static-link + authority contract
```

Each has a hostile false-witness companion.  The split is architectural: a
future parser bug, bootstrap-provenance bug, and linker-authority bug are three
different classes of failure and should remain independently testable.

**AC2 v1 profile decision.** The first target profile uses C-style ASCII
identifiers with a maximum length of **63 bytes**.  This is deliberately bounded
for a small self-hosted implementation while being comfortably above every
identifier pressure that exposed CC_B's eight-byte ceiling.  Unicode identifiers
remain deferred.  Integer lexical tokens must preserve the complete **64-bit**
target magnitude, including hexadecimal systems constants; the signed/type rules
for those values are a Phase 10.2 ABI/type decision rather than a lexer shortcut.

The target profile requires byte character/string literals, prototypes, pointers,
arrays, `struct`, `typedef`, `enum`, separate translation units, and source/header
composition.  That is the *target profile*, not a claim that Phase 10.1 implements
every item at once.  The staged Phase 10 decomposition remains authoritative.

Development source bundles contain exact read-only bytes plus unique logical
names.  A host may package bytes but may not parse C, expand macros, resolve
symbols, relocate, or link.  A source/header logical name is metadata only:

```text
source path != authority
header path != authority
```

**Bootstrap decision.** The only initial accepted lineage is:

```text
CC_B -> CC2_0 -> CC2_1 -> CC2_2
```

Every published compiler artifact requires successful compilation, sealed output,
and exact current compiler/source generations.  Generations may not be skipped.
Authoritative closure requires the exact same source artifact throughout the
chain and byte-identical `CC2_1 == CC2_2`.  `CC2_0 == CC2_1` is intentionally not
required: CC2_0 is the older compiler's bootstrap product.  The distinction is
important because fixed point is evidence about self-compilation, not a demand
that two different compilers emit identical first-generation output.

**AOM/link decision.** Phase 10.0 freezes AOM semantic validity but not its byte
encoding.  Version 1 modules must have bounded, nonempty, correctly aligned
sections; well-formed symbols; and relocations with nonzero width that remain
inside their owning section and target declared compatible symbols.  A required
import has exactly one definition.  Zero definitions and multiple strong
definitions both fail.

The linked permission plan preserves Anka's separation:

```text
code   = executable, non-writable
rodata = readable, non-writable, non-executable
```

Writable executable output is invalid.  Link publication is transactional and
requires semantic readiness, link success, a complete output, sealing, and the
current output generation.  Link failure cannot leave a runnable partial image.

Most importantly:

```text
symbol name != authority
relocation != capability
successful link != execution authority
```

A linked artifact executes only through the already-established Anka path:

```text
valid exact artifact
+ explicit execution authority
+ ordinary spawn admission
-> execution
```

The linker may establish address relationships.  It may not amplify runtime
authority.

**Formal result.** No new axioms.  The Phase 10.0 gate closes at:

```text
anka100_ac2_profile_contract.kleis                 12/12
anka100_ac2_profile_contract_false_witnesses.kleis 0/6

anka100_cc2_bootstrap_contract.kleis               13/13
anka100_cc2_bootstrap_contract_false_witnesses.kleis 0/7

anka100_aom_link_contract.kleis                    30/30
anka100_aom_link_contract_false_witnesses.kleis     0/13

TOTAL: 55/55 positive, 0/26 hostile accepted
```

Every hostile claim is explicitly disproved by Z3.  The theories are written in
evaluator-safe conditional form so a concrete witness is not weakened by the
direct evaluator leaving Boolean conjunction ASTs symbolic.

**Non-claim.** This does not prove that AnkaCC2 implements C correctly.  It proves
the structural profile, bootstrap provenance, AOM/link validity, and authority
boundaries that later compiler/linker implementations must refine.  Compiler
semantic correctness continues to be tested by self-hosting, the permanent
semantic corpus, fixed-point identity, hostile programs, rebuilt userspace, and
the final CPU-to-HTTP acceptance path.

**Consequence.** Phase 10.1 can now begin with a much smaller question: implement
the AnkaCC2 lexer/parser core under CC_B without renegotiating what identifiers,
full-width literals, source provenance, bootstrap generations, or future linking
are allowed to mean.

## DN-43: Bootstrap AnkaCC2 With a Narrow Real Front End Before Expanding AC2 (Phase 10.1)

**Date:** 2026-09-19

**Context.** Phase 10.0 froze the AC2 target profile, CC2 bootstrap provenance,
and AOM/link authority rules.  The implementation risk in 10.1 is now the
opposite one: trying to implement the entire target profile at once would mix a
new lexer, parser, type system, object format, linker, include mechanism, and
self-hosting transition into one debugging surface.  The existing CC_B compiler
process ABI already gives us a supervised source/workspace/output environment
and a compile-only sealing path.

**Decision.** Build the first AnkaCC2 compiler as real Anka userspace C that is
itself accepted by CC_B, and make its language input strictly larger only where
Phase 9 userspace has already earned the pressure.  The implementation lives at:

```text
userspace/system/compiler/ankacc2_stage1.c
```

and the bootstrap edge is literal rather than conceptual:

```text
CC_B(ankacc2_stage1.c) -> sealed AnkaCC2-stage1 image
AnkaCC2-stage1(AC2 stage-1 source) -> sealed direct executable
```

The development bridge reuses the same compiler code virtual address and the
same exact source/workspace/output ABI as CC_B.  It also forces compile-only
mode, so compiling with AnkaCC2 cannot silently execute the produced program.

**Lexer decision.** Stage 1 implements the frozen C-style ASCII identifier
shape exactly:

```text
[A-Za-z_][A-Za-z0-9_]{0,62}
```

This is a semantic expansion over the bootstrap compiler's source spelling
constraints while preserving the 63-byte AC2 bound.  Decimal and `0x`/`0X`
hexadecimal integer tokens preserve any magnitude through `u64::MAX`.  Width is
computed from significant digits; leading zeroes therefore do not consume the
magnitude budget.  Decimal 20-digit values are checked lexicographically against
`18446744073709551615`, avoiding an overflow-prone host or signed-range shortcut.

**Parser decision.** Do not pretend Stage 1 implements the whole AC2 profile.
The executable parser envelope is intentionally:

```text
int f() { return INTEGER; }
int f() { return g(); }
```

for one or more zero-parameter functions.  This is enough to force real symbol
spelling, function definition tables, forward-call fixups, `main` resolution,
and direct execution while keeping declarations/types/AOM/linking out of 10.1.
Parameterized functions and richer expressions are rejected with a stable parse
diagnostic rather than accidentally accepted as partial C.

**Direct-backend decision.** Stage 1 still emits the pre-AOM direct executable
format.  A full-width constant is synthesized nibble-by-nibble into a 64-bit
target register, so lexical support for `0xffffffffffffffff` is not defeated by
the ISA's small `MOVI` immediate.  Every generated function saves/restores LR on
the stack before RET.  That detail is required by Anka64's CALL/RET authority
stack: a function that calls another function must restore the caller's exact
return target before its own RET.

**Stable diagnostics.** The first failure taxonomy is intentionally small and
machine-readable:

```text
1 lexical rejection
2 identifier too long
3 integer magnitude/hex-token rejection
4 outside stage-1 grammar
5 duplicate function
6 missing main
7 unresolved function
8 bounded compiler resource exhaustion
```

The first error is retained in the shared compiler workspace and compilation
returns nonzero.  A failed compile never publishes a successful executable.

**Authority decision.** Reusing the compiler ABI does not weaken the Phase 10.0
authority theorem:

```text
CC_B builds compiler != execution authority
compiler accepts source != execution authority
compiler seals output != execution authority
```

The produced direct executable remains inert until ordinary exact-artifact and
execution admission occurs.  Stage 1 emits no AOM, so symbol names and fixups
remain compiler-internal address relationships only.

**Formal result.** `anka101_ankacc2_frontend.kleis` refines the Phase 10.0 AC2
profile without new axioms.  It closes at 15/15 positive examples.  Its hostile
companion closes at 0/8 accepted claims: digit-first identifiers, 64-byte
identifiers, above-width integer tokens, parameterized Stage-1 functions,
unsealed compiler admission, premature AOM output, and compilation-derived
execution authority are all rejected.

**Runtime gate.** Nine Rust witnesses exercise the real intended path, including
CC_B -> AnkaCC2, 63-byte uppercase/underscore identifiers, exact maximum decimal
and hexadecimal 64-bit literals, significant-width leading-zero behavior,
stable width/parser/symbol diagnostics, and execution of the generated direct
image.  After the bootstrap-grammar correction below, the complete regression
suite closes at:

```text
932 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

This is the previous 923-test Phase 9.4g baseline plus all nine Phase 10.1
runtime witnesses, with no regressions.

**Bootstrap-grammar correction.** The first Cargo run reached the intended
bootstrap boundary and failed all nine new witnesses before AnkaCC2 executed:
CC_B returned `CompilerRejected(1)` while compiling `ankacc2_stage1.c`.  The
source contained one bare `syscall(5, ...)` expression statement.  CC_B reserves
`syscall` as a primary expression and does not admit it through the ordinary
identifier-call statement production.  Rewriting that operation as
`int seal = syscall(5, ...);` keeps the exact same seal operation while placing
it inside grammar CC_B actually supports.  A direct audit of the corrected
source against CC_B's frozen lexer/parser accepts the complete translation unit.
This is a bootstrap-compatibility repair, not an expansion of CC_B and not a
change to the AC2 Stage-1 language.  The corrected tree subsequently passed the
full Cargo suite at 932/932, so this failure is retained as a regression lesson
rather than an open gate.

**Closure.** Phase 10.1 is CLOSED: 932/932 Rust tests, 15/15 positive Kleis
witnesses, 0/8 hostile witnesses accepted, and no new axioms.  The old compiler
now builds the first executable generation of its successor through the ordinary
Anka compile-only/seal path.

**Consequence.** Phase 10.2 can expand declarations/types/ABI against a working
second-generation lexical/parser core without also inventing AOM or the linker.
The bootstrap compiler remains a provenance root, not a permanent language
constraint.

## DN-44: Provenance Is a Trust Relationship, Not a PKI Product

**Date:** 2026-09-19

**Context.** Phase 10's compiler lineage makes software provenance an explicit
architectural concern.  Modern network distribution often makes the problem look
cryptographic because the receiver sees little more than `untrusted network ->
bytes`.  Historically, however, software could arrive through a much larger
physical and institutional channel: a known vendor, purchasing records, labeled
media, sealed packaging, postal/courier custody, a receiving department, and a
machine-room operator.  For especially sensitive material an organization could
replace the general delivery channel with its own trusted courier/emissary and
maintain a direct chain of custody.

**Decision.** Do not define Anka provenance as X.509, a public CA hierarchy, or
any other particular PKI.  Define the architectural core as:

```text
recognized authority A
+ purpose/namespace for which local policy trusts A
+ attestation by A to exact sealed artifact X
+ current exact identity of X
-> provenance of X is acceptable for that policy
```

The attestation may travel through conventional PKI, an offline signature, a
locally controlled build key, a site-specific attestation service, or a physical
chain of custody accepted by local policy.  An air-gapped installation may, for
example, accept a release physically carried by its own designated custodian.
The cryptographic and physical cases are mechanisms for carrying evidence about
the same underlying relationship; neither mechanism is itself the relationship.

The memorable minimal statement is:

```text
this trusted authority vouches for this exact sealed artifact
```

How the installation came to trust that authority is a separate root-of-trust
and policy problem.  Sometimes that answer is a conventional certificate chain;
sometimes it is an offline key under organizational custody; sometimes it is a
controlled build performed locally; and sometimes it is a human chain of custody.
Physical delivery is not intrinsically secure, and cryptography does not remove
the need to decide which authority is recognized.

**Separation from execution authority.** Provenance answers where an artifact is
accepted as coming from / being vouched for.  It does not answer what the artifact
may cause on this machine:

```text
cryptographic validity != recognized authority
recognized provenance   != execution authority
artifact name/path       != provenance
transport channel        != authority
```

A signature from an unrecognized key therefore creates no Anka authority.  The
same is true of a physically delivered tape merely because somebody carried it.
Only local policy can bind evidence to a recognized provenance authority, and
only the ordinary Anka exact-artifact/capability/spawn path can authorize the
resulting software to execute.

**Consequence for Phase 10.9.** Supply-chain closure should be able to explain
two independent histories for any admitted compiler/program artifact:

```text
artifact derivation:
source -> compiler generation -> object/link steps -> exact sealed artifact

trust derivation:
local trust policy -> recognized attester/custodian -> attestation/custody evidence
                   -> exact sealed artifact
```

PKI can be one implementation of the second line, but Anka must not bake one
global trust transport into the meaning of provenance.  This keeps high-assurance,
offline, air-gapped, organization-local, and conventional Internet distribution
under the same small architectural rule.

## DN-45: Make the Type System Real Before AOM, but Do Not Invent Writable Globals Yet (Phase 10.2)

**Date:** 2026-09-19

**Context.** Phase 10.1 proved the old self-hosted compiler can build a real
successor front end, but the executable language was intentionally tiny: only
zero-argument `int` functions returning a literal or another zero-argument call.
The next pressure is no longer lexical.  Real modular Anka C needs declarations,
function signatures, pointers, arrays, aggregates, aliases, enum constants, and
a calling convention that is written down rather than inferred from whichever
bootstrap compiler happened to generate the code.

At the same time, the Phase 10 roadmap deliberately keeps AOM and the linker in
10.3/10.4.  A conventional compiler would be tempted to add writable globals by
placing bytes somewhere convenient in the executable image.  That would be an
architectural regression for Anka: the direct executable is sealed code, and a
writable file-scope object needs a real data-section/mapping/permission story.

**Decision.** Introduce `ankacc2_stage2.c` as another real Anka userspace
compiler source that remains compilable by CC_B.  Keep `ankacc2_stage1.c`
unchanged as the closed 10.1 checkpoint.  Stage 2 reuses the exact supervised
compiler process ABI and compile-only seal path; only source semantics expand.

The first AC2 object model is explicit:

```text
int       8 bytes, align 8
char      1 byte,  align 1
pointer   8 bytes, align 8
enum      same representation as int
void      no object representation
```

Struct layout is declaration-order layout with ordinary alignment padding and
final rounding to the maximum member alignment.  Fixed arrays are contiguous
`count * element_size` objects.  To keep the bootstrap implementation bounded,
Stage 2 limits a fixed extent to 1024 elements and the typed local-object portion
of one frame to 8192 bytes.  Recursive-by-value incomplete structs therefore
fail, while pointer recursion remains representable.

`typedef` is an exact alias, not a new runtime object.  Enum constants are
compile-time integer values.  `sizeof(type)` and `sizeof(type[extent])` are
included now because they make type layout executable and testable without
waiting for member-access syntax.

**ABI decision.** Freeze the first AnkaCC2 direct function ABI as:

```text
R0..R3  up to four scalar/pointer arguments
R0      scalar/pointer return value
LR      protected CALL/RET return authority, saved by callee
FP      callee frame pointer, saved by callee
SP      bounded local-object and temporary-expression stack
```

Named parameters are spilled into the callee frame.  Array parameters decay to
an element pointer in the recorded function signature.  Aggregate-by-value
arguments and returns are deliberately rejected in 10.2; choosing a struct ABI
without a real need would be exactly the kind of premature convention Anka has
avoided elsewhere.  A later phase may earn such an ABI.

Function prototypes are now semantic objects.  A definition must match an
existing prototype exactly in return type, parameter count, and parameter types.
Calls require a known declaration, and any called prototype must resolve to a
real definition before the compiler publishes success.  This makes a prototype
a type/symbol promise, not authority.

**Direct-backend data decision.** Mutable file-scope data remains unsupported:

```text
file-scope name != storage authority
compiled declaration != writable mapping
sealed executable != writable data object
```

The compiler rejects mutable globals with diagnostic 14.  This is temporary in
language coverage but permanent in architectural principle.  When globals are
introduced, AOM must describe their section and the loader must map that section
with the correct non-executable writable permissions.  The compiler is not
allowed to smuggle mutable state into RX code just to make a familiar C program
compile.

**Expression scope.** Phase 10.2 implements only the expression operations
needed to prove the type and ABI work end to end: integer/enum values, scalar
locals, address-of, 64-bit pointer dereference, calls, and integer `+`/`-`.
For the supported arithmetic operators, byte-sized `char` is promoted to `int`;
the byte storage rule and the word arithmetic rule are deliberately distinct.
Struct field access, general indexing, character/string literal semantics, and
the broader expression/statement language remain later compiler work.  This is
not a claim of full ISO C support; it is the first internally coherent AC2 type
and ABI layer.

**Stable diagnostics.** Codes 1..8 retain their 10.1 meanings.  Stage 2 adds:

```text
9   type/object mismatch
10  declaration/tag/alias error
11  prototype/definition signature mismatch
12  direct ABI limit / aggregate-by-value rejection
13  layout/extent/frame bound violation
14  mutable file-scope data unsupported by direct backend
```

The first error remains sticky and failed compilation publishes no successful
artifact.

**Formal result.** `anka102_ac2_types_abi.kleis` closes at 23/23 positive
examples.  Its hostile companion closes at 0/14 accepted claims.  No new axioms
are introduced.  The theory fixes the object sizes/alignments, positive bounded
arrays, the `char`-then-`int` struct-padding witness, exact prototype matching,
the four-register scalar/pointer ABI, array-parameter decay, stack-resident
locals, absence of mutable globals in the direct backend, absence of AOM in
10.2, and the continuing rule that compilation cannot create execution
authority.

**Bootstrap-shape audit.** The Stage-2 compiler source is intentionally kept
inside CC_B's own finite envelope.  The first real Cargo attempt produced 932
passing baseline tests and 12 `p102_` failures, all at the same upstream edge:
CC_B rejected `ankacc2_stage2.c` with error 1 before Stage 2 itself ever ran.
The cause was not the AC2 type system.  CC_B has a flat local-symbol table per
function and therefore rejects a local name redeclared in another lexical block.
Stage 2 had legal-C block-local reuse of `type` in `primary`, `type`/`base` in
`unary`, and `ns`/`nl` in multiple branches of `topitem`.  Those bootstrap names
are now unique; a redundant identical branch in `unary` was removed at the same
time.

The corrected source is also no longer stored as one minified line.  Fully
conventional indentation would exceed the predecessor's source arena, so the
bootstrap file uses compact multiline formatting: statements and braces are
line-separated, with blank lines between functions but no indentation.  Static
inspection now records:

```text
source bytes                  19,745 / 20,472-byte CC_B source limit
source headroom                  727 bytes
bootstrap functions              61 / 64
maximum bootstrap parameters      4 / 4
maximum flat symbols/function    14 / 32
flat local-name duplicates        0
bootstrap call sites            368 / 512 fixup bound
largest source literal       81,920 / 131,071
CC_B output geometry          measured by the real `p102_` runtime witness
```

This is an important bootstrap lesson: nested-scope semantics belong to AC2,
but the implementation of the AC2 compiler must still obey CC_B's flatter
source language until the successor crosses the bootstrap boundary.  Source
readability is also constrained by that finite predecessor arena, so compact
multiline formatting is deliberate rather than accidental.

There is deliberately no generated-text estimate anymore.  The
`p102_ccb_builds_real_ankacc2_stage2` test reads the actual `CompiledCImage`
returned by CC_B and calculates exact code bytes, literal bytes, occupied bytes,
free-gap bytes, and output-arena size.  The test prints those values under
`--nocapture` and asserts the geometry accounts for the complete 81,920-byte
arena.  The measurement therefore comes from the same real bootstrap execution
that is being admitted, not from a source-level approximation.

**Runtime witnesses.** Twelve `p102_` tests cover CC_B building Stage 2,
compatible prototypes plus four register arguments, pointer/address/dereference
through array-parameter decay, typedef + enum constants, struct and array layout,
byte-sized `char`, and stable rejection of signature mismatch, five arguments,
struct-by-value ABI, recursive-by-value layout, zero arrays, mutable globals,
unresolved prototypes, void objects, and unknown aliases.

**Status.** CLOSED.  Implementation and formal gates are complete.  The Cargo
runtime gate first reached 943/944.  The sole failure was narrower than the
arithmetic path: `char c = 42` failed before `+`/`-` because `typeok()` admitted
`char`→`int` but not the corresponding Stage-2 scalar narrowing `int`→`char`.
Arithmetic promotion was already correct.  Scalar value compatibility is now
symmetric for the `int`/`char` subset: storing `int` to `char` keeps the low byte,
and loading `char` zero-extends it into the word-register ABI.  The formal
refinement includes that conversion explicitly.  The final full-suite closure is
**944/944 Rust tests passing, 0 failures**, together with 23/23 positive Kleis
witnesses and 0/14 hostile witnesses accepted.

**Consequence.** Phase 10.3 can introduce AOM as a representation for semantics
that now already exist: typed functions, exact signatures, stack-local object
layout, and a clear distinction between code and future data sections.  AOM no
longer has to invent the type system and object model at the same time it invents
relocation.

## DN-46: Resolve Known CC_B Calls Before Spending Deferred Fixups (Phase 10.6)

The Stage-3 bootstrap exceeded CC_B's 512-entry deferred-call table even with
ample output space. Recording every call made ordinary calls to already-known
functions consume the same finite resource as unresolved forward calls.

The extended bootstrap now looks up the existing function table first. A known
target is patched immediately after exact arity checking, with the same first
matching definition and call encoding used by deferred resolution. Only forward
calls consume deferred entries; the 512-entry bound and canonical compiler source
remain unchanged. This follows the placement/output-headroom repair rather than
expanding an unrelated limit.

The formal contract is `theories/anka106_ccb_call_fixups.kleis` and its
`_false_witnesses.kleis` partner: 6 positive witnesses and 3 explicitly disproved
hostile assertions. Runtime regressions cover 513 known calls, ordinary forward
resolution, rejection of 513 unresolved calls, and wrong arity. These changes are
part of the merged Phase 10.6 baseline and subsequent passing full suites.

## DN-47: Concrete CC2 Fixed Point Includes Publication Identity and Geometry (Phase 10.6)

**Status.** Phase 10.6 is merged to `main`; its local full-suite checkpoint was
995 passing tests. The later Phase 10.7 checkpoint also exercises this lineage.

`witness_cc2_fixed_point` builds CC2_0 from the exact current Stage-3 source with
extended CC_B. Guest `ankapp` preprocesses one immutable source bundle on both
self-host edges. CC2_0 emits AOM_1; guest `ankald` links and publishes sealed
CC2_1. The exact linked CC2_1 emits AOM_2, which is linked and published as a
distinct sealed CC2_2. Closure requires identical bytes, code size, literal start,
and entry. Byte equality alone does not establish provenance (see DN-7).

The first compiler witness uses standalone source and requires preprocessing to
reproduce its bytes exactly. Include-bearing compiler seeds remain a later
refinement. Imported Stage-3 caches cannot select a generation in this witness.
Explicit developer execution authority is required.

A linked compiler's `main` is an ordinary function and may have a nonzero entry.
A separate sealed launcher CALLs the linker-selected entry, establishes protected
return authority, and exits with the compiler result. The compiler image is never
prefixed or patched. Existing physical and virtual placement managers admit the
mappings; code receives RX and literals R. The spawn ABI remains unchanged.

The compiler source itself needs the earned bootstrap integer-word dereference
exception. Workspace word 68480 is explicitly enabled on both self-host edges;
ordinary application compilation leaves it zero. A guest regression reads the
actual control word and emits sealed output, testing ordinary seed and linked
compilation as zero and both bootstrap edges as one. This is a narrow compiler
source profile, not a general application permission.

For application rebuilds, the witness now retains private publication Fabric and
placement state, original keys, immutable compiler identity, and guest-produced
preprocessor/linker images. It validates both sealed/current compiler publications
and rejects altered public observation bytes, keys, or execution geometry before
application preprocessing. Public observations do not substitute for producer
evidence. Retained helper images are not yet persistent tool publications.

Existing formal gates cover closure and bootstrap language admission:

| Gate | Positive witnesses | Hostile assertions explicitly disproved |
|---|---:|---:|
| `anka106_cc2_self_host_closure` | 26 | 26 |
| `anka106_ac2_self_host_language` | 26 | 26 |

These establish acceptance contracts, not a proof of every compiler instruction.
The runtime fixed-point test supplies the concrete generation-chain witness.

```sh
cargo test --lib p106_concrete_cc2_generation_chain_closes_fixed_point -- --test-threads=1 --nocapture
```

The development monitor supports `cc2 fixed-point [prefix]`. The default prefix
is `cc2-fp`; observations are retained under `<prefix>-0`, `<prefix>-1`,
`<prefix>-2`, `<prefix>-aom-1`, and `<prefix>-aom-2`. `tool-artifacts` lists them;
`dump cc2-fp-1 cc2-1.bin` exports observation bytes. This observation registry does
not itself authorize ordinary application execution.

## DN-48: Rebuild Applications With Verified CC2 and Separate Execution Authority (Phase 10.7)

**Current phase status:** Phase 10.7 is complete and merged to `main`; DN-59 records
its final scope and the 1037-test validation. The checkpoints below retain their
historical status at the time of each implementation step. Earlier statements that
10.7 remains open do not override DN-59. Typed syscall I/O, compiler/toolchain
modularization, persistent tool/source receipts, and broader service rebuilds are
scheduled in 10.8; the final CPU-to-HTTP closure remains 10.9.

**Checkpoint, 2026-10-10.** On `feat/anka107-userspace-rebuild`, the user reported
**997 passing tests, zero failures**, run single threaded (864.83 seconds). The
concrete CC2-backed application witness passes. Phase 10.7 remains open; this is
a first executable subset of the broader rebuild contract.

### Formal acceptance contract

`theories/anka107_userspace_rebuild.kleis` imports the self-host closure,
application pointer, and HTTP contracts. Admission requires:

- Concrete fixed-point evidence, the exact sealed/current CC2_1 object and
  generation, and explicit compiler execution authority.
- Exact immutable source bundle membership, root, profile, source generation,
  effective translation unit, and exact current guest preprocessor.
- Ordinary application profile, valid AOM emission, exact current guest linker,
  complete linked bytes and geometry, sealed/current output, and permission
  non-amplification.
- Host transport and observation only; preprocessing, compilation, linking and
  symbol resolution execute inside Anka, with no host artifact repair.
- The exact application artifact key, separate application execution authority,
  ordinary execution admission, and existing physical/virtual placement admission.
- Failure publishes no next-stage output and never executes failed output.
  Earlier successful artifacts may remain.
- For eventual HTTP closure, exact rebuilt socket and HTTP artifacts actually
  boot, existing protocol contracts hold, HTTP has no NIC authority, and the
  exact alive request produces the exact alive response.

Object and generation must both match; filenames and byte equality are
insufficient. Imported admission flags summarize obligations whose evidence the
implementation must supply. Setting a Boolean is not a runtime proof. This first
producer selection is CC2_1; choosing another generation needs policy refinement.

### Typed application pointers

`theories/anka107_application_pointers.kleis` freezes these requirements:

- The typed application profile disables the compiler bootstrap raw integer-word
  exception. Pointer assignment requires matching pointee types and no implicit
  integer conversion.
- IPC/syscall address boundaries require an explicitly declared address contract,
  exact signature and typed result, preserving Fabric checks. Transporting pointer
  bits grants no memory authority and does not introduce general casts.
- Initial pointee scope is `char` (one byte) and `int` (eight bytes). Void,
  function and aggregate dereference are outside this first profile.
- Forward movement scales by element size. Division-based preflight rejects
  multiplication/addition overflow and the result must equal the exact scaled
  displacement. Zero movement and forming one-past are allowed; dereferencing
  one-past is rejected.
- Each access requires a complete typed pointee, exact width, nonwrapping virtual
  address, an in-bounds nonzero range within one mapping, a current-generation
  capability, required permissions and natural alignment.

Pointers remain numeric virtual addresses. Region bounds are model obligations;
no new bounded-pointer representation, pointer metadata, capability format,
syscall ABI or memory manager is introduced. The model's 0/1 BitVec8 flags express
solver obligations rather than a runtime ABI. Checked subtraction establishes
bounds without unchecked endpoint addition. Negative movement, pointer
subtraction, arbitrary integer casts and broad ISO C conformance remain deferred.

### Implemented executable subset

`rebuild_application` validates the retained fixed-point producer, guest-preprocesses
an immutable source bundle, compiles with linked CC2_1 under the ordinary profile,
guest-links `main`, publishes exact sealed bytes, and registers that same
object/generation. Registration copies metadata only and grants no authority.
The separate `RebuiltApplication::run` call requires explicit application
execution authority and uses ordinary SYS_SPAWN/SYS_WAIT. Compilation never runs
the resulting application.

`userspace/bin/pointer_probe.c` uses typed `int*` loads/stores of a stack word and
exits with 42. The concrete regression also rejects raw integer dereference,
missing compiler/application authority, and altered compiler keys, bytes or entry.
The current Stage-3 parser accepts the syscall intrinsic as an expression; the
probe places it in a local initializer because bare syscall expression statements
are not supported by its statement dispatcher.

This first application is standalone, single-AOM, with linked entry zero and an
explicit exit syscall. Nonzero application entries are rejected before publication;
compiler entry handling remains the separate protected-call launcher described
in DN-47. The current ISA supplies word-sized loads/stores, so byte access needs
an explicit lowering decision before implementation.

### Gates and remaining work

| Phase 10.7 gate | Positive witnesses | Hostile assertions explicitly disproved |
|---|---:|---:|
| Application pointers | 57 | 55 |
| Userspace rebuild | 60 | 52 |
| Total | 117 | 107 |

All gates passed. Every hostile assertion must be explicitly disproved; parse or
type errors, unknown solver results, and generic nonzero exits do not qualify.
These conditional contracts and examples do not prove all C semantics or that
Rust implements every modeled predicate.

```sh
python3 scripts/check-anka107-gates.py --kleis /path/to/kleis
cargo test --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address -- --test-threads=1 --nocapture
cargo test -- --test-threads=1
```

The gate runner also accepts `kleis` on PATH with no `--kleis` argument. It needs
a working standard library and Z3 dependencies and handles deliberately nonzero
hostile-suite exits only when all expected explicit disproofs are present.

Next work is typed byte access, checked scaled pointer arithmetic, and exact typed
address-boundary handling, reviewed against the existing Kleis contract before
implementation. Multi-module rebuild, persistent current tool publications and
source-generation receipts remain open. Then adapt and rebuild `socket.c` and
`httpd.c` under the ordinary application profile and apply the deterministic
socket/HTTP tests to those exact artifacts. Never enable the compiler-only raw-word
profile to make services compile. The final boot and alive response remain the
Phase 10 acceptance boundary from DN-41.

### Documentation policy

Keep lasting decisions, validation checkpoints and remaining obligations in this
file. Keep executable formal contracts in `theories/` and gate runners in
`scripts/`. Routine patch application instructions and one-off corrections belong
in delivery messages or commit history. Separate documents require a distinct,
lasting purpose. This entry supersedes the five Phase 10.6/10.7 patch-note files.

## DN-49: Byte Instructions Must Preserve Exact Fabric Data Spans (Phase 10.7)

**Decision before implementation.** Add native zero-extending byte loads and
low-byte stores to the ISA, with encodings chosen only after decoder review.
A CPU instruction is distinct from its Fabric transaction. Operand translation,
request authorization, and commit must preserve exact object, generation, offset,
width and operation permission. Existing word instruction encodings and semantics
remain unchanged; no syscall or new pointer representation is required.

The proposed `anka107_byte_transactions.kleis` contract freezes:

- Exact operand/request object and offset, declared length one, and actual operand
  data span one. Aligning down or fetching an enclosing word is inadmissible.
- Exact capability object/generation, current mapping, memory kind, the operation's
  permission, an in-bounds byte, and nonwrapping virtual base-plus-offset.
- Zero-extended byte loads (0..255) and stores of only the source's low eight bits.
  Byte alignment is one. Word alignment rules remain unchanged.
- Write-only byte stores without an implicit read of an enclosing word. Read-only
  authority does not permit stores; write-only authority does not permit loads.
- Pointwise preservation of every non-target byte on successful stores, all memory
  on rejected stores, and the destination register on rejected loads. This does
  not prevent the ordinary fault transition or fault-reporting state updates.
- Zero operand-data span on rejection and one on admission, with no pre-admission
  backing-data fetch. Store payload length must also be one, independently of the
  declared request. Exact bridge, identity/range and environment evidence are all
  required; evidence flags cannot replace actual validation.

This allows access to the final authorized byte of an object without requiring
permission for an enclosing eight-byte range. A word read/modify/write lowering
would widen authority requirements and could overwrite a neighboring update.
Native byte transactions avoid that widening.

**Proof boundary.** These are proposed acceptance predicates and a pointwise byte
state model, not verification of an implemented decoder or backing-memory path.
The trace span refers to operand data, not instruction fetch or metadata reads.
The rejection-fetch predicate requires no backing-data read in the modeled
transaction path; it does not prove physical cache/bus/speculation/timing
noninterference. Even a one-byte simulator slice is executed by a host whose
microarchitecture is outside this model. Physical hardware requires a separate
fetch-granularity and side-channel contract. No new atomic ordering or memory
model is established here.

The new suite has **41 positive witnesses**, including universally quantified
low-byte range/idempotence, neighbor preservation, rejected-store identity and
write-only admission laws. Its **36 hostile assertions must all be explicitly
disproved by Z3**. The existing application-pointer and userspace-rebuild suites
are also rerun by `scripts/check-anka107-gates.py`: the combined gate is 158
positive witnesses and 143 explicit hostile disproofs. There are no new axioms.

```sh
python3 scripts/check-anka107-gates.py --kleis /path/to/kleis
```

**Next implementation gate.** Implement unused byte instruction encodings and
CPU-to-Fabric width-one requests, with tests of the final object byte, wrong/stale
identity, denied permissions, exact payload length, neighboring-byte preservation,
and no operand-data read or mutation before admission. Then lower `char*`
dereferences in CC2 and extend the concrete verified-compiler application witness.
A passing theory gate alone does not close this implementation step.


**DN-49 implementation checkpoint: CPU byte substrate.** The description table now
assigns unused I-format opcodes 0x24/0x25 to `ldb`/`stb`; the table-driven decoder,
assembler and disassembler share them. The generated ISA theory is refreshed.
Byte operations use checked signed effective addresses and checked object offsets,
reject ambiguous mappings, and issue one-byte Fabric requests. Loads zero-extend;
stores truncate without reading adjacent bytes. Rejected loads preserve their
register, and rejected stores preserve memory. Existing word instructions are
unchanged. Seven new CPU tests inspect actual transaction width/payload/state and
cover last-byte access, write-only authority, neighbors, stale generations,
permission/bounds failures, ambiguous mappings and overflow. All 42 CPU tests
passed locally. Full-suite validation remains a local follow-up. Compiler byte
lowering is deferred until this ISA/Fabric checkpoint passes locally.

```sh
cargo test --lib p107_byte_ -- --test-threads=1
cargo test -- --test-threads=1
```

## DN-50: Typed Pointees Select Exact CC2 Memory Instructions (Phase 10.7)

**Baseline.** The byte ISA/Fabric substrate is merged to `main`; the user reported
1004 passing tests, zero failures (873.51 seconds, single threaded). Work continues
on `feat/anka107-cc2-byte-lowering`. Compiler byte lowering is not implemented by
this formal-only refinement.

The existing application-pointer gate defines typed admission; DN-49 defines the
byte instruction/Fabric boundary. The new `anka107_cc2_byte_lowering.kleis` connects
the pointee type and operation to emitted instruction evidence:

| Pointee | Operation | ISA opcode | Operand width |
|---|---|---:|---:|
| `char` | load | `ldb`, 0x24 | 1 |
| `char` | store | `stb`, 0x25 | 1 |
| `int` | load | `ld`, 0x20 | 8 |
| `int` | store | `st`, 0x21 | 8 |

The pointee tags in the theory are semantic `int=1`/`char=2`, not the compiler's
encoded pointer tags. Access tags are load=0/store=1; the description table remains
the authority for actual opcode encodings. Void and all other unsupported pointees,
unknown access tags, wrong opcodes and wrong widths are rejected.

The application profile requires a typed pointer and complete pointee, and disables
the bootstrap integer-word exception. Lowering preserves the exact effective
operand address, zero-extends byte values into word registers, truncates byte stores
to the low eight bits, and preserves full word values for `int`. It neither changes
capability authority nor bypasses Fabric. Exactly one operand-data transaction is
emitted; enclosing-word access and an extra software read/modify/write read are
inadmissible. Instruction fetch and metadata reads are outside that operand count.

Profile, instruction shape, address, value rule, effects and Fabric-contract evidence
are all required for lowering acceptance. These flags summarize actual obligations;
setting them does not supply evidence or authorize a runtime access. Successful
lowering does not imply a successful memory access: ordinary Fabric permission,
generation, mapping, range and lifecycle checks still determine execution. Source
and emitted effective addresses must independently obey the nonwrapping rules.

The new gate contains **43 positive witnesses** and **40 hostile assertions**, all
explicitly disproved. Universal laws cover byte projection/range and word value
preservation. Hostile coverage includes raw integer dereference, bootstrap-profile
leakage, word operations on bytes, byte operations on words, sign extension of 255,
store truncation failure, address align-down/shift, added authority, extra operand
transactions, enclosing-word access and omitted Fabric evidence.

The updated runner executes all four Phase 10.7 theory pairs: **201 positive
witnesses and 183 explicit hostile disproofs**. No axioms or implementation changes
are introduced. This is an emitted-evidence acceptance contract, not a formal proof
that the C compiler implements it, an ISO C semantics proof, or a microarchitectural
confidentiality claim.

```sh
python3 scripts/check-anka107-gates.py --kleis /path/to/kleis
```

**Next implementation.** Make Stage-3 select byte versus word instructions from the
pointee type in dereference expression and assignment lowering, while retaining the
restricted application profile. Review local `char` storage too so the end-to-end
probe does not accidentally widen neighboring-byte accesses. Compile and run a
byte-pointer probe through the concrete verified CC2_1 chain; assert unsigned values,
truncation, neighboring-byte preservation and continued raw-address rejection.
Re-run the fixed point after compiler-source changes. Use placement managers and
existing exact publication/explicit execution admission. Full Phase 10.7 and HTTP
closure remain open.


**DN-50 implementation checkpoint: CC2 byte lowering.** Stage-3 now selects
`ldb`/`stb` for `char` dereferences and `ld`/`st` for `int`. Typed dereference is
limited to those two pointees; the existing compiler-only raw-word exception
remains guarded by the bootstrap workspace flag, which application compilation
leaves disabled. Local `char` reads now use `ldb` rather than an enclosing word
load plus mask. Local initialization and assignment use the shared type-selected
store helper. Stack spills, ABI slots and pointer values remain word-sized.
The source shrank from 20,151 to 19,973 bytes, leaving 499 bytes in the 20,472-byte
bootstrap source payload. Placement and execution authority remain unchanged.

The existing concrete rebuild test now reuses its newly verified CC2_1 producer to
build `userspace/bin/byte_pointer_probe.c`. It checks the exact published code for
byte pointer load/store opcodes and absence of widened pointer accesses, then
expects exit 365: unsigned/truncated pointer value 255, sentinel locals 17 and 51,
and a narrowed local value 42. Those sentinel locals are separate stack slots;
physical adjacent-byte preservation is established by the existing CPU substrate
tests, not by claiming the local slots are packed. Negative sources test mismatched
pointer types and void-pointer dereference, in addition to existing raw-address,
producer-identity and explicit-authority checks. The changed compiler source goes
through the complete fixed-point chain before the application is built.

All 201 positive and 183 hostile Kleis checks passed locally. The Rust test harness
builds and the exact-publication registration regression passes. The expanded
bootstrap-backed test and full runtime suite have not been executed in this
container; prior full bootstrap attempts exhausted its memory. The expected suite
count remains 1004 because the existing concrete test was extended.

```sh
cargo test --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address -- --test-threads=1 --nocapture
cargo test -- --test-threads=1
```

The passing 1004-test baseline predates this compiler change. This checkpoint is
pending the local commands above. Scaled pointer arithmetic, multi-module rebuild,
persistent tool/source receipts and the rebuilt HTTP chain remain open.


**DN-50 hostile-source refinement.** The first local run completed the changed
CC2 fixed point (CC2_1/CC2_2 code and backing 124,744 bytes, entry 122,392) and the
byte probe/opcode assertions, then failed the void-pointer hostile witness's
expected error code. A direct local `void *p` declaration is outside q50's
statement dispatch and returns syntax error 10 before dereference validation.
The witness now uses the already-supported `typedef void *VP; VP p;` form so it
can reach q47's unsupported-pointee rejection and require error 9 precisely.
No compiler change or broadened error matching is introduced. Existing lowering
gates cover this supported typedef/declaration form. The corrected end-to-end
witness still needs a local rerun; full-suite validation remains pending.

## DN-51 — Allocation-associated pointers: formal checkpoint

Phase 10.7 on `feat/anka107-pointer-arithmetic` now treats an application pointer
as allocation identity, allocation generation, a narrowed byte-offset interval,
a current position, and access rights. This supersedes the earlier assumption
that ordinary numeric addresses plus caller-supplied bounds are sufficient.
The machine representation and compiler ABI remain undecided and unimplemented.

`anka107_pointer_metadata.kleis` defines a dynamic allocation lifecycle:
creation requires a free record, checked placement, existing Fabric authority,
and a strictly advanced generation; release requires the live allocation's
identity/generation and owner authority. Reuse cannot overwrite a live record,
retain the old generation, or wrap an exhausted generation. Identity zero and
generation zero are reserved. Initial allocation advances generation 0 to 1.
An implementation must preserve generation history across record-slot reuse;
exhausted slots must be retired or replaced with genuinely fresh identities.

Pointers retain original provenance across copy/store/load/pass/return and
forward arithmetic. Checked byte/word scaling permits one-past formation but
not dereference. Narrowing can reduce bounds and rights, never expand them.
An application buffer's bounds can be smaller than its containing Fabric
object. Resolving an old address to a newly allocated object cannot restore
pointer validity. Release authorization is distinct from ordinary write rights.

The access predicate composes metadata authenticity, live original allocation,
matching identity/generation, representable allocation end, narrowed bounds,
complete exact-width access, rights, alignment, and Fabric admission. Fabric
admission is an obligation to the existing mapping/object/capability gates;
this theory neither replaces nor proves their implementation. Authenticity is
also an explicit obligation: merely supplying metadata-shaped integers cannot
establish it. Allocation creation's placement obligation must be discharged
against all live allocations; pairwise non-overlap is provided as a helper.

The contract applies to heap allocations and scoped stack/local allocations.
The implementation must invalidate each protected scope at its lifetime end,
serialize invalidation against access, and preserve unrelated records. It must
implement a metadata-preserving ABI and storage path. No runtime allocator,
metadata table, hardware tag, compiler lowering, or borrow checker is added by
this patch. Zero-size allocation policy, backward arithmetic, subtraction,
integer reconstruction, and concurrency/borrowing semantics remain open.
The record requires a representable exclusive end, conservatively excluding
an allocation reaching past the largest representable address.

Validation: 65 new positive witnesses pass; all 61 hostile assertions are
explicitly disproved by Z3. The complete Phase 10.7 runner passes 266 positive
and 244 hostile witnesses, with no Unknown accepted. Four new positive checks
include quantified frame preservation and lifetime rejection properties.
These are contract checks, not an end-to-end proof of runtime memory safety.

Run from the repository root:

```sh
python3 scripts/check-anka107-gates.py --kleis /path/to/kleis
```

Next implementation decision: choose protected pointer metadata storage and
propagation across the CC2 ABI, together with allocation-record lifecycle and
stack/local scope registration. Representation selection needs refinement gates
before compiler/runtime changes. The compiler-only bootstrap raw-word profile
remains a separate exception; ordinary application pointers receive no such
exemption.

## DN-52 — Protected descriptor-pointer representation refinement

The initial candidate has a 16-byte DATA payload: word 0 is a 64-bit descriptor
handle (upper 32 bits epoch, lower 32 bits slot); word 1 is a 64-bit byte position
relative to the allocation base. A protected pointer-kind tag must bind the pair.
The tag is additional protected state, not an ordinary writable integer and not
included in the 16-byte payload size. This is a proposed application ABI, not a
change to existing AC2 sizes, machine registers, instructions or bootstrap ABI.

Slots and descriptor epochs are nonzero 32-bit values. Lookup must match both
encoded components, descriptor liveness and caller-domain binding. Free slots
can be published only by a trusted issuer after validation and initialization,
with a strictly advanced epoch. Epoch exhaustion retires the slot: wrapping or
forgetting slot history is prohibited. The finite slot namespace may exhaust;
allocation must then fail safely. This does not prescribe preallocating a large
table, and records may be grown dynamically within the representable namespace.

An issued descriptor stores allocation identity, allocation generation, narrowed
lower/upper bounds, and rights. Its contents are immutable while issued. The
allocation generation is independent of the descriptor epoch; dereference checks
both lifecycles. A descriptor still live after allocation release is unusable.
Changing a descriptor's allocation in place is prohibited. Narrowing uses a
separately validated and published descriptor with the same allocation identity
and generation and reduced bounds/rights. Domain transfer is outside this gate;
merely copying payload words into another domain grants no authority.

Copy, pointer storage, typed load, argument passage and return must preserve the
ordered pair and protected tag coherently. Ordinary writes clear pointer-kind
state; partial or torn values cannot remain usable pointers. Arithmetic retains
the handle and tag and changes only a checked, element-scaled position. Null is
an untagged zero handle/zero position and fails lookup. Materializing a numeric
address uses checked allocation base plus position only after admission; it does
not reconstruct provenance from the address.

`anka107_pointer_representation.kleis` checks packing roundtrips, publication,
lookup, immutable metadata, narrowing, pair transport, arithmetic, null,
descriptor/heap ABA rejection, and domain/Fabric checks. Quantified checks prove
that concrete admission implies the imported abstract admission contract and
that a valid allocation plus bounded position cannot wrap address materialization.
The implication is a compositional predicate refinement, not a proof that a
compiler, allocator or hardware implements these predicates.

This proposal exposes a necessary enforcement decision before implementation:
where the protected tag resides and which trusted operations can create, copy,
clear or consume it. The theory models tag validity as an explicit obligation;
it does not derive unforgeability from the two payload integers. Register-side
pointer-kind state, protected pointer storage and atomic/coherent transport need
implementation-specific gates. An alternative representation could use protected
side metadata, provided it satisfies the same abstraction relation.

Validation: 57 new positive witnesses pass; all 50 hostile witnesses are explicitly
disproved. Full Phase 10.7 totals: 323 positive and 294 hostile checks. No Rust,
compiler, ISA or runtime code changes accompany this checkpoint.

Next gate: pointer-kind enforcement and concrete CC2 call/storage ABI, including
multiword argument/return placement, spills/reloads, ordinary byte writes to
pointer storage, descriptor reclamation, scoped allocation registration and
access/invalidation serialization. The descriptor candidate remains provisional
until these costs and enforcement mechanisms are reviewed against the codebase.

## DN-53 — Threads, SMP and DMA allocation lifetime gates

`anka107_pointer_concurrency.kleis` proposes a serialized lifecycle refinement:
Live -> Closing -> Retired -> Live with a new allocation generation. Admission
checks validity and increments an operation lease count in one serialized step.
Closing bars new CPU and DMA leases and preserves existing counts and backing.
Retirement requires both CPU and DMA counts to be zero. Reuse additionally
requires a newer non-wrapped generation and checked placement. Saturated counts
reject admission; failures to drain retain the backing instead of reusing it.

Existing `anka_concurrent_protection.kleis` requires Fabric generation/rights
revalidation at commit. Allocation closure is distinct from Fabric revocation:
an already admitted allocation lease may finish during Closing only if Fabric
still permits commit. A lease pins backing memory; it is not irrevocable access
authority. The new pointwise effect gate preserves bytes when commit is denied.
No existing Fabric revocation semantics are weakened.

CPU cache entries are hints. Their control epoch and current Live state must be
checked against authoritative shared state atomically with admission. Control
state must not cycle an epoch back to a stale cache's value. Implementation must
select epoch widths and retirement rules and specify cache invalidation/ordering.
The simple model requires shared serialization even if a cached epoch matches.

Ticket consumption decrements one nonzero count and invalidates the active
operation ticket in the same serialized step. The ticket must match operation,
allocation identity/generation and issuing CPU/device. This binding and exact
one-time consumption are explicit trusted-state obligations, not properties
proved for a runtime ticket registry. Aggregate counters are separate for CPU
and DMA; their sum need not fit in a machine word. An unrelated allocation or
operation must not be mutated by the concrete implementation.

Pointer publication uses a proposed versioned storage protocol: even means
stable, odd means a write is in progress. Before payload mutation, the writer
publishes an odd version and clears protected pointer-kind state. A trusted typed
writer initializes both ordered payload words and publishes protected kind before
releasing a fresh even version. Readers accept only equal even version samples,
a valid tag, current storage identity and ordered payload/tag reads between the
samples. Versions never wrap; exhausted storage identities require safe retirement.
Raw writes cannot mint a tag. This is a protocol obligation, not a claim that
ordinary concurrent Rust/C reads of non-atomic fields are valid: concrete storage
must use locking or an explicitly supported atomic mechanism for every such read.
Reader-versus-overwrite safety after snapshot also needs descriptor lookup/lifetime
serialization before access. Coherent snapshots do not guarantee data-race freedom.

DMA grants retain the original allocation identity/generation, narrowed span and
rights, plus exact authorized device/Fabric binding. TX requires device READ;
RX requires device WRITE. Nonzero spans must fit entirely within the pointer view.
DMA grant validation composes with the same atomic lease-admission transition.
Device payload addresses do not grant provenance or permit device-side descriptor
lookup. Existing finite NIC DMA admission and commit checks remain applicable.

DMA terminal evidence must establish stopped device activity, drained downstream
bus operations, completed mapping/cache synchronization, disabled future grant
use, and an acknowledgment bound to the correct operation. These conditions are
composed directly with ticket consumption. A cancellation request, timeout, or
unbound acknowledgment cannot release the lease. Host hardware enforcement must
prevent device access outside the grant; an arbitrary physical bus master cannot
be made safe merely by software counters or generation changes.

DMA writes overlapping pointer storage must clear protected pointer-kind state
before device mutation; unrelated cells retain their tags. The concrete version/
lock protocol must cover DMA invalidation and CPU readers, and DMA must have no
access to descriptor, allocation, ticket or protected-tag metadata. Cache visibility
and payload synchronization are modeled as obligations, not a proven cache model.

Validation: 88 positive witnesses, including quantified drainage, no-admission-
after-close, non-wrapped decrement and denied-commit effect checks. All 81 hostile
witnesses are explicitly disproved. Complete Phase 10.7 totals: 411 positive and
375 hostile checks. The concrete CPU/DMA close-drain-retire sequence is included.
These are compositional predicates and selected interleavings, not an exhaustive
SMP weak-memory, liveness, fairness or hardware DMA verification.

Next implementation gates must discharge protected tags, descriptor/ticket tables,
shared serialization and memory ordering against actual runtime operations. The
placement manager remains responsible for backing placement; this lifecycle gate
specifies when release/reuse may occur, not a replacement physical allocator.

## DN-54 — Protected pointer-kind state and CC2 application ABI v2

This checkpoint specifies a candidate ABI and proves predicate refinements; it
adds no compiler, ISA, Fabric or runtime implementation. Inspection confirms
q24/q25 in ankacc2_stage3.c currently use size/alignment 8 for pointers; q45/q46
perform word loads/stores. Existing AC2 passes up to four arguments in R0..R3
and returns in R0. The bootstrap/legacy ABI remains separate from application v2.

| Property | Proposed v2 rule |
| --- | --- |
| Pointer payload | 16 bytes: handle first, allocation-relative byte position second |
| Pointer alignment | 16 bytes |
| Protected kind | Trusted side state, outside application-visible payload |
| Register pairs | R0/R1, R2/R3, R4/R5, R6/R7, R8/R9, R10/R11 |
| Other registers | R12 scalar-only; R13 FP, R14 LR, R15 SP reserved |
| Arguments | R0..R3 lanes; scalar one lane; pointer starts even and consumes two |
| Return | Pointer R0/R1; scalar R0 with R0/R1 kind cleared |
| Expression temporary | Pointer R4/R5 |
| Call preservation | R0..R12 caller-clobbered; typed spills preserve live pointers |
| Frame and spill | Base/extent aligned 16; complete aligned 16-byte pointer cells |
| Null | Untagged zero/zero; transportable but not dereferenceable |

The initial subset has no stack arguments. Two pointers fit R0/R1 and R2/R3.
An int then pointer occupies R0 and R2/R3, leaving R1 untyped; a following int
is rejected. Frame offsets in the theory are positive offsets from frame base;
compiler translation to its FP-relative negative slots must be checked. Scalar
char/int sizes remain 1/8. Expanded argument windows, aggregates and pointer-to-
pointer type layout require additional profile work.

CPU pointer-kind side state belongs to register pairs. Generic integer MOV,
arithmetic and ordinary loads cannot copy or mint kind. Writing either half
clears its tag; unrelated pairs retain theirs. The semantic allowlist for creation
is trusted descriptor issuance, validated typed copy/load, and checked derivation.
These are operation classes, not assigned instruction opcodes. Applications have
no set-tag operation. The gate explicitly separates canonical untagged null from
valid tagged pointers.

Memory side state is keyed by Fabric object identity, object generation and
aligned object-relative cell offset, never by virtual address. All aliases share
the same protected tag entry. Application and DMA access must exclude metadata.
An admitted raw CPU/DMA write clears kind on EVERY overlapping pointer cell before
payload mutation; unrelated cells survive. Rejected writes preserve tags and data.
Invalidation and admitted writes must use the serialized publication/commit
protocol; DMA invalidation precedes device access. A versioned snapshot does not
permit data races in host Rust/C: concrete storage must use locks or supported
atomic accesses.

Typed storage checks validated source or null, complete aligned cell, exact tag
key, Fabric permission, trusted typed operation and coherent ordered transport.
Pointer argument lowering combines register-lane assignment with actual ordered
payload/tag transport. Quantified implications prove these typed spill/argument
predicates imply repr107_transport for tagged nonnull pointers. Authentication,
metadata isolation and source validation remain implementation obligations, not
properties inferred from application-supplied flags.

Calls and linking require explicit v2 artifact ABI metadata, size/alignment 16,
verified canonical ordered signatures and current code authority. Mixed v1/v2,
unverified metadata, mismatched signatures and implicit domain transitions are
rejected. Signature identity is a verified canonical record, not an unchecked hash.
Call entry preserves kind only on verified pointer-argument pairs, clearing all
scratch/unused tags. Scalar results clear pair kind; pointer/null results validate
the pair. Syscalls/raw bootstrap interfaces need explicit verified bridges; copying
two integers cannot bridge authority or provenance.

Context switching preserves payload and kind in trusted kernel images bound to
the same thread/domain. User frames cannot restore protected kind. Subsequent
access still rechecks descriptor/allocation lifetime. Concrete trap/context code
must preserve architectural FP/SP/LR and restore tags coherently without leaking
them to another thread.

Validation: 91 new positive witnesses pass; all 79 hostile assertions are explicitly
disproved. Full Phase 10.7 totals: 502 positive and 454 hostile. Quantified gates
cover argument/spill representation refinement, lane bounds, ordinary-operation
noncreation and overlapping-write invalidation. These are compositional contract
proofs, not an end-to-end compiler or hardware memory-safety theorem.

Before implementation, refine trusted operation classes into exact emulator/ISA
transitions and artifact ABI fields, including tag isolation and admission/commit
ordering. Preserve the self-hosting fixed-point bootstrap through the explicitly
separate legacy compiler profile. The two-word representation and this restricted
ABI remain a candidate whose costs must be validated during implementation.

## DN-55 — Core/Fabric pointer machine-transition refinement

The new `anka107_pointer_machine.kleis` specifies deterministic pointwise payload
and tag next-state functions and guarded admission/commit predicates. No Rust,
ISA descriptor, assembler or opcode changes are made. Semantic operation names
below are specification names; opcode assignments remain an implementation choice.

| Operation | Proposed transition |
| --- | --- |
| Trusted issue | Published current domain-bound descriptor, valid view/position and valid destination pair; protected kind supplied only by trusted issuer |
| PMOV | Capture both source words and kind from pre-state; validate pairs and exact transport; update destination pair and kind together |
| PADD | Retain handle/kind; validate descriptor, domain and exact checked element scaling; capture result before in-place destination mutation |
| PLOAD | One coherent committed 16-byte object-cell snapshot of payload and protected kind; validate cell identity/generation, source and destination before pair update |
| PSTORE | One exact contiguous 16-byte typed request; little-endian handle bytes 0..7 followed by position bytes 8..15; commit bytes and kind together |
| PREAD/PWRITE | Descriptor-based application data access through existing exact-width allocation/Fabric gates; never a raw numeric-address bypass |
| Ordinary register write | Commit scalar value and clear kind of any pair containing the destination register |
| Raw Store/StoreByte/Atomic/DMA write | After successful precommit, invalidate every overlapping pointer cell and mutate payload under the same serialization |
| Trap entry | Capture protected user image first; handler-visible pair kind cleared |
| Protected resume | Validate saved thread/domain, coherent protected image and current return frame, then restore payload/kind together |

Inspection of Core::step confirms ALU, MOV, MOVI and scalar load paths currently
write core.r directly. They require a common successful-register-write barrier.
CMP is flags-only and must not invalidate pair kind. OS syscall/event completion
paths also write core.r directly and require that same barrier; merely modifying
instruction dispatch would leave a bypass. Scalar/atomic results must clear kind.

Fabric::phase_commit currently invokes validate_precommit before changing bytes.
The existing checks include current generation, checked physical range and exact
payload length. Pointer-state changes must join this commit boundary, after all
checks pass. Neither Prepared nor authorization is enough to expose operand
effects. Guarded functions compute Committed/Faulted from precommit evidence;
stage-only pointwise functions are private effect helpers, not an application API.
On failure, payload bytes, register operands and protected tags remain unchanged.
Fault/control records may change. Leases retain backing but never override Fabric
revocation. Terminal faults still consume their operation ticket exactly once.

Typed pointer READ/WRITE requires a new trusted request classification, coherent
payload/kind capture and an exact single-object 16-byte span. Two independent
word transactions are prohibited as a substitute. The current Width/AccessKind
and CPU decoder need corresponding implementation refinement; this theory does
not assert current execute_read/write already provides typed pointer operations.
A write-only pointer cell store must not add an enclosing payload read requirement.
Protected metadata access is internal validation, not guest operand READ authority.

The payload helpers explicitly model handle-first little-endian storage. Successful
stores update only the target 16 bytes and its tag; neighboring bytes/cells survive.
Raw writes use the existing overlap contract to clear all affected cells. Pointer
cell keys remain Fabric object/generation/offset, independent of virtual aliases.
All raw physical mutation helpers must be audited: bootstrap-only write_physical
cannot be exposed as an application/DMA bypass of tag invalidation.

ABI v2 application operand accesses cannot use legacy numeric-address Load/Store
paths, even if a numeric address happens to map to authorized memory. PREAD/PWRITE
must apply descriptor/allocation/access checks before materializing the exact
Fabric request. Compiler-generated frame accesses need validated scoped-cell
operations, not a blanket SP/FP bypass. Kernel/bootstrap accesses remain distinct
and still pass Fabric checks. Arithmetic itself preserves original provenance;
it never establishes dereferenceability or revives a released allocation.

Context effects are admitted only from a coherent kernel-protected image bound
to the returning thread/domain and a current event frame. This supplements the
existing event_return path, which restores privilege/interrupt state and return PC.
User-writable frames cannot restore tags. Saving/restoring payload, tags, control
state and frame ownership must be atomic against scheduling and trap nesting;
this gate models those bindings as explicit obligations rather than proving the
current scheduler implements them. Restored stale descriptors remain unusable at
subsequent access. Architectural FP/SP/LR and existing interrupt semantics remain
obligations of the complete concrete context transition.

Validation: 84 new positive witnesses pass; all 76 hostile witnesses are explicitly
disproved. Full Phase 10.7 totals: 586 positive and 530 hostile checks. Quantified
properties include rejected pair/store no-ops, revoked precommit preserving tags
and bytes, self-copy source capture, scalar-operation noncreation, wrong-thread
restore rejection and pair transport refinement to repr107_transport.

These are machine-effect predicate refinements under trusted admission evidence,
not a full inductive whole-machine, weak-memory or verified Rust/compiler proof.
Registry authentication, exact physical mapping, lease accounting, source snapshot
serialization and metadata isolation must be implemented and tested. The next
implementation slice should establish protected pair/cell side state and common
raw-write barriers, then typed pair operations and context integration. CC2 ABI v2
lowering follows only once those machine operations enforce the specified effects.

## Phase 10.7 scoped fixed-buffer runtime foundation

`src/anka64/scoped_pointers.rs` implements a bounded trusted registration table
for already allocated fixed buffers. Registration is restricted to the current
LIFO scope. An opaque Rust pointer carries slot, allocation generation, and byte
position; the table supplies immutable bounds, owner domain, and write permission.
Checked displacement permits one-past transport, while every nonempty access must
fit the exact registered span. Scope exit invalidates its allocations. Reuse
increments the generation; a slot at the maximum generation is permanently
retired. Scope identities also fail closed rather than wrap. Capacity exhaustion
is explicit and does not require guest malloc.

This realizes a sequential subset of the validated pointer metadata and machine
contracts. Three focused tests cover traversal, boundary rejection, stale pointers
at reused addresses, nested lifetimes, domain and permission checks, arithmetic
overflow, bounded capacity, and exhausted generations. The library test target
compiled successfully and those tests passed single threaded (1004 existing tests
filtered out). The full regression suite was not run for this slice.

Integration boundary: this table does not allocate buffers, prove their ownership,
perform a Fabric transaction, implement protected machine kind tags, or encode the
CC2 two-word pointer ABI. Only trusted runtime code may register buffers after
checking their backing allocation and authority. Returned addresses must still go
through Fabric authorization. Concurrent CPU/DMA accesses require the previously
specified admission/closing/lease protocol before scope exit can retire storage;
this sequential table must not be used as a concurrent lifetime manager.

The concrete end-to-end milestone remains a CC2-rebuilt fixed-local-byte-array
program with traversal, pointer argument/return transport, typed spill/reload,
out-of-bounds rejection, and escaped-local-pointer rejection. Next implement the
protected register and memory kind state and coherent pointer machine operations,
then bind scope registration/exit and CC2 lowering to those operations. Guest
malloc remains deferred.


## DN-56 — Protected Core/Fabric pointer transport foundation

This slice implements the protected pair/cell state described by DN-54/DN-55 as
crate-private trusted runtime operations. The existing pointer representation,
kind ABI and machine-transition gates cover its payload order, pair restrictions,
raw-write effects, bounds and identity checks; all existing gates were rerun before
integration and passed (586 positive, 530 explicitly disproved hostile witnesses).
No opcodes, new C syntax, executable artifact format, or guest ABI are introduced.

Core has six protected pair entries for R0/R1 through R10/R11. Typed move captures
the source before replacing both destination words. Checked byte displacement
preserves the handle. Ordinary writes to either half clear the pair kind, even if
the integer value is unchanged. Core instructions and all production OS register
assignments now use a common write barrier; CMP performs no destination write.
Host register-array access remains available for existing trusted bootstrap/tests;
it is not a guest interface and must not be used to mutate live protected pairs.

The scoped descriptor payload is `(epoch32 << 32 | slot32, position64)`, with a
one-based nonzero slot. The scoped table conservatively retires a descriptor slot
at epoch32 exhaustion, rather than wrapping. Registration checks current Fabric
read authority (and write authority for writable buffers), physical backing, and a
single unambiguous mapping. Issued pointers also bind the Fabric object identity,
its generation, and object-relative base. Revocation followed by regrant cannot
revive an old pointer; virtual mapping changes cannot redirect its accesses.
Registration still requires the trusted caller to establish allocation ownership
and scope: permission to access a larger object is not evidence of a local lifetime.

Fabric pointer cells use `(ObjectId, Generation, aligned object offset)` keys.
Typed spill/reload commits or observes one exact 16-byte span, little-endian handle
first and position second. A serialized exclusive Fabric borrow covers payload and
protected kind together. Unchanged raw writes still clear kind; canonical all-zero
null remains untagged and transportable, but cannot be dereferenced. Untagged
nonzero integer payloads cannot acquire pointer kind through a typed reload.

CPU, DMA span, atomic exchange, loader initialization, zero-fill and trusted
physical-write paths clear every overlapping pointer cell at successful mutation.
Validation failure preserves bytes and kind. Virtual aliases share the cell key;
ambiguous mappings and arithmetic overflow reject before destination mutation.
Object placement changes discard the object's stored cell kinds rather than
reattaching old kinds to unrelated backing bytes. Bounds/rights/lifetime and
Fabric authorization are independent checks at actual dereference.

Validation: 50 Core tests, 48 Fabric tests, 3 scoped-pointer tests and 3 selected
OS syscall regression tests passed. Eight new Core tests exercise typed transport,
byte traversal, spills/reloads, escaped scope rejection, null, denied issuance,
encoded CMP/MOV, raw register forgery attempts, aliases, failed raw writes,
cross-cell DMA spans, atomic/bootstrap/loader invalidation, ambiguous mappings,
and stale backing generations. Test discovery now contains 1015 library tests.
The compiler-backed `p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address`
run was terminated by SIGKILL in this environment; it did not report an assertion
failure before termination. The complete regression suite is not verified here.
The 74 existing library-test warnings remain unchanged.

The protected-pointer application milestone remains incomplete. These operations
are not yet architectural instructions and CC2 still emits its existing pointer
ABI. In particular, do not enable protected application execution until complete
protected event-context save/restore is integrated: current event handling restores
control metadata, not a protected payload/tag image. Instruction encoding and
trusted local-frame registration/retirement need their concrete Kleis refinements,
then Core dispatch/assembler/decoder integration and CC2 argument/return/spill
lowering. The final witness must be produced by the exact self-hosted CC2 lineage,
not by a host emitter or a manually supplied protected token.

The scoped table and registration stack are a sequential foundation, not a
multithreaded allocation manager. Per-context scope ownership and the formal
closing/admission/lease protocol are required before admitting concurrent CPU/DMA
operations against scoped storage. No guest malloc or placement arithmetic is
added by this slice.

Focused local verification:

```sh
python3 scripts/check-anka107-gates.py --kleis /path/to/kleis
cargo test --lib anka64::core::tests -- --test-threads=1
cargo test --lib anka64::fabric::tests -- --test-threads=1
cargo test --lib scoped_pointers -- --test-threads=1
cargo test --lib anka64::os::tests::p92a_syscall -- --test-threads=1
```

## DN-57 — Protected event-context save/restore

Baseline supplied by the local full regression run: 1015 tests passed after the
protected transport foundation. This slice implements complete event register
images for the protected profile while preserving the existing legacy profile's
control-only/register-passthrough behavior. Guest pointer opcodes and CC2 ABI v2
are still not enabled.

Formal work preceded implementation: `anka107_pointer_events.kleis` refines the
DN-55 context gate with owner/domain, depth/header, profile consistency, explicit
scalar result lanes, and pointwise rejected-transition no-ops. All 30 positive
witnesses passed and all 30 hostile witnesses were explicitly disproved. The
Phase 10.7 runner now includes these files; total checks are 616 positive and
560 hostile. Quantified properties cover rejected payload/tag preservation and
complete asynchronous tag restoration. As with the earlier machine gates, these
are conditional transition refinements, not an inductive proof of Rust execution.
The implementation must supply the trusted image and admission facts.

A private saved-event stack accompanies the observable control-header stack.
Each entry binds the exact header to a trusted execution-context identity and
protection domain. Fresh context identities use an atomic checked counter with
no wrap; identity is independent of the CPU bus-master agent, so moving a complete
context to another physical CPU does not invalidate its saved frames. Cloning a
whole Core preserves context identity and represents a trusted copy/checkpoint of
that same context; it is not an independent-thread/fork constructor. New contexts
must be constructed through `Anka64Core::new`.

Protected entry captures all sixteen register words, six protected pair kinds,
flags, halted state and the protected return-authority stack. Handler entry clears
pair kinds and isolates the handler's return-authority stack. Words remain as
untagged inputs so the existing syscall argument ABI still works. Nested events
capture the interrupted supervisor context separately, restoring that handler
before the outer event restores the user. Pending IRQ bits and arbitration state
are external event state and are intentionally not rolled back.

Event return peeks and validates context identity, domain, matching public/private
depths, exact control header and saved profile before consuming either entry.
Success restores PC, privilege and interrupt enable state in the common primitive;
protected mode also restores the complete private image. Wrong-context, wrong-domain,
tampered, missing-image and replayed public-header returns are rejected without
consuming frames or changing the current operand image. Integer memory or a public
control header alone cannot manufacture a saved protected image. Existing trusted
synthetic I/O fixtures now use the common entry primitive rather than pushing bare
headers.

Syscall results are an explicit exception to complete register restoration. Kernel
result writers call `write_syscall_result`, which records scalar outputs in R0..R12
for the matching protected syscall frame. Handler instruction scratch writes are
not exported. Return overlays those recorded values onto the saved words; either
half being written clears the corresponding pointer kind, even when the scalar
bits are unchanged. Reserved FP/LR/SP lanes cannot be exported through the result
mask. Asynchronous event frames ignore result recording. Typed pointer returns from
syscalls are not introduced by this contract.

Mode selection is trusted and monotonic. Successful typed pointer installation
selects protected context handling, or the future loader can select it explicitly.
An outstanding legacy frame cannot be upgraded into a protected image: registration
rejects such an upgrade before issuing a descriptor. Existing guest compilers and
applications remain in the legacy profile and retain their established behavior.

Encoded ERET, ordinary host syscall return and blocked I/O completion use the same
checked return primitive. Failed ERET produces ControlFlowViolation without popping;
failed host-mediated return marks the process as ProtectionFault rather than
panicking or resuming an invalid context. Restoring a stale pointer's kind does not
revive its allocation: descriptor, domain, backing generation, bounds and Fabric
permission checks still occur at subsequent use.

Validation: all 58 Core tests and 280 OS tests passed single threaded, including
10 new event/context tests. Tests cover complete payload/kind/flags/return-stack
restoration, handler authority isolation, nested events, explicit scalar output
patches, unchanged-bit invalidation, scratch/reserved-lane exclusion, stale
allocations, wrong context/domain, CPU migration, tampering/replay, profile upgrade
rejection before descriptor issuance, actual TRAP/ERET execution, blocked block-I/O
completion, and process fault on a fabricated header. Both library and binary test
targets compile with `cargo test --no-run`. The library test warning count remains
74. The library now has 1025 tests; its complete regression suite has not been run
for this slice.

Focused verification:

```sh
python3 scripts/check-anka107-gates.py --kleis /path/to/kleis
cargo test --lib anka64::core::tests -- --test-threads=1
cargo test --lib anka64::os::tests -- --test-threads=1
```

Next: concrete instruction encoding and trusted local-frame registration/retirement
contracts, then decoder/assembler/Core dispatch and CC2 protected ABI lowering.
The final milestone still requires a program rebuilt by the exact self-hosted CC2
lineage, demonstrating local-array traversal, calls, typed spills, bounds rejection
and escaped-local rejection. Context save/restore does not itself close that witness,
add malloc, or implement concurrent scoped allocation/lease retirement.

## DN-58 — Concrete protected pointer encodings and local-frame refinement

This checkpoint reserves the following ABI v2 instruction words. It does not yet
add them to `desc::INSNS`, change execution, or lower CC2 source. Rust's machine
description remains the executable ISA source of truth; the next implementation
must make decoder, assembler, disassembler, Core and generated ISA theory agree.
The user's preceding complete regression run passed all 1025 tests single threaded.

The existing 32-bit layouts are retained: opcode in bits 31..26, rd in 25..22,
rs1 in 21..18, rs2 in 17..14 and function in 13..0 for R format; I format instead
has a signed immediate in 17..0; S format has a payload in 25..0. Pair operands
name their first register, one of R0/R2/R4/R6/R8/R10. Scalar operands are R0..R12.
All these instructions preserve arithmetic flags. Instruction fetch remains the
normal code-authorized fetch, distinct from the data transactions below.

| Opcode | Instruction and operands | Format and canonical encoding | Effect |
| --- | --- | --- | --- |
| 0x26 | `pmov pair_dst, pair_src` | R; rs2=0, function=0 | Copy both captured words and protected kind |
| 0x27 | `padd pair_dst, pair_src, scalar_delta` | R; function=0 | Checked signed 64-bit **byte** displacement; preserve allocation identity/view/rights |
| 0x28 | `pload pair_dst, [pair_address + disp]` | I; signed imm18 | One typed 16-byte read and kind transport |
| 0x29 | `pstore pair_src, [pair_address + disp]` | I; source in rd, address in rs1 | One typed 16-byte write and kind transport |
| 0x2a | `pread scalar_dst, [pair_address], width` | R; rs2=0; function=0/1/2/3 for 1/2/4/8 bytes | Exact-width read, zero extend, ordinary destination write clears any overlapping pair kind |
| 0x2b | `pwrite scalar_src, [pair_address], width` | R; source in rd; rs2=0; same width function | Exact-width write of low bits; invalidate all overlapping memory kinds |
| 0x2c | `pframe manifest_index` | S; unsigned index26 | Trusted reservation and atomic issuance of a manifest's local descriptors |
| 0x2d | `plocal pair_dst, local_index` | I; rs1=0; unsigned index17, bit17=0 | Lookup a preissued descriptor at position zero in the current active scope |
| 0x2e | `punframe` | S; payload=0 | Retire the exact current scope before releasing its storage |

0x2f is unassigned. No instruction accepts a raw integer base for issuance or typed
storage. Assembly validates field ranges **before** encoding, including signed
imm18 [-131072,131071]; masking an overflowing register/immediate is not admission.
Unused fields and invalid width/pair encodings fault without operand effects.
Reservations become executable only in the authenticated protected application
profile; a valid word by itself is neither a pointer kind nor allocation authority.

PMOV captures before replacing the destination, including self/overlapping scalar
sources of PADD. PADD treats its scalar delta as two's-complement signed bytes and
checks overflow and view bounds; one-past is representable but cannot authorize a
nonempty access. Null can be transported through PMOV/PLOAD/PSTORE, but is not a
memory address or arithmetic source. PLOAD/PSTORE first derive the address with
checked signed displacement and validate the **whole** 16-byte span against its
allocation/view/rights, current domain, backing generation and Fabric permission.
The storage cell must also be 16-byte aligned in the backing object. Payload order
is little-endian handle then position. They use the existing serialized typed
transport rules, not two independent eight-byte transactions. A loaded non-null
payload without a matching protected kind is rejected. All failed admissions
preserve register operands, memory bytes and kinds; instruction fault reporting
and PC handling remain separate control effects.

### Trusted manifest and frame state

An ABI v2 application artifact supplies an immutable frame-manifest table, validated
at admission and bound to its published artifact identity/generation and code.
Each record has: index (<2^26), authorized entry code offset, scope identity/parent,
function/call association, positive frame byte size (multiple of 16), authorized
exit sites/control transitions, and ordered local storage records. Local records
have index (<2^17), relative byte offset, positive length, alignment (1/2/4/8/16),
read/write rights, and storage class (application object, scalar compiler slot or
typed pointer slot). Typed slots have size/alignment 16. Records are disjoint,
fit the frame without overflow, and cannot name control metadata, caller storage,
padding or another allocation. Union/interior views must be explicit same-allocation
views in a later extension; overlapping independent manifest allocations are
rejected here. Dynamic-sized locals, arbitrary jumps across scope boundaries,
setjmp/longjmp and unvalidated indirect/tail transitions are outside this first
compiler subset and must be rejected, not assigned guessed lifetimes.

The loader must validate artifact provenance, manifest structure, entry/exit PCs,
call ancestry and allowed control-flow transitions. A seal alone does not prove a
manifest is safe. An application cannot choose a larger ambient stack range,
replace a manifest with writable bytes, or mint a descriptor by presenting FP/SP.
The stack region/backing comes from the existing process virtual-layout and physical
placement managers. This design adds no independent hard-coded placement scheme.

Each execution context owns a **private** stack cursor, stack region, active scope
stack and activation identities. A frame record binds context identity, domain,
artifact generation, protected call activation/scope ancestry, manifest, backing
object/generation, reserved interval, parent cursor/FP and preissued descriptors.
Activation identities do not wrap. Separate threads have separate stacks; the
current single global `ScopedPointers` LIFO stack is not sufficient for this design.
Sharing a Fabric must not force unrelated threads to retire in global LIFO order.

PFRAME uses the private cursor, never integer FP/SP, to reserve [cursor-size,cursor).
Admission checks stack limits, 16-byte alignment, exact authenticated entry,
correct ancestry, no duplicate activation, manifest validity, current Fabric
backing/rights, and capacity for **all** records. Issue all descriptors and publish
the frame atomically, or publish none and preserve cursor, scopes and operands.
Their bounds are individual local intervals, not the ambient stack or whole frame.
PFRAME publishes SP/FP=frame base while saving previous values privately. Scalar
writes to FP/SP cannot change allocation ownership or the private cursor.

PLOCAL is a lookup into that frame, including scalar and compiler spill slots; it
cannot request a new base, length or rights. Repeated lookup preserves allocation
identity and generation. ABI v2 scalar slot accesses also use protected addressing
and PREAD/PWRITE; legacy raw LD/ST/LDB/STB/XCHG addressing cannot bypass the contract.
Pointer arguments may retain caller allocations while the callee owns its own frame.
CALL suspends caller scope ownership rather than retiring it. Nested lexical scopes
use separate manifested activations and retire in context-local order. The initial
compiler may restrict itself to function-scoped fixed storage until nested scope
transitions are implemented and validated.

### Retirement, return and events

PUNFRAME requires the current context/domain, exact top activation and protected
exit authority. Close new admissions first; wait for previously admitted CPU/DMA
work to reach terminal drain; invalidate every descriptor owned by that activation
and associated protected storage kinds; then pop the frame and restore the private
parent cursor and FP/SP. These effects form one serialized retirement transition.
Failure changes none of them. Parent allocations survive a child's retirement.
Copied pointer words/kinds in registers or caller cells cannot revive a retired
allocation. Storage reuse requires retirement, drain and a fresh generation;
epoch exhaustion retires the descriptor slot permanently rather than wrapping.

RET and tail exits require no outstanding scope for the returning call activation
and genuine protected return authority. Every early return closes its scopes first;
branching around PUNFRAME does not authorize RET. Process teardown/trusted unwind
must retire scopes in order and drain before releasing backing. Normal guest
retirement cannot retire another context's or an ancestor's scope. Until leases
are implemented, this first sequential slice must reject DMA exports of local
storage rather than pretending there is nothing to drain.

TRAP/IRQ entry **suspends**, rather than retires, the interrupted frame stack and
private cursor. The protected event image must save those fields with its existing
words/kinds/control image; handlers use an isolated trusted scope stack. ERET
restores the matching interrupted stack only after handler-owned scopes have closed.
An event header or scalar register cannot authorize retirement or frame restoration.
This extends DN-57's implementation obligations; it is not already supplied by the
current event image. Physical CPU migration retains context identity and its stack.

### Gates and scope of proof

`anka107_pointer_encoding.kleis` specifies canonical fields, signed displacement
representability, profile/semantic admission, and quantified R/I field round trips.
`anka107_pointer_frames.kleis` specifies context-bound admission, stack subtraction,
local interval/alignment and disjointness, preissued lookup, ordered/drained exit,
allocation invalidation and storage reuse. Hostile files assert their negations and
must all be explicitly disproved. Quantified witnesses cover stack containment,
nonwrapping local ends, rejected retirement preservation and parent survival.

The manifest, control, capacity, backing, generation and drain flags are explicit
trusted implementation obligations. These are conditional predicate/transition
refinements, not an inductive whole-machine proof, a verified loader/CC2 proof, or
an implementation of concurrent allocation retirement. The next slice must provide
those obligations in runtime state and validated artifact metadata before exposing
PFRAME/PLOCAL. The final compiler-backed local-array/call/spill/escape witness and
malloc remain open.

Run all formal gates with:

```sh
python3 scripts/check-anka107-gates.py --kleis /path/to/kleis
```

Validation: the full Phase 10.7 runner passed **721 positive witnesses and 665
hostile witnesses explicitly disproved**. This adds 49 encoding and 56 frame
witnesses, with 105 corresponding hostile checks. No Rust/compiler code changed;
the previously reported 1025-test runtime result remains the baseline, not a new
runtime run for this formal-only checkpoint.

## DN-59 — Concrete protected local application ABI (Phase 10.7)

**Status: COMPLETE, merged to `main`, 2026-10-10.** Phase 10.7 closes the verified
CC2 application rebuild and protected local-pointer milestone: byte/word accesses,
checked scaled arithmetic, typed pointer arguments/results and spills, local-frame
registration/retirement, and protected event-context save/restore. The exact
CC2_0 → CC2_1 → CC2_2 fixed point and compiler-backed application/hostile witnesses
pass in the final full suite.

This scope supersedes the earlier roadmap assignment of compiler/toolchain
modularization to 10.7. Phase 10.8 starts with typed syscall I/O, then broader
modular toolchain/userspace rebuilds. Those tasks, malloc and the other deferred
features below do not reopen 10.7. Phase 10.9 retains the final supply-chain audit
and exact rebuilt CPU-to-HTTP alive-response acceptance gate.

The implementation binds DN-58's nine canonical pointer instructions to a validated,
sealed linked image. CC2 has an explicit protected-application profile; its own
bootstrap remains the established compiler profile. This distinction is trusted
invocation policy, not a source filename or integer-cast escape hatch.

ABI v2 uses even register pairs for opaque pointer words, with protected register
kinds; scalar arguments consume one of R0–R3 and pointer arguments consume an
aligned pair. Pointer results use R0/R1. Typed spills occupy aligned 16-byte local
slots and use PLOAD/PSTORE. Scalar and byte accesses use PREAD/PWRITE with exact
width. C element offsets lower to one checked PADD per element byte, avoiding a wrapping
scalar multiplication before bounds checking. Subtraction rejects signed-minimum
negation. Each checked step retains allocation identity and bounds.
Adding two pointers, constructing pointers from arbitrary integers, and unsupported mixed interfaces
are rejected. Fixed byte/word arrays, address-taking, pointer parameters and returns,
and indirect scalar reads/writes are the initial supported application subset.
Nested block declarations are rejected until lexical activation lowering exists.

The linked literal section contains an exactly consumed little-endian v2 manifest:
magic `0x50313037`, version, exact code length, function count, then each function's
entry/end/frame size/local count and each local's offset/length/alignment/flags.
Flags 1 and 3 identify writable scalar/buffer and typed pointer storage. Exit sites
are derived from canonical PUNFRAME instructions. Admission validates complete code,
function coverage, canonical fields, branch/call destinations, distinct local bounds,
and exit structure before binding the bytes to a current sealed Fabric object.

PFRAME allocates from a private context cursor and atomically registers every local;
PLOCAL only retrieves those registrations. Allocation bounds retain declared array
length even when storage is padded. PUNFRAME invalidates owned descriptors and kinds
before restoring parent cursor/FP/SP and the protected saved LR. Caller allocations
survive child retirement. Event images suspend and restore frame ownership. Process
teardown also retires suspended frames. Scope LIFO order is per context, allowing
independent contexts to interleave without sharing a global stack.

This first slice is sequential: protected stacks reject DMA export and other-domain
sharing. Protected applications can use scalar SYS_EXIT only; numeric-address
syscalls are rejected until a typed syscall ABI is implemented. Malloc, DMA leases,
shared allocation retirement, aggregates and nested lexical lifetimes remain future
work. A pointer is still an opaque allocation identity and position with protected
kind, bounds, rights, generation and backing state; it is never an ordinary integer.

The larger compiler source uses the existing virtual layout builder and placement
manager to reserve a disjoint source span. Frozen bootstrap entry points retain
legacy geometry. CPU-only compiler/preprocessor/linker harnesses discard terminal
transaction diagnostics between bounded execution quanta; transaction IDs remain
monotonic and live transactions are retained. This is not device retirement or a
change to application/kernel transaction semantics.

The artifact gate adds 23 positive and 23 hostile witnesses, including the scaling
no-wrap invariant and signed-minimum negation boundary. All Phase 10.7 formal
gates pass: **744 positive, 688 hostile explicitly disproved**. These remain
conditional refinements, not an inductive whole-machine or verified-compiler proof.

**Final validation checkpoint, 2026-10-10:** all **1037 Rust/runtime tests passed**,
single threaded, in 977.42 seconds. This supersedes the earlier container-limited
validation checkpoint and validates the final checked-scaling compiler changes,
fixed-point lineage and protected application witnesses. The full Phase 10.7
Kleis runner passes **744 positive witnesses and 688 hostile assertions explicitly
disproved**; Unknown results are never accepted.

Commands for reproducing the checkpoint:

```sh
cargo test --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address -- --test-threads=1 --nocapture
cargo test -- --test-threads=1
```
test result: ok. 1037 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 977.42s

## DN-60 — Typed syscall console-output contract (Phase 10.8)

**Status, 2026-10-15: synchronous protected console output COMPLETE and validated.**
Formal gates, exact CC2 fixed-point/application integration, and all **1043
Rust/runtime tests** pass. Phase 10.7 remains complete. This is the first bounded slice of 10.8,
not a claim that input, asynchronous I/O, or the userspace service rebuild is done.

### Contract and concrete trap ABI

`theories/anka108_typed_syscall_io.kleis` imports the 10.7 protected pointer and
event contracts without adding axioms. The first operation is synchronous console
byte output, reusing syscall number `SYS_WRITE = 1` under a **protected-mode trap
ABI**. The legacy address-based ABI remains a separate dispatch path; protected
validation failure must never fall back to it.

| Lane | Protected SYS_WRITE meaning |
| --- | --- |
| R0 | syscall number 1; scalar |
| R1 | reserved, exactly zero |
| R2/R3 | protected descriptor handle and allocation-relative byte position |
| R4 | byte count, 0 through 65536 inclusive; scalar |
| R5 | flags, exactly zero |
| Result R0 | complete byte count on success; `u64::MAX` on failure |

The R0/R1 and R4/R5 pairs must have scalar kind; R2/R3 must have protected pointer
kind. Syscall arguments and pointer tags are captured from the authenticated
**saved application event image**, not the handler's registers, whose pointer tags
are cleared on entry. `io108_request` composes the actual ABI, descriptor/allocation
range, event ownership/mode/depth, and serialized lease admission checks.

This trap ABI is not an extension of the four-lane CC2 C function-call ABI. A future
compiler intrinsic/wrapper taking `(char *buffer, int length)` can receive its
pointer in R0/R1 and length in R2, save length into scalar R4, PMOV the pointer to
R2/R3, then install scalar syscall number/reserved/flags. Implementation must preserve
live values using the existing typed spill discipline. The exact source-level
intrinsic name and lowering still require an implementation/refinement review;
ordinary raw `syscall(1, address, length, 0)` is not silently reinterpreted.

### Buffer authority and zero length

One current descriptor, one live allocation generation, and one current Fabric
READ grant must cover the entire requested interval. The local allocation owner
context and descriptor domain must match the caller. Descriptor rights and Fabric
rights must each include READ; WRITE alone never authorizes output. Permission
fragments and mappings cannot be stitched to fabricate a wider grant. Bounds are
checked by subtraction before any addition, so request and effective-address
arithmetic cannot wrap. Reads are exact bytes; byte alignment is sufficient.

Zero length deliberately differs from legacy SYS_WRITE: it still validates live
pointer provenance, owner, domain, view and READ rights. An authentic one-past
pointer with length zero is valid; null, forged, stale and revoked pointers are
not exceptions. A zero-length request performs no operand read.

The flat `cap_object` field identifies the allocation covered by one selected grant;
the runtime adapter must prove its correspondence to the actual Fabric object and
generation. `fabric_current`, `serialized`, ticket freshness/binding, and event
header integrity denote trusted implementation obligations, never guest flags.
A bound operation ticket includes invocation identity, allocation identity and
generation, descriptor/view, starting position, requested length and caller context.
A successful check cannot be reused for a different request.

### Lifecycle, output atomicity and return

Admission and CPU-lease acquisition linearize together. The lease prevents backing
retirement/reuse; it does not override permission revocation. Every byte read checks
the active bound ticket and current Fabric authority. Closing may drain an existing
operation, but bars new operations. Scope retirement waits for the lease to drain.

All bytes are staged privately. Only complete copying, current authority and a
serialized, capacity-checked sink append permit publication. Failure discards the
staging buffer and changes no output bytes or length. Success returns the entire
count: this first console contract has no short/partial successful writes. It is
output-atomic, **not a snapshot guarantee** for concurrently modified source bytes.
The final authorization and append must share the same serialization boundary.
`io108_publish` composes the copy/sink guard with current active/bound lease
admission; `io108_publish_flag` is the publication decision used by sink/result
effects. An old admission certificate alone cannot publish after lease release.

Both success and post-admission failure consume the lease ticket exactly once after
all reads cease. Pre-admission rejection acquires none. Return permits no retained
borrow, callback, DMA operation or active ticket. R0 is the sole scalar result lane;
10.7 event restoration preserves the source pointer pair and unrelated saved state,
while clearing pointer kind in the R0/R1 result pair. No pointer authority is
exported to the output sink. The application buffer is read, not modified.

Blocking/input syscalls, partial transfers, retained buffers, DMA and cross-domain
sharing are **not authorized by this checkpoint**. They need their own subsequent
contracts and hostile witnesses before implementation. The error-return policy
applies to well-formed owned traps; malformed/foreign protected event frames retain
the existing process-fault behavior rather than attempting an unsafe return.

### Proof scope, validation and next implementation gate

Positive examples include universal refinement of an admitted buffer to each
existing protected byte-access predicate, nonwrapping effective addresses and sink
sizes, failed-output noninterference, and prefix/zero-length preservation. Hostile
assertions cover raw/stale pointers, ownership/domain confusion, bounds and rights,
zero-length forgery, revocation, event tampering, lease misuse, partial publication
and retained authority. These are definition-level proofs and witnesses. They do
not yet verify a kernel copy loop, compiler lowering, actual table lookup or SMP
implementation. Boolean certificates in stage predicates must be derived from the
complete admission/current-authority checks; they are not proof substitutes.

Run the combined prerequisites and new gate using the existing Kleis installation:

```sh
python3 scripts/check-anka108-gates.py --kleis /Users/enginatik/.cargo/bin/kleis
```

Use `--only-108` for a focused rerun after the 10.7 prerequisites have passed. The
runner requires explicit Z3 disproof of every hostile assertion; Unknown, timeout,
missing examples and evaluation errors do not count as rejection.

**Validation:** the supplied Kleis executable and standard library pass all
**113 positive witnesses**, with **86/86 hostile assertions explicitly disproved
by Z3**. The unchanged 10.7 prerequisites also pass (744 positive, 688 hostile),
for a combined **857 positive / 774 explicitly disproved hostile** checkpoint.

The next implementation milestone is one rebuilt protected CC2 application emitting
an exact local byte buffer through this ABI, plus runtime rejection tests. Preserve
existing legacy output behavior and the 10.7 fixed-point/application regressions.
Full Rust tests remain a local MacBook checkpoint; no Rust or C code changed here.


### DN-60 implementation checkpoint — synchronous typed console output

The protected SYS_WRITE path now captures words and pointer kind from the intact,
context-owned private syscall image. Handler scratch cannot select a different
operation or substitute pointer payloads. Only EXIT and typed WRITE are admitted
for protected applications; a malformed saved frame faults before output.
Legacy SYS_WRITE retains its address-based ABI and historical return convention.
Protected WRITE returns the byte count or `u64::MAX` and restores the source pair.

`write_bytes(char *buffer, int length)` is a compiler intrinsic reserved in the
stage-3 lexer. It is admitted only in protected profile 2, requires `char *` and a
scalar length, uses typed spills while evaluating both expressions, and lowers to
the DN-60 R2/R3 + R4 trap ABI. It does not reinterpret ordinary `syscall` arguments.
The intrinsic has no implicit declaration, link dependency or host execution path.

`ScopedPointers::read_span` checks owner context, domain, live generation and the
whole interval, including zero length. Fabric checks one current READ grant and a
matching CPU/domain. Existing nonzero-width capability semantics are unchanged;
the new empty-range check applies only to protected console output. Every source
byte uses an exact Fabric byte-read transaction. The runtime stages the entire
range, rechecks authority before append, and reserves output storage without
publishing bytes on failure. It allocates no application memory.

**Serialized lease refinement:** a stack-local captured pointer is used only while
`&mut Kernel` exclusively owns Fabric through admission, copy and append. This
path never schedules another process, ticks a device, invokes a callback, returns
a borrowed buffer, or runs scope retirement. Thus no backing retirement/reuse or
revocation can interleave. These exclusive serialized operations implement the
first synchronous contract without adding an unused lease counter. Runtime
checks still revalidate identity/range/READ authority on each byte and before
publication. Introducing concurrent mutation, DMA, asynchronous output, callbacks
or a yield inside this path would invalidate this refinement and requires an
explicit lease implementation first. The more general concurrency theories are
not a claim that SMP has been implemented.

`userspace/bin/typed_output_probe.c` emits `[65, 0, 255, 66]`, checks the returned
count, verifies authenticated zero-length one-past output and rejection of an
out-of-bounds span, and confirms its source remains readable. The existing
`p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address` test now runs
this probe with its already-built exact CC2 lineage and checks the actual byte
output. It also rejects integer pointers, word pointers and pointer-valued lengths
at compilation. Sharing that lineage avoids a second full bootstrap in the suite.

**Checks run here:** Rust test build succeeded; six new `p108` runtime tests pass;
three legacy `p73h` output tests, ten `p107_event` tests and two `p107_encoded`
frame/transport tests pass. No formal files or imports changed since the already
passing 113-positive/86-hostile 10.8 gate.

**Final developer validation, 2026-10-15:** the exact CC2 integration test passed
locally in **209.51 seconds**. CC2_0 contained 146224 code bytes; CC2_1 and CC2_2
both contained **165256 code/backing bytes**, with entry **162568**. The fixed-point
comparison passed, and the rebuilt typed-output probe emitted the exact expected
bytes and passed its count, bounds, zero-length and source-preservation checks.
The compiler rejection and ControlFlowViolation diagnostics in this passing test
come from its deliberate hostile cases.

The full single-threaded Rust/runtime suite then passed locally:

```text
test result: ok. 1043 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 999.68s
```

This closes the synchronous typed console-output slice, not Phase 10.8 as a whole.
The previously validated formal checkpoint remains **113 positive / 86 hostile**
for 10.8, or **857 positive / 774 hostile** including 10.7 prerequisites; every
hostile assertion was explicitly disproved. Unchanged formal files were not rerun
for the implementation-only changes.

Developer commands (from repository root):

```sh
cargo test --lib p108 -- --test-threads=1
cargo test --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address -- --test-threads=1 --nocapture
cargo test -- --test-threads=1
```

No unchanged Kleis rerun is needed for this implementation-only patch. If the
10.8 contracts change, use `check-anka108-gates.py --only-108`; if a dependency,
Kleis executable or stdlib changes, expand to the affected/full formal gates.

## DN-61 — Synchronous process-owned input contract (Phase 10.8)

**Status, 2026-10-16: synchronous protected typed input COMPLETE and validated.**
Formal gates, exact CC2 fixed-point/input-echo integration, and all **1057
Rust/runtime tests** pass. The previous console-output milestone (DN-60) remains
complete. This input slice does not close Phase 10.8.

### Concrete requirement and authority

A rebuilt protected application must be able to receive a bounded sequence of
source/data bytes into a local `char` buffer and process or echo those bytes.
The initial source is an immutable, trusted-loader-provisioned input image owned
by one process incarnation. This earns an input facility without first adding
filesystems, global console routing, device waits, async leases or malloc.

The proposed compiler intrinsic is `read_bytes(char *destination, int capacity)`.
The proposed protected syscall number is **20** (`SYS_READ_BYTES`); the merged
runtime currently implements numbers 0 through 19. No legacy syscall is changed
or repurposed. Number 20 is reserved by this specification, not yet executable.

| Lane | Proposed protected input ABI |
| --- | --- |
| R0 | scalar syscall number 20 |
| R1 | reserved, exactly zero |
| R2/R3 | protected destination handle and byte position |
| R4 | scalar unsigned byte capacity, at most 65536 |
| R5 | flags, exactly zero |
| Result R0 | bytes copied, or `u64::MAX` on failure |

The R0/R1 and R4/R5 pair kinds must be scalar; R2/R3 must carry authentic protected
pointer kind. Arguments come from the owned private syscall event image. Only R0
is a scalar result; event restoration preserves the destination pair and unrelated
saved state. This trap layout is separate from the ordinary CC2 function-call ABI.
The intrinsic's type/argument evaluation and typed spill lowering must implement
this layout; integer addresses and pointer-valued counts remain invalid.

A stream binding holds image identity/generation, owner process slot/generation,
context, domain, cursor and exact immutable image length. Process generation zero
is valid, matching the existing process model. Stream identity and generation are
nonzero. The maximum initial image size is **1 MiB**, independent of the 64 KiB
per-call limit. The image is not guest-mapped writable storage and cannot alias a
guest-writeable source or destination. The caller supplies no source address,
stream number, process selector or capability that could redirect another stream.

Provisioning requires trusted loader authority, a drained inactive binding, and
an incremented nonwrapping stream generation. Guest read permission does not
confer provisioning, reset or replacement authority. A live binding cannot be
replaced in place. Detach/free requires all users drained and trusted owner
control. Process teardown removes its binding before slot reuse. A new process
incarnation cannot inherit an old binding merely by occupying the same slot;
child inheritance is not implicit. Source image owner/content/length remain fixed
within a live generation; the cursor changes only through accepted reads.

### Destination checks, short reads and EOF

Admission composes the ABI, owned event image, complete destination range, current
input binding and serialized lease acquisition in `in108_request`. One live
allocation/view in the caller's context/domain and one generation-current Fabric
**WRITE** grant must cover the **entire requested capacity**. READ permission
alone is insufficient. This is the direction reversal from console output.
Checked subtraction preserves bounds and prevents arithmetic wrap; capability
fragments cannot be stitched together.

For valid capacity `c`, cursor `p`, and source size `t`, the planned count is
`n = min(c, t-p)`. A positive request fills its capacity whenever enough source
bytes remain. A short successful read occurs only at the finite image tail;
zero means EOF or a zero-capacity request. There is no implicit NUL terminator,
line editing, encoding conversion or padding.

**EOF is not missing input.** An absent/detached binding returns the error sentinel.
A live empty image is valid and is already at EOF. Even at EOF or capacity zero,
source ownership and complete requested destination authority are validated. A
valid one-past destination with capacity zero is admitted; null, forged, stale,
READ-only and wrong-context pointers are not exceptions. An EOF call with a
nonzero out-of-bounds capacity fails even though its planned count is zero.

### Atomicity, pointer kind and lifetime

Preflight the original capacity, stage exactly `n` source bytes and revalidate the
source identity/generation/cursor and destination authority at final commit.
`in108_commit` also requires the active bound allocation lease and current Fabric
authority. The operation ticket binds the caller, destination pointer/range,
original capacity and selected source snapshot. An old admission result cannot
be replayed after cursor advancement, input replacement, revocation or retirement.

Destination publication, pointer-kind invalidation and cursor advancement form
one serialized transition. On success, write exactly `[position, position+n)` and
advance the cursor by exactly `n`. Bytes outside that interval—including the
unused capacity after a short read—are unchanged. Every overlapping protected
16-byte storage cell loses its tag through the ordinary raw-write barrier, even
when only one byte overlaps or the storage has a physical alias. Input bytes can
never mint pointer kind. The source image itself is never modified.

On failure, destination bytes, pointer-kind state and stream cursor are unchanged.
Repeated one-byte writes followed by an error are not an implementation of this
contract. A future runtime must preflight every fallible step and use one exact-
range atomic Fabric write, or prove an equivalent combined transaction. It must
not consume source bytes before a successful destination commit. Source cursor
serialization must prevent two reads from both consuming the same old snapshot.

EOF and zero-capacity success issue **no destination memory transaction**, alter
no tags and consume no source bytes. Both success and post-admission failure drain
all uses and release the borrow before return; pre-admission rejection acquires
none. Source detach/backing retirement cannot interleave with a live borrow.

The first runtime refinement should retain DN-60's exclusive synchronous Kernel/
Fabric execution boundary. This makes the source snapshot and backing stable
without implementing an unused asynchronous lease subsystem. Adding callbacks,
blocking, DMA or concurrent source mutation requires a separate refinement first.
The contract does not authorize arbitrary device input, sockets or file reads.

### Formal gates and next implementation witness

The new pair is:

- `theories/anka108_typed_input.kleis`
- `theories/anka108_typed_input_false_witnesses.kleis`

It imports the unchanged typed-output and protected pointer/event vocabulary,
adding **no axioms**. The supplied Kleis executable and standard library pass
**116 positive witnesses**, with **88/88 hostile assertions explicitly disproved
by Z3**. Universal properties cover bounded counts/cursors, each destination
WRITE-byte refinement, bounded source indexing, failure noninterference, short-read
tail preservation and inability of raw input to create pointer tags. Whole-request
witnesses cover binding ownership, process reincarnation, event integrity, range
admission and lease acquisition. Hostile cases also cover cursor races, stale
input generations, missing-stream/EOF confusion and live-source replacement.

These are specification-level refinements and witnesses, not a proof of an
implemented copy loop or a complete inductive machine theorem. Trusted lookup,
immutable-image exactness, current-generation certificates, atomic Fabric commit
and exclusive execution remain implementation obligations.

For this new contract, run only its affected gate pair:

```sh
python3 scripts/check-anka108-gates.py --kleis /Users/enginatik/.cargo/bin/kleis --only-input
```

`--only-108` runs both input and output pairs. The default still runs the full
10.7 prerequisites and both 10.8 pairs for an integration checkpoint. No unchanged
output/10.7 gates or Rust suite were rerun for this formal-only addition. If an
imported dependency, Kleis executable or stdlib changes, expand the selected gates.
Unknown, timeout and evaluation errors never count as hostile rejection.

The implementation witness is one rebuilt protected CC2 application supplied
an explicitly provisioned image containing ordinary bytes, embedded zero and 255.
It reads into local buffers, verifies full/short/EOF counts and untouched tail,
echoes via `write_bytes`, and exercises hostile destinations without consuming
input. Implementation also needs teardown/reuse, saved-event integrity and raw-
write pointer-tag invalidation tests, recorded in the implementation checkpoint below.


### DN-61 implementation checkpoint — private immutable input and CC2 echo probe

`SYS_READ_BYTES = 20` is now dispatched only for protected applications using the
owned saved-event image. `ScopedPointers::write_span`, Core range validation and
Fabric input admission require a writable allocation and one WRITE grant across
the entire original capacity, including EOF and zero capacity. Existing output
checks now share the same internal range-admission helper with READ direction.
Legacy syscall numbers and their calling conventions are unchanged.

Kernel input bindings are private and hold a copied immutable image, process key,
context, domain, nonzero stream id, nonwrapping generation and cursor. Trusted
provisioning rejects oversized images, stale process keys and live replacement.
Caller-owned source mutation after provisioning cannot change the image. Detach
and process termination/reclamation erase the binding; process-slot reuse carries
no implicit input. Exhausted generations never wrap.

The synchronous read holds exclusive Kernel/Fabric access and the same input
binding throughout validation, staging, final authorization, memory commit and
cursor update. It stages exactly the available bounded count and performs one
exact-span `Fabric::execute_write`, whose existing precommit path validates the
whole write and clears all overlapping physical pointer-cell tags before mutation.
After a successful write, cursor assignment is the only remaining source-state
operation and cannot fail. Rejection leaves cursor and destination unchanged.
EOF/zero capacity bypass the memory transaction entirely after all authentication
checks. No scheduler, device tick, callback or retained buffer can interleave.
This remains a serialized synchronous refinement, not an implemented SMP/async
lease protocol.

CC2 reserves `read_bytes` as a two-argument intrinsic in protected profile 2. It
requires `char *` and scalar capacity, preserves the destination with typed spills
while evaluating expressions, and emits the established R2/R3 + R4 ABI with scalar
R0=20, R1=R5=0. No host source address or stream selector is passed by application
code, and ordinary raw `syscall` arguments are not reinterpreted.

Development execution gains a separate `DeveloperInputAuthority` and
`RebuiltApplication::run_with_input`. Execution permission alone cannot provision
input. The bridge runs its sealed supervisor in single-instruction rounds until
ordinary SYS_SPAWN creates the exact registered artifact's child, binds the image
to that actual child before its first instruction, then resumes normal scheduling.
This uses the existing scheduler's fixed process-range iteration at round entry:
a new child cannot execute in its birth round. The bridge test exercises this
setup and distinct authority rejection; input is neither inherited by the parent
nor left for later process incarnations.

`userspace/bin/typed_input_probe.c` attempts an invalid read without consuming
input, checks a zero-capacity one-past read, then reads and echoes `[65, 0, 255]`
and the short tail `[66, 67]`. It checks exact counts, EOF and unchanged destination
tail bytes. The existing fixed-point application integration test supplies the
explicit input `[65, 0, 255, 66, 67]`, checks exit status zero and exact echoed
output, and verifies compiler rejection of integer/word pointers and pointer-valued
capacities. It reuses the same exact CC2 lineage already built for output and the
10.7 application witnesses, avoiding another expensive bootstrap in the suite.

**Validation run here:** Rust test build passed. All **14 new input tests** pass,
including the provisioning bridge, atomic Fabric failure, immutable source copy,
wrong owners/generations, stale stream prevention, empty-range checks and physical
pointer-tag invalidation. The complete focused `p108` selection passes **20 tests**
(new input plus existing output); three legacy output, ten protected-event, two
encoded-frame and six other development-runner tests also pass. The 116-positive/
88-hostile input theories are unchanged since the user's successful local gate;
no unchanged formal suite was rerun for this implementation patch.

**Final developer validation, 2026-10-16:** the exact self-hosted CC2 integration
passed locally in **216.39 seconds**. CC2_0 contained **148376 code/backing bytes**;
CC2_1 and CC2_2 both contained **168032 code/backing bytes**, with entry **165344**.
The fixed-point comparison and rebuilt input/echo witness passed, including exact
output `[65, 0, 255, 66, 67]`, short reads, EOF, unchanged destination tail and
nonconsuming rejected reads. Compiler rejection and ControlFlowViolation diagnostics
in that successful test are its deliberate hostile cases.

The full single-threaded Rust/runtime suite then passed:

```text
test result: ok. 1057 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1009.45s
```

This supersedes the pending-validation status for typed input and closes the
synchronous input slice. The 1043-test result in DN-60 remains its historical
output checkpoint. Input formal validation remains **116 positive / 88 explicitly
disproved hostile witnesses**; unchanged gates were not rerun for implementation-
only changes. Broader service/toolchain rebuild work and final CPU-to-HTTP closure
remain open.

```sh
cargo test --lib p108_input -- --test-threads=1
cargo test --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address -- --test-threads=1 --nocapture
cargo test -- --test-threads=1
```

No new Kleis run is required unless the contract, its imported theories, the Kleis
executable or standard library changes. Keep using `--only-input` for changes
confined to the input theory pair, and reserve full formal runs for affected
prerequisites or integration checkpoints.

## DN-62 — Bounded rebuild artifact channel and publication receipt (Phase 10.8)

**Status: first trusted in-memory implementation and acceptance complete; see
DN-64 for the CC2 witness and 1064-test full-suite checkpoint.** Typed input and
output remain complete at the DN-61 checkpoint of 1057 passing Rust tests. This
slice advances the compile-only path: an explicitly selected producer consumes
an exact immutable source image, emits a bounded AOM v1 object into private
staging, and publishes the complete object and its exact receipt together. It
does not close Phase 10.8 or the final CPU-to-HTTP rebuild milestone.

The contract is in `theories/anka108_rebuild_artifact.kleis`, with deliberately
false claims in `anka108_rebuild_artifact_false_witnesses.kleis`. It imports the
existing userspace rebuild and typed-input contracts, including their source,
compiler-lineage, pointer, event and transaction prerequisites. It adds no axioms.
It uses canonical BitVec8 certificates (only 1 means admitted); certificates and
session state are protected trusted state, never caller-supplied success flags.
The producer requirements of `rebuild107_producer_valid` are restated in this
representation; source/profile and host-boundary admission remain obligations
of the existing checks, not consequences of matching names.

The concrete first channel has these rules:

- One private session belongs to one process slot/generation, context and domain,
  with a fresh nonreused session identity. Reuse requires a new identity and a
  drained previous incarnation. No guest allocator or general filesystem is
  introduced.
- The compiler, effective source and immutable versioned profile are bound by
  exact publication identities and generations. Source admission includes the
  exact bundle, root, include/preprocessing lineage and effective bytes. The
  initial single-source case does not require inventing host preprocessing.
- A session reserves at most **1 MiB** of private output capacity. Nonempty
  appends are at most **64 KiB**, must start exactly at the current length and
  fit by subtraction without wrap. Zero appends are rejected without mutation;
  there is no seek, overwrite or sparse output. This is a channel bound, not an
  enlargement of the compiler's current code arena or an ISA change.
- Each append must authenticate the whole source range with current Fabric READ
  authority. Protected syscalls use the existing event and pointer descriptor;
  the DN-63 trusted compiler adapter uses its selected private arena and exact
  object/generation/range grant. This is a separate trusted interface, not a
  conversion of numeric addresses to application pointers. Copy
  into private staging completes before serialized append; no live CPU/DMA lease
  or borrowed guest pointer survives return. Failed appends preserve every byte
  and the previous length. Console diagnostics are outside the artifact channel.
- Preparation requires successful compiler termination, exact consumed input,
  nonempty complete output, exact declared length, full AOM validation with no
  trailing bytes, current lineage, immutable staging and drained accesses. EOF
  alone never proves successful compilation. The validator examines the exact
  staged object; an application's reported length or success is insufficient.
- Publication rechecks owner, lineage and reserved output generation under one
  serialized commit. Output must differ from source and compiler. A matching
  publication epoch prevents competing stale commits; the epoch cannot wrap.
  The object and its receipt become visible together or neither does. Failure
  preserves previous visible publications and the epoch.
- The receipt binds exact compiler/source/profile identities and generations,
  transitive source lineage, output identity/generation, length and exact bytes.
  A digest can index a record but does not replace exact validation. Logical
  names remain metadata. Published AOM data is immutable **READ only**: it grants
  no write, seal, linking or execution authority. Downstream linker and explicit
  application execution gates still apply.

Protected phases are collecting (0), frozen/validated (1), published (2), and
aborted (3). Preparation is the only collecting-to-frozen transition, and
publication requires frozen state. Published and aborted states are terminal;
there is no direct collecting-to-published transition or rollback of a published
artifact. Explicit abort requires drain. Reclaiming private storage requires a
terminal phase, zero CPU/DMA accesses and complete drain; published store-owned
bytes and receipt are retained. Rejected operations stutter. Transition
certificates must be derived from the corresponding actual operation predicate
in the same critical section, rather than being chosen independently.

**Proof scope:** the quantified checks establish append bounds/nonwrap, exact
pointwise byte effects and frame rules, rejection preservation, terminal phases,
publication ordering and shared artifact/receipt visibility in this model. Other
checks exercise authority, owner/generation substitution, malformed/truncated
objects, stale competing commits, executable output and invalid receipt rejection.
This is a conditional contract, not a verified AOM parser, compiler semantics,
concurrent Rust implementation or storage recovery proof. Atomic visibility here
is process-visible atomicity. Persistent crash-consistent receipts require a
separate storage/recovery refinement; no disk journal is assumed or required for
the first in-memory implementation.

**Implementation scope (now implemented in DN-64):** provide the bounded private accumulator and
atomic in-memory AOM/receipt publication, with a concrete producer adapter and
source/profile binding. The current CC2 system compiler uses its admitted raw
workspace bootstrap profile; it is not already a protected-pointer application
using `read_bytes`. DN-63 now establishes the concrete adapter ABI and transfer
refinement. Implement those checks before connecting the producer to publication.
Do not reinterpret raw numeric addresses as protected pointers, grant the guest
new raw-address authority, or claim that an echo probe is a compiler rebuild.
The first compiler-backed witness must consume the selected exact source, publish
an admitted AOM object with matching receipt, pass it through the existing linker,
and execute only under separately granted execution authority.

**Validation here:** **124 positive witnesses pass; all 99 hostile assertions are
explicitly disproved by Z3.** No unknown, timeout or evaluation error counts as a
hostile disproof. Only this new pair was run for acceptance. One unchanged
65-witness pointer-metadata theory was run while diagnosing local Kleis expression
translation; the unchanged full formal suite was not rerun. No Rust or long CC2
suite was run because this patch changes only formal contracts, gate selection
and documentation. The user's 1057-test result remains the runtime checkpoint.

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis --only-rebuild
```

`--only-rebuild` selects just the new pair; `--only-input` retains its meaning.
`--only-108` includes output, input, rebuild-artifact and the DN-63 compiler-adapter
pairs. The default also runs the 10.7 prerequisites. Rerun affected imported gates when dependencies
change, and reserve a full formal run for integration or a changed Kleis binary
or standard library. No new standalone notes file is needed.

## DN-63 — Concrete CC2 compiler-adapter ABI refinement (Phase 10.8)

**Status: formal refinement and first runtime implementation validated; see
DN-64 for the CC2 witness and 1064-test full-suite checkpoint.** This
selects the concrete first producer for DN-62: the exact linked CC2 publication
from the established fixed-point lineage, running in its isolated system-compiler
machine and emitting protected application AOM under target profile 2. The
compiler's own admitted raw-workspace execution and the output language profile
are distinct. This slice neither changes the compiler into a protected-pointer
application nor adds a raw-address application syscall.

`anka108_compiler_adapter.kleis` and its hostile pair refine the existing
rebuild-artifact contract. The ABI is an internal trusted launch/result interface,
version 1. No guest-supplied structure contains authority-bearing host addresses.
The coordinator retains exact compiler/source/profile publication identities and
generations, the actual process/session owner, output reservation and publication
authority. Workspace words and AOM names never replace those identities.

### Concrete invocation and result layout

The first adapter supports only target profile **2**. Profiles 0 and 1 remain
outside this adapter even though existing compiler helpers support them. Values
below come from `dev_compiler.rs`, `guest_compiler.rs` and the exact stage-3 C
compiler. Existing placement managers allocate physical extents and virtual
suffixes; the table records the compiler ABI rather than new placement arithmetic.

| Item | Concrete representation and rule |
| --- | --- |
| Source object | Immutable READ object; little-endian u64 payload length at offset 0; exact payload at offset 8; remaining allocation bytes zero |
| Source bound | At most 65528 payload bytes; envelope is at least 20480 bytes, rounded up by 4096-byte pages when larger, at most 65536 bytes |
| Source placement | Small source normally maps at 28672; larger source gets a disjoint region from `VirtualLayoutBuilder`; all mappings require exact identity and placement checks |
| Workspace | Fresh private 24576-byte RW object at virtual 49152 |
| Source position / length / text base | Workspace offsets 0 / 8 / 16; terminal position and length must match the exact selected payload; text base is selected source mapping + 8 |
| Error | Workspace offset 24, virtual 49176; must be zero alongside a normal zero process exit |
| Serialized output length | Workspace offset 72, virtual 49224; checked against actual AOM total length |
| Scratch frontier | Workspace offset 19304, virtual 68456; initially 262144; result must satisfy `out_pos <= frontier <= 262144` |
| Compile-only mode | Workspace offset 19312, virtual 68464; set to 1 |
| Output limit | Workspace offset 19320, virtual 68472; exactly 262144 bytes |
| Target profile | Workspace offset 19328, virtual 68480; exactly 2 |
| Source overrides | Workspace offsets 19336 / 19344, virtual 68488 / 68496; explicitly set to selected source base and envelope size minus 8, for small inputs too |
| Private output arena | 262144 bytes at virtual 73728; compiler initially receives RWS, workspace RW, source READ, compiler code RX |
| Compiler entry | Separate launcher at PC 0 CALLs `code_base + entry`; target is 8-byte aligned, lies in exact compiler code and fits the signed CALL_PC20 displacement |
| Return | Compiler main returns R0; launcher copies that value to R1, sets R0 to SYS_EXIT (0), then TRAP 0; errors cannot be replaced by zero |

Normalizing both source overrides deliberately removes the old zero/fallback
choice from the new adapter. It is compatible with the compiler's current C
entry point, but requires new adapter initialization. The private source envelope
also accounts for the legacy compiler lexer reading aligned words: the theory
proves that an aligned word containing any admitted payload byte stays inside the
allocated envelope. Zero padding is private, grants no additional application
pointer range, and is excluded from source identity/receipt length.

### Snapshot and exact transfer

The adapter first checks exact launch identity/geometry, source bytes, controls,
rights and isolation. The linked compiler route has one process; success requires
normal termination, exact preserved return status zero, workspace error zero,
complete source position, current bindings and no pending access. Process count
alone is **not** evidence that generated output was never executed: the
compile-only/no-output-execution obligation must be checked separately.

Workspace results become usable only after all writers stop and the snapshot is
current. They remain reports to validate, not trusted capabilities. Rechecking
controls at the end is not a proof that arbitrary producer code could never
modify them transiently; exact admitted producer identity and execution isolation
remain prerequisites of this conditional model.

Current SYS_SEAL (5) transitions the arena to Sealed, increments its generation,
and grants RX inside the compiler's private domain. Consequently the adapter must:

1. Refuse an exhausted generation before launch; the generic runtime generation
   counter currently wraps, so its existence alone does not establish this rule.
2. Verify the actual post-seal generation and acquire an explicit READ-only grant
   in the adapter domain to **exactly `[0, out_pos)`** of that selected arena.
3. Validate AOM magic/version/geometry/tables and the admitted target profile over
   exactly that prefix. The full existing validator remains an obligation;
   checking the header alone is insufficient.
4. Copy consecutive chunks of `min(65536, out_pos - used)` into a private exact-size
   accumulator, using the same object, generation, domain, range and chunk values
   in the concrete READ check and the abstract append guard.
5. Freeze and prepare only when the copied length equals `out_pos` and the exact
   source-consumption and successful-completion checks hold.

In profile 2 the downward-growing portion of the arena holds compiler metadata
scratch. It must not be appended as a literal tail. The serialized AOM prefix
already contains its protected-frame manifest and symbol/relocation data. Full
arena copying or carrying a legacy backing-image length into this path would
leak unrelated bytes and fail the contract.

The trusted transport interface authenticates a selected Fabric object and READ
range; it does not fabricate protected pointer kinds or a protected event image.
DN-62's `span_checked` documentation is refined accordingly: protected syscall
transport and this trusted isolated-compiler transport discharge the same exact
READ-range obligation through their respective checks. Its abstract predicates
and existing witness expectations are unchanged. The compiler source cursor is
its checked workspace source position here, not a claim that CC2 called
`read_bytes` or that a host parser consumed its source.

### Publication and receipt composition

Publication creates a fresh sealed exact-length object distinct from compiler,
source, workspace and private arena. The exported capability is READ only; the
arena's compiler-local RX/SEAL authority is never transferred. Physical page
allocation can round up internally, but logical artifact length and admitted
readable range remain exact. The recipe is transport plus structural validation;
no host C parsing, preprocessing, symbol resolution, relocation or byte patching
is admitted.

`ad108_copy` composes the actual range check with the DN-62 append guard over the
same chunk. `ad108_prepare` maps the completed source/output counts into the
abstract prepare guard. `ad108_publish` composes fresh-object export with the
abstract atomic artifact/receipt publication over the same keys, rights, epoch
and receipt. A separate success flag cannot bypass either side. Exact receipt
lineage comes from coordinator-owned bindings (`rb108_binding` and
`rb108_receipt`), not invented compiler-identity fields in the AOM header.

Timeout, fault, seal failure, malformed output, wrong generation, partial copy
or rejected publication exposes no new artifact/receipt. Cleanup requires a
terminal producer, stopped writers and zero pending CPU/DMA accesses. Existing
published objects retain their own ownership. Persistent storage recovery remains
outside this in-memory publication refinement.

### Validation and implementation boundary

At the original formal checkpoint, the adapter gates passed **169 positive witnesses**, and all **137 hostile
assertions are explicitly disproved by Z3**. Quantified properties establish
source-envelope bounds, safe private lexer word coverage, nonwrapping chunk
progress, completion in at most four 64 KiB copies, and copy/prepare/publication
refinement to the abstract guards. Hostile cases cover stale pre-seal grants,
wrong owner/domain, scratch inclusion, profile substitution, unaligned/out-of-range
entry, missing return authority, erased errors, live writers, partial staging,
reused arena publication, amplified rights and missing publication authority.

The affected abstract rebuild gates were also rerun: **124 positive / 99 hostile**.
No unrelated full formal suite or Rust/long CC2 suite is required for this formal
patch. At that formal-only checkpoint, DN-61 recorded 1057 passing runtime tests;
DN-64 now records the 1064-test implementation acceptance. These proofs are
conditional on the explicitly stated trusted checks; they do not prove the C
compiler, AOM parser, Rust adapter or scheduler correct.

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis --only-adapter
```

For an external Kleis standard library, configure the parent of `stdlib/` before
running the gate (replace the example path with the actual Kleis checkout):

```sh
export KLEIS_ROOT="/absolute/path/to/kleis"
```

Alternatively pass `--kleis-root /absolute/path/to/kleis` to the gate runner.
The runner verifies `stdlib/prelude.kleis`, forwards `KLEIS_ROOT`, and runs each
10.8 Kleis command from that directory using absolute theory paths. This also
supports supplied CLI builds whose test-import resolver uses the working
directory rather than `KLEIS_ROOT` alone. Without either setting, the runner
retains its repository-local behavior. It never copies the standard library
into Anka or changes any theory to bypass an import.

**External-library validation:** reproduced the missing-prelude failure with an
isolated Anka checkout, then passed **169 positive / 137 explicitly disproved
hostile witnesses** with a separate stdlib tree selected through `KLEIS_ROOT`.
An invalid explicit root fails clearly before running witnesses. The original
local validation had a repository-local stdlib, which masked this setup need.

`--only-adapter` selects the new pair. `--only-rebuild` keeps selecting the abstract
artifact pair. `--only-108` and the default include both. Rerun both affected pairs
when changing their shared contract; unchanged unrelated theories can wait for
an integration checkpoint.

**Implementation scope (now implemented in DN-64):** implement the trusted adapter with explicit
source controls, terminal snapshot checks, post-seal exact READ authorization,
private bounded accumulation, fresh READ-only AOM publication and an atomic
in-memory receipt. Reuse the exact fixed-point producer and existing linker in
one compiler-backed acceptance witness. The user runs that long integration test
and the full single-threaded Rust suite locally; focused adapter tests can run
here. No further speculative formal layer is needed before this implementation
unless coding exposes a change to the contract.


## DN-64 — Concrete CC2 adapter and atomic AOM receipt (Phase 10.8)

**Status: COMPLETE for the first trusted in-memory adapter/publication slice.**
The user reported the long CC2 acceptance witness passing in **216.85s**, followed
by the full single-threaded suite: **1064 passed, 0 failed**, in **1027.13s** on
2026-10-16 (America/Chicago). This supersedes DN-61's 1057-test checkpoint and
closes the implementation acceptance for DN-62/DN-63; broader Phase 10.8 work
remains open.

### Execution and transport

`compiler_adapter.rs` admits the exact fixed-point CC2 producer through
`Cc2FixedPointWitness::application_tools`, before execution and again before
publication. The existing guest `ankapp` supplies the effective source. The
strict path in `dev_compiler.rs` seals the length-prefixed, zero-padded source
object and an immutable version-1/profile-2 configuration object before launch.
Both source override words are explicit, including for small inputs. Compiler
execution still uses the existing placement managers and protected launcher CALL
and return; no compiler C source, host parser or linker was introduced.

After termination the bridge checks the same process incarnation, context and
domain, normal zero exit, zero compiler error, complete source cursor, unchanged
controls, source identity, single process, drained accesses and post-seal arena
generation. It checks every retained transaction batch for a Fetch from the
output arena before discarding the batch. An attempt to execute the output in
the compiler's own process therefore fails even when no second process exists.

A fresh adapter domain receives exactly READ to `[0, out_pos)` at the current
sealed generation. Copying uses committed Fabric READ transactions, in consecutive
chunks of at most 65536 bytes, with the same domain/object/generation/range used
for admission. The maximum is four chunks. Private downward-growing scratch,
source padding and arena slack are excluded. The resulting bytes pass the existing
full `AomModule::parse` and protected-frame validator before publication.

This first profile admits closed protected translation units: unresolved imports
or relocations are rejected. This matches the current standalone protected CC2
path. Adding separately compiled modules needs a corresponding profile and
relocation/manifest admission design; the host must not repair their bytes.

### Publication, identity and authority

`RebuildArtifactStore::compile(expected_epoch, producer, bundle, execution,
publication)` returns a committed epoch. `receipt(epoch)` and
`artifact_bytes(epoch)` expose immutable observations of the same record.

Publication allocates a fresh exact-length object, initializes and seals it, and
grants READ only. It is distinct from the compiler, source, profile, workspace and
private arena. The compiler-local RX grant on the arena is never exported.
Artifact and receipt become visible through one complete record insertion under
exclusive mutable access. Expected epochs reject stale commits; increment is
checked for exhaustion. All fallible preparation precedes insertion. Failed
attempts discard their private machine and cannot alter prior published records.

The receipt binds the actual compiler/source/profile/artifact object generations,
exact compiler bytes and geometry, fixed-point origin publication, exact source
bundle and effective source, preprocessing/linking tool images, target profile,
logical output length and process/context owner. Object IDs are local to a Fabric;
the receipt's nonreused execution context supplies the namespace. Comparing bare
object numbers across machines is not an identity check. Concrete u32 process
generation `g` is represented as `u64(g) + 1`, preserving injectivity while
reserving the abstract zero sentinel.

`RebuildPublicationAuthority::provision()` is explicit developer policy, separate
from `DeveloperExecutionAuthority`. The protected rebuild API now requires it as
a fourth argument. Missing authority is rejected before expensive work. A receipt
or its copied fields grant no authority. The public store accepts a verified
fixed-point witness; it has no public method for publishing arbitrary host bytes.

`rebuild_protected_application` retains the committed AOM and receipt, passes the
exact published bytes to the existing guest `ankald`, validates the linked
protected image, and registers it through the existing application path. Its
`compiled_aom()` and `rebuild_receipt()` accessors expose the retained evidence.
Running the linked application still requires explicit execution authority.
Legacy profile-0 rebuild behavior is unchanged.

This is an isolated trusted adapter, not a new guest syscall or a conversion of
raw addresses into protected pointers. The store retains each private compiler
Fabric and its placement ownership to keep bound objects alive; this first bridge
therefore retains a 16 MiB Fabric backing per committed record. Persistent disk
receipts, crash recovery, artifact eviction and a general concurrent compilation
service remain outside this milestone. No runnable compiler process is retained.

### Formal correction and validation

Implementation exposed one concrete refinement mismatch: fresh Fabric objects
start at generation **0** and their first seal produces **1**. `ad108_seal` now
admits `0 -> 1` while still rejecting wrap and any wrong successor. A positive
witness covers the initial transition; the hostile `0 -> 2` case remains rejected.
The affected adapter gate passes **170 positive witnesses / 137 explicitly
disproved hostile assertions**. No unchanged full formal suite was rerun.

Focused runtime validation completed here:

- Seven new adapter tests pass: exact chunk boundaries, narrow READ admission,
  stale/wrong-domain/amplified grants, small and maximum source envelopes,
  modified controls/cursors, preserved failure return status, and same-process
  output-fetch rejection.
- Publication tests cover exact lineage and READ-only rights, malformed/truncated
  AOM and invalid manifest rejection, partial accumulation, stale epochs, missing
  authority, pool exhaustion, epoch exhaustion, and preservation of earlier
  artifacts/receipts across failures and a later successful publication.
- Existing compiler-layout/transport tests, transaction-trace collection and exact
  application registration pass. These runs cover **15 distinct focused tests**.
- `cargo check --all-targets` passes; existing repository warnings remain.

The existing long test
`p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address` now exercises
the adapter for protected applications, including typed input/output probes. It
checks the retained receipt, exact AOM, fixed-point producer identity and separate
publication authority, reusing its one CC2 bootstrap. No additional long
fixed-point test was added.

### Local acceptance checkpoint — 2026-10-16

The user ran the existing long witness locally: **1 passed, 0 failed**, in
**216.85s**. CC2_0 remained 148376 code/backing bytes. CC2_1 and CC2_2 remained
identical at 168032 code/backing bytes, with entry 165344. The protected rebuild
path passed its publication, receipt, linking, typed I/O and execution checks.
The compiler rejections and ControlFlowViolation messages in this test are the
expected hostile cases.

The subsequent full single-threaded run reported:

```text
test result: ok. 1064 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1027.13s
```

Warning cleanup remains deferred by agreement. This acceptance update changes
only documentation; it does not alter the tested implementation or formal gates.
The bounded compiler-adapter/AOM-receipt slice is ready to commit. No merge is
claimed by this checkpoint.

Reproduction commands for the formal and runtime acceptance paths (the unchanged
formal gate was not rerun for this documentation update):

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis --only-adapter

cargo test --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address \
  -- --test-threads=1 --nocapture

cargo test -- --test-threads=1
```

The passing long witness establishes the concrete compiler-to-AOM-to-link-to-run
path with a retained in-memory receipt. Phase 10.8 remains open for
compiler/toolchain modularization, broader I/O and rebuilt services.

## DN-65 — Protected module composition contract (Phase 10.8)

**Status: FORMAL GATE PASSED; implementation proceeds in pieces (DN-66–DN-68).** On 2026-10-17,
the focused Kleis gate passed **217 positive witnesses** and explicitly
disproved **168/168 hostile assertions**. The original formal patch changed
theories, the gate runner and documentation only. Its runtime checkpoint was
DN-64's **1064 passing tests**; no Rust suite or CC2 bootstrap was rerun for that
formal patch. The user independently confirmed the same focused formal result.

### Existing foundations and the concrete gap

Phase 10.3 already supplies AOM emission and separate translation units. Phase
10.4 already supplies the guest static linker, typed symbol resolution and CALL
relocations. Phase 10.5 already supplies immutable source bundles and guest
include-only preprocessing: PR #9 merged that implementation with 980 passing
tests. The roadmap's old 10.5 "implementation pending" text was stale and is
corrected in this patch. General macros and conditional preprocessing remain
outside that completed include-only scope.

The next work composes these facilities with the Phase 10.7 protected ABI and
DN-64's producer/publication boundary. At the formal checkpoint there were
three restrictions:

- CC2's protected `q59` manifest writer requires every function-table entry to
  be defined locally; an imported function currently causes rejection.
- The adapter admits only closed protected objects, rejecting imports and
  relocations and applying the closed-program frame validator.
- Guest `ankald` copies each input rodata section. Multiple complete protected
  manifests need composition into one manifest, together with PFRAME index
  rebasing. Concatenating those independent headers is insufficient.

### Selected bounded profile

Keep **AOM v1**, **target profile 2**, the **v2 pointer representation/calling
convention**, and the **v2 manifest encoding**. Introduce separate trusted
admission roles for a relocatable protected module and a closed linked image.
A role records what was validated; it grants no rights. An unresolved module
can be retained as immutable READ data with a compiler receipt, but cannot pass
application execution admission. The existing closed-image path must retain
its stronger checks.

Each input contains nonempty code and exact manifest-only rodata. The initial
slice adds no arbitrary literal pools, data relocations, globals, dynamic
linking, archive extraction, heap allocation or IR/register allocator. Each
compiler AOM remains bounded by the adapter's 262144-byte arena; the serialized
linked code plus merged manifest is bounded by the existing 1 MiB artifact
limit. Total frames are bounded by 4096; every module must own a nonempty frame
set. Capacity checks fail before arithmetic wraps or an output is published.

### Compiler/module admission obligations

Definitions have a dense module-local frame ordinal; imports and unused
prototypes have no frame. The actual function-table-to-frame mapping must be a
bijection for definitions, with exact export-entry agreement. Equal counts
alone do not prove that mapping. PFRAME operands use these dense ordinals,
rather than raw table indices that include imported declarations.

The new module validator must retain the existing exact AOM/manifest parsing,
complete function coverage, instruction restrictions, local storage bounds and
nonoverlap, argument-lane validity, within-function branches, and PUNFRAME/RET
discipline. Only an external CALL may remain unresolved, and only when exactly
one admitted import relocation covers its canonical zero-displacement CALL/NOP
slot. Internal CALLs already target local frame entries. A relocation cannot
cover a PFRAME, an arbitrary instruction, an out-of-function slot or noncanonical
padding. Unsupported widths/kinds/addends remain rejected.

### Guest linking and manifest composition

Consume modules in the immutable request's explicit order. Starting from zero,
fold code sizes and frame counts to obtain each module's code base and frame
prefix. Do not reorder modules or introduce a trampoline. For a module with
frame prefix `p`, local frame `i` becomes `p + i`; checked bounds make this
mapping injective and disjoint from the next module's frame range.

Rebase frame entry/end PCs and their derived exit PCs by the module's code
base. Keep frame size and every local offset, length, alignment, flag and local
index unchanged. PLOCAL indexes within its own frame, so it is never rebased.
Rewrite PFRAME indices only at validated frame entries. Preserve internal CALL
and branch displacements because their source and target shift together.

Resolve imports against exactly one compatible exported function, with the
same pointer ABI, valid argument layout, exact return/parameter types, and one
matching target frame entry. Duplicate exports remain invalid. Apply only the
existing zero-addend, code-section, 8-byte CALL_PC20 relocation. Despite its
wire name, the instruction uses a signed **22-bit displacement in 4-byte words**;
the positive and negative limits differ and are checked before encoding.

The guest linker writes one manifest header followed by the ordered rebased
frame records and unchanged local records. With `F` frames and `L` total local
records, its exact byte length is `32 * (1 + F + L)`. The header's code length
and frame count describe the complete output. Metadata follows the code with
no extra payload or trailing bytes in this profile. Every code slot must be
unchanged or justified by its complete PFRAME/import-CALL patch predicate;
paired NOPs remain unchanged. Host-side symbol resolution, relocation and
manifest repair remain forbidden.

After guest linking, rerun full closed-image validation on the exact returned
code and merged manifest. There must be no unresolved imports or unapplied
relocations. The first application entry remains **`int main(void)` at offset
zero**, at a validated frame entry. Put the entry module first and define main
first in that module; a nonzero entry fails explicitly. Supporting another
entry convention requires its own refinement.

### Lineage, publication and calls

Retain a frozen dependency vector in linker input order. Every consumed entry
must match its position, Fabric context/object/generation, exact AOM bytes,
module admission role and current full compiler receipt. Those receipts retain
the exact source bundle/root/includes/effective source, fixed-point producer,
profile and tools. A logical filename or a digest alone cannot replace this
identity. Matching bare object IDs across separate Fabrics is insufficient.

The linked receipt binds the complete ordered dependencies, exact guest linker,
linked bytes, entry, geometry and merged manifest. Preserve DN-64's publication
authority, current reservation/owner/binding checks, drain, nonwrapping epoch
and one shared artifact/receipt visibility decision. Failure preserves prior
records and publishes no linked result; already published input modules may
remain. The new output must be distinct from all inputs, tools and staging.
The serialized artifact carries READ only. Loader mappings retain RX code and
READ/non-executable metadata; ordinary registration, placement and explicit
execution authority remain separate gates. This is in-memory atomicity, not
persistent crash recovery.

Calls across modules use the existing same-domain pointer ABI, protected pair
transport and typed spills. A module boundary creates no authority. Returning
from the helper retires its own frame while preserving the caller's buffer;
an escaped helper-local pointer becomes stale under the existing frame rules.

### Formal scope and validation

`anka108_protected_modules.kleis` imports the existing linker-process,
protected-artifact and compiler-adapter theories. It adds no axioms. The older
linker's conditional Bool guards are expressed in bit-vector/logical normal
form here for composition in quantified assertions. Pointer ABI and receipt
predicates are reused directly.

The gate proves arithmetic/encoding properties and conditional admission and
publication laws. Universal witnesses cover frame-index bounds/injectivity,
disjoint successive frame ranges, PFRAME representability, extent preservation,
CALL encode/decode round trips and invariance under uniform rebasing, dependency
progress, failure preservation, shared visibility and nonwrapping publication.
Concrete cases include a two-module layout, forward/backward calls, preserved
pointer cells, dependency substitutions and authority failures.

Parser/scan certificates in the model are explicit implementation obligations:
they must be computed over the same frozen bytes and all relevant items. A
count or caller-supplied success flag cannot establish them. These proofs do
not establish full compiler/parser/linker C semantics or implementation
correspondence; the concrete refinement and runtime witnesses remain next.

The supplied Linux Kleis executable with Z3 4.12.2 ran the new pair successfully:

```text
PASS: anka108_protected_modules.kleis: 217 positive witnesses
PASS: anka108_protected_modules_false_witnesses.kleis: 168/168 explicitly disproved
```

Run only this new gate pair locally:

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis \
  --only-modules
```

`--only-108` now includes this pair; the default still includes 10.7 prerequisites.
The focused command loads imported definitions but does not rerun the unchanged
prerequisite example suites. Unknown results, parser/evaluation errors and
non-disproof failures remain gate failures.

### Next concrete witness

Implement a shared prototype header plus two protected C units: `main.c` owns a
fixed byte buffer, and `buffer.c` defines a helper accepting its protected pointer
and length. Compile both through the exact fixed-point CC2 and guest preprocessor,
publish each admitted AOM/receipt, link with guest ankald, retain the linked
dependency receipt, validate/register normally, and emit the helper's result
through typed console output. Exercise wrong signatures, malformed frame maps,
unresolved calls, stale/substituted dependencies and absent execution authority.
Reuse one CC2 bootstrap for these integration checks. The user runs the long
single-threaded acceptance/full suite after implementation. Broader service
rebuilds, persistent receipts and Phase 10.9's exact CPU-to-HTTP closure remain
open.

## DN-66 — Protected modules, implementation piece 1 (Phase 10.8)

**Status: emission and structural validation implemented; concrete CC2
acceptance passed on the developer machine (1 passed, 239.48s).** Work stays on
`feat/anka108-protected-modules`. The DN-65 Kleis contract passed on the user's
machine before this implementation: **217 positive / 168 hostile disproofs**.
No theory changed in this piece, so the unchanged gates were not rerun.

### Bounded handoffs

Keep the implementation in separate reviewable/testable handoffs:

1. **This piece:** CC2 protected-module emission, structural module validation,
   fast hostile cases, and compiler checks sharing the existing CC2 bootstrap.
2. Guest `ankald` manifest merge and PFRAME rebasing, with exact import CALL
   resolution and closed-image validation on the returned bytes.
3. Adapter module admission and linked-artifact publication with the complete
   ordered dependency receipts and existing distinct authorities.
4. Two-unit protected-buffer execution, typed output and hostile integration
   witnesses, then the full single-threaded regression suite.

Each handoff updates this root document and supplies only changed files in its
ZIP. Finish the relevant acceptance checks before starting the next piece.
DN-67 and DN-68 record the subsequent piece-2 and piece-3 handoffs. Cross-unit
execution and the composition milestone's full suite remain piece 4.

### Concrete changes

CC2 now counts only defined functions in the protected manifest. `q52` emits
a provisional PFRAME index; `q59` assigns dense ordinals in definition-table
order and patches each corresponding entry slot itself. Imports and unused
prototypes consume no frame. Internal forward calls still receive the existing
guest fixup, while external calls retain the existing typed AOM relocation.
No host patches the compiler output. The AOM/profile/manifest versions stay
1/2/2. Raw bootstrap and ordinary application profiles retain their paths.

`ValidatedPointerModule::from_aom` parses the exact bounded AOM and v2 manifest,
retaining immutable original bytes plus parsed tables. It checks definition/
frame bijection, matching export entries, aligned complete frames, canonical
instruction/NOP slots, public argument-lane fit, and unique zero-addend import
relocations at canonical zero-displacement CALLs. Common frame validation
preserves instruction restrictions, local bounds/nonoverlap, within-function
branches, resolved internal calls and PUNFRAME/RET discipline.

A module validation result is separate from an executable program and does
not establish producer lineage or publication authority. The closed-image
constructor always uses an empty unresolved-call set. The current compiler
adapter remains restricted to closed objects until piece 3; no imported module
can use this new constructor to bypass application admission.

The AOM public-type check now uses remainder instead of repeated subtraction,
with equivalent type classification. This keeps a hostile 64-bit type tag
from controlling an enormous validation loop. Tests cover large valid and
invalid tags as well as malformed relocations, padding, export/frame aliasing,
ABI overflow, raw memory instructions, out-of-frame branches and bad metadata.

The existing concrete CC2 acceptance test now guest-preprocesses and compiles
two small translation units sharing a prototype header. They deliberately
include an unused prototype, an external pointer-taking call and a forward
definition whose frame order differs from code order. The check validates the
resulting AOMs and confirms that the unresolved caller fails closed-image
validation. Piece 1 stops before cross-module linking/execution. Both compilations
reuse the one fixed-point producer already built by that test.

### Piece-1 validation checkpoint

Agent-run focused checks passed:

```text
anka64::pointer_frames::tests: 10 passed, 0 failed (9 new tests)
anka64::compiler_adapter::tests: 6 passed, 0 failed
```

The Rust test target builds, including the added integration check. The user's
first piece-1 run reached the CC2 fixed point: CC2_0 was 148984 bytes; CC2_1 and
CC2_2 were identical at 168888 bytes with entry 166200. The new module fixture
then failed preprocessing with `PreprocessorRejected(2)` before either module
was compiled. Its include operand was `api.h`, but the bundle member's exact
name was `/probe/api.h`. Phase 10.5 deliberately performs no relative-path
resolution. Both fixture directives now use `/probe/api.h`, and preprocessing
failures identify the failing fixture. Preprocessor semantics are unchanged.
The user then reran the full concrete application acceptance successfully:
**1 passed, 0 failed, 1072 filtered out, 239.48s**. The same CC2_0/CC2_1/CC2_2
sizes and fixed-point entry were observed. The compiler refusals and
ControlFlowViolation lines in that passing run are expected hostile cases.
The latest full-suite evidence remains the prior
**1064 passed in 1027.13s** checkpoint; it is not a result for this patch.

The piece-1 commands were:

```sh
cargo test --lib anka64::pointer_frames::tests -- --test-threads=1
cargo test --lib anka64::compiler_adapter::tests -- --test-threads=1
cargo test --lib \
  anka64::userspace_rebuild::tests::p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address \
  -- --exact --nocapture --test-threads=1
```

The passing acceptance permits the piece-2 work below. Reserve the full-suite
run for the completed composition milestone unless a specific regression
requires it earlier.

## DN-67 — Protected modules, guest-linker composition (Phase 10.8, piece 2)

**Status: implemented and concrete CC2 acceptance passed on the developer's
machine.** Continue on `feat/anka108-protected-modules`.
This implements the guest linking and structural result checks from DN-65.
The existing 217-positive/168-hostile Kleis gate covers this slice; its theories
and contracts are unchanged, so they were not rerun. This is runtime evidence
for the implementation, not a proof of the full C linker or compiler semantics.

### Guest construction and independent result checks

Guest `ankald` distinguishes protected modules by the initial PFRAME and rejects
mixed protected/legacy input sets. The protected path checks exact manifest
geometry, dense definition/frame correspondence, canonical PFRAME and CALL/NOP
slots, unique zero-addend relocations, local CALL targets and argument-lane fit.
It uses the existing exact symbol/signature resolver for external calls.

The explicit input order determines packed code bases and frame prefixes. The
guest writes one v2 manifest, rebases each frame entry/end and its PFRAME index,
and copies frame sizes and local records unchanged. Internal CALLs, branches,
PLOCAL operands and all other instructions retain their bytes. Imported CALLs
use the existing signed 22-bit displacement encoding and range checks. No
trampoline or inter-module padding is introduced. The entry must remain
`int main(void)` at offset zero. AOM/profile/manifest versions remain 1/2/2.

`run_protected_ankald` accepts immutable `ValidatedPointerModule` values. It
checks the aggregate limits before executing the guest, then independently
checks the guest's exact returned bytes. The result must pass full closed-image
validation, exact geometry/entry checks, frame/local correspondence and an
exhaustive comparison of every original code slot. For an imported CALL, the
checker decodes the guest-selected target address and verifies the export at
that address against the import's exact name and signature. It does not search
by import name to choose an address, emit code, apply a relocation, merge a
manifest or repair bytes. Duplicate exported names are rejected.

Each protected input remains bounded by 262144 bytes. Total frames are capped
at 4096, and **code plus merged metadata** must fit the 1 MiB artifact limit.
Invalid protected composition uses guest error 9; the existing entry, symbol
and signature errors remain distinct. Public-type validation in guest ankald
now reduces large type tags in a bounded number of binary steps, avoiding the
old repeated-subtraction loop. Legacy code-only and arbitrary-rodata linking
retain their existing path and entry convention.

The guest's composition checks supplement the complete Rust module validator;
they do not replace its instruction/local-storage/return checks. Structural
success creates no producer receipt, publication authority or execution right.
DN-68 implements the subsequent module/linked receipt boundary (piece 3).
Actual cross-module protected-pointer execution remains piece 4.

### Validation and local handoff

Agent-run checks using the real guest linker compiled by canonical CC_B:

```text
p108_protected_link: 7 passed, 0 failed, 1073 filtered out; 35.23s
```

These cover forward and backward imported calls, definition order different
from code order, exact manifest composition, preserved pointer-slot metadata,
deterministic output, malformed frame/relocation inputs, wrong or unresolved
signatures, duplicate exports, changed entry contracts, mixed profiles, changed
guest output, aggregate frame/image limits and legacy rodata behavior. Small
hand-assembled AOM inputs avoid another CC2 bootstrap for these focused checks.
The Rust test target builds, including the extended integration test.

The existing long CC2 acceptance now compiles the two exact protected C units
and links them through guest ankald using its one fixed-point producer. The
helper also calls back into the first unit, exercising both relocation
directions. Successful validation prints `protected-module link: modules=2
frames=3 code=... metadata=... entry=0`. This test checks linked bytes; it does
not yet publish module receipts or execute the cross-module application.

After applying the piece-2 ZIP at the repository root, run locally:

```sh
cargo test --lib p108_protected_link -- --nocapture --test-threads=1
cargo test --lib \
  anka64::userspace_rebuild::tests::p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address \
  -- --exact --nocapture --test-threads=1
```

The user confirmed both checks on 2026-10-17: **7 focused tests passed in
19.99s**, followed by **1 acceptance test passed, 1079 filtered out, in 246.54s**.
CC2_0 remained 148984 bytes; CC2_1 and CC2_2 were both 168888 bytes with entry
166200. The protected module result was exactly **2 modules, 3 frames, 688 code
bytes, 512 metadata bytes, entry 0**. The expected compiler refusals and
ControlFlowViolation cases also passed. This is not a full-suite result.

## DN-68 — Protected module admission and linked receipts (Phase 10.8, piece 3)

**Status: implemented and locally accepted; 22 focused checks passed in 23.16s,
then the receipt-integrated CC2 acceptance passed in 248.79s.** Stay on
`feat/anka108-protected-modules`. The existing DN-65 Kleis contract supplies the
module role, ordered dependency, complete linked validation, authority and
atomic publication obligations. No theory, guest ABI, compiler or linker C
source changed, so unchanged Kleis gates were not rerun. These concrete checks
exercise the implementation obligations; they do not establish full compiler
or linker correctness from the conditional formal predicates alone.

### Admission and frozen dependencies

`RebuildArtifactStore::compile_module` uses the same guest preprocessing,
fixed-point producer validation, strict compiler transport and fresh sealed
publication as the existing closed-translation-unit API. It applies
`ValidatedPointerModule` and records `RelocatableModule` admission. The original
`compile` API still rejects imports and relocations and requires a closed
protected program. A module admission role never grants execution rights.

`freeze_modules` captures an explicit ordered sequence of published module
epochs, their complete receipts, exact AOM bytes, dependency positions and the
store's expected publication epoch. The request is immutable through the public
API. Each dependency includes its context/object/generation, full original
source bundle and effective source, target profile, compiler image and exact
tool images. Every dependency must agree on the guest linker image used by the
request. Bare object numbers and friendly source names cannot establish identity.

Before linking and again before publication, the store checks the same complete
snapshots against current records. It checks sealed source/compiler/profile
objects, the artifact's exact READ grant and bytes, role, context, generation,
position and full receipt equality. The test deliberately uses equal bare
artifact keys in different compiler Fabrics: substituting the other context's
receipt fails even when the AOM bytes are identical. Reordering a frozen vector,
altering source/tool evidence or revoking a dependency also fails.

### Terminal guest output and atomic publication

The linker runner now retains its terminal Fabric, placement manager, exact
linker/input/staging/control keys and actual process identity for publication.
It verifies unchanged request controls and ordered sealed inputs, unchanged
process owner, a single terminal process, no pending I/O, drained transactions
and no attempted fetch from generated staging. Runnable process state is
dropped before publication. The existing physical and virtual placement
managers continue to own all placement decisions.

`link_modules` requires both developer execution authority for the guest linker
and separate rebuild publication authority. It reruns the piece-2 exact-byte and
closed-image result checks against the same frozen inputs. It also checks that
the actual sealed transport objects match each dependency in order, the actual
linker matches its recorded image, and the staged bytes match the guest result.
No host symbol resolution, code generation or manifest repair is introduced.

Publication creates a fresh exact-size sealed object in that attempt's Fabric
and grants **READ only**. A `LinkedRebuildReceipt` binds the exact image bytes,
entry/segment geometry/merged manifest, complete ordered compiler receipts and
AOM bytes, actual transported input keys, linker identity and process context.
The linked result has a distinct `LinkedImage` role and cannot be fed back as a
relocatable module. `linked_image` checks the current sealed publication before
returning its bytes; receipt copies alone are historical evidence, not authority.

Compiled and linked publications share one monotonically increasing store
epoch. Exclusive `&mut` ownership serializes a link attempt, while exact expected
epoch comparison and checked increment prevent stale reservations and wrap.
The artifact and receipt become visible by inserting one complete record; no
fallible work or guest execution follows that insertion. A failed attempt drops
its private machine and reservations. Existing module/linked records remain
unchanged, including when linking fails or the real placement pool is exhausted.
This is in-memory atomicity, not persistence or crash recovery.

### Verification and next handoff

The agent ran the affected adapter and linker tests together, single-threaded:

```text
22 passed; 0 failed; 1067 filtered out; 40.23s
```

This includes nine new publication tests, six existing adapter tests and seven
piece-2 linker tests. Tests cover separate admission roles, immutable ordered
receipts, context collisions, changed generations/source/tools, missing
authorities, stale/replayed requests, epoch exhaustion, guest failure, wrong
actual output/input bindings, request-control tampering, READ-only publication
and allocation failure preserving prior records. Small compiler ABI fixtures
test the publication boundary; they make no claim to be fixed-point compilers.
The linker checks execute real guest ankald built by canonical CC_B.

The actual-binding test was then extended with a nonterminal transaction and a
faulted fetch attempt from staging. That focused rerun also passed:
**1 passed, 1088 filtered out, 34.02s**. Both cases must reject publication even
when the guest's linked bytes and all dependency receipts are otherwise valid.

The long acceptance fixture now compiles and publishes both C modules through
the public module API, freezes their dependency order, guest-links them and
publishes the exact linked image with its receipt. It reuses the existing single
CC2 bootstrap and the same two module compilations. It checks absent authority,
each retained source/tool receipt and the exact linked bytes. It prints the
existing `protected-module link` line plus:

```text
protected-module publication: epoch=3 dependencies=2 rights=READ
```

Apply this handoff at the repository root and run locally:

```sh
cargo test --lib -- \
  anka64::compiler_adapter:: anka64::ankald_tests::p108_protected_link \
  --test-threads=1
cargo test --lib \
  anka64::userspace_rebuild::tests::p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address \
  -- --exact --nocapture --test-threads=1
```

The user confirmed the final 22 focused tests in **23.16s** and the extended
CC2 acceptance in **248.79s** on 2026-10-17 (1 passed, 1088 filtered out).
The fixed point remained CC2_0=148984 bytes and CC2_1=CC2_2=168888 bytes, entry
166200. Publication reported epoch 3, two dependencies and READ rights, with
the same 688-byte code / 512-byte metadata image. These are targeted results;
no full-suite result had been reported at this checkpoint. DN-69 records the
subsequent piece-4 full-suite failure and its probe correction.
DN-69 implements the subsequent execution handoff. Piece 3 itself publishes
READ artifacts and does not execute the cross-module application.

<a id="dn-69"></a>

## DN-69 — Receipt-bound protected module execution (Phase 10.8, piece 4)

**Status: the four-piece protected-module implementation checkpoint is accepted
on 2026-10-17.** Five focused execution tests passed in 32.80s. The full
single-threaded run reported 1093 passed and one C probe failure in 1134.87s;
after correcting that fixture's process-exit path, the expanded fixed-point
acceptance passed in **249.49s** (1 passed, 1093 filtered out). All 1094 library
tests have passing evidence across those runs. A new full-suite run on the
corrected tree has not been reported. Work was performed on
`feat/anka108-protected-modules`; the developer subsequently confirmed its merge
to `main` on 2026-10-17.

### Formal boundary and exact application identity

DN-65's existing `pm108_execute` gate requires linked-image admission, full
closure, current artifact identity, explicit execution authority, ordinary
admission, physical placement and virtual layout. Its call predicate reuses
the protected ABI, and the previously established frame rules retire a helper's
locals without retiring its caller's storage. This handoff makes those existing
obligations concrete. It changes no pointer representation, guest instruction,
syscall ABI, compiler/linker C implementation or Kleis definition. The unchanged
217 positive / 168 hostile module witnesses were not rerun. Their conditional
certificates are implementation obligations, not a proof of all compiler or
linker semantics.

`RebuildArtifactStore::run_linked_application` takes a complete expected
`LinkedRebuildReceipt` and an explicit application execution authority. The
receipt is compared with the retained store record, including its context,
object/generation, exact image, geometry, tools and ordered dependencies. A
module epoch, altered receipt or another Fabric's identical bytes/bare object
key cannot select the publication. Missing authority fails before loading.

The store rechecks the current sealed publication and exact READ grant, actual
linker and transported module bytes, and each original module's current full
compiler receipt. It reruns module validation and the complete protected link
result validator on those same bytes. Consequently closure, entry, every guest
patch and merged frame metadata are recomputed rather than inferred from a
cached success flag. Source/tool/module revocation or changed dependency order
cannot pass the new execution entry point.

Registration uses the **existing sealed artifact in its original Fabric**.
There is no second publication, copied executable object or new epoch. The
ordinary development runner supplies the existing PhysicalPlacementManager and
VirtualLayoutBuilder path, boots its supervisor and executes SYS_SPAWN/SYS_WAIT.
Explicit execution authorizes RX code and READ/non-executable metadata. The
ordinary loader still independently admits the protected program. After
teardown, the publication, READ grant and receipt remain intact and can be used
for another explicitly authorized run. `CompilerAdapterError::Run` preserves
ordinary registration, placement, spawn and runtime failures.

### Concrete C witness and hostile callers

The shared header and two C sources live under
`userspace/bin/protected_modules/`. The header is installed in each immutable
test bundle at `/probe/api.h`, exactly matching the include operand.

The main unit owns a four-byte buffer. `touch` in the second unit uses its own
local storage, changes the caller's first byte from 64 to 65, and calls `tail`
back in the first unit. After both returns, the caller reads its live buffer
and emits exactly **[65, 0, 255, 66]** through `write_bytes`. Empty one-past output
is accepted; an overrun output span returns failure without adding bytes. The
second unit also exports `escape`, so the expanded positive image has **four
frames**, instead of the earlier three-frame linking-only witness. The failed
fixed-point acceptance measured 2328 code / 1280 metadata bytes. After the
explicit-exit correction, both the targeted CC2_0 diagnostic and the passing
self-hosted acceptance measured **3336 code / 2048 metadata bytes**.

Application entry is direct: there is no caller or C startup wrapper above
`main`. Every successful or error path from this probe therefore invokes
`syscall(0, status, 0, 0)` (SYS_EXIT). Ordinary helpers still use `return` to
consume their actual CALL authority. This follows the existing standalone
application ABI; it introduces no new return semantics or authority.

Two additional callers reuse that already-published helper module. One reads a
pointer returned to a helper-local array after the helper has retired. The other
passes a one-past pointer to `touch`, which attempts a byte access. Both images
must link and pass structural admission, then terminate with ProtectionFault
and no output. These cases reuse the same fixed-point compiler producer and
guest tools; there is no additional CC2 bootstrap. Earlier successful linked
receipts remain available while the hostile images are compiled and run.

The long acceptance checks exact executed object/generation, two or more
observed process slots, RX/READ segment permissions and unchanged publication
identity/epoch after the successful run. The developer's passing rerun confirmed:

```text
protected-module execution: exit=0 output=[65,0,255,66] receipt=matched
protected-module rejection: escaped-local=ProtectionFault output=[]
protected-module rejection: one-past=ProtectionFault output=[]
```

### Explicit process-exit correction

The 2026-10-17 full run reached an identical CC2_1/CC2_2 fixed point, linked the
four-frame image and published it with two dependencies and READ rights. It
then faulted at PC `0x6e0`, with object 0 and offset 0. The positive C probe
incorrectly used plain `return` from `main`: that instruction is RET, but direct
process entry has no return authority. The runtime correctly rejected it.

The correction changes the positive probe's six termination paths to explicit
SYS_EXIT. It also corrects the one-past hostile caller: if its forbidden access
were ever to succeed, it must exit normally so the test fails, rather than
produce a misleading ProtectionFault at the entry function's RET. The escaped
local caller already used SYS_EXIT. Compiler, linker, runtime and formal
contracts are unchanged; the existing Kleis gates need no modification for
this fixture correction.

A temporary targeted diagnostic used CC2_0, the real guest ankapp and ankald,
and the ordinary registered-artifact execution path. It reproduced the exact
original image geometry and decoded `0x6e0` as RET. All five cases passed their
expected outcomes in one diagnostic test (105.15s):

| Case | Observed process result | Output bytes |
|---|---|---|
| Original positive probe | ProtectionFault at `0x6e0`, after correct output | `[65, 0, 255, 66]` |
| Corrected positive probe | Exited(0) | `[65, 0, 255, 66]` |
| Escaped helper-local pointer | ProtectionFault | `[]` |
| One-past access with explicit exit fallback | ProtectionFault | `[]` |
| In-bounds control with explicit exit | Exited(1), the helper's returned status | `[]` |

The diagnostic was removed after use; it adds no permanent test or repeated
bootstrap cost. It isolated the exit error. The developer then ran the complete
CC2_0 -> CC2_1 -> CC2_2 receipt-bound acceptance successfully, as recorded below.
The test count remains 1094.

### Focused checks and local closure

Agent-run evidence:

```text
p108_module_execution: 5 passed; 0 failed; 1089 filtered out; 32.80s
```

The focused tests use small hand-assembled modules and the real guest ankald
built by canonical CC_B. They exercise ordinary protected execution and typed
output, repeated runs, explicit authority, receipt/context substitution,
changed current objects/READ access, stale original dependencies, exact-byte
and closed-image revalidation, escaped locals, one-past access and real
placement exhaustion followed by retry. They do not substitute for the
self-hosted C compilation witness. The full Rust test target, including that
expanded witness, built successfully. Existing warning cleanup remains deferred.

Developer-run closure evidence, 2026-10-17:

```text
CC2_0 ready: code=148984 backing=148984
CC2_1 == CC2_2: code=168888 backing=168888 entry=166200
protected-module link: modules=2 frames=4 code=3336 metadata=2048 entry=0
protected-module publication: epoch=3 dependencies=2 rights=READ
protected-module execution: exit=0 output=[65,0,255,66] receipt=matched
protected-module rejection: escaped-local=ProtectionFault output=[]
protected-module rejection: one-past=ProtectionFault output=[]
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1093 filtered out; finished in 249.49s
```

The escaped-local fault at PC `0x28` and one-past fault at PC `0x298` are
required negative outcomes. The later compiler rejections and protection
faults in this acceptance run are also intentional hostile cases; the test's
final status is success. The corrected root-RET failure at `0x6e0` is gone.

The acceptance command, retained for future changes to this path, is:

```sh
cargo test --lib \
  anka64::userspace_rebuild::tests::p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address \
  -- --exact --nocapture --test-threads=1
```

No test rerun is required for the subsequent documentation consolidation. If
a fresh full-suite checkpoint is desired before merge, use
`cargo test -- --test-threads=1` and record it separately from the full run plus
successful corrected acceptance. The four-piece module checkpoint is complete;
broader service rebuilds, persistent source/tool receipts and Phase 10's
CPU-to-HTTP rebuild closure remain separate work. This acceptance does not close
all of Phase 10.8 or the final “Anka64 is alive” rebuild milestone.

<a id="dn-70"></a>

## DN-70 — Hardware direction deferred; timing/cache contracts required

**Decision, 2026-10-17: record native FPGA/hardware realization as a future
direction. Do not start hardware implementation now.** The active work remains
the software reference architecture, self-hosted toolchain and software
“Anka64 is alive” closure. Hardware work does not enlarge the completion scope
of Phase 10.7 or the current Phase 10.8 protected-module checkpoint.

Execution timing and caches introduce additional security obligations beyond
architectural value correctness, bounds and authority checks. Future hardware
work must begin with substantial Kleis specification/refinement of observers
and permitted information flows, cache hits/fills/evictions and metadata caches,
request pipelines, revocation and relocation ordering, shared-resource
contention, coherence/DMA, and protected state across context switches/reset.
Timing noninterference must be formulated over observable execution traces
under explicit assumptions; existing functional tests are not evidence of that
property. Optional speculation/prefetch must be covered if introduced.

The consolidated [future FPGA architecture](ARCHITECTURE.md#future-fpga)
records the two logical memory regions, fabric request path, architectural
comparison, metadata scaling, Mermaid diagram and timing/cache proof
obligations. Cache partitioning, flushing, deterministic scheduling and a
cache-free prototype remain alternatives for later evaluation. No mitigation,
board, clock target or hard real-time promise is selected by this decision.

This update records scope and future work only. It adds no RTL, Kleis theory or
test gate, and changes no executable code. The 1094-test software run was still
in progress when this deferral was recorded; its subsequent result and probe
correction are recorded in DN-69. Hardware theory work itself will begin only
when that direction is explicitly resumed.

### Hardware candidates and sizing questions retained for later work

The earlier board discussion is retained as research context, not a purchase
recommendation or a confirmed fit for Anka64 RTL:

| Candidate discussed | Possible role | Questions before selecting it |
|---|---|---|
| Artix-7 XC7A200T, PA200T-StarLite class | A future native core without depending on a hard ARM processor | Actual chip, DDR reference design, schematics, pin constraints, tool support and licensing |
| Zynq-7020 | Fabric experiments and bootstrap support | Every ARM/DDR/debug path must be accounted for; running the Rust runtime on ARM is not native Anka64 execution |
| Kintex UltraScale+ XCKU5P | Larger core count or additional I/O | Memory-controller support, board documentation, clocking, licenses, power and cost |

Before purchase or integration, obtain schematics, memory part numbers, XDC
pinout, clock/reset plan, JTAG procedure, tool compatibility and a working DDR
reference design. No native Anka64 utilization or maximum clock frequency has
been measured. Object capacity must count metadata, capabilities, placement,
fragmentation and bandwidth; one million objects is only a sizing scenario.

### Conditional bring-up gates

These are future stages, conditional on an explicit decision to resume hardware:

| Gate | Required work and evidence |
|---|---|
| 0 — formal contracts | Specify and prove the selected observer/timing/cache model, non-bypass, authority, lifecycle, placement and transaction ordering contracts. Include hostile witnesses and an RTL refinement relation. |
| 1 — board and memory | Bring up clocks, reset, JTAG/UART and memory diagnostics. Inventory every bus master and debug path; define object-store, conventional-RAM and fabric-private metadata windows and their permitted masters. A small on-chip prototype may precede external DDR. |
| 2 — fabric RTL | Implement protected metadata, capability/domain checks, placement lookup, ordering and fault behavior. Use existing adversarial programs as conformance vectors against the Rust reference; denial must cause no prohibited memory effect. |
| 3 — native core and boot | Execute an image on a native Anka64 core through authorized object accesses. Auxiliary loading by a PC or ARM does not substitute for native execution. |
| 4 — additional agents | Integrate DMA, storage, network and additional cores through the same fabric; check races, coherence, revocation visibility, invalidation and isolation under contention. |
| 5 — physical validation | Establish RTL-to-architecture correspondence, synthesis, place-and-route and clock timing closure; run on-board adversarial tests and analyze timing/cache/contention/power/debug channels, including effects outside the formal model. |

### Future demonstration criteria

- A native Anka64 core executes on FPGA fabric.
- Two protection domains obtain distinct authorized/denied outcomes for the
  same object; bounds, permissions, stale generations and revocation are enforced.
- Object movement changes placement without changing identity or creating authority.
- Sealing and revocation have the required effects on subsequent requests.
- CPU, boot, debug and DMA paths are audited for bypass of the fabric.
- Logs, synthesis resources, timing measurements, assumptions and outstanding
  proof obligations are recorded with the result.

Functional conformance, clock timing closure and timing confidentiality are
separate evidence. No hard real-time behavior is promised; a deadline cannot
justify bypassing an authority check.

### Implementation anchors for future refinement

- `src/anka64/state.rs`: object, agent and domain identities, capabilities,
  lifecycle and permissions.
- `src/anka64/fabric.rs`: authority, translation, revocation and transactions.
- `src/anka64/placement.rs`: page-granular contiguous placement independent of authority.
- `src/anka64/core.rs`: protected pointer-kind, call/return and event-context state.
- `theories/`: architectural contracts to inspect and extend before hardware claims.

The separate FPGA proposal has been absorbed into ARCHITECTURE.md and this note.
The separate headless-web proposal is retired; the single-trust-anchor direction
is stated briefly in ARCHITECTURE.md. Neither consolidation starts implementation.

<a id="dn-71"></a>

## DN-71 — Shared allocation, whole-stack review, and compiler resource growth (Phase 10.8)

**Status: all four A1 pairs accepted on the developer machine, 2026-10-19;
Undertaker asynchronous-reclamation refinement developer-accepted, 2026-10-20;
A2.1 registry/reservation foundation developer-accepted, recorded 2026-10-22;
A2.2 bounded placement/reservation Kleis refinement developer-accepted,
recorded 2026-10-23; A2.2 Rust developer-accepted with the full single-threaded
library suite: 1134 passed, 0 failed, 0 filtered out in 1149.73s, recorded
2026-10-23. A2.3 Fabric/shadow/initialization refinement developer-accepted on
2026-10-24: 192 positive witnesses (30 quantified laws) and 162 explicitly
disproved hostile witnesses. A2.3.1 fixed Fabric/shadow storage and private
attachment are developer-accepted: 17 new tests passed in 0.01s and the
144-test focused shared-component regression passed in 0.09s (including those
17), recorded 2026-10-24. A2.3.2 private byte/tag initialization is also
developer-accepted: 18 new tests passed in 0.02s and the 162-test focused
regression passed in 0.10s (including those 18). A2.3.3 conditional protected
heap-cell operations are developer-accepted: 22 new tests passed in 0.01s and
the 184-test focused regression passed in 0.13s (including those 22).
A2.3.4 attached-failure closure is developer-accepted: 17 new tests passed in
0.02s and the 201-test focused regression passed in 0.13s (including those 17).
A2.3.5 concrete worker/terminal-work Kleis refinement is developer-accepted at
197 positive witnesses (23 quantified laws) / 172 explicitly disproved hostile
witnesses, recorded 2026-10-24. A2.3.5a fixed worker roles and per-job leases are
developer-accepted: 21 new tests passed in 0.02s and the 222-test focused
regression passed in 0.13s (including those 21). A2.3.5b bounded CPU backend
registration/pinning is developer-accepted: 21 new tests passed in 0.03s and
the 243-test focused regression passed in 0.16s (including those 21), recorded
2026-10-24. A2.3.5c bounded execution/cancellation, terminal consumption and
current drain census are developer-accepted, recorded 2026-10-25: 22 new tests
passed in 0.02s and 265 focused tests passed in 0.17s (including those 22).
A2.3.6 queued-job worker recovery is developer-accepted, recorded 2026-10-25:
21 new tests passed in 0.01s and 286 focused tests passed in 0.16s (including
those 21). A2.3.7 authority retirement is developer-accepted: 21 new tests
passed in 0.02s and 307 focused tests passed in 0.19s (including those 21),
recorded 2026-10-25. Complete trusted cleanup/reuse is now developer-accepted:
92 positive / 79 explicitly disproved hostile witnesses; 19 new tests passed
in 0.01s and 326 focused tests passed in 0.19s, including those 19. No full
1333-test run was reported. A3 C malloc/free is now developer-accepted: the
earlier full run passed 1344 tests (including all twelve A3 unit tests) and failed
only the new direct-entry fixture. After its correction, the shared CC2/C
integration rerun passed: 1 passed, 0 failed, 1344 filtered out in 1026.53s,
reported 2026-10-25. It covers ordinary malloc/free, typed I/O, hostile aliases,
cross-module heap return and independent A/B/C reuse. The new Kleis pair passed
locally before implementation at 52 positive / 43 hostile; no developer rerun
of that pair is reported. These are separate results, not one green 1345-test
suite. A4's required source review is delivered below, with bounded follow-ups.
R1's local-frame initialization refinement is now developer-accepted; recorded
2026-10-27: Kleis 151 / 118, 16 focused Rust tests, shared CC2 integration in
1008.62s, and the full 1361-test suite in 2446.84s all pass.** The original compiler-resource plan
merged to `main` after the protected-module checkpoint. The revised order is
general protected allocation, its C `malloc`/`free` interface, a required
whole-stack review, then compiler resource growth using that shared foundation.
The compiler is an ordinary allocation client; multiple agents must be able to
compile concurrently. The allocation lifecycle, concrete ABI, residual-data
isolation and storage/reclamation pairs have developer-confirmed evidence:
579 positive witnesses and 386 explicitly disproved hostile assertions. The
Undertaker pair below adds 257 positive witnesses and 171 explicitly disproved
hostile assertions, developer-confirmed on 2026-10-20. All five pairs now have
developer acceptance across the reported focused runs. A2.1 below adds executable
bounded metadata and quota reservations. The sixth pair below refines bounded
placement and the compound reservation; the developer confirmed its 215 positive /
180 hostile gate run, recorded 2026-10-23. All six allocation pairs now have
developer acceptance across focused runs. A2.2 Rust below adds private physical
and virtual extent custody and exact cancellation. The seventh pair (A2.3)
is now developer-accepted, bringing the accepted focused-run totals to 1243
positive / 899 hostile. The eighth pair (A2.3.5) brings accepted evidence across
focused runs to 1440 positive / 1071 hostile; no new combined run is claimed.
A2.3.1 connects private Fabric metadata without authority publication, and
A2.3.5a adds worker/lease metadata, A2.3.5b adds pinned CPU request records,
and A2.3.5c connects their synchronous software effects and terminal consumption.
A2.3.6 adds recovery/reassignment of queued jobs after exact worker fencing.
A2.3.7 adds developer-accepted authority retirement after current drainage and
exclusion checks. Developer-accepted cleanup/reuse connects retired-stage
recovery, bounded byte/tag scrub, extent release and payload refunds. This brings
developer-accepted evidence across focused formal runs to 1532 positive / 1150
hostile; no combined run is claimed. A3 now connects C malloc/free, production
publication, owned guest results and process-exit cleanup. Its independent-client
and toolchain acceptance now pass. A4 has reviewed the delivered source and
recorded bounded follow-ups. Earlier A2 deferrals describe their delivery
checkpoints; A3/A4 provide the current integration status.
Keep the plan here and the current
status in ARCHITECTURE.md; do not create another standalone note.
Current development branch: `feat/anka108-protected-allocation` (developer-confirmed).

### Goal and completion boundary

A developer should submit a valid program in the supported AC2 profile without
predicting its output size or editing compiler capacity constants. The build
path should size resources or grow and retry automatically within a declared
build budget. Available memory, the supported language/calling convention and
representable instruction/format ranges still determine what can run. Resource
failure must identify the exhausted resource and budget without publishing a
partial artifact or disturbing an earlier successful publication.

The architectural foundation is a reusable allocation and lifetime service for
ordinary programs, including compilers, services and other agents. Expose the
supported C allocation interface before making compiler-specific growth policy
the next executable milestone. Arena growth can technically be implemented
without C `malloc`; the chosen order provides the common programming environment
that the complete computation stack needs. It does not require a new optimizer
or IR/register allocator, nor reopen completed Phase 10.6/10.7 scope. The eventual
closure client remains the source rebuild of the real service stack.

### Shared allocation foundation: formal contract first

The first allocation profile may be process-private, but its resource service
must support independent concurrent clients from the outset. The contract must
specify:

- checked sizes, alignment, size-zero behavior, allocation-failure results and
  the supported `malloc`/`free` ABI, including `free(NULL)` and invalid, interior,
  foreign or duplicate frees; do not silently claim full libc compatibility;
- protected allocation identity and owner process/domain incarnation, current
  generation, bounds and permissions; heap allocations have individual lifetimes
  and may be freed in arbitrary order rather than inheriting local-frame LIFO;
- per-client budgets and atomic global reservations, including allocator
  metadata, rounding, retained objects and temporary copies; failure must not
  overcommit backing or leave partial grants/reservations;
- trusted issuance of protected pointers, byte access and pointer-cell behavior,
  invalidation of every stale alias on release, and safe backing reuse after
  admitted work is accounted for; saved event contexts cannot restore validity;
- failure, cancellation and process-death cleanup without disturbing another
  client's allocations; include generation exhaustion and partial-admission
  rollback, and separate safety from any scheduler/fairness assumptions;
- composition with PhysicalPlacementManager, VirtualLayoutBuilder, Fabric
  authorization and commit checks. An ordinary process must be able to use the
  service; a host-only compiler wrapper is not the completed allocation API.

No handoff should introduce an unrelated allocator to work around placement
constraints. If the initial heap profile forbids exporting allocations to other
domains or DMA, enforce that boundary. Cross-domain ownership transfer and DMA
borrows require their own refined contracts before they are enabled.

### A1 accepted model and proposed concrete ABI

This handoff supplies `anka108_allocation.kleis`,
`anka108_allocation_abi.kleis`, and the memory-initialization refinement described
below, each with a hostile counterpart. It specifies
the initial process-private profile for multiple independent concurrent clients.
It adds no Rust or C implementation. The current 10.7 local-frame machinery
continues to operate as before; heap lifetimes must not be implemented by
pretending every allocation is a LIFO local frame.

**Allocation identity and storage.** Keep the existing protected two-word
payload: `(generation << 32) | one_based_slot`, followed by byte position.
The protected kind is separate trusted state. Heap and local pointers must use
one collision-free registry namespace, with a trusted record class distinguishing
them. Heap records bind process slot/incarnation, execution context, domain,
logical length, backing identity, rights, current generation and lifetime phase.
The 32-bit generation never wraps; exhausted slots remain retired. Numeric
payloads, including a copied address, cannot reconstruct a protected pointer.

The first physical policy uses one page-rounded backing object per allocation,
placed through PhysicalPlacementManager and a reusable virtual arena integrated
with the placement module and VirtualLayoutBuilder. The exposed
logical length is the requested length. A one-byte allocation does not grant
access to the rest of its page. Alignment is at least 16 bytes, sufficient for
the present AC2 scalar, struct and protected-pointer types. Small-object
suballocation remains a later refinement. The current VirtualLayoutBuilder is
monotonic and does not provide reusable heap holes; the reclamation refinement
below makes reusable virtual ranges an A2 acceptance requirement. Keep the
existing image/stack/trap layout reservations disjoint from the heap arena.
Finite virtual capacity and fragmentation remain explicit admission outcomes.

Before publication, initialize the whole reserved backing extent to zero and
clear every overlapping physical pointer-cell tag. This prevents a new owner
from observing old payload or importing old pointer authority. Reserve metadata
and pointer shadow storage as well as payload. Heap pointer storage admits an
aligned, fully contained 16-byte cell under its live heap owner, rather than a
local-frame manifest. Preserve existing source-token authentication, coherent
typed transport, raw-write tag clearing and object/generation/offset cell keys.

**Admission and charging.** Use one shared serialized decision for global and
per-client reservations; per-process locking alone is insufficient. A client
account is bound to its exact incarnation, not just a reusable PID. Charge actual
rounded backing, metadata, shadow storage, staged copies and retained resources;
preallocated pools are charged once, and reusable metadata must not be charged
twice. Byte availability does not imply a metadata slot, an encodable pointer,
or a virtual extent is available. Any such admission failure returns capacity
failure without publishing a pointer or leaving visible reservations/grants.
The witness's 256-byte metadata cost is illustrative, not a prescribed Rust
layout. A2 must derive charges from its bounded resource representation.

Allocation publication rechecks the current owner and ledger, then commits
records, exact RW-only mapping/grants, counters and the pending pointer result
together. Broader grants or raw-address paths must not bypass heap lifetime
checks. Staged resources remain private until commit and are unwound on failure.
This requires extending current runtime paths; flags in the theory are not a
substitute for performing these checks.

**Release and reclamation.** A whole-allocation base alias may free its heap in
any order. Null is a no-op. Interior, narrowed, foreign, local-frame, forged,
stale and duplicate frees fault before that operation mutates the allocator.
Subsequent process-fault cleanup is a separate transition and may retire that
process's remaining allocations. Closing invalidates
admission through every surviving alias, including saved events and spills.
Already admitted operations remain accounted for until their exact terminal
completion or completed cancellation. Their commits still require current Fabric
authority. Closing retains charges and backing; timeout alone cannot reclaim it.
`free` returns only after retirement, grant/map/tag removal, unplacement and
accounting commit. Nonreclaimable metadata remains charged globally even when
its former client exits. The initial profile permits no heap export to other
processes, shared threads, DMA or raw-address interfaces. These are enforced
admission restrictions, not assumptions about cooperative callers.

Process death closes only that exact incarnation's heap records and follows the
same drain/reclaim rules. A failed or terminated client must not release another
client's records, corrupt its bytes, reset its budget or revoke its authority.
The model proves safety conditions; progress still depends on terminal work and
scheduling assumptions. It does not prove SMP memory ordering or device drainage.

**Concrete interface proposed for implementation:**

| Operation | Application/trap inputs | Trusted result |
|---|---|---|
| `void *malloc(int bytes)` | AC2 64-bit scalar byte count; trap R0=21 (`SYS_MALLOC`), R1=bytes, R2..R5=0, pairs 0/2/4 scalar | R0/R1 protected pointer at position zero, or canonical untagged zero/zero; R2=status, R3=0 |
| `void free(void *pointer)` | C argument in R0/R1; typed PMOV into R2/R3 before overwriting R0; trap R0=22 (`SYS_FREE`), R1=R4=R5=0, pairs 0/4 scalar | Scalar R0=R1=0 after valid retirement, or immediately for canonical null; invalid free is ProtectionFault |
| Allocation status | Status remains outside the returned pointer pair | 0=success (including size zero); 1=capacity/admission failure; 2=negative or unrepresentable signed size |

`malloc(0)` returns NULL without consuming allocation resources. Positive
requests are bounded by the representable nonnegative AC2 `int` and admitted
resources. The initial C surface is the supported subset, not a full libc claim:
`size_t`, errno, realloc/calloc, over-aligned allocation, shared heaps and
asynchronous borrows are not silently supplied. Typed `void *`/object-pointer
conversion must preserve identity, position, bounds and kind. No integer-to-
pointer conversion is introduced. The ordinary ABI v2 pointer return stays
R0/R1, with normal typed expression moves/spills in the compiler.

The runtime currently exports **scalar syscall results only**. A2 must introduce
a distinct trusted pointer result tied to the intact saved syscall image, exact
process incarnation/context/domain, nonreused event identity, and the newly
published allocation slot/generation. A result is consumed once. Reject IRQ
injection, handler scratch, wrong/consumed frames, another allocation's result,
stale lifetimes and scalar overlays on either pointer word. Return must install
both words and kind atomically. Other saved registers/kinds, flags and return
authority retain the established event rules. Generic `write_syscall_result`
does not gain permission to manufacture pointers.

**Evidence and scope.** On 2026-10-19 the supplied Linux Kleis binary and stdlib
passed 171 allocation witnesses and 116 ABI witnesses; all 125 and 81 hostile
assertions respectively were explicitly disproved by Z3. The developer confirmed
these same counts on 2026-10-19. This is model acceptance, not verification of new Rust/C.
The witnesses include global admission races, arbitrary free order, retained
charges during drainage, exact completion identity, close → finish → retire →
reuse with stale-alias rejection, process-incarnation isolation, storage-cell
bounds and protected result delivery. Quantified laws cover budget bounds,
logical access bounds, unchanged fields/accounts and nonresurrection on reuse.

The model uses explicit transitions and pointwise frame rules, with conditional
implementation obligations for full extent scans, exact ledgers, preparation,
Fabric grant/map coverage, no bypass, and physical synchronization. These checks
must refer to the same current request and resources. They are trusted-side
obligations, never application-supplied certificates. This handoff does not prove
the future allocator algorithm, a complete C semantics, a whole-machine
refinement, hardware behavior or the future cross-domain ownership protocol.
Further structural refinements discovered while choosing concrete storage or
teardown mechanisms must pass their gates before those mechanisms are enabled.

Run all three A1 gate pairs, including the residual-data isolation refinement:

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis \
  --only-allocation
```

Imports load the needed existing definitions; this option does not rerun every
unchanged independent example suite. No Rust regression or CC2 bootstrap rerun
is required for this formal-only handoff.

### A1 refinement: residual-data isolation at every new private lifetime

**Required invariant:** a new private allocation must expose no payload or
pointer authority inherited from a previous lifetime. A malicious program can
obtain a perfectly valid new pointer and read its allocation; stale-pointer
rejection alone does not address that attack. The requirement applies even when
the new owner is the same process, and includes local-frame reuse. It is a
zero-before-new-authority policy, not an immediate zero-on-free policy.

`anka108_memory_initialization.kleis` and
`anka108_memory_initialization_false_witnesses.kleis` formalize this rule. The
initialization state is separate from the allocation lifetime state. For a
reused extent, old lifetime retirement, terminal CPU/DMA accounting and effective
exclusion of every former access path precede scrubbing. Reserve the storage
privately, initialize its complete reserved extent and clear physical pointer
tags, then publish new authority. The same rule applies to fresh backing; boot
or host memory being incidentally zero is not the contract.

The model uses a trusted completed-prefix cursor advanced only by exact scrub
chunks. Each committed chunk zeroes its bytes and clears overlapping pointer
tags together. Positive quantified laws establish the byte and tag prefix
invariants inductively. A completion receipt binds reservation, backing object,
physical base/extent, new lifetime, owner incarnation identity and current
mutation version. Partial work, skipped padding, another clean allocation's
receipt, an intervening write, or early readers/writers cannot authorize
publication. Failure or cancellation keeps incomplete storage private. Never
place a partially initialized extent on a pool advertised as ready for exposure.

The principal witness starts with an arbitrary old secret and old pointer tag,
performs two actual scrub transitions, publishes the new lifetime, and permits a
fresh valid read. Every logical byte reads zero and no old kind survives. A
two-execution quantified witness holds allocation controls fixed, varies all
possible prior byte values, and proves identical resulting bytes. Neighboring
storage is unchanged. A delayed old-epoch write cannot contaminate the published
allocation; pending old CPU/DMA work prevents initialization from beginning in
the first place. Hardware must separately refine the terminal-drainage and
visibility assumptions; incrementing an epoch cannot physically stop a device.

For code/data images, parameter spills or explicit local initializers, initialize
clean storage with the authorized **new** source values before exposure. The
model includes a pointwise overlay law preserving independence from prior
contents. It does not zero intended program contents after they have been
installed, and ordinary byte initialization never creates pointer kind.
Intentional sharing or ownership transfer of existing contents is a different
operation requiring its own authority/lifetime contract.

Observed current paths and implementation obligations:

| Path | Current behavior | Required follow-through |
|---|---|---|
| New heap API | Trusted cleanup/reuse, A3 unit tests and shared-producer C/module/A-B-C acceptance now pass. | A4 review delivered below; track R1 local initialization, compiler budgets and ownership/DMA findings. |
| Protected local frames | `retire_pointer_frame()` invalidates lifetimes and removes storage kinds; frame entry does not scrub payload | Add a bounded formal-first frame-initialization refinement and implementation; order scrubbing before new-call argument spills/local initializers, preserve live parent/control storage, and validate same-address reuse with a fresh valid local pointer |
| Recycled process stacks/trap pages | Reuse helpers zero returned extents before new grants; reclamation itself does not wipe | Check complete extent, tag clearing, ordering and error propagation against this contract in the stack review |
| Generic object/placement release | `destroy_object()` explicitly does not scrub; placement release does not wipe | Require initialization at every later private publication; object destruction alone is not a clean-memory certificate |
| Loaders and explicit initializers | Several paths zero object contents before writing the new image | Audit exact coverage, padding that may later become visible, publication ordering and current-input provenance |

The known local-frame gap is an explicit pending implementation obligation;
neither these witnesses nor completed Phase 10.7 lifetime checks establish that
the current runtime already enforces the new uniform confidentiality rule. Fix
the affected frame path in a bounded piece before claiming this guarantee for
ordinary protected C applications. Carry the remaining path inventory into A4;
the required post-malloc whole-stack review is now delivered in A4 below.

**Local evidence, 2026-10-19:** 113 positive witnesses passed and all 72 hostile
assertions were explicitly disproved by Z3. Combined with the unchanged two A1
pairs, recorded A1 evidence is 400 positive / 278 hostile witnesses. The new
pair was run independently; no Rust or long CC2/regression run was required.
These are conditional byte/pointer-state model results, not verification of the
runtime, cache/timing noninterference, copies elsewhere, or physical erasure.
The developer subsequently confirmed all three A1 pairs with the same counts
on 2026-10-19; the earlier developer-acceptance step is complete.

To check only this added refinement:

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis \
  --only-initialization
```

### Reusable extents and bounded metadata: reclamation refinement

`anka108_allocation_reclamation.kleis` and its false-witness counterpart refine
storage reuse before A2 implementation. The existing lifetime/initialization
gates remain prerequisites. This pair adds no Rust/C allocator and no live-object
compactor. Its acceptance scope is exact extent transformations, stable identity
across metadata eviction, bounded accounting and allocation/free cycle laws.

**Physical and virtual arenas.** Maintain a sorted, disjoint partition of each
arena into free, reserved, live and closing extents. Allocate a prefix of one
free extent and retain its exact suffix; remove an empty suffix. On completed
release, return the exact recorded span and merge only immediately adjacent free
neighbors. Quantified coverage and separation laws establish that splitting or
joining neither duplicates nor loses bytes and does not swallow another live
extent. A two-client trace frees A before B, rejects joining across live B,
then frees B and recovers the whole original arena. Sufficient total free bytes
alone do not establish that a contiguous request fits.

Apply the same algebra to each exact owner's virtual arena. A new allocation
can reuse an old virtual address only after its former mappings and authority
have retired; its protected generation changes and initialization remains
mandatory. The current physical manager already coalesces adjacent free extents;
extend its composition and the existing placement module for reusable virtual
ranges rather than introducing per-client raw-address arithmetic. A2 must couple
physical/virtual reservations, registry capacity and ledger admission under one
shared nonwrapping revision, preserving all selected state on compound failure.
Physical address, virtual address and object/handle identity remain distinct.

**Metadata storage policy.** Use a bounded stable directory for the common
heap/local pointer namespace. Each one-based slot retains its last 32-bit
generation and free/reserved/live/closing/permanently-retired state. Generations
never reset or wrap. The complete directory and arena-index capacity are charged
once as infrastructure. Retiring a generation-exhausted slot consumes an entry
already in this directory; it must not create an unbounded separate tombstone
list. Capacity exhaustion is explicit and cannot be bypassed by a new page.

Bulky allocation records can occupy reclaimable pages. Evict a page only when
the exact census of *all* its slots contains no reserved, live or closing record,
including local records, and no metadata reader or staged writer holds it.
Empty or permanently retired slots still retain their identity history in the
directory. Rehydration restores that same history and confers no authority;
subsequent publication uses the next generation and the existing initialization,
Fabric and pointer-result gates. Never compact live slot numbers. The model
prescribes these storage invariants, not Rust struct sizes or a page width.

Fabric object/placement map entries may be removed by exact key after teardown;
unselected entries are unchanged. Published ObjectId destruction does not rewind
the identity counter. Fresh ID issuance must reject exhaustion. An object's
numeric ID is not an array index requiring all preceding IDs to remain stored.
Removing a map entry or clearing a vector is not evidence that all of its backing
capacity has been returned: retained capacity remains charged until actually
released or accounted for once as a reusable pool. The current low-level
`destroy_object` helper alone is not the complete coordinated reclamation path.

**Bounds and release resources.** For a maximally coalesced partition with K
nonfree extents there are at most K+1 free extents. Prefix-induction witnesses
establish the count bound; reserve index storage for the configured maximum
claims and the additional boundary hole. Reserve required release bookkeeping
at allocation admission, so freeing does not depend on an unbudgeted allocation
for temporary free-list storage. A2 must derive actual directory, record, shadow,
index and scratch costs from the selected bounded representation. Do not reuse
the earlier illustrative metadata charge as a measured Rust footprint.

Charge fixed infrastructure, occupied backing, resident metadata and other
retained/staged storage exactly once. Closing or outstanding work retains the
charge. A completed exact release refunds backing; successful metadata eviction
refunds only bytes actually returned. The cycle law restores reusable backing
and virtual geometry while preserving advanced generations/revisions. These
step invariants support bounded repeated churn under the model assumptions;
they do not promise infinite successful allocations with finite generations,
successful allocation despite fragmentation, scheduler progress, or a bound on
unmodeled logs/caches. Those resources remain in the required A4 inventory.

**Implementation obligations and proof boundary.** Derive the census and ledger
from actual current records under serialization, not caller assertions. Maintain
the global sorted partition and apply the local frame/separation laws to every
remaining entry. The model's fixed-width, pointwise and local transition proofs
do not verify a complete arbitrary-length Rust free-list algorithm. Actual CPU
and DMA terminal completion, mapping/grant/tag removal, initialization visibility,
same-request reservation binding and coherent pointer publication retain their
existing refinement obligations. A2 needs forced-capacity and interleaved-client
runtime witnesses in addition to these model gates.

**Churn acceptance for A2/A3:** repeatedly allocate/free varied page-rounded sizes
and free out of order; recover the original free intervals, reuse virtual holes,
evict/rehydrate record storage, and reject old register/spill/event aliases. Track
free bytes, largest free extent, active/reserved/closing records, reusable/retired
slots, resident metadata and all charges. With fixed demand and terminal work,
storage must return to a declared bounded baseline; configured capacity or epoch
exhaustion must fail explicitly. Include failure between preparation steps and
process death while another client continues. Retained infrastructure need not
shrink to zero, but its bound and charge must be explicit.

Moving live objects and small-object suballocation are later separate gates.
`Fabric::move_object` currently changes translation without copying payload,
clears pointer-cell metadata through placement changes, and can lose the old
mapping if the new placement is rejected. It is not a compactor. A future
relocation protocol needs quiescence/pinning, payload and protected-kind
preservation, transactional placement publication, rollback and safe old-backing
release before it can replace that helper for live compaction.

**Focused validation, 2026-10-19:** the supplied Linux Kleis binary and stdlib
passed **179 positive witnesses**, including 32 quantified laws, and explicitly
disproved **108/108 hostile assertions**. No unknown/evaluation failures count
as passing evidence. The developer subsequently accepted this pair on
2026-10-19, bringing all four A1 pairs to **579 positive / 386 hostile** witnesses.
The previous three pairs were not rerun for that formal-only extension; all four
are rerun with the Undertaker gate in the 2026-10-20 checkpoint below. No Rust, C,
CC2 fixed-point or full regression tests were needed because no runtime or
compiler source changed.

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis \
  --only-reclamation
```

`--only-allocation` now includes lifecycle, ABI, initialization, reclamation and
Undertaker asynchronous-reclamation pairs.

### Undertaker: asynchronous reclamation after process death

`anka108_async_reclamation.kleis` and
`anka108_async_reclamation_false_witnesses.kleis` refine the asynchronous work
lifecycle before A2 runtime changes. The first profile returns whole page-backed
reservations. It does not introduce a small-object allocator or resolve the
separate protected-local-frame initialization gap.

The death transition can finish while cleanup remains pending. It must first
close admission and record every cleanup obligation atomically. The required
order remains **close admission/register work → drain old operations → retire
old authority → scrub bytes and pointer tags → establish clean storage → return
backing → authorize a separately admitted new lifetime**.

**Reserved records and atomic closure.** Reserve one durable cleanup-directory
slot before publishing each allocation, and an owner record before admitting a
process. The bounded directory itself is the queue: no allocating enqueue or
fresh job ID is needed at process death. Under one serialization boundary, close
the exact owner incarnation and change all its armed records to queued. An exact
current directory census moves that owner's credits from armed to pending;
already-pending records are not counted twice. Pointwise laws preserve other
owners, and prefix-count induction preserves the bounded census. A full queue
can still process death using its pre-reserved credits; it rejects new allocation
admission. A process with no allocations can also terminate when all slots are
occupied. The process fence denies admission before a worker visits any row.

The implementation must derive the census from all current records, preserve
unique keys and disjoint custody, and make the owner fence, row changes and count
updates one trusted transaction. The local model laws do not verify a Rust
arbitrary-length directory scan or durable-store algorithm. Required record and
release capacity must be reserved during admission, including worker scratch and
retained owner/account metadata, rather than discovered missing at death.

**Identity and asynchronous stages.** A job binds its nonreused job ID, owner
incarnation/context/domain key, protected slot/generation handle, object,
exclusive backing reservation, physical base and complete reserved span.
Notifications confer no authority. Repeated notifications acknowledge the
existing obligation without adding work or resetting it. A stale notification or
completion cannot select a new owner, generation, object or same-address
reservation. Numeric job/handle fields are trusted lookup data, not a way for a
guest to construct protected pointer kind.

| Stage | Required state and permitted transition |
|---|---|
| Armed | Allocation is live; its cleanup record and queue credit already exist. |
| Queued/draining | Owner admission is closed; exact old CPU/DMA tickets can become terminal. |
| Authority retired | Old grants/maps and access paths are gone; terminal writes are visible; backing remains exclusively reserved and charged. |
| Scrubbing | One authenticated scrub ticket per job; only terminal successful chunks advance the clean byte/tag prefix. |
| Clean/quarantined | The entire reserved extent is clean and visible; custody and charges remain until exact return. |
| Released | One atomic commit returns the recorded extent, consumes the pending record and refunds only actual returned backing. |

The lifetime projection refines A1 closing without changing old counts or
generation. Authority retirement uses `conc107_retire` while storage stays held.
This deliberately separates retirement from the earlier synchronous
retire/unplace/refund path. Do not call retirement twice or refund at its first
step. No change to those earlier theory definitions or runtime helpers is made.

**Worker leases and exact scrub tickets.** Claiming work leaves its record in the
pending census. The nonwrapping lease epoch and worker identity exclude a second
worker. Each scrub submission also consumes a fresh nonwrapping **operation
number**, even if it is later cancelled. A completion binds the job, lease,
worker, operation, mutation version, start and amount. Version and range alone
are insufficient: a cancelled attempt could otherwise masquerade as a retry of
the same range within the same worker lease. A successful completion consumes
its active ticket, zeros bytes and overlapping pointer tags together, and
advances the prefix and mutation version with the same decision.

Submission, partial execution, failed completion and requested cancellation do
not establish a clean prefix. A terminal failed chunk may be retried with a new
operation number after its exact ticket is consumed. Partial device effects must
stay within the submitted uncompleted range. The former lifetime's accepted CPU
and DMA tickets use the existing exact terminal-completion contract. Epoch
increments and timeouts do not physically drain a controller.

**Failure and recovery.** Failure changes the lease to revoking, keeping its job,
stage, identities, counters, reservation and charges. Further scrub admission is
closed immediately. Reassignment requires all old scrub operations to be
terminal or terminally cancelled, the old worker fenced, and its memory effects
visible. Recovery invalidates the old receipt version and resets the clean
prefix. Scrubbing or clean records return to authority-retired state; queued
records still need old-work drainage. A new claim advances the lease epoch. The
operation sequence is retained across cancellation and worker recovery. Delayed
old completions cannot authorize bytes, clean receipts or release.

Here **durable means retained by the trusted owner/cleanup directory across
worker failure and restart**. The worker must not be the sole owner of the record
or account. This is not a filesystem persistence protocol or a proof of recovery
from host/kernel reset or power loss; those need separate refinement. If trusted
maintenance writes are permitted, they must atomically invalidate the prefix and
version before any receipt can be consumed. The first implementation can instead
exclude those writes entirely.

**Accounting and new authority.** Pending includes queued, leased, retired,
scrubbing and clean jobs. None refunds storage. Fixed queue/directory capacity is
charged once as infrastructure; payload, resident metadata and retained capacity
remain separate ledger categories. Exact release refunds only the backing
actually returned. Clean pools remain occupied and charged. No record or owner
account may disappear while its obligation survives. Epoch, operation, version
or capacity exhaustion fails closed; it does not justify dropping work.

An Undertaker completion grants no pointer or execution authority. A new private
lifetime must still satisfy its own exact reservation/owner/generation binding,
initialization and ordinary allocation-publication gates. This first refinement
does not authorize replaying an old cleanup receipt as a new initialization
receipt. Avoiding a redundant scrub through a clean-pool transfer requires an
explicit binding/visibility refinement. Later suballocations and local-frame
reuse still require their own initialization; clearing a page once is insufficient.

**Progress and proof boundary.** Quantified laws give a finite lexicographic
measure over phase, outstanding CPU/DMA counts and remaining bytes. Terminal old
operations, phase changes and committed scrub chunks decrease it. Claim,
submission and idle steps may stutter; recovery can increase it. Eventual release
requires eventual fault-free service, terminal devices, successful scrub work,
fair scheduling and completion delivery, and sufficient nonwrapping counter
headroom. Permanent device errors retain quarantine. These requirements are
explicit implementation/environment obligations, not axioms or a proved temporal
scheduler theorem. Idle-only service and a permanently stocked clean pool under
arbitrary demand are not guaranteed.

The constructive trace closes an owner at full reserved queue capacity, drains a
CPU and a DMA operation, retires authority, scrubs half a page, submits another
chunk, and loses its worker. Recovery is rejected while that scrub is outstanding.
After exact terminal cancellation and fencing, a new worker rescrubs the entire
4 KiB page in two chunks, establishes clean storage and returns it. The other two
pending obligations and their 8 KiB of backing remain charged. Quantified byte
and pointer-cell laws vary arbitrary prior contents, establish zero throughout
the reserved page including padding, and preserve neighboring storage. All
transitions are evaluated in linear `let` bindings; no trace checkpoint is
assumed as an axiom. Four hostile content assertions use equivalent single-point
universal statements to avoid the supplied CLI's costly ground-false trace
expansion; each still requires explicit Z3 disproof.

**Validation, 2026-10-20:** the supplied `kleis-linux-x86_64(10)` (reporting
`kleis 1.0.0`) and `stdlib(8).zip`, with its required Z3 shared library supplied
locally as Z3 4.12.2, pass **257 positive Undertaker witnesses, including 42
quantified laws**, and explicitly disprove **171/171 hostile assertions**. The
complete allocation selection passes **836 positive / 557 hostile witnesses**
across all five pairs. Unknown, errors, missing examples and timeouts do not
count. The developer subsequently ran `--only-undertaker` on 2026-10-20 and
confirmed **257 positive / 171 explicitly disproved hostile assertions**. This
completes developer acceptance of all five pairs across the reported focused
runs; the complete five-pair local run above is separate evidence. No Rust or C source
changed, so no runtime regression or CC2 fixed-point run is claimed or needed
for this formal-only handoff.

Run the new pair only from the repository root:

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis \
  --only-undertaker
```

Use `--only-allocation` for all five allocation pairs. `--only-108` and the default
10.8 selection also include the new pair. The next implementation remains bounded
A2 work against the **software Fabric**. An FPGA zeroing engine must later refine
the same custody, drainage, byte/tag effects, cache visibility and receipt
contract; the current model establishes no hardware erasure or timing guarantee.

### A2.1: bounded registry, accounts and reserved cleanup records

**Local runtime checkpoint, 2026-10-20; developer acceptance recorded 2026-10-22.**
`scoped_pointers.rs` now owns the single fixed-capacity directory for local and
heap identities. The new `scoped_pointers/heap.rs` supplies the metadata/quota
service. This is the first bounded A2 piece, not the completed allocation API.
The existing `Fabric::new` profile still enables only local pointers; configuring
heap account/cleanup capacity and connecting it to process admission comes with
the subsequent service integration.

**Stable directory and existing locals.** All slot, scope, account and cleanup
arrays are allocated at construction with fallible capacity reservation and
never grow. A slot retains its generation even after cancellation or local scope
exit. Local and heap rows consume the same slots and advance the same 32-bit
generation; an exhausted slot stays permanently unavailable in the original
array. No slot compaction, reset, tombstone list or metadata-page eviction is
introduced. The initial representation retains its complete record pool and
charges it once, which satisfies the accepted fixed-pool storage policy.

Local Fabric backing identity now resides in its fixed directory row instead
of the separate `pointer_backings` BTreeMap. Scope ownership also uses the fixed
scope table instead of dynamically allocated maps and per-owner stacks. Local
LIFO rules remain per context; closing a heap neither depends on nor changes
that order. Occupied-prefix bounds keep ordinary frame scans short while the
complete generation directory remains retained.

Frame admission now preflights scope/slot/revision capacity, every backing check,
address arithmetic and the result vector before mutating the registry. It no
longer clones the registry or a backing map for rollback. Under the exclusive
Fabric borrow, commit cannot encounter a different authority or ledger state.
A late rejected local leaves all generations, scope state, backing bindings,
pointer-cell tags and payload unchanged. Existing pointer-cell tag clearing and
Fabric revalidation remain in effect. This change does not scrub local payload;
the separately recorded frame-initialization gap remains open.

**Accounts and reservations.** `AllocationOwner` binds the existing `ProcessKey`,
execution context and domain. An opaque `OwnerAccount` also carries a fresh,
nonwrapping admission serial so a recycled row cannot select an old account.
The kernel's existing process generations start at zero; the account serial
starts at one. Duplicate admission of an exact process incarnation is rejected
even if a mistaken caller changes its context/domain. A closed account remains
resident while it has obligations, and another incarnation has independent
usage and state.

One exclusive registry borrow serializes both local and heap changes. Heap
admission checks the current shared revision, requested signed-size range,
page rounding through the existing placement helper, owner/global byte budgets,
a reusable slot/generation and a cleanup row before its first write. A successful
reservation charges the exact rounded backing **quota**, reserves a cleanup
credit and issues an opaque staging identity. It creates no physical object,
virtual range, grant, mapping, pointer tag or protected heap pointer. Rejection
leaves every selected table, counter, identity and other account unchanged.

An unpublished reservation may be cancelled in arbitrary order, including after
its owner closes. Cancellation consumes that exact slot/generation/job/account
identity, restores its backing quota and preserves advanced generation/job
history. Duplicate, stale and mismatched cancellation fails without mutation.
This is cancellation of metadata-only staging, not evidence of physical storage
reclamation. Once later code attaches backing, it must extend cancellation into
one coordinated rollback before enabling publication.

**Cleanup reservation and closure.** The fixed cleanup directory is the queue.
Every staged allocation already owns a row and job ID. `close_owner` fences the
exact account and scans all its current reserved/live records, moving them to
closing and queuing only previously unqueued obligations. It allocates no queue
node, scratch vector or new identity and retains the complete quota. Full queue
capacity does not prevent death; duplicate death is idempotent; an empty owner
can close while all cleanup rows belong to others. Another incarnation's rows
and account remain unchanged. The account row cannot be released while work or
reserved quota remains.

The independent whole-heap close transition rejects local, foreign, interior,
stale and duplicate inputs and preserves every other lifetime. Its live-row
witnesses use an explicitly test-only publication fixture. **There is no
production heap-publication method**, and even those fixture pointers are
rejected by the existing local-only access/backing paths. Published/closing
records cannot use staging cancellation to refund resources. Worker claim,
CPU/DMA drain, authority retirement, scrubbing, completion, recovery and backing
release are not implemented in this piece.

Revision and identity exhaustion reject new admissions. Cleanup uses the
terminal revision value as a permanent admission fence: revision never wraps or
resets, and mandatory closure/cancellation can still finish without needing a
fresh revision or ID. No admission can accept a snapshot at that terminal value.

**Concrete storage charge.** Construction computes `size_of::<ScopedPointers>()`
plus the actual retained capacity of each of the four vectors multiplied by its
concrete element size, using checked arithmetic. This includes vector headers,
local backing fields, empty/reserved/closing/exhausted rows and retained account
and cleanup capacity. It does not substitute the theory's illustrative 256-byte
charge. At the A2.1 checkpoint, the x86-64 Rust 1.90.0 witness measured the
following layout; the A2.2 layout measurements below supersede these sizes:

| Representation | Bytes per element |
|---|---:|
| Registry value, including all vector headers/counters | 168 |
| Common identity/record slot | 80 |
| Optional local scope row | 24 |
| Optional owner account row | 72 |
| Optional cleanup row | 48 |

For the 3-slot, 3-scope, 1-owner, 2-cleanup fixture, fixed storage is 648 bytes;
its one-byte request reserves another 4096 bytes of backing quota. Cancelling
and releasing the owner leaves the full 648-byte infrastructure charge. Sizes
are derived on the target, not assumed from this measurement. This accounting
covers the Rust value/buffer representation, not host allocator headers or RSS.
It is not yet a complete machine-memory budget: physical/virtual indexes,
heap pointer-shadow storage, worker scratch, existing Fabric/process maps,
logs and staged copies must be included in their subsequent A2/A4 composition.
They cannot be omitted when heap publication is enabled.

**Focused evidence.** `cargo check --locked --lib` succeeds with Rust 1.90.0.
The 19 new `a21_` witnesses pass. The combined focused run passes **120 tests**:
new metadata tests, existing scoped-pointer tests, Fabric tests, Phase 10.7 core
and OS event tests, and Phase 10.8 typed I/O tests. The metadata churn witness
runs 2,048 cycles with two clients, interleaved locals, varied rounded requests,
out-of-order cancellation and stale replay, checking every ledger and fixed
capacity after each cycle. It makes no claim about backing churn or live heap
reuse. The frame-preflight witness also checks tags and bytes across late
failure and stale identity rejection after successful slot reuse.

**Developer acceptance, recorded 2026-10-22.** The developer confirmed the
focused run using `--test-threads=1`, including all 19 new A2.1 witnesses:

```text
test result: ok. 120 passed; 0 failed; 0 ignored; 0 measured; 993 filtered out; finished in 0.03s
```

This confirms the A2.1 focused runtime checkpoint on the developer machine.
The 993 filtered tests were not part of this run. The `cargo check` success
above remains separately recorded local evidence. The subsequent A2.2
implementation and its current acceptance boundary are recorded below.

Run the same focused acceptance from the repository root:

```sh
cargo check --locked --lib
cargo test --locked --lib a21_ -- --nocapture --test-threads=1
cargo test --locked --lib -- \
  scoped_pointers:: anka64::fabric::tests:: \
  anka64::core::tests::p107_ anka64::os::tests::p107_ \
  anka64::os::tests::p108_ \
  --test-threads=1
```

No theories changed in A2.1; the five accepted Kleis pairs remain its formal
prerequisites. The long Rust/CC2 fixed-point suite was not rerun for this handoff.
A2.2 below composes these reservations with bounded physical/reusable-virtual
placement using the existing placement managers, derives the added index and
scratch charges, and preserves atomic failure across the complete reservation.
Publication remains closed until the later Fabric, pointer-shadow,
initialization and typed-result checks are connected.

### A2.2 formal gate: bounded placement and compound reservations

**Local formal checkpoint, 2026-10-22; developer acceptance recorded
2026-10-23 at 215 positive / 180 explicitly disproved hostile witnesses.**
`anka108_allocation_placement.kleis` and its
`_false_witnesses.kleis` counterpart refine the concrete bounded representation
and transaction implemented by A2.2 below. They import the accepted Undertaker
pair and add no axioms. The five earlier allocation pairs remain unchanged.

Extend the existing `PhysicalPlacementManager` and virtual placement module;
do not introduce a compiler allocator or calculate application addresses outside
the placement managers. The physical manager owns one shared arena. Each owner
has a reusable virtual arena, identified by its exact nonreused account serial.
Physical addresses, virtual addresses, reservation identities and eventual
Fabric object identities remain distinct. The new gates allocate no Fabric
objects and issue no protected pointer authority.

**Bounded representation.** For an arena permitting at most K simultaneous
claims, count reserved, live and closing extents as occupied. The accepted
partition induction bounds canonical free extents by K+1. This refinement
reserves **K+2 free-array entries**, including one additional insertion slot.
Release can insert at its sorted position, merge adjacent free neighbors, and
compact the array in place without allocating a temporary merge vector. The
extra slot is transient workspace inside permanently charged capacity; it does
not permit another admitted claim or an extra canonical hole. K must fit the
stable directory namespace. Actual retained host capacity may exceed K+2 and
must be charged in full. An arena with K=0 cannot admit.

The new laws specify active-prefix indices, exact-take removal, partial-take
suffix updates, insertion shifts and compaction. Quantified source-index and
inverse/injectivity laws prevent reading an inactive row, duplicating a
surviving row or dropping one during a shift. Return checks immediate neighbors
and derives their presence from the insertion index and active length; an
application cannot hide a conflicting neighbor by supplying an absence flag.
The four left/right adjacency cases merge only adjoining free spans. A live
gap remains a gap. The existing exact coverage/separation laws still apply to
every other entry in the global partition.

**One admission commit.** Read-only physical, virtual and metadata plans must
refer to the same current shared revision. Under one exclusive boundary,
preflight signed size and page rounding, exact owner/account/arena binding,
owner closure, both selected free extents, both claim/index capacities, the
stable slot and generation, cleanup credit, job identity and both budgets.
Both extents use the same rounded span. Obtain current rows from trusted
tables; cached proposals must match their current index, base and length.
All checks precede the first write. The commit itself must be nonfallible and
install physical custody, virtual custody, registry and cleanup records, owner
and global charges, and generation/job/revision advancement together. Every
projection uses the same decision; no intermediate one-arena reservation is
externally observable. A rejected admission changes none of these fields.
The `a22_installed` postcondition explicitly requires the same freshly advanced
generation and owner/slot/job identity in all four installed records.

Fixed charging separates existing A2.1 storage, physical free indices, all
retained virtual free indices, additional claim bindings, owner-arena
descriptors and fixed scratch. Shared storage belongs to exactly one category.
Check capacity-times-stride and every category addition for overflow, using
actual target element sizes and retained capacities. The concrete numbers in
the examples are illustrative, not a new Rust layout prescription. Accounting
laws compose checked additions and residual-budget bounds; backing quota is
charged once per admitted rounded span. These charges do not measure host
allocator headers/RSS or silently include later Fabric/shadow metadata.

**Cancellation after acceptance is a separate transition.** It requires the
exact owner, slot, generation and job in the current registry, both placement
claims and cleanup record, plus both recorded bases and the common span.
The direct path applies only to private reservations that have **never** been
attached or published; attachment is a sticky fact. Previously attached work
must pass the later retirement/reclamation gates even after grants disappear.
An owner may close before a private reservation cancels. Preflight both bounded
geometric returns before removing either claim or refunding anything. Return
both extents, remove the selected records and refund the rounded charge once,
preserving all other owners and all fixed infrastructure charges.

Cancellation preserves consumed generation/job history; it does not turn a
failed lifetime into a never-issued identity. The last generation leaves an
exhausted stable slot. Cleanup may advance the shared revision to its terminal
value or leave that value saturated, as in A2.1. New admissions reject the
terminal revision. This private cancellation rule does not relax the published
Undertaker release contract or allow an old writer to survive reuse.

**Evidence and boundary.** The new pair passes **215 positive witnesses,
including 34 quantified laws, and 180/180 explicitly disproved hostile
assertions**. Unknown, timeout, parse/evaluation failure and generic assertion
failure do not count as success. Concrete traces include two owners sharing
physical storage with separate virtual arenas; A closes and returns first while
B retains its extents and quota; B then returns to recover the full arenas.
Another trace reuses A's physical hole with a fresh generation/job and a valid
virtual reservation, while rejecting A's old token. Late virtual-return failure
preserves both claims and all charges. These are bounded symbolic traces, not
executed guest concurrency or a sustained Rust allocator churn run.

The implementation still has to establish exact table census and provenance,
maintain the complete sorted/disjoint partition, apply the pointwise operations
to every affected row, derive actual storage charges, and hold one serialization
boundary through all nonfallible writes. The gates do not verify an arbitrary
Rust loop, host allocation success, SMP ordering, CPU/DMA completion, scrubbing,
publication, C malloc/free or hardware behavior. A2.2 Rust acceptance requires
forced-capacity failure snapshots, interleaved clients, varied-size/out-of-order
cancellation, full physical/virtual recovery, stale-token rejection and stable
retained capacities. Later publication and process/worker integration stay gated.

Run the new pair from the repository root:

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis \
  --only-a22
```

At the A2.2 checkpoint, `--only-allocation` included the six allocation pairs;
the later A2.3 section adds a seventh pair. `--only-108` and the
default full selection also include A2.2. The runner executes gate files
sequentially. `--test-threads=1` belongs to the later Rust test command, not Kleis.
The A2.2 combined local run passed all six pairs: **1051 positive / 737
explicitly disproved hostile assertions**, including the unchanged original
five pairs at 836 / 557. That combined run is local formal evidence; developer
acceptance covers all six pairs through the reported focused runs. Formal
evidence does not substitute for Rust/CC2 acceptance.
Local proof environment: the supplied Linux Kleis reports 1.0.0, with binary
SHA-256 `a93c8d2d958a7823f2b9bfaa220903f9ef624c61f9bde5b329783da34030cc9c`,
Z3 4.12.2, and supplied stdlib prelude SHA-256
`86014730d7bf2cc048632208d21c20aec6390f2c7ceaa8230cb2291976158432`.
No Rust source changed in that formal handoff. The Rust implementation follows;
none of the six accepted theories or the gate runner changes in this slice.

### A2.2 Rust: bounded extent custody and exact cancellation

**Developer runtime acceptance recorded 2026-10-23: all 1134 library tests
passed single-threaded, with no failures or filtered tests.**
`ScopedPointers::with_heap_placement` composes the existing common
registry with a bounded profile of `PhysicalPlacementManager` and one reusable
profile of `VirtualLayoutBuilder` per retained owner row. Shared extent
operations live inside the existing placement module; the registry never
calculates application addresses. Legacy ObjectId and monotonic APIs cannot
allocate through these bounded profiles. Their existing public profiles retain
their previous behavior, including the Fabric-checked ObjectId release path.

The trusted constructor supplies a dedicated physical pool and a virtual
window template. Each owner gets that window in its own address space; equal
numeric virtual addresses across processes are intentional. Later loader/Fabric
integration must establish that these pools do not overlap other placements.
All claim arrays, K+2 free-array capacity and owner-arena descriptors are
allocated and charged at construction. An owner binds an already retained
virtual arena to its nonreused serial; releasing a quiescent owner unbinds it
without dropping its buffers or infrastructure charge. There is no heap
manager accessor or clone of the owning registry.

Admission preflights metadata, quotas, identity, both arenas and their claim
capacities while holding the same exclusive registry borrow. Opaque physical
and virtual plans stay inside that synchronous operation and carry its current
revision. Only after all checks succeed does an allocation-free commit install
both claims, the common slot and cleanup record, charge the rounded span once,
and advance generation/job/revision. A late virtual failure leaves the physical
arena and all metadata unchanged. This is serialized interleaving through one
`&mut ScopedPointers`, not a new lock-free or SMP protocol.

`abort_heap` checks the current owner/slot/generation/job and exact recorded
bases/spans, requires an unpublished, never-attached reserved or closing
lifetime, and preflights both geometric returns before changing either arena.
Return inserts into the precharged slot, merges immediate free neighbors, and
compacts in place; no temporary merge vector or host allocation is needed.
The commit clears both claims and selected metadata and refunds only the
rounded backing charge. Identity history and fixed storage stay consumed.
Owner closure and terminal revision still allow this cancellation. The sticky
attachment guard must be set before future Fabric/work attachment; previously
attached or published work requires the later Undertaker path.

**Measured storage.** The constructor first checks minimum retained storage,
then charges actual vector capacities using checked target-size arithmetic.
Inline manager headers already belong to the registry value and are not
charged twice. Empty legacy ObjectId maps and the unused monotonic region
vector never grow in the bounded profile. On x86-64 with Rust 1.90.0:

| Representation | Bytes |
|---|---:|
| Registry value, including inline physical manager and vector headers | 312 |
| Common identity/record slot, now including optional extent pair | 96 |
| Optional owner account row | 72 |
| Optional cleanup row | 48 |
| Retained virtual manager descriptor | 120 |
| Fixed operation-plan allowance | 208 |

The four-slot/four-scope/two-owner/four-cleanup fixture with four physical
claims and three virtual claims per owner charges **2312 bytes** before any
payload reservation: 1128 bytes for the common registry/tables and 1184 for
placement buffers, virtual descriptors and operation plans. The latter includes
the maximum size of `Option<AdmissionPlacement>` or `Option<ReturnPlacement>`;
it is a fixed value-storage allowance, not a host-stack/RSS measurement or a
separate heap scratch allocation. Cancellation retains the entire fixed charge.
Fabric objects, mappings, pointer shadow and worker storage remain subsequent
budget obligations, and heap publication cannot use this partial footprint.

**Focused runtime evidence.** `cargo check --locked --lib` passes. A clean,
nonincremental Rust 1.90.0 Linux build passes **160 tests, 0 failed, 974 filtered
out**, using one test thread: the earlier 120 focused tests, all 19 existing
placement tests, and **21 new A2.2 tests**. New witnesses cover full and zero
claim capacity, metadata/quota exhaustion, stale revision and identity,
fragmentation despite sufficient aggregate free bytes, every permutation of
four frees, exact cross-record substitution, attachment/publication denial,
terminal revision, exhausted generation and owner-account reuse. Independent
test censuses reconstruct each complete physical/virtual partition and sum all
current claims and charges. A test-only allocator counter observes zero host
allocations around admission, cancellation, closure and owner-row reuse.

The 2,048-cycle witness interleaves two owners and a live local allocation,
varies request sizes and cancellation order, checks stale replay after reuse,
preserves the other owner's extents, and verifies complete recovery and
unchanged retained capacities. This exercises private extent custody, not
initialized guest payloads or live-authority reclamation. Heap publication,
Fabric attachment/mappings/grants, pointer shadow, initialization, Undertaker
execution, typed heap results and C malloc/free remain disabled/pending.

Reproduce the focused checks from the repository root:

```sh
cargo check --locked --lib
cargo test --locked --lib a22_ -- --nocapture --test-threads=1
cargo test --locked --lib -- \
  scoped_pointers:: anka64::placement::tests:: anka64::fabric::tests:: \
  anka64::core::tests::p107_ anka64::os::tests::p107_ \
  anka64::os::tests::p108_ \
  --test-threads=1
```

**Full developer regression acceptance, recorded 2026-10-23.** After restoring
the existing `src/anka64/scoped_pointers/heap/tests.rs` alongside the new
`src/anka64/scoped_pointers/heap/placement/tests.rs`, the developer reported the
successful full-library run:

```sh
cargo test --locked --lib -- --test-threads=1
```

```text
test result: ok. 1134 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1149.73s
```

This supersedes the pending developer runtime checkpoint and covers all tests
registered in the library test binary, including the 21 A2.2 witnesses. The
earlier 160-test run remains separate local focused evidence. Both required
test files are present in the accompanying source archive. The A2.2 acceptance
correction itself changed only the two planning documents; Rust sources and accepted
Kleis gates were unchanged. A2.2 extent custody/cancellation is accepted; the
remaining Fabric, initialization, publication and Undertaker work stays gated.

### A2.3 Kleis: bounded Fabric attachment, shadow and initialization

**Formal checkpoint developer-accepted, 2026-10-24.** The accepted A2.2 implementation owns
exact private physical/virtual reservations and can cancel a never-attached
reservation. It does not yet create heap Fabric objects, initialize backing,
publish heap pointers or implement C `malloc`/`free`. The next refinement is
`theories/anka108_allocation_fabric.kleis` with its paired hostile witnesses.
It imports A2.2 and composes its custody/accounting obligations with the
accepted lifetime, initialization, protected-cell and Undertaker contracts.

The immediate implementation issue is bounded metadata. `Fabric` currently
keeps objects, placements and protected pointer cells in growing `BTreeMap`s;
domain grants use growing vectors. The current typed-store path builds a byte
vector, performs the payload write and then inserts its protected pointer cell.
An allocation service cannot promise preflighted resource use while leaving
those heap paths able to allocate host storage during commit. This refinement
selects the following initial software representation:

| Resource | Concrete A2.3 contract |
|---|---|
| Heap Fabric metadata | Preallocate one composite row per common registry slot. The row holds the object identity, placement, private map/grant plan, exact owner/reservation binding and initialization state. No second pointer namespace and no growing map/vector/string insertion during an admitted heap commit. |
| Protected heap cells | Preallocate a dense shadow table covering the dedicated physical heap pool, one entry per aligned 16-byte cell. Authenticate the current lifetime and `(object, object generation, offset)` before indexing it; a physical index never confers authority. |
| Fixed accounting | Charge actual retained row/shadow capacities times their actual target element sizes, plus fixed scratch, once at service construction. All additions and multiplications are checked. A2.2 already charges rounded payload per owner and globally; attachment and publication do not charge it again. |
| Physical and virtual exclusion | Reserve the complete physical heap pool against loader/legacy placement and raw access. Each owner's heap arena excludes its code, stack and other mappings. Different owners may use equal numeric virtual addresses. Every rounded extent, including padding, remains in the exact A2.2 custody record. |
| Object identity | Use a checked machine-global counter shared with every Fabric object issuer; zero is a valid object ID, exhaustion fails closed and attached identities never rewind. Preserve the allocation epoch already consumed by A2.2. |
| Visibility | One trusted row stage controls whether heap object, map and RW grant are usable. Private attachment is invisible; initialized publication and the typed result commit together. Logical size is exposed; page-rounded padding is not. |

The dense shadow is a bounded initial software choice, with predictable
indexing and no store-time capacity failure. Its cost is proportional to the
configured heap pool even when few cells contain pointers. The formula is
`retained_shadow_entries * size_of::<ShadowEntry>()`, with at least
`pool_bytes / 16` entries. Witness strides are illustrative, not a claim about
the future Rust struct size. This is not a claim of optimal memory overhead,
complete host RSS accounting or a future FPGA tag format. A later packed or
sparse representation needs its own capacity/failure/refinement gate. Reject
construction if the actual retained storage does not fit its fixed budget.

**Transitions and failure behavior.** All checks read current trusted state
under the same exclusive boundary used by owner closure and shared reservation
revision. Caller-supplied booleans or guessed completion counts are insufficient.

1. **Attach privately.** Recheck the exact account serial, process incarnation,
   context/domain, slot, allocation epoch, job, physical/virtual custody and
   prepared capacity. Require terminal old work and no alternate readers or
   writers. Install the preallocated row, consume one fresh ObjectId, set the
   sticky attached marker and start the initialized prefix/version at zero.
   No user authority or pointer is published. Process generation zero is valid;
   the nonreused account serial supplies the owner identity used by the model.
2. **Initialize full backing.** Synchronous software-Fabric steps clear at most
   one page each, in contiguous aligned chunks. Each committed chunk clears
   bytes and overlapping protected tags together and advances the trusted
   prefix/version/revision. The rounded backing, including padding, must be
   covered. Any other trusted private write resets the initialized prefix and
   advances the mutation version; an older clean receipt can no longer publish.
   Such writes must also use the ordinary overlapping-tag invalidation barrier.
3. **Publish only when the complete lifecycle is connected.** Bind the exact
   row and current initialization version, complete prefix, owner, logical-only
   object/map/RW-grant plan, visible byte/tag completion and protected result
   destination. A single nonfallible commit changes visibility and returns the
   same reserved slot/epoch at position zero. No EXEC, ATOMIC, SEAL, cross-owner
   export or device authority is introduced. A failed publish preserves the
   existing result pair and prior private state.
4. **Close without premature refund.** Failure or owner death after attachment
   closes access and queues the already-reserved Undertaker record. All aliases,
   including spills and saved events, must reauthenticate the current lifetime.
   Removing one register copy is not revocation. Extents, charges, identity
   bindings and pending-work accounting remain held until the accepted
   retirement/scrub/release path completes. Direct A2.2 cancellation is allowed
   only before the sticky attachment marker has ever been set. Closure remains
   possible at revision exhaustion, using the existing saturating cleanup rule.

Every generic lookup and physical writer that could reach the dedicated pool
must honor this contract. A valid legacy capability, matching address, old
object-generation pair or restored pointer-kind bit cannot override a closed
heap lifetime. Typed heap stores additionally require current source authority
or canonical null, coherent payload/kind transport and no remaining fallible
host allocation. Dense shadow does not by itself establish any of those checks.

**Evidence and limits.** Local validation using the supplied Kleis executable
passes **192 positive witnesses**, including **30 universally quantified laws**,
and **162/162 explicitly disproved hostile witnesses**. The constructive trace
attaches a 31-byte logical object in 4096 bytes of backing, clears it in 16-byte
and 4080-byte steps, publishes a usable pointer and then closes it. Quantified
observations range over arbitrary old bytes and tags: the complete backing
becomes initialized, logical reads succeed with no old-byte dependence, padding
remains inaccessible, and another owner's bytes/tags remain unchanged. Further
laws cover bounded/injective shadow indexing, failed-transition preservation,
single visibility, nonwrapping identity issuance and rejection of stale aliases.
Hostile cases include stale receipts, live DMA/CPU work, owner restart, wrong
geometry, exhausted identities, metadata shortage and store-time host allocation.

This is a conditional finite-transition model, not proof that the current Rust
code implements it. Trusted complete scans, actual exclusion, serialized
updates, typed-result context binding, real terminal drainage and visibility
remain implementation obligations. It proves no unconditional cleanup progress,
cache/timing secrecy, device behavior or hardware realization. It also does not
close the existing local-frame payload-initialization gap. The original formal
handoff changed no Rust sources or earlier accepted theories and ran no long
Rust/CC2 tests; the subsequent A2.3.1 Rust piece is recorded below.
The earlier six allocation pairs remain developer-accepted at **1051 positive /
737 hostile** across their recorded runs; they were not rerun for this handoff.
The developer has now confirmed the new pair at 192 / 162. These counts are not
a claim of a newly executed combined seven-pair run.

Run only the new pair:

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis \
  --only-a23
```

`--only-allocation` and the complete 10.8 selection now include A2.3. Unchanged
imported examples do not execute under `--only-a23`; imported definitions still
participate in the new proofs. Unknown, timeout and evaluation/parse errors
continue to fail closed. Python syntax and the new selector were checked.

**Bounded implementation order (the formal gate is accepted):**

1. A2.3.1 below implements fallible setup and fully charged bounded heap Fabric rows/shadow, a
   shared checked ObjectId issuer and private attachment with exact reservation
   checks. Keep guest publication disabled. Test metadata-budget/late-failure
   behavior, unchanged unrelated owners and no host allocations inside admitted
   mutation/store commits. This does not yet bound unrelated emulator logs or
   all legacy process/object metadata.
2. A2.3.2 bounded backing initialization/trusted-write invalidation and A2.3.3
   conditional protected heap-cell transport/scalar tag invalidation are
   developer-accepted. A2.3.4 per-allocation attached-failure closure is also
   developer-accepted. Keep publication disabled
   until cleanup and result delivery are connected.
3. A2.3.5's concrete worker/terminal-work refinement is developer-accepted.
   A2.3.5a worker records/claims and A2.3.5b backend registration/pinning are
   developer-accepted. A2.3.5c bounded software effects, terminal consumption
   and current drain checks are developer-accepted. A2.3.6 queued-job recovery
   and A2.3.7 authority retirement are also developer-accepted. Complete trusted
   cleanup/reuse below adds the required later-stage worker refinement and the
   whole scrub/release/refund path in one accepted delivery. A3 then connects
   working C malloc/free, owner exit/fault integration and owned typed results;
   its developer acceptance is recorded below. A4 records the required review.

Working independent C clients and safe reuse now pass in A3; the required
A4 review is delivered below. The full compiler A/B/C acceptance remains:
clients A and B compile concurrently; A exhausts or exits; C reuses A's backing;
B stays correct and all A's stale aliases fail. The formal observations above
are not execution evidence for that scenario. Compiler growth follows the
review and uses this shared service; it does not get a separate allocator.

### A2.3.1 Rust: fixed Fabric storage and private attachment

**Implementation and developer acceptance, 2026-10-24.** The developer
confirmed both A2.3 gates at 192 positive / 162 explicitly disproved hostile.
This piece implements only their fixed-storage/private-attachment foundation.
It does not initialize an allocated lifetime or enable guest heap pointers.

`Fabric::with_private_heap` constructs a fresh optional machine profile using
the existing A2.2 placement managers and common registry. Setup uses fallible
allocation for the Fabric memory buffer, fixed composite rows and dense shadow.
The physical pool must fit actual Fabric memory. The metadata budget is checked
before table allocation and again against actual retained capacities. Additional
fixed charges include the inline heap descriptor, row/shadow arrays and a
value-storage allowance for the attachment plan/row. Existing registry/placement
charges are not counted again. Memory-buffer capacity is the emulator's physical
RAM model, not an additional per-allocation payload charge or host RSS claim.

`attach_private_heap` verifies the current trusted owner descriptor against
the nonreused account, existing domain, exact reservation/cleanup record,
shared revision and both current placement claims. The registry must still
hold a reserved, unpublished, never-attached lifetime. A bounded row census
checks slot availability, physical custody and same-owner virtual separation;
different owners may retain equal numeric virtual addresses. The Fabric also
rechecks legacy placements, pointer-cell placements and nonterminal transaction
spans for conflicts with its dedicated pool. No caller-provided quiet flag is
accepted. New object identity and every potentially failing check are prepared
before the first mutation.

The commit sets the registry's sticky attachment marker, advances its shared
revision once, installs the exact private composite row and consumes one fresh
ObjectId. It changes neither the allocation epoch/job nor payload quota. The
row includes logical bounds, rounded physical/virtual custody, an RW-only map/
grant plan and zero initialized-prefix/version counters. It is **absent from
the legacy public object/placement maps** and creates no grant, mapping,
initialization receipt or `ScopedPointer`. Existing bytes and tags remain
untouched. The returned ObjectId is diagnostic identity only.

The common ObjectId issuer now checks increment overflow and existing identity
collisions. The heap path returns `Capacity(Identity)` on exhaustion;
`try_alloc_object` gives legacy callers a fallible identity API. Existing
`alloc_object` callers retain their compatibility wrapper, which panics rather
than wraps on exhausted/occupied identity; migrating all legacy failure handling
is outside this piece. The old unpublished-staging rollback remains available,
but a retained high-water fence prevents it from ever rewinding across an
attached heap identity, even after future row reclamation.

Dedicated-pool exclusion applies before the first reservation: legacy object
placement, translation, full precommit spans, object initialization/zeroing and
raw bootstrap reads/writes/zeroing cannot access the pool. Complete overlapping
spans are rejected before a byte or tag changes. Fallible raw helpers return
`None`/`false`; existing infallible bootstrap wrappers report misuse by panic.
Legacy relocation now validates the destination before replacing its old
placement, so a rejected move into the heap pool preserves translation.
The physical high-watermark includes the whole configured pool. Heap identities
cannot be granted, sealed, revoked, destroyed or rolled back through legacy APIs.

After attachment, direct `abort_heap` remains forbidden. Existing owner closure
fences the registry and queues its preallocated cleanup records while retaining
charges, extents and private Fabric rows. This piece supplies no release worker
or per-allocation attached cleanup: those resources intentionally remain held
until the later Undertaker integration. Rejected attachment leaves the original
never-attached reservation available for ordinary A2.2 cancellation.

**Validation:** `cargo check --locked --lib` and `cargo check --locked --tests`
completed successfully. The latter compiles the tests without executing them.
**No Rust tests were run by the agent**, at the developer's request. Seventeen
new `a231_` tests are included for exact charging, invalid configuration,
identity exhaustion/collision/rollback, preserved bytes/tags/charges/epochs,
late failure, stale keys/revisions/owners, duplicate attachment, independent
owner closure, pool exclusion, complete-span rejection, CPU/DMA pipeline
conflicts, shadow indexing and legacy-profile compatibility. Relevant steady
state operations are measured with the existing thread-local allocation counter.
The developer subsequently confirmed both focused runs on 2026-10-24:

- New A2.3.1 tests: **17 passed, 0 failed, 1134 filtered out, 0.01s**.
- Shared-component regression: **144 passed, 0 failed, 1007 filtered out,
  0.09s**, including those 17 tests; the two counts are not additive.

This establishes focused runtime acceptance for A2.3.1. The last accepted
full-library result remains **1134 passed in 1149.73s** from A2.2; no full
1151-test run was reported.

Run the new tests locally:

```sh
cargo test --locked --lib a231_ -- --test-threads=1
```

The shared ObjectId, relocation and physical-access changes also warrant this
focused integration selection; it includes the new tests and the existing
registry/placement/Fabric/developer-ingress checks:

```sh
cargo test --locked --lib -- --test-threads=1 \
  anka64::fabric:: anka64::scoped_pointers:: \
  anka64::placement:: anka64::dev_shell::
```

No accepted Kleis files changed, so this implementation handoff does not require
rerunning unchanged formal examples. The full Rust/CC2 suite remains a local
integration checkpoint, not an agent-side cost in this handoff.

**Remaining boundaries:** this profile is not installed by the OS or compiler
runner yet. Trusted process-descriptor freshness, code/stack exclusion from the
virtual heap window, process exit/fault delivery and real controller drainage
must be connected before guest publication. The fresh constructor has no old
device state; rejecting overlapping Fabric transactions is not proof of a
physical device's drainage. Heap metadata is bounded, but the census of legacy
machine maps/traces still depends on that existing inventory; this piece claims
neither constant execution time nor a bound on all emulator logs/legacy metadata.
Existing machine profiles continue to use `Fabric::new` with no heap pool.
A2.3.1 itself supplies no malloc/free, heap-cell load/store, initialization,
worker, syscall, compiler or hardware implementation. The subsequent A2.3.2
piece below supplies private byte/tag initialization only.

### A2.3.2 Rust: complete private backing initialization

**Implementation and developer acceptance, 2026-10-24.**
This piece follows the accepted A2.3 `a23_chunk`/`a23_dirty` transitions and
`init108_*` byte, tag, prefix, version and exact-binding laws. It adds no new
architectural contract or Kleis axiom. The accepted theories and gate scripts
are unchanged; no unchanged formal examples were rerun for this handoff.

`Fabric::private_heap_initialization` derives an opaque `HeapInitialization`
snapshot from the current trusted row. It binds the complete reservation
(slot/epoch/account/job), owner process incarnation/context/domain, object and
object generation, logical/rounded geometry, RW plan, completed prefix and
mutation version. Every observation, scrub, trusted write and completion check
revalidates the current owner account, domain, unpublished attached registry
state, unqueued cleanup record, shared revision and both current manager claims.
It checks actual backing/shadow bounds and repeats the existing legacy placement,
pointer-cell and nonterminal transaction census. A caller cannot supply a
completion count or an `already_zero` flag. ObjectId zero remains valid.

`initialize_private_heap_chunk` accepts a nonzero multiple of 16 bytes, at most
4096 bytes, starting exactly at the trusted completed-prefix cursor. Checked
bounds cover the complete rounded allocation, including padding. All identity,
version, range and capacity checks finish before mutation. Under the same
exclusive Fabric borrow, the commit zeros the byte slice, clears every affected
dense-shadow cell, updates the prefix and increments both initialization version
and common revision once. There is no chunk buffer, growing table or host
allocation in that commit. No second quota, allocation epoch or ObjectId is
consumed. Other allocations retain their bytes, tags, progress and charges.
The fixed construction budget now also reserves value-storage allowances for
the initialization plan, ranges and snapshot; this is not a host RSS bound.

`write_private_heap` is the trusted non-scrub mutation path for private backing.
It accepts 1..4096 bytes inside rounded custody, including unaligned spans;
it clears all overlapping 16-byte tags and atomically resets the **entire**
initialized prefix to zero while incrementing version/revision. Even writing
zero values invalidates older completion records. Rejected writes leave prior
progress intact. This API is not an initialized-image overlay: the next scrub
must overwrite those bytes before a fresh zero-filled heap may be published.
Legacy/raw writers remain excluded from the dedicated pool. No write creates
protected pointer kind from numeric payloads.

`validate_private_heap_initialization` accepts only the exact current complete
snapshot. A copied snapshot's `is_complete()` is a historical observation and
cannot substitute for revalidation. Re-scrubbing identical bytes after a trusted
write never revives an older version. Version/revision exhaustion fails closed;
existing owner closure still works and retains all attached custody/charges.
An unrelated client's mutation requires a fresh shared revision but does not
invalidate this allocation's own unchanged version. These are serialized
software-Fabric interleavings, not evidence of running parallel C clients.

**Visibility remains disabled.** A complete snapshot is neither a memory grant
nor a protected pointer. There is no public object/map insertion, guest read,
per-allocation attached release, cleanup worker, C malloc/free, syscall-result
publication or OS/runner integration in this piece. Future publication must
repeat the completion check inside its exclusive commit along with the remaining
lifecycle, typed-result and current-process gates. This synchronous initializer
does not establish device drainage, FPGA/cache visibility or the separate
local-frame payload-initialization guarantee.

**Validation:** `cargo check --locked --tests` passes, compiling the library,
binary and test code without running tests. **No Rust tests were executed by
the agent.** Eighteen new `a232_` tests cover full backing/padding/tag coverage,
multiple chunks/pages, rejected gaps and counts, exact snapshot bindings, stale
versions/revisions, mutation invalidation, exhaustion, owner closure,
independent owners, pending CPU/DMA/atomic work, legacy tag/placement conflicts,
late storage failure and current cleanup/physical/virtual claim checks. The
existing thread-local allocation counter guards admitted and rejected paths.
The developer subsequently confirmed both focused runs on 2026-10-24:

- New A2.3.2 tests: **18 passed, 0 failed, 1151 filtered out, 0.02s**.
- Shared-component regression: **162 passed, 0 failed, 1007 filtered out,
  0.10s**, including those 18 tests; the two counts are not additive.

This completes focused runtime acceptance of A2.3.2. No full 1169-test library
run was reported; the last accepted full baseline remains A2.2's 1134 tests.

Run the new tests locally, then the affected shared-component regression:

```sh
cargo test --locked --lib a232_ -- --test-threads=1

cargo test --locked --lib -- --test-threads=1 \
  anka64::fabric:: anka64::scoped_pointers:: \
  anka64::placement:: anka64::dev_shell::
```

The following A2.3.3 piece supplies conditional protected heap-cell operations;
A2.3.4 supplies attached-failure closure. Undertaker worker/process integration
and typed-result publication remain downstream. C malloc/free and independent-client
acceptance still precede the required whole-stack review and compiler growth.

### A2.3.3 Rust: protected heap-cell transport and scalar invalidation

**Implementation and developer acceptance, 2026-10-24.** The developer
confirmed **22 new tests passed in 0.01s** (1169 filtered out), followed by
**184 focused shared-component tests passed in 0.13s** (1007 filtered out).
The 184 include the 22; these are not additive counts. No full 1191-test run
was reported. A2.2's 1134-test run remains the last accepted full-library baseline.
This piece implements the already accepted `a23_current`, `a23_access`,
`a23_cell` and `a23_store` conditions together with `kind107_typed_storage`,
coherent payload/kind transport, canonical null and overlapping-write rules.
No new Kleis theory or architectural primitive is introduced. Accepted theory
files and gate scripts are unchanged; unchanged formal examples were not rerun.

**Publication stays disabled.** The new access paths require a genuinely live,
published heap lifetime; neither reservation, attachment nor a complete A2.3.2
initialization snapshot admits access. No production code in this piece sets
that published state or issues a heap pointer. Positive component tests run real
reserve/attach/initialization, then synthesize the pending publication checkpoint
through `cell_test_support`, compiled only under `#[cfg(test)]`. Those fixtures
are explicit test assumptions, not an implementation of publication, malloc,
process activation or cleanup. Production builds do not contain those helpers.

`ScopedPointers::prepare_heap_pointer` reads the opaque token's current slot and
generation, live/published/attached state, exact open owner account, process
incarnation/context/domain, unqueued cleanup identity and both current placement
claims. It returns a checked plan, not a new pointer or authority. The complete
logical point may include one-past for transport; every memory operation checks
its own nonempty logical span before touching bytes or shadow. A local/heap
class lookup selects validation only; it never authenticates a token.

Fabric requires a registered CPU agent in the current owner's existing domain,
the exact reserved row and geometry, expected object generation, RW-only rights,
complete prior initialization, actual byte/shadow bounds and exclusion of
legacy placement or outstanding work. The row remains outside legacy public
object/placement maps; its stage is derived from the common registry instead
of a second Fabric visibility flag. All entry points finish under one exclusive
Fabric borrow and consume current state. No caller can supply a prevalidated
cell index or bypass ownership with a raw ObjectId/physical address.

The new internal runtime operations are:

| Operation | Concrete behavior |
|---|---|
| `store_heap_pointer_cell` | Validate a live aligned 16-byte destination and an authenticated source or canonical null; serialize both payload words into a fixed stack array and install payload/tag together |
| `load_heap_pointer_cell` | Validate the destination cell, compare both stored words with its opaque shadow token, and reauthenticate that token before returning it; untagged nonzero or mismatched payload fails |
| `write_heap_bytes` | Validate a nonempty logical span of at most 4096 bytes, write it and clear **all** overlapping 16-byte tags, even when the supplied bytes are unchanged |

Heap pointers and same-context local pointers may be transported. Local sources
also require a current frame lifetime, backing object generation and READ
permission at the transported point. One-past can be copied but never used as a
cell or byte destination. Canonical null is exactly untagged zero/zero; a tag
with zeroed or altered payload fails rather than falling back to null. Raw
copies of valid handle words never recreate a tag.

Both sides authenticate on every operation. Closing a source heap invalidates
all copies still held in registers, cells or other trusted snapshots without
requiring erasure. A local source similarly fails after scope retirement or
slot reuse. Destination closure rejects reads, typed stores and scalar writes.
Another owner's equal numeric virtual address selects different custody and
cannot authorize cross-owner transport. Tests exercise serialized independent
owner interleavings; this is not running concurrent C-client acceptance.

Data operations leave allocation epochs, ObjectIds, owner/global charges and
ledger revision unchanged. They do not grow the legacy pointer-cell BTreeMap,
transaction history or fault log. The dense shadow is already reserved, and
construction now charges value-storage allowance for access plans, span and
16-byte transport scratch. Full shadow use or exhausted owner quota does not
require new metadata. Admission/revision exhaustion does not disable existing
live data operations; owner closure still fences them. Errors preserve bytes,
tags and accounting because every fallible check precedes the first mutation.

These internal APIs are **not yet routed from CPU instructions or syscalls**.
Existing core pointer arithmetic/spills and generic transaction paths remain
unchanged; legacy, raw, DMA and atomic access cannot reach the heap pool. The
future caller must bind the current process descriptor and protected destination
register/context before integrating the API. Existing legacy exclusion scans
still depend on that inventory; this is not a whole-emulator memory/time bound,
hardware coherence proof or completed saved-event/heap ABI integration.

**Validation:** `cargo check --locked --tests` passes for production and test
code. The agent executed **no Rust tests**. Twenty-two new `a233_` tests cover
conditional live/null/heap/local roundtrips, private-state rejection, exact
logical bounds, one-past transport, scalar forgery and cross-cell invalidation,
source/destination closure, local scope/permission changes, owner/CPU/DMA
isolation, malformed metadata, incomplete publication, pending-work conflicts,
full-shadow capacity and exhausted-ledger behavior. Mutation paths are wrapped
with the existing thread-local allocation counter. Their developer-confirmed
focused acceptance is recorded above; A2.3.2's 162-test acceptance is prior evidence.

Run locally:

```sh
cargo test --locked --lib a233_ -- --test-threads=1

cargo test --locked --lib -- --test-threads=1 \
  anka64::fabric:: anka64::scoped_pointers:: \
  anka64::placement:: anka64::dev_shell::
```

The next bounded piece, A2.3.4 below, implements per-allocation
**attached-failure closure** into its already-reserved cleanup record. Undertaker
worker/process integration follows. Publication remains closed until
terminal cleanup, current process/context checks and typed-result delivery are
connected. C malloc/free and the A/B/C safe-reuse scenario remain prerequisites
for the required whole-stack review; this conditional cell milestone does not
trigger that checkpoint.

### A2.3.4 Rust: attached-failure closure without premature reclamation

**Implementation and developer acceptance, 2026-10-24.** The developer confirmed
**17 new tests passed in 0.02s** (1191 filtered out), followed by **201 focused
shared-component tests passed in 0.13s** (1007 filtered out). The 201 include the
17. No full 1208-test run was reported; A2.2's 1134-test run remains the last
accepted full-library baseline. The latest uploaded archive matches the A2.3.4
handoff's source and documentation.
This piece implements the accepted `a23_close`, `a23_stage`, `a23_held` and
saturating `a22_cleanup_revision` rules. The existing current-lifetime checks
reject subsequent access. No new architectural contract is introduced; Kleis
theories and gate scripts are unchanged and were not rerun.

`Fabric::close_attached_heap` is a trusted internal failure/cleanup operation
for one exact attached reservation. It takes the opaque reservation, retained
owner descriptor and exact ObjectId. Registry preflight rechecks the account
serial, process incarnation/context/domain, slot/generation/job, sticky attached
marker, stage/publication consistency, reserved cleanup row, rounded accounting
and both actual placement claims. Fabric then rechecks its exact row, object
generation, identity high-water mark, logical size, RW plan, geometry and
retained byte/shadow bounds. Every fallible check precedes mutation under one
exclusive Fabric borrow. Cleanup-index lookup is now bounds-checked as well;
an invalid binding fails without indexing outside the directory.

A successful commit changes only the allocation's common stage to `Closing`,
queues its already-reserved cleanup record and advances the shared revision
with saturation. It allocates no host storage, inserts no map/log entry and
consumes no ID, queue slot, allocation epoch or quota. Construction charges the
additional closure-plan value allowance once. The owner remains open for its
other allocations. Both placement claims, owner/global charges, account/slot/job
bindings, ObjectId, bytes, pointer tags and initialization progress remain held.
Direct `abort_heap` still rejects every ever-attached lifetime.

An exact repeat returns `AlreadyClosing` without changing any state or revision.
That result observes an existing closure; it is **not** a second successful
`a23_close` transition. It works in either order with existing `close_owner`;
already-queued work is not counted twice. A different owner, incarnation,
reservation or ObjectId still fails even on the duplicate path. The retained
identity suffices after the domain has been removed; cleanup does not depend
on a live CPU or caller-supplied PID. This API is not a guest free syscall.

**Close admission before draining.** Closure does not require a quiet pool,
complete initialization, a new admission revision or counter headroom. Full
reserved cleanup capacity and revision/identity exhaustion do not block it.
Outstanding CPU/DMA/atomic transaction state is neither cleared nor declared
terminal. Backing remains unavailable for reuse, even after a legacy conflicting
transaction is subsequently rejected by its existing precommit gate. Terminal
work accounting, worker leases, retirement and cleanup were outside this
closure handoff. Their subsequent implementation and current acceptance are
recorded in the complete trusted cleanup/reuse section below.

The A2.3.2 initialization paths reject a closed private allocation, including
previously complete snapshots. Conditional live A2.3.3 operations reject closed
destinations and every surviving source alias they reauthenticate. Payload and
shadow copies remain intact, demonstrating lifetime invalidation rather than
erasure. Positive live cases still use the explicit test-only publication
fixture; real heap CPU calls, spills and saved event results remain unwired.
Independent-owner/sibling tests exercise serialized interleavings, not concurrent
C programs or the complete A/B/C backing-reuse acceptance scenario.

**Validation:** `cargo check --locked --tests` passes; the agent executed **no
Rust tests**. Seventeen new `a234_` tests cover dirty/partial/complete private
closure, live source/destination alias rejection, exact duplicate and owner-death
ordering, lost-domain cleanup, stale/substituted custody, malformed cleanup
bindings, unrelated owners/siblings, full directory/exhausted counters, pending
CPU/DMA/atomic work, retained charges/extents and legacy bypass rejection.
Mutation/rejection paths use the existing thread-local allocation counter.
Their developer-confirmed focused acceptance is recorded above.

Run locally on `feat/anka108-protected-allocation`:

```sh
cargo test --locked --lib a234_ -- --test-threads=1

cargo test --locked --lib -- --test-threads=1 \
  anka64::fabric:: anka64::scoped_pointers:: \
  anka64::placement:: anka64::dev_shell::
```

The concrete review identified a required refinement: the abstract Undertaker
model does not select a worker registry or bind old-work completion to actual
backend request records. A2.3.5 below specifies those representations and gates
before their Rust implementation.
Keep production publication disabled until the cleanup lifecycle and owned
typed-result delivery are connected. C malloc/free, independent clients and the
required whole-stack review retain their DN-71 order.

### A2.3.5 Kleis: bounded worker identity and exact terminal-work accounting

**Formal gate developer-accepted, 2026-10-24.**
`anka108_cleanup_workers.kleis` and its hostile companion refine the accepted
Undertaker claim/lease/old-ticket rules through the A2.3 Fabric contract. Local
validation passes **197 positive witnesses**, including **23 quantified laws**,
and **172/172 explicitly disproved hostile witnesses**. The developer confirmed
both counts using `--only-workers`. The seven previously accepted allocation
pairs remain 1243 positive / 899 hostile across their reported focused runs;
with this pair the accepted total is 1440 / 1071. This is not a new combined run.

**Why this gate precedes implementation.** Current protected heap-cell
operations are synchronous under an exclusive Fabric borrow. At the formal
handoff there was no concrete worker registry; A2.3.5a below supplies its metadata
foundation; A2.3.5b supplies bounded prepared CPU requests and their pinned
ledger records. A2.3.5c below connects synchronous software execution, stopped
cancellation and exact terminal-ticket consumption. Legacy `Transaction::is_terminal()` distinguishes committed or
faulted records, but a future device adapter must additionally establish that
no delayed effects remain and that completed effects are visible. A notification,
timeout, worker death or caller-supplied counter is not that evidence. Existing
legacy transactions and controller slots do not automatically become safe heap
work records merely because their identifiers can be copied.

The selected software representation is:

| Record | Binding and storage rule |
|---|---|
| Worker directory | Fixed rows separate from allocation-owner accounts. An opaque one-based row/serial handle binds the trusted process incarnation, context, domain, cleanup role and current descriptor. Serial issuance is positive, global to this registry and nonwrapping; process generation zero remains valid. |
| Per-job lease | An extension of the already-reserved cleanup row holds unowned/held/revoking state, lease epoch and worker handle. Claiming leaves the job in the pending census and preserves every allocation charge and extent. The first concrete claim profile selects only queued/draining jobs. |
| Old-work directory | Fixed rows bind the full allocation/custody key, a separate nonreused operation ID, CPU/DMA class, registered backend, source index/generation/request ID, agent and exact offset/length/access. Slot zero and ID zero remain valid for backend records; they are distinct from nonzero heap operation identities. |
| Backend reservation | A source record and its capacity must be prepared before work starts, pinned to the exact operation until terminal consumption, and committed with its ledger row. A generic growing legacy history is not assumed to satisfy this bounded interface. |
| Fixed accounting | Charge actual retained worker/work capacities and the cleanup-row extension using actual target element sizes, plus scratch, once at construction. Checked products/sums and allocation success precede service exposure. Model witness strides are illustrative. |

Worker enrollment requires trusted cleanup authority, a current descriptor, a
free preallocated row and a unique incarnation. Normal applications cannot
claim cleanup merely by presenting a PID or being allocation owners. Every
lease use rechecks the worker row and process/context/domain/role binding.
Global fencing makes those checks fail immediately without declaring the
worker's effects terminal. A fenced worker row cannot be removed while job
leases or worker operations still refer to it. Fencing and terminal consumption
use saturating cleanup revision; enrollment, new work and new claims require
identity/revision headroom. Exhaustion retains obligations rather than wrapping.

**Admission and terminal consumption.** A new asynchronous operation needs a
current live allocation, permitted profile, checked access, free ticket row,
fresh operation ID, prepared backend and no remaining fallible commit work.
These requirements must be established in the same exclusive operation before
either the backend or ledger is exposed. No post-admission best-effort ticket
insertion is allowed. The first heap profile remains CPU-only; DMA rows in
conditional model witnesses do not grant DMA access or enable an adapter.

Completion authenticates the stored allocation and backend tuple against current
trusted records, including source-slot generation and operation identity. The
source remains pinned. A terminal committed or faulted state must also have
stopped effects and visible results. Requested, authorized and prepared work,
timeout-only notifications, reused slots and duplicate completion all reject.
An exact terminal operation consumes its ledger row and backend pin once, under
one lock, while preserving payload and fixed storage charges. Its authenticated
stored class selects the count: a DMA completion cannot decrement CPU work,
or vice versa, even when both counts are nonzero. It can complete
while its allocation is live or closing, and while a cleanup worker is absent
or fenced. Completing an operation does not free its allocation.

**Exact census and readiness.** A bounded complete-table scan derives CPU/DMA
counts from active rows for the selected job. The quantified base/induction
laws bound the counts by scanned capacity; foreign jobs do not contribute.
Malformed active rows or unknown classes fail the scan instead of disappearing
from the count. Erasing one authenticated matching row agrees with decrementing
the corresponding census by one. Other directory rows remain unchanged.

A readiness decision requires a complete current scan under the same exclusive
operation, zero registered CPU/DMA work, zero unregistered source conflicts,
closed admission paths, visible effects, retained custody and a current worker
lease. An unchanged revision number is insufficient to reuse a cached scan;
that matters particularly at revision saturation. Every enabled legacy/controller
path must be included in the exclusion/accounting inventory. Readiness is a
current predicate, not a persistent clean, retired or reusable-memory receipt.

The constructive conditional-backend trace admits two A operations and an
independent B operation before A closes, claims A's queued job while work
remains, consumes an exact CPU completion and fenced terminal DMA failure, and
establishes A's drain readiness while B's operation remains outstanding. It
also rejects duplicate consumption and verifies that the closed heap has no
application authority. This is model evidence, not running concurrent C clients
or the full A/B/C compiler/backing-reuse scenario.

**Proof boundary.** These are finite transition and pointwise/fold laws with no
new axioms. They do not prove the Rust scan, opaque-handle representation,
backend capacity/pinning, adapter fidelity, scheduler fairness, actual device
fencing, cache coherence or progress under permanent faults. Implementation
must derive the trusted predicates from current records and real terminal
events. None may be supplied by an application. Scrub submission, worker
recovery, retirement, release and typed result delivery remain separate pieces;
this handoff neither implements them nor closes the local-frame initialization
gap or post-malloc review checkpoint.

Run only the new gate:

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis \
  --only-workers
```

`--only-workers` selects only this pair. `--only-allocation` and the complete
10.8 selection include it. Unknown, timeout and parse/evaluation failure still
fail closed; every hostile assertion requires explicit Z3 disproof. Python
syntax and selector help were checked. Rust sources are unchanged, so no Rust
build or tests were run for this formal/documentation handoff.

Following developer gate acceptance, the bounded implementation handoffs are:

1. **A2.3.5a (developer-accepted):** precharged worker
   rows and per-job leases, enrollment, exact queued-job claim, current-worker
   authentication and fencing. Keep publication and scrub off.
2. **A2.3.5b (developer-accepted):** precharged work
   rows and a bounded software CPU backend, atomic registration/pinning, fresh
   operation IDs and admission rejection. Effects were deferred to A2.3.5c; DMA stays disabled.
3. **A2.3.5c (developer-accepted):** bounded CPU execution/cancellation, exact terminal
   consumption and complete current census, with hostile stale,
   duplicate, wrong-incarnation and unregistered-source cases. A2.3.6 and
   A2.3.7 below record accepted recovery and retirement. The complete trusted
   cleanup/reuse delivery finishes the remaining worker/scrub/release path.

### A2.3.5a Rust: fixed worker roles and retained per-job leases

**Developer-accepted, 2026-10-24:** 21 new tests passed in 0.02s (1208 filtered
out); 222 focused tests passed in 0.13s (1007 filtered out), including those 21.
The accepted `cw108_storage`, `cw108_enroll`, `cw108_worker`, `cw108_claim`,
`cw108_lease`, `cw108_fence` and `cw108_drop_worker` contracts cover this bounded
piece. Kleis theories and the checker are unchanged; no repeat formal run was
needed. `cargo check --locked --tests` passes. The agent ran no Rust tests.

The common `ScopedPointers` registry now owns fixed worker rows, separate from
allocation-owner accounts. `with_private_heap_and_workers` preallocates and
charges their actual retained capacity before exposure. Existing
`with_private_heap` callers retain zero worker capacity. The inline directory
and nonwrapping serial are charged by `size_of::<ScopedPointers>()`; the extended
cleanup row, including its lease, is charged once through its actual retained
table capacity. Fabric charges the fixed operation-value scratch allowance.
All size arithmetic and budget checks precede successful construction. This is
service metadata accounting, not a claim to bound the entire emulator's RSS.

Worker handles contain a one-based row and positive, globally nonreused serial.
Each row binds process incarnation, context and domain. Presence of an active
row is the explicit cleanup-role grant; neither an allocation-owner account
nor a process ID confers that role. The Kernel's trusted
`enroll_cleanup_worker` entry point reads the actual Running process descriptor.
A private-constructor, non-cloneable borrowed descriptor prevents mutation
between that check and the Fabric operation. Fabric also checks the current
domain and registered CPU. Claim and lease authentication repeat these checks;
process-slot reuse, a changed context/domain, death, missing CPU registration or
fencing rejects old copies. Migration to another current CPU in the same domain
preserves the context-bound role. No guest syscall or IPC message grants it.

A claim authenticates the full reservation, retained owner, physical/virtual
claims, exact private Fabric row, ObjectId/generation, logical size and rights.
Only attached, Closing, queued jobs with an unowned lease and epoch/revision
headroom can be claimed. A successful claim increments the lease epoch and
shared revision, records its worker, and leaves the job in the pending directory.
It does not change payload, pointer tags, extents, object identity, quotas or
other clients. Enrollment and claim reject stale revisions and exhaustion;
the last lease epoch is valid at MAX, but cannot wrap.

The first profile has only queued/draining cleanup jobs: scrub submission and
its in-flight state have no implementation path yet. Claim deliberately does
not require zero pending legacy work. Its opaque lease is metadata, not byte
authority or evidence that an allocation has drained. Even successful current
lease authentication must not be reused as permission for a later operation.

Supervisor fencing requires the exact active worker handle, works after process
or domain death and at revision MAX, and invalidates every use through the
central worker row. It retains all job leases and unresolved obligations. A
fenced row can be removed only after an actual complete cleanup-directory scan
finds no reference to it; removal never refunds fixed storage or resets serials.
Held and reserved-for-future `Revoking` leases both block removal. No worker
operation can currently exist. A2.3.5b's ordinary CPU requests bind application
accounts, not cleanup-role handles, even when one process holds both roles.
Before enabling worker/scrub operations, removal must also scan those actual
worker references. Removing a cleanup role never consumes application work. Fencing
does not unclaim a job, establish terminal completion or enable reassignment.

All admitted metadata operations finish under the same exclusive Fabric/registry
borrow and allocate no host storage. The new **21 `a235a_` tests** cover the
Kernel boundary, fixed accounting, exhaustion, exact custody, stale identities
and leases, global fencing, unrelated workers, dirty backing/tag retention,
pending work and failure atomicity, with allocation-counter checks. Existing
A2.3.4 tests also cover the shared custody preflight extracted for claim/use.

Run locally on `feat/anka108-protected-allocation`:

```sh
cargo test --locked --lib a235a_ -- --test-threads=1

cargo test --locked --lib -- --test-threads=1 \
  anka64::fabric:: anka64::scoped_pointers:: \
  anka64::placement:: anka64::dev_shell::
```

The second command includes the new tests; it is not an additional acceptance
count. No full suite or CC2 bootstrap is requested for this metadata-only slice.
The accepted full baseline remains A2.2's 1134 tests. A2.3.5a's 222-test focused
run was the accepted focused result at that handoff; A2.3.5b below supersedes
it with 243. No full 1229-test run was reported.

**Following piece: A2.3.5b below**, exact preallocated backend-ticket registration
and pinning, followed by A2.3.5c execution/terminal consumption/current census. Worker
scheduling, automatic exit/fault hooks, recovery, scrub, retirement, backing
release, publication and guest allocation results remain separate work. There
was no working C malloc/free or concurrent-client acceptance at that handoff.
A3 now records that acceptance and A4 records the completed source review.

### A2.3.5b Rust: bounded CPU backend registration and pinned work records

**Developer-accepted, 2026-10-24:** 21 new tests passed in 0.03s (1229 filtered
out); 243 focused tests passed in 0.16s (1007 filtered out), including those 21.
The A2.3.5c source archive matches this accepted implementation. This piece
implements the accepted `cw108_storage`, `cw108_submit` and
`cw108_work_binding` obligations for a narrow software CPU profile, composed
with existing live heap/span/closure checks. It adds no architecture or guest
ABI rule requiring a new Kleis theory. The theories and checker are unchanged;
no repeat formal run was needed. `cargo check --locked --tests` passes.
The agent ran no Rust tests.

**Selected concrete backend.** `with_private_heap_cpu_work` is an explicit
fresh-machine configuration. Earlier constructors have no work backend. Its
two independent fixed arrays hold the work ledger and actual prepared CPU
request records. Request storage includes a 4096-byte owned scalar payload;
the current profile accepts only nonempty read/write spans of at most 4096
bytes within the allocation's logical bounds. It introduces no controller,
DMA, atomic access, integer request decoder or growing legacy transaction log.
CPU class and software-backend identity are fixed by the private record types;
application arguments cannot select another class or backend.

Each opaque work ticket binds a one-based ledger row and a positive,
nonwrapping operation ID. Its source key binds a separate zero-based backend
index, generation and request ID; zero is valid in that source namespace.
The work and source records both retain the exact reservation/owner, object
and generation, logical and physical/virtual extents, rights, submitting CPU,
offset, length and access. The source also pins the exact work ticket. A
successful admission consumes fresh operation/request identities and advances
the source slot's next generation without releasing the occupied slot. Checked
exhaustion retires issuance instead of wrapping; the final source/request value
at MAX is representable and cannot be reused.

`CurrentHeapProcess` is the shared private-constructor borrowed Kernel
descriptor, extracted from A2.3.5a without changing cleanup-role semantics.
Every admission checks the actual Running process incarnation, context, domain
and registered CPU, then current live published heap authority, complete
initialization, exact custody, logical span and existing legacy-pool exclusion.
Cleanup-role enrollment is not required for ordinary application CPU work.
Publication remains unavailable in production; positive tests initialize real
private backing and use the existing explicit test-only publication fixture.

**Atomic registration.** Preflight checks both free capacities, all existing
pin pairs, identity/revision headroom and the complete request before mutation.
Write input is copied into the source's preallocated owned payload; later caller
changes cannot alter it. Read payload starts zeroed and is not a completed result.
The backend source and ledger row then commit in the same exclusive Fabric
operation, with one common revision advance. There is no post-admission
fallible allocation or best-effort ticket insertion. Any rejection leaves
existing requests, IDs, revision, backing, tags and charges unchanged.

Actual retained capacities and target element sizes, including inline request
payloads and fixed operation-value scratch, are charged at construction before
exposure. Inline directory descriptors are already included in HeapFabric's
base charge. Application heap charges and extents do not change on work
registration. This bounds this service's storage; it does not bound all emulator
logs or prove host RSS. Work slots are globally bounded in this first profile;
per-owner work-slot quotas and admission fairness are not claimed. Exhaustion
can reject a new request while preserving another client's already registered
request and allocation.

**Pinning and retention.** Complete bidirectional structural checks reject a
missing ledger/source row, wrong source generation/request ID, substituted
binding or mismatched pin. The trusted `validate_heap_work_ticket` observation
also rechecks current retained allocation and Fabric custody, including after
closure or owner death. This is an exact-binding observation, not a completion,
drain or reusable readiness result. Cleanup claims and worker fencing do not
consume application requests, reset their IDs or refund their charges.

At the A2.3.5b handoff, the backend represented **Prepared requests only**:
execution, terminal transition, row removal, unpin, source-slot reuse and
completion were deferred. A2.3.5c below now connects actual bounded execution
or stopped cancellation to terminal state, visible effects, exact once-only
consumption of both records and a complete current census. Before adding worker/scrub
requests, extend worker-removal checks to their exact worker references.

The **21 new `a235b_` tests** exercise setup charging, independent capacity
failure, no-allocation atomic admission, exact source/pin identity, owned write
payloads, typed/logical bounds, process and CPU checks, private/unpublished
rejection, malformed/orphan records, counter exhaustion, retained custody,
closure with another active client, cleanup-role independence and raw bypass
rejection. A2.3.5a's accepted worker tests remain in the focused regression.

Run locally on `feat/anka108-protected-allocation`:

```sh
cargo test --locked --lib a235b_ -- --test-threads=1

cargo test --locked --lib -- --test-threads=1 \
  anka64::fabric:: anka64::scoped_pointers:: \
  anka64::placement:: anka64::dev_shell::
```

The second command includes the new tests. Both commands are developer-accepted
at the counts above; A2.3.5b's 243 tests were the accepted focused result at that handoff.
The accepted full baseline remains A2.2's 1134 tests; no full 1250-test run was
reported. A2.3.5c below supersedes that focused result. Heap publication, typed
result delivery, working C malloc/free and independent guest clients were
later acceptance steps at that handoff; they are now accepted in A3 and the
required A4 review is delivered below.

### A2.3.5c Rust: bounded CPU effects, terminal consumption and current drainage

**Developer-accepted, recorded 2026-10-25:** 22 new tests passed in 0.02s
(1250 filtered out); 265 focused tests passed in 0.17s (1007 filtered out),
including those 22. The latest archive matches the delivered A2.3.5c source.
The accepted `cw108_terminal`, `cw108_finish`, `cw108_census`, `cw108_scan`,
`cw108_scan_complete` and `cw108_ready` predicates were assessed before enabling
this piece, together with A2.3.3's scalar byte/tag rules and retained-custody
checks. This implements their narrow synchronous software CPU case. It adds
no ISA, C ABI, DMA or asynchronous completion rule; the Kleis theories and
checker are unchanged. No repeat formal run is required for unchanged gates.
These are an implementation mapping and runtime witnesses, not a mechanically
verified Rust refinement or a hardware memory-ordering proof.

**Concrete terminal evidence.** Each actual source record now has a private
`Prepared`, `Committed` or `Cancelled` state. `execute_heap_cpu_work` rechecks
the exact pin, logical span, retained registry/placement/Fabric custody and
legacy-pool exclusion, then performs one bounded read or write under the same
exclusive Fabric borrow. Reads copy precisely the admitted prefix into owned
backend storage. Scalar writes copy the admitted bytes and clear every
intersected protected shadow cell, including partial-cell writes. `Committed`
is set only after those effects finish. No callback, scheduler yield or
partially executing source exists in this profile; stopping and visibility
follow from that synchronous implementation, not supplied booleans.

`cancel_heap_cpu_work` accepts only an exact `Prepared` source. It establishes
that execution never started, zeros its private payload and marks it
`Cancelled` (the stopped/faulted terminal case). A notification, timeout,
owner death or worker fence alone does not complete or consume work. Duplicate
execution/cancellation and attempts to cancel committed work reject unchanged.
New access still needs a live published allocation and current process/CPU.
Previously admitted work may finish after owner closure or death using its
retained exact custody; it does not depend on a still-running submitter.

**Consumption is separate from completion.** `finish_heap_cpu_work` reads
terminal status from the authenticated source, validates a fresh complete
ledger/source census, then clears precisely that source and ledger row once.
Prepared, committed and cancelled records all count until consumed. Source
payload is zeroed before removal; read results are currently trusted backend
data and are discarded by consumption. No guest read-result delivery is
claimed. Backend slot reuse requires fresh operation/request IDs and the next
source generation. Exhausted counters stay exhausted. This is request-slot
reuse, not allocation-backing reuse.

The complete scan checks every fixed ledger position and both directions of
every pin. Empty rows contribute zero. Valid foreign jobs are excluded from
the selected job's count, but malformed foreign rows or orphan sources reject
the scan. Actual retained allocation custody is checked for every active row.
`HeapWorkCounts` is diagnostic data: no mutator accepts it as authorization.
The fixed CPU/software profile has no private-heap DMA sources, so its DMA
count is zero by construction, not an unchecked device-completion assertion.

**Current readiness.** The Kernel bridge reconstructs the current Running
worker descriptor; Fabric rechecks its enrolled role, exact lease, Closing
queued job, custody, complete current census and legacy-pool exclusion. Even
with zero registered work, an unregistered conflicting transaction prevents
readiness. The result is an observation only. A future retirement operation
must repeat these checks within its own exclusive operation; neither a cached
`true` nor unchanged numerical revision is a reusable permit. Completion and
consumption use the existing saturating cleanup revision and remain possible
at MAX; new work admission stays closed there. All checks are still repeated.

Effect/finish/count value scratch and the actual source-state storage are
included in setup charges. Admitted operations allocate no host storage.
Consumption, census and readiness leave allocation bytes/tags, extents,
cleanup leases and all allocation/fixed metadata charges intact. Rejected
operations preserve existing work and unrelated clients. Execution modifies
only the selected write span/tags or the selected read payload plus terminal
state/revision. Per-owner work-slot fairness remains a later policy question.

The **22 new `a235c_` tests** cover exact byte and partial-cell effects,
4096-byte boundaries, read capture, cancellation versus completion, once-only
consumption, owner death and worker fencing, complete scans with holes/foreign
rows/orphans, legacy conflicts, current worker/lease checks, saturated revision,
slot reuse and nonwrapping exhausted identities. They use real private
reserve/attach/initialize operations and the existing explicit test-only
publication fixture. They are not guest malloc/free or full A/B/C acceptance.

`cargo check --locked --tests` passes. The agent ran no Rust tests. Run locally:

```sh
cargo test --locked --lib a235c_ -- --test-threads=1

cargo test --locked --lib -- --test-threads=1 \
  anka64::fabric:: anka64::scoped_pointers:: \
  anka64::placement:: anka64::dev_shell::
```

The focused regression includes the new tests; it is not a second independent
acceptance count. Both commands are now developer-accepted at the counts above;
265 tests are the accepted focused baseline. No full 1272-test run was reported;
A2.2's 1134 tests remain the accepted full baseline.
Subsequent sections record accepted queued-job recovery and authority
retirement, followed by the complete trusted cleanup/reuse handoff. Automatic
process lifecycle dispatch, owned guest allocation results and C malloc/free
remain for the next functional delivery. Device work remains disabled. The
required A4 review follows working independent C clients; compiler growth
follows A4.

### A2.3.6 Rust: fenced worker recovery for queued cleanup jobs

**Developer-accepted 2026-10-25:** 21 new tests passed in 0.01s; 286 focused
tests passed in 0.16s (including those 21). No full 1293-test run was reported.
This bounded piece reassigns responsibility for a queued/draining job without
retiring its allocation or releasing storage. The accepted Undertaker
`ut108_fail`, `ut108_recover`, `ut108_recovered_stage` and
`ut108_recovered_done` contracts, version advance, concrete worker fence/claim
rules and current census were assessed before implementation. The first
profile has no scrub progress or scrub backend: its cleanup prefix is zero,
and recovery keeps the job queued. No new architecture/ABI rule or changed
Kleis gate is introduced. The accepted theories and checker are unchanged;
the Rust mapping is supported by runtime witnesses, not a machine-checked
proof of the Rust implementation.

**Two explicit supervisor transitions.** `revoke_heap_cleanup` authenticates
the exact retained worker handle, lease epoch, reservation/owner and actual
Fabric/placement custody. It changes only that held job's lease to `Revoking`
and advances the common cleanup revision. Existing worker-lease authentication
and new claims reject this state. Revoking one job does not fence the worker's
other jobs; the existing global `fence_cleanup_worker` role operation remains
separate. Revocation is allowed before or after that global fence, including
after process/domain death, with pending work or at counter exhaustion. It
never asserts that outstanding effects stopped.

`recover_heap_cleanup` requires that same exact job still be `Revoking` and
the retained worker role be globally `Fenced`. A dead process, reused process
slot, timeout or notification alone is insufficient. Fabric revalidates actual
custody, the complete current CPU source/ledger census and legacy-pool
exclusion before returning the lease to `Unowned`. Malformed foreign rows,
orphan sources and conflicting legacy transactions reject without mutation.
No cached count/readiness flag is accepted; all checks and the commit occur
within one exclusive Fabric borrow, including at saturated common revision.

**Application work is distinct from worker effects.** The enabled source type
contains ordinary software CPU requests, never a cleanup-role reference or
scrub/device request. Software effects execute synchronously under the same
exclusive borrow. Those facts, the complete pin/custody scan and legacy
exclusion establish the current profile's absence of outstanding worker
effects. Already-admitted application requests, including requests submitted
by a process that also held the cleanup role, remain pinned and counted.
They need not be zero for lease reassignment. The replacement worker still
cannot observe drain readiness until they are consumed through A2.3.5c.
Worker/scrub/device admission must extend this reference census and terminal
proof before enabling such effects; ordinary CPU completion is not a DMA fence.

Each reserved cleanup row now stores a nonwrapping mutation `version`,
initialized to zero. This is distinct from the lease epoch and private backing
initialization version. Recovery advances it once; revocation preserves it.
Recovery preserves the old lease epoch in `Unowned`; the next accepted claim
advances that epoch. Stale leases therefore cannot revoke, recover or
authenticate a replacement. Recovery/version exhaustion retains the revoking
job; exhausted lease/worker identities are never reset. Cleanup may advance at
saturated common revision, while new claims/enrollment remain fenced there.
Worker-role removal still requires every held or revoking reference to be gone.

The added field is charged through actual cleanup-row element size and retained
capacity at setup; fixed recovery-plan scratch is also charged. No admitted
revoke/recover operation allocates host storage. Both transitions preserve
allocation state, queued status, memory bytes, pointer tags, initialization
history, physical/virtual extents, ordinary work, owner accounts and all
payload/fixed charges. Successful recovery is neither a clean-memory receipt
nor authorization to reuse backing. Automatic death hooks and worker
scheduling are not connected by these explicit supervisor methods.

The **21 new `a236_` tests** cover per-job versus global fencing, exact
owner/object/worker/epoch binding, process and worker-row reuse, worker/domain
death, retained pending and terminal CPU work, unrelated-client preservation,
current replacement-worker checks, foreign orphan records, legacy conflicts,
version/epoch/worker-ID exhaustion, revision saturation, all-job role references
and repeated bounded worker-row reuse. Cases with application requests use the
existing test-only publication fixture. This is not C malloc/free or the full
A/B/C compiler/backing-reuse witness.

`cargo check --locked --tests` passes. The agent ran no Rust tests. Run locally:

```sh
cargo test --locked --lib a236_ -- --test-threads=1

cargo test --locked --lib -- --test-threads=1 \
  anka64::fabric:: anka64::scoped_pointers:: \
  anka64::placement:: anka64::dev_shell::
```

Both commands are now developer-accepted; the second includes the new tests.
The accepted focused baseline is 286 tests. A2.2's 1134-test run remains the
accepted full baseline. A2.3.7 below records accepted authority retirement.
The complete cleanup/reuse delivery follows it. A3 subsequently establishes
working C malloc/free, and A4 below records the completed review.

### A2.3.7 Rust: authority retirement after current drainage

**Developer-accepted 2026-10-25:** 21 new tests passed in 0.02s; 307 focused
tests passed in 0.19s, including those 21. No full 1314-test run was reported.
This piece implements the accepted `ut108_retire` and `conc107_retire`
transition. `Closing` already fences new application access while admitted
requests drain. `Retired` records that current drainage and authority exclusion
have also passed. Retirement does not zero, unplace, refund or recycle storage.

The contracts were assessed before implementation:

| Formal requirement | Concrete enforcement |
|---|---|
| Exact bound job and current lease | Current Running process incarnation/context/domain/CPU; separately enrolled active worker role; exact held lease epoch and reservation/owner/ObjectId |
| Closing → Retired; zero CPU/DMA work | Fresh complete ledger/source pin and custody census; prepared, committed and cancelled sources all count until consumed |
| No grants/maps or alternate access path | Borrowed census of every retained Kernel process descriptor; Fabric domain grants/device authorities, public object/placement entries, pointer-stack registrations, local backing records and legacy pool/transaction exclusion |
| Retained custody and visible terminal effects | Both placement-manager claims and exact private Fabric row; synchronous software effects completed under the same exclusive Fabric borrow |
| Atomic commit and preserved obligations | Fixed-row state change plus saturating common revision; retained generation, cleanup job/lease/version, owner account, extents, bytes, tags and all charges |

The registry's `Retired` state projects to Undertaker job stage 2 and concurrency
lifetime phase 3. In A2.3's coarser attachment model it remains quarantined, not
released. The existing `queued` flag means a durable pending cleanup obligation;
it remains set in both Closing and Retired. Duplicate attached closure returns
`AlreadyRetired` without changing state or queueing again. Owner closure also
preserves retirement. Neither abort, slot reuse nor owner-account release can
consume an attached retired obligation.

`Kernel::retire_heap_authority` is explicit trusted dispatch, with no new guest
syscall or automatic death hook. Its opaque `CurrentHeapRetirement` holds an
immutable borrow of the entire process slice and binds the selected object.
The census checks all retained descriptors, including exited processes, every
address-map entry (even zero-length or overflowing ranges), every occupied
memory/device capability slot and owned stack/trap object references. It does
not resolve just one virtual address or filter out stale generations. Fabric
then checks current worker identity, exact custody and the complete work census,
plus actual domain authority and alternate legacy paths, before committing in
one exclusive borrow. A caller cannot provide a count, quiet flag or previously
observed readiness value instead. This remains true at saturated revision.

Surviving register, saved-event and storage-cell pointer copies are retained.
Application access still requires the central lifetime to be Live, so restoring
an old event image cannot restore authority. Pointer-kind erasure is not used
as revocation. Physical pointer tags and dirty payload remain for later scrub.
Retirement consumes no generation, lease epoch or cleanup-version headroom;
those identities are retained, never wrapped or reset. All validation failures
precede mutation. Added plan/context scratch is charged at setup; admitted
retirement performs no host allocation.

**Profile boundary at this checkpoint.** The CPU backend admits synchronous
software requests; private-heap DMA, asynchronous worker effects and hardware
caches are absent. CPU drainage is not a hardware/device fence. A2.3.7 used the
queued-only `cw108_claim` and A2.3.6 recovery profile, so a worker failure after
retirement retained custody in quarantine. The complete cleanup/reuse delivery
below explicitly refines that boundary before extending the runtime. No new
Kleis file was needed for retirement itself. Neither gate results nor this
mapping are a machine-checked proof of the Rust source.

The **21 new `a237_` tests** cover dirty/unpublished custody; pending and
terminal-but-unconsumed work; foreign orphan/malformed sources; current worker
identity and lease failure; surviving register/saved-event/cell aliases;
retained dead-process mappings/capabilities/resources; legacy grants, placement,
stack and inactive local backing records; exact owner/object binding;
revision/generation/epoch/version boundaries; duplicate closure; unavailable
retired slot/extents; and unaffected client B work while A retires. Positive
live-access cases use the existing test-only publication fixture. These are
not C malloc/free or the full A/B/C compile-and-reuse acceptance scenario.

The agent compile-checked this handoff; the developer subsequently accepted the
new tests and focused regression at the counts above. The last full run remains
A2.2's 1134 tests. The complete cleanup/reuse delivery below finishes the trusted
cleanup path before the next functional delivery exposes working C malloc/free.

### Complete trusted cleanup and reuse

**Developer-accepted, 2026-10-25:** Kleis 92 positive / 79 hostile; 19 new Rust
tests passed in 0.01s and 326 focused tests passed in 0.19s (including those 19).
No full 1333-test run was reported.
This completes retired-worker recovery, bounded scrub, exact extent release and
payload refunds together. It deliberately replaces the proposed sequence of
separate later-stage recovery/scrub/release handoffs with one functional result.

**Formal-first evidence.** `anka108_cleanup_reuse.kleis` and its hostile pair
passed locally before runtime implementation: **92 positive witnesses, including
13 quantified or structural laws; 79/79 hostile assertions explicitly
disproved**. `scripts/check-anka108-gates.py --only-cleanup` selects only this
pair, and the complete/`--only-allocation` modes include it. Unchanged gates
were not rerun. Developer acceptance of this pair brings evidence across focused
runs to 1532 positive / 1150 hostile. This is a sum of separately reported runs,
not a newly executed combined gate.

The new profile imports the accepted worker/Undertaker contracts rather than
rewriting their restrictions. `cr108_claim` adds recovered retired jobs while
preserving `cw108_claim` as queued-only. Recovery resets Scrubbing/Clean jobs to
Retired with zero completed prefix and a changed version; the next claim uses
a fresh lease epoch. `cr108_chunk` composes submission and terminal completion
under one exclusive software operation. `cr108_release` explicitly permits a
saturated common revision when the exact current snapshot and both prepared
returns are checked within that same exclusive operation. Below saturation it
refines `ut108_release`; saturation is an intentional extension, not a wrapped
revision or cached readiness exception.

| Contract obligation | Concrete implementation |
|---|---|
| Retired lifetime remains inaccessible | `SlotState::Retired` persists while the charged cleanup job moves through Pending, Scrubbing and Clean; application paths continue to require Live |
| Current authority for every cleanup effect | Trusted Kernel calls borrow all retained process descriptors; Fabric checks the running worker incarnation, role, lease, exact reservation/job/version/sequence/progress, private row, complete backend census and legacy authority exclusions |
| Bounded complete zeroing | Aligned chunks of 16–4096 bytes (multiples of 16) cover the entire rounded backing, including padding; byte zeroing, pointer-tag clearing and progress advancement commit together |
| Worker failure and retry | Exact lease revocation and worker fencing precede recovery; no enabled scrub effect survives the synchronous call; replacement starts at zero, retains sequence history and rejects old snapshots |
| Atomic release and exact refunds | Prepare both physical and virtual manager returns before any mutation; commit both, remove private custody/job, refund rounded owner/global payload charge once, and release the slot |
| Reuse preserves identity and accounting | Fixed metadata remains charged; generations and the checked ObjectId floor never rewind; generation exhaustion permanently retires that slot from reuse |
| Clean backing does not authorize a new allocation | New lifetime attachment still requires its own current initialization evidence; cleanup snapshots cannot publish heap pointers |

`HeapCleanupSnapshot` has no external integer constructor. Copying one is safe:
each call rechecks the complete current state, so stale, partial, duplicate,
wrong-worker and recovered snapshots cannot advance or release custody.
`Kernel::begin_heap_scrub`, `scrub_heap_chunk` and `release_clean_heap` provide
explicit trusted dispatch. There is no new guest syscall in this delivery.

Release does not rescan the entire payload. The monotonic contiguous prefix
establishes zero bytes and absent pointer tags; all enabled writers reject
retired storage, and every step/release freshly checks exclusions. Bounded
source arrays and precharged scratch preserve the no-host-allocation property
inside admitted cleanup. Counter exhaustion retains obligations unless a
completed clean job can release without issuing a new identity. Fixed table
capacity remains available and charged across reuse; this is not physical
compaction or host-vector shrinking. Existing placement managers coalesce
returned holes.

The implementation adds **19 `a238_` tests** across registry and Fabric/Kernel
layers. They cover exact single refunds, failed two-manager return preparation,
full rounded byte/tag clearing, stale/duplicate requests, versions/sequences
and generation exhaustion, recovery from retired/partial/clean stages, changed
worker incarnations, newly retained process maps and legacy grants, orphan
backend work, rejected old writers, repeated bounded reuse and coalescing after
arbitrary release order. The A2.3.7 retired-worker failure witness is updated to
require revocation and fencing before recovery instead of permanent quarantine.

One new service-level witness runs A and B with independent allocations and
pending work: A exhausts its quota and exits; cleanup returns A's backing; C
reuses it with a fresh identity; B's pending work remains intact and completes
correctly; A's stale aliases fail. Positive live access still uses the existing
explicit test-only publication fixture. **This is not evidence of concurrent C
compiler jobs or supported C malloc/free. The developer has now passed this
service-level test as part of the 19 new tests.**

Cleanup verification: `cargo check --locked --tests` passed, and the developer
subsequently passed the focused commands below. The agent ran no Rust tests,
long suites or CC2 bootstrap. These are historical commands, not a request to
repeat unchanged gates:

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis --only-cleanup

cargo test --locked --lib a238_ -- --test-threads=1

cargo test --locked --lib -- --test-threads=1 \
  anka64::fabric:: anka64::scoped_pointers:: \
  anka64::placement:: anka64::dev_shell::
```

The accepted focused baseline is now **326 tests**, including the 19 new tests;
the last accepted full library baseline remains **1134 tests**. Filtered runs
do not establish a new full-suite result.

### A3 — Supported C malloc/free and the protected application runtime

**Developer runtime acceptance reported 2026-10-25; the entry-fixture
regression is resolved.** The corrected shared integration passed in 1026.53s;
the required A4 source review follows below.
This connects the accepted allocator/reclamation components to ordinary compiled
C code. It is a functional allocation/use/free delivery, including exit cleanup,
not another prerequisite-only handoff. No Rust tests or CC2 bootstraps were run
by the agent; `cargo check --locked --tests` passes.

**Formal-first refinement.** `anka108_malloc_runtime.kleis` imports the accepted
allocation ABI and cleanup/reuse models. Before implementation its **52 positive
witnesses (including 9 quantified or structural laws) and 43 hostile assertions**
passed locally. `--only-malloc` runs just this pair; full/`--only-allocation`
selections include it. A developer rerun has not been reported; the recorded
local pass supplies the formal-first evidence. The model
covers exact one-use saved events, publication after current initialization and
custody checks, owner-qualified access, null/object-pointer conversion, free
retirement, and pointwise death fencing. Current Kernel/Fabric checks discharge
its abstract readiness predicates; passing models are not a proof of the Rust
or generated C implementation.

| Boundary | Implemented behavior |
|---|---|
| C interface | Protected profile 2 recognizes `malloc(int)` and `free(void *)`; `/include/stdlib.h` supplies optional matching prototypes. A `void *` can convert to/from object pointers without changing either word or kind. Literal `0` (also parenthesized) converts to canonical null; arbitrary integers do not. Pointer equality/inequality, null conditions, typed pointer-to-pointer dereferences and stores are supported. `void *` dereference remains rejected. |
| Trap/result ABI | Syscalls 21/22 follow A1's registers. Allocation returns the pair in R0/R1 and scalar status in R2; the compiler uses PMOV to preserve kind. Free stages its argument in R2/R3 before setting scalar controls. An owned saved syscall image has a nonwrapping event identity and one-use result state; publication and pair/status replacement commit together. Scalar overlays, changed events, foreign incarnations and duplicate result use are rejected. |
| Allocation publication | The Kernel derives owner process/incarnation/context/domain, reserves quota and custody, initializes the full rounded backing in chunks of at most 4096 bytes, then checks current worker, all retained process maps/capabilities/resources, Fabric exclusions, source/ledger census and exact initialization. Failure exposes no pointer; attached failed staging is closed and remains charged until cleanup. |
| Heap access and storage | Core PMOV/PADD/PREAD/PWRITE and pointer cells select the private heap row and exact owner. Local stack spills preserve opaque heap tokens; reload reauthenticates the current lifetime. Heap cells authenticate both destination and source. Ordinary writes clear overlapping kinds. Numeric address-map paths cannot access private backing. Typed byte input/output accepts validated heap spans. |
| Free | Null is an immediate no-op. Only an authenticated whole-allocation base from the same owner can free. Closing fences all aliases immediately. The service waits for current retirement, full scrub, exact extent return and payload refund before acknowledging nonnull free; this is stronger than the ABI's minimum retirement condition. Invalid free faults, after which ordinary process-fault cleanup is a separate transition. |
| Process lifecycle and cleanup | Exit, fault, orphan termination and reclamation close the exact incarnation's allocations. A kernel-owned cleanup worker uses existing roles/leases; each scheduler visit scans a bounded directory and performs at most one 4096-byte scrub chunk. Failed checks retain custody/charges. Normal runner teardown drains eligible jobs and removes its worker role. Blocked or inconsistent work remains quarantined, not declared reclaimed. |
| Independent clients | One service accounts for separate process owners. A client's exhaustion or exit cannot free another owner's backing. Fresh allocation after reuse gets a new lifetime and fully zeroed backing, with no inherited pointer kinds. This software scheduler interleaves clients; it does not claim host-thread or SMP execution. |

`malloc(0)` returns null/status 0. Negative/unrepresentable signed sizes return
null/status 2; positive allocation/admission failure returns null/status 1.
The initial software profile uses page-rounded physical storage per allocation
and exposes only the requested logical span. The protected application runner
reserves a 2 MiB physical pool at `0x800000`, outside its existing placement
pool, with a 1 MiB per-process payload quota. Its stable directory has 4096
slots/scopes, 64 owner rows, 512 cleanup/physical claims, 128 virtual claims per
owner, one cleanup role and 16 CPU work/source rows. A 64 MiB accounting ceiling
includes the fixed metadata allowance; it is not 64 MiB of physical heap RAM.
These are explicit initial runtime policies. This delivery does not remove the
compiler's source/output/table capacities or implement `realloc`, small-block
suballocation, heap sharing, private-heap DMA or FPGA/cache coherence.

Protected standalone rebuilds and receipt-bound protected-module executions use
this profile. The module linker constructs its retained Fabric with a disjoint
heap pool; later execution preserves the original artifact/dependency identity.
The linker itself still uses its existing fixed workspaces. Generic `Fabric::new`
and legacy applications are not silently converted; other trusted runtimes opt
into a heap profile and enable the service explicitly.

**Developer evidence, 2026-10-25:** the full run reported **1344 passed, 1
failed in 1967.45s**. The only failure was the long rebuilt-application test;
all twelve `a3_` unit tests passed. These cover actual
publication, canonical failure/null results, owned Core access, cancellation and
free waiting, refund timing, old-event aliases, cross-client denial/reuse,
heap-cell invalidation, saved-event replay/substitution, and partial/dirty or
raw-mapped publication rejection. The CC2 fixed point closed at 186920 bytes
for both CC2_1 and CC2_2, entry 184232; the existing protected-module positive
and hostile cases also passed. That run stopped at the first malloc probe.
The corrected developer rerun passed the entire shared-producer test: **1 passed,
0 failed, 1344 filtered out in 1026.53s**. It reached every acceptance case below:

- `/bin/malloc_probe.c`: null conversions, calls/returns, char/word/pointer-cell
  allocation, typed output `[65,0,255,66]`, repeated free/reuse and exit with a
  live allocation; the same sealed application runs twice.
- Typed heap input/output, compile rejection of scalar forgery and void
  dereference, and runtime rejection of stale, duplicate, interior, local-frame
  and heap-cell aliases.
- Actual independent compiled C clients: A allocates 8192 bytes, exhausts its
  8192-byte quota and exits; B retains and verifies 4096 bytes; C obtains A's
  observed physical extent, verifies all 8192 bytes are zero, and frees it.
  The fast runtime witness separately retains and rejects A's old saved-event
  alias. These are allocator clients, not yet concurrent compiler jobs.
- Two independently compiled modules: a callee returns allocated heap storage
  across its frame exit; the caller writes and frees it. The exact receipt-bound
  linked image executes twice with unchanged publication identity.

CC2's expression parser remains within its existing 32 parameter/local slots
by reusing temporaries; no compiler capacity constant was raised. The corrected
developer run closes the concrete fixed point: CC2_0 164840 bytes; CC2_1/CC2_2
186920 bytes, entry 184232.

Focused commands for future affected changes (the runtime tests already have
developer evidence; this documentation update requires no repeat):

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis --only-malloc

cargo test --locked --lib a3_ -- --test-threads=1

cargo test --locked --lib \
  p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address \
  -- --test-threads=1 --nocapture
```

The full run and corrected focused rerun resolve the sole reported failure;
do not combine them into one all-green full-suite claim. Reserve the next full
suite for a subsequent cross-cutting implementation checkpoint or concrete risk.
Unchanged Kleis suites need no rerun for the fixture correction or A4 review.

**A3 direct-entry fixture correction, 2026-10-25.** The first malloc probe
reported `ProtectionFault` at PC `0x12e8`, object/offset zero. Its new `main`
used plain `return`, despite the existing direct-entry ABI documented in DN-69:
no startup caller has minted return authority. Protected CC2 emits PUNFRAME/RET
for a return, and the Core rejects RET without that authority. This repeats a
fixture error already corrected for the protected-module witness; the machine
must not accept an unauthenticated return to make a test pass.

The correction changes all 11 exit paths in `malloc_probe.c` and 22 exit paths
across the 13 inline C entry functions to `return syscall(0, status, 0, 0);`.
Called helpers (`identity`, `empty`, `buffer`) keep ordinary return semantics.
The hostile fixtures also exit normally if their forbidden operation is wrongly
accepted, so the final entry RET cannot produce a false-positive ProtectionFault.
Guard failures now report their explicit exit status. The positive assertion
also reports output bytes on failure. Compiler, allocator, Core and Kleis
contracts are unchanged; no new formal gate or unchanged-gate rerun is required.

The agent checked every changed C main exit path, preserved helper returns,
and ran `cargo check --locked --tests`; it ran no Rust tests or bootstrap.
The developer's corrected run then passed all C cases, reaching the diagnostic
`protected malloc/free: C probe + typed I/O + hostile aliases + independent A/B/C reuse passed`.
Hostile faults and compiler rejections are expected assertions within that pass.

**Checkpoint reached:** working malloc/free with independent C clients satisfies
A4's entry condition. The review below is complete; its gaps are follow-up work,
not a reason to repeat the audit or reopen A3 acceptance.

### A4 — Post-malloc whole-stack review (2026-10-25)

**Review delivered; implementation follow-ups remain open.** The protected
allocation service and supported C malloc/free now have formal-first and
developer runtime evidence, including independent concurrent clients. This
checkpoint reviews the stack as clients of that service before compiler growth.
It does not close Phase 10.8 or establish that every layer is migrated. Track
these findings in subsequent work; repeat only analysis affected by new changes.

#### Evidence and scope

Source basis: the supplied `Archive(20261025-151242).zip`, the delivered 28-file
malloc implementation and the four-file `anka108_malloc_exit_fix.zip`. The exit
patch SHA-256 is
`a8004ea841efb9e5af5e7124db3af5e2cf0fe4bca450965518da3cdf760edb27`.
The developer reports the feature branch synchronized with its remote. This is
an inspection of the available delivered source, not verification of a named
remote commit or unreported local edits.

- The malloc runtime theory passed **52 positive / 43 hostile** locally before
  implementation; the earlier allocation/cleanup gates have developer evidence
  above. A separate developer rerun of the new pair has not been reported.
- The developer full run reported **1344 passed / 1 failed in 1967.45s**;
  all twelve new `a3_` unit tests passed. The sole failure was the new direct-entry
  C fixture's plain return from main.
- After the explicit-exit correction, the developer reported **1 passed /
  0 failed / 1344 filtered out in 1026.53s**. The exact CC2 chain closed again:
  CC2_0 164840 bytes; CC2_1/CC2_2 186920 bytes, entry 184232. The shared test
  reached the malloc, hostile, concurrent-client and linked-module cases.
- These are results across two revisions/runs, not a single green 1345-test
  suite. This review runs no Rust tests or new Kleis gates and changes no
  runtime, compiler, C fixture or theory source.

#### Layer evidence and gaps

Paths below are relative to `src/anka64/` unless otherwise qualified. Formal
witnesses establish their models under stated assumptions, not all Rust/C code.

| Layer and inspected source | Implemented mechanism and evidence | Gap or assumption; follow-up |
|---|---|---|
| Memory, placement, Fabric — `scoped_pointers/heap/`, `placement/bounded.rs`, `fabric/heap/`, `fabric.rs` | Fixed directories retain generations; quota, extent, shadow and cleanup capacity precede publication. Owner/custody checks, full rounded byte/tag initialization and CPU-only private access protect heap lifetimes. Closure fences aliases; retirement, scrub and exact release precede reuse/refund. Physical and per-owner virtual holes coalesce. Generic grants, placement and raw access reject the private heap pool. | Legacy objects are not automatically owner-budgeted heap allocations. Generic destruction/release is not a scrub receipt. Page rounding, finite metadata and fragmentation remain admission limits. Live compaction and small-block suballocation are deferred. Preserve the explicit pool boundary during compiler migration and include legacy metadata in C1's budget inventory. |
| CPU, pointers, calls, saved events — `core.rs`, `core/heap.rs`, `pointer_frames.rs`, `fabric.rs::issue_pointer_frame` | Heap transport and local/heap spills reauthenticate current lifetime/owner. Saved syscall replies are exact-event and one-use. The accepted unit witness restores an old saved alias after death/reuse and rejects its use. Direct-entry main uses SYS_EXIT; helpers return normally. | **Historical A4 finding, closed by accepted R1 below:** frame issue previously cleared pointer-cell tags without wiping payload bytes. R1 now initializes the whole frame before publishing new local authority, preserving parent spans, validated arguments and return authority. Retirement still need not scrub eagerly. Focused Rust, guest C and full-suite results establish acceptance for this implementation scope. |
| Processes, domains, scheduling — `os.rs`, `os/heap_application.rs`, `os/heap_context.rs` | Ownership binds ProcessKey generation, context and domain. Exit/fault/orphan/reclaim close that owner's allocations. Free waits on an exact saved event until scrub/release/refund. Cleanup rechecks retained process maps/capabilities/resources and current work. A/B/C uses one Kernel with interleaved clients. | This acceptance is software interleaving, not simultaneous host threads/SMP. Malloc initializes every chunk synchronously in one handler; a 4096-byte chunk does not imply a scheduler yield. Process/context tables and scans lack complete per-client accounting; some legacy identity exhaustion paths panic or use ordinary increment. C1 must specify resource admission/denial, cleanup service capacity and conditional progress. |
| IPC and buffer ownership — `os.rs::handle_send_key`, `handle_send_cap`, message/capability tables | Messages bind process incarnations. Capability delivery validates source authority, attenuation, receiver capacity and route; receive reveals the installed handle. Private heap pointers are not exportable through legacy grants. | Notification/delegation does not revoke all sender aliases or transfer exclusive ownership. Before adversarial shared-buffer reuse, specify a typed trusted handoff with centralized lifetime/ownership-epoch change, exact recipient incarnation, drainage and failure atomicity. Register clearing and compiler publication cannot supply these semantics. No new instruction is selected here. |
| Drivers/controllers/DMA — `nic.rs`, `block.rs`, device dispatch in `os.rs`, `fabric/heap/work/` | NIC RX enters a bounded device-private queue and targets an existing object/span through a narrow temporary WRITE delegation; TX uses READ. Request generation, requester and delegation identify completions. Temporary DMA domains retire after terminal Fabric transactions. Private heap work currently supports the bounded CPU backend; generic DMA into the pool is excluded. | This is not a per-packet heap lease or a DMA pin on malloc storage. Enabling heap DMA requires exact allocation/lifetime/span/rights/request binding, retained charges, and actual completion/cancellation before reuse. Death or timeout is not drainage. Controller-held transaction indices constrain history reclamation. Hardware visibility/cache obligations remain deferred. |
| Compiler/preprocessing — `dev_compiler.rs::run_compiler`, `source_bundle.rs::run_ankapp_with_capacity`, `cc2_fixed_point.rs`, `userspace/system/compiler/` | Guest tools produce source/output bytes; the exact fixed point passes. Current host invocations create separate Fabric/layout/mutable workspaces. Sealed inputs and controls are checked; output transfer uses bounded Fabric transactions. | These jobs do not yet allocate their mutable regions through the shared service in one machine. The A/B/C test compiles client images before running them concurrently. Fixed numeric workspace locations, source/output and table ceilings remain. C1 must define job/attempt identity, complete budgets and region/result ABI; C2/C3 migrate resources and implement bounded capacity/retry outcomes. |
| Linking/publication/receipts/loading — `ankald.rs`, `compiler_adapter.rs`, `compiler_adapter/protected_modules.rs`, `dev_runner.rs`, `system_image.rs` | Guest link results are checked against modules/calls/frames. Ordered dependencies, tool/source/profile identity and publication epochs bind sealed READ artifacts. Execution authority is separate and revalidates closure. Module execution preserves artifact identity and opts into the heap. Image loading and process stack/trap reuse explicitly initialize fresh storage. | `RebuildArtifactStore` retains a Fabric/placement instance per record, plus source/tool/dependency copies. Its record maps lack a shared-job retention budget or retirement API. Heap refunds do not charge these retained machines. C1/C4 must budget peak and retained storage and release without invalidating live receipt dependencies. Publication is in-memory; the 1 MiB image policy remains. |
| Network/other services — `userspace/system/services/net/`, `http_tests.rs`, `system_image.rs` | Earlier Ethernet-through-HTTP `/alive` behavior exists. `http_tests.rs` compiles socket/HTTP with CC_B and grants both peers the same 1024-byte stream object. Length/ready/complete messages coordinate the handshake; HTTP has no NIC capability. | Real services still use numeric buffers and word-based byte helpers. Their handshake neither frees a heap allocation nor revokes shared access. Ownership/DMA gates precede the protected service port; then rebuild and run the exact artifacts. No acceptance evidence here establishes a malloc-backed filesystem/file-manager rebuild. |
| Emulator/future hardware trust — `fabric.rs`, `core.rs`, `os.rs`, current Kleis models | Trusted Rust constructs boot state, owners, grants and cleanup roles. Exclusive mutable access serializes the relevant reference-emulator transitions. Current checks enforce model predicates for initialization, custody and terminal work. | Host allocation success, privileged embedding and metadata containers remain trusted assumptions. Hardware needs cache/speculation/interconnect observations, ordering, visibility and DMA refinement. Software acceptance supplies no SMP, hardware zeroing or timing-channel guarantee. Future FPGA work remains deferred. |

The missing shared budget is an availability/accounting gap, not evidence of a
bypass of the accepted heap owner check. For example,
`Fabric::discard_completed_compiler_trace` can discard terminal compiler-only
history when no device retains its indices; it is not a general controller-safe
collector. Account for retained capacity as well as live elements, including
fault logs and process/receipt history. Quarantined backing remains charged;
permanent inconsistency must not be described as successful cleanup.

#### Required A/B/C scenario: accepted and outstanding evidence

| Step | Available evidence | Actual compiler-job obligation |
|---|---|---|
| A and B run concurrently | Independent compiled C clients interleave in one Kernel and 16 KiB heap pool, with 8 KiB owner quotas. | Launch two actual CC2/preprocessor jobs in the shared-service machine, with private mutable regions and frozen inputs. Separate host invocations/Fabrics are insufficient. |
| A exhausts or exits | A allocates 8192 bytes, receives null on another allocation, writes markers and exits with a live allocation. | Force exhaustion during parsing/output growth and terminate another attempt mid-build; no partial publication or success-epoch consumption. |
| C reuses A's backing | C obtains A's observed physical extent and checks all 8192 bytes are zero. After completion, payload charges return to fixed metadata. | Admit C's compiler job on returned storage with fresh job/attempt/lifetime identities and its own source/tool bindings. |
| B remains correct | B retains the same extent and checks both end markers before free. | B must emit the expected canonical artifact and valid receipt despite A's failure and C's reuse. |
| A's aliases remain dead | Hostile C cases reject stale/interior/duplicate/local/heap-cell misuse. A separate fast unit test restores A's saved event after death/reuse and rejects the old pointer. | Retain stale compiler-region tokens and delayed attempt messages through reuse; reject each without changing B/C. No single C test is claimed to execute the saved-event restoration. |

C5 retains the actual concurrent-compilation scenario. Also cover near-global
exhaustion, metadata/admission failure, foreign free, stale completion, and
authorized immutable tool sharing. Serial host tests can execute these guest
interleavings; they need not run in parallel to establish that behavior.

#### Required Kleis gates and bounded follow-up order

R1's theory pair and runtime are developer-accepted; the passing execution
evidence and implementation boundary are recorded below. The C1 compiler-resource pair is delivered below; the other new filenames remain **proposals only**,
not delivered theories or passing results. Existing gates retain their stated scope. After a contract changes,
rerun affected/importing gates; unchanged independent gates need no repeat here.

| Work item | Formal gate before implementation | Bounded acceptance |
|---|---|---|
| **R1 — local-frame initialization, accepted** | Delivered `anka108_local_initialization.kleis` and hostile counterpart, composing memory initialization, frame/encoding, kind/representation and saved-event contracts. The focused result below covers full-frame byte/tag initialization after complete preflight and before new authority. | Developer acceptance: 16 focused tests, the shared CC2 integration and the full 1361-test suite pass. A writes a secret; a later fresh local at reused storage reads zero. Parent/parameter data survive, nested/event-suspended lifetimes remain valid and escaped aliases still fault. |
| **C1 — shared compiler resource/ABI contract** | The delivered `anka108_compiler_resources` positive/hostile pair covers job/attempt identities, owner/global peak budgets, metadata/retained artifacts, work/retry limits, typed capacity outcomes and nonwrapping denial. Refine compiler-adapter/rebuild/protected-module, allocation/cleanup and lifecycle gates where boundaries change. Specify the concrete ABI revision and legacy metadata/history bounds together. | A finite C2-C5 plan and complete resource/limit inventory. Invalid hints, denial and stale events preserve B and prior receipts. This uses the accepted allocator. |
| **C2-C4 — resource migration and growth** | Compose C1 with `anka106_compiler_virtual_layout`, `anka105_include_preprocessing`, `anka104_ankald_process_abi`/static-linker and protected artifact/frame gates. Preserve lineage, checked encodability, exact used bytes and capacity-independent output. | Output growth/retry first; then source/tables; then linking/publication/loading. Cross actual old boundaries and preserve receipts on denial. C5 subsequently re-establishes the fixed point and real compiler A/B/C scenario. |
| **Service ownership boundary** | Proposed `anka108_buffer_ownership` positive/hostile pair, then a concrete runtime ABI refinement. Compose lifecycle/IPC/capability and `anka107_pointer_concurrency`: centralized revocation/new authority, recipient incarnation, failed-transfer preservation, bounded borrows and current drainage. | A epoch 12 → B 13 → A 14: old saved/spilled epoch-12 aliases remain invalid despite matching owner/address. Reject stale notifications/dead recipients. Define explicit typed handoff before porting shared-buffer clients. |
| **Heap/controller boundary** | Proposed `anka108_heap_dma` positive/hostile pair before admitting private heap buffers to devices. Compose `anka93e3_nic_controller`, `anka93e4_finite_nic_dma`, generic device, heap worker/reclamation and pointer-concurrency contracts. Bind allocation/epoch/span/rights/request to current terminal controller state. | Pending DMA prevents release/reuse; death/cancellation cannot drop accepted work; stale completion cannot affect C; failed admission preserves RX input/credits. Keep current denial until this boundary is accepted. |

**Order:** R1 is closed. Follow C1 → C2 → C3 → C4 → C5 using the shared allocator. Schedule ownership and DMA
refinements before enabling those interfaces in the real network rebuild.
The accepted allocation service and delivered A4 review remain the baseline;
the full protected socket/HTTP rebuild and Phase 10 hostile/CPU-to-HTTP closure
still require their own end-to-end evidence.

**Deferrals:** moving compaction, small-block suballocation, realloc,
unrestricted heap sharing, durable artifact storage, arbitrary legacy-C
compatibility, hardware DMA, SMP and timing/cache guarantees. R1/C1 do not
depend on completing these directions. The existing single trust-anchor
direction, currently considering OIDC, gains no new implementation scope here.


### R1 — Protected local-frame initialization refinement (2026-10-26)

**Formal gate and runtime accepted; final execution evidence recorded 2026-10-27 below.**
The runtime delivery uses `Archive(20261026-212200).zip` as its baseline.
It includes the previously delivered R1 theory pair and checker selector,
which are absent from that archive, without changing their formal content.
The developer reports 151 positive and 118 explicitly disproved hostile
witnesses. No Rust tests or CC2 bootstrap were executed for this delivery.

The reviewed baseline gap was in `Fabric::issue_pointer_frame`: it registered new
locals and cleared their overlapping pointer-cell tags, but left old payload
bytes in place. The accepted implementation below closes this gap. Clearing authority tags
alone does not establish confidentiality
for a **new valid pointer** to that storage. R1 requires a successful new local
read to observe initialized bytes, independently of the previous occupant.

The supported CC2 ABI permits a simple rule: **zero the entire new aligned
frame before publishing its local descriptors**. In `ankacc2_stage3.c`, `q47`
stages evaluated arguments in caller-owned typed spills and reloads the ABI
registers before CALL. `q52` emits PFRAME before storing the incoming registers
into the callee's parameter locals. Thus incoming arguments survive in registers;
parameter stores and explicit initializers overlay the clean frame afterward.
Padding and unused spill space are also cleared. Only manifest locals receive
descriptors; clearing padding does not authorize access to it.

| Transition obligation | Concrete implementation boundary |
|---|---|
| Exact current identity and geometry | Derive the new frame from the private cursor, never guest FP/SP. Check current context/domain, stack object/generation, sealed code, exact entry and fresh activation. Check the complete virtual stack and its current physical backing, alignment, subtraction/addition bounds and RAM limits. |
| Complete preflight | Validate every manifest local and pointer-slot shape, same backing/generation and exact relative offset, pairwise nonoverlap and full-frame READ/WRITE authority. A bad later entry must not clear an earlier local. |
| Reserve before mutation | Reserve scope, eligible nonterminal descriptor slots, registry revision headroom, registration/result storage and the Core active-frame push. Allocation or validation failure precedes the first byte/tag write. |
| Physical exclusion | Recheck all live or event-suspended overlapping storage, outstanding CPU/atomic/DMA work and external readable/writable authority over the exact physical frame. Virtual disjointness or the same domain alone is insufficient. |
| One serialized commit | With exclusive Core/Fabric state, zero all frame bytes and remove all overlapping pointer-cell tags, then publish the descriptors and cursor/FP/SP. No yield, callback, allocation or fallible validation may intervene after the first mutation. Completion is trusted work performed in this operation, not a caller's clean flag or receipt. |
| ABI and lifetime preservation | Preserve incoming register words/kinds, LR, flags, protected return state and all storage outside the new frame. Fresh generations still authenticate every local access. Restoring a saved pointer kind cannot revive an expired descriptor. |
| Event and retirement distinction | ERET resumes an existing frame and must not reinitialize it. PUNFRAME retires authority; it need not eagerly wipe bytes. A later admission clears reused storage before issuing the new lifetime. |

`local108_geometry` checks virtual and physical geometry; `local108_member`
and `local108_fold` express validation of the complete local list.
`local108_capacity`, `local108_quiet` and `local108_prepare` state the remaining
preconditions. `local108_byte`/`local108_tag` give the exact write footprint,
and `local108_issue` derives publication from the complete synchronous clear.
The concrete two-local child-frame trace establishes positive access to zeroed
bytes, not merely rejection of an old alias. Quantified laws cover all bytes
and tags in/out of the extent, failure preservation, argument preservation,
checked arithmetic and independence from the previous contents. Physical-end
bounds are proved through projection-base, remaining-room and checked-addition
lemmas; their composition uses the exact translated frame base.

These are executable model refinements with **no new axioms**. Complete-list
validation, actual authority/work census, stable translation, host storage
reservation and serialization remain concrete implementation obligations;
their model predicates are not guest inputs. This is not a proof of the Rust
implementation, arbitrary concurrent hardware execution or recoverable partial
hardware writes. Cache visibility, speculation and asynchronous hardware scrub
remain in their separately deferred refinement.

Developer-accepted on 2026-10-26: **151 positive witnesses (26 quantified laws) / 118 explicitly disproved hostile witnesses**:

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis \
  --only-local-initialization
```

The new pair is also included by `--only-allocation`, `--only-108` and the
default complete run. `--only-initialization` keeps its existing residual-data
pair scope. The imported theories are unchanged; no independent old suites need
rerunning for this delivery. Unknown, timeout, parse/evaluation failure and
missing witnesses still fail the checker.

**Runtime delivery (2026-10-26).** Core retains the admitted stack object,
generation, offset and full virtual bounds. Every PFRAME rechecks current
translation and complete physical geometry, derives its frame from the private
cursor, validates exact local mappings and reserves registrations and active-frame
capacity. Fabric requires full-frame READ/WRITE authority, validates all local
ranges, reserves returned pointers and checks fixed registry capacity/revision
before the first write. The immutable validated manifest supplies local alignment
and pointer-cell shape checks.

Fabric's new `local_frames` module checks actual current authorities and pending
transactions, including captured physical addresses after logical rebinding.
Overlapping active/sealed object aliases, live frames and legacy live local
backings deny admission. Complete-frame custody, including padding and zero-local
frames, is stored in the existing bounded scope table. Event suspension retains
that row; retirement removes it. The larger scope row is included automatically
in the registry's `size_of`-based fixed metadata charge.

Under exclusive Core/Fabric state, commit clears the full frame payload and
physically overlapping pointer-cell kinds, then publishes descriptors and FP/SP.
No validation or host allocation follows the first mutation. Unrelated bytes,
pointer cells, registers/kinds, flags and return authority remain unchanged.
The synchronous reference machine has no partial-write/yield boundary here.
ERET does not scrub; later frame reuse does. PUNFRAME still need not wipe bytes.

**Supported profile:** a private stack has only its currently registered CPU
agent in the owner domain during admission. Another registered agent sharing
that domain causes denial. Trusted scheduling must keep registrations current.
This is conservative exclusion in the CPU-only emulator profile, not a claim
of simultaneous SMP, cache coherence or hardware DMA safety.

Added **16 focused Rust tests** cover payload/padding/kinds, typed null storage,
late validation failure, complete authority, scope/descriptor exhaustion,
physical alias and CPU/atomic/DMA work exclusion, unrelated pending work,
current agents/grants, stale generations, parent arguments and nested events.
`userspace/bin/local_initialization_probe.c` checks fresh and reused C locals,
null pointer cells and nested argument preservation. It runs inside the existing
shared-producer integration, with no additional CC2 bootstrap. Main explicitly
uses SYS_EXIT, while helper functions return through protected calls.

Compilation check: `cargo check --tests --offline` passed. The developer
reports all 16 focused R1 Rust tests passing in 0.02s; the corrected C integration
and full suite also pass, as recorded below. Reproduction commands from the
repository root (no rerun is needed for this documentation-only update):

```sh
cargo test --lib r1_ -- --test-threads=1
cargo test --lib a21_frame_preflight_rejection -- --test-threads=1
cargo test --lib a21_fixed_metadata -- --test-threads=1
cargo test --lib anka64::core::tests::p107_ -- --test-threads=1
cargo test --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address -- --nocapture --test-threads=1
```

**R1 fixture correction (2026-10-26).** The developer's first focused run
reported 14 passed / 2 failed (0.02s). Both failures were fixture construction
errors: `place_object` rejected overlapping placements, but the tests ignored
its false return. One transaction therefore never acquired a physical address;
the other fixture contained no physical alias for admission to reject.
The captured-work test now prepares a transaction at a legal disjoint location,
relocates its object, and moves the stack over the retained physical span, with
assertions at each setup boundary. The alias test first confirms the public
placement rejection, then explicitly injects malformed placement state inside
the test to exercise PFRAME's independent exclusion check. Production runtime
and Kleis contracts are unchanged. Compilation was checked; the developer subsequently confirmed **16 passed /
0 failed in 0.02s**. The corrected focused fixtures are accepted.

**R1 C-probe correction (2026-10-26).** The subsequent shared integration
failed in 472.14s with `CompilerRejected(1)`, source position 0, source_bytes=1429,
functions=0. CC2_1 and CC2_2 both linked at code/backing=186920, entry=184232;
protected-module publication/execution and expected hostile rejections completed
before the new probe was compiled. This is not a reported fixed-point failure.

The probe incorrectly began with a block comment. Current CC2 `q4` skips only
whitespace and `q14` rejects slash as lexical error 1; the include-only `ankapp`
preprocessor copies ordinary lines unchanged. Removing only the leading comment
keeps the probe within the current C subset without changing its assertions,
compiler implementation or runtime. Source inspection confirms that the new file
starts with its prototype and contains no slash/comment tokens. No Rust tests,
CC2 bootstrap or guest C execution were run during preparation of the correction.
The developer subsequently completed the shared integration and full-suite
gates successfully, as recorded below.

**R1 final acceptance, recorded 2026-10-27.** The developer reports:

| Check | Reported result |
|---|---|
| R1 Kleis pair | 151 positive / 118 explicitly disproved hostile witnesses |
| Focused R1 Rust tests | 16 passed / 0 failed in 0.02s |
| Shared CC2/C integration | 1 passed / 0 failed / 1360 filtered in 1008.62s |
| Full single-threaded suite | 1361 passed / 0 failed / 0 ignored / 0 measured / 0 filtered in 2446.84s |

The shared integration confirms CC2_0 = 164840 bytes and exact
CC2_1 = CC2_2 = 186920 bytes, entry 184232. It reports successful fresh/reused
local initialization, typed nulls and nested argument preservation, protected
module output `[65,0,255,66]` with a matching receipt, and malloc/free with
typed I/O, hostile aliases and independent A/B/C reuse. Expected protection
faults and compiler rejections are hostile-case assertions in that passing run.
The focused and full results are separate runs; no counts or timings are added
together. The older failures remain historical diagnostics, not current blockers.

**Metal 4 plan update, 2026-10-27.** The deferred direction is documented in
[ARCHITECTURE.md, Future Apple Metal Execution Backend](ARCHITECTURE.md#future-metal),
with official Apple references. It now includes M5 GPU tensor accelerators and
Metal machine-learning passes whose inference engine may be selected as GPU or
ANE, alongside ordinary GPU compute. One Anka64 semantic model can underpin
these execution paths; supported model selection does not automatically route
arbitrary guest instructions. Metal 4 command buffers do not retain resources,
so a future backend must retain exact backing/epoch and scratch resources until
matching terminal completion, including mixed GPU/ANE work. Resource retention,
visibility, stale completion rejection and reuse become explicit Kleis obligations
before backend implementation. Independent bounded machine batches remain the
first candidate; no speedup, hardware security or accelerated proof search is
claimed. This direction adds no prerequisite to C1-C5 or Phase 10 closure.

R1 is complete. Proceed directly to C1's shared compiler resource/ABI contract
and the existing C2-C5 milestones. This documentation-only update changes no
runtime or Kleis files and requires no repeat of the accepted test runs.

### C1 — Shared compiler resources and adapter ABI 2 (2026-10-27)

**Formal gate developer-accepted; C2.1 implementation below.** Baseline is GitHub commit
`47105f008ef673876474a216bfe117411d9d6be8` on
`feat/anka108-compiler-resources`. The new
`anka108_compiler_resources.kleis` / `_false_witnesses.kleis` pair passes locally:
**221 positive witnesses, including 26 quantified laws; 195/195 hostile
assertions explicitly disproved.** No unknown or evaluation failure is accepted.
The developer independently confirmed **221 positive / 195 explicitly disproved**
with `--only-compiler-resources` on 2026-10-27. The existing 1361-test full-suite
acceptance remains the integration baseline; C2.1 adds focused Rust evidence
below, without rerunning unchanged Kleis gates or the long CC2 chain.

The model imports the existing allocation contract and reuses its owner/global
budget admission, rounding, virtual disjointness and pointwise account rules.
It introduces no axioms. Request/region/result guards are a specification for
C2-C5, not evidence that today's compiler accepts ABI 2 or grows automatically.
ABI 1 and its enforced limits remain intact until each caller/producer migrates.

#### Decisions and scope

- One frozen job binds an exact source bundle/root, ordered dependencies, tools,
  target profile and immutable resource plan. Nonreused job/attempt/owner keys
  resolve trusted records; an owner includes process incarnation, context and
  domain. Possession of these numeric keys grants no authority.
- New admission reserves job, owner and global peak charges atomically against
  the same current ledger revision. Charge retained capacity, page rounding,
  shadow, metadata, images/stacks, copies, scratch, publications, histories and
  cleanup obligations. Guest counters and requested sizes cannot set quotas.
- A failed attempt remains charged until the accepted close/drain/scrub/return
  machinery finishes. Retry uses a fresh identity and workspace with unchanged
  frozen bindings. No arena copying preserves embedded compiler pointers.
- Growth is `max(round_page(minimum), min(2 * old_capacity, ceiling))`, with
  checked arithmetic and page-aligned positive capacities/ceilings. The model
  branches before doubling to avoid overflow. A valid minimum must exceed the
  old capacity. A requirement beyond the admitted ceiling is BudgetDenied.
- Only a validated NeedCapacity report for a producer-supported resource can
  retry. Source/representation errors, generic legacy error 8, malformed reports,
  faults and timeouts are terminal. Both retry count and cumulatively metered
  execution work are finite; a retry does not reset the work counter.
- Publication requires independent authority, validated complete guest output,
  exact used-prefix copying, a fresh READ artifact, retained-storage charges
  and receipt capacity. A failed attempt consumes no publication epoch and
  preserves prior artifacts, dependency records and receipts.

#### Concrete internal ABI 2

All scalar fields are little-endian u64 words. Magic is `0x41435232` (ACR2),
version is 2, header and reply are each 128 bytes, and every region record is
128 bytes. A request contains exactly `128 + count * 128` bytes. The admitted
plan bounds count at at most 16 unique roles; table entries and payload capacities
inside those roles can grow. Reserved words must each be zero. A different
version/layout is rejected, never decoded as legacy workspace controls.

| Header byte offset | Meaning |
|---|---|
| 0, 8, 16 | Magic, ABI version, header size |
| 24, 32, 40 | Job key, attempt key, exact owner key |
| 48, 56, 64 | Frozen source/root binding, tool-chain binding, target-profile binding |
| 72, 80 | Ordered-dependency binding, immutable resource-plan binding |
| 88, 96 | Region count, record stride (128) |
| 104, 112, 120 | Exact request size, reply size (128), zero reserved word |

Each binding key resolves a complete immutable coordinator record, rather than
an unverified hash or a guest name. All binding words are compared against the
current frozen record on launch, completion, retry and publication. Producer
execution profile and target application profile remain distinct.

| Region byte offset | Meaning |
|---|---|
| 0, 8 | Resource role, exact rights (READ=1 or RW=3) |
| 16, 24 | Exact object identity and current object generation |
| 32, 40 | Protected pointer handle/position pair, position zero |
| 48, 56 | Logical capacity bytes, valid input bytes |
| 64, 72 | Entry stride bytes, entry capacity count |
| 80, 88 | Checked virtual mapping base, actual rounded backing size |
| 96, 104 | Exact owner key, current allocation incarnation |
| 112, 120 | Two individually zero reserved words |

The pair starts on a 16-byte boundary and must carry authenticated pointer-kind
state. Its backing, allocation incarnation, owner, bounds and mapping must match
the actual current allocation record. Mapping addresses and serialized handle
words create no authority. Count-times-stride, logical bounds, every descriptor
and every pairwise placement/physical-alias check precede launch.

Roles are: 1 source; 2 workspace; 3 compiler output; 4 functions; 5 call fixups;
6 local names; 7 typedefs; 8 structure records; 9 fields; 10 enum entries;
11 frame/literal scratch; 12 preprocessing workspace; 13 linked output;
14 linker scratch; 15 request/control; 16 reply. Roles 1 and 15 are READ-only;
other data roles are private RW. Immutable tool RX authority is separate.
Missing roles depend on the selected stage/profile and must be validated by its
trusted schema. Only the explicitly advertised growth subset may emit hints;
C2 initially enables compiler output role 3. Schema/completeness checks are
trusted implementation obligations, not guest boolean certificates.

The resource-aware entry receives a protected READ request pair in R0:R1 and a
protected RW reply pair in R2:R3, installed for the compiler's exact owner before
execution. This is a proposed service entry ABI, not a new opcode or a change
to ordinary application calls. It must be advertised by the admitted producer.
Private heap regions must use authenticated protected access. Neither bootstrap
compatibility nor a numeric mapping authorizes raw loads into private heap.
Legacy code remains on ABI 1 until its corresponding access path is migrated;
remaining legacy storage is still included in the complete resource budget.

Source bytes start at position zero in the ABI-2 source region; their length is
`valid input bytes`, not the old eight-byte envelope. Enough initialized logical
padding must exist for any final aligned word fetch. Padding is not source text.
C2 must preserve the explicit ABI-1 envelope for unmigrated producers.

| Reply byte offset | Meaning |
|---|---|
| 0, 8 | Magic, ABI version |
| 16, 24 | Exact job and attempt keys |
| 32, 40, 48 | Status, resource role, minimum required bytes |
| 56, 64, 72 | Exact used output bytes, source cursor, diagnostic code |
| 80, 88, 96 | Source, tool-chain and target-profile bindings |
| 104, 112, 120 | Ordered-dependency binding, resource-plan binding, zero reserved word |

Guest tags: 0 Success, 1 NeedCapacity, 2 SourceRejected, 3 RepresentationRejected.
The coordinator alone produces 4 BudgetDenied, 5 ExecutionFailure or
6 ProtocolRejected. Guest reports require normal transport exit with code zero,
unchanged controls/bindings, no output execution, stopped writers and actual
drainage. A zeroed or partially written reply cannot count as success.
Success requires the entire source consumed and a validated aligned AOM prefix
of at least 112 bytes, with resource/minimum/diagnostic zero. NeedCapacity
requires used/diagnostic zero and a checked minimum greater than current capacity;
its source cursor is bounded by the frozen input length. Rejections have no
output/minimum/resource and carry a nonzero diagnostic. All unused fields are
canonical. Future stage-specific artifact formats require their own validator;
ABI 2 does not silently change AOM version 1.

A minimum is an untrusted request for a blocked reservation, not a promise of
final size. Even a well-formed inflated hint can consume only the admitted quota,
work and retry allowance. Compiler instrumentation must establish correct hint
production; the coordinator cannot infer C semantics from a numeric request.

#### Source inventory and implementation ownership

This extends the inventory below with concrete source locations and separates
storage policy from language/encoding constraints. It does not raise any limit.

| Current boundary at baseline | Location | Treatment |
|---|---|---|
| Default preprocessed output 20472 bytes; strict adapter source ceiling 65528 | `source_bundle.rs::EFFECTIVE_SOURCE_CAPACITY`; `dev_compiler.rs` source admission | Distinct limits: C3 migrates preprocessing and immutable source regions; preserve ABI-1 envelope/padding during transition |
| Output/tool-image admission 262144 bytes; workspace 24576 bytes | `dev_compiler.rs`; `guest_compiler.rs::WS_SIZE` | C2 output and producer admission; C3 region-based workspace |
| 64 functions at stride 80; 128 fixups at stride 16; 32 local names at stride 40 | `ankacc2_stage3.c::q40/q41/q43` | C3 described tables with checked counts and offsets |
| 32 typedefs, stride 24; 16 structures, stride 48; 64 fields, stride 40; 64 enum entries, stride 24 | `q21/q23/q27/q29` | C3 storage migration; structure codes 100..115 also encode a profile limit, so widening requires the type representation to change coherently |
| Identifier length 63; four parameter slots and protected argument-lane constraints | `q8/q48`, call lowering | Language/call ABI limits, not automatically growable storage |
| Array count 1024; local/structure allocation 8192; frame local/spill records 4096 | `q27/q43/q60`; `pointer_frames.rs` | C3 inventory and C4 admission/runtime refinement where policy is widened; preserve instruction encodability |
| Source member name 127, include depth 32; include cycles rejected | `source_bundle.rs`; guest `ankapp.c` | Name/profile validation remains; C3 explicitly budgets include stack, bundle/member copies and output |
| Linked code+metadata 1 MiB; frame/dependency counts 4096 | `ankald.rs`, `ankald.c`, `pointer_frames.rs`, `compiler_adapter/protected_modules.rs` | C4 coordinated linker/publication/loader budgets and gates |
| Linker scratch derived from input size; format records 112/160/48 bytes | `ankald.rs`; `aom.rs` | Checked sizing and retained peak charge; AOM wire layout unchanged |
| Compiler, preprocessor and linker RAM 16 MiB; compiler virtual ceiling 16 MiB, other tools 8 MiB; tool stacks 16 KiB | `dev_compiler.rs`, `source_bundle.rs`, `ankald.rs` | Provision/account complete machines; C3/C4 migrate policy, preserve target/host address bounds |
| 100000-step quanta and 10000-round launch budgets | Same runners | Meter cumulative work across attempts; reserve cleanup work separately |
| Copy transactions at most 65536 bytes; fixed call/immediate encodings | `compiler_adapter.rs`; ISA/AOM validation | Preserve per-transaction limit while iterating over larger used prefixes; reject unencodable artifacts |
| Process/context/transaction logs, directory/shadow capacity, sealed tool copies and per-record Fabric/placement retention | A4 layer matrix; `compiler_adapter.rs::RebuildArtifactStore` | C1 complete-ledger obligation; C2-C4 charge peak/retained capacity and give retained records a safe release policy |

#### Proof boundary and next implementation

The 26 quantified laws cover checked addition/reservation bounds, full folds,
ABI directory/record containment and pair alignment, foreign-owner preservation,
finite work/retry progress, bounded geometric growth, stale identities, release
arithmetic, exact prefix copying, publication preservation and conditional
canonical byte equality. Hostile witnesses cover overflow, stale snapshots,
foreign owners, raw bypass, unsupported hints, active work, dirty reuse and
publication/receipt failures. The modeled A/B/C sequence preserves B's account,
alias and receipt while A exhausts and C is admitted after A's exact release.

Trusted obligations remain explicit: complete current owner/ledger/region and
work censuses, actual protected-kind authentication, correct meters and staging
charges, full guest artifact validation, and canonical serialization. The
conditional canonical-byte law assumes both guest results represent the same
frozen job; it is not a proof of the C compiler. A header/role bound is not a
proof of the concrete decoder. These guards must be implemented and tested in
C2-C5; no hostile witness count is a claim of whole-stack security or fairness.

With developer acceptance recorded, proceed directly through **C2 output growth**: add the
versioned producer/adapter path and typed capacity result, use checked fresh
attempts and shared allocation admission, then cross the actual 256 KiB boundary.
Retain the C3 source/tables, C4 linking/publication and C5 fixed-point/concurrent
compiler milestones below. C5 still needs actual concurrent compiler jobs:
A exhausts/exits, C reuses its backing, B emits the expected artifact/receipt,
and A's delayed replies and saved aliases fail. This theory's model sequence
and the accepted malloc-client tests do not replace that executable witness.
Existing gates are rerun when those implementations change their boundaries;
unchanged independent gates need no repeat for this handoff.

Run only this new pair:

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis \
  --only-compiler-resources
```

### C2.1 — ABI-2 reply decoder and output retry planner (2026-10-27)

**First bounded implementation piece; C2 output growth remains open.**
`compiler_adapter::resources` implements the scalar part of C1 without changing
any guest compiler source, ABI-1 runner, allocation, publication or artifact
limits. The new API is available to the upcoming ABI-2 bridge; the existing
production compiler path does not call it yet.

The decoder consumes exactly 128 bytes in the specified little-endian layout.
It checks magic/version, job/attempt identity, all five frozen binding keys,
reserved zero, source cursor and every status-specific field. Only an admitted
output-growth producer can return role-3 NeedCapacity. Success metadata requires
an aligned complete output prefix and exact source consumption. Source and
representation errors stay terminal. Guest tags 4/5/6 and generic legacy error
8 cannot trigger retry.

The planner uses checked page rounding and geometric growth, a nonwrapping next
attempt, finite remaining retries and positive cumulatively metered work. It
preserves counters in the proposed next budget; a fresh attempt cannot obtain a
zero-work retry. Over-ceiling requests, stale hints and exhausted work/retries
leave the current budget unchanged. A proposal is only a sizing decision: its
public API has **no commit, allocation, refund, launch or publication operation**.
This prevents a numerical plan from masquerading as completed cleanup or fresh
allocation admission.

Formal mapping: the decoder implements the scalar fields of `res108_report`,
`res108_success`, `res108_need` and `res108_rejected`; planning implements
`res108_page`, `res108_work`, growth arithmetic and the identity/counter portion
of `res108_retry`. It does not establish the model's trusted current-owner,
protected-kind, frozen-record, normal-exit, stopped/drained, artifact-valid,
release or shared-budget predicates. The runner must obtain those facts from
actual current runtime records. No guest-provided boolean substitutes for them.

Developer acceptance: **18 focused Rust tests passed, 0 failed**, with 1361
filtered out, in 0.00s. This independently confirms the local C2.1 result. Coverage includes
all 16 reply words, truncation/trailing bytes/endianness, stale bindings, invalid
statuses and cursor/output geometry, unsupported growth, signed-limit rounding,
work overflow, attempt exhaustion, finite retries and unchanged-state denial.
The arithmetic test proposes growth from 256 KiB to 512 KiB; it is **not** a
compiler-produced artifact or a completed retry witness. The existing 1361-test
full-suite result remains historical integration evidence; no new full suite,
CC2 bootstrap or unchanged Kleis gate was run for this piece.

Run the focused handoff test:

```sh
cargo test --lib anka64::compiler_adapter::resources::tests -- --test-threads=1
```

**C2 integration sequence (C2.2 and C2.3 checkpoints below).** Wire the admitted ABI-2 producer and
protected request/reply transport into the existing compiler adapter. Connect
NeedCapacity to actual terminal/drain/cleanup evidence and fresh shared-service
allocation, keeping complete peak charges and frozen inputs. Migrate the guest
output accesses through authenticated pointers without granting raw heap
access. Then demonstrate a forced retry, exact direct-versus-retried bytes and
an emitted artifact beyond 256 KiB before claiming C2 closure. Continue to use
ABI 1 for unmigrated bootstrap producers. Existing C1 gates cover this planned
boundary; refine them before implementation only if the concrete ABI or
invariants change.

### C2.2 — Protected runtime capacity-retry bridge (2026-10-27)

**Bounded runtime checkpoint accepted; guest CC2 integration remains open.**
`os::compiler_retry` now connects the C2.1 planner to actual protected processes,
shared-service malloc buffers, real CPU execution and the existing cleanup
service. Its internal binding captures an output token from R4:R5 and a 128-byte
reply token from R2:R3, checking current process incarnation/context/domain,
protected kind, exact logical sizes and distinct private allocations. These
are bridge staging lanes; C1's service-entry R0:R1 request / R2:R3 reply
ABI is unchanged. C2.3 below adds that loader; the guest compiler has not migrated.

The bridge reserves cumulative work before each bounded real CPU slice. Its
compile-only dispatch permits malloc/free and intercepts the authenticated
SYS_EXIT trap; execution, device and IPC syscalls are rejected. At a zero exit,
it checks current output/reply custody and the full registered-work census,
then copies the exact reply through the private heap access checks. Outstanding
or terminal-but-unconsumed work blocks capture. Malformed reports, faults,
nonzero exits, source/representation errors, legacy error 8 and budget denial
cannot produce a next-attempt budget.

On a valid NeedCapacity result, normal process completion centrally closes the
owner. Old aliases immediately fail authentication, while storage and charges
remain until the accepted cleanup machinery performs actual retirement, full
byte/tag scrub, exact extent returns and refunds. Polling advances at most one
existing cleanup step; it releases the proposed next budget only after **all**
private allocations and the account for that exact owner are gone. A Kernel-only
receipt gates consumption of the non-Clone proposal, preserving cumulative work,
remaining retries and frozen binding keys. Polling the same completion twice
cannot create another budget. The next process still needs fresh malloc
admission; a returned scalar budget is not memory or execution authority.

Development validation: **11 new runtime tests passed, 0 failed, 1379 filtered
out, in 0.90s**. These use a small admitted Anka ISA producer that performs real
guest malloc calls, protected PWRITE report construction and a real exit trap.
They exercise actual 256 KiB output allocation followed by cleanup and fresh
512 KiB allocation, independent A/B/C backing reuse with B preserved, stale and
forged tokens, changed bindings, malformed/terminal reports, work/budget denial,
forbidden execution and outstanding CPU work. This is **not** a C compilation,
AOM emission, compiler fixed-point or concurrent compiler-job witness. Final
handoff checkpoint was subsequently accepted for progression on 2026-10-27:
the developer reported **12 heap-runtime tests in 0.01s**, and the supplied
archive reproduced **11 bridge tests in 0.82s** plus **18 planner tests in 0.00s**
in the development environment. No long regression, CC2 bootstrap or unchanged
Kleis gate was run for that checkpoint.

```sh
cargo test --lib anka64::os::compiler_retry::tests -- --test-threads=1
cargo test --lib anka64::compiler_adapter::resources::tests -- --test-threads=1
cargo test --lib anka64::os::heap_application::tests -- --test-threads=1
```

C1 supplies the identity/report/work/drain/retry requirements; existing A3 and
cleanup gates supply the actual malloc, closure and release mechanisms. This
piece does not change the architectural contract or add a theory prerequisite.
The ordinary scheduler uses its existing dispatch behavior. The specialized
bridge currently supports capacity-probe attempts only: a Success result is
terminal metadata, not an admitted or published artifact, and this route cleans
its storage. Ordinary compilation continues through ABI 1.

**Remaining integration after C2.3:** migrate the resource-aware CC2 producer,
using the ABI-2 loader, this runtime bridge and a success path that
validates/copies output before releasing its storage. Complete job/owner/global
peak accounting must also include legacy tool/stack/control copies and retained
publications; this patch reuses existing heap accounting and does not claim that
whole-job census is complete. C2 closes only with an actual automatic compiler
retry, emitted AOM beyond 256 KiB, direct-versus-retried byte equality and prior
publication preservation. The existing C3-C5 sequence remains unchanged.

### C2.3 — Protected ABI-2 request loader (2026-10-27)

**Implemented and locally checked; developer acceptance pending.**
`os::compiler_retry::loader` now prepares a fresh, already admitted protected
process for the concrete ABI-2 entry. Its trusted coordinator must select an
ABI-2 producer and supply the frozen effective source and binding keys; this
loader does not authenticate a new tool image or infer its ABI from code.

The shared allocation service reserves, attaches and fully zeroes five separate
regions. Source is read-only, workspace and output are read/write, the 768-byte
request is read-only, and the 128-byte reply is read/write. The request contains
the exact 128-byte header and five 128-byte region records in role order
`1, 2, 3, 15, 16`. Records describe actual object/incarnation, owner account,
logical capacity, valid bytes and reserved virtual/physical sizes. Their five
pointer cells carry protected kind, including an authenticated self-reference
to the request; copying their numeric bytes cannot reproduce that authority.
Entry receives request in **R0:R1** and reply in **R2:R3**. The attempt retains
its output token directly from publication, without an R4 staging dependency.

**Formal refinement before implementation.** The existing compiler-resource
pair now specifies first publication of a checked initialized image, immutable
role rights, agreement between registry and Fabric rights, and complete fresh
entry installation. Local Kleis results: **254 positive witnesses (28 quantified
laws) / 226 hostile assertions explicitly disproved**. The added laws establish
that read-only allocations reject writes and successful writes require matching
writable registry state. Concrete custody, byte/tag atomicity and exact-source
checks remain implementation obligations, tested below; these theory results
are not a proof of the Rust implementation or future hardware.

Rights are fixed at first publication in both the registry and Fabric. A trusted
image overlay follows full zeroing and current custody/drain checks, then commits
payload, protected cells and publication together. Source/request never receive
a writable guest alias. Scalar stores, pointer-cell stores, queued CPU writes
and typed syscall input all check write authority, including empty input spans.
Read-only allocations retain the normal process-death and cleanup behavior.
Ordinary `malloc` still publishes zeroed read/write memory. Arbitrary private
staging writes still invalidate initialization and require a fresh scrub.

The loader rejects a started/stale process, an existing heap account or a source
length mismatch before allocating. Failure after owner admission fences the
process and leaves partial storage charged until actual cleanup. Registers are
installed only after all five regions publish. No scheduler interleaves this
exclusive Kernel operation. Initialization uses the existing bounded scrub
chunks; the complete load is synchronous, and its coordinator work is not yet
part of the instruction-budget meter.

Local validation: **8 new loader tests passed in 0.27s**; **19 bridge/loader tests
passed in 1.36s** (including those 8); **18 planner tests in 0.01s**; and **250 heap
tests in 0.57s**. The ISA producer exercises actual directory PLOAD, source PREAD,
output/reply PWRITE, exit, cleanup and fresh retry loading. Other tests cover
read-only enforcement, numeric-copy forgery, exact metadata/padding, duplicate
entry, partial allocation failure with an unaffected peer, and source bounds.
No CC2 bootstrap or full regression suite was run for this patch.

```sh
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis --only-compiler-resources
cargo test --lib anka64::os::compiler_retry -- --test-threads=1
cargo test --lib anka64::compiler_adapter::resources::tests -- --test-threads=1
cargo test --lib heap -- --test-threads=1
```

**Next bounded task: C2.4, guest producer migration.** Route CC2's source,
workspace, output and reply accesses through these protected regions and emit
the structured capacity result. Preserve the unmigrated ABI-1 bootstrap path.
The C2.3 source ceiling remains 65528 bytes, with initialized logical padding to
the next eight-byte boundary (minimum eight); workspace remains 0x6000 bytes.
Their growth belongs to C3. Successful output capture/admission/publication and
complete job accounting still need integration: the current bridge treats
Success as terminal metadata and releases its storage. The five new regions
use shared heap accounting; legacy tool/stack/control copies and retained
publications still need the complete job census. C2 remains open until the
real compiler produces an automatically retried AOM beyond 256 KiB, matching a
direct adequate-capacity build and preserving prior publication on denial.

### C2.4 — Guest producer migration checkpoint (2026-10-27)

**Status updated 2026-10-31: C2.4 developer-accepted and merged to main.**
Kleis: 293 positive / 259 hostile explicitly disproved; targeted runtime witness
passed in 410.74s; full suite: 1406 passed, zero failures, in 589.71s.
The Rust runs used optimized host execution with debug assertions and overflow
checks enabled. Earlier handoff notes below are historical; C2.5 is next.

The earlier formal-only checkpoint is extended by the implementation below. C2.3 is now developer-accepted: 19 runtime/loader tests passed in
0.56s, 18 planner tests passed in 0.00s, 250 heap tests passed in 0.18s, and the
compiler-resource gates passed 254 positive / 226 hostile witnesses. These
focused results do not establish a new full-suite result.

Source inspection found that the current producer uses numeric addresses for
its private workspace and output arena. The proposed ABI-2 migration retains
the existing ABI-1 bootstrap source and introduces a separate protected
producer. It would pass an authenticated request-directory pointer through
memory-using routines, resolve internal selectors relative to authenticated
workspace/output roots, and use protected loads/stores. A numeric selector
alone must never confer authority. The four-register argument ABI and the
64-function table limit constrain this migration; bounded parameter packing
and removal of a trivial helper are candidate implementation choices, not
completed changes. Source and workspace/table growth remain C3 work.

The preliminary extension in the existing compiler-resource theory pair adds
20 positive checks (including four quantified laws) and 16 hostile checks for
aligned region selectors, bounded name packing, and strictly increasing,
representable output-capacity hints. Only dedicated output collision cases
may request output growth; generic table/representation errors must remain
terminal. These checks establish the stated model properties, not equivalence
of a migrated compiler or end-to-end output publication.

**Proof correction and local validation (2026-10-27).** The first version
reported 271/272 positive checks and 242/242 hostile disproofs; the combined
universal capacity-bound assertion returned unknown. That delivery did not
satisfy the formal gate. An isolated rerun of the unchanged assertion passed
through Kleis in 4.607s; a separately expanded bit-vector counterexample query
returned unsat in 0.242s. These diagnostics did not establish the cause of the
earlier full-run unknown and did not replace the required gate.

The correction proves the same universal obligation by exhaustive cases:

1. Every accepted hint has error code 17 or 18, for all frontiers, capacities
   and error codes.
2. For code 17 (an 8-byte emission), every accepted hint is strictly larger
   than the current capacity and no greater than `2^63 - 1`.
3. For code 18 (a 48-byte metadata record plus an 8-byte gap), the same bound
   holds for every accepted hint.

The three laws cover all four original quantified variables. No predicate,
arithmetic definition, guard, assumption, axiom or solver limit was changed.
No boundary sampling replaces a universal check. The existing nonempty valid
hint witnesses and hostile overflow/rejection witnesses remain in the gate.
The corrected complete compiler-resource gate now passes **274 positive
witnesses and 242/242 hostile witnesses explicitly disproved** locally.
Developer confirmation remains pending; the C2.3 accepted baseline is 254 / 226.
The runner's fail-closed treatment of unknown and errors is unchanged.

This is a proof-formulation correction, not a runtime vulnerability fix or a
claim that the producer migration is complete. The guarantee concerns hints
that satisfy the specified checks; the producer must still implement those
checks and emit the matching reply through ABI 2.

Next implement the protected producer and structured replies, then validate a
real CC2 compilation through the admitted ABI-2 path. Successful output
capture/admission/publication and complete job accounting remain separate
unfinished integration requirements. No Rust or long regression tests were
run for this documentation/formal checkpoint.

#### C2.4 implementation handoff — awaiting local execution

This patch adds `userspace/system/compiler/ankacc2_abi2.c`: a separate protected
producer with a five-region request entry, protected source/workspace/output
access, and ABI-2 success, output-capacity, source-error and representation-error
replies. The accepted ABI-1 compiler source is unchanged. The protected producer
supports the application profile; source/table growth and its own new fixed
point remain later work.

The producer specializes away unused legacy backend paths, packs bounded
internal scalar arguments to fit the existing four-register call ABI, and
splits primary-expression parsing from the precedence loop. It has 62 functions
and stays within the existing compiler name/frame limits in a short host-side
diagnostic. Parameter staging is aligned at internal workspace offset 61904.
All emitted compiler accesses still need their authenticated region pointers.
Output failures are distinguished from fixed-table/representation failures;
only checked output collisions produce a NeedCapacity reply.

`compiler_adapter/producer.rs` builds the checked-in source with the accepted
CC2 lineage and guest ankald, then validates its protected executable manifest.
Building this tool uses an explicit bounded 1 MiB bootstrap output reservation;
this does not change ordinary application policy or close automatic output
growth. No host-generated diagnostic artifact enters the accepted lineage.

The existing shared fixed-point integration test now includes the new producer:
exact protected AOM comparison against ABI 1, adequate-capacity independence,
real NeedCapacity through the runtime bridge and owner cleanup, source rejection,
and table exhaustion that must remain terminal. Successful output observation
is test-only at the authenticated exit boundary. Production artifact capture,
publication and complete job accounting remain unfinished.

**Validation at handoff:** `cargo check --tests --offline` passed. A short native
source diagnostic accepted the producer source, but it is not an Anka execution
witness. The new guest build/runtime integration and regression suite have NOT
been run here. This implementation is not yet accepted. The previously verified
formal gate remains 274 positive / 242 hostile; no theory or gate script changes
are included in this implementation patch.

Run locally:

```sh
cargo test --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address -- --test-threads=1 --nocapture
```

Acceptance requires the new `protected CC2 ABI 2` success line and a passing test.

#### C2.4 linker-profile correction (2026-10-27)

The first developer execution failed after compilation at
`ProducerBuildError::Link(LinkerRejected(9))` (577.18s). The guest linker still
used the application module's 256 KiB input bound. It also required a protected
`int main()` entry, while the ABI-2 producer requires
`int main(int **request, int *reply)`. Increasing only the compiler's output
reservation had not updated either downstream contract. This was an integration
mistake; the unused-field warnings were unrelated to the linker rejection.

The correction adds an explicit trusted linker transport profile at control
byte offset 88. Value 0 retains application behavior. Value 2 admits exactly
one protected compiler-tool module, bounded to 1 MiB, with `main` at byte zero,
integer return type, and exactly two pointer parameters `[2001, 1001]` (the
existing type codes for `int **` and `int *`). Unknown profiles, legacy inputs
in the tool profile, and wrong entry signatures are rejected. The existing
1 MiB combined-image and 4096 frame/record limits are unchanged.

A distinct module constructor validates the bounded compiler tool. Ordinary
application linking rechecks its 256 KiB module limit even if it receives a
module constructed through the tool path. Both guest and host check the
selected profile; host validation retains complete frame, instruction, call,
metadata and exact-byte checks. The host neither repairs nor synthesizes linked
bytes. The linker control profile is covered by the existing unchanged-control
check. This creates no publication or execution authority and does not close
C2 automatic growth or C4's general link-limit work.

Before implementing the correction, the compiler-resource gate passed **293
positive witnesses and 259/259 hostile witnesses explicitly disproved**,
including new application/tool policy separation, exact ABI signature,
unknown-profile, oversized-input, legacy-input and multiple-module checks.
These are model checks, not a proof of the complete C/Rust implementations.

The three new `ProducerBuildError` dead-field warnings are resolved by a
`Display` implementation that actually reads and preserves the nested errors;
the acceptance panic uses that diagnostic. Existing `PointerMachineError`
payload warnings reflect errors retained for Debug diagnostics. Unused
`CCA_FUNC_COUNT`, `CompileArtifact.funcs`, test `NetRun.buffer` fields and the
cleanup `lease()` accessor are separate cleanup work. No error payload is
replaced with `()` and no broad `cargo fix` is applied.

**Local validation:** the two `p108_compiler_producer_link` Rust regressions
passed (2/2, 153.22s). They execute guest ankald, cover a module above 256 KiB,
retain application input/signature rejection, verify the exact linked bytes,
reject wrong producer pointer types and reject over-limit/malformed tool inputs.
The test build reports 79 warnings, down from 82; the three producer diagnostic
warnings are removed. No full CC2 integration or regression suite was run here.
The full ABI-2 producer execution remains pending until the developer reruns
the shared fixed-point acceptance test successfully.

A failure should be investigated before another full regression run. Phase 10.8
remains open: C2 output growth/publication integration, C3 source/workspace growth,
C4 link/admission growth and C5 self-hosted/concurrent closure remain in DN-71.

### Inventory: output size is only one limit

The following are observed current limits, not proposed permanent capacities:

| Resource or boundary | Current implementation | Planned treatment |
|---|---|---|
| Effective source | 65528 bytes after preprocessing; 8-byte envelope header | Size the immutable source object from actual bytes; give preprocessing its own growth/result contract. Preserve checked padding for lexer word reads. |
| Compiler image and output | Compiler image admission and each AOM are bounded by the 262144-byte policy | Admit the producer by its exact image and negotiated budget; separate executable-tool size from output reservation. Grow the private output region through the resource protocol. |
| Workspace tables | CC2 has 64 function entries, 128 deferred-call entries and 32 local-name entries, among other fixed tables | Inventory every table and replace storage ceilings with explicit region bases, counts and capacities. Count prototypes as well as definitions where the current table does so. |
| Protected locals and manifests | 1024-element local-array limit, 8192-byte local allocation bound and 4096 frame/local-record checks appear at different layers | Classify each limit as storage policy, language profile or encoding constraint. Change compiler, admission, runtime and theory together when widening a policy. |
| Linked artifact and publication | Code plus merged metadata capped at 1 MiB; publication also checks a 1 MiB bound | Carry an explicit artifact budget through guest linking, exact-byte validation, publication and loader admission. Preserve per-transaction copy limits while allowing multiple chunks. |
| Linker scratch | Currently derived as three times total input-container bytes | Retain checked input-based sizing or use a guest sizing result; charge the allocation against the same job budget. The host does not compute authoritative link semantics. |
| Machine and runner | Fixed private Fabric/placement pools, virtual ceilings, stacks and execution-round budgets | Provision through PhysicalPlacementManager and VirtualLayoutBuilder; account for the complete live memory footprint and cumulative work across retries. |
| Instruction/format representation | Finite immediates, branch/call displacements, indices, lengths and alignment rules | Keep checked encodability separate from memory policy. Never truncate a value to make a larger image fit an instruction. Any required far-call/branch or format extension gets its own formal refinement. |

The first audit must also cover typedef/struct/field tables, parser work stacks,
preprocessor members/include depth and cycles, fixup storage, string/literal
packing, compiler stacks and protected runtime tables. Increasing the output
constant alone would simply move the first failure to another fixed table.

### C2.4 entry-frame fixture correction (2026-10-27)

The developer's next run confirms successful protected producer linking:
322816 code bytes, 479296 backing bytes, entry zero. Execution then faults on
its first PFRAME at PC zero; no producer C body has executed. This result does
not establish ABI-2 producer acceptance.

The runtime fixture incorrectly reused the small transport probe's registry:
64 shared identity slots, with five already occupied by the ABI regions. A
short native compiler-metadata diagnostic reports 174 local registrations for
the producer entry (2144 frame bytes), exceeding the remaining 59 slots. The
native diagnostic is an inspection aid, not trusted compiler-lineage evidence.
The existing registry correctly refuses the entire frame before modifying
payload or issuing any local pointers; the architectural fault mapper reports
that refusal as ControlFlowViolation.

The producer fixture now uses Fabric's existing bounded application heap
profile: 4096 shared slots and 4096 scopes. It retains the two-MiB owner quota
and the existing authenticated loader and frame checks. This corrects fixture
provisioning; it does not implement dynamic table growth or claim arbitrary
recursion capacity. No architectural invariant or Kleis theory changes.

A short ISA-only regression loads the actual five ABI regions, reproduces the
old first-instruction exhaustion with 174 locals, and checks that registers,
registry and dirty stack bytes are unchanged. A second regression uses the
application profile to enter 174- and 588-local nested frames, spill/restore
both protected arguments, retire the frames and preserve the heap regions.
These probes do not rebuild CC2.

PointerMachineError now formats all nested causes without discarding payloads.
Test builds print that cause before architectural fault conversion, so a future
failure reports e.g. `pointer registry: Exhausted` instead of only the generic
ControlFlowViolation. Guest-visible fault behavior is unchanged. This also
removes the two Frame/Heap dead-field warnings; unrelated warnings are deferred.

**Local validation:** both `p108_producer_entry` regressions passed (2/2,
0.40s). The old fixture reports `pointer registry: Exhausted` at PC zero;
the corrected profile passes nested entry and argument preservation. The test
build reports 77 warnings, down from 79. No long CC2 or full-suite run was
performed here. Full producer execution still needs the developer's rerun:

```sh
cargo test --lib p108_producer_entry -- --test-threads=1 --nocapture
cargo test --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address -- --test-threads=1 --nocapture
```

### C2.4 producer diagnostic-history slowdown (2026-10-31)

The developer's two entry regressions pass (0.19s), but the integrated witness
was interrupted after printing the 4096-slot frame budget. That log is not
evidence of producer completion or of an infinite guest loop.

Source inspection identifies an unbounded-history performance defect in the
new test harness. `Fabric::submit` appends every legacy transaction, including
instruction fetches, to `transactions`. Both protected-frame exclusion in
`fabric/local_frames.rs` and the heap privacy check in `fabric/heap.rs` scan
that vector to find nonterminal work. The heap check also runs when authenticating
live heap pointers in `fabric/heap/cells.rs`. Terminal entries are skipped only
after being visited. The ABI-2 compiler repeatedly accesses its heap-backed
workspace and enters helper functions, so retaining the entire trace causes
history-dependent overhead on its hot path, potentially quadratic overall,
plus unbounded diagnostic-memory growth. The older development compiler and
guest linker harnesses already collect completed traces between batches; the
new `observe` and NeedCapacity test loops omitted that collection.

The test-only correction uses 256-step execution slices and calls the existing
`discard_completed_compiler_trace` collector between them, including the exit
slice. Collection is refused if a controller or non-CPU agent is present, and
the collector refuses to discard anything while any transaction is nonterminal.
The fixture is synchronous and retains no transaction-vector handles between
successful collections. Transaction IDs remain monotonic. Fault records,
heap-work tickets, pointer-kind cells, owner lifetimes and all authorization,
initialization, overlap and cleanup checks are retained. This change is not
a general-purpose trace compactor for concurrent controllers or DMA.

The billion-step guest-work cap is unchanged. Stage labels and five-second
progress reports now identify the current case, elapsed time, dispatched work
budget, sampled PC and process state. `ANKA_PRODUCER_TIMEOUT_SECS` sets a
positive per-stage diagnostic wall limit (default 300 seconds); the timeout
reports registers and fails the test, never counts as acceptance. Checks run
between slices, so this is not a preemptive host watchdog. Dispatched work is
an upper bound, not an exact retired-instruction count. These diagnostics cover
the producer cases and owner cleanup, not the preceding CC2 bootstrap/link.

Two focused regressions compare every instruction's PC/register state with and
without collection through real nested frames and loader-issued heap pointers;
they also check actual trace release, nonterminal-transaction refusal, DMA-agent
refusal and monotonic transaction identity. Existing entry regressions remain.
No architecture/ABI change or new Kleis gate is required for this test-only
use of the existing synchronous collector. All existing formal gates remain
required for the production transitions they cover.

**Validation status:** source-reviewed; Rust/cargo is unavailable in the patch
environment, so the new regressions have not been compiled or run here. No long
integration or full suite was run. The slowdown mechanism is established from
source; its wall-time contribution and complete producer acceptance require
the developer's rerun. Do not mark C2.4 accepted from this patch alone.

```sh
cargo test --lib p108_producer_ -- --test-threads=1 --nocapture
cargo test --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address -- --test-threads=1 --nocapture
```

### C2.4 local-metadata traversal correction (2026-10-31)

The developer confirms all four entry/trace regressions pass (0.43s). With
trace collection, exact-AOM and capacity-independence producer executions
complete in 44.74s and 44.67s (555008 dispatched steps each). NeedCapacity
completes in 266.76s (3167744 dispatched steps), followed by owner cleanup.
The adequate-output case still reaches the 900-second diagnostic deadline
after 11068416 dispatched steps. Advancing PCs and a stable dispatch rate do
not by themselves establish compiler progress or termination. Do not treat
the prior recommendation to increase a timeout as evidence of correctness.

Inspection found a second performance defect in ABI-2 `q59`: for every local
ordinal, the emitter restarts at the head of a reverse-linked metadata list.
With N locals this traverses N*(N-1)/2 links. The 70-assignment fixture has
71 locals and therefore performs 2485 link traversals. Each traversal calls
the guest qptr helper, including its protected calls, frames and heap checks.
The small-buffer case fails during code emission before this metadata walk,
so its measured duration does not predict the successful case's duration.

The ABI-2 emitter now reverses the private scratch list once, checking that
ordinals descend by one and that the chain has exactly the declared length.
It then emits records in ascending ordinal order in one forward pass. The
reversal is bounded by the local count; a missing, repeated, out-of-order or
extra link fails with the existing representation diagnostic 19. The existing
q55 output-capacity checks, metadata format, field order, frame registrations
and authority checks remain in place. No additional allocation or guest ABI
is introduced. ABI-1 stays unchanged as the independent reference algorithm.

Formal-contract assessment: this is an implementation optimization under the
existing exact-artifact and local-ordinal contracts, not a new architectural
permission or lifetime transition. Existing Kleis gates are unchanged. Native
differential checks below do not constitute a universal formal refinement
proof or replace the guest-lineage acceptance requirement.

**Diagnostic validation:** a host C adapter widened integers and literals to
64 bits, supplied ordinary host arrays in place of protected regions, and ran
the old/new ABI-2 source algorithms. All 24 combinations of 0/1/2/10/35/70
assignments and 4096/8192/65536/131072-byte output capacities matched status,
cursor, size and every emitted AOM byte. For 70 assignments at capacity 65536,
both produce 8872 bytes and consume all 449 source bytes. qptr calls fall from
26083 to 18700; the old 2485-link repeated search is replaced by two linear
passes over 71 records. These measurements establish source-level behavior
only; they do not rule out a separate generated-code problem.

The integrated witness now also compares the larger result byte-for-byte with
the accepted ABI-1 compiler, whose ordinal-search implementation is unchanged,
then validates the resulting protected module. Rust/cargo is unavailable in
this patch environment: guest compilation/execution and the added assertion
were pending at this patch handoff; both passed in the 2026-10-31 acceptance
run recorded below. Do not extend the diagnostic deadline
again as a substitute for investigating a further failure.

For the next local run, use an optimized host emulator while explicitly
retaining debug assertions and overflow checks; guest C and acceptance checks
are unchanged. This builds a separate release test binary and incurs a one-time
host compilation cost. It is a separate performance configuration, not a claim
that the ordinary debug-profile regression suite has passed.

```sh
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true \
ANKA_PRODUCER_TIMEOUT_SECS=900 \
cargo test --release --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address -- --test-threads=1 --nocapture
```

### C2.4 bounded output observation correction (2026-10-31)

The user's optimized guest run with the linear metadata traversal reached the
successful exit boundary for the larger source, then failed in the test observer
at `producer_tests.rs:151` with `Pointer(Bounds)`. Exact-AOM and capacity-independence
stages completed in 4.47s and 4.29s; NeedCapacity completed in 25.40s. The whole
test failed after 189.99s. This is evidence of progress past the earlier timeout,
not acceptance of the full producer witness.

Root cause: the observer passed the entire successful output to `read_heap_bytes`
in one operation. `checked_heap_backing_span` deliberately rejects lengths above
4096 bytes. Allocation/output capacity is distinct from the per-read limit.
The larger source's native diagnostic emitted 8872 bytes; the guest run's actual
artifact bytes have not yet passed the reference comparison.

The test-only observer now validates the reported length against its bound
request capacity and copies in at-most-4096-byte chunks. Each chunk derives an
offset from the original protected token and uses the existing authenticated
Fabric read; no direct physical-memory access or limit widening is introduced.
Empty captures also authenticate the token. Failure returns no output vector.
The existing stopped-process/exclusive-Kernel observation boundary is retained.

Two fast Rust regressions cover patterned data across 4096-byte boundaries,
an 8872-byte prefix, exact capacity, over-capacity rejection, the unchanged
single-read limit, and retired-owner rejection including empty output.
Rust tooling is unavailable in the editing environment; these tests and the
full guest witness were pending at this patch handoff; both are now developer-accepted
(2 focused tests in 0.12s and the integrated witness in 410.74s). No machine contract changes
or new Kleis gates are needed for this test-harness correction. Production
artifact capture/publication remains the separate C2.5 milestone.

### C2.5 — ABI-2 capture, retained custody and publication

This is the single current C2.5 design section. The **implementation checkpoint
table near the end of DN-71** records acceptance and remaining work; historical
C2.4 handoffs above do not override it. The developer reported the publication
Kleis pair passing **136 positive / 118 hostile**, then the nine C2.5a capture
tests passing in **0.01s**, eight retention tests in **0.00s**, and the complete
42-test compiler-retry bridge group in **0.04s**, followed by all 11
publication tests in **0.01s** and the 53-test bridge group in **0.04s**. These earlier results are focused acceptance. C2.5c real-compiler acceptance
and the current gate counts are recorded below; no new full-suite pass is inferred.

**Contract and proof scope.** `anka108_artifact_publication.kleis` and its hostile
pair import the compiler-resource contract. They specify bounded exact-prefix
copying, role admission, independently retained charges, exact producer cleanup,
and atomic READ-only artifact/receipt publication. The 136 positive witnesses
include 18 quantified laws; all 118 hostile claims were explicitly disproved.
The accepted compiler-resource baseline remains 293 / 259. One earlier
monolithic peak-sum law timed out without a counterexample; decomposing checked
addition and subtotal laws resolved it without weakening a guard or adding an
axiom. The accepted pair has no unknown result.

The concrete implementation uses the existing 4096-byte heap read limit and
ABI-2 source offset zero. The older ABI-1 adapter's length prefix, 64-KiB copy
policy and isolated-Fabric receipt cannot silently become ABI-2 heap rules.

| Formal phase | Required custody and transition |
|---|---|
| 0 executing | Actual protected zero exit, exact owner/incarnation and request bindings; exclude writers and outstanding output/reply work; reserve capture space while source tokens remain live. |
| 1 capturing | Exclusive Kernel custody; consecutive authenticated reads of at most 4096 bytes; exact successful prefix only; no partial visibility. |
| 2 admitted candidate | Exact AOM and role validation; independent candidate custody/charge established before retiring the producer. |
| 3 ready | Real cleanup/return for the exact producer owner; candidate remains immutable and charged. Final provenance and authority checks are still required. |
| 4 published | One complete artifact/receipt insertion under the expected epoch; fresh exact-length READ-only object, no execution grant. |
| 5 aborted | Destroy private payload before refund; retain unsettled cleanup obligations and preserve earlier records. |

**Implemented capture.** `os/compiler_retry/capture.rs` shares actual execution
and exit checks with the retry bridge. It rechecks original protected output
and reply tokens, owner/agent, geometry and drainage, decodes the bound report,
and copies the exact prefix in bounded reads. Closed units reject imports and
relocations and pass program validation; relocatable modules use their separate
validator. Neither can claim linked-image admission.

The non-Clone `CapturedCompilerOutput` holds exclusive Kernel access. Its bytes
are immutable; there is no detached-Vec conversion, receipt or execution grant.
Before copying, the shared heap reserves page-rounded **32 * used + 4096** for
staging and bounded parser payload. An allocation-free preflight bounds aggregate
frame scan length by code length before allocating exit lists. This allowance
is conservative, not measured host RSS or complete job accounting. Existing
parser allocations still assume the host process can allocate; host allocator
failure is not converted into an Anka resource reply. The current 256-KiB
application admission limit remains explicit. These limits may reject output
that fits the producer arena; growing admission is separate work.

**C2.5b custody/cleanup — focused Rust acceptance received.**
`CapturedCompilerOutput::retain()` reserves independently before moving the
already admitted Vec into a private Kernel record. The existing unscheduled
runtime service is the trusted custodian; it uses a separate owner account in
the same shared allocator, under the existing service owner/global quota.
The reservation covers actual Vec capacity, the fixed candidate record and a
4096-byte conservative map-node allowance, page-rounded by the shared service.
Old staging and new retention are both charged at the handoff peak. Payload is
moved without cloning. No guest pointer, backing object or public receipt is
issued for these private reserved extents.

The reservation-incarnation/custodian-context handle has no integer constructor
or Clone. The bytes, role, original context and producer owner remain in the
Kernel even if its caller loses the handle. On successful handoff the capture
guard refunds its old staging reservation and retires the producer. A failed
retention reservation instead follows normal capture discard/cleanup and cannot
replace another candidate. Other clients remain included in shared accounting.

`poll_compiler_candidate` advances at most one existing cleanup step and derives
readiness from `compiler_heap_owner_released` for the exact producer. Pending or
unconsumed work on any producer allocation blocks readiness. A ready view borrows
immutable bytes from the Kernel and rechecks the custodian, exact still-reserved
charge and producer release. Readiness is private admission evidence, **not
publication authority**. Producer cleanup cannot refund the separate custodian
reservation or erase its host candidate.

Cancellation destroys payload before aborting the exact never-attached
reservation. A failed abort retains an unreadable tombstone and charge for retry.
Custodian death destroys its candidates before account closure; orderly service
shutdown cancels them before dismantling the service. A failed cancellation
keeps custody quarantined rather than inventing a refund. Runtime guards and
handles are trusted host mechanisms; guest code cannot invoke these operations
or forge their fields. This is serialized emulator custody, not a hardware or
external-DMA fence guarantee.

Eight new focused tests cover retained bytes/charges through cleanup, A/B
isolation with C reusing A's backing, stale/foreign-Kernel handles, cancellation,
retention quota denial preserving prior candidates, shutdown/custodian death,
and pending work on another producer region blocking readiness. The existing
real CC2 witness now traverses capture, independent retention, actual cleanup
and candidate discard before its exact reference comparison; the comparison
Vec is test-owned. The developer accepted all eight retention tests and the
42-test bridge group. The updated real CC2 integration remains unreported.

**C2.5b publication commit — focused developer acceptance received.**
`os/compiler_retry/publication.rs` adds a pre-execution frozen job, carried by
opaque binding through capture and retention. Freeze requires an authentic
five-region loader attempt at the unstarted protected entry. It compares actual
loaded source bytes, admitted compiler object/generation/code, canonical frame
manifest, ABI/profile and the actual retry budget against the selected sealed
inputs. Source offset is zero; ABI and target profile are 2. Bundle, selected
preprocessor/linker and ordered dependencies are independently snapshotted.
These are trusted coordinator selections: snapshots alone do not prove the
preprocessor produced the source or that the compiler has accepted self-host
lineage. C2.5c must supply that derivation and lineage evidence.

Before snapshots allocate, the custodian reserves a conservative allowance:
`2 * (input bytes + admission-word bytes) + 128 * input count + 8192`.
Inputs are bounded to 1 MiB each and 4096 ordered dependencies; shared owner and
global quotas still apply. These are conservative charged payload allowances,
not measured host RSS. Reserving this evidence can deny a large compiler under
a small custodian quota; the coordinator must account for the complete peak.

Commit requires exact producer release, current custodian and reservation,
publication authority, matching nonwrapping expected epoch, and a fresh read
of every sealed input under current grants. Artifact backing is separately
reserved while the candidate and provenance charges remain held. Fabric first
initializes the whole backing, then overlays the exact admitted payload and
publishes a READ-only protected token directly: there is no RW alias interval.
The token remains Kernel-private until one complete artifact/receipt record is
inserted. Candidate payload is destroyed before its staging charge is refunded;
artifact and receipt/provenance charges survive publication. Failures before
that insertion preserve prior records and epoch; attached storage goes through
actual cleanup, never an invented immediate refund. Cancellation, custodian death
and service shutdown destroy retained metadata before account teardown.

The concrete seal is immutable private-heap first publication, **not** a legacy
`ObjectState::Sealed` row. The receipt uses the protected slot generation rather
than the private object's legacy generation-zero field. It binds actual code
admission and exact input bytes; it grants no EXEC permission. Reads authenticate
the current custodian and protected token and remain bounded to 4096 bytes.
Trusted host code and exclusive Kernel access remain part of the implementation
boundary; BTreeMap allocation failure retains the existing host-OOM assumption.

Eleven new focused tests cover exact bytes/READ rights/receipt identity, missing
pre-execution binding, source/compiler/profile/plan mismatch, authority and
cleanup readiness, every changed sealed input, revoked grants, stale/exhausted
epochs preserving prior records, quota denial/retry, failure after private sealing,
cancellation/late freeze and service shutdown. These are ISA transport fixtures,
not a real C compiler publication witness. Rust is unavailable in the editing
environment. The developer subsequently reported all 11 publication tests and
all 53 affected bridge tests passing after the fetch-history correction.

**Publication regression correction (2026-10-31).** The first focused run
reported 4 passes and 7 failures. Source inspection found that `sealed_length`
applied `compiler_trace_safe` to every provenance object, including the compiler
that had just executed. That helper enforces an output-only no-FETCH policy:
legitimate terminal compiler fetches therefore rejected successful publication.
The correction retains global transaction quiescence and each input's current
seal, generation, READ grant and exact-byte recheck, while permitting executed
sealed tools. Output capture's compile-only policy is unchanged. The existing
success test now explicitly requires actual compiler FETCH history and verifies
that this history passes sealed-input admission while failing the output-only
predicate. No formal contract was weakened or changed. The developer's rerun
passed all 11 tests in 0.01s and all 53 bridge tests in 0.04s.

**C2.5c retry/publication integration — developer-accepted and merged to main.**
`os/compiler_retry/flow.rs` composes the existing guarded operations into one
bounded runtime flow: execution, actual retry cleanup, independently retained
candidate, cleanup readiness and atomic publication. Each advance performs one
execution slice or one cleanup step. NeedCapacity returns the original opaque
next budget exactly once, after producer release and cancellation of old frozen
metadata; it never resets cumulative work or retry fuel. Terminal errors close
or discard only the flow's producer/candidate and frozen record, leaving real
cleanup obligations charged. A lost flow handle cannot detach payload from
Kernel custody; service teardown still owns cancellation. Process admission and
current lineage selection remain trusted coordinator duties.

Concurrent jobs may finish against a newer publication epoch. A new explicit
`refresh_compiler_publication_epoch` revalidates readiness, exact producer release,
current custodian/reservation/charge, every sealed input and publication authority
before changing only the candidate's expected epoch. It refuses backwards or
exhausted epochs and cannot insert/overwrite any visible record. The flow uses
this operation when a peer has committed; the existing direct publication API
still rejects stale epochs. Kleis now includes this transition: **149 positive
witnesses (20 quantified laws), 129/129 hostile claims explicitly disproved**
locally on 2026-10-31 and subsequently on the developer machine. The earlier
136/118 result is the historical C2.5b baseline, not the current gate count.

Six fast flow tests passed on the developer machine in 0.00s. They cover
success and one-shot completion; cancellation with an
independent client; missing commit authority; two concurrent candidates whose
commits advance the epoch; changed provenance/missing authority during refresh;
and a real ISA NeedCapacity reply followed by actual cleanup and preserved retry
budget. They supplement, rather than relabel, the accepted 53-test baseline.

The shared real CC2 witness now runs `producer_publication_tests.rs` using the
same guest-built protected ABI-2 producer and accepted fixed-point lineage.
Actual guest ankapp expands an include-bearing source bundle. Exact bundle bytes,
effective source, selected tool bytes, accepted compiler bytes, producer source,
admitted code/frame manifest and actual resource plan are frozen in publication
inputs. The lineage remains immutably borrowed and is rechecked at phase boundaries.
The host fixture transports/schedules; it does not emit or repair accepted AOM.

A and B run in one Kernel with separate owners and output arenas. A deliberately
exhausts 4096 bytes while B executes smaller quanta. Real cleanup releases A;
a fresh C attempt consumes the returned budget and reuses A backing. Old A tokens
must fail even under C's owner; B's charge and live output token remain valid.
B publishes while C is live. C then publishes via guarded epoch refresh; B's
prior receipt and exact bytes must remain unchanged. Further capacity replies
repeat this bounded loop. A second adequate-capacity small compilation must emit
identical published bytes. Outputs are compared byte-for-byte with compilations
from the accepted lineage and receipts are checked for ABI, role, source offset,
producer, ordered evidence, exact length, generation and READ-only rights.

The integration fixture explicitly provisions 64 MiB RAM, a 32 MiB private pool,
a 128 MiB global accounting ceiling and 16 MiB per-owner quota. Accounting covers
fixed host-side metadata as well as charged payload; it is not physical guest RAM.
The first integration run failed at fixture construction with `Capacity(GlobalBytes)`:
the former 64 MiB ceiling could not accommodate 2,097,152 shadow entries plus
registry/work storage. The allocator correctly rejected that configuration.
Only the fixture ceiling changes. A new cheap setup test uses Rust's actual
`size_of::<Option<ScopedPointer>>()` and the registry's reported fixed metadata
charge to assert enough headroom for the complete 32 MiB pool before CC2 runs.
This does not widen production output admission. Its sealed tool/source ingestion,
legacy code/stacks and comparison Vecs are test infrastructure, not complete
shared-service job billing or an ordinary user-facing command. C2's artifact
above 256 KiB and complete accounting remain open; C3-C5 retain their order.
No new guest instruction, syscall, permission or hardware claim is introduced.

**Accepted evidence, recorded 2026-11-01:** the corrected fixture test passed
in 0.01s (fixed charge 69,098,160 bytes, payload pool 33,554,432 bytes,
global budget 134,217,728 bytes). The shared guest integration passed in
464.34s, reporting two retries, real preprocessing/accepted lineage, A cleanup,
C backing reuse, stale-A rejection, independent B, exact AOMs and READ-only
receipts. The affected bridge passed **60 tests in 0.04s**. The developer
confirmed **149 positive / 129 explicitly disproved hostile witnesses** and
reported merging the branch into main. C2.5c is closed. The last reported
complete suite is still C2.4's **1406 tests in 589.71s**; a 1441-test complete
suite pass has not been reported.

### C2 remaining work — output boundary and complete accounting

The next bounded delivery removes the obsolete 256-KiB envelope from the
**ABI-2 capture path only**. Its authentic attempt capacity now bounds the used
prefix and role-specific module validator. Checked `32 * used + 4096` staging
reservation precedes copying and parsing; owner/global/placement denial still
fails closed. Reads remain at most 4096 bytes. Independent custody, actual
producer cleanup, READ-only publication and receipt checks remain mandatory.
Legacy ABI-1 admission and the producer-bootstrap policy keep their own limits.
This does not authorize larger linked images or widen C language/ISA bounds.

The affected publication theory adds the capture-budget refinement: capacity,
minimum/aligned AOM extent, checked staging arithmetic and preservation of
already-held charges. **163 positive / 139 hostile witnesses passed locally**
before implementation and were independently confirmed on the developer machine. Boolean certificates still require concrete runtime
observations; these results are not a proof of Rust execution.

Six new fast Rust tests cover oversized exact publication at two capacities,
READ-only access/exact tails, quota denial preserving prior publication,
validation beyond the old boundary, role rejection and arithmetic overflow.
They use a constructed valid AOM and an actual ISA/loader transport, not a C
compiler. The separate ignored `c26_real_cc2_oversized_publication` test is the
required real-producer acceptance gate: guest preprocessing, accepted CC2
reference AOM larger than 262144 bytes, actual ABI-2 exhaustion at 262144,
cleanup-released retry, exact READ publication, then identical publication
from a larger adequate starting capacity. It checks all bytes and prior receipts.
The small source uses a large pointee type to generate real PADD instructions;
there is no padding of the resulting AOM. This test is explicitly run with
`--ignored`, so routine regressions do not rebuild the lineage a second time.
**C2.6 acceptance history:** after removal of the missed final-sealing
256-KiB check, all six fast tests passed in 0.03s and the affected bridge passed
66 tests in 0.07s (one dedicated test ignored). The developer independently
confirmed Kleis 163/139. The dedicated real-compiler test then failed during
reference compilation in 29.58s with `CompilerRejected(16)`: its
`walk(struct Block *p)` signature violates q57's existing AOM signature profile,
which permits pointers rooted in scalar/void types, not struct types. It had
emitted 328912 bytes before symbol serialization rejected that signature;
this is not successful AOM publication evidence.

The corrected fixture uses `int walk()` with a local struct pointer initialized
to typed null, then five zero-offset pointer additions. `main` returns zero and
never calls `walk`. No struct-valued local is created (protected mode excludes
those too), and function signatures remain scalar. This is a compilation and
publication witness, not evidence that null-pointer arithmetic may execute. It still requires an actual AOM larger than 262144
bytes and exact direct-versus-retried publication. No compiler, ABI, quota or
formal guard is widened. **Developer acceptance, 2026-10-31:** the corrected
real-producer test passed, 1 passed / 0 failed / 1447 filtered, in **2174.32s**.
The actual artifact is **321336 bytes**, above 262144; automatic retry count is
one. It established exact accepted-lineage AOM bytes, capacity independence and
preservation of prior receipts. The three reported production-flow stages took
606.48s, 748.98s and 749.99s. The existing 163/139 theory gate, six fast witnesses
and 66-test bridge remain accepted. This is not a new complete-suite pass.
Do not rerun this 36-minute acceptance for unrelated documentation/storage edits.

This removes one concrete output boundary, not the whole C2 accounting gap.
Still required: charge legacy admitted producer code/stacks, source/tool ingestion,
preprocessor machines and host-side job storage through the common accounting
contract; enforce admission before allocation, preserve shared immutable-tool
ownership, and release/refund only with real lifecycle evidence. Existing heap,
staging, candidate and publication charges must not be counted twice. Refine
C1/publication/lifecycle gates for those boundaries before implementing them.
Do not reopen the completed allocator or whole-stack audit to deliver this work.
C3 source/table growth, C4 link/load growth and C5 ordinary rebuild closure remain
the subsequent fixed deliverables. Metal/FPGA and unrelated optimizations remain
deferred. Ownership/DMA refinements are required before enabling those interfaces
in the real service rebuild, not as speculative prerequisites for output capture.

The theory's Boolean certificates are trusted implementation obligations, never
guest flags. The candidate and publication paths refine `pub108_queue_cleanup`,
`pub108_ready`, `pub108_retained` and the serialized commit of `pub108_publish`.
The end-to-end coordinator must still establish the selected-tool derivation
and accepted-lineage obligations; passing model witnesses do not establish
that integration or verify this Rust implementation. Proofs are not whole-program correctness, unconditional
liveness or hardware side-channel proofs. Scheduler fairness, allocator
correctness and eventual drain remain explicit assumptions. Metal/FPGA execution
requires its own memory-ordering and synchronization refinement.

Run the new tests and the affected fast bridge group first:

```bash
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true \
cargo test --release --lib c25_flow -- --test-threads=1

CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true \
cargo test --release --lib anka64::os::compiler_retry:: -- --test-threads=1
```

For the coherent guest integration checkpoint, reuse the existing witness:

```bash
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true \
cargo test --release --lib \
  anka64::userspace_rebuild::tests::p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address \
  -- --exact --nocapture --test-threads=1
```

Run only the changed publication pair for the epoch-refresh refinement:

```bash
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root ~/git/cee/kleis --only-publication
```

Run the six fast flow tests and affected bridge group first, then the shared
real CC2 witness above. A full suite is deferred until this integration passes.

### Compiler client design after the allocation checkpoint

Use an explicit resource plan and fresh-attempt retry on top of the shared
allocation service. Ordinary users invoking the compiler through Anka must get
this behavior, and each job must own its mutable regions and attempt identities.
Charge its reservations against both its budget and the global allocation state.

1. **Freeze the job.** Bind the exact immutable source bundle, root member,
   preprocessing/compiler/linker lineage, target profile and ordered module
   dependencies. Keep execution and publication authorities separate. Recheck
   their current identities on every attempt; revocation or substitution aborts
   the job instead of selecting a different tool or source.
2. **Admit a resource budget.** Use one versioned, immutable job resource plan
   with limits for source, tables/workspace, output, linked artifact, peak live
   memory and cumulative execution/retry work. Charge page rounding, scratch,
   staging copies, tool images, retained publications and metadata. A guest
   capacity request is a request for resources, not authority to obtain them.
3. **Describe the actual regions.** A new compiler-adapter ABI conveys exact
   object/incarnation bindings, selected mappings, lengths, capacities and
   region roles. Keep any fixed bootstrap control block small; growing tables
   and buffers use region-relative offsets/indices. Do not silently reinterpret
   revision-1 control words. Use the existing placement managers for both
   physical allocation and nonoverlapping virtual layouts.
4. **Return a typed outcome.** Distinguish `Success(exact_length)`,
   `NeedCapacity(resource, minimum)`, ordinary source rejection,
   representation/profile rejection, budget denial and execution failure.
   `minimum` is a checked requirement for a blocked reservation, not a promise
   about final output size. Validate it as untrusted protocol data. The present
   generic compiler error 8 is insufficient to authorize an automatic retry.
5. **Grow only on resource exhaustion.** Select a larger page-aligned capacity
   using checked geometric growth and any valid minimum request, within the
   admitted budget. Require strict progress and a finite retry/work allowance.
   A syntax error, protection fault, timeout or malformed result is terminal.
   Diagnose which resource needed more space and why the request was denied.
6. **Restart cleanly.** Stop and drain the failed attempt; revoke its temporary
   grants and reclaim/scrub its resources before reusing backing storage.
   Restart from the frozen inputs in a fresh attempt with fresh identity and
   workspace. Do not copy a partly constructed compiler arena into a larger
   object and assume its embedded addresses remain valid. Previously published
   artifacts and receipts survive unchanged; failed attempts consume no public
   publication epoch.
7. **Publish one complete result.** After normal completion and drain, validate
   the exact packed AOM/linked image, transfer only its used bytes through
   bounded Fabric reads, and publish a fresh sealed READ artifact with the
   actual producer/dependency/resource-ABI binding. Scratch, padding and unused
   capacity remain private. Execution still requires independent authority.

Fresh-attempt retry is the first implementation strategy because it avoids
relocating live compiler pointers. Accurate guest sizing passes or resumable
growth can be considered later if measured retry cost warrants them. Retry is
the compiler's policy on top of the common service, not a separate allocator.

### Determinism and bootstrap obligations

Two successful executions of the same frozen job under different sufficient
storage capacities must produce the same canonical artifact bytes. Arena size,
physical location, retry count, padding and private metadata addresses must not
leak into the emitted AOM or final linked image. Receipts may have different
object/attempt identities; byte equality does not mean receipt identity equality.
Guest packing and relocation must establish this property, rather than host
rewriting of compiler output.

Preserve the established seed lineage and produce the new resource-aware CC2
through guest tools. Keep legacy bootstrap entry points explicitly versioned
until their callers migrate. Larger compiler source, image, function tables and
metadata must themselves fit the bootstrap transition; do not use a host C
compiler or change the frozen CC_A's language semantics to bypass that gate.
Re-establish exact CC2_1 == CC2_2 after changes to the compiler or its artifact
geometry. Capacity-independent output is a separate required witness from the
ordinary same-capacity fixed-point check.

### Kleis gates before implementation

The A1 handoff now provides `anka108_allocation.kleis` and
`anka108_allocation_false_witnesses.kleis`, plus the concrete runtime/C interface
pair `anka108_allocation_abi.kleis` and
`anka108_allocation_abi_false_witnesses.kleis`, and the residual-data pair
`anka108_memory_initialization.kleis` and
`anka108_memory_initialization_false_witnesses.kleis`, and the storage pair
`anka108_allocation_reclamation.kleis` and
`anka108_allocation_reclamation_false_witnesses.kleis`, and now
`anka108_async_reclamation.kleis` and its false-witness counterpart. Focused gates and exact
scope are recorded above. Preserve these contracts and establish the stated trusted
implementation obligations before enabling the corresponding runtime behavior.

After the allocation interface and required stack review, add the compiler-client
resource/lifecycle theory and its hostile counterpart, provisionally
`anka108_compiler_resources.kleis` and
`anka108_compiler_resources_false_witnesses.kleis`. This pair is developer-accepted in C1 above (221 positive / 195 hostile). Then implement/refine the concrete
adapter and the affected preprocessing, rebuild, module and pointer-admission
contracts. Existing constants remain the enforced contract until those
refinements and their implementations are accepted together.

The formal work must establish:

- checked size arithmetic, alignment, count-times-stride and pairwise region
  nonoverlap; a reservation either fits or returns a capacity outcome before
  touching bytes outside its region;
- exact immutable request/tool/profile binding, trusted owner/context identity
  and non-amplifying resource grants across every attempt;
- monotone progress, bounded retries and cumulative work, including hostile
  hints that understate, overstate, wrap or repeatedly change a requirement;
- stop/drain/revoke/reclaim ordering, stale-generation rejection and isolation
  of partial outputs from the publication namespace;
- budget accounting for peak simultaneous storage, not just the final output;
  allocation failure leaves earlier artifacts/receipts intact and permits a
  later separately authorized retry;
- guest-authoritative compilation/linking, exact used-prefix transfer and
  atomic publication, including rejection of forged success or changed controls;
- correspondence between variable-capacity region/table operations and the
  existing compiler ABI, protected frame, call and artifact invariants;
- capacity-independent canonicalization and deterministic retry composition,
  with explicit compiler/serializer assumptions identified rather than treated
  as a proof of complete C semantics.

Imported or composed contracts needing review include placement/allocation,
protected-pointer metadata/representation/machine/frame/event/concurrency,
process reclamation, IPC and DMA contracts, as well as
`anka106_compiler_virtual_layout.kleis`, `anka108_compiler_adapter.kleis`,
`anka108_rebuild_artifact.kleis`, `anka108_protected_modules.kleis`, and the
source-bundle/preprocessing and protected-pointer frame/artifact theories.
Run changed gates and their affected dependents; unchanged independent theories
need not be rerun for every piece. A Kleis/stdlib change invalidates that
assumption and requires rechecking the affected proof environment.

### Bounded implementation handoffs

Each row is a separately reviewable handoff with its relevant formal gate
accepted before executable changes. Keep the established bootstrap reproducible;
version or replace affected ABIs deliberately. Small handoffs do not imply a
compiler-only architecture or permanent compatibility with temporary service ABIs.

| Piece | Concrete deliverable | Acceptance evidence |
|---|---|---|
| A1 — allocation contract and ABI | Shared service, individual heap lifetimes, concurrent reservations, runtime/C interface, residual-data isolation and storage reclamation | Developer accepted all four pairs: 579 positive / 386 hostile; no runtime implementation claim |
| A1-U — Undertaker refinement | Atomic death/registration, bounded durable directory, retained charges, exact worker/ticket identities, scrubbing and restart | 257 positive / 171 hostile developer-accepted on 2026-10-20; all five pairs accepted across focused runs and pass locally together at 836 / 557 |
| A2.1 — registry and reservation foundation | Fixed common directory, retained owner accounts, atomic rounded-quota/slot/cleanup reservation, independent closure and clone-free local-frame admission | Developer confirmed all 120 focused tests, including 19 new witnesses, with one test thread; acceptance recorded 2026-10-22; no production heap publication |
| A2.2 — bounded placement/reservation refinement | K+2 insertion capacity, reusable virtual holes, exact charging, shared-revision admission and identity-preserving cancellation through existing managers | Kleis 215 positive (34 quantified) / 180 hostile and Rust developer-accepted, recorded 2026-10-23; full single-threaded library run: 1134 passed, 0 failed, 0 filtered out in 1149.73s, including 21 new A2.2 witnesses; earlier local focused run: 160 passed |
| A2.3 — Fabric/shadow/initialization refinement | Fixed heap Fabric rows, precharged dense shadow, private attachment, full backing byte/tag initialization, atomic visibility and attached-failure routing | Developer-accepted 2026-10-24: 192 positive (30 quantified) / 162 explicitly disproved hostile; runtime composition is now covered by accepted A3 below |
| A2.3.1 — fixed Fabric storage/private attachment | Fallible setup and exact retained-capacity charging, shared checked ObjectIds, sticky private attachment, pool exclusion and unchanged-owner/failure preservation | Developer-accepted 2026-10-24: 17 new tests passed in 0.01s; 144-test shared-component regression passed in 0.09s, including those 17 |
| A2.3.2 — private byte/tag initialization | Bounded full-backing scrub, opaque exact progress snapshots, current completion checks, trusted-write prefix invalidation and preserved other-owner state | Developer-accepted 2026-10-24: 18 new tests passed in 0.02s; 162-test shared-component regression passed in 0.10s, including those 18; publication disabled |
| A2.3.3 — protected heap cells | Conditional live pointer-cell load/store, exact current source/destination checks, scalar tag invalidation and bounded dense-shadow use | Developer-accepted 2026-10-24: 22 new tests passed in 0.01s; 184-test focused regression passed in 0.13s, including those 22; positive tests use explicit test-only publication fixtures |
| A2.3.4 — attached-failure closure | Exact per-allocation fencing, reserved-job queueing, idempotent repeats, retained backing/charges and closure before drainage | Developer-accepted 2026-10-24: 17 new tests passed in 0.02s; 201-test focused regression passed in 0.13s, including those 17; no worker reclamation or production publication |
| A2.3.5 — concrete workers and terminal accounting | Fixed worker/lease/work records, incarnation-bound cleanup role, pinned exact backend tickets, complete census and current readiness | Developer-accepted Kleis: 197 positive (23 quantified laws) / 172 explicitly disproved hostile, 2026-10-24; runtime composition is now covered by accepted A3 below |
| A2.3.5a — worker records and job leases | Fixed charged rows, borrowed current Kernel descriptor, explicit cleanup role, exact queued claim/authentication and supervisor fencing | Developer-accepted 2026-10-24: 21 new tests passed in 0.02s; 222 focused tests passed in 0.13s, including those 21 |
| A2.3.5b — backend registration and pinning | Independently bounded CPU source/ledger arrays, exact incarnation/span binding, atomic registration and retained pins | Developer-accepted 2026-10-24: 21 new tests passed in 0.03s; 243 focused tests passed in 0.16s, including those 21 |
| A2.3.5c — execution and terminal accounting | Bounded CPU execution/cancellation, exact terminal consumption, complete current census and worker-authenticated drain observation | Developer-accepted 2026-10-25: 22 new tests passed in 0.02s; 265 focused tests passed in 0.17s, including those 22; no full 1272-test run reported |
| A2.3.6 — queued-job worker recovery | Exact per-job revocation, global worker fence, current backend checks and versioned return to unowned state; retained custody/work/charges | Developer-accepted 2026-10-25: 21 new tests passed in 0.01s; 286 focused tests passed in 0.16s, including those 21; no full 1293-test run reported |
| A2.3.7 — authority retirement | Current worker/lease, complete fresh drain census and actual process/Fabric exclusion; Closing → Retired while retaining all custody and charges | Developer-accepted 2026-10-25: 21 new tests passed in 0.02s; 307 focused tests passed in 0.19s, including those 21; no full 1314-test run reported |
| Complete trusted cleanup/reuse | Retired/scrub/clean worker recovery, bounded full byte/tag scrub, exact physical/virtual returns, payload refunds and safe reuse | Developer-accepted: 92 / 79 Kleis; 19 new Rust tests in 0.01s and 326 focused tests in 0.19s, including those 19 |
| A2 — trusted allocation service | Implement the accepted contract through placement, reusable virtual arenas, bounded metadata, Fabric and process lifecycle machinery | Isolation, rollback, stale-alias rejection, arbitrary free order, concurrent-client exhaustion/reuse and sustained-churn storage/accounting witnesses |
| A3 — C malloc/free | CC2 builtins, owned replies, private heap publication/access, free completion and lifecycle cleanup | Accepted 2026-10-25: all 12 A3 unit tests passed in the earlier full run; corrected shared CC2/C/module/A-B-C integration passed in 1026.53s. Kleis 52 / 43 passed locally before implementation |
| A4 — whole-stack review | Source review delivered 2026-10-25 | Evidence/gap matrix and formal gate mapping above; follow-ups remain open |
| R1 — local initialization | Formal pair and whole-frame byte/tag initialization runtime accepted | Kleis 151 / 118; 16 focused tests in 0.02s; shared CC2/C integration in 1008.62s; full 1361-test suite in 2446.84s, all passing |
| C1 — compiler contract and ABI | Delivered resource/lifecycle theory, concrete ABI-2 layout and expanded limit inventory above | Original gate developer-accepted: 221 positive (26 quantified) / 195 hostile. C2.3 first-publication refinement developer-accepted: 254 (28 quantified) / 226. C2.4 selector/capacity and linker-profile refinements developer-accepted: 293 / 259 on 2026-10-31 |
| C2 — output growth/accounting | C2.1-C2.5c accepted and merged; C2.6 oversized boundary developer-accepted. Host-storage quota refinement accepted. Charged immutable ingress/loader integration covered by the later passing 83-test bridge group. Complete job charging remains open | C2.6: 321336-byte real AOM, one automatic retry, capacity independence and prior receipts preserved; 1 test passed in 2174.32s. Do not infer full C2 closure |
| C2 host storage | Shared-ledger quota without phantom guest extents; capture/candidate/frozen receipt integration; fixed charged directory and destruction-before-refund | Accepted: local Kleis 34 / 23; developer 10 new tests (0.03s), 89 heap tests (0.08s), 67 bridge tests (2.74s), one long test intentionally ignored |
| C2 immutable ingress | Quota-reserved source/tool custody, shared immutable borrows, exact source-to-loader copy, cancellation and service-death cleanup | Expanded storage Kleis: 59 positive / 45 hostile passed locally; 12 new Rust tests supplied; subsequent 83-test bridge group passed (3.04s). Real CC2 publication fixture uses the charged source loader |
| C2.5 formal gate | ABI-2 capture, retained custody, cleanup and publication contract | Developer-accepted C2.5c: 149 positive (20 quantified laws) / 129 hostile. Output-budget refinement: developer-accepted 163 / 139 |
| C2.5a — capture/admission | Production bounded authenticated capture, role validation and quota-reserved staging | Developer-accepted: 9 capture tests in 0.01s; subsequent 42-test bridge group passed in 0.04s. Updated guest/full-suite acceptance not reported |
| C2.5b — retained custody/publication | Focused acceptance complete: retention, cleanup, frozen provenance and atomic READ-only publication | 11 publication tests passed in 0.01s; affected bridge 53 passed in 0.04s. Real CC2 publication moves to C2.5c |
| C2.5c — retry/publication integration | Accepted and merged: bounded runtime flow, real CC2 publication, concurrent A/B/C witness | Developer: Kleis 149 / 129; six flow tests; fixture preflight 0.01s; shared guest integration 464.34s; 60-test bridge 0.04s. No new full-suite pass claimed |
| C3 — source, workspace and struct-pointer interfaces | In progress: geometry/type foundation and C3.1 guest directory accepted; C3.2 source/preprocessor growth accepted (110.74s). C3.3 forward/recursive declarations accepted (137.92s). C3.4 wide local type encoding accepted (211.55s); typed cross-module heap-list execution accepted (249.11s). Automatic directory-table retry is implemented below; real retry acceptance and ordinary-driver integration remain pending | Cross the existing source/table boundaries with valid programs; compile separate modules using shared-header struct-pointer parameters/returns and opaque forward declarations. Module-local numeric type IDs must not be mistaken for cross-module identity. See required C3/C4 contract below |
| C4 — link, admission and struct-pointer interoperability | In progress: typed guest linking and shared publication consumption accepted. Persistent linked receipts accepted (7 tests). Explicit C startup and nine receipt-execution checks are developer-accepted; real-producer rerun, large-image acceptance and complete execution charging remain open | Link/execute beyond the old 1 MiB cap; accept compatible shared/opaque struct-pointer interfaces and reject incompatible definitions/signatures before execution. Preserve pointer bounds, rights, generation and lifetime through calls/returns; retain existing denial/receipt guarantees |
| C5 — self-hosted closure | Connect the resource-aware path to ordinary user-facing compiler invocation and the rebuild driver, including concurrent jobs and real service code | Exact CC2 generation fixed point, independent concurrent compilations, automatic growth, matching direct-vs-retried artifacts, protected-module execution, and affected regressions; document remaining genuine language/encoding limits |

### C2 host-storage quota refinement — developer-accepted

**Problem:** host capture/parser staging, retained candidate Vecs and frozen
provenance/receipt records were charged with `reserve_heap`. That also reserved
physical and per-owner virtual guest extents for bytes that actually live in host
storage. A full guest pool could therefore deny capture even with sufficient
shared memory quota. Heap cleanup semantics also should not stand in for actual
host-payload destruction. This delivery separates the two resource kinds while
retaining one shared owner/global ledger, not a second independent quota system.

`scoped_pointers/heap/host_storage.rs` supplies opaque, nonwrapping host-storage
reservations. Its fixed directory has `RegistryLimits.cleanup` rows and its actual
retained capacity is included in registry setup charges. Admission page-rounds
conservative host capacity, checks the current common revision, owner/global
ceilings, directory capacity and shared reservation-identity counter before any
mutation. It does not allocate a guest object, pointer slot, cleanup job or physical/
virtual extent. The token type cannot be supplied to heap attachment/publication.
Host and heap charges both contribute to the existing account/global totals.

Capture reserves before Vec/parser allocation. Retention installs a separately
charged custodian record before the producer staging guard releases its charge.
Frozen inputs and admission evidence stay charged with their receipt. Final
published artifact bytes still use ordinary backed heap reservations, zeroing,
READ-only publication and real scrub/reclamation. The capture/custody overlap
remains conservatively charged at peak; host allocator/RSS overhead is not claimed
exact. The implementation retains existing conservative parser/map allowances.

Process closure fences host-storage use but cannot refund it or enqueue it for
CPU/DMA scrub. A closed account remains unreapable while host storage is held.
The trusted custodian drops payload/scratch (or transfers into independently
charged custody) before exact release. Release remains possible after counter
exhaustion; stale handles cannot refund a reused directory row or account.
Cancellation and service-death hooks preserve that destruction-before-refund
order. Failed release retains an obligation rather than declaring reuse safe.

**Formal gate:** `anka108_compiler_storage.kleis` and its hostile pair refine
shared accounting and lifetime requirements from C1. Locally: **34 positive
witnesses, including 11 quantified laws, and 23/23 explicit hostile disproofs**.
The laws cover bounded, nonwrapping shared admission, peer preservation, failed
transition preservation, charge retention on death and destruction-before-refund.
The latter is a trusted Rust lifetime obligation, not a guest-controlled flag and
not a proof of the Rust implementation. No new axioms or hardware claims.

**Runtime evidence to collect:** nine registry tests plus one capture integration
test (`c27_`). They cover a fully occupied guest pool, shared heap/host quota,
fixed-directory exhaustion, account closure, stale/double release, terminal
counters, A exit/C row reuse preserving B, and capture under full physical-pool
occupancy while B's bytes and charges remain intact. Existing bridge tests cover
candidate and receipt cleanup, failed publication, owner death and prior-record
preservation under the new reservation kind. **Developer acceptance:** ten new
tests passed in 0.03s; the legacy fixed-metadata test omitted the new directory
in its expected total (112 bytes in the reported profile). The test-only correction
was confirmed by 89 heap tests in 0.08s and 67 bridge tests in 2.74s, with the
long output test intentionally ignored. No runtime quota was weakened.

**Remaining C2 accounting obligation, unchanged:** use the shared reservation
mechanism for actual source/tool ingestion, producer code/stacks and host-side
preprocessor/job storage, with admission before allocation and owner/refcount
custody for shared immutable tools. Destroy/unmap/drain the corresponding
resource before refund. This patch migrates capture/candidate/provenance storage;
it does not falsely count legacy machines/images as migrated. Bind the complete
job plan to these charges without double-counting already charged heap artifacts.
The next implementation should integrate that resource ownership in the actual
coordinator; no new allocator redesign or repetition of the completed A4 audit.

### C2 immutable input custody and loader integration — Rust acceptance pending

The next accounting gap is input ownership before the five-region loader. The
existing `load_compiler_request` accepted an external byte slice; its destination
heap was charged, but the coordinator had no charged immutable ingress record.
`os/compiler_retry/inputs.rs` now reserves shared owner/global host quota before
allocating a retained source/tool copy, including actual payload capacity and a
conservative descriptor/map allowance. Invalid shape or quota denial does not
return unaccounted input bytes. A copy failure destroys storage before refund;
a failed refund leaves an unreadable Kernel-owned obligation for cleanup.

Handles bind the exact reservation incarnation and current service custodian.
Reads require current custody, the retained reservation, exact length and role.
They return an immutable borrow, not a detached Vec or executable capability.
Multiple consumers can borrow one stored tool without duplicating its payload
or charge. Tool storage does not prove lineage or authorize code loading. Source
and tool limits remain 65528 bytes and 1 MiB respectively; C3/C4 owns widening.
Empty effective source is representable; an empty tool is rejected.

`load_compiler_request_from_input` validates source role/length and a distinct
producer, then uses the same exact immutable bytes with the existing ABI-2 loader.
Moving the Vec temporarily under exclusive Kernel custody avoids an extra clone;
the same payload/charge is restored on both loader success and failure. Source
custody and destination heap coexist, both charged, during copying. Cancellation
of the ingress record cannot invalidate the independently charged guest source.
Producer death does not release service-owned inputs. Custodian death/service
shutdown destroys their bytes before refund and fences old handles.

The actual CC2 publication fixture's common `start` path now uses this ingress
and loader API, discarding the staging input only after loader completion. This
wires both ordinary and oversized publication acceptance through the new source
boundary. That real CC2 path has not been rerun for this delivery. Twelve new
`c28_` tests cover exact copy/role separation, shared tools, boundary rejection,
quota denial, failure after copy, old/foreign handles, actual loader instructions,
partial-load failure and retry, producer/custodian death, shutdown, and A cleanup/C
backing reuse while B's source/charges remain intact and A's aliases are rejected.
These short transport tests do not claim to execute CC2 or preprocessing.

**Formal-first:** the existing compiler-storage pair now passes locally at
**59 positive / 45 explicitly disproved hostile witnesses**, including source/tool
role guards, complete ingress charges, current custody, exact loader length and
immutable shared borrowing. Existing allocation, publication and accepted-lineage
gates still apply; successful storage admission cannot bypass any of them.

**C2 remaining boundary:** this accounts service-owned ingress copies, not the
external caller's original bundle/tool storage, the preprocessor's isolated
machine, or legacy admitted producer code/stacks. Those resources still require
reserve-before-create integration and actual destruction/drain-before-refund.
Shared executable images need lifetime ownership across all live consumers;
stored immutable tool bytes alone do not establish it. The raw-slice loader is
retained for existing transport callers and is not claimed to provide complete
job accounting. Integrate these final execution-resource lifetimes next; keep
C2 open until that and its concurrent-client evidence are established. C3/C4
struct-pointer interoperability and C5 ordinary rebuild remain unchanged.

### Required C3/C4 closure: shared and opaque struct-pointer interfaces

**Scope decision, 2026-10-31:** passing pointers to structs between separately
compiled C modules is required C3/C4 work, not a permanent profile exclusion.
The current q57/AOM signature restriction is a toolchain gap, not an Anka64 CPU
or protected-pointer limitation. The C2 oversized fixture workaround does not
satisfy this requirement. This section adds explicit acceptance to the existing
C3/C4 deliverables; it does not create a separate preliminary milestone.

**C3 supplies the representation and compiler behavior.** Support shared-header
struct declarations and incomplete/opaque forward declarations in pointer
parameters and return types. Define cross-module compatibility, type identity,
completion and layout evidence; do not export current module-local numeric
struct ordinals as global identities. A complete definition records field types,
offsets, size and alignment under the chosen ABI. An opaque caller may retain,
copy, pass and return an authentic protected pointer without knowing its layout;
reject field access, sizeof of the incomplete object, and pointer arithmetic
requiring its size until a compatible complete definition is visible. Pointer
size itself remains known. Account for type records, recursive references and
serialization/validation work within the compiler resource contract. The exact
wire representation and compatibility algorithm must be specified before code.

**C4 consumes and enforces that contract.** Resolve imported/exported function
signatures using compatible type evidence, including repeated declarations,
opaque-to-complete resolution and pointer-recursive types. Same spelling or
same size alone is not sufficient; differing local numbering alone is not a
mismatch. Reject incompatible field types/order/offsets, alignment, completion
or function signatures before publishing/admitting executable code. Bind the
accepted type evidence and ABI version to the exact module/dependency bytes
covered by publication receipts. Call/return transport must preserve authentic
pointer kind, bounds, rights, generation and lifetime; a type declaration or
matching layout must never create allocation authority or revive a stale alias.
An opaque interface confers no additional memory permissions. Struct-by-value
calling conventions and unrestricted legacy-C compatibility are separate scope.

**Formal-first gate:** refine the existing protected-module, AOM/linker ABI,
pointer kind/call ABI and artifact-publication contracts for type evidence,
compatibility resolution and authority preservation. Add a focused positive/
hostile theory pair if those existing theories cannot express the new relation
cleanly; the C3/C4 foundation now supplies `anka108_module_types.kleis` and its hostile
pair, plus the bounded Rust evidence validator. Guest emission, consumption and
receipt integration are still pending. Require witnesses
for compatible independent compilation, opaque completion, recursive type
references, same-name incompatible definitions, different-ID compatible types,
malformed/oversized/cyclic metadata, stale dependency substitution and failed
link/publication preserving earlier artifacts. Recursive type graphs must have
bounded traversal and accounting; pointer recursion must not imply an infinite
layout expansion. Witnesses are model evidence, not a claim of verified Rust/C.

**Required executable acceptance:** independently compile and guest-link a
producer/consumer pair sharing a struct header, pass a protected struct pointer
in both parameter and return positions, and verify permitted field access.
Also compile an opaque client that calls a defining module without seeing the
layout. Use the accepted allocator for the concrete object's backing. Demonstrate
that incompatible interface metadata is rejected and that stale, out-of-bounds
and insufficient-rights pointers remain rejected despite compatible types.
Include failure preservation of prior receipts and resource charges. Close
C3/C4 only after the relevant Kleis gates and these runtime cases pass; current
support and acceptance are **pending**.

For larger local arrays/frames, stacks or parser nesting, C3 first identifies
the limiting contract and C4 widens admission/runtime policy only where its
formal refinement permits it. If instruction or calling-convention changes are
needed, split out that refinement rather than hiding it inside arena growth.
No piece is accepted merely because a constant was raised.

### C3/C4 implementation foundation — 2026-11-01

**Scope and status:** the user requested C3/C4 work while the final C2 accounting
migration remains open. This delivery implements reusable C3/C4 components; it
neither closes C2 nor claims that the ordinary CC2/ankald path has acquired new
limits or struct-pointer interfaces. The latest archive already includes the
C2.8 private-policy-field test correction. The user accepted compiler-storage
Kleis **59 positive / 45 explicitly disproved hostile** witnesses; no C2.8 Rust
pass is inferred from that formal result.

`compiler_adapter::resources::growth` implements checked source lookahead/page
geometry, seven non-overlapping described workspace tables, finite capacity
selection, and code/rodata/metadata link geometry under explicit policy. It has
no baked-in 64-KiB source, 64-function, 16-structure or 1-MiB image policy. It
checks signed address bounds, addition/multiplication, frame and metadata
budgets, alignment and the existing signed PC20 call displacement. These are
**plans**, not allocations; the shared-service coordinator must reserve their
entire live storage before use. Existing CC2's fixed addresses and structure
ordinal representation must not be used with this new workspace plan. A larger
plan alone cannot make the current guest compiler consume it.

`compiler_adapter::interfaces` implements zero-copy **ATY1 version 1** parsing,
canonical layout validation, opaque/complete compatibility and exact ordered
input revalidation. It allocates no directory, graph or recursive work stack.
All scans and comparisons consume a caller-owned `TypeWork` budget shared across
parse, link checking and revalidation. Caller-owned backing must remain charged
and immutable for the borrowed views' lifetime. Count/byte limits are trusted
policy, never selected by the incoming header. Exhausted work fails closed.

**ATY1 wire contract:** little-endian u64 words; exact total length; no unused
arena tail. A name is a C identifier of 1–63 ASCII bytes followed by a NUL and
zero padding to 64 bytes. Names are compared in full, never hashed. Numeric
module-local type IDs do not appear on the wire. The evidence describes only
types reachable from public signatures; private tags are not exported into the
link-unit namespace. Typedefs normalize to their underlying reference. This
first profile requires named public structure tags; anonymous public structure
types and struct-by-value calls are not admitted.

| Record | Exact layout |
|---|---|
| Header, 40 bytes | `ANKATY1\0`, version=1, total bytes, declaration count, function count |
| Type reference, 80 bytes | kind (1=int64, 2=byte, 3=void, 4=struct), pointer depth 0–63, 64-byte tag (all zero unless struct) |
| Declaration, 112 bytes + fields | tag[64], complete flag, size, alignment, field count, value-layout rank, reserved=0; followed by exactly that many field records |
| Field, 160 bytes | name[64], type reference[80], byte offset, positive array count |
| Function, 480 bytes | name[64], binding (1=export, 2=import), parameter count 0–4, return reference, four parameter-reference slots; unused slots all zero |

Opaque declarations have complete=0 and all geometry/rank/count words zero.
They permit type-compatible pointer transport but not object layout/stride
queries. Complete declarations have positive fields/size, natural alignment,
exact field offsets and final padding: int64 uses 8/8 size/alignment, byte 1/1,
and protected pointers 16/16. Embedded complete structs use their verified
layout; direct void fields, zero-count/flexible arrays and packed layouts are
not part of this profile. Minimal value-layout rank is one plus the maximum
embedded-value child rank (primitives/pointers have rank zero). Every embedded
edge strictly decreases rank. Pointer edges do not expand layout, so self- and
mutually recursive pointers terminate without permitting by-value cycles.

A public type key is the full structure tag in the link unit. Equal spelling
alone is insufficient: **every pair of complete definitions** must agree on
all field names/types/order/counts/offsets, size, alignment and rank. Opaque
records may match complete ones but cannot bridge incompatible complete
records elsewhere in the link set. Declaration order is immaterial. Each import
must find exactly one export with the same full return/parameter references.
All definitions are checked, including ones not directly selected by a call.
The existing four argument-register-lane ABI remains: pointer arguments align
to an even lane and consume two lanes; a third pointer or scalar/pointer/scalar
combination that needs five lanes is rejected.

`CompatibleInterfaces` retains borrowed exact inputs. `check_exact_inputs`
rejects replacement/reordering, but **does not prove** that inputs are sealed,
current dependencies or authorized for publication. The trusted publication
path must establish those independently and include the exact type evidence
and ABI version in the receipt-bound module/dependency bytes. This delivery
deliberately does not enable an unbound type sidecar in the current AOM format.
It cannot mint a pointer, change pointer-kind state, grant rights or resurrect
retired aliases. Runtime pointer checks remain mandatory even for compatible
types. There are no changes to current AOM v1 admission or guest byte production.

**Validation delivered:** `--only-c3-c4` runs
`anka108_compiler_growth` (**25 positive / 23 hostile**) and
`anka108_module_types` (**44 positive / 38 hostile**). All four local Kleis
commands pass. These establish the stated scalar guards/laws and witnesses,
not a mechanically checked refinement proof of the Rust or guest toolchain.
**22 focused Rust tests passed on the developer machine** (0 failed,
1470 filtered out, 0.00s), accepting the C3/C4 foundation. No Rust toolchain
is available in this editing environment.
They cover old-boundary geometry, overflow/denial, PC20 limits, compatible
independent declaration order, opaque and recursive types, embedded cycles,
conflicting definitions/signatures, malformed/truncated metadata, bounded work,
and exact dependency evidence revalidation. No actual oversized C3/C4 compile,
guest link, load or runtime struct-pointer call is claimed.

**Remaining implementation, in dependency order:**

1. Wire the source/preprocessor path and a versioned CC2 workspace directory to
   these plans under the shared service. Replace address literals and table
   accesses; replace the 100..115 local structure code range coherently. Add
   capacity reasons for source/workspace/table exhaustion and route them through
   actual cleanup plus cumulative job budgets. This remains C3 work.
2. Have guest CC2 emit canonical interface evidence with complete/opaque
   declarations and pointer-recursive references. Define and gate its exact
   embedding in the next AOM/profile before admitting it. Add shared-header and
   forward-declaration C probes, including struct-pointer returns. Host code must
   not translate C or repair guest output to manufacture this acceptance.
3. Make guest ankald consume the same evidence and described image budgets;
   cross-check its compatibility/layout/relocation results, bind evidence in
   publication receipts, then migrate loader limits. Keep older profiles
   explicit; do not silently reinterpret existing type tags or frame metadata.
4. Run the existing required C3/C4 concrete acceptance: source/table and image
   boundary crossings, independent shared/opaque modules using heap objects,
   stale/bounds/rights rejection, mismatch/denial preservation and concurrent
   client isolation. Only those results can close C3/C4. C5 remains afterward.

### C3.1 — protected guest CC2 workspace directory

**Developer-accepted targeted checkpoint.** Described storage is connected
to the actual protected C compiler. This does not
close C3/C4 or the outstanding C2 complete-execution-accounting gap.

`WorkspaceDirectory` builds a canonical directory from seven requested counts,
using checked `WorkspacePlan` geometry. A fixed 24-KiB prefix retains existing
scalar/parser scratch during this migration; the seven tables occupy disjoint
contiguous tails. An **eighth companion table** stores 64-byte function-frame
records with exactly the function-table count. Growing functions without this
table would overwrite other memory. Counts are 1..4096, with structures still
limited to 16 until the 100..115 type encoding is replaced. Workspace capacity
is page-rounded, at most 1 MiB in this directory profile, and remains subject
to actual shared owner/global/physical allocation limits. This is explicit
policy, not unlimited memory or automatic table retry.

ABI-2 request word 15 selects workspace profile 0 (legacy) or 1 (directory).
Profile 0 retains its exact 768-byte request and 24576-byte workspace. Profile 1
uses a 1024-byte READ-only request, keeping all five 128-byte region descriptors
and protected cells at their existing offsets. Bytes 768..1024 contain eight
32-byte descriptors, each `(workspace_byte_offset, count, stride, reserved=0)`.
Order/strides are functions/80, fixups/16, locals/40, typedefs/24, structures/48,
fields/40, enums/24, function frames/64. Offsets start at 24576 and are canonical
and contiguous; capacity is the exact page-rounded end. The loader/Fabric and
guest both check the new directory; the guest rejects malformed geometry before
parsing source. It cannot write request contents through its read-only grant.

`ankacc2_abi2.c::qdir` resolves table bases/counts and the output pseudo-base.
All seven table access sites and function-frame sites now use it. `qptr` maps
the described workspace and separate output through their authentic protected
pointers. Output pseudo-addresses move with workspace capacity, so larger tails
do not collide with the old 73728 output base. No physical address, pointer kind
or allocation authority is minted from these scalar offsets. Legacy requests
still use the former table locations and capacities. The producer has 63 C
functions, within the accepted bootstrap compiler's 64-function limit.

`load_compiler_request_with_workspace` performs actual shared-service allocation,
zero initialization and publication of all five regions, retaining normal
partial-load owner fencing and cleanup. `load_compiler_input_with_workspace`
uses charged immutable ingress, without cloning retained source bytes. Input
custody and producer custody remain independent. At C3.1 acceptance, source
admission remained 65528 bytes. C3.2 below extends profile 1 explicitly;
profile 0 retains its original bound.

Publication must bind the actual selected directory. The sealed plan is the
existing 22 budget words followed, for profile 1 only, by 35 words:
`(0x57445331, 1, workspace_capacity, directory[32])`. The attempt retains the
loader-selected directory, and pre-execution freeze compares every word.
A missing/substituted directory is rejected even when all original budget
bindings match. Existing sealed-dependency rechecks and failure preservation
remain in force. Publication profile and AOM v1 are unchanged; this work does
not enable ATY1 sidecars or struct-pointer exports.

**Evidence:** local `anka108_workspace_directory` passes **26 positive / 24
explicitly disproved hostile witnesses**. New coverage includes canonical
geometry, coupled function/frame counts, profile-length pairing and exact plan
binding. Native C syntax checking passed. A temporary native 64-bit diagnostic
also checked legacy/directory parity, legacy 66-function rejection (error 8),
successful directory compilation of 66 functions (17056-byte AOM), byte-identical
output across two directory capacities, and successful 40-local compilation
(2656 bytes). That diagnostic is not a protected Anka execution or self-host
acceptance, and its output is not admitted/published as a project artifact.

**Developer runtime evidence:** 7 fast tests passed (one real test ignored),
and the 83-test bridge group passed (two ignored, 3.04s). The explicitly run
`c31_real_workspace_compiler` passed: **1 passed, 1499 filtered, 762.05s**.
It established legacy/directory parity, legacy 66-function rejection, successful
66-function/companion-frame compilation, identical bytes across directory
capacities, and 40 locals. C3.1 is accepted; this is not a full-suite pass.

**Coverage:** 7 fast Rust tests (3 directory, 2 actual
loader/charged-ingress, 2 publication binding), plus one explicitly ignored
real-CC2 acceptance. The latter builds the protected producer through accepted
lineage/guest ankald, then uses the real loader, protected execution, output
capture and cleanup. It checks the same legacy/growth/capacity-independent
results and inspects the 66 function symbols. This is the required concrete
workspace integration checkpoint, now accepted from the developer
protected guest execution rather than the native diagnostic.

**Following checkpoint:** C3.2 below integrates source/preprocessor growth
and capacity outcomes. After its acceptance, replace local type encoding and
emit ATY1 evidence.
Guest ankald/receipt-bound type integration and >1-MiB link/load acceptance
remain C4 work. C5 ordinary rebuild/concurrent closure follows those results.

### C3.2 — bounded effective-source and preprocessor growth

**Developer-accepted: fast checks and real guest acceptance passed after the scanner correction (110.74s).** Directory-profile CC2 can
consume effective source through **1 MiB minus 8 bytes**, admitted through
`ingest_compiler_directory_source` and the existing charged five-region loader.
The profile-0 ingress/loader/compiler still reject source above 65528 bytes.
The new bound is an explicit supported profile limit, not unlimited allocation;
owner/global/physical limits can reject earlier. Workspace and output capacities
remain independent. No new request fields or AOM format are introduced. Exact
source length/bytes, selected directory, compiler image and sealed plan remain
subject to the existing publication provenance checks.

Source storage is reserved and initialized before READ-only publication. Its
logical extent covers the final aligned word; remaining padding stays zero.
The guest checks the profile limit, length versus extent, and word alignment.
Raw integer copying cannot grant pointer kind, and the larger payload overlay
does not relax pointer bounds, owner identity or source immutability. Charged
host ingress survives failed legacy-profile admission and remains independent
of the producer's cleanup. Retrying does not create an uncharged source clone.

`run_ankapp_growing` executes the real include preprocessor with an explicit
`PreprocessGrowthPolicy`: page-aligned initial/maximum output, at most 1 MiB,
1..16 attempts and a nonzero cumulative dispatched budget capped at the existing
one-billion-instruction budget. Each quantum is charged **before** dispatch;
unused quantum is conservatively spent. Only ordinary exit **7**, matching
status **7**, a full output buffer, unchanged sealed manifest/member bytes,
valid transport state and terminal transactions permit capacity growth. A
fault, partial/mismatched capacity reply, include error, placement denial or
budget exhaustion is terminal. Attempts grow strictly by doubling up to policy;
they never reset the cumulative budget. The isolated software Kernel/Fabric is
destroyed before a replacement attempt is constructed. Failed partial output
is never returned as effective source. Successful output is the exact emitted
prefix, independent of unused capacity; outputs beyond the supported source
profile limit are rejected.

**Formal scope:** `anka108_source_growth.kleis` passes locally at **39 positive
/ 35 explicitly disproved hostile witnesses**. Four quantified laws cover source
extent containment, whole-word fetch containment, strictly decreasing dispatch
budget and rejection of stale transport. These are scalar refinement contracts,
not a proof of the C/Rust implementations. Existing storage, allocation,
workspace, accepted-lineage and publication obligations still apply. The older
compiler-storage ingress shape explicitly describes profile 0; its charging,
custody and lifetime rules also apply to the new directory ingress.

**Validation supplied:** nine fast Rust tests cover policy/work bounds, real ISA
capacity/fault transport, actual large-source loader bytes/zero padding/read-only
rights, release/stale access, and ingress quota/peer preservation. One ignored
`c32_real_source_growth_compiler` reuses a single accepted lineage: real ankapp
expands a bundled include beyond 64 KiB, retries from 64 to 128 KiB, produces the
same source as an adequate first attempt, rejects missing includes and work
exhaustion, then protected CC2 consumes the admitted large source and produces
byte-identical AOM to the small equivalent. The host never expands includes or
compiles the accepted artifact.

Locally, Kleis, Python gate-script syntax and C syntax checks passed. A temporary
native 64-bit diagnostic compiled a 70023-byte padded source to the same 400-byte
AOM as the small equivalent and retained the C3.1 table checks. **This is not
protected execution or guest acceptance. Rust tooling is unavailable here; all
new Rust results remain pending.** No new full-suite result is claimed.

**Bounded remaining work:** C3.2 does not claim complete C2 execution accounting.
The preprocessor still owns an isolated 16-MiB emulator machine outside the
shared allocation ledger; original caller bundle/tool storage and returned
preprocessor bytes are external ingress until explicitly admitted. Legacy
producer code/stacks also retain the documented accounting gap. Destroying an
isolated CPU-only software machine is not a proof of hardware/DMA drainage.
No heap pooling, hardware acceleration, automatic table retry or new type ABI
is added here. After this checkpoint, C3 type encoding/ATY1 guest emission and
C4 linking, receipt-bound type admission and larger link/load remain required.
Self/mutually recursive struct pointers and the linked-list acceptance specified
above remain explicit C3/C4 requirements. C5 closes the ordinary concurrent
rebuild path only after these obligations are met.

### Validation cost and immediate next action

Run the new formal gate and fast group first. The earlier 83-test bridge result
is the baseline; use the affected bridge group for integration. Run the new
ignored guest acceptance explicitly in release mode, once. It reuses its
producer image. Do not repeat the accepted 36-minute C2.6 oversized test or the
accepted C3.1 66-function test for this patch. Reserve a full suite for the
coherent integration checkpoint or a concrete cross-cutting failure.

```bash
python3 scripts/check-anka108-gates.py \
  --kleis /Users/enginatik/.cargo/bin/kleis \
  --kleis-root "$HOME/git/cee/kleis" --only-source-growth

cargo test --lib c32_ -- --test-threads=1
cargo test --lib anka64::os::compiler_retry:: -- --test-threads=1

ANKA_PRODUCER_TIMEOUT_SECS=900 cargo test --release --lib \
  c32_real_source_growth_compiler -- --ignored --nocapture --test-threads=1
```

C2 complete accounting, C3 remaining growth/type integration, C4 guest linking
and C5 end-to-end closure remain open. Successful component tests do not close
Phase 10.8 by themselves.

### C3.2 scanner timeout and bounded correction

The developer confirmed the source-growth gate at **39 / 35**, all **9 fast
C3.2 tests** (0.08s, one ignored), and the **87-test compiler bridge** (3.06s,
three ignored). The explicit guest run subsequently timed out at 900 seconds
inside `C3.2 source beyond 64 KiB`, with dispatched budget 120029440. The complete
failed test took 979.51s. Bootstrap/fixed point, both real ankapp runs, their
source equality and error/work checks, and the small reference compilation
(2.87s; budget 377344) had already completed. That run did not accept C3.2; the corrected run below subsequently passed.

**Diagnosis:** the log's first and last roughly minute-long windows sustained
about 133520 and 133995 dispatched-budget units per second. This does not show
progressive throughput collapse, but the old log had no source cursor, so it
cannot by itself rule out a repeated-state guest loop. Inspection found q4's
whitespace path repeatedly calling q1, q2, q0 and qptr for every byte. Each
helper incurs the protected guest call/frame machinery. Existing diagnostic
transaction history is collected every 256-dispatch slice and remains bounded;
a new trace-retention leak is not demonstrated by this log.

A temporary native 64-bit diagnostic of the same C source completed the
70023-byte padded fixture at cursor 70023. It counted 350637 qptr, 70041 q1,
70068 q0 and 70023 q2 calls (560769 total). These are **native source-level
call counts**, not guest instruction counts or a Rust profiler breakdown.
This establishes finite scanner behavior in that diagnostic, not an independent
proof of the timed-out guest's state or the whole compiler's termination.

**Correction:** q4 now reads the protected source/workspace pointers directly.
Each iteration either stops, advances one whitespace byte, or skips exactly
eight literal spaces. The eight-byte shortcut requires an aligned cursor and
eight remaining effective-source bytes; a final padded word never authorizes
consuming padding. Embedded NUL, non-whitespace, existing error and source-end
behavior are preserved. The cursor is committed after each step. No source is
trimmed by the host; the >64-KiB fixture, immutable-source checks, frame/lifetime
checks, quotas and 900-second diagnostic limit remain intact.

The source-growth pair now passes locally at **56 positive / 50 explicitly
disproved hostile witnesses**. Added contracts cover whitespace classification,
alignment/tail guards, strictly decreasing remaining source and contained word
skips. The finite-step law is a refinement obligation for this loop, not a proof
of all compiler control flow. Before/after native scanner comparisons matched
in **12000 cases**, exercising all byte values, alignments, tails, NUL, preexisting
errors and negative cursors. Native compilation retained the 400-byte AOM for
both small and 70023-byte padded sources and the C3.1 table witnesses. The new
four-helper total for that padded source was **696**; no wall-clock guest
speedup is claimed until local protected execution passes.

The real producer observer now retains the authentic workspace token from its
loaded request and reports `source_cursor=Some(n)/length` every five seconds
and on timeout. Reads use current owner/agent checks and do not bypass the
Fabric. Cursor diagnostics add no per-slice memory read. The real C3.2 witness
also compares a small mixed-whitespace program with the reference artifact.
At delivery, new guest/Rust acceptance was pending. The developer subsequently supplied the passing evidence below; Rust tooling was unavailable here.

**Original acceptance action (now completed):** rerun `--only-source-growth`, the fast compiler bridge, then
`c32_real_source_growth_compiler` in release mode using the existing command.
Do not increase the timeout or reduce the source boundary to mask this issue.
Metal remains a planned alternative backend; this log does not establish that
GPU execution is required or faster. Fix and measure excessive guest work first;
CPU/Fabric backend acceleration still requires separate refinement and profiling.


### C3.2 accepted; C3.3 forward and recursive declarations

**Accepted developer evidence:** source growth 56 positive / 50 hostile Kleis
witnesses; 87 bridge tests passed (3 ignored, 3.06s); real C3.2 acceptance passed
in 110.74s. The large-source stage completed in 28.49s / 4073216 dispatched
budget, compared with its earlier 900s timeout. Cursor samples advanced through
13408, 27048, 40616, 54208 and 67840 of 70024 bytes. These are specific-workload
results, not a general proof of compiler termination or a fresh full-suite pass.

**Closure status:** C2 remains open for complete job accounting, including the
isolated preprocessor, executable storage and external input custody. C3 now has
accepted workspace/source growth but still needs type representation migration,
guest ATY1 evidence and the required recursive/opaque module probes. C4 still
needs guest type admission, receipt binding and larger link/load acceptance.
No new phase is introduced by this patch; C3.3 is a bounded part of C3.

**Implemented C3.3 slice:** `struct Node;` reserves a stable local tag, repeated
forward declarations reuse it without consuming another slot, and later bodies
complete the same declaration. Pointer fields may refer to the struct being
built or another not-yet-defined tag. Definitions acquire their field-table
start at definition time, not the earlier forward reservation: otherwise an
intervening definition can make their field records overlap. The active
structure index is initialized/reset to -1 and denies size lookup for a
structure under construction. This prevents a partial nonzero layout from
admitting `struct A { int x; struct A self; };`. Already-complete embedded values
remain supported. Empty bodies, duplicate definitions, incomplete values and
opaque pointer arithmetic/dereference remain rejected. No register authority,
Fabric access check, AOM signature encoding or publication policy is relaxed.

This is the existing file-scope subset, not support for block-scope tag
shadowing. Unknown member tags can be reserved while parsing a file-scope body;
unknown local tags still require a preceding declaration. At C3.3 delivery, the 16-tag limit and
struct-pointer export rejection remained explicit. C3.4 below removes the
directory-profile tag limit; exports still require the ATY1 change.
Accepting a recursive declaration does not yet establish heap linked-list field
access, traversal or cross-module interoperability; those remain required work.

**Formal-first evidence:** extended `anka108_module_types` before implementation:
57 positive / 51 explicitly disproved hostile witnesses. New checks cover tag
reuse/exhaustion, partial-layout exclusion, incomplete pointer transport,
definition conflicts and deferred field-table placement. These scalar contracts
do not prove the C implementation. The existing compiler-growth, workspace and
source-growth gates also passed locally unchanged.

**Local validation:** the native 64-bit diagnostic compiled six supported cases
under legacy and two directory capacities with identical per-case AOMs, and
rejected six hostile declarations/operations. It also retained 66-function,
40-local and >64-KiB source diagnostics. This is not protected guest acceptance.
Rust/cargo was unavailable; no long Rust tests were run here.

**Next acceptance command** (one bootstrap shared by all declaration probes):

```bash
python3 scripts/check-anka108-gates.py \
  --kleis "$HOME/.cargo/bin/kleis" --kleis-root "$HOME/git/cee/kleis" --only-c3-c4
ANKA_PRODUCER_TIMEOUT_SECS=900 cargo test --release --lib \
  c33_real_recursive_struct_declarations -- --ignored --nocapture --test-threads=1
```

The test checks forward/implicit mutual declaration parity across legacy and
independent directory capacities, self pointers, deferred definitions, opaque
transport and explicit rejection diagnostics. It compiles/parses AOMs; it does
not execute linked-list traversal. Following acceptance, replace the local
16-structure type encoding, then implement the already-required ATY1 guest
emission/linker/receipt path. Keep this ordering in the C3/C4 table rather than
creating another independent roadmap.


### C2–C5 closure effort: C3.4 wide local types

**Accepted checkpoint:** the developer passed all C3/C4 gates, then
`c33_real_recursive_struct_declarations`: 1 passed, 1510 filtered out, 137.92s.
Forward/self/mutual declarations, independent-capacity/profile parity and the
six invalid/incomplete-layout rejections are accepted. No full-suite result
was supplied with this checkpoint.

**Implemented next dependency:** the protected ABI-2 compiler now stores private
local types as `(pointer_depth << 16) | base`. Primitive bases are 1/2/3;
struct bases are 100..4195, covering all 4096 directory slots. The old `1000 +
pointee` scheme would collide with structure ordinal 900. All pointer tests,
construction, decay, dereference, arithmetic, malloc/free and typed-I/O checks
now use the new private encoding. Constructor guards reject depth overflow
before the 32-bit type is packed beside an array count. Public scalar signatures
are explicitly converted back to `depth*1000+base` at AOM emission. Struct
signatures remain rejected; no raw local ordinal is exported as type identity.

The trusted workspace directory and guest directory admission now both accept
up to 4096 struct slots, subject to the existing 1-MiB workspace and shared quota.
Profile 0 deliberately retains its 16-slot physical table. Neither the ABI-2
request layout nor AOM v1 changes. Existing profiles with <=16 structs preserve
their meaning; an older producer rejects a larger directory rather than silently
reinterpreting it. Source, workspace, output and per-object layout bounds remain
independent; this is not unlimited memory or unrestricted C support.

**Formal-first validation:** module-type gates pass 69 positive / 61 hostile;
workspace 26 / 24; compiler growth 25 / 23; source growth 56 / 50. New quantified
laws establish base/depth round trips; concrete cases cover the old ordinal-900
collision, final struct slot, pointer-depth exhaustion and unchanged scalar AOM
signatures. These contracts are not a proof of the C implementation.

**Native diagnostics:** 901 forward declarations compiled with identical artifacts
under independent directory capacities; the legacy profile rejected table
exhaustion. Direct compiler-helper checks covered all 4096 struct layouts and
65536 pointer depths. Scalar `int **` return/parameter evidence remained 2001.
The existing six supported/six hostile recursive declaration cases, 66 functions,
40 locals and padded >64-KiB source diagnostics also passed. These execute native
64-bit diagnostic C, not the protected guest machine. Rust tooling was unavailable;
new Rust and real guest acceptance remain pending.

**Required local acceptance:**

```bash
python3 scripts/check-anka108-gates.py \
  --kleis "$HOME/.cargo/bin/kleis" --kleis-root "$HOME/git/cee/kleis" --only-c3-c4
cargo test --lib compiler_adapter::resources::growth::workspace:: -- --test-threads=1
ANKA_PRODUCER_TIMEOUT_SECS=900 cargo test --release --lib \
  c34_real_wide_struct_types -- --ignored --nocapture --test-threads=1
```

The ignored test shares one bootstrap and checks 17 recursive struct tags,
legacy rejection, independent directory capacities and parsed public signature
bytes. Passing it accepts private type widening, not cross-module struct linkage.

**Remaining closure work (same C2–C5 scope, no new phase):**

| Gate | Concrete work still required | Acceptance needed |
|---|---|---|
| C2 complete job accounting | Move preprocessing and legacy executable/process storage under admitted custody; cover dynamic metadata, trace/process growth and cleanup, not just RAM. Carry source/tool/bundle custody and copy peaks through the coordinator. | A/B concurrent jobs; A denial/exit and C clean reuse preserve B; stale A references rejected; no refund while retained work/storage survives. |
| C3 type evidence | Emit complete/opaque ATY1 references in an explicitly gated object profile; implement struct field operations needed for real heap lists. | Shared-header/opaque declarations, struct-pointer parameters/returns, self/mutual recursion and actual allocation/traversal/free. |
| C4 guest linker/loading | Guest ankald consumes type evidence, rejects mismatches and binds exact bytes into receipts; extend link/load policy and runtime admission. | Compatible modules execute, incompatible definitions reject, pointer authority survives calls, image crosses old 1-MiB limit. |
| C5 ordinary rebuild | Connect admitted source, preprocessing, compiler retry, guest linking and publication to the ordinary user command and service rebuild driver. | Exact artifacts/fixed point, concurrent independent jobs, direct/retried parity, socket/HTTP rebuild and affected regressions. |

**C2 audit detail:** `run_ankapp_attempt` creates an isolated Kernel/Fabric and
untracked dynamic transport/process/trace structures. Reserving only
`ANKAPP_RAM_SIZE` in the parent ledger would undercount the job. Any fixed
metadata allowance must be backed by enforced admission limits or actual
retained-capacity accounting. Destruction-before-refund and ownership on fault
must cover that whole runner. No such allowance or fake closure claim is added
in this type-widening batch. The post-malloc review is not repeated; these are
its existing compiler-accounting follow-ups.


### C3/C4 typed-object, member and large-link integration — 2026-11-01

C3.4 is developer-accepted: Kleis 69/61 module-type witnesses, three directory
tests and the real guest witness in 211.55s (1511 filtered). The following packet
implements additional C3/C4 work. **Rust compilation and real guest acceptance
of this packet are pending. C2–C5 are not closed.**

AOM v2 keeps the existing header/section/relocation geometry and appends one exact
ATY1 trailer after the relocation table. Scalar-only compilation remains v1.
Public struct pointers carry a normalized numeric marker and full canonical tag
references in the trailer; local ordinals do not cross the interface. Only tags
reachable from emitted signatures are emitted, including opaque and recursive
references. Rust and the guest linker check symbol names, bindings, parameter
counts, references, complete layouts and conflicting definitions. An opaque
intermediary cannot hide two conflicting complete definitions. These checks do
not grant execution authority. The publication path retains and seals the
entire object, including its trailer, under the existing capture charge.

Protected member lowering implements `p->value`, `p->next->value`, nested
aggregate members, scalar array decay and `&p->next`. Members derive addresses
using PMOV/PADD; scalar values use PREAD/PWRITE and pointer cells use
PLOAD/PSTORE. Layout checks do not replace runtime kind, owner, bounds, rights
or lifetime checks. No raw integer load/store fallback is emitted. Heap-backed
lists are covered by the new real acceptance source pair. Standalone local
aggregate allocation/copy and arbitrary aggregate assignment remain unsupported;
this is not a full C implementation.

A separate trusted large-application linker profile permits modules and combined
code/metadata through 2 MiB. It retains the 4096-frame bound, ordinary zero-entry
ABI, exact guest-output verification, and placement admission for input/scratch/
stack/trap storage. A module cannot select the profile. Legacy application and
compiler-producer policies are unchanged. This removes the old 1-MiB boundary
for that explicit route; it is not unlimited memory or complete job accounting.

**Bootstrap failures caught before delivery:** the original typed emitter exceeded
the stage-3 compiler's 32-named-local limit; adding member assignment also exceeded
the statement parser's 8-KiB frame limit. The emitter now has its own function,
the pure pointer predicate is inlined to stay at 64 compiler functions, and
statement calls reuse expression-call parsing. Neither bound was raised. The
native stage-3 diagnostic compiles the exact new producer source (50885 bytes)
into a 602280-byte AOM: 401464 code bytes, 190464 frame metadata bytes, 64 frames,
largest frame 635 locals. This is a native diagnostic, not guest acceptance or
a new self-hosting fixed-point claim.

**Validation here:** Kleis module types 116 positive / 107 hostile; compiler growth
25/23, workspace directory 26/24 and source growth 56/50. Native diagnostics
compile the two checked-in list modules, link them with exact type evidence,
reject malformed references, and exercise the explicit large-image policy
(1052672 code bytes, 1052736 total image bytes; default policy rejects).
Native linker diagnostics explicitly model Anka's logical opcode shifts; native
C signed-shift behavior is not treated as machine equivalence. No Rust/cargo or
long emulator regression suite was run in this environment.

**Added Rust acceptance:** exact v2 trailer/symbol binding; malformed geometry;
independent host/guest tag and layout rejection; compatible opaque/complete
linking; charged capture and exact publication through producer cleanup; an
ignored real two-module heap-list execution/free/stale-alias witness with
capacity parity; and an ignored real image link/load beyond 1 MiB. The latter
uses assembled padding to isolate link/load, not a claim of a >1-MiB C program.

Run locally:

```bash
bash scripts/check-anka108-closure.sh
bash scripts/check-anka108-closure.sh --real
```

The second command is the explicit long acceptance. After both pass, run the
remaining affected compiler tests and the full single-threaded release suite
before merging. Do not infer a new full-suite pass from earlier results.

**Typed-link bootstrap correction and receipt profile binding:** the developer
reported three failing typed guest-link tests (three passed, one ignored). All
three failing tests enter the same `ankald_image()` bootstrap. A native
execution of the generated canonical CC_B source reproduced rejection at source
cursor 2522: the new ATY1 magic and signed-maximum constants exceed CC_B's
131071 literal limit. After constructing those identical values from 16-bit
words, canonical compilation reaches its 81920-byte output ceiling and rejects
at cursor 15490. The existing extended CC_B completes the exact corrected linker
source: 17844 source bytes, 46 functions, 93824 code bytes, zero deferred fixups.
The linker and source-bundle test bootstraps now both select this existing
extended route. The frozen canonical compiler, ISA immediates and linker
control address are unchanged. The bootstrap test checks code stays below
`ANKALD_CONTROL_VADDR`; the closure script runs it before downstream witnesses.
These are native diagnostic results; the reported Rust tests still need rerunning.

`ApplicationLinkProfile` now distinguishes Standard and Large application policy
without exposing the compiler-producer ABI as an application option.
`freeze_modules_with_profile` freezes that selection. Execution, actual linker
control word, publication receipt and later image/dependency validation must
agree. A copied receipt with a substituted profile is rejected before loading.
Publication remains READ-only and requires the existing execution/publication
authorities; loading still requires explicit execution authority. Default callers
retain Standard. Two new runtime tests cover profile-preserving publication/run,
caller receipt substitution, actual transport or runner-profile substitution,
no commit on failure and retry. The C4 refinement was checked before this Rust
integration: module-type gates now pass 116 positive / 107 hostile witnesses.

This connects profile selection to the existing module store, not yet to the
new shared-Kernel ABI-2 job service. That store still admits individual modules
through its original 256-KiB producer path; selecting Large does not widen that
producer. Larger **combined** images may use multiple admitted modules subject
to actual placement. Direct >1-MiB link/load acceptance remains separate from
whole-service resource-accounting and concurrent job acceptance. Corrected
native linker diagnostics still pass typed linking (2552 code / 3640 image bytes)
and explicit large linking (1052672 code / 1052736 image bytes).

**Real-lineage bootstrap failure correction:** the developer's real C3.5 witness
failed before generation 1 with `WrongPermission` while compiling tools. The
previous packet corrected linker test fixtures but missed the linker call in
`witness_cc2_fixed_point`; that production call now uses the extended 256-KiB
arena too. Tool-specific progress messages distinguish preprocessor and linker
bootstrap failures. The canonical fixed-point compiler remains unchanged.

A native diagnostic reproduced the underlying error-path defect: with the
80-KiB arena, output emission sets error 1, but an enclosing branch/call fixup
still writes offset 81920. In the emulator that address is outside the writable
output and Fabric correctly refuses the write. Extended CC_B now skips patches
after an error and checks that each aligned 8-byte patch slot was actually
emitted below the literal frontier. The canonical source is unchanged. Kleis
module-type gates pass 125 positive / 115 hostile witnesses, including patch
bounds and failure behavior. Native checks now return error 1 without an
out-of-arena patch for 81920 capacity, and succeed with 93824 code bytes for
262144 capacity. Generated extended source is 18535 bytes, within the existing
20472-byte source allowance. These diagnostics do not replace Rust acceptance.

A new focused runtime regression deliberately compiles the real linker in the
small arena, requires `CompilerRejected(1)` rather than a protection fault, then
compiles it successfully in a fresh extended arena. The closure script runs it
before real acceptance. No long regression suite was run here.

The latest supplied archive contained 17 project files and omitted the gate
runner and most source. The complete recovery ZIP restores the last complete
project archive plus the preceding typed-link/receipt corrections, overlays all
17 supplied files, and applies this fix. It contains project files only, no Git
history. Extract it over the existing repository, preserving `.git`; a patch ZIP
must not replace the project directory. The closure script checks essential
files before starting tests. C2/C5 implementation and C3/C4 runtime acceptance
remain open; this recovery does not mark Phase 10.8 closed.

**Remaining acceptance and implementation, without introducing a new phase:**

| Existing gate | Verified status | Remaining closure condition |
|---|---|---|
| C2 | Shared heap/capture/publication, accounted preprocessing, compiler admission and linker transport accepted. Application-run accounting accepted: eight focused tests, 149 runtime tests (nine ignored), real C5 run 247.31s. | Ordinary service and actual concurrent A/B/C accepted (75.79s). Preserve accounting in protected service I/O; final affected regressions. |
| C3 | Source/workspace growth, recursive declarations, typed heap-list and automatic table retry accepted. Real table retry preserves exact AOM (83.55s). | Preserve these gates through the ordinary service and protected service-source rebuild. |
| C4 | Typed guest linking, shared consumer, persistent receipts, C startup and charged execution accepted. Large-image link/load accepted (22.10s). | Ordinary service link/run integration accepted. New private-input HTTP execution and final affected regressions remain. |
| C5 | Kernel-owned jobs retain exact source/provenance across retries and complete guest link, receipt and C startup. Latest real job passed in 247.31s. | `anka rebuild` coordinator accepted: 6 focused, 154 runtime (10 ignored), actual concurrent A/B/C in 75.79s. Protected HTTP/input is implemented below; socket/NIC rebuild and final regressions remain. |

The current packet removes orchestration from test fixtures. It does not claim
that the existing raw-address socket/HTTP sources have been ported or that all
ignored guest tests ran. The required post-malloc review remains recorded earlier;
this table tracks its findings without repeating the audit. FPGA/Metal remain
future execution backends, not substitutes for closure evidence.


**C3.5 protected compiler frame-pressure correction (2026-11-01, runtime now accepted):**
The latest supplied log confirms the bootstrap capacity regression, real linker
bootstrap, six typed-link component checks, two receipt-profile checks and the
large-profile policy check passed. The real heap-list witness reached the
protected ABI-2 compiler, then faulted with pointer-registry `Exhausted` at
`pc=0x4e190`, the entry of primary-expression parser `q63`. This is a different
failure from the earlier bootstrap write-permission fault.

The compiler reserved 625 protected local records for each primary expression
and 635 for each statement, including recursive block dispatch. A native C
instrumentation diagnostic, weighted with the actual emitted guest frame
manifests, measured a peak of 4770 locals plus five ABI records for the supplied
list sources. That exceeds the unchanged 4096-record producer registry. This
measurement diagnoses synchronous parser call pressure; it is not guest runtime
acceptance or an exhaustive bound for arbitrary programs.

The implementation now dispatches literals, parenthesized expressions and simple
identifiers through a compact `q63`, with heavyweight primary forms in `q66`.
Blocks use a compact `q50` and other statements use `q67`. Pure identifier-character
predicates are inlined to keep the bootstrap function table at 64 functions.
The canonical CC2 source, registry limits, authority checks and frame retirement
rules are unchanged. No new architectural contract is introduced: the existing
bounded-resource and protected-frame contracts continue to apply.

Native stage3 compilation of the exact revised producer succeeds. Instrumented
native execution of the same consumer/provider sources now measures 3961 local
records plus five ABI records. Both emitted AOMs are byte-identical to their
pre-refactor counterparts (5744 and 2392 bytes). These are native diagnostic
results only. The required acceptance is the existing real protected compiler,
linker and heap-list execution witness:

```sh
cargo test --release --lib c35_real_typed_modules_and_heap_list -- --ignored --nocapture --test-threads=1
```

After that passes, run the remaining real large-application witness. More deeply
nested sources can still exhaust finite compiler resources; this patch is not a
general stack-growth implementation. C2 whole-job accounting, the ordinary C3/C4
service integration and C5 closure obligations in the table above remain open.


**Current closure evidence and next implementation boundary (2026-11-01):**
The developer accepted the real typed heap-list witness (249.11s), seven shared
publication-consumer tests (3.48s), and seven persistent linked-publication tests
(6.70s). The earlier capability-entry compilation error is superseded. These
results accept those checkpoints, not all C2-C5. The current full regression
suite and explicit large-image execution acceptance have not been supplied.

The shared Kernel consumer accepts current local module epochs and an explicit
Standard/Large application profile. It rechecks original sealed dependencies,
current grants and exact selected linker bytes; bounded protected reads and
parser/result storage use shared quota. Actual guest ankald links the modules.
The guarded result retains ordered dependencies, profile, image and charges.
`CompilerLinkedOutput::publish` requires separate publication authority, a current
nonwrapping epoch and live custody. It initializes a fresh heap artifact before
publishing exact READ-only bytes, transferring existing host reservations without
cloning or refunding. One record insertion exposes the artifact and receipt.
This is in-memory persistence, not disk durability or executable admission.

Receipt/read access rechecks current custodian, reservations, provenance, ordered
module bytes, profile and the exact authentic heap image. Individual discard and
Kernel shutdown destroy host payload before refund and close heap authority
before physical reuse. Worker drainage and scrub remain required. Failed cleanup
retains unreadable charged records and records completed releases for safe retry.
Individual link discard preserves the source module publications.

**New implementation, pending local Rust acceptance:**
`Kernel::run_linked_compiler_publication(epoch, execution_authority, config)`
connects that persistent receipt to the established protected `SYS_SPAWN` /
`SYS_WAIT` runner. It checks current receipt/provenance and exact heap bytes while
holding the exclusive Kernel borrow. No caller-provided image, profile or detached
receipt can replace those bindings. Entry must be zero, protected metadata must
immediately follow nonempty code, the retained application profile bounds total
image size, and dispatch quanta/rounds must be nonzero and within existing default
limits. The established runner separately validates virtual/physical geometry.

Execution authority is required independently of publication authority. A fresh
isolated application Fabric receives an exact sealed executable copy; the shared
publication remains READ-only. The child gets RX code and READ metadata through
ordinary spawn admission and no grants to compiler jobs. The result names its
original publication epoch explicitly; the runner's artifact key belongs only to
that transient execution realm. Execution neither advances the publication epoch
nor discards the source record. Denial, child fault and bounded timeout preserve
publication custody. A subsequent authorized run uses a fresh execution realm.

This bridge deliberately reuses the existing isolated runner. Its RAM, dynamic
metadata, trace/output storage and peak-copy accounting have NOT been migrated
to shared job quota. The publication's existing charge must not be presented as
covering that footprint. Therefore this is a C4 execution integration checkpoint,
not closure of C2 whole-job accounting or the C5 user-facing coordinator.

The existing publication theory was refined before implementation and now passes
**256 positive witnesses and 221/221 explicitly disproved hostile claims**.
The execution refinement checks authority/currentness/profile, entry and image
geometry, finite dispatch policy and preservation of the publication epoch.
Boolean certificates denote trusted runtime checks; these model results are not
a proof that every Rust transition implements the theory.

**Explicit protected C startup — 2026-11-01, implemented; Rust acceptance pending:**
The developer accepted the eight execution-fixture tests (5.66s). The subsequent
real CC2 publication witness failed at `pc=0xb0` after compiling/publishing B:
ProtectionFault instead of Exited(42), in 126.54s. This exposed a broader entry ABI
gap, not a compiler output or return-authority defect. AOM main is a callable C
function, but the receipt runner entered it directly as a process. The prior
fixture-only SYS_EXIT correction did not resolve ordinary `return` from main.

The new explicit C entry runner installs a trusted binding to the exact current
sealed object, generation, code and total image sizes. Protected metadata must
validate before selection; selection cannot be replaced within that Kernel. A
matching process must have zero code offset/entry and the same geometry. Other
objects retain ordinary direct-entry behavior. Stale bindings fail closed.

The process's existing owned trap page keeps HALT at offset zero and holds a
16-byte startup sequence at offset 16: CALL main; MOV R1,R0; MOVI R0,SYS_EXIT;
TRAP. It is initialized before sealing. The caller checks alignment and signed
22-bit word displacement before encoding CALL. After ordinary protected-program
admission, the core starts at this launcher. CALL itself mints the existing
object/generation/target-bound return authority. Main retires its frame and RET
consumes that authority; the launcher exits with the C result. No host-created
return token, RET exception, source rewriting or artifact-byte patching is used.
Main may also explicitly SYS_EXIT, in which case the launcher does not resume.

The selected policy is fixed-size and the launcher uses the already allocated
trap page. Its page follows existing process ownership/reclamation. Application
code/metadata and the READ-only linked publication remain exact. Execution still
requires independent authority, and application code receives no access to the
publishing Kernel. Direct-entry runner APIs remain unchanged: a bare RET without
CALL authority still faults. The real B publication probe keeps its original
`return *p+1` source and expected exit 42.

`run_linked_compiler_publication` selects this C entry path. Nine execution tests
now cover ordinary return, explicit exit, direct-entry RET rejection, authority,
provenance, stale/discarded receipt, exact bytes, finite policy and timeout/retry.
Four startup tests cover encoded CALL/return-result transfer, signed displacement
limits, exact current identity/geometry and non-retargetable selection. The
>1-MiB acceptance uses ordinary main return through this same explicit runner.

The publication Kleis gate was refined before implementation: **256 positive /
221 explicitly disproved hostile witnesses** passed. The additional contract
separates exact startup binding from actual CALL minting and requires live
launcher generation, retired frames and the exact return target. These are
model results, not a blanket proof of the Rust implementation. Existing direct
entry, protected return and event-context mechanisms are preserved.

The whole isolated execution footprint still lacks complete C2 charging; using
an existing trap page does not close that gap. C3/C5 automatic growth and ordinary
service coordination are unchanged by this startup implementation. No new phase
or additional closure requirement is introduced. This environment has no Rust
compiler; the added runtime paths require local validation:

```sh
cargo test --release --lib c4_startup_ -- --nocapture --test-threads=1
cargo test --release --lib c4_execution_ -- --nocapture --test-threads=1
cargo test --release --lib p107_concrete_cc2_rebuild_runs_typed_pointer_and_rejects_raw_address -- --nocapture --test-threads=1
cargo test --release --lib c4_real_large_application_link_and_load -- --ignored --nocapture --test-threads=1
```

The remaining closure obligations are the C2-C5 table above: whole-job accounting;
automatic workspace growth/retry; explicit large-image loading acceptance; ordinary
admitted source-to-publication/execution service coordination; concurrent A/B/C
exhaustion/exit/reuse with stale rejection; actual socket/HTTP rebuild and affected
fixed-point/regression acceptance. Phase 10.8 remains open until those requirements
have implementation and passing evidence. No additional phase is introduced.


### C3 automatic workspace retry — implementation, 2026-11-01

**Accepted evidence carried forward:** the latest developer logs pass four
startup tests, nine receipt-execution tests (5.98s), and publication Kleis
256/221. The logged real producer failure at `pc=0xb0` preceded that patch;
there is no subsequent real-producer completion in the attached logs. This
packet does not relabel that failure as resolved by an unobserved run.

**Implemented:** directory-profile ABI-2 producers report capacity status 1 with
resource roles 32..38 for Functions, Fixups, Locals, Typedefs, Structs, Fields,
and Enums, respectively. Minimum is a record COUNT, not a byte length. Used
output and diagnostic must be zero; job, attempt, bindings, source cursor and
reserved words are checked exactly. Profile 0 still rejects those roles. Its
error 8 and the 4096 local/frame representation bound remain terminal.

The trusted loader binds the initial workspace directory into the non-Clone
retry budget before execution. A request must strictly exceed that table's
current count and stay within 4096. The runtime grows that count geometrically,
rebuilds the canonical directory and function-frame companion, and enforces the
existing 1-MiB workspace profile bound. Other counts and output capacity remain
unchanged. Count growth is valid even when it fits the same allocation page.
Shared owner/global admission can still deny the next allocation.

Both the capacity bridge and publication flow use the checked budget decoder.
The proposed next budget consumes one retry, increments the attempt without
wrap, and retains all spent work. Only actual old-owner cleanup can release it.
The next loader automatically uses the carried directory; supplying an older or
different directory is rejected before allocation. Output-capacity retries also
retain the workspace binding. Publication requires equality between the budget
and actual loaded directory, and the existing sealed plan binds its exact words.
No guest hint selects addresses, strides, source, tools or publication authority.

**Formal gate passed before implementation:** workspace-directory theory now has
55 positive witnesses and 52 explicitly disproved hostile claims, including
non-output role rejection, incomplete cleanup, budget reset and unchanged-page
count growth constraints. The other C3/C4 gates remain passing. These models
state the transition obligations; they do not prove the Rust/C implementation.

**New runtime acceptance:** seven scalar/geometry tests, one real loader/retry
A/B/C isolation test, and one publication-flow test. An explicitly ignored real
CC2 test starts with a one-function directory, observes actual guest exhaustion,
waits for cleanup, reloads using the carried two-function directory, and compares
the AOM against an adequate-capacity reference. No host-generated artifact is
accepted as compiler output. That test's machine admission is still a harness,
not the ordinary C5 service. Rust tests were not run in this environment.

```sh
python3 scripts/check-anka108-gates.py --kleis "$HOME/.cargo/bin/kleis" \
  --kleis-root "$HOME/git/cee/kleis" --only-c3-c4
cargo test --release --lib c3_workspace_retry_ -- --nocapture --test-threads=1
cargo test --release --lib anka64::compiler_adapter::resources:: -- --test-threads=1
cargo test --release --lib anka64::os::compiler_retry:: -- --test-threads=1
ANKA_PRODUCER_TIMEOUT_SECS=900 cargo test --release --lib \
  c3_workspace_retry_real_compiler -- --ignored --nocapture --test-threads=1
```

**Closure:** this implements the missing table-capacity transition, not C2 whole
job accounting or the C5 ordinary rebuild command. The existing C2-C5 table above
remains the closure checklist. Do not repeat the completed post-malloc audit or
introduce additional phases. Next implementation must migrate admission and
orchestration out of fixtures, account the entire preprocessing/execution
footprint, and connect the real service rebuild under those same contracts.


### Workspace publication integration repair — 2026-11-01

The supplied archive contains the new directory-aware budget decoder and loader,
but still has the preceding versions of `compiler_retry/capture.rs`,
`compiler_retry/publication.rs` and `check-anka108-closure.sh`. Byte comparison
against the delivered workspace-retry ZIP identifies exactly these three code/
script differences. The archive is otherwise consistent with that packet.

The failing flow calls `context.decode`, which intentionally understands only
output capacity. It therefore rejects workspace role 32 with `UnsupportedGrowth`,
although the separate loader/retry test correctly calls `budget.decode` and passes.
Restore the directory-aware decoder and workspace proposal branch in capture,
the budget/loaded-directory equality guard at publication freeze, and the closure
script's workspace tests. No ABI, authority or Kleis contract is changed by this
repair; these are the already-delivered integration changes.

Developer evidence: seven workspace scalar tests and the A/B/C loader/cleanup
test pass; the publication-flow test failed, and real workspace compiler acceptance
was ignored. The real large-application link/load witness passed in 22.10 seconds.
After applying this overlay, rerun `c3_workspace_retry_` and the affected compiler
runtime group before the ignored real workspace witness. No full regression or
post-repair Rust pass is claimed here.


### Bootstrap function-table correction — 2026-11-01

The developer accepted all nine workspace-retry component tests and the affected
114-test compiler-runtime group (seven ignored, 11.67s). The subsequent real
workspace test failed while BUILDING the producer, before executing any retry:
`CompilerRejected(8)`, functions=64, source position=1713, elapsed 28.81s.

The added `qneed` helper made 65 producer function definitions. The accepted
bootstrap compiler has 64 function slots; a directory-aware compiler cannot use
its own new facilities before it has been built. This was an implementation
regression, not failure of the workspace capacity protocol. The correction folds
all seven table-report paths into existing `q3`: internal codes 20..26 select the
table; profile 1 and a count below 4096 emit the same role 32..38/minimum-count
reply; profile 0 and the hard limit retain terminal error 8. First-error retention
and existing output-capacity behavior remain unchanged. The producer now has
exactly 64 unique function definitions. No bootstrap bound, permission or
accepted compiler source was widened.

A cheap Rust source-shape guard detects another function-directory overflow
before real compilation. A native diagnostic using 64-bit integers passed all
seven table cases, legacy/hard-limit rejection, first-error retention and output
capacity reporting. C grammar validation also passed. These host diagnostics
are not accepted guest artifacts or proof of the Anka execution. The existing
Kleis workspace contract is unchanged. The subsequent developer log accepts the corrected real guest test: 1 passed in 83.55s, and 10 focused checks passed with the real witness ignored in that group.

The closure script's missing workspace checks are restored in this overlay. Run
`c3_workspace_retry_` for the new bootstrap guard, then explicitly run
`c3_workspace_retry_real_compiler -- --ignored` in release mode. The already
accepted 114-test group need not be repeated solely for this C-source correction.
C2 whole-job accounting, C5 ordinary service orchestration and final affected
regressions remain required; this repair does not declare Phase 10.8 closed.


### C5 Kernel-owned compiler jobs — 2026-11-01

**Evidence:** the developer's latest log contains an old bootstrap failure followed
by the corrected 10-test component pass and the real workspace retry pass (83.55s).
The earlier failure is superseded. No current whole-suite pass is inferred.

**Implemented in this overlay:** `os/compiler_retry/jobs.rs` owns job handles,
retained effective source, provenance keys, publication-flow state and the single
non-Clone retry budget. Callers poll bounded slices. A capacity reply becomes
`NeedsProcess` only after actual producer cleanup; the caller can inspect a
read-only next-plan encoding but cannot take, replace or reset its budget.
`resume_compiler_job` accepts only a fresh, unstarted process using the same
compiler object/generation and a new sealed plan. It reuses the retained source,
directory and work/retry ledger through the accepted loader. A loaded peer cannot
be consumed as a retry process. The plan is checked by the publication gate,
not trusted because the caller supplied a key.

The original frozen, charged provenance snapshot survives the retry interval.
It is rechecked before admission, including exact source/tool/dependency bytes.
It is destroyed only after the next snapshot is frozen, so both snapshots are
charged at their overlap. Job descriptor/dependency capacity and retained source
are charged to shared host-storage custody. Cancellation closes its own producer,
destroys source/pin payload before refund and keeps failed cleanup in Kernel
custody. Custodian death and service shutdown dispose jobs before input and
publication teardown. Successfully published receipts outlive job disposal.

The job API starts with an already admitted and loaded first attempt. It is an
internal service API, not a new CLI. It neither builds a fresh process itself nor
migrates isolated preprocessing/legacy process storage into charged admission.
The real acceptance witness still supplies those admission operations explicitly.
These limits are C2/C5 work, not a reason to describe this packet as Phase closure.

**Formal gate:** `anka108_compiler_jobs.kleis`: 39 positive witnesses;
`anka108_compiler_jobs_false_witnesses.kleis`: 31/31 explicitly disproved here.
The model specifies authenticated custody, state transitions, cleanup-gated retry,
provenance pin retention, publication, destruction-before-refund and independent
peer state. Execution, fresh admission, exact pin comparison and actual cleanup
are trusted certificates supplied by existing gates; this is not a proof of the
Rust implementation, scheduler liveness or entire-stack resource accounting.

**Acceptance to run locally:** 11 `c5_job_` tests, the affected
`anka64::os::compiler_retry::` group, and the ignored
`c5_real_compiler_job_retry_publication` witness. The latter uses accepted CC2,
forces a real output retry through the job API, compares exact AOM bytes, disposes
the job while preserving its receipt, guest-links, and runs C `main` to exit 70.
Rust is unavailable in this environment; none of these new Rust checks is claimed
as passed. Kleis, Python syntax and shell syntax checks passed. The closure script
now includes job gates and restores the omitted workspace retry checks.

**Remaining closure sequence:** finish charged preprocessing and fresh process /
provenance admission (including dynamic metadata and trace bounds), wire the job
API into the ordinary rebuild command, rebuild the socket/HTTP service stack,
and record required direct/retried, concurrent A/B/C and full regression results.
C2, C5 and Phase 10.8 remain open. Existing C3/C4 component acceptance is retained.


### C5 integration repair — 2026-11-01

The latest developer run did not reach tests: Rust reported 22 errors. Comparing
all 14 delivered job-overlay files against the supplied archive identifies two
older files: `src/anka64/os.rs` and `scripts/check-anka108-closure.sh`. The Kernel
lacks both the `compiler_jobs` field and its initialization, although the new job
module and teardown hooks are present. These omissions cause the repeated E0609
errors; the two E0308 diagnostics occur in expressions whose registry type could
not be resolved. Restore the missing field/initializer before treating those as
independent reference-type defects. No borrow semantics were changed speculatively.

This repair restores those two integration files and adds
`scripts/check-anka108-job-integration.py`, invoked before closure gates. It checks
explicit wiring anchors across the Kernel, job module, teardown, flow, provenance,
tests and gate scripts. It catches the supplied incomplete archive and accepts
the repaired overlay. This is an installation diagnostic, not a Rust parser,
formal proof or runtime pass. No Kleis contract changed, and no new passing Rust
result is claimed. Run the job tests and affected compiler-runtime group before
the real compiler-job witness. C2/C5 and Phase 10.8 remain open as listed above.


### C2 accounted preprocessing and C5 source transfer — 2026-11-01

**Accepted evidence:** the latest developer log passes all 11 C5 job tests in
0.01s. It contains no result for the broader compiler-runtime group or ignored
real-job witness; neither is inferred as accepted.

**Implemented:** `Kernel::preprocess_compiler_source` takes an authenticated,
charged Tool input and a borrowed immutable source bundle. It computes and
reserves transport quota before constructing an isolated machine. The reservation
covers 16 MiB guest RAM, 4 MiB bounded fixed metadata allowance, 64 KiB per member
plus 16 fixed descriptor allowances, twice the manifest extent and twice the
maximum output capacity. This is a conservative policy charge for retained
payload/capacity, not a measurement or guarantee of allocator RSS. The fixed
pointer registry has a separately enforced 2-MiB construction budget. The
accounted profile bounds member count at 256, image size at 128 KiB, and output
at the existing 1-MiB policy maximum; PM still owns physical placement.

The restriction is enforced, not merely estimated: one legacy CPU process, no
heap service/timer/controllers, only ordinary user exit or SYS_EXIT, 1024 return
slots, one event frame, and 256 instructions per trace slice. Trace slots are
reserved before execution (four per instruction); current scalar instructions
use at most fetch+read+write and eight-byte payloads. Protected-pointer operations
cannot run in this legacy profile. No syscall that creates processes, objects,
mailboxes, device work or output buffers reaches its handler. Call-depth rejection
is conservative at the limit, including before a RET. Adding ISA instructions
or changing retained container layouts requires revisiting these bounds.

Output-growth attempts retain one shared reservation and cumulative work budget.
The isolated machine is destroyed before its result returns; successful exact
bytes are copied into the existing charged EffectiveSource input while staging
is still charged. Staging is destroyed before transport refund. Errors and quota
denials yield no source handle. Failed refund remains a charged ledger obligation.
A borrowed caller bundle remains external ingress; this does not claim that all
caller-owned source/tool lifetime has already migrated to the shared service.

`begin_compiler_job_from_input` joins this ingress to the accepted job coordinator
without exporting source bytes. It temporarily moves the original Vec under an
exclusive Kernel borrow, restores it on success/error, and separately charges the
job's retained source copy. The real C5 compiler-job witness now uses charged
guest preprocessing, this transfer, capacity retry, exact AOM comparison, guest
linking, receipt retention and execution. The real-test fixture explicitly admits
48 MiB per owner inside its existing 128-MiB global budget to cover preprocessing;
no architectural quota check was bypassed or physical pool enlarged.

**Formal acceptance here:** `anka108_preprocessor_storage.kleis` 31 positive;
false witnesses 23/23 explicitly disproved. Predicates cover shape, admission,
restricted step bounds, custody transfer and destruction-before-refund. Concrete
layout allowances, instruction transaction counts, allocator behavior and Rust
refinement are implementation obligations, not proved by Boolean certificates.

**Local acceptance pending:** eight `c2_preprocess_storage_` tests plus its ignored
real include-growth witness; one additional component test extends `c5_job_` with
admitted-input transfer (12 job tests total). Run the affected compiler-runtime
and source-growth groups, then the real C5 witness. The old unaccounted preprocessing
API remains available to legacy callers; this packet introduces and connects the
accounted route, not a false claim that every caller has migrated.

**Closure remains pending:** charged compiler process/code/stack admission;
isolated linker/application-run accounting; ordinary user-command integration;
actual socket/HTTP rebuild; required concurrent-job and complete regression
acceptance. No new phase is introduced and C2/C5/10.8 are not marked closed.

### Accounted preprocessor exit-gate correction (2026-11-01)

The first local runtime run reported five passes, three failures and one ignored
real test. Successful-output, capacity-retry and peer-isolation probes all hit
`RestrictedTransport`: the restricted runner incorrectly required user mode at
all instruction boundaries. Anka64 TRAP enters supervisor mode and returns
Continue; the next instruction executes the trap gate HALT. This was a runner
refinement defect, not a failed quota check or an infinite loop.

The runner now admits exactly one pending SYS_EXIT event from user mode, with
interrupts masked and PC at the trap vector. The gate must halt; arbitrary
supervisor execution and other syscalls remain forbidden. The same check applies
across slice boundaries. A regression places TRAP immediately before, at and
after the 256-instruction boundary, checking both accepted EXIT and rejected WRITE
and checking quota refund. Existing success, retry and peer tests are retained.

The Kleis storage contract now explicitly distinguishes ordinary user steps from
the pending exit gate: 40 positive witnesses and 31 explicitly disproved hostile
witnesses passed. Runtime acceptance of this correction remains pending; the
failed run did not reach the subsequent job or compiler-runtime test groups.
This correction does not mark C2/C5 or Phase 10.8 closed.


### Accounted preprocessing acceptance: finite-budget fixture correction (2026-11-01)

User-reported compiler-runtime group: 135 passed, zero failed, nine ignored in
12.03 seconds. This accepts the focused exit-gate correction, not the ignored
real-toolchain tests. The subsequent real include-growth test failed at the
legacy reference call with WorkExhausted after 34.89 seconds, before invoking
the accounted preprocessing path. Its 100-million-instruction fixture budget
was one tenth of the existing C3.2 budget for the same >64-KiB include workload.

The real fixture now uses the established one-billion-instruction budget for
both reference and accounted runs, shared across attempts in each run. No
production limit, retry count, quota, or exhaustion classification changed.
The exact-byte and dispatched-budget parity assertions remain. Progress output
identifies reference completion and accounted execution separately. The real
include-growth and compiler-job acceptance tests remain pending; the chained
job test did not execute after this failure. Phase 10.8 remains open.


### C2 compiler admission arena — concrete implementation (2026-11-01)

**Accepted baseline:** the developer's latest log accepts real accounted
preprocessing (41.88s) and the Kernel-owned compiler job (257.65s). The latter
completed two capacity retries, exact AOM comparison, guest linking, publication
receipt validation, ordinary C startup and exit 70. These results supersede the
preceding fixture failure, not the remaining C2/C5 closure obligations.

**Developer-accepted (latest reply: both tests passed; no new counts/timings):** a Kernel-owned compiler
admission arena replaces manual executable/process/stack construction in that
real C5 witness. A separately required execution authority admits one validated
protected producer image and one to eight stack slots. Shared owner/global quota
is reserved before parsing, copying, placing objects or publishing execution
permissions. Fabric rejects overlapping placements, including the private heap.
Initial code padding and every stack are zeroed. The code is sealed, and only
its validated program enters a fresh process context.

The backing/metadata reservation remains charged for the lifetime of the arena
and its Kernel, including idle slots. It includes code/trap pages, one MiB per
stack, eight times the linked image size plus two MiB per program/slot for bounded
parser/core metadata. This is a conservative service-quota allowance, not an
allocator RSS guarantee. The shared heap has independent fixed-table and payload
charges. This fixed boot profile is deliberately not a fresh malloc per retry;
unused arena capacity remains reserved and cannot be represented as refunded.
Changing producer image or arena geometry currently requires a new Kernel. A
future online arena-release operation must destroy all retained slot metadata,
code and receipt references before refund; this packet does not invent such a
release certificate. The source/tool ingress buffers borrowed by configuration
remain caller-owned, not retroactively charged by this reservation.

Retirement requires an exited exact process incarnation, actual heap-owner
release and terminal Fabric transactions. It drops saved event/register/frame
copies, retires the process slot, removes the old agent/domain and destroys the
old stack ObjectId. Reuse creates a fresh ObjectId and zeroes the same physical
backing before grants. The immutable compiler code stays alive for publication
receipts. A late failure keeps the slot quarantined and its quota retained.

Admitted compiler execution uses only the compiler dispatch path, at most 256
instructions per slice, no devices or timer, fewer than 128 calls/active frames,
at most one event context. The initial profile allowed 4096 live local references;
the HTTP frame-pressure correction below supersedes that compiler limit with
16384 and checks the pending frame before admission. Application execution keeps
its separate 4096-local envelope. Transient local creation and Vec growth remain
included in the conservative metadata allowance. Terminal
CPU-only diagnostic trace collection bounds retained history and never consumes
live requests. General-purpose scheduling cannot bypass the compile-only path.

Kleis gate `--only-compiler-admission`: **32 positive witnesses; 24 hostile
witnesses explicitly disproved**. These scalar admission/reuse/envelope contracts
are refinement obligations for the concrete checks, not a whole-Rust proof.
Eight focused Rust tests cover quota denial, overlapping backing, malformed
metadata rollback, independent A/B then C reuse, stale A retirement, authority,
fixed slot capacity, recursive metadata limits, scheduling bypass and real
owner-cleanup ordering (some tests cover multiple cases). Run those before the
updated real C5 witness. Both were subsequently reported passing by the developer.
No long Rust suite was run in the development environment.

**Still open for 10.8:** linker/isolated-run accounting; ordinary command/service
admission and actual socket/HTTP rebuild integration; combined A/B compiler jobs
with A exhaustion/exit and C backing reuse; affected regressions and final closure
acceptance. Existing C3/C4 language and linker witnesses remain accepted at their
reported revisions. Do not reinterpret this arena packet as full Phase 10 closure.


### C2 guest-linker machine accounting — implementation and remaining closure

The compiler admission packet is accepted by the developer's latest “both tests
passed” report. It supersedes that packet's pending status, without supplying
new test counts or elapsed times. The C2–C5 status table above is authoritative;
earlier dated implementation notes remain historical evidence.

The shared publication consumer now reserves three separate amounts: input and
parser staging, retained image capacity, and the isolated linker machine. The
new machine reservation is taken from the same custodian account and global
ledger before constructing a Fabric. It includes 16 MiB of RAM, 4 MiB of bounded
registry/CPU/trace metadata, 64 KiB per module plus 16 fixed descriptors, two
control-buffer allowances and two maximum-image allowances. Existing 32× input
staging covers concurrent parsed input and linked-program validation. This is a
conservative retained-capacity quota, not an allocator RSS or performance claim.

Preflight permits 1–4096 modules, a nonempty tool of at most 128 KiB, and at most
7 MiB of aggregate input bytes; checked placement can still reject an impossible
combination of inputs, scratch, stack and control. It never changes the existing
Standard/Large module or image limits. The image length is checked against the
selected profile before allocating its exact-capacity capture buffer.

The isolated machine uses the accepted restricted scalar transport: one process,
no private heap, devices or timer; exit-only syscall dispatch; call depth below
1024, at most one pending exit event, and at most 256 instructions per slice with
bounded terminal trace storage. The existing one-billion-instruction total is
preserved across slices. A guest cannot grow process/object/output tables via
spawn, exec, write, malloc or yield. A repeated loop still spends finite work;
recursive CALL is refused at the metadata boundary. No new ISA operation is added.

On success the linker returns only its exact validated image. Its Fabric,
placement tables and temporary machine state are destroyed before the caller
refunds the transport reservation. The independent image/staging charges remain
live through publication. On any failure the machine unwinds before the guard
refunds its own reservations; input/prior publications and peer charges remain.
A failed release remains charged. Legacy linker APIs keep their previous profile;
only the shared-service consumer selects the accounted transport.

Kleis `--only-linker-storage`: **33 positive witnesses; 23 hostile witnesses
explicitly disproved**. The gate states admission, capture/refund ordering,
geometry and strictly decreasing nonwrapping work. It imports the existing
preprocessor transport contract (including the separate TRAP/exit-gate steps).
These are concrete refinement obligations, not a proof of the Rust allocator.

Four new focused Rust tests cover quota geometry, denial before execution,
forbidden syscalls/refund, and bounded recursion/retry. The existing real guest
link parity test now also asserts that machine quota is refunded while image
quota remains. Success fixtures explicitly allow 48 MiB rather than the former
8 MiB of owner quota; the low-quota denial fixture remains at 8 MiB, and its
publication-denial counterpart fills the updated fixture limit. Production
limits are unchanged. Python integration checks and shell syntax passed here;
Rust compilation and runtime acceptance must run on the developer's Mac.

**Next work, with no additional phase:** (1) enforce and account the isolated
application-run envelope, including output, saved contexts and cleanup; (2)
connect ordinary command/service ingress to the accepted compiler-job coordinator,
then exercise concurrent actual A/B compile jobs, A exhaustion/exit, C reuse,
B correctness and stale A rejection; (3) rebuild the socket/HTTP service through
that path and run the affected closure gates. C3/C4 components remain accepted;
C2/C5 and Phase 10.8 remain open until these integration conditions pass. The
Metal/FPGA plan stays recorded as a future backend, not an acceptance substitute.


### C2 application-run accounting — concrete implementation (2026-11-01)

**Accepted baseline:** the developer supplied one passing linker geometry test,
146 passing compiler-runtime tests (nine ignored) in 3.00s, and the explicit real
C5 job in 249.26s. The real job retained source/provenance across two retries,
matched exact AOM, guest-linked, checked the receipt and completed ordinary C
startup with exit 70. This accepts the preceding linker-storage packet; it does
not imply that the other eight ignored real tests ran.

**Accepted:** eight focused tests passed in 2.36s, the compiler-runtime group
passed 149 tests (nine ignored) in 2.93s, and the real C5 job passed in 247.31s.
The earlier 249.26s result belongs to linker acceptance. Receipt-authorized execution now
reserves both isolated-machine and returned-output storage from the current
custodian's shared owner/global ledger before constructing the application
Fabric. The input receipt, actual provenance and profile remain revalidated;
publication authority still cannot authorize execution.

The conservative machine charge is 96 MiB plus 32 times the exact linked image
size: 16 MiB RAM, the entire existing 64-MiB application heap/registry budget,
and 16 MiB of bounded nonheap process, pointer-cell, trace and staging storage,
plus image parser/program copies. The 64-MiB reservation deliberately includes
unused capacity; it is not a claim of measured RSS. Existing heap accounting
still measures its fixed registry/shadow/work tables and reserves its payload.
Stack sizes are nonzero and at most 64 KiB each; virtual layout is at most 16 MiB;
Standard/Large image limits are unchanged. Actual constructed RAM capacity and
fixed heap metadata are checked before publishing execution grants.

The runtime profile enforces one scalar supervisor, one nonscheduled cleanup
worker and one protected child. The supervisor may perform one SPAWN attempt,
WAIT and EXIT; the child retains protected EXIT/READ_BYTES/WRITE/MALLOC/FREE.
Other scalar syscalls and extra spawn attempts fault. This is a restricted
one-shot execution profile, not a change to general Anka64 process semantics.
Devices/timers are excluded. Each instruction boundary applies the accepted
call/frame/event/local envelope (128-call/frame boundary, one saved event and
4096 live locals), and terminal CPU trace is collected into a 16384-entry
preallocated allowance. No live transaction is silently discarded.

Typed I/O in this profile has a 4096-byte per-call limit and 64-KiB total captured
output. Overflow or quota exhaustion returns the existing failure sentinel before
reading or appending a prefix. A full buffer cannot widen the allocation via Vec
growth. The existing protected pointer and complete-span checks still apply.
The scheduler executes finite one-instruction rounds, retaining ordinary
spawn/wait and cleanup transitions. Its maximum round count is the checked
product of the supplied bounded quantum and rounds; a tiny budget still times
out. No output or error path grants an unbounded retry.

The isolated Fabric, placement, registry, CPU contexts and cleanup state are
destroyed before refunding the machine charge, including timeout/fault paths.
This realm has no device/external DMA borrower and its backing is not transferred
to the shared Kernel. The output Vec has a **separate 69632-byte reservation**
(64 KiB plus report allowance). `LinkedCompilerRunReport` now borrows its Kernel
and exposes `execution()` by reference. Dropping the report destroys its buffer
before refunding that reservation. Internal callers were updated to drop the
report before mutating the Kernel again. Caller-created copies of borrowed
results are caller-owned storage, as with other trusted borrowed interfaces.
Failed quota release remains charged; exit alone is never a refund certificate.

Successful receipt-execution fixtures now explicitly admit 256 MiB per owner
and 512 MiB globally to include the conservative machine reservation. These are
test policies; production service limits are unchanged. Low-quota tests still
prove rejection before machine construction, and publication-quota tests fill
the updated fixture limit. The real C5 fixture includes these charges alongside
its retained compiler admission arena.

Kleis `--only-application-run`: **29 positive witnesses; 19 hostile witnesses
explicitly disproved**. Contracts cover separate authority/receipt/admission,
one-shot spawn, machine/report destruction before their respective refunds,
bounded steps and nonwrapping output arithmetic. The proof imports the compiler
metadata-envelope contract; it is not a complete Rust/allocator proof.

Eight new focused Rust tests cover arithmetic/geometry, prepared realm shape,
spawn/syscall restrictions, frame/process bounds, atomic typed output denial,
quota rollback and report custody. Existing receipt execution tests now use the
charged path, including timeout/retry and C startup, and the real C5 acceptance
uses it. Run `bash scripts/check-anka108-application-run.sh --real`; Python wiring,
shell syntax and the Kleis gate passed here. No long Rust suite was run here.

**Remaining closure work:** application-run acceptance is complete. Connect the
ordinary source/tool ingress and shell/service command to the existing admitted
compiler-job coordinator. Exercise actual concurrent A/B compiler jobs with A
exhaustion/exit, C clean backing reuse, unaffected B and rejected stale A aliases;
rebuild socket/HTTP through that ordinary path and run the affected closure
acceptance. C3/C4 components remain accepted at their reported revisions. C2/C5
and Phase 10.8 remain open pending that integration; no new phase is introduced.


### C5 ordinary rebuild service — accepted (2026-11-01)

`anka rebuild [--include FILE] [--initial-output BYTES] [--run] ROOT.c [MODULE.c ...]`
is now a normal binary command. It uses the reusable production coordinator in
`os/compiler_retry/service.rs`, not test helpers. It freezes exact bundle/source/
tool/plan evidence, runs accounted guest preprocessing, admits the protected
compiler, carries output/workspace retry budgets through actual cleanup, publishes
READ-only modules, guest-links in argument order and optionally runs the linked
receipt under separate execution authority. Standard output contains application
bytes; diagnostics/progress use standard error. A nonzero C exit becomes the
command's exit status. No detached uncharged output Vec leaves the run guard.

The command accepts up to eight module roots and 256 total members. Lookup names
are exact file basenames; `#include` must use those names. Duplicate names reject
before bootstrap. Host ingestion bounds each file and the combined canonical
bundle to 1 MiB; growing files cannot defeat the read limit. The ordinary command
currently compiles modules sequentially. The underlying service admits two live
jobs, supports bounded round-robin polling and separates their handles by realm,
slot and nonwrapping serial. Completion consumes a handle. A wrong/stale handle
cannot select another job. Work/capacity failures retire only the selected owner;
failed cleanup leaves resources charged/quarantined, never reusable by assertion.

Service provisioning uses accepted CC2 lineage to build the actual ABI-2 image.
That trusted bootstrap and caller-owned source ingress are outside per-job quota;
this is explicit, not a claim that all host bootstrap allocation is guest billed.
The owned service uses 64-MiB RAM, a 32-MiB protected heap pool, 512-MiB global and
256-MiB owner quota, and the existing charged two-slot compiler admission arena.
A separate 70-MiB prepaid charge covers RAM, bounded nonheap service/provenance
metadata and canonical-bundle staging. Immutable provenance backing occupies
4–16 MiB, has at most 256 objects, and remains retained/charged until service
teardown because receipts depend on it. Each object is bounded to 1 MiB. Failed
arena attempts burn their reserved slot rather than reusing evidence. This fixed
provenance capacity is a stated service policy; dynamic compiler buffers continue
to use shared allocation and existing checked growth. It is not unlimited memory.

Compile slices are at most 256 instructions. Each compiler job carries at most
one billion instructions across retries, plus a bounded coordinator/cleanup
allowance; preprocessing has its own finite shared-retry budget. Accepted source,
workspace, output, linker and application-run bounds remain enforced. Service
exhaustion returns an error and preserves peer state and prior publications.

Kleis `--only-rebuild-service` passed **29 positive / 21 explicitly disproved
hostile witnesses** here before delivery. It adds composition obligations for
charged admission, exact retained evidence, actual release before retry, current
publication authority, peer-preserving cancellation, realm/serial handles and
nonwrapping provenance geometry. Boolean prerequisite predicates state required
conditions; they do not independently prove the complete Rust implementation.
The existing imported machine/accounting contracts and runtime checks remain
necessary.

Six focused Rust tests cover boot quota/realm identity, canonical bundle binding,
retry plan serialization, sealed backing/geometry, collision preservation and
CLI argument bounds. The explicitly ignored real witness uses the SAME production
service: admit actual compiler A and B; exhaust A's 512-instruction ledger while B
is live; confirm owner release and stale aliases; admit C into A's physical stack
and released heap backing with fresh identity; poll B/C independently; guest-link
and execute their receipts to exits 42 and 70. It also rejects cross-realm, consumed
and capacity-exceeding handles. The developer subsequently supplied a passing real run in 75.79s, six focused tests in 0.02s and 154 runtime tests (ten ignored) in 2.89s; binary checking also completed. This accepts the ordinary-service packet.

Run `bash scripts/check-anka108-rebuild-service.sh --real` from the repository.
The script runs the new gate, focused tests, affected runtime group, binary check
and explicit concurrent witness. No long Rust tests were run here. The supplied
application-run acceptance remains valid evidence for its preceding revision.

**To close 10.8:** the ordinary path is accepted. Port/rebuild the actual socket/HTTP
service through it (the existing service code still dereferences numeric raw
addresses), and run the corresponding end-to-end and final regression gates.
Assess the concrete network I/O and shared-buffer authority contracts in Kleis
before changing them. A successful arbitrary application or the original legacy
`/alive` test alone cannot certify that protected service rebuild. No new phase
or optional GPU work is inserted into this closure sequence.


### Protected HTTP application/input and README reconciliation (2026-11-01)

**Accepted baseline:** ordinary-service Kleis 29 positive / 21 hostile; six
focused Rust tests (0.02s), 154 runtime tests with ten ignored (2.89s), successful
binary checking, and the real concurrent compiler witness (75.79s). A exhausted
its work ledger while B stayed live; C reused A's stack/heap backing with fresh
identity; stale A aliases rejected; B and C published, linked and exited 42/70.
There is no new regression failure in that log. Its earlier 247.31s result belongs
to the already accepted application-run packet, not another full-suite run.

The next implementation is `userspace/system/services/net/httpd_protected.c`.
It retains the existing bounded `/alive` routing and exact 74-byte 200 / 64-byte
404 responses, replacing numeric-address loads/stores with protected byte
pointers. One private 1024-byte local buffer accumulates a finite typed-input
image; positive reads advance within the remaining extent, EOF ends input, and
a one-byte overflow probe rejects more than 1024 bytes before any output. Empty
input exits 11; oversized input exits 14; typed I/O failure exits 10/15. Valid
bounded requests and bounded nonmatching requests emit 200/404 and exit zero.
Header bytes remain opaque, including binary bytes. This intentionally preserves
the original limited HTTP subset; it is not a new general HTTP parser.

`anka rebuild --input FILE --run ...` supplies up to 65536 input bytes under
separate `DeveloperInputAuthority`. Input without `--run`, duplicate input options
and excessive file size reject before bootstrap. Kernel receipt execution checks
input and execution authorities, exact current receipt and length before machine
construction. A **135168-byte** additional reservation (two 64-KiB buffers plus
4096 metadata allowance) covers the input-copy/Box-conversion peak. The existing
machine/report charges remain separate. Bounded provisioning checks capacity and
attaches the immutable image to the exact spawned child/context before its first
instruction. Startup handoff rounds count toward the existing total dispatch
bound. Empty explicit input is EOF; absence of input does not imply authority.

The entire isolated machine and its input binding are destroyed before refunding
the machine/input reservation. Captured output remains borrowed and separately
charged until report drop. Quota failure, bad receipt, missing authority, timeout
and invalid input preserve earlier publication state. No new global permissions,
NIC capability, shared buffer lease or implicit revocation is introduced.

Kleis `--only-http-application` passed **27 positive / 18 explicitly disproved
hostile witnesses** before implementation. The gate composes separate authority,
charged actual-child input and destruction conditions, bounds input/request/
response sizes and proves strictly advancing, nonwrapping bounded reads. These
are abstract composition obligations, not a proof of the entire parser or Rust
implementation. The maximum-u64 hostile value uses bitvector subtraction rather
than an oversized decimal literal, which this Kleis evaluator did not reduce.

Five new focused runtime tests cover separate authorities, oversized/wrong-receipt
rejection, extra input quota, input refund before report refund, and failed startup
cleanup. The explicit real witness compiles the actual protected HTTP source
through `RebuildService`, publishes and guest-links it, then checks exact response
bytes for `/alive`, a different path, opaque binary headers, truncated input,
1024/1025-byte boundaries, empty input and repeated fresh runs. Each run must leave
shared quota unchanged after its report is dropped. The supplied log now accepts
five focused tests (one ignored) in 2.36s, 159 compiler-runtime tests (11 ignored)
in 2.93s, and the CLI test. The real HTTP compilation failed as detailed below;
its guest application acceptance remains pending.
A native C byte/length diagnostic, Kleis and script/wiring checks passed here;
no long Rust regression was run. Run:

```sh
bash scripts/check-anka108-http-application.sh --real
```

All ten real README.md files were reviewed and updated: root; userspace root,
bin, etc, lib, include/anka, system, system/compiler, system/services and its net
directory. Removed stale claims that HTTP/linking/includes are unimplemented or
that Stage 1/2 grammar limits describe current CC2. Historical bootstrap stages
remain explicitly identified; supported subsets, exact include naming, legacy
versus protected paths and current acceptance are distinguished. No extra notes
file was introduced.

**Remaining closure is concrete:** accept this private-input HTTP application;
specify/pass the protected socket endpoint and buffer-custody/DMA-drain contracts;
connect the actual socket/NIC stack and run the rebuilt Ethernet/TCP `/alive`
witness; then run the required ignored acceptance and complete regression gates.
The new file-input demonstration is not network acceptance. The existing raw
socket/HTTP shared-memory handshake remains a legacy contract and does not revoke
aliases on SEND. C2/C3/C4 component acceptance is retained; C5 network integration
and Phase 10.8 closure are not declared complete by this packet.


### HTTP compiler frame-pressure correction and network closure path (2026-11-01)

**Evidence:** the latest real HTTP witness reached the accepted CC2 lineage and
protected producer, then failed after about 515 seconds of HTTP compilation:
`pc=0x77f8`, pointer registry `Exhausted`, followed by capture execution failure.
The whole test took 590.52s. This was a capacity fault before HTTP execution,
not a diagnostic timeout. Elapsed-only reports do not prove source progress or
an infinite loop. The log did not record live locals or the precise preflight
subcondition; the new diagnostics expose frame/local counts and all exhaustion
counters. Runtime acceptance of this correction is still pending.

The ordinary service had one 4096-slot registry shared by two protected compilers
and heap identities. The recursive parser registers large generated frames (the
producer has previously reported 663 locals in its largest frame). C3.5's earlier
parser factoring reduced one fixture's pressure but never established 4096 as a
sufficient budget for HTTP, arbitrary nesting, or two independent compilers.

The compiler profile now permits **16384 live local identities per admitted
process**. The two-job service constructs **36864 slots = 2 × 16384 + 4096**,
retaining headroom for its bounded heap/service identities. These are finite
policy limits, not a promise to compile every valid program. The existing
`RegistryLimits` construction checks and charges actual retained table capacities
before running jobs. No guest can enlarge the registry; the 512-MiB service
quota, 1-MiB per-compiler stack, per-frame 4096-local representation bound,
finite instruction ledger, and authority/lifetime checks remain enforced.
The conservative prepaid core metadata allowance covers the larger local vectors;
fixed registry bytes stay charged through process exit and reuse. Ordinary
application execution retains its 4096-local policy. Before PFRAME, the runtime
checks used + pending locals using subtraction after bounding used; overflow or
excess rejects before payload writes or identity issuance.

Kleis `--only-compiler-admission` passes **48 positive / 38 explicitly disproved
hostile witnesses**. New obligations bound both job allowances and headroom,
prove nonwrapping pending-frame admission, reject uncharged storage and preserve
the smaller application profile. This models budget conditions; it does not
prove the concrete Rust implementation or guarantee HTTP termination.

Two inexpensive scan changes preserve validation: backing exclusion traverses
only the registry's maintained active prefixes, and ordered local intervals use
adjacent disjointness checks instead of repeatedly scanning all earlier locals.
Unordered manifests retain full pairwise validation and original local-index
order. Physical-alias checks, captured work exclusion, zero-before-publication,
kind initialization and generation authentication are unchanged. No measured
speedup is claimed until the same release-mode HTTP witness passes locally.
New short tests cover pending-frame rejection, ordered/unordered overlap handling,
two real sets of seven 663-local frames, stale A after retirement with B live,
and charging of the expanded service registry. Five-second HTTP diagnostics now
show PC, dispatch polls, retries, active frames and local usage. Registry failure
also reports requested/free slots, free scopes, next scope and revision.

**Legacy networking migration decision:** preserve the existing CC_B stack and
its packet/IPC tests as regression evidence while porting its service boundaries.
Do not relabel the old shared-buffer handshake as protected ownership or remove
the only working reference stack. The bounded next network contract is a typed
socket endpoint with copying into private protected buffers. It needs endpoint
identity and process incarnation, separate RX/TX authority, exact spans, short
read/write/EOF behavior, finite work and queue quotas, cancellation and close,
cleanup and stale-delivery rejection. It must not grant raw DMA access to HTTP.
Copies avoid alias handoff; zero-copy leases would require their own ownership,
revocation and drainage refinement before implementation.

| Remaining closure step | Required evidence |
|---|---|
| Accept protected HTTP | This corrected ordinary compile/link/run witness: exact 200/404, binary bytes, 1024/1025 boundaries, cleanup and receipt checks |
| Typed socket boundary | New Kleis endpoint/copy/close contract and hostile witnesses; affected typed-I/O, process-incarnation, quota and cleanup gates |
| Port network services | Compile Ethernet/ARP/IP/ICMP/UDP/TCP/socket through the protected toolchain, preserving each protocol test; explicit controller RX/TX authority and DMA drain/initialization gates |
| Rebuilt network acceptance | Actual NIC → rebuilt TCP/socket → protected HTTP → NIC `/alive`, plus stale/error/peer-exit cases and exact published tool/source receipts |
| Final closure | Required real/ignored witnesses and full release single-threaded regression, then update this table to accepted |

A transition bridge may help test a protected service against the old stack, but
that alone does not close the full stack rebuild. Ports and contract gaps should
be delivered against this finite list, without inventing more project phases.

**Metal 4 prototype:** move performance investigation forward, separately from
network acceptance. Apple's Metal 4 documentation provides compute dispatch,
explicit resource management and synchronization; its shader compilation
improvements are not AnkaCC2 C compilation improvements. First prototype bounded
CPU/Fabric steps for a supported instruction subset with explicit fallback at a
semantic boundary, keeping the Rust reference as the oracle. Compare one serial
compiler and batches of independent compilers; measure total wall time, guest
instruction throughput, dispatch/readback cost and retained memory. A batch-only
speedup must not be reported as lower single-job latency. Before broader use,
Kleis refinement must cover instruction effects, byte transactions, pointer-kind
metadata, authority checks, retirement, ordering and fault/rollback parity.
Threadgroup barriers do not by themselves synchronize different threadgroups;
never commit speculative branches or memory effects before authority is checked.
This packet does not implement Metal or claim an M5 speedup.
Official reference checked 2026-11-01:
https://developer.apple.com/videos/play/wwdc2025/205/


### HTTP timeout: private heap membership scan (2026-11-01)

The second HTTP log accepts the frame-budget packet: **9 focused tests / 1
ignored (2.46s)**, **160 compiler-runtime tests / 11 ignored (3.04s)**, CLI test,
and compiler-admission **48/38** plus HTTP **27/18** Kleis gates. The real witness
then hits its unchanged **1200-second diagnostic timeout** (1272.47s overall),
with no new registry fault. The final sample was 64389 polls at 1197.1s, about
13770 dispatched-budget units/second (256 per poll, not a measured committed
instruction count). Sampled live-local counts peaked at 3396; five-second samples
are not the true instantaneous maximum. Changing PC/frame counts alone does not
prove source progress.

Source inspection found a concrete amplification of a hot-path cost:
`Fabric::translate` calls `private_heap_object`, whose `contains_object` scanned
all private rows for ordinary code/stack identities. Increasing registry capacity
also increased this absent-identity scan from 4096 to **36864 rows**, even when
only the compiler's five ABI heap regions occupied the table. The capacity
correction was necessary for the prior failure but amplified this existing
linear lookup. This explains a significant avoidable cost; no whole-test speedup
or completion is claimed before the local Rust rerun.

`HeapFabric` now retains a charged `rows_end` boundary. All production row writes
use `set_row`, including attachment, initialization and compiler publication.
The boundary covers every occupied row, including holes, sparse high slots and
retired rows that are not yet released. Authenticated clean release removes the
row and trims only an actually empty trailing suffix. Membership scans the
prefix; all exact identity comparisons and lifetime/rights/backing checks remain.
This is neither an authorization cache nor reclamation on process death. Fixed
row/shadow capacity remains allocated and charged. `sizeof(HeapFabric)` accounting
includes the added field. Attachment's independent overlap census remains intact.

Kleis allocation/Fabric gate now passes **198 positive / 167 explicitly disproved
hostile witnesses**: insertion preserves the prefix invariant, sparse slots grow
it, hole reuse cannot erase higher rows, and truncation requires an empty suffix.
The scalar model states the invariant; Rust tests remain necessary for every
concrete mutation path. Two focused tests cover 36864 empty rows, ordinary
translation, private-identity exclusion, sparse attachment after 300 locals,
holes, removal, reuse, and equivalence with a full-table membership scan.

A host-native diagnostic compiled the current ABI-2 C compiler and fed it the
HTTP source after host preprocessing: **6340/6340 source bytes**, compiler error
0, reply status 0, **52120 output bytes**, 127954 qptr calls. This shows that the
native diagnostic terminates; it does not prove guest termination, exact artifact
parity, or protected HTTP execution. The guest acceptance now reports source
cursor/length read through the authentic workspace token every five seconds,
without scanning or reading source state on every dispatch. If a retry retires
that token, the diagnostic returns None rather than bypassing authentication.
The 1200-second diagnostic limit and finite guest work budget are unchanged.

Run `bash scripts/check-anka108-http-application.sh --real` after this overlay.
It includes the affected Fabric gate and heap regression group before the real
HTTP test. Rust acceptance and the network closure steps above remain pending.


### HTTP protected entry ordering correction (2026-11-01)

The latest local run accepts allocation/Fabric **198/167**, its **160-test**
heap group, **11 focused HTTP tests / 1 ignored**, and **160 compiler-runtime
tests / 11 ignored**. Most importantly, actual guest HTTP compilation completed
in **21.83 seconds**, versus the earlier 1200-second diagnostic timeout. This is
measured progress after the occupied-row lookup correction, not a Metal result.

The next failure was `Link(LinkerRejected(8))` at the HTTP link call. The HTTP
fixture defined helpers before `main`; CC2 emits definitions in source order.
The protected application linker requires exported `int main()` at code offset
zero. The HTTP source now places helper prototypes first, the `main` definition
next, then unchanged helper definitions. Neither the host nor guest linker entry
checks are relaxed. This repairs source conformance to the existing entry
contract; it introduces no new authority or architectural invariant requiring a
new Kleis theory.

A cheap `c5_http_source_places_main_before_helpers` fixture test catches this
ordering mistake before the expensive real run. A native diagnostic using the
actual ABI-2 compiler source accepted all **6481 host-preprocessed source bytes**
and emitted **52120 AOM bytes**; inspection verified the exported main symbol's
code offset **0**, return type **int**, and **zero parameters**. Native HTTP
response/boundary checks and the Python integration checker also passed. Native
diagnostics do not substitute for protected guest execution. Rust tests were not
run in this environment; the new fixture test and real link/run acceptance remain
pending. Run `bash scripts/check-anka108-http-application.sh --real` locally.
Phase 10.8 and the full protected network service rebuild remain open.


### HTTP read-loop source correction (2026-11-01)

The latest real HTTP run compiles in **22.47 seconds** and successfully links.
It then fails the response assertion with empty output (94.99s overall). The
assertion ran inside the output callback before checking the child's result,
so the supplied log did not expose its exit status.

The concrete source bug is `while (used<1024 && done==0)`. CC2's current lexer
recognizes single `&`, not the C short-circuit `&&` token. The expression was
accepted as bitwise `&` followed by unary address-of: the right comparison tests
`&done==0`. The address is nonnull, so the first loop condition is false and
`used` stays zero. The application takes its explicit empty-input return 11.
This is a source/subset mismatch and also exposes a compiler diagnostic gap:
unsupported adjacent logical operators should eventually be rejected as whole
tokens, or implemented with true C short-circuit semantics; they must not be
advertised as supported C. This patch does not implement that language extension.

The source now uses `while ((used<1024) & (done==0))`. Each comparison yields
scalar 0 or 1 and has no side effects, so eager bitwise conjunction has the
required behavior. No pointer, input authority, syscall, quota or linker check
changes. A focused fixture regression guards both the explicit condition and
absence of unsupported logical operators. The real test compares output under
the existing charged borrow, retains only Boolean/length diagnostics, then checks
exit status before asserting byte equality. Each case logs its input length,
result and output length; no unaccounted output clone is introduced.

Validation: a native diagnostic of the actual ABI-2 compiler accepted **6484
host-preprocessed bytes** and emitted **52104 AOM bytes**. A bounded diagnostic
of emitted instructions up to the first trap/return reproduces return **11**
before I/O for the previous code and reaches syscall **20**, capacity **1024**,
for the corrected code. It does not emulate Fabric authority and is not guest
acceptance. Native HTTP checks cover exact 200/404, binary headers, truncated
input, 1024/1025-byte boundaries, empty input and a repeated request.

The HTTP Kleis gate adds the exhaustive four Boolean input combinations for
scalar bitwise conjunction, fresh/EOF/full loop witnesses and hostile opposites.
The initial quantified encoding returned unknown; the equivalent finite
Boolean truth table is used explicitly rather than treating unknown as a pass.
The resulting gate passes **34 positive / 21 explicitly disproved hostile
witnesses**. Rust and the protected guest link/run must still be rerun locally. The broader
Phase 10.8 network closure conditions above remain unchanged.
