# Design Notes

Architectural decisions, alternatives considered, rejected assumptions,
deferred changes, and reasoning about why we chose not to act.

See `ARCHITECTURE.md` for the authoritative current architecture, rules,
milestones, and implementation facts.

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
same rule that governed the 9.2c/OIDC exact-presented-authority design.

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
