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

### Hostile suite (14 tests)

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
  13. Direct delivery: full ABI (R1=2, cap handle, sender ProcessKey, mailbox unchanged).
  14. Fabric derive rejects presented/backing object mismatch.

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

715/715 tests; 29 instructions.  Phase 9.3a is complete.
