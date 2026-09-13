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

Old-style harnesses (`run_6b4_harness`, `run_ccb_harness`) remain for
testing the compiler pipeline.  They will be retired in Phase 8.6 when
the boot contract replaces all direct-construction test paths.

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
