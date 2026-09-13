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
