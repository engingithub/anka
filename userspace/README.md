# Anka64 userspace source tree

This host-side tree mirrors the logical namespace Anka64 is growing toward.
It is a development source/artifact store, **not** a host-filesystem mount inside
Anka and not an authority boundary.

Current logical roots are intentionally small and earned by real software:

- `system/` — operating-environment services and system programs
- `bin/` — ordinary user-invoked programs
- `lib/` — guest libraries
- `include/` — CC_B-visible guest headers
- `etc/` — future configuration payloads

We do not reproduce Unix directory structure wholesale.  New roots are added
only when Anka64 develops a concrete semantic need for them.

For C sources, the development shell maps the host-relative path to the future
logical install path by removing the `userspace/` prefix and `.c` extension:

`userspace/system/services/net/arp.c` -> `/system/services/net/arp`

The host path, logical path, and runtime `(ObjectId, Generation)` remain three
distinct identities.  Neither path grants authority.
