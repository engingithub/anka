# /system/services/net

Home of the user-space networking stack.

Implemented progression:

- `ethernet.c` — Phase 9.4a: finite NIC RX, Ethernet length validation, EtherType extraction and dispatch

Planned next:

- `arp.c`
- `ipv4.c`
- `icmp.c`
- later UDP/TCP, sockets, and HTTP

These are real Anka64 system services, not examples. The end-to-end target is:

`GET /alive HTTP/1.1` -> `Anka64 is alive.`

## Phase 9.4a Ethernet boundary

The first executable Ethernet service consumes one frame through `SYS_NIC_RX`.
The virtual NIC presents exactly:

`dst MAC[6] | src MAC[6] | EtherType[2] | payload`

Preamble/SFD/IFG and FCS are outside the guest-visible frame. Untagged frames
must be 14..1514 bytes. EtherType is decoded in network byte order from bytes
12 and 13. The current one-shot dispatch result is:

- `1` — ARP (`0x0806`)
- `2` — IPv4 (`0x0800`)
- `3` — structurally valid but currently unknown EtherType
- `64` — malformed Ethernet length
- `100 + status` — `SYS_NIC_RX` failed

Those exit values are an executable Phase 9.4a witness, not the eventual
inter-service IPC ABI.

CC_B currently has no preprocessor/header inclusion step, so `ethernet.c` is a
self-contained translation unit. Shared network headers should be introduced
only when the compiler/source-composition path actually supports them.

The Phase 9.4a Rust witness boots the service with an exact virtual-NIC
execution environment: a DMA buffer at virtual address `0x10000`, NIC_RX handle
`0:0`, and WRITE-buffer handle `1:0`. This is a deterministic bootstrap
convention for the current single-service witness; it is not ambient authority
and it is not derived from the logical pathname.
