# /system/services/net

Home of the user-space networking stack.

Implemented progression:

- `ethernet.c` — Phase 9.4a: finite NIC RX, Ethernet length validation, EtherType extraction and dispatch
- `arp.c` — Phase 9.4b: Ethernet/IPv4 ARP validation plus authorized local reply TX

Planned next:
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

## Phase 9.4b ARP boundary

`arp.c` is the first bidirectional user-space network service.  It consumes one
Ethernet frame through `SYS_NIC_RX`, accepts only the frozen Ethernet/IPv4 ARP
subset, and transmits a reply through `SYS_NIC_TX` only when all of these hold:

- the guest-visible Ethernet frame is 42..1514 bytes,
- EtherType is ARP (`0x0806`),
- HTYPE is Ethernet (`1`),
- PTYPE is IPv4 (`0x0800`),
- HLEN is `6` and PLEN is `4`,
- opcode is request (`1`), and
- target IPv4 is the service's configured local address.

The Phase 9.4b executable witness uses local identity
`02:00:00:00:00:02` / `10.0.0.2`.  A reply swaps peer/local identity in the ARP
payload, sets opcode `2`, addresses the Ethernet reply to the request's ARP
sender MAC, and preserves the incoming frame length (including any padding).
Incoming ARP replies and requests for another IPv4 address never trigger TX.

The one-shot result tags are:

- `1` — local request validated and one ARP reply committed through NIC TX
- `2` — valid ARP request for another IPv4 address, ignored
- `3` — supported ARP packet that is not a request, no reply
- `64` — malformed/unsupported Ethernet+ARP structure
- `100 + status` — `SYS_NIC_RX` failed
- `120 + status` — `SYS_NIC_TX` failed

For the Phase 9.4b test runtime, the empty process capability table receives one
combined NIC_RX|NIC_TX handle at `0:0` and one RW DMA-buffer handle at `1:0`.
The buffer remains mapped at virtual `0x10000`.  These are explicit bootstrap
authorities, not authority derived from `/system/services/net/arp`.

Until Anka has an inter-service IPC/startup protocol, `arp.c` validates the
small Ethernet envelope it depends on directly.  This does not move Ethernet
or ARP parsing into Rust and does not establish a second kernel protocol path.
