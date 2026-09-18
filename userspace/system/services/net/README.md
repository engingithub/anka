# /system/services/net

Home of the user-space networking stack.

Implemented progression:

- `ethernet.c` — Phase 9.4a: finite NIC RX, Ethernet length validation, EtherType extraction and dispatch
- `arp.c` — Phase 9.4b: Ethernet/IPv4 ARP validation plus authorized local reply TX
- `ipv4.c` — Phase 9.4c: fixed-IHL IPv4 validation, checksum and local protocol dispatch
- `icmp.c` — Phase 9.4c: validated ICMP echo request/reply through authorized NIC TX
- `udp.c` — Phase 9.4d: strict IPv4 UDP validation and one-shot payload reflection on development port 49152
- `tcp.c` — Phase 9.4e: single passive TCP connection with handshake, in-order ACK, and FIN close on development port 49153
- `socket.c` — Phase 9.4f: process-facing single stream socket over exact IPC + explicitly shared memory

Planned next:
- HTTP

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


## Phase 9.4c IPv4 + ICMP boundary

The first IPv4 stack accepts only version 4 with IHL 5, a contained total
length, valid 20-byte header checksum, no fragmentation, and the configured
local destination `10.0.0.2`.  Options and fragment reassembly are deferred.
`ipv4.c` exposes the generic one-shot dispatch witness; local protocol 1 is
ICMP.

`icmp.c` is independently runnable and therefore validates the small
Ethernet+IPv4 envelope it depends on before interpreting ICMP.  A reply is sent
only for checksum-valid type-8/code-0 echo requests with at least the fixed
8-byte ICMP header.  The reply uses local MAC/IP as source, the request peer as
destination, preserves identifier/sequence/payload, recomputes both ICMP and
IPv4 checksums, and leaves Ethernet padding beyond IPv4 total length untouched.
Odd-length ICMP payloads are supported by the Internet checksum implementation.

As in 9.4b, this duplicate envelope check is a temporary composition seam while
CC_B has no linker and Anka has no inter-service network startup/IPC ABI.


## Phase 9.4d UDP boundary

`udp.c` is the first transport-layer user-space witness. It accepts only the
strict Phase 9.4c IPv4 subset, protocol 17, and a UDP datagram whose length is
at least 8 bytes and exactly consumes the IPv4 payload. IPv4 UDP checksum zero
is accepted as the protocol-defined "checksum omitted" case; a supplied
checksum must validate over the IPv4 pseudo-header plus the complete UDP
datagram.

The first endpoint is deliberately a development witness, not a socket table:
UDP destination port `49152` reflects the opaque payload to the request sender.
The reply swaps UDP source/destination ports, uses local MAC/IP as source,
recomputes IPv4 and UDP checksums, resets TTL to 64, and preserves Ethernet
padding outside IPv4 total length. Anka emits a real nonzero UDP checksum even
when the IPv4 request omitted one.

As with ARP and ICMP, `udp.c` independently validates the small Ethernet/IPv4
envelope because CC_B still has no linker and Anka has no inter-service network
startup/IPC ABI. The fixed port is configuration for this executable witness;
it is not kernel policy and creates no authority.


## Phase 9.4e TCP boundary

`tcp.c` is the first persistent stateful network service. It accepts one
passive connection on development port `49153` and implements
`LISTEN -> SYN_RCVD -> ESTABLISHED -> CLOSED`. The first stack supports only
the strict fixed-header IPv4/TCP subset: data offset 5, mandatory TCP
pseudo-header checksum, exact saved peer IPv4/port tuple, exact final handshake
ACK, and in-order payload/FIN sequence numbers. TCP options, retransmission,
out-of-order queues, multiple connections, congestion control, and sockets are
deferred.

The executable witness uses deterministic local ISS `0x414e4b41`. SYN and FIN
each consume one receive sequence number; accepted data advances `RCV.NXT` by
its exact byte count. SYN-ACK and ACK replies are rebuilt as 40-byte IPv4/TCP
packets in 60-byte Ethernet frames with zero padding, preventing received data
from leaking into padding when a shorter control reply is emitted.

The service remains ordinary user-space C with explicit NIC_RX|NIC_TX and RW
DMA-buffer authority. TCP state changes protocol behavior only; it creates no
new capability or kernel authority.


## Phase 9.4f socket boundary

`socket.c` is the first process-facing network abstraction. It owns the same
strict single-connection TCP state machine and all NIC authority, but exposes
only CONNECTED, DATA(length), SEND(length), and CLOSED to one exact client
incarnation. A 1024-byte object is explicitly mapped into both domains as the
stream buffer. The ordinary client has no NIC/DMA capability and never supplies
TCP sequence or acknowledgement numbers.

The Phase 9.4f witness client is `userspace/bin/socket_echo.c`: it waits for
CONNECTED, receives four opaque stream bytes (`ping`) via DATA(4), writes
`pong` into the shared buffer, issues SEND(4), and waits for CLOSED. The socket
service alone turns those bytes into TCP and advances SND.NXT. This is the seam
the HTTP service will consume next.


## Phase 9.4g HTTP boundary

`httpd.c` is the first application-layer service using the Phase 9.4f socket
boundary. It has no NIC or DMA capability and sees only CONNECTED, DATA(n),
SEND(n), CLOSED plus the explicitly shared 1024-byte stream buffer.

The first route is intentionally small: one complete bounded
`GET /alive HTTP/1.1` request ending in `\r\n\r\n` returns a 200 response whose
body is exactly `Anka64 is alive.`. Header bytes are opaque. Other first
requests receive a bounded 404. Request reassembly across multiple socket DATA
events, pipelining, request bodies, persistent HTTP connections, TLS, and
concurrent clients are deferred.
