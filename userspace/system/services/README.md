# /system/services

Operating services composed through explicit process/domain, IPC, memory and
device authority. The current service sources are in [net/](net/README.md).

Both the legacy stack and the bounded protected CC2 path have returned the
`/alive` response through the virtual NIC. On the protected path HTTP uses
typed socket I/O; the driver owns the NIC capability. Both the legacy and protected UDP reflectors passed the same 17 wire cases.

Each service profile must state its input custody, resource bounds, peer lifetime,
failure cleanup and backing-reuse rules. Changes to these contracts require the
affected Kleis gates before implementation. Current evidence is centralized in
[DESIGN_NOTES.md](../../../DESIGN_NOTES.md#dn-71).
