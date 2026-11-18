# /system/services

Operating services composed through explicit process/domain, IPC, memory and
device authority. The current service sources are in [net/](net/README.md).

Both the legacy stack and the bounded protected CC2 path have returned the
`/alive` response through the virtual NIC. On the protected path HTTP uses
typed socket I/O; the driver owns the NIC capability. Both the legacy and protected UDP reflectors passed the same 17 wire cases.

Each service profile must state its input custody, resource bounds, peer lifetime,
failure cleanup and backing-reuse rules. Changes to these contracts require the
affected Kleis gates before implementation. Current evidence is centralized in
[DN-71](../../../DESIGN_NOTES.md#dn71-status).

Phase 10.10's file-backed persistence service and authority adapters currently run
as Rust host reference components. The CC2 guest Select and artifact-upload probes
in `userspace/bin/` use the bounded outbound virtual-NIC path; GA110 upload and
lost-reply recovery are accepted. This does not install a general remote filesystem
or authenticate external HTTP requesters. See [DN-72](../../../DESIGN_NOTES.md#dn72-status).
