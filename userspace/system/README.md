# /system

Source mirror for programs that form the Anka64 operating environment.

- `compiler/` contains real guest compiler, preprocessor and linker sources.
- `services/net/` contains the implemented Ethernet-through-HTTP stack and the
  accepted protected packet/TCP/socket/HTTP rebuild path.

System membership and logical names do not grant privilege. Device access,
source/tool admission, publication and execution require their explicit runtime
authorities. Original CC_B services and protected ABI-2 rebuilt applications are
separate execution profiles; neither is silently upgraded to the other.

See [compiler details](compiler/README.md), [network details](services/net/README.md)
and the [closed Phase 10.8 record](../../DESIGN_NOTES.md#dn71-status).
Current [Phase 10.10 work](../../DESIGN_NOTES.md#dn72-status) adds durable storage:
the protected upload and download probes live in `userspace/bin/`. Upload,
retrieval, fresh live launch and RR110 bounded independent restart are accepted.
RR110 reuses a persisted precompiled download pump and reconstructs fresh guest
state under current boot authority. The file service and evidence adapters are
Rust host reference components, not additional C services installed here.
General installation/enrollment and whole-machine reboot remain open.
