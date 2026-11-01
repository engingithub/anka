# /system

Source mirror for programs that form the Anka64 operating environment.

- `compiler/` contains real guest compiler, preprocessor and linker sources.
- `services/net/` contains the implemented Ethernet-through-HTTP stack and the
  protected HTTP application being integrated into the rebuild path.

System membership and logical names do not grant privilege. Device access,
source/tool admission, publication and execution require their explicit runtime
authorities. Original CC_B services and protected ABI-2 rebuilt applications are
separate execution profiles; neither is silently upgraded to the other.

See [compiler details](compiler/README.md), [network details](services/net/README.md)
and the current [Phase 10.8 checklist](../../DESIGN_NOTES.md#dn-71).
