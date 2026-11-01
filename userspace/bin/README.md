# /bin

Ordinary programs and executable acceptance probes. Placement here conveys no
capabilities and does not imply a Unix process or library ABI.

- `hello.c` is a legacy development-monitor program.
- `socket_echo.c` exercises the original exact-peer IPC/shared-buffer socket ABI;
  its client has no NIC capability. It is not yet a protected CC2 socket client.
- `pointer_probe.c`, `byte_pointer_probe.c` and `protected_pointer_probe.c` exercise
  the successive protected pointer/lifetime contracts.
- `typed_input_probe.c` and `typed_output_probe.c` exercise typed byte I/O.
- `malloc_probe.c` exercises supported protected C allocation/free.
- `local_initialization_probe.c` exercises initialized local bytes and pointer kinds.

Some probes intentionally fault or reject malformed inputs; their Rust harnesses
supply the required authority and exact expected inputs. Running every file
without its harness is not a regression suite.

Use `anka rebuild` for the protected compiler/publication path. Use `anka dev`
for legacy CC_B monitor examples. Commands and current acceptance are recorded in
[the source-tree README](../README.md) and [DESIGN_NOTES.md](../../DESIGN_NOTES.md).
