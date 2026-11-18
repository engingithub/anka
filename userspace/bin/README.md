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
- `storage_select.c` is the protected CC2 outbound persistence probe. Its harness
  supplies the admitted peer, frozen request and virtual NIC. It sends a Select,
  calls `sshut()`, and checks the full canonical reply through EOF. Focused runtime
  acceptance passed for both 64-byte and 4-KiB queues, including lost-reply
  recovery after reopening the file; reproduce with `bash scripts/check-anka110-guest-select.sh --real`
  from the repository root. It is not a standalone authenticated storage client.
- `storage_upload.c` is the bounded protected artifact-exchange client. A trusted
  harness supplies one exact length-prefixed request; the compiled guest sends it
  through typed sockets and checks the echoed reply through EOF. The GA110 harness
  reuses it to upload real compiler output to a file via the virtual NIC and
  guarded localhost TCP. Accepted: seven quick tests and the explicit real witness
  (85.09s), including three payload chunks and exact recovery after a lost Publish
  reply and file-service reopen. Run `bash scripts/check-anka110-guest-artifact.sh --real`;
  the script checks the quick witnesses first. Stored-image retrieval/launch is
  separate work; this probe does not confer execution authority.
- `storage_download.c` is the distinct protected AR110 read pump. It sends one
  exact 168-byte command, receives `200 + count` response bytes and waits for real
  EOF before writing the payload into its charged private report. The trusted
  Kernel adapter compares those bytes with authenticated receive custody and
  assembles contiguous ranges under one budget/deadline. Run
  `bash scripts/check-anka110-guest-download.sh --real` for the real CC2/NIC/file
  witness. Downloaded bytes remain non-executable private custody.
- `local_initialization_probe.c` exercises initialized local bytes and pointer kinds.

Some probes intentionally fault or reject malformed inputs; their Rust harnesses
supply the required authority and exact expected inputs. Running every file
without its harness is not a regression suite.

Use `anka rebuild` for the protected compiler/publication path. Use `anka dev`
for legacy CC_B monitor examples. Commands and current acceptance are recorded in
[the source-tree README](../README.md) and [DESIGN_NOTES.md](../../DESIGN_NOTES.md).
