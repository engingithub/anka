# /system/services/net

Home of the user-space networking stack.

Planned progression:

- `ethernet.c`
- `arp.c`
- `ipv4.c`
- `icmp.c`
- later UDP/TCP, sockets, and HTTP

These are real Anka64 system services, not examples.  The end-to-end target is:

`GET /alive HTTP/1.1` -> `Anka64 is alive.`
