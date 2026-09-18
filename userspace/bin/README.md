# /bin

Ordinary user-invoked Anka64 programs.  Unlike `/system/services`, membership
here means "a program a user asks to run", not "part of the operating service
fabric".


Phase 9.4f adds `socket_echo.c` as the first ordinary process using the
user-space socket boundary. It deliberately has no NIC capability and sees only
shared stream bytes plus exact-peer IPC notifications.
