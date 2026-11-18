# /etc

Reserved for future configuration payloads. There are no active configuration
files in this directory. It implies neither Unix `/etc` semantics nor automatic
filesystem access, credential discovery or runtime authority.

An installation recognizes one explicitly configured trust anchor in the Phase
10.9 model. No identity protocol or credential encoding has been selected; OIDC
is not an architectural requirement. Recognition, grants and boot admission are
separate decisions. This directory does not yet implement persistent installation
configuration or login. See [DN-72](../../DESIGN_NOTES.md#dn72-status).
