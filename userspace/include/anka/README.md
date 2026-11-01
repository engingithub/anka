# /include/anka

Location for explicit Anka64 guest-interface headers. This directory is not an
ambient include search path and has no associated runtime authority.

The include-only guest preprocessor resolves exact quoted names from the supplied
source bundle. The ordinary `anka rebuild --include FILE` command supplies each
file under its basename; callers of the source-bundle API may choose other exact
logical names. No host filesystem fallback, macros or conditional includes are
implied. CC_B itself remains a bootstrap compiler, not a header preprocessor.

The supported allocation declarations are currently in `../stdlib.h`; include
them explicitly when needed. Protected pointer and call rules are specified in
[ARCHITECTURE.md](../../../ARCHITECTURE.md), not by host C layout conventions.
