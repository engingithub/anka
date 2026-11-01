# /lib

Reserved for guest libraries shared by Anka64 programs. The current tree does
not install a complete libc, dynamic linker or Unix library hierarchy.

Supported `malloc/free` declarations live in `../include/stdlib.h`. Their
implementation is the compiler/runtime protected-allocation path, not a second
`lib/stdlib.h` or a host allocator linked into the guest. Do not copy that header
here to repair an include-path error: supply its correct explicit bundle name.

Reusable C modules can be compiled separately and guest-linked through the
protected rebuild service. Their interfaces must satisfy the supported scalar/
protected-pointer and module type-evidence ABI. Mutable globals and arbitrary
host ABI assumptions are not introduced by putting a source in this directory.
