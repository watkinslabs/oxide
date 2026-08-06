# FUSE ABI target

Audit date: 2026-08-05.

Oxide targets the Linux FUSE wire ABI **7.45**. The major is 7; there is no
Linux FUSE ABI 8 in the audited UAPI. `proto::FUSE_KERNEL_VERSION` and
`proto::FUSE_KERNEL_MINOR_VERSION` are the executable source of truth and the
codec test pins them to `(7, 45)`.

The version number describes the wire dialect, not a promise that every
optional opcode or INIT capability is implemented. Oxide advertises only the
capability bits it consumes. A daemon using major 7 and a lower minor is
negotiated down to that minor. A different major is rejected.

## Locked wire rules

- INIT uses the 64-byte extended `fuse_init_in` introduced in 7.36 and sets
  `FUSE_INIT_EXT`; advertising 7.45 with the old 16-byte request is forbidden.
- INIT replies use the 64-byte 7.45 layout. Fields Oxide does not negotiate are
  decoded as reserved/zero and must not affect behavior.
- Every request/reply structure Oxide emits or consumes has one named size
  constant and a byte-roundtrip test.
- Mount options are parsed once by `FuseContextOps`. `fd=` is pinned and
  validated during parameter parsing; `get_tree` consumes the typed state.

## Change gate

Changing the advertised minor requires one change set that:

1. audits every intervening Linux UAPI changelog entry and changed structure;
2. updates the affected codecs, sizes, flags, and negotiation behavior;
3. updates the pinned-version and byte-layout tests;
4. runs the hosted FUSE suite plus live libfuse mount/read probes on x86_64 and
   aarch64; and
5. updates this file in the same commit.

Do not raise the version merely because a newer header exists, and do not add a
new optional capability bit until the operation it enables is implemented and
tested end to end.
