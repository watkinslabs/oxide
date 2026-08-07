# state.md — B1916 handoff

Branch: `B1916-netlink-remaining-socket-flags`.
Committed checkpoint: `f43bb83df netlink: wire namespace multicast flags`.
No B1916 PR, push, or merge exists.

## Feature state

- `RTM_NEWNSID` now accepts FD or PID peer references; `RTM_GETNSID` accepts
  FD, PID, caller-local NSID, and target-NSID forms. Target lookup enforces
  `CAP_NET_ADMIN` in the target namespace owner.
- Namespace-ID parser errors retain rejected attribute offsets. The live
  handler emits `NLMSGERR_ATTR_OFFS`; ACK shaping retains that TLV only with
  `NETLINK_EXT_ACK` enabled.
- `NetworkNamespace::peer_by_id` is the canonical reverse lookup.

`RTM_GETNSID` emits multipart dumps from the canonical peer-ID map. Linux has
no `RTM_DELNSID` handler, so none was added. LISTEN_ALL_NSID checks the socket
opener's retained `CAP_NET_BROADCAST` snapshot against the source namespace.

## Verification

- `cargo test -q -p network-namespace -- --nocapture` — 4 passed.
- `cargo test -q -p netlink -- --nocapture` — 275 passed.
- `cargo run -q -p xtask -- kernel --arch x86_64 --check` — passed.
- `cargo run -q -p xtask -- kernel --arch aarch64 --check` — passed.
- `make smoke` — x86 passed in 52 s; arm passed in 108 s.

First command: `git status --short --branch`
