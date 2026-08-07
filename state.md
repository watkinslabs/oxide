# state.md — B1916 handoff

Worktree: `/home/nd/oxide/kernel-B1916`

Branch: `B1916-netlink-remaining-socket-flags`, based on `9a31b2a33`
(`origin/main` at branch creation). No B1916 commit, push, PR, or merge has
occurred. The worktree contains all changes listed below.

## Objective

Close the `NETLINK_F_EXT_ACK`, `NETLINK_F_BROADCAST_SEND_ERROR`, and
`NETLINK_F_LISTEN_ALL_NSID` row in `scratch/known_issues.md` using the
Linux-shaped owners. Do not move the row to `scratch/fixed-issues.md` until
all three behaviours are implemented and verified.

## Implemented, uncommitted

- Caller-scoped peer netns-ID map lives in `network-namespace::NetworkNamespace`
  as weak peer ownership. `assign_peer_id` rejects negative, duplicate-ID, and
  duplicate-peer assignments; `peer_id` resolves the receiver-local ID.
- `nscg::net_ns_from_fd` resolves a netns FD through the canonical nsfs inode.
- `RTM_NEWNSID` and FD-form `RTM_GETNSID` are routed through `NetlinkSocket`;
  GET replies with `RTM_NEWNSID` and `NETNSA_NSID`.
- `LISTEN_ALL_NSID` cross-netns route multicast requires a receiver-local map
  for the source, queues that ID, and recvmsg emits the `SOL_NETLINK`, type-8
  control message when the receiver enabled the option. The generic receive
  control path now accepts multiple protocol cmsgs, retaining PKTINFO too.
- `BROADCAST_SEND_ERROR` is represented by `listeners::RtnlBroadcast`:
  a full opted-in receiver records `delivery_error`; ordinary receivers do not.
  Existing notification callers still consume only the delivered count, which
  mirrors kernel-originated notification call sites that do not expose this
  result to userspace.
- ACK shaping now receives the socket's EXT_ACK flag. `nlmsg_ack_bad_attr`
  builds an `NLMSGERR_ATTR_OFFS` TLV and the shape layer retains it only when
  EXT_ACK is enabled, placing request payload before TLVs. This builder is NOT
  YET called by a parser/handler with an actual rejected attribute offset.

## Still required

1. Finish `EXT_ACK`: make request parsers return a typed error carrying the
   rejected attribute offset (and, where applicable, missing-type/message
   context); pass that context through the route handler to
   `nlmsg_ack_bad_attr`. Start with `rtnetlink/nsid_req.rs`, then use a shared
   typed result rather than a parallel socket-layer parser. Add red/green tests
   proving no TLV without the option and correct offset/type-2 TLV with it.
2. Audit `LISTEN_ALL_NSID` capability semantics for cross-namespace delivery;
   current set-time privilege is present, but delivery-time source-userns
   capability must match the reference before declaring complete.
3. Support the full RTM namespace-ID request surface (PID and target-ID forms,
   deletion/dump) or remove the claim that the FD-only route is complete. Do
   not close the known-issues row based on the FD form alone.
4. Run full B1916 verification, both target checks, and `make smoke`; then
   update ledger truth, move only completed rows to `scratch/fixed-issues.md`,
   commit, push with local-gate bypass, open PR, merge, refresh main.

## Verification already run

- `cargo test -q -p network-namespace -- --nocapture`: 4 passed.
- `cargo test -q -p nscg -- --nocapture`: 57 passed.
- `cargo test -q -p netlink -- --nocapture`: 274 passed after latest ACK work.
- `cargo test -q -p syscalls --lib -- --nocapture`: 1235 passed before the
  latest netlink-only ACK changes.
- `cargo run -q -p xtask -- kernel --arch x86_64 --check`: passed.
- `cargo run -q -p xtask -- kernel --arch aarch64 --check`: passed before the
  latest netlink-only ACK changes; rerun before finalizing.

## Current modified files

`crates/kernel/netlink/{Cargo.toml,src/genetlink/mcast.rs,src/listeners.rs,
src/netlink_socket.rs,src/netlink_socket/ack_response.rs,
src/netlink_socket/netfilter.rs,src/netlink_tests.rs,src/receive.rs,
src/rtnetlink.rs,src/rtnetlink/ack.rs,src/rtnetlink/attrs.rs,
src/rtnetlink/uapi.rs,src/rtnetlink/nsid.rs,src/rtnetlink/nsid_req.rs,
src/wire.rs}`, `crates/kernel/network-namespace/src/{lib.rs,owner.rs,
registry.rs,tests.rs}`, `crates/kernel/nscg/src/{lib.rs,proc_ns.rs}`,
`crates/kernel/syscalls/src/{recv_control.rs,recvmsg/netlink.rs,unix_recv.rs}`,
and `scratch/known_issues.md`.
