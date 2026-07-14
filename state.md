# state - B831 raw and packet socket semantics

Update: 2026-07-14.

## Current tree

- Worktree: `/home/nd/oxide-wt/B831-network-raw-packet-socket-semantics`
- Branch: `B831-network-raw-packet-socket-semantics`
- Base: `478bc037` (`origin/main`, merged B830)
- Scope: replace raw-IP UDP-shell behavior and complete raw/AF_PACKET receive,
  capability, namespace, and socket-filter semantics.

## B830 publication

- PR: `#3090`, merged as `478bc037` on 2026-07-14.
- Hosted net suite: 431 passed; classic-BPF verifier suite: 5 passed.
- x86 and ARM target builds passed; both smoke boots reached `basic.target`.

## B830 implemented

- TCP classic-filter attachment uses network-namespace-owner `CAP_NET_ADMIN`;
  eBPF fd attachment remains unprivileged as on Linux.
- Attach, detach, and lock operations follow Linux uaccess, lock, and errno
  precedence. Filter locking is irreversible and passive children inherit the
  listener's final attachment and lock state after handshake completion.
- Classic BPF rejects uninitialized scratch loads and unknown negative packet
  offsets while supporting Linux `SKF_AD_*` ancillary loads.
- UDP and TCP filters receive protocol, ingress interface, hardware type,
  payload offset, CPU, and random metadata. Filter runners and netfilter hooks
  are installed in production initialization, not debug-only boot code.
- TCP filters execute before transport state processing. Positive verdicts trim
  payload without invalidating the already-validated checksum; partial ACKs
  trim retransmit entries, and retransmit checksums include payload bytes.

## B830 verification

- `cargo test -p net --lib`: 431 passed.
- `cargo test -p security socket_filter --lib`: 5 passed.
- `cargo check -p syscalls`: passed.
- `make x86` and `make arm`: passed.
- Focused socket-filter suite: 4 passed, including final-ACK inheritance and
  partial-payload retransmission progress.

## B829 publication

- PR: `#3089`, merged as `0f400b2b` on 2026-07-14.
- Hosted net suite: 427 passed; independent Linux/glibc semantic review clean.
- x86 and ARM target checks and smoke passed.

## B828 publication

- PR: `#3088`, merged as `9259ac24` on 2026-07-14.
- Hosted net suite: 427 passed.
- x86 and ARM target checks and smoke passed.

## B827 publication

- PR: `#3087`, merged as `7bef233a` on 2026-07-14.
- x86 and ARM target checks and smoke passed.

## B826 publication

- PR: `#3086`, merged as `094dedb6` on 2026-07-14.
- Hosted net suite: 425 passed.
- x86 and ARM smoke reached `basic.target`.

## B825 implemented

- One canonical global `NetStack`; rtnetlink no longer owns a shadow route table.
- IPv4/IPv6 routes, policy rules, interfaces, addresses, INET transport state, multicast state, fragments, diagnostics, procfs views, and notifications are network-namespace scoped.
- Netlink route/link/address/rule operations and inet-diag use the socket-captured namespace; rtnetlink multicast is filtered by listener namespace.
- `/proc/net/{dev,route,tcp,tcp6,udp,udp6,unix,arp,if_inet6,snmp}` captures an immutable namespace-relative snapshot at open.
- IPv4 route lookup honors longest prefix, metric, weighted ECMP, exact next hop, terminal route errors, and `RTN_THROW` policy continuation.
- Virtio-net consumes the route-selected IPv4/IPv6 next hop instead of performing a second FIB lookup.
- `RTM_NEWROUTE` implements atomic create/exclusive/replace/append groups, strict route parsing, weighted multipath, terminal route types, and namespace-owned output-interface validation; `RTM_DELROUTE` supports selector deletion without mandatory OIF.
- SIOC route mutation validates Linux `rtentry`, resolves devices in the socket namespace, uses canonical route mutation, and reports collision/miss errors. SIOC mutation requires owner-user-namespace `CAP_NET_ADMIN` and a supported socket fd.
- Combined `CLONE_NEWUSER|CLONE_NEWNET` establishes the user namespace before recording network-namespace ownership.
- Namespace cleanup primitives remove interfaces, addresses, FIB/rules, neighbors, multicast, fragments, and INET transport state.

## B825 publication

- Implementation commit: `071e0f35`.
- PR: `#3085`, merged as `4505f665` on 2026-07-14.
- `main` and `origin/main` both advanced to the merge commit before B826 was created.

## B825 verification

Passed:

```text
RUSTFLAGS='-Awarnings' cargo test -q -p net -p netlink -p procfs -p nscg -p syscalls -- --test-threads=1
net 423; netlink 59; nscg 10; procfs 44; all syscalls test binaries passed
RUSTFLAGS='-Awarnings' cargo check -q -p net -p netlink -p procfs -p nscg -p syscalls
git diff --check
```

- x86 smoke reached login in 42 seconds.
- ARM smoke reached login in 79 seconds.

## Honest follow-up

- Network namespace lifetime is not complete: tasks, every socket family, netlink sockets, and namespace fds still carry raw namespace ids rather than one refcounted canonical `NetNamespace`. Production cannot trigger cleanup exactly at the final owner drop. This requires the next fresh architecture branch, not an id scan or task-table heuristic.
- SIOC mutable MTU, hardware address, broadcast address, and transmit queue state remain unsupported rather than false-success; raw `rtentry` user reads still need migration to the shared fault-recoverable ABI import path.
- Existing syscall-matrix row-specific ABI, security-hook, protocol-family, and differential gaps remain `PARTIAL`.
