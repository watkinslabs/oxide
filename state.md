# state - B827 classic socket-filter uaccess

Update: 2026-07-14.

## Current tree

- Worktree: `/home/nd/oxide-wt/B827-network-classic-filter-uaccess`
- Branch: `B827-network-classic-filter-uaccess`
- Base: `094dedb6` (`origin/main`, merged B826)
- Scope: import classic socket filters through fault-recoverable uaccess with Linux errno semantics.

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
