# state - B825 network namespace routes

Update: 2026-07-14.

## Current tree

- Worktree: `/home/nd/oxide-wt/B825-network-netns-route-tables`
- Branch: `B825-network-netns-route-tables`
- Base: `62b47845` (`origin/main`, merged B824)
- Published branch tip: `7db08041` claim commit; implementation remains uncommitted pending final audit and lockstep verification.
- Quota and B810 mount work are already contained by merged main; B825 did not start from stale main.

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

## Verification

Passed:

```text
RUSTFLAGS='-Awarnings' cargo test -q -p net -p netlink -p procfs -p nscg -p syscalls -- --test-threads=1
net 423; netlink 59; nscg 10; procfs 44; all syscalls test binaries passed
RUSTFLAGS='-Awarnings' cargo check -q -p net -p netlink -p procfs -p nscg -p syscalls
git diff --check
```

Final dual-target builds and x86/ARM smoke remain before push.

## Honest follow-up

- Network namespace lifetime is not complete: tasks, every socket family, netlink sockets, and namespace fds still carry raw namespace ids rather than one refcounted canonical `NetNamespace`. Production cannot trigger cleanup exactly at the final owner drop. This requires the next fresh architecture branch, not an id scan or task-table heuristic.
- SIOC mutable MTU, hardware address, broadcast address, and transmit queue state remain unsupported rather than false-success; raw `rtentry` user reads still need migration to the shared fault-recoverable ABI import path.
- Existing syscall-matrix row-specific ABI, security-hook, protocol-family, and differential gaps remain `PARTIAL`.
