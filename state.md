# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
both arches build, x86 smoke 14s + arm smoke 20s green.

## Session tally (PRs #1191–#1192)

| PR    | What |
|-------|------|
| F131  | AF_PACKET / PF_PACKET SOCK_RAW: socket() admit + bind() (sockaddr_ll) + sendto() (push raw L2 frame through NetDev::xmit). Adds SockKind::Packet variant + InetSocket::new_packet. Moves sys_sendmmsg/sys_recvmmsg to mmsg.rs to honour 1000-line cap. |
| F132  | netlink-fd shims for bind/setsockopt/getsockname/sendto/recvfrom (route through NetlinkSocket::read/write). New kernel/src/syscalls/netlink_fd.rs. Plus AF_UNIX socket-path chmod tolerance — dhcpcd's bind→chmod(/var/run/dhcpcd/...) now succeeds (UnixRegistry consulted before resolve_path_inode). |

## dhcpcd progress (cumulative)

| Stage | Status |
|-------|--------|
| double-fork daemon | B47 fixed (no 0x40935a #GP, no SIGCHLD-handler leak) |
| /var/db/dhcpcd, /var/run/dhcpcd | B47 mkdir whitelist works |
| control_open (AF_UNIX) | B48 ECONNREFUSED works |
| control_start (bind + chmod + listen) | F132 chmod tolerance works |
| SIOCGIFFLAGS/SIOCGIFINDEX/etc | B48 ioctls work |
| netlink bind/getsockname/setsockopt | F132 works |
| socket(AF_PACKET, SOCK_RAW, ETH_P_ALL) | F131 works |
| bind(AF_PACKET, sockaddr_ll, ...) | F131 works |
| sendto(AF_PACKET, L2_frame) | F131 frame reaches NetDev::xmit |
| **if_discover: Not a socket (ENOTSOCK)** | **NEW BLOCKER** — somewhere in dhcpcd's iface-discovery loop a syscall still returns ENOTSOCK; not yet traced to a specific call (debug-syscall log shows the exit path but not the failing call mid-loop). |
| **DHCPDISCOVER on the wire** | **not yet — virtio-net rx-deliver path also unwired** |

## Open next (priority order)

1. **Trace the if_discover ENOTSOCK** — instrument errno-return sites
   or wrap getifaddrs to identify which musl/netlink syscall is
   returning ENOTSOCK. Likely candidates: sendmmsg, recvmsg on
   netlink fd (not yet routed), or a getsockopt() variant.
2. **virtio-net real TX validation** — F131 routes the frame to
   `dev.xmit()`, but our virtio-net driver's tx queue path has
   never been exercised by a real frame. Boot-time smoke at
   F19-F25 only verifies device init.
3. **AF_PACKET RX delivery** — currently AF_PACKET sockets'
   rx queue stays empty. We need the virtio-net rx-ring handler
   to demux frames and deliver to bound AF_PACKET sockets.
4. **AF_UNIX socket path materialisation in tmpfs** — F132's
   chmod tolerance is a hack. Real fix: bind(AF_UNIX) creates a
   socket-type inode at the path in the parent's tmpfs.
5. **arm tickless idle** — F130's arm side busy-spins in tick_yield.
6. **K10 eBPF rest** — verifier + JIT.
7. **K13 DRM/KMS atomic modeset**.
8. **per-fd targeted epoll wakes** — global broadcast today.

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch
- Never delete branches
- spec-lint clean before every commit + PR
- Never commit directly to main

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
```

Then pick item 1 (trace if_discover ENOTSOCK). Easiest path:
add a klog inside Errno::Enotsock-returning sites (or change
the few specific socket-syscalls' error returns to log which
syscall #) and re-run dhcpcd to identify the failing call.
