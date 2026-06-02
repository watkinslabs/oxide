# Session hand-off

## Headline
main @ 0457b3b1. Both arches boot to `oxide login:` with **netlink rtnl
fully working** (loopback comes up — no deferral). This session landed
PRs #1508 (dentry mounts + openat + clock) and #1510 (netlink reply-pid
fix). One pre-existing follow-up open: PID1 "Looping too fast" epoll spin.

## Netlink rtnl — FIXED (#1510)
Root cause (proven, NOT clock/scheduler): SETLINK ack arrives 2 ms after
send + consumed, but systemd sd-netlink DROPS any non-broadcast reply
whose `nlmsg_pid != socket nl_pid` (netlink-socket.c parse_message_one
:307). We echoed the request pid (often 0) into replies while getsockname
returned current.tid — inconsistent → replies dropped → async RTM_SETLINK
callback never fired → loopback_setup timed out.
Fix: all three consistent on the socket's `port_id` — handle_one stamps
nlmsg_pid=port_id into every reply nlmsghdr; getsockname(fd) returns
port_id; getsockopt(SO_PROTOCOL) re-enabled (open succeeds). Verified
x86(KVM)+arm(TCG): "Failed to bring loopback … timed out" GONE, login
reached with rtnl active.

## Also landed (#1508)
- vfs: mount crossing keyed by DENTRY IDENTITY, not path string
- syscall: real openat dirfd resolution (`resolve_at`) + MS_REMOUNT-before-
  MS_BIND → machine_id_setup completes
- time: real PIT TSC calibration + LIVE rdtsc/cntvct vDSO clock (both
  arches; replaced the stale published snapshot)
- netlink real-state infra (mutable iface flags, MSG_PEEK recvmsg)

## Open follow-up — PID1 "Looping too fast" (CPU spin, pre-existing on main)
sd-event epoll never blocks because ONE fd is perpetually level-ready
POLLIN. TRACED: it's a `SockKind::UnixMsgPair` (AF_UNIX SEQPACKET
socketpair), one fd, reports POLLIN ~every scan. The read path DOES drain
it (net::sock::recvfrom → UnixMsgPair @sock.rs:963 → pair.recv pops the
same ring has_msg checks). So cause is (a) continuous traffic, or (b)
systemd doesn't read THAT fd. Lead: `sys_recvmsg` (net.rs:622-625)
special-cases UnixDgram + Unix-stream but NOT UnixMsgPair — it falls
through to the recvfrom loop that does NOT fill the returned msghdr
(msg_flags/MSG_EOR/controllen). If systemd's recvmsg on its SEQPACKET
socketpair needs those, its handler may not treat the read as consumed.
Next: add a proper recvmsg_unix_msgpair (mirror recvmsg_unix_dgram in
unix_cmsg.rs / recvmsg_unix_stream in cmsg_parse.rs) that drains AND fills
the msghdr; wire into sys_recvmsg's special-cases. Login is reached
regardless — CPU-efficiency, not a blocker.

## Harness notes
- KVM (~1min): `OXIDE_QEMU_KVM=1 make SMP=2 qemu-x86`. Default TCG ~10-15min.
  arm is TCG-only, boots clean to login (~14s startup).
- Free :2222 first: `ss -ltnp|grep 2222 → kill -9 <pid>` (comm truncated to
  "qemu-system-x86"; pgrep -x misses it — kill the pid from ss).
- Run boots ALONE in background; spec-lint clean before commit.
