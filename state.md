# state.md — session hand-off

## Headline
Network Linux-compliance campaign. **20 PRs merged** (B1349-B1364 + D364/D365).
**Eight real Linux-parity bug fixes**, the ARP-TX deadlock fix (unblocked the
hosted net suite), the dual-stack demux fix, a stale-test fix, and full
differential corpora for socket rows 41-55. Main green: net 979/979 serial,
syscalls 164/164, both arch kernel builds pass.

## Added after the first tally (B1359-B1364)
- **B1359** setsockopt error precedence (short-optlen EINVAL before NULL EFAULT,
  unknown level/opt ENOPROTOOPT).
- **B1360** getsockopt unknown-LEVEL EOPNOTSUPP (non-IPv6) vs ENOPROTOOPT (v6).
- **B1362** recvmsg validates msg_namelen per `__copy_msghdr` (negative→EINVAL,
  >128 clamp) — was consuming datagrams on a negative namelen.
- **B1363** sendmsg clamps msg_namelen>128 (completes `__copy_msghdr` parity).
- **B1364** SO_RCVBUF/SO_SNDBUF value doubling + SOCK_MIN floor.
- Verified Linux-correct (no fix needed): dup2/dup3/pipe2/epoll_create1/
  timerfd_create/signalfd4 flag validation.

## Documented open (sysctl-dependent, need infra + guest — NOT safe blind)
- SO_*BUF rmem_max/wmem_max cap (Oxide has no sysctl).
- fresh-socket default SO_RCVBUF (Oxide 16384 vs Linux rmem_default*2); needs
  tcp_rmem/rmem_default sysctl owner, not a bare constant bump (would 8x
  AF_PACKET default accounting).
- sendmsg/recvmsg cmsg/SCM ancillary corpus (not yet probed).

## Real bug fixes this session
- **B1349** socket(2): unix protocol PF_UNIX, unix SOCK_RAW→SOCK_DGRAM type
  rewrite, `__sock_create` family-range-before-type order.
- **B1350** dual-stack TCP listener demux — `::` listener serves IPv4.
- **B1351** ARP-deferred TX queues (Linux `neigh_resolve_output`) instead of
  spin-waiting; had DEADLOCKED the hosted net suite (now 979/979 serial).
- **B1355** datagram/raw listen() → EOPNOTSUPP not EINVAL (`sock_no_listen`).
- **B1356** bind() per-family min addrlen (v4≥16, v6≥24), sufficient-length
  family mismatch → EAFNOSUPPORT, AF_UNSPEC v4 INADDR_ANY accept;
  length-aware `read_sockaddr_in6_len`.
- **B1359** setsockopt error precedence — short-optlen EINVAL before NULL-optval
  EFAULT, unknown level/option ENOPROTOOPT (removed a premature EFAULT guard).
- **B1360** getsockopt unknown-LEVEL → EOPNOTSUPP for non-IPv6, ENOPROTOOPT v6.
- **B1362** recvmsg validates msg_namelen per `__copy_msghdr` (negative →
  EINVAL, >128 → clamp); was consuming datagrams on a negative namelen.
- **B1357** stale `debug-syscall-return` cfg count (8→9).

## Corpora added (rows verified matching Linux)
t_socket(41), t_connect(42), t_accept(43), t_sendrecv(44/45), t_shutdown(48),
t_bind(49), t_listen(50), t_sockname(51/52), t_socketpair(53),
t_setsockopt(54), t_getsockopt(55), t_msg(46/47). All in
`userspace/glibc_conformance/`, registered in
`tools/network-conformance-manifest.tsv`.

## Method
Probe C + host oracle (`env -i PATH=/usr/bin:/bin LC_ALL=C ./bin`) → source-audit
the Oxide owner vs Linux → fix in the canonical crate → verify with
`xtask glibc-test --tests <name>` (host ABI), hosted `cargo test`, both
`xtask kernel` builds. **glibc-test runs the HOST kernel** — it proves ABI, not
Oxide-kernel logic; use source audit + hosted tests for kernel behavior.
**Always verify audit claims against the oracle** — 3 agent claims were disproven
(copyout ordering, setsockopt optlen<0-before-fd, MSG_CMSG_CLOEXEC echo).

## Known open divergences (characterized, deferred)
- **sendmsg msg_namelen > 128**: Linux clamps+sends, Oxide EINVAL. Needs a
  two-path send change (`import_name_with` + `copy_sockaddr`) + a test update +
  address-parser check on a clamped 128-byte name; risky without the guest.

## Blocker: N22 guest differential channel
`tools/oxide-conformance-ssh.sh` boots to userspace + sshd listens, but SSH
readiness fails: **intermittent virtio-net/NetworkManager interface bring-up**
(driver/boot, not net syscalls). See memory `network-differential-channel-blocker`.
Do not boot-loop it.

## Remaining network rows
16 ioctl (large, well-covered), 299/307 recvmmsg/sendmmsg (prior work + t_mmsg),
plus the sendmsg>128 clamp above. Then the broader syscall matrix
(`syscall-compliance-matrix.md`).

## First command next session (fresh main)
`git -C /home/nd/oxide/kernel pull`, then continue the source-audit+oracle method
on rows 16/299/307 or the sendmsg>128 clamp; or start the non-network syscall
matrix. `cargo test -p net --features hosted --lib -- --test-threads=1` = 979/979.
