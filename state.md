# state.md — session hand-off

## Headline
Network Linux-compliance campaign (scratch/network-plan.md). Nine PRs merged this
session: three REAL bug fixes + one deadlock fix + five regression corpora. Every
network socket row 41-53 now has a `t_*` differential corpus and confirmed parity.

## Merged this session (all on main)
Real fixes:
- **B1349** socket(2): unix protocol PF_UNIX, unix SOCK_RAW→SOCK_DGRAM type
  rewrite, `__sock_create` family-range-before-type check order.
- **B1350** dual-stack TCP listener demux — a `::`-bound listener now serves IPv4
  (Linux `__inet_lookup_listener` shares the IPv4 hash).
- **B1351** ARP-deferred TX queues instead of spin-waiting (Linux
  `neigh_resolve_output`). This had DEADLOCKED the whole hosted net suite; it now
  runs to completion (979/979 serial). Also an unbounded kernel spin removed.
- **B1355** datagram/raw listen() → EOPNOTSUPP not EINVAL (`sock_no_listen`).
- **B1356** bind() per-family min addrlen (v4≥16, v6≥24), sufficient-length family
  mismatch → EAFNOSUPPORT, AF_UNSPEC v4 INADDR_ANY accept; length-aware
  `read_sockaddr_in6_len` (fixes latent connect over-strictness too).
- **B1357** stale syscalls test count (debug-syscall-return cfg 8→9). syscalls 161/161.

Corpora (rows confirmed already Linux-correct by source audit):
- **B1352** t_sockname (51/52), **B1354** t_connect (42), **B1358** t_accept (43) +
  t_socketpair (53).

## Method (differential channel is blocked — see below)
Write probe C in `userspace/glibc_conformance/`, run host oracle
(`env -i PATH=/usr/bin:/bin LC_ALL=C ./bin`), source-audit the Oxide owner vs
Linux, fix in the canonical crate, verify: `xtask glibc-test --tests <name>`
(host-oracle vs Oxide-sysroot ABI), hosted `cargo test -p net --features hosted`
for net-crate logic, both `xtask kernel` builds. Register in
`tools/network-conformance-manifest.tsv`. NB: glibc-test runs on the HOST kernel,
so it proves ABI, not Oxide-kernel logic — use source audit + hosted tests for
kernel behavior. VERIFY audit claims against the oracle (one audit claim about
copyout ordering was DISPROVEN by an mmap EFAULT probe).

## Blocker: N22 guest differential channel
`tools/oxide-conformance-ssh.sh` boots to userspace + sshd listens, but SSH
readiness fails: **intermittent virtio-net / NetworkManager interface bring-up**
(pcap: some boots the guest answers ARP + gets 10.0.2.15, others no ARP at all).
Driver/boot integration, NOT net syscalls. Do not boot-loop it. See memory
`network-differential-channel-blocker`.

## Open network rows (next work)
44 sendto, 45 recvfrom, 46 sendmsg, 47 recvmsg, 54 setsockopt, 55 getsockopt,
16 ioctl, 288 accept4, 299 recvmmsg, 307 sendmmsg. A source audit of 44/45/54/55
was in flight at session end.

## First command next session (fresh main)
`git -C /home/nd/oxide/kernel pull` then continue rows 44/45/54/55 via the method
above; check the audit output and fix any real divergences it named first.
