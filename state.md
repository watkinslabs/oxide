# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
x86 smoke ~16s green; arm smoke ~20s green (pre-push hook).

## What actually works (post-F156…F179)

### TCP — wire correct
- Real 3WHS through slirp NAT
- Per-conn waitqs (connect/recv/send) + per-listener (accept)
- SO_RCVTIMEO/SNDTIMEO via timer-wake scanner; EINTR on signal
- SIGPIPE + EPIPE on closed-side write; SO_ERROR per-conn errno
- SYN + data retx (RFC 6298); conn abort after retries
- SO_SNDBUF cap; write-blocking backpressure
- output() drains correctly; single-source retx_q
- close+TIME_WAIT (60s) reaper; shutdown(SHUT_RD/WR/RDWR) distinct
- **MSS negotiation** (F173)
- **TCP_NODELAY / Nagle** (F175)
- **ICMP unreach → SO_ERROR** (F174)
- **SO_REUSEADDR strict TIME_WAIT check** (F176)
- **Window scaling (RFC 7323)** + snd_wnd enforcement (F178)
- **Out-of-order receive buffer** (F179) — silent OOO drop fixed

### UDP / AF_UNIX / AF_PACKET
- UDP recvfrom per-port waitq; ICMP unreach → error_eno
- AF_UNIX accept + per-pair recv waitqs
- AF_PACKET recvfrom per-socket waitq

### ARP
- **Per-entry timestamp + 60s stale GC** (F177, Linux gc_stale_time)

### Discipline
- R04 docs/07§5 + `code/magic-errno` lint enforce typed-enum ABI
  literals (Errno, Signum, OpenFlags, NR_*)
- sched::live::Signum + send_signal_self + wake_if_sleeping +
  deliverable_signals

## This session's PRs (33 total: F156…F179 + lints + state)

F156 outbound TCP · F157 read EAGAIN (interim) · D38 state ·
F158 read waitq · F159 retx + connect waitq · F160 accept ·
F161 close+TW · F162 UDP recv waitq · F163 SO_ERROR ·
R04 + C lint · F164 write+SNDBUF · F165 output() correctness ·
F166 shutdown+EPIPE · F167 SIGPIPE+Signum · D39 state ·
F168 EINTR · F169 SO_*TIMEO · F170 AF_UNIX accept · D40 state ·
F171 AF_UNIX recv · F172 AF_PACKET recv · F173 MSS ·
F174 ICMP unreach · F175 Nagle · D41 state · F176 SO_REUSEADDR ·
F177 ARP aging · F178 window scaling · F179 OOO recv buffer

## Open next (in correctness-priority order)

### Deferred from this session (size / scope)

1. **F180 IPv6 real transport** — IPv6 header parse/emit, ICMPv6,
   NDP cache (replacing ARP), SLAAC/RA, dual-stack listeners.
   ~2000 LoC; substantial standalone effort. Not gated for
   IPv4-app cross-build.
2. **F179a SACK option emit/consume + sacked-retx skip** — RFC 2018
   §3-§5. Performance optimization on top of F179's OOO buffer
   (recovery faster post-loss). Without it: peer's RTO catches
   us up via retx, correct but slower.
3. **F181 Per-fd targeted epoll wakes** — replace global
   notify_epoll_waiters with fd→subscriber map. Needs Inode
   trait extension + epoll_ctl(ADD) bookkeeping. Perf, not
   correctness.
4. **F182 TCP timestamps + PAWS** (RFC 7323) — TSopt on every
   segment, ts_recent tracking, PAWS drop. Useful only for
   long-running (hours+) flows where seq wrap is a real hazard.
   Defer until that workload exists.

### Tier 3 (perf / edge)

5. Real per-iface MTU lookup for OWN_MSS (currently 1460 fixed).
6. Recv-buf autotune + OWN_WSCALE > 0 for high-BDP.
7. Congestion control (Reno → CUBIC).
8. TCP keepalive (SO_KEEPALIVE setsockopt is round-tripped but
   not honored).
9. Multipath / RFC 7414 misc.

### The real next step — proof

10. **Cross-build a real distro program** (bash / curl / ssh / nginx)
    as a smoke target. Network stack is wire-correct at this point;
    the only way to validate the suite end-to-end is to run something
    real against it. Toolchain work + rootfs image work — separate
    project tier from the kernel-side PRs above.

## Discipline notes

- Pre-push hook gates kernel-surface pushes: `git config core.hooksPath .githooks`
- Never rebase a published branch; never delete branches
- spec-lint clean before every commit + PR (incl. magic-errno)
- Never commit directly to main
- ARM lockstep via pre-push (smoke-x86 + smoke-arm)
- Use typed enums for ABI constants (Errno, Signum, OpenFlags, NR_*)

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | grep "test result" | head -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
make smoke-dhcp-x86  # quick: ~16s
```

Pick #10 (cross-build) or #1 (IPv6) depending on what bottleneck
matters next. The Tier-1+2 correctness work is done; further
kernel PRs are perf or features, not bugs.
