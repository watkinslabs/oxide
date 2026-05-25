# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
x86 smoke ~16s green; arm smoke ~20s green (pre-push hook).

## What actually works (post-F156…F175)

### TCP — wire correct
- Real 3WHS through slirp NAT; SSH banner round-trip
- Per-conn waitq for connect/recv/send; per-listener for accept
- SO_RCVTIMEO/SNDTIMEO via timer-wake scanner (F169)
- EINTR on signal (F168); SIGPIPE+EPIPE on closed-side write
- SYN + data retx with RFC 6298 RTO + abort after retries
- SO_SNDBUF cap, write-side backpressure
- output() drains correctly; single-source retx_q
- close() emits FIN; TIME_WAIT (60s) reaper
- shutdown(SHUT_RD/WR/RDWR) distinct semantics
- SO_ERROR per-conn (RST → ECONNREFUSED/RESET; retry → ETIMEDOUT)
- **MSS negotiation** (F173) — peer's MSS option latched, min applied
- **Nagle / TCP_NODELAY** (F175) — default-on coalescing, ACK-drains
- **ICMP unreach → SO_ERROR** (F174) — abort + surface eno

### UDP — wire correct
- recvfrom blocks on per-port waitq with SO_RCVTIMEO
- UDP port released on close
- ICMP unreach → per-port error_eno, consumed by next recv / SO_ERROR

### AF_UNIX — per-pair waitqs
- accept blocks on UnixListener.accept_waiters (F170)
- read blocks on per-direction waitq for UnixPair/UnixMsgPair (F171)
- UnixDgramQueue per-queue waitq (F171)

### AF_PACKET
- recvfrom blocks on per-socket recv_waiters (F172)

### Discipline
- R04 docs/07§5 rule + `code/magic-errno` lint enforces typed-enum
  ABI literals (Errno, Signum, OpenFlags, NR_*)
- sched::live::Signum + send_signal_self + wake_if_sleeping +
  deliverable_signals helpers

## PRs this session (26 total)

F156 outbound TCP · F157 read EAGAIN (interim) · D38 state ·
F158 read waitq · F159 retx + connect waitq · F160 accept ·
F161 close+TW reaper · F162 UDP recv waitq · F163 SO_ERROR ·
R04 + C lint magic-errno · F164 write+SNDBUF · F165 output()
correctness · F166 shutdown+EPIPE · F167 SIGPIPE+Signum ·
D39 state · F168 EINTR · F169 SO_*TIMEO · F170 AF_UNIX accept ·
D40 state · F171 AF_UNIX recv per-pair · F172 AF_PACKET recv ·
F173 MSS · F174 ICMP unreach · F175 Nagle

## Open next (priority order — most are perf, not correctness)

1. **SO_REUSEADDR enforcement** — currently no-op since we only
   EADDRINUSE on duplicate listener (SO_REUSEADDR doesn't relax
   that case). Once TIME_WAIT conflict matters, this lights up.
2. **ARP cache aging / timeout** — stale entries linger forever.
3. **Window scaling** — we advertise + ignore window=65535 fixed.
   Throughput cap on high-BDP links.
4. **SACK** — limits recovery on lossy links.
5. **Real IPv6 transport** — `family=AF_INET6` accepted but
   V4-mapped only.
6. **Per-fd targeted epoll wakes** — `notify_epoll_waiters`
   still wakes every epoll'd fd on every socket event.
7. **TCP timestamps option (RFC 7323)** — better RTT samples,
   PAWS protection.
8. **Cross-build distro programs** — toolchain integration to
   actually run /bin/bash, /usr/bin/curl etc. as smoke targets.

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

Pick item 8 (cross-build a real distro program — bash/curl/ssh
as a smoke target) — that's the biggest "do Linux apps actually
work" delta now that the network stack itself is wire-correct.
Items 1-7 are perf/edge cases; the cross-build proves the suite
end-to-end.
