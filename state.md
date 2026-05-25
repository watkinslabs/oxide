# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
x86 smoke ~16s green; arm smoke ~20s green (pre-push hook).

## What actually works (post-F156…F170)

### TCP
- Real 3WHS through slirp NAT; SSH banner round-trip
- Per-conn waitq for connect/recv/send with SO_RCVTIMEO/SNDTIMEO
  timer-wake (F169) and EINTR on signal (F168)
- SYN + data retransmission with RFC 6298 RTO (F159)
- Conn abort after 6 SYN retries / 15 data retries → ETIMEDOUT
- SO_SNDBUF cap honored; write_blocking + write_nonblock (F164)
- output() drains correctly; retx_q single source of truth (F165)
- close() emits FIN; TIME_WAIT (60s) reaper (F161)
- shutdown(SHUT_RD/WR/RDWR) distinct semantics (F166)
- EPIPE + SIGPIPE on write to closing/closed side (F166/F167)
- SO_ERROR returns real per-conn errno (F163)

### UDP / AF_UNIX / AF_PACKET
- UDP recvfrom blocks on per-port waitq (F162)
- AF_UNIX accept blocks on per-listener waitq (F170)
- AF_PACKET recvfrom + AF_UNIX recv still on global epoll-wake
  / tick_yield fallback (separate PRs)

### Discipline / lint
- R04 docs/07§5: no magic numbers for typed ABI constants
- `code/magic-errno` lint enforces R04 (validated by injection)
- `sched::live::Signum` typed enum + `send_signal_self` /
  `wake_if_sleeping` / `deliverable_signals` helpers

## PRs this session (19 total)

| # | What | Headline |
|---|---|---|
| 1222 | F156 TCP outbound | virtio-net spinlock self-deadlock fix |
| 1223 | F157 read Eagain | interim |
| 1224 | D38 | state truth |
| 1225 | F158 read blocking waitq | proper Inode::read contract |
| 1226 | F159 retx + connect waitq | SYN/data RTO + abort |
| 1227 | F160 accept blocking | TCP listener waitq |
| 1228 | F161 close + TW reaper | FIN + cleanup |
| 1229 | F162 UDP recvfrom waitq | DNS no longer busy-poll |
| 1230 | F163 SO_ERROR | real per-conn errno |
| 1231 | R04 spec | no-magic-numbers rule |
| 1232 | C lint | R04 enforcement |
| 1233 | F164 write blocking + SO_SNDBUF | backpressure |
| 1234 | F165 output() correctness | multi-segment + single-source retx |
| 1235 | F166 shutdown + EPIPE | POSIX semantics |
| 1236 | F167 SIGPIPE + Signum | `cmd \| head` works |
| 1237 | D39 | state mid-session |
| 1238 | F168 EINTR | signal-aware blocking |
| 1239 | F169 SO_*TIMEO | timer-wake infra |
| 1240 | F170 AF_UNIX accept | per-listener waitq |

## Open next (Tier 2 — degraded behavior without)

1. **AF_UNIX recv per-pair waitq** — UnixPair/UnixMsgPair/UnixDgramQueue
   still use the global epoll-wake. Per-pair waitqs avoid waking
   every epoll'd fd on every Unix-socket activity.
2. **AF_PACKET recvfrom waitq** — dhcpcd / wireshark-style apps.
3. **TCP MSS negotiation** — we hardcode 1460; ignore peer's
   MSS option in SYN/SYN-ACK. OK on slirp (MTU 1500); breaks
   on real-network apps over tunnels.
4. **ICMP unreach → SO_ERROR on UDP** — apps learn "no listener".
5. **SO_REUSEADDR enforcement** — once we have richer bind
   conflicts (we currently only EADDRINUSE on duplicate listener,
   which SO_REUSEADDR doesn't actually relax).
6. **ARP cache aging / timeout** — stale entries.
7. **TCP_NODELAY semantic** — we're effectively always-NODELAY;
   no Nagle small-write coalescing.
8. **Window scaling + SACK** — throughput on high-BDP / lossy
   links.
9. **IPv6 real transport** — `family = AF_INET6` accepted but
   V4-mapped only.
10. **Per-fd targeted epoll wakes** — global notify_epoll_waiters
    wakes every epoll on every socket event.

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

Pick item 1 (AF_UNIX recv waitqs) or item 4 (ICMP unreach →
SO_ERROR). Both are tractable. After those, the remaining list
is performance work (MSS / window / SACK / IPv6) that's lower
priority for "cross-compile Linux apps and they work right".
