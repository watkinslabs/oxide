# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
x86 smoke ~16s green; arm smoke ~20s green (pre-push hook).

## What actually works (post-F156…F167)

- DHCP via udhcpc; UDP outbound + reply; AF_PACKET TX/RX
- TCP loopback + TCP outbound through slirp NAT (real 3WHS)
- TCP recv via per-conn waitq, real EOF semantics
- TCP send bounded by SO_SNDBUF, blocks via waitq when full
- TCP connect waits via waitq + SYN retransmission (RFC 6298)
- TCP data retransmission on RTO; conn aborts after max retries
- TCP accept blocks on per-listener waitq
- close()/shutdown() emit FIN; TIME_WAIT reaper (60s) cleans tcp_conns
- UDP recvfrom blocks on per-port waitq
- SO_ERROR returns real per-conn errno (ECONNREFUSED/RESET/ETIMEDOUT)
- shutdown(SHUT_RD/WR/RDWR) distinct semantics
- Write to closed TCP side → SIGPIPE + EPIPE (POSIX)
- ARM lockstep on the above

## Discipline added this session

- **R04 on docs/07§5**: no magic numbers for typed ABI constants
  (errno/signal/flag/syscall-slot). CLAUDE.md Forbidden patterns
  list updated.
- **spec-lint `code/magic-errno`**: enforces R04. Validated by
  injection — fires on `*_eno = 110;` style.
- **Typed enums introduced**: `sched::live::Signum` for per-task
  signal raise (Sigchld/Sigpipe/Sigalrm/Sigterm/Sigint/Sighup);
  retrofit zombies.rs SIGCHLD raw shifts.

## PRs shipped this session

| # | What | Why it mattered |
|---|---|---|
| 1222 | F156 TCP outbound 3WHS works | virtio-net rx_poll spinlock self-deadlock; SockKind discrimination; src-IP pick |
| 1223 | F157 TCP read Eagain (interim) | small fix to unblock the rx round-trip |
| 1224 | D38 state.md truth | killed the iretq-archaeology dead-end |
| 1225 | F158 TCP read blocking via waitq | proper Inode::read contract |
| 1226 | F159 TCP retx + connect waitq + abort | dropped SYN no longer permanent stall |
| 1227 | F160 accept blocking waitq | TCP server side |
| 1228 | F161 close hook + TIME_WAIT reaper + UDP unbind | fd leak fix |
| 1229 | F162 UDP recvfrom blocking waitq | DNS / NTP no longer busy-poll |
| 1230 | F163 SO_ERROR real per-conn errno | async-connect / EPOLLOUT path |
| 1231 | R04 docs/07: forbid magic numbers | typed-enum standardization |
| 1232 | C lint code/magic-errno | R04 enforcement |
| 1233 | F164 TCP write blocking + SO_SNDBUF | backpressure on stalled peer |
| 1234 | F165 TCP output() drains correctly | multi-segment writes; single-source retx_q |
| 1235 | F166 shutdown SHUT_* + EPIPE | POSIX semantics |
| 1236 | F167 SIGPIPE delivery + Signum | `cmd \| head` style works |

## Open next (priority order — gates for cross-compiled Linux apps)

1. **SO_RCVTIMEO / SO_SNDTIMEO honored in blocking waits**
   — read/write/connect helpers park indefinitely. Need a
   timer-wake primitive on `WaitList` (`park_with_deadline`).
   Many apps rely on bounded blocking I/O.
2. **Signal-aware blocking (-EINTR on signal)** — Ctrl-C on a
   blocked read currently hangs. Park helpers should re-check
   `sigpending` on wake and return Eintr if a non-blocked signal
   arrived.
3. **SO_REUSEADDR enforcement at bind** — without it, servers
   that restart inside the 60s TIME_WAIT window get EADDRINUSE.
4. **AF_UNIX accept / recvfrom waitqs** (currently tick_yield
   fallback). AF_PACKET same.
5. **TCP MSS negotiation** — we hardcode 1460, peer's MSS option
   in SYN/SYN-ACK ignored. Wire-correct interop with small-MTU
   networks (slirp default is 1500 → fine, but real-network
   apps may see fragments).
6. **ICMP unreach → SO_ERROR** for the offending socket. UDP
   apps rely on this to learn "no listener".
7. **TCP_NODELAY semantic** — we're effectively always-NODELAY.
   Apps relying on Nagle for small-write batching see different
   latency profile.
8. **Window scaling** + **SACK** — throughput gates on
   high-BDP / lossy links. Large.

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch; never delete branches
- spec-lint clean before every commit + PR (new rule: no magic-errno)
- Never commit directly to main
- **ARM lockstep**: every kernel-side network change verified on
  both arches via the pre-push smoke (smoke-x86 + smoke-arm)
- Use typed enums for ABI constants (Errno, Signum, OpenFlags, NR_*)

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | grep "test result" | head -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
make smoke-dhcp-x86  # quick: ~16s
```

Then attack item 1 above (SO_*TIMEO via timer-wake primitive on
WaitList) — it's the biggest remaining Linux-app gate and the
required infra (`park_with_deadline`) also unblocks item 2
(signal-aware Eintr).
