# state — hand-off

Branch: main (clean). spec-lint clean, 1179 hosted tests pass,
x86 smoke ~16s green; arm smoke ~20s green (pre-push hook).

## What actually works (post-F156…F183)

### TCP — RFC-conformant on the common paths
- Real 3WHS through slirp NAT
- Per-conn waitqs (connect/recv/send) + per-listener (accept)
- SO_RCVTIMEO/SNDTIMEO via timer-wake; EINTR on signal
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
- **OOO receive buffer** (F179)
- **SACK option emit/consume + skip-sacked retx** (F179a, RFC 2018)
- **Timestamps + PAWS** (F182, RFC 7323) — every segment carries
  TSopt when negotiated; PAWS drops stale TSvals (seq-wrap
  protection); ts_recent tracked per-conn

### UDP / AF_UNIX / AF_PACKET
- UDP recvfrom per-port waitq; ICMP unreach → error_eno
- AF_UNIX accept + per-pair recv waitqs (F170, F171)
- AF_PACKET recvfrom per-socket waitq (F172)

### ARP
- Per-entry timestamp + 60s stale GC (F177, Linux gc_stale_time)

### Tests
- **F183**: 14 hosted regression tests covering MSS/WSCALE/OOO/
  ARP-age/SO_REUSEADDR/SO_SNDBUF/multi-segment-output
- **F179a**: 5 hosted tests for SACK block coalesce + apply + skip
- **F182**: 6 hosted tests for TS negotiation + PAWS drop/accept
- Total: 1179 hosted tests (was 1151 pre-session, +28 net-specific)
- Catches regressions at hosted-test time — no QEMU boot needed
  to validate

### Discipline
- R04 docs/07§5 + `code/magic-errno` lint enforce typed-enum ABI
  literals (Errno, Signum, OpenFlags, NR_*)
- sched::live::Signum + send_signal_self + wake_if_sleeping +
  deliverable_signals
- Pre-push hook gates ARM lockstep (both smokes must pass)

## This session's PRs (37 total: F156…F183 + F179a + F182 + 5× state)

Core network correctness: F156-F179 (16 PRs)
Tier-2 correctness: F176 SO_REUSEADDR · F177 ARP age ·
F178 wscale · F179 OOO recv · F179a SACK ·
F182 timestamps+PAWS
Hosted tests: F183 (regression suite)
Spec/lint: R04 + `code/magic-errno` enforcement
State updates: D38, D39, D40, D41, D42, D43

## Open next

### Deferred — explicitly out of scope for this session

1. **F180 IPv6 real transport** — minimum viable is ~500 LoC
   (parse + ICMPv6 echo + demux); full RFC support (NDP cache,
   SLAAC, RA, dual-stack listeners) is ~2000 LoC. Real project,
   not a single PR. Not gated for IPv4-only Linux apps.
2. **F181 Per-fd targeted epoll wake** — current global
   `notify_epoll_waiters` IS correct (level-triggered
   semantic); per-fd subscriber map is a perf win when many
   epoll'd fds + many epollers coexist. v1 has 1-2 epolls in
   practice. Inode-trait change required; modest refactor.

### Tier 3 (perf / features)

3. Real per-iface MTU lookup for OWN_MSS (currently 1460 fixed).
4. Recv-buf autotune + OWN_WSCALE > 0 for high-BDP.
5. Congestion control (Reno → CUBIC).
6. TCP keepalive (SO_KEEPALIVE round-tripped, not honored).

### The real proof

7. **Cross-build a real distro program** (bash / curl / ssh / nginx)
   as a smoke target. Stack is now RFC-conformant across the
   common Linux-app paths — the only validation that matters
   end-to-end is running something real against it.

## Discipline notes

- Pre-push hook gates kernel-surface pushes: `git config core.hooksPath .githooks`
- Never rebase a published branch; never delete branches
- spec-lint clean before every commit + PR (incl. magic-errno)
- Never commit directly to main
- ARM lockstep via pre-push (smoke-x86 + smoke-arm)
- Use typed enums for ABI constants (Errno, Signum, OpenFlags, NR_*)
- **Every new correctness fix lands with hosted tests** (F183 pattern)

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | grep "test result" | head -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
make smoke-dhcp-x86  # quick: ~16s
```

Either tackle cross-build (the proof), F180 IPv6 (multi-session
project), or F181 epoll refactor (perf with modest refactor).
The correctness tier is closed.
