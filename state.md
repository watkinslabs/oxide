# state - network completion

Update: 2026-07-14.

## Current lane

- `main`: `9dda60c2`, synchronized with `origin/main`.
- N01 merged in PR #3093; branch and worktree deleted.
- N01 closure tracking merged in PR #3094.
- N02 multicast robustness accounting merged in PR #3095 at `85be212d`.
- B834 uses the GNU aarch64 target for reproducible vDSO generation.
- B835 adds strict per-architecture vDSO ABI validation.
- N03.1 canonical network-namespace owner foundation is the next network lane.

## Implemented

- Socket-owned raw4/raw6 namespace tables, demux, reassembly, filtering,
  queues, poll, shutdown, close, bind/connect, diagnostics, and errors.
- Linux-shaped raw4/raw6 transmit, PMTU, fragmentation, caller headers,
  multicast policy, checksums, options, receive accounting, and error queues.
- Raw `sendmsg` IPv4/IPv6 ancillary parsing and immutable per-message controls,
  including source routing, extension headers, interface overrides, flags,
  capability checks, and Linux error/length precedence.
- Review corrections cover conflicting fragment queues, receive lost wakeups,
  IPv4 option compilation, source-route wire destinations, direct on-link
  `MSG_DONTROUTE`, weak-host source selection, IPv6 fragment-zero completeness,
  arbitrary-protocol fragmentation, and 65,535-byte payload enforcement.

## Verification

- Full hosted: net 484, procfs 46, syscalls 53; zero failures.
- Focused: raw4 controls 7, raw6 transmit 11, raw cmsg parser 5.
- `cargo check -p net -p procfs -p syscalls`: passed.
- `make x86`: passed.
- `make arm`: passed.
- `git diff --check`: passed; changed Rust files remain below 500 lines.
- N02 hosted network suite: 497 passed, zero failures.
- N02 focused ordering/lifecycle races: 9 passed; learned QRV exhaustion: 2 passed.
- N02 `cargo check -p net -p procfs -p syscalls`: passed.
- N02 `make x86`: passed.
- B834 vDSO ELF/type/export checks: passed.
- B834 `make x86` and `make arm`: passed.
- B835 exact versioned-export, ELF layout, relocation, and tool-isolation
  checks: passed.
- B835 hosted HAL tests: shared 12, ARM 47, x86 74; zero failures.
- B835 `make x86` and `make arm`: passed.

## Remaining network work

- N03 through N22 remain in `network-plan.md`.
- Integrated ARM smoke remains blocked by unrelated glibc-service traps and
  the `upower.service` restart loop captured in `/tmp/B832-smoke-arm.log`.

## First resume command

`cd /home/nd/oxide/kernel && git pull --ff-only && rg -n 'N03' network-plan.md`
