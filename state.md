# state - network completion

Update: 2026-07-14.

## Current lane

- `main`: `4d08b5a1`, synchronized with `origin/main`.
- N01 merged in PR #3093; branch and worktree deleted.
- Next item: N02 multicast robustness accounting, currently unclaimed.

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

## Remaining network work

- N02 through N22 remain in `network-plan.md`.
- N02 must preserve successful membership across report-output failure and
  consume a bounded Linux robustness count without retry-forever behavior.
- Integrated ARM smoke remains blocked by unrelated glibc-service traps and
  the `upower.service` restart loop captured in `/tmp/B832-smoke-arm.log`.

## First resume command

`cd /home/nd/oxide/kernel && git pull --ff-only && rg -n "N02|robust" network-plan.md crates/kernel/net/src`
