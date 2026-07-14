# state - B832 real raw IP sockets

Update: 2026-07-14.

## Current lane

- Worktree: `/home/nd/oxide-wt/B832-network-raw-ip-sockets`
- Branch: `B832-network-raw-ip-sockets`
- Draft PR: `#3093`
- Tracker: `network-plan.md` N01; N02 starts only after N01 merge.

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

## Remaining N01 closure

- Commit and push the ancillary tranche.
- Refresh against `origin/main`, mark PR #3093 ready, and pass PR checks.
- Run required dual-architecture smoke, merge, update main, and clean worktree.
- Record merged N01 evidence, then create the N02 branch.

## First resume command

`cd /home/nd/oxide-wt/B832-network-raw-ip-sockets && git status --short && gh pr view 3093 --json isDraft,mergeStateStatus,statusCheckRollup,url`
