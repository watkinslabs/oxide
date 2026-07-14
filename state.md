# state - B832 real raw IP sockets

Update: 2026-07-14.

## Current lane

- Worktree: `/home/nd/oxide-wt/B832-network-raw-ip-sockets`
- Branch: `B832-network-raw-ip-sockets`
- Draft PR: `#3093`
- Base: current `origin/main`; branch was 0 behind after the latest fetch.
- Tracker: `network-plan.md` N01; do not start N02 before N01 is merged.

## Committed work

- `ae9e0fab`, `29613e66`: socket-owned raw4/raw6 endpoints and syscall routing.
- `5e91a7a`, `89242256`: raw options and IPv6 transmit.
- `27e02e7a`: signed/zero raw option lengths and fault-recoverable import.
- `94c65124`: namespace diagnostics and Linux-shaped ICMP pending errors.
- `ef39e372`: explicit N01.1-N01.12 completion checklist.

## Open work

- N01.6 local/device bind validation and mapped-IPv6 rejection.
- N01.7 raw sendmsg ancillary controls and send flags.
- N01.8 Linux caller-owned IPv6 header contract.
- N01.9 route-selected connected source and IPv4 broadcast permission.
- N01.10 raw4 receive-buffer byte accounting and drops.
- N01.11 IPv6 raw UDP zero-checksum mangling.
- N01.12 shutdown versus receive-arm lost-wakeup closure.
- Final full hosted suites, syscall check, x86/ARM builds, PR review/merge,
  main update, integrated smoke, and branch/worktree cleanup.

## Verification

- Full hosted net before latest tranche: 448 passed.
- Focused raw4 after errors: 11 passed.
- Focused raw6 after errors: 9 passed.
- Focused procfs raw diagnostics: passed; full procfs worker run: 46 passed.
- `cargo check -p net -p procfs -p syscalls`: passed across committed tranches.
- x86 and ARM target builds passed before the latest diagnostics/error tranche.

## First resume command

`cd /home/nd/oxide-wt/B832-network-raw-ip-sockets && git status --short && gh pr view 3093 --json isDraft,mergeStateStatus,statusCheckRollup,url`
