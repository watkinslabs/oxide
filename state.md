# state - network completion

Update: 2026-07-16.

## Current lane

- Active branch: `B885-network-packet-get-copy-order`, created from exact
  merged `origin/main` `eb5efef94` after differential harness PR #3165.
- N07.10.2 owns packet `getsockopt` output-length/value transaction ordering
  and unsupported-option precedence exposed by the first x86 differential.
- No competing N07.10.2 branch, worktree, PR, or implementation existed at
  claim.
- The portable 79-record probe, GNU x86_64/aarch64 cross-build, opt-in rootfs
  injection, early root service, retained UART capture, and exact ordered
  comparator are implemented in the worktree. Host output is identical across
  three consecutive runs; both GNU targets compile with native glibc loaders.
- First valid x86 differential completed. It proves packet `getsockopt`
  value/length and unknown-option ordering mismatches, packet-type metadata
  mismatch, and four V3 publications where Linux emits one.
- Independent source audit added V3 private-offset narrowing, fanout origin and
  ignore behavior, TX-ring poll, queue accounting, raw hardware timestamp, and
  fanout close-order defects to N07.10 in `scratch/network-plan.md`.
- Campaign smoke is blocked before login by a repeated existing systemd
  `safe_close()` EBADF after `dbus.socket` loses its listening fd. The early
  targeted AF_PACKET service executes before that failure.

## Recently merged

- N07.8 packet transmit rings merged in PR #3162 at `a6917a573`; net 823/823,
  socket 35/35, syscalls 116/116 plus integration, workspace check, and dual
  target builds passed.
- N07.7 V3 receive blocks merged in PR #3161 at `05679b5d7`; net 810/810,
  workspace check, and dual target builds passed.
- N07.6 V1/V2 receive rings merged in PR #3160 at `78d19b2a6`; net 800/800,
  workspace check, and dual target builds passed.
- N07.5 packet-ring allocation/mmap lifetime merged in PR #3159 at
  `baa76c16c`; net 794/794, syscalls 114/114, VMM 153/153, workspace check,
  and dual target builds passed.
- N07.4 packet fanout merged in PR #3158 at `5ca8dea05`.

## Remaining network work

- N07.10, N08-N24, N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B884-network-packet-linux-differential && git status --short --branch`
