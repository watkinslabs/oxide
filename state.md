# state - network completion

Update: 2026-07-16.

## Current lane

- Active branch: `B887-network-packet-v3-private-offset`, created from exact
  merged `origin/main` `ba25e43f3` after packet getsockopt PR #3166, then
  rebased onto merged `origin/main` `1df8dc296` before implementation commit.
- N07.10.3 owns V3 private-offset width and mapped private-area integrity.
- No competing N07.10.3 branch, worktree, PR, or implementation existed at
  claim.
- The portable probe, GNU x86_64/aarch64 cross-build, opt-in rootfs injection,
  early root service, retained UART capture, and exact ordered comparator are
  implemented. The original 79-record host output is identical across three
  consecutive runs; the new 80th large-private record matches in the x86
  Linux/Oxide differential. Both GNU targets compile with native glibc loaders.
- N07.10.2 implementation is complete in the worktree. One common copyout
  writes the clamped length before the value and preserves Linux error and
  statistics-reset ordering. Hosted syscalls pass 121/121 and both kernel
  targets build.
- The post-fix x86 differential removes all three packet `getsockopt`
  mismatches. Its only remaining differences are N07.10.8: packet type 4
  versus Linux 2 and four V3 publications versus Linux one.
- Linux 6.19 source, host BTF, and a real GNU/glibc probe disprove the queued
  V3 private-offset widening: Linux narrows the accepted `u32` request through
  an internal `unsigned short` and reports offset 48 for 65,536, as Oxide does.
  Hosted boundaries cover 65,535/65,536/65,537 and full-width validation;
  net passes 854/854 and the differential retains that exact behavior.
- Independent source audit retains fanout origin and ignore behavior, TX-ring
  poll, queue accounting, raw hardware timestamp, and fanout close-order
  defects in N07.10.
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

`cd /home/nd/oxide-wt/B887-network-packet-v3-private-offset && git status --short --branch`
