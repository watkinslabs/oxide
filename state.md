# state - network completion

Update: 2026-07-16.

## Current lane

- Active branch: `B884-network-packet-linux-differential`, created from exact
  merged `origin/main` `4dd368cbf` after the N07.9 merge record in PR #3164.
- N07.10 owns matching Linux/Oxide glibc AF_PACKET probes, integrated subsystem
  gates, dual-architecture builds, and campaign smoke.
- No competing N07.10 branch, worktree, PR, or implementation existed at claim.

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
