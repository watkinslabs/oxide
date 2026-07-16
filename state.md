# state - network completion

Update: 2026-07-16.

## Current lane

- Active branch: `B882-network-packet-tx-rings`, created from exact merged
  `origin/main` `05679b5d7` after N07.7 merged in PR #3161.
- N07.8 implementation and local verification are complete in PR #3162;
  merge, main fast-forward, and cleanup remain.
- Evidence: hosted net 823/823, socket 35/35, syscalls 116/116 plus integration
  suites, workspace check, x86_64/aarch64 kernel builds, diff lint, touched-code
  lint, and file caps pass.

## Recently merged

- N07.7 V3 receive blocks merged in PR #3161 at `05679b5d7`; net 810/810,
  workspace check, and dual target builds passed.
- N07.6 V1/V2 receive rings merged in PR #3160 at `78d19b2a6`; net 800/800,
  workspace check, and dual target builds passed.
- N07.5 packet-ring allocation/mmap lifetime merged in PR #3159 at
  `baa76c16c`; net 794/794, syscalls 114/114, VMM 153/153, workspace check,
  and dual target builds passed.
- N07.4 packet fanout merged in PR #3158 at `5ca8dea05`.

## Remaining network work

- Commit, push, merge, and clean up N07.8.
- N07.9-N07.10, N08-N24, N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B882-network-packet-tx-rings && git status --short --branch`
