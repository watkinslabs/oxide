# state - network completion

Update: 2026-07-16.

## Current lane

- Active branch: `B880-network-tpacket-v12-rx`, created from exact merged
  `origin/main` `baa76c16c` after N07.5 merged in PR #3159.
- N07.6 owns V1/V2 receive-ring publication, status ownership, metadata,
  pressure/drop accounting, poll/wake, wrap, and userspace-release races.
- No competing N07.6 branch, worktree, or implementation existed at claim.

## Recently merged

- N07.5 packet-ring allocation/mmap lifetime merged in PR #3159 at
  `baa76c16c`; net 794/794, syscalls 114/114, VMM 153/153, workspace check,
  and dual target builds passed.
- N07.4 packet fanout merged in PR #3158 at `5ca8dea05`.
- N07.3 packet pressure/statistics merged in PR #3157 at `80493b29d`.

## Remaining network work

- Audit, implement, verify, and merge N07.6.
- N07.7-N07.10, N08-N24, N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B880-network-tpacket-v12-rx && git status --short --branch`
