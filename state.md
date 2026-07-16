# state - network completion

Update: 2026-07-15.

## Current lane

- Active branch: `B876-network-packet-metadata`, created from current
  `origin/main` merge `537554cd9` after B875 merged in PR #3155.
- N07.2 owns `PACKET_AUXDATA`, `PACKET_ORIGDEV`, original-device retention,
  packet metadata, and recvmsg ancillary copyout.
- No competing N07.2 branch, worktree, or implementation existed when B876
  was claimed.

## Recently merged

- N07.1 packet option ABI and outgoing control merged in PR #3155 at
  `537554cd9`; net 771/771, syscalls 106/106, workspace check, and dual target
  builds passed.
- N07 audit/decomposition merged in PR #3154 at `fed783485`.
- N06 packet memberships merged in PR #3153 at `490c315b7`.

## Remaining network work

- Implement, verify, and merge N07.2, then claim N07.3 from refreshed main.
  N07.3-N07.10, N08-N24, N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B876-network-packet-metadata && git status --short --branch`
