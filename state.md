# state - network completion

Update: 2026-07-16.

## Current lane

- Active branch: `B878-network-packet-fanout`, created from current
  `origin/main` merge `80493b29d` after B877 merged in PR #3157.
- N07.4 owns namespace-scoped packet fanout groups, all Linux selection modes,
  compatibility/capacity, filter ownership, rollover stats, and teardown.
- No competing N07.4 branch, worktree, or implementation existed when B878
  was claimed.

## N07.4 implementation

- One namespace-keyed group owner provides legacy/native fanout ABI, exact
  compatibility and capacity, unique IDs, and all eight Linux selection modes.
- Group-owned CBPF/EBPF, rollover pressure/history/statistics, outgoing
  suppression, IPv4 defragmentation, and exactly-one receive delivery are live.
- Membership selection serializes with final release and packet bind; namespace
  filtering occurs before fanout classification. Linux NAPI and Virtio carry
  receive queue identity into QM selection.

## N07.4 verification

- Passed: net 786/786, syscalls 111/111, Virtio net 28/28, focused Linux
  netdev 5/5, workspace check, x86_64 build, aarch64 build, diff/file caps.
- Deterministic coverage includes all modes, native layouts, namespace
  isolation, compatibility/capacity, filters, rollover, defragmentation, bind,
  and selected-delivery versus final-release serialization.

## N07.2 implementation

- Packet sockets retain one enqueue-time receive record containing
  sockaddr_ll identity and native auxdata fields after filter truncation.
- `PACKET_ORIGDEV` selects retained original interface identity at enqueue;
  observed/original leases must share one exact network namespace.
- `PACKET_AUXDATA` emits Linux status, full/snapshot length, network offset,
  checksum, TCP GSO, and hardware or SOCK_DGRAM inline VLAN metadata.
- Virtio and Linux-module RX carry driver checksum/offload metadata through
  the canonical netdev boundary; Virtio runtime state now has a focused child
  owner instead of exceeding the 500-line file cap.

## N07.2 verification

- Passed: net 774/774, syscalls 107/107, Virtio net 28/28, focused Linux
  netdev 5/5, workspace check, x86_64 build, aarch64 build, diff/file caps.
- Full modules retains unrelated debugfs automount baseline failure: 178/179.
- Full lint reports 1,989 findings versus 1,990 on `main`; B876-added code is
  clean.

## N07.3 implementation

- One packet receive queue owns frames, byte charge, pressure state, admitted
  packet count, and drops; the fixed 64-frame limit is removed.
- Positive-filter frames are admitted against the current socket receive-byte
  budget, and non-peek dequeue releases the exact retained charge.
- `PACKET_STATISTICS` reports admitted plus dropped observations and clears
  counters before user copy. V1/V2 return 8 bytes; V3 returns 12 bytes.
- Exact native-int `PACKET_VERSION` set/get validates V1/V2/V3 and provides
  the canonical version state later ring work must consume.

## N07.3 verification

- Passed: net 776/776, syscalls 109/109, workspace check, x86_64 build,
  aarch64 build, diff/file caps.
- Full lint retains 1,989 unrelated baseline findings; new queue code is clean.

## Recently merged

- N07.3 packet pressure/statistics merged in PR #3157 at `80493b29d`; net
  776/776, syscalls 109/109, workspace check, and dual target builds passed.
- N07.2 packet receive metadata merged in PR #3156 at `335ba6da1`; net
  774/774, syscalls 107/107, Virtio net 28/28, workspace check, and dual
  target builds passed.
- N07.1 packet option ABI and outgoing control merged in PR #3155 at
  `537554cd9`; net 771/771, syscalls 106/106, workspace check, and dual target
  builds passed.
- N07 audit/decomposition merged in PR #3154 at `fed783485`.
- N06 packet memberships merged in PR #3153 at `490c315b7`.

## Remaining network work

- Merge N07.4, then claim N07.5 from refreshed main. N07.5-N07.10, N08-N24,
  N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B878-network-packet-fanout && git status --short --branch`
