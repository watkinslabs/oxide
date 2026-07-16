# state - network completion

Update: 2026-07-15.

## Current lane

- Active branch: `B872-network-packet-observation`, PR #3152, based on merged
  B871 commit `22bbe738f`; merge is the remaining B872 operation.
- N05 implementation is complete locally. One AF_PACKET observation owner now
  handles physical Virtio, Linux-module, loopback, local, forwarded, and
  packet-originated traffic with exact retained namespace/device generations.
- RAW/DGRAM L2 views, VLAN/QinQ protocol selection, all packet types, BPF
  filtering, sender suppression, malformed-frame rejection, Linux skb header
  preservation, and exact-once delivery have deterministic coverage.

## Verification

- Passed: net 764/764, Linux netdev 13/13, Virtio net 27/27, socket 33/33,
  syscalls 99/99, workspace check, x86_64/aarch64 kernel builds, and
  diff/file-cap checks.
- Default/hosted full modules suites retain two pre-existing fixture failures:
  debugfs automount reproduces on untouched main; configfs passes alone.

## Remaining network work

- Merge B872, refresh `main`, close N05 with PR/merge evidence, then claim N06
  packet memberships and device lifecycle from exact merged `origin/main`.
- N06-N24, N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B872-network-packet-observation && git status --short --branch`
