# state - network completion

Update: 2026-07-16.

## Current lane

- Active branch: `B879-network-packet-ring-foundation`, based on merged N07.4
  main `5ca8dea05`; claim commit `eac913737` is pushed.
- N07.5 implementation and local gates are complete; commit, push, PR, merge,
  refresh main, and cleanup remain.

## N07.5 implementation

- One socket-owned RX/TX ring owner allocates zeroed contiguous page-backed
  blocks and releases every object reference after socket and VMA pins vanish.
- Native V1/V2/V3 request parsing validates page/frame/private-area/count and
  overflow rules with existing/mapped-ring `EBUSY` precedence.
- `PACKET_VERSION`, `PACKET_HDRLEN`, and `PACKET_RESERVE` use exact native ABI,
  usercopy ordering, and concurrent version/reserve transaction checks.
- Packet-fd mmap uses owner frames for shared/private mappings with exact
  RX-then-TX size, zero offset, final-close survival, and VMA lifetime pins.

## Verification

- Passed: net 794/794, syscalls 114/114, VMM 153/153, workspace check,
  x86_64 kernel build, aarch64 kernel build, diff check, and file caps.
- Focused ring tests: 8/8; dedicated syscall backing tests: 2/2.

## Remaining network work

- Merge N07.5, then claim N07.6 from refreshed `origin/main`.
- N07.6-N07.10, N08-N24, N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B879-network-packet-ring-foundation && git status --short --branch`
