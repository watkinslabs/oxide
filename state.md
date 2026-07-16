# state - network completion

Update: 2026-07-16.

## Current lane

- Active branch: `B883-network-packet-offload-options`, created from exact
  merged `origin/main` `a6917a573` after N07.8 merged in PR #3162.
- N07.9 implementation and local verification are complete in PR #3163;
  merge, main fast-forward, and cleanup remain.
- Implemented `PACKET_VNET_HDR`, `PACKET_VNET_HDR_SZ`, `PACKET_TIMESTAMP`,
  `PACKET_TX_HAS_OFF`, `PACKET_COPY_THRESH`, and `PACKET_QDISC_BYPASS` with
  canonical queue/ring/virtio/timestamp effects and Linux ordering.
- Evidence: hosted net 853/853, virtio-net driver 28/28, socket 35/35,
  syscalls 120/120 plus integration suites, workspace check, x86_64/aarch64
  kernel builds, diff check, and touched-file caps pass.

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

- Commit, push, merge, and clean up N07.9.
- N07.10, N08-N24, N26.4, and the completion gate remain in
  `scratch/network-plan.md`.

## First resume command

`cd /home/nd/oxide-wt/B883-network-packet-offload-options && git status --short --branch`
