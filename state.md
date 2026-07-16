# state - network completion

Update: 2026-07-16.

## Current lane

- Active branch: `B943-network-packet-hw-timestamps`, created from exact
  merged `origin/main` `1c6c8b5eb`.
- N07.10.7 owns production raw-hardware timestamp ingress and receive-ring
  differential evidence.
- N07.10.7 implementation is complete. Linux-netdev skb software and
  raw-hardware timestamps flow into canonical packet metadata. AF_PACKET keeps
  driver provenance separate from its mandatory realtime fallback, selects
  hardware before software, and sets no timestamp-source status bit when no
  requested source exists. Virtio-net 1.2 exposes no receive timestamp field
  and correctly reports no hardware source. GNU/glibc V1/V2/V3 fallback records
  match host Linux exactly in the x86 88-record differential; only the three
  existing N07.10.8 loopback/V3 records differ. Modules pass 14/14, net passes
  861/861, virtio metadata passes 1/1, both GNU targets compile, and both kernel
  targets build.
- N07.10.6 implementation is complete. Packet queue and fanout decisions share
  Linux 6.19 64-bit skb allocation-class charge; admission checks current rmem,
  permits the frame that crosses the receive budget, and drops the next frame.
  At effective `SO_RCVBUF=4096`, Linux and Oxide both accept five 64-byte frames
  and drop the sixth. The x86 85-record differential differs only in the three
  existing N07.10.8 RX-ring records. Full net passes 861/861, both GNU targets
  compile, and both kernel targets build.
- N07.10.5 is merged. AF_PACKET preserves generic datagram
  writability for available, `SEND_REQUEST`, `SENDING`, and `WRONG_FORMAT`
  TX-ring states, and TX status notifications wake only `POLL_OUT`
  subscribers.
- No competing N07.10.7 branch, worktree, PR, or implementation existed at
  claim.
- B894 suppresses a packet-origin socket's complete fanout group before
  selection, keeps ordinary origin suppression socket-local, and applies
  outgoing-ignore policy at the Linux fanout group hook rather than at the
  selected member's ordinary socket hook.
- Member release uses Linux swap-delete ordering. Packet-ring replacement
  serializes delivery, temporarily unlinks the member, commits the new ring,
  and appends the member, matching Linux selector ordering. Validation occurs
  before unlink, so rejected ring changes preserve member order.
- Hosted fanout tests pass 16/16 and full net passes 860/860. The four new
  GNU/glibc records match host Linux exactly in the x86 84-record differential;
  only the existing N07.10.8 ring records differ. Both kernel targets build.
- The expanded TX GNU/glibc record uses a kernel-rejected malformed offset to
  produce `EINVAL` plus `TP_STATUS_WRONG_FORMAT`, repairs the header, and then
  completes the same frame. Host Linux and Oxide match byte-for-byte for all
  TX poll states and lifecycle fields. Focused TX tests pass 11/11; full net
  passes 860/860; native and aarch64 GNU builds and both kernel builds pass.
  The x86 84-record differential differs only in the three N07.10.8 RX-ring
  records (V1/V2 packet type and V3 packet type/publication count).
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
- Independent source and runtime evidence closes raw hardware timestamp ingress
  and fallback semantics. The remaining packet defects are N07.10.8 loopback
  classification and duplicate V3 publication.
- Campaign smoke is blocked before login by a repeated existing systemd
  `safe_close()` EBADF after `dbus.socket` loses its listening fd. The early
  targeted AF_PACKET service executes before that failure.

## Recently merged

- N07.10.5 packet TX poll semantics merged in PR #3205 at `704d253fa`;
  focused TX tests 11/11, net 860/860, dual GNU and kernel builds passed, and
  the TX differential record matches Linux exactly.
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

`cd /home/nd/oxide-wt/B943-network-packet-hw-timestamps && git status --short --branch`
