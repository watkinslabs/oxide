# state.md — session hand-off

Current integration: `B1877-serial-rx-lock-ownership`, PR #4739. Code head
`a1e2a08d7`; rewritten base `be5808ec8`. The exact source passed the full
workspace test run, local pre-push gates, and first-attempt x86_64/aarch64
smoke including serial RX.

## What just landed

- B1872 / PR #4734: synchronous virtio-blk waits park directly on completion;
  process-context networking uses bottom-half exclusion. Three Firefox runs
  passed valid and invalid-DNS pages without the former freeze.
- B1873: packet paths retain their concrete network-namespace owner and nftables
  publishes one compiled immutable generation. The exact Firefox run rendered
  valid/invalid pages in 4.960/2.700 s at 0.150 us kernel time per syscall.
- B1874 / PR #4736: x86 PAT WC, arm64 Normal-NC, and driver-owned raw-PFN cache
  policy. Virtio framebuffer RAM remains WB.
- B1875 / PR #4737: Multiboot2 type-5 request and type-8 RGB handoff,
  `drv-simplefb`, post-PCI fallback binding, exact firmware pixel formats, and
  page-offset-aware WC mapping. QEMU std-VGA with virtio-gpu omitted reached
  userspace. A 125 MiB full-frame write took 0.27 s WC versus 3.10 s with the
  temporary UC control. Measurements: `scratch/simplefb-performance-20260806.md`.
- The stale real-hardware AP-bringup claim was retired: x86 INIT/SIPI and arm64
  PSCI were already live. The enlarged boot handoff now lives in static
  architecture-owned storage; x86 boot stack depth improved from its 20,000-byte
  baseline to 19,904, and arm remains at 12,129.
- B1876 / PR #4738: the 16550 line handler drains the legacy edge-triggered IRQ
  source to deassertion with a bounded 512-pass limit, and initialization raises
  the UART's `OUT2` interrupt gate. The hosted positive control fails with the
  former single-service path; five exact forced-path boots passed with serial RX.
- B1877 / PR #4739: serial RX echo now leaves the IRQ-save port owner before one
  ordered device submission; the dead duplicate RX registration path is gone,
  and fbcon tests use one global-state domain. The hosted positive control fails
  with three inline writes; the fixed path submits one batch at IRQ depth zero.

## Live known-work summary

The canonical type/severity table is in `scratch/known_issues.md`: 127 live
rows = 2 blockers, 0 high, 56 medium, 69 low. The two blockers are x86 UEFI
boot and xHCI/USB input. Retired rows and their failure/pass evidence remain in
`scratch/fixed-issues.md`.

## First task next session

```sh
git pull
tools/issues.sh --count
```

Re-run the release Firefox workload against
`scratch/firefox-performance-20260806.md` and
`scratch/write-combining-performance-20260806.md`, save the new comparison,
then claim and fix the largest measured remaining cost. Firefox/performance
remains the top user-facing priority; do not alter GitHub CI or merge policy.
