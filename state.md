# state.md — session hand-off

Current integration: `B1876-uart-thre-retrigger`, PR #4738. Code head
`38d333178`; base `17a3113b2`. The final exact commit passed the full workspace
test run, local pre-push gates, five forced-path x86 boots, and first-attempt
x86_64/aarch64 smoke.

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

## Live known-work summary

The canonical type/severity table is in `scratch/known_issues.md`: 130 live
rows = 2 blockers, 0 high, 58 medium, 70 low. The two blockers are x86 UEFI
boot and xHCI/USB input. The closed B1876 high row and its failure/pass evidence
remain in `scratch/fixed-issues.md`.

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
