# state.md — session hand-off

Current integration: `B1875-physical-framebuffer-source`, PR #4737. Code head
`85421ec51`; base `def0c5718`. Worktree clean, no QEMU remains. The final exact
commit passed the local pre-push gates and first-attempt x86_64/aarch64 smoke.

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

## Live known-work summary

The canonical type/severity table is in `scratch/known_issues.md`: 131 live
rows = 2 blockers, 1 high, 58 medium, 70 low. The two blockers are x86 UEFI
boot and xHCI/USB input. The one high issue is new and reproducible:

- IRQ-driven 16550 TX can stop mid-record and never restart. It occurred before
  simplefb registration in three forced-framebuffer attempts, under both WC and
  the temporary UC control. One 240 s run plus serial SysRq produced no output;
  the retained reproduction stops in the AHCI LBA0 line. Ordinary SMP=2 boots
  also pass, so this is intermittent, not a deterministic framebuffer failure.

## First task next session

```sh
git pull
tools/issues.sh --count
```

Then claim the 16550 TX-loss row and compare the local THRE enable/retrigger
path with Linux `serial8250_start_tx`, `serial8250_THRE_test`, and the THRE
timer fallback. Preserve Firefox/performance as the top user-facing priority;
do not alter GitHub CI or merge policy.
