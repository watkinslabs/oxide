# 21 HAL aarch64

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`07`,`14`,`22`,`23`,`38`. Provides:kernel.
## 1 Purpose

aarch64 impl of HAL traits. Boot trampoline (EL2→EL1 drop). Vector table. GICv3 driver. Generic Timer. Per-CPU via `tpidr_el1`.

## 2 Floor

ARMv8.2-A. Mandatory: GICv3+, Generic Timer, FEAT_HCS / FEAT_VHE-not-required, FEAT_PAN, FEAT_PXN. Optional but used: FEAT_LSE (atomics), FEAT_DPB (cache cleaning), FEAT_PMUv3.

## 3 Boot

Bootloader: EDK2 (UEFI) or U-Boot. Hands kernel: physical entry point, FDT/DTB, memory map, ACPI (when EDK2), framebuffer.

`_start`:
1. May enter at EL2; drop to EL1: set HCR_EL2.RW=1, ELR_EL2 = `_el1_entry`, SPSR_EL2 = EL1h with DAIF masked, `eret`.
2. EL1: set up SCTLR_EL1 (MMU off, alignment-checks on, SP-aligned), VBAR_EL1 = `vector_table`.
3. Set up TCR_EL1: 48-bit VA, 4 KiB granule, TTBR0/TTBR1 split.
4. Build initial PTs (TTBR1 = kernel higher-half, TTBR0 = identity for boot).
5. Enable MMU: SCTLR_EL1.M=1; ISB.
6. Higher-half jump.
7. PMM/VMM init.
8. Per-CPU area; `tpidr_el1` = per-cpu#0.
9. GICv3 init (distributor + redist).
10. CNTPCT calibration; CNTP_CTL.
11. PSCI_CPU_ON to start secondaries (UEFI/PSCI). Each AP enters `ap_start`.
12. Start init.

## 4 Memory map

| VA range | Use |
|---|---|
| `0x0000_0000_0000_0000` .. `0x0000_FFFF_FFFF_FFFF` | userspace (TTBR0; 48-bit) |
| `0xFFFF_0000_0000_0000` .. `0xFFFF_7FFF_FFFF_FFFF` | kernel direct-map |
| `0xFFFF_8000_0000_0000` .. `0xFFFF_BFFF_FFFF_FFFF` | vmalloc/modules |
| `0xFFFF_C000_0000_0000` .. `0xFFFF_DFFF_FFFF_FFFF` | per-CPU stacks/areas |
| `0xFFFF_E000_0000_0000` .. `0xFFFF_FFFF_FFFF_FFFF` | fixmap, vDSO mapping in user, MMIO map |

Kernel image: relocated to higher half at boot.

## 5 PT format

4-level (L0..L3). Granule 4 KiB.

PTE bits:
- AttrIndx[2:0]: index into MAIR_EL1 (cacheability).
- AP[2:1]: access perms (kernel/user/RO/RW).
- SH[1:0]: shareability.
- AF: access flag (we set on map; HW updates).
- nG: not-global (per-ASID); set for user.
- UXN, PXN: unprivileged/privileged execute-never.
- D (TF): dirty (HW or SW based on FEAT_HAFDBS).

Map sizes:
- 4 KiB → L3 entry.
- 2 MiB → L2 block entry.
- 1 GiB → L1 block entry.

ASID: TTBR0_EL1 carries ASID; TLB tagged. Allocated per-AS.

## 6 KPTI

Two TTBR0 PTs per process: `pgd_kernel`,`pgd_user`. On entry from EL0:
- Switch TTBR0 to kernel-side via `MSR TTBR0_EL1, x` and `ISB`.
- ARM has no PCID-style avoidance; rely on ASID + BTB flushes per FEAT.

(arm64 KPTI is mostly relevant for older Cortex-A75-class cores; modern E-cores from 2020+ have hardware mitigations. We enable KPTI but allow runtime opt-out via cmdline.)

## 7 Syscall entry

`svc #0` from EL0 traps to vector `synchronous_lower_el_64`.

```asm
sync_lower_el_aarch64:
  # Save scratch.
  sub  sp, sp, #PT_REGS_SIZE
  stp  x0, x1, [sp, #0]
  stp  x2, x3, [sp, #16]
  ...
  stp  x29, x30, [sp, #240]
  mrs  x21, sp_el0
  mrs  x22, elr_el1
  mrs  x23, spsr_el1
  stp  x21, x22, [sp, #256]
  str  x23, [sp, #272]

  # KPTI swap (if enabled).
  mrs  x0, ttbr0_el1
  bic  x0, x0, #1
  orr  x0, x0, #1                 # set kernel ASID bit
  msr  ttbr0_el1, x0
  isb

  # Args: x0..x5 from saved regs; nr in x8.
  ldr  x8, [sp, #(8*8)]
  mov  x0, x8
  add  x1, sp, #0                 # &SyscallArgs
  bl   dispatch
  str  x0, [sp, #0]               # retval into x0 slot

  # Restore.
  ldr  x23, [sp, #272]
  ldp  x21, x22, [sp, #256]
  msr  spsr_el1, x23
  msr  elr_el1, x22
  msr  sp_el0, x21
  ldp  x0, x1, [sp, #0]
  ...
  add  sp, sp, #PT_REGS_SIZE
  eret
```

≤120 lines. Vector table 16 entries, each 128 bytes (ARM ABI).

## 8 IRQ entry

GICv3 path. CPU IRQ vector: `irq_lower_el_aarch64`. Reads `ICC_IAR1_EL1` for the IRQ id, dispatches, writes `ICC_EOIR1_EL1`.

## 9 Context switch

`14§6`. Asm in `crates/hal-aarch64/src/context_switch.S`.

## 10 Per-CPU

`tpidr_el1` indexed; per-CPU area set on AP startup.

## 11 IrqOps (GICv3)

```rust
fn enable_line(line:u32);    # GICD_ISENABLER bit
fn disable_line(line:u32);   # GICD_ICENABLER
fn eoi(line:u32);            # ICC_EOIR1_EL1 + DSB
fn set_affinity(line, mask)  # GICD_IROUTER<n>
fn alloc_msi(...)            # ITS / GICv3 LPI alloc
fn send_ipi(target, vec)     # ICC_SGI1R_EL1
fn ack(_) -> Some(vec)       # ICC_IAR1_EL1
```

LPIs (>8192 IDs) for MSI-X; ITS programmed for device → LPI mapping.

## 12 TimerOps (Generic Timer)

```rust
fn monotonic_ns() -> Nanos     # cntvct_el0 + math
fn set_oneshot(deadline)        # cntp_cval_el0 / cntp_ctl_el0
fn freq_khz() -> u32             # cntfrq_el0 cached
```

## 13 Cache mgmt

DMA buffers: `dc civac` to flush before device read; `dc ivac` to invalidate before CPU read after device write. Wrapped in `dma_wmb`/`dma_rmb` from `06§7`. ISB / DSB sequences explicit.

## 14 Perf budget

| Op | p99 cy |
|---|---|
| Syscall entry-to-dispatch | ≤ 200 |
| IRQ entry-to-handler | ≤ 180 |
| `MmuOps::map` 4 KiB | ≤ 350 |
| TLBI VAE1 single | ≤ 40 |
| Cross-CPU TLB shoot (DVM) | ≤ 3500 |
| GIC SGI send | ≤ 250 |

## 15 Test contract (frozen)

- Boot test: hello-world boots on QEMU `virt` machine.
- SMP test: 8 vCPU bring-up via PSCI.
- Syscall round trip; canary stable; budget met.
- KPTI check.
- vDSO `clock_gettime` agrees ±100ns.
- ABI cite: AAPCS64 IHI 0055D §5.1.1, ARM ARM DDI 0487 §D5/D7.
- Coverage of asm: 100% of vector entries.

## 16 Failure modes

- Synchronous fault from EL1 (kernel bug): dump ESR, FAR, regs; halt.
- PSCI_CPU_ON failure: kassert with target id + status.
- Generic timer not present: kassert.

## 17 Debug

`debug-hal-aarch64`: dump TCR, MAIR, SCTLR, all per-cpu regs on boot.

## 18 Cross-spec

`14`,`22`,`23`,`27`,`32`,`33`,`34`,`36`.

