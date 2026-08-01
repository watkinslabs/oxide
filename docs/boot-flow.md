# Boot Flow

FROZEN 2026-05-02. Dep:`20`,`21`,`33`,`36`,`29`. Updates on early-init change per `00§11`.

End-to-end boot sequence both arches. Same logical phases; arch-specific HW interaction in `20`/`21`.

## 1 Sequence

```mermaid
sequenceDiagram
    participant FW as Firmware (UEFI/U-Boot)
    participant BL as Bootloader (GRUB both arches)
    participant Boot as boot-{x86_64|aarch64}
    participant K as kernel _start
    participant PMM
    participant VMM
    participant SMP as smp_init
    participant Sched
    participant Init as PID 1

    FW->>BL: load GRUB (BIOS El Torito x86 / OVMF EFI arm)
    BL->>BL: read grub.cfg, build kernel cmdline
    BL->>Boot: x86: multiboot2 (eax=magic, ebx=info)<br/>arm: EFI-stub `linux` of the arm64 Image
    Note over Boot: x86: 32-bit protected mode, paging off<br/>arm: EL2→EL1 drop, MMU off
    Boot->>Boot: build PT, identity + higher-half + HHDM
    Boot->>Boot: enable paging/MMU, jump higher-half
    Boot->>Boot: kernel GDT/TSS/IDT (x86) or vector table (arm); mask legacy PIC
    Boot->>Boot: parse MB2 tags (x86) / DTB+EFI cfg table (arm) into BootInfo
    Boot->>K: jump kernel_main()
    K->>PMM: pmm.init(memmap regions)
    PMM-->>K: ok; kernel image + ACPI/DTB regions reserved
    K->>VMM: vmm.init(); kernel direct map up
    K->>K: per-CPU#0 area; GS_BASE/TPIDR_EL1 set
    K->>K: ACPI MADT walk (x86) / DT cpus walk (arm)
    K->>K: APIC/GIC init; TSC/CNTPCT calibration
    K->>SMP: smp_init() — start APs via APIC SIPI / PSCI_CPU_ON
    Note over SMP: each AP: per-CPU area, idle task, joins runqueue
    SMP-->>K: all CPUs online
    K->>Sched: sched.init(num_cpus)
    K->>K: register drivers (linkme distributed_slice)
    K->>K: probe drivers (PCIe walk; virtio-mmio; platform DT)
    K->>K: mount ext4 root from the virtio-blk disk
    K->>K: mount /proc, /sys, /dev (devtmpfs), /dev/pts, /sys/fs/cgroup
    K->>Init: execve /init
    Init->>Init: spawn services per /etc/init.conf
    Init->>K: getty on /dev/tty1 (interactive) OR direct service (headless)
```

## 2 Phase boundaries (frozen)

| Boundary | Pre-state | Post-state |
|---|---|---|
| Bootloader → trampoline | FW-defined, multi-vendor | per `36` |
| trampoline → `kernel_main` | identity-mapped, IRQs off, BSP only | higher-half, MMU on, IRQs off, BSP |
| `kernel_main` → `smp_init` | UP, no allocator | UP, PMM+VMM+slab+sched all up; APs not yet started |
| `smp_init` → driver probe | SMP up, idle tasks running | full SMP, RQ scheduling |
| Driver probe → mount | drivers registered+probed | block/net/console operational |
| Mount → execve init | rootfs mounted, /proc /sys /dev populated | init binary loaded, ready to run |
| execve init → user space | kernel done; init owns userspace | running |

## 3 Memory model transitions

Per `06§12`. Pre-`smp_init`: trivially sequential. Post-`smp_init`: full memory model applies. Code before `smp_init` initializes locks correctly even though they're no-ops at the time.

## 4 IRQ state transitions

| Phase | IRQs |
|---|---|
| Bootloader → trampoline | off |
| trampoline → MMU on | off |
| MMU on → APIC/GIC init | off |
| APIC/GIC init → smp_init | off (BSP timer only after this point) |
| Post-smp_init | per-CPU |

## 5 Cmdline tokens consumed at boot

`oxide.smp=N`, `oxide.pti=on|off`, `oxide.kaslr=on|off`, `oxide.console=...`, `oxide.root=...`, `oxide.log=<per-target levels>`. Per `36§5`.

## 6 Failure points + handling

| Phase | Failure | Action |
|---|---|---|
| Bootloader magic absent | per `36§8` | UART halt msg "boot protocol error" |
| memmap empty | invariant | halt |
| kernel image relocation fail | rare | halt |
| ACPI table checksum fail | per-table | log warn, fall back; some tables fatal (MADT) |
| AP startup timeout | per-CPU | kassert with stuck CPU id (`20§16`/`21§16`) |
| TSC/timer cross-CPU sync >1ms | per `23§13` | kassert |
| `/init` not found on the root fs | per `29§11` | kernel panic |
| `/init` exits | per `29§11` | kernel panic |

## 7 Cross-spec

`20§3` (x86 boot detail), `21§3` (arm boot detail), `33` (FW table parse), `36` (bootloader handoff struct), `29§6` (post-init userspace seq), `06§12` (memory-model boot ordering), `13§4` (sched init).

## 8 Changelog

(none)

