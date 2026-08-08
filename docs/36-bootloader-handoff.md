# 36 Bootloader Handoff

FROZEN 2026-05-02. Dep:`01`,`02`,`07`,`20`,`21`,`33`,`39`. Provides:kernel `_start`.
## 1 Purpose

Define the boundary between bootloader (GRUB both arches) and kernel. What state we expect, what we accept, what we reject.

## 2 Invariants (frozen)

1. x86_64: multiboot2 through GRUB from BIOS or x86_64 UEFI. GRUB enters the kernel's own 32-bit trampoline; the trampoline reaches long mode before any Rust runs. No real-mode, no v8086, no firmware calls after entry.
2. aarch64: arm64 Image protocol. Either a UEFI application (EFI stub, entered by GRUB `linux` under EDK2) or a flat `Image` at a known phys addr (U-Boot `booti` / QEMU `-kernel`). CPU at EL2 or EL1 with MMU off after the stub drops it.
3. Bootloader hands the kernel enough to build one `BootInfo`: memory map, ACPI RSDP or DTB pointer, kernel cmdline string.
4. Kernel does not parse multiboot1, BIOS int 13h, or any protocol other than the two above.
5. Kernel image format: ELF64 loaded by multiboot2 (x86_64); PE32+ arm64 Image (aarch64).
6. No initramfs and no bootloader module list. Root is an ext4 block device named by the cmdline (`39§5`).

## 3 Multiboot2 protocol (x86_64)

Kernel ELF embeds a Multiboot2 header (spec §3.1.2) in the first 32 KiB. GRUB's BIOS and x86_64 UEFI programs enter the same entry-address tag (type 3), naming a 32-bit trampoline instead of `_start`: the trampoline begins in protected mode with paging off and builds its own page tables before any Rust code runs.

| Stage | State |
|---|---|
| GRUB → trampoline | 32-bit protected mode, paging off, A20 on, IF=0, `eax` = `0x36d76289`, `ebx` = MB2 info phys addr |
| Trampoline | Saves magic + info ptr; builds identity (0–1 GiB), higher-half (`0xFFFFFFFF80000000` → LMA `0x200000`), and HHDM (`0xFFFF800000000000` → phys 0, 1 GiB pages) maps; enables PAE+LME+NXE+PG; tears down the low identity map |
| Trampoline → `_start` | Long mode, IRQs off, BSP only, kernel at its linked higher-half VA |

Multiboot2 info tags consumed:

| Tag | Use |
|---|---|
| 1 (boot command line) | `/proc/cmdline`, `oxide.*` tokens (`§5`) |
| 6 (memory map) | `BootInfo.memmap`, carved around the loaded kernel image |
| 15 (ACPI 2.0 RSDP) | `BootInfo.rsdp_pa` — preferred; carries the XSDT the MADT walk needs |
| 14 (ACPI 1.0 RSDP) | fallback only; RSDT-only |
| 8 (framebuffer information) | `BootInfo.framebuffer`; validated packed-RGB platform fallback |

Not supplied by this handoff, and therefore owned by the kernel:
- HHDM base: installed by the trampoline, reported as `BootInfo.hhdm_offset`.
- Framebuffer request: optional type-5 header tag with loader-selected geometry. The type-8 information tag becomes a `simple-framebuffer` platform device only after PCI/native display probing found no scanout; its driver owns the WC mapping and fbdev/fbcon registration (`35`).
- CPU topology and AP startup: ACPI MADT plus the kernel's own INIT/SIPI trampoline (`13§11`). The handoff carries no CPU table.
- GDT/IDT/PIC state: the trampoline's GDT is temporary; `_start_rust` installs kernel-owned GDT/TSS/IDT and remaps+masks the legacy 8259 before the first `sti` (`20§3`).

## 4 EDK2 / U-Boot (aarch64)

Kernel is a PE32+ arm64 `Image` (64-byte Linux Image header, per the Linux arm64 boot protocol) wrapping the kernel ELF's loadable image, with an EFI stub entry.

UEFI path (the one CI boots): OVMF → GRUB `arm64-efi` → `linux /boot/oxide-aarch64.Image`. The stub, still in Boot Services:
- Reads the cmdline from the loaded-image protocol's UCS-2 `LoadOptions`. This firmware publishes no FDT, so there is no `/chosen/bootargs` to read.
- Finds the ACPI 2.0 RSDP in the EFI configuration table (`gEfiAcpi20TableGuid`) and records it for `BootInfo.rsdp_pa`; without it PCI never enumerates.
- `ExitBootServices`, drops the MMU, then joins the self-boot trampoline.

U-Boot / QEMU `-kernel` path: `booti` loads the flat Image at the RAM base and jumps to byte 0 with MMU off and `x0` = DTB phys. The kernel parses the DTB `/memory` node for the memmap and `/chosen/bootargs` for the cmdline.

Both paths converge on the same trampoline: drop EL2→EL1 if needed, build identity + higher-half + HHDM tables, enable the MMU, jump to the higher-half VA, clear TTBR0, tail-call `_start`.

AP startup is PSCI `CPU_ON` driven by the kernel off the DTB `/cpus` list or the MADT — no bootloader parks APs.

## 5 Cmdline

Single string: `oxide.<key>=<value> ... <kernel-cmdline>`. Examples:
- `oxide.log=info,sched=debug`
- `oxide.smp=N` (cap CPUs at N)
- `oxide.pti=on|off`
- `oxide.kaslr=on|off` (v2)
- `oxide.console=ttyS0,115200` or `=tty1`
- `oxide.root=PARTUUID=...` or `=UUID=...`

Parsed at boot; stored in `/proc/cmdline`.

## 6 Concurrency

Single-threaded boot until `smp_init`.

## 7 Test contract (frozen)

- GRUB multiboot2 boot in QEMU q35 under SeaBIOS and OVMF → "hello via UART" + clean QEMU exit (ISA-debug-exit).
- GRUB EFI-stub boot in QEMU `virt` under OVMF: same sequence.
- Both arches: `BootInfo.rsdp_pa` non-zero, MADT decodes, memmap total ≈ QEMU `-m`.
- x86_64: RGB framebuffer tag round-trips base, pitch, geometry, channel masks; native scanout wins, otherwise simplefb registers with WC policy.
- Cmdline parse: invalid `oxide.smp=abc` logs warn, ignores; valid keys take effect.
- Memory map sanity: PMM init reports total ≈ QEMU `-m`.

## 8 Failure modes

- Bootloader magic absent (entered outside the multiboot2 trampoline): empty memmap, kernel halts with "boot protocol error" via UART.
- ExitBootServices fail: halt.
- Memmap empty: halt.

## 9 Debug

`debug-boot`: dump the parsed handoff (HHDM, RSDP, bootloader magic); full memmap; cmdline tokens.

## 10 Cross-spec

`33` (RSDP/DTB consumption), `20`/`21` (early arch setup), `39§5` (image builder produces the GRUB ISO + root disk), `13§11` (kernel-driven AP startup).
