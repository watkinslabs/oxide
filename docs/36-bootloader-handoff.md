# 36 Bootloader Handoff

FROZEN 2026-05-02. Dep:`01`,`02`,`07`,`20`,`21`,`33`,`39`. Provides:kernel `_start`.
## 1 Purpose

Define the boundary between bootloader (Limine on x86, EDK2/U-Boot on arm) and kernel. What state we expect, what we accept, what we reject.

## 2 Invariants (frozen)

1. x86_64: Limine modern protocol. CPU in long mode at kernel entry. No real-mode, no v8086, no BIOS calls.
2. aarch64: UEFI app (EDK2-compatible) or U-Boot booti. CPU at EL2 or EL1 with MMU off.
3. Bootloader hands a defined struct of (memory map, ACPI RSDP or DTB ptr, framebuffer info, kernel cmdline string, modules list inc. initramfs).
4. Kernel does not parse legacy multiboot1, BIOS int 13h, or 32-bit protected mode.
5. Kernel image format: ELF64 with `_start` as entry; relocated by bootloader if PIE (KASLR future).

## 3 Limine protocol (x86_64)

We use Limine ≥ 6.0 with the [Limine Boot Protocol](https://github.com/limine-bootloader/limine).

Kernel ELF embeds `.limine_requests` section with feature-request structs:
- `LIMINE_FRAMEBUFFER_REQUEST` → fb info.
- `LIMINE_HHDM_REQUEST` → higher-half direct-map base.
- `LIMINE_MEMMAP_REQUEST` → memory map.
- `LIMINE_RSDP_REQUEST` → ACPI RSDP physical address.
- `LIMINE_SMP_REQUEST` → AP info.
- `LIMINE_KERNEL_FILE_REQUEST` → kernel ELF self-pointer (for kallsyms etc.).
- `LIMINE_MODULE_REQUEST` → loaded modules (initramfs).
- `LIMINE_KERNEL_ADDRESS_REQUEST` → physical and virtual base.
- `LIMINE_BOOT_TIME_REQUEST` → boot wallclock seed.

Kernel `_start` reads response pointers; aborts if any required is null.

Bootloader-provided invariants we trust:
- Higher-half direct-map established.
- ACPI tables physically reachable.
- BSP in long mode, paging on, IRQs disabled.

## 4 EDK2 / U-Boot (aarch64)

Kernel is a UEFI executable (PE32+ wrapping our ELF) OR a flat `Image` blob loaded by U-Boot at a known phys addr.

UEFI path:
- Kernel runs as UEFI application; uses Boot Services to:
  - Get memory map (`GetMemoryMap`).
  - Get ACPI from `EFI_CONFIG_TABLE` (or DTB from same).
  - Locate framebuffer via GOP.
  - Load initramfs from same FS.
- Then `ExitBootServices`. After: only Runtime Services available.

U-Boot path:
- DTB in `x0`; Image base in fixed addr.
- Set up minimal env, jump to kernel.
- Initramfs loaded by U-Boot script to a known addr; address noted in DTB chosen-node.

## 5 Cmdline

Single string: `oxide.<key>=<value> ... <kernel-cmdline>`. Examples:
- `oxide.log=info,sched=debug`
- `oxide.smp=N` (cap CPUs at N)
- `oxide.pti=on|off`
- `oxide.kaslr=on|off` (v1.x)
- `oxide.console=ttyS0,115200` or `=tty1`
- `oxide.root=PARTUUID=...` or `=UUID=...`

Parsed at boot; stored in `/proc/cmdline`.

## 6 Concurrency

Single-threaded boot until `smp_init`.

## 7 Test contract (frozen)

- Limine boot of empty kernel → "hello via UART" + clean QEMU exit (ISA-debug-exit).
- Limine boot with initramfs module attached: kernel sees module, mounts as rootfs.
- EDK2 boot in QEMU `virt`: same sequence.
- Cmdline parse: invalid `oxide.smp=abc` logs warn, ignores; valid keys take effect.
- Memory map sanity: PMM init reports total ≈ QEMU `-m`.

## 8 Failure modes

- Required Limine request null: kernel halts with "boot protocol error" via UART.
- ExitBootServices fail: halt.
- Memmap empty: halt.

## 9 Debug

`debug-boot`: dump every Limine request response; full memmap; cmdline tokens.

## 10 Cross-spec

`33` (RSDP/DTB consumption), `20`/`21` (early arch setup), `39` (image builder produces compatible ESP/initramfs).

