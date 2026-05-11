# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `94ced16`.

## What shipped this run

1. **`bf8e5a5`** `fix(irq): ungate LAPIC/GIC bring-up (was hidden by debug-acpi)` —
   `smoke_device_map_{x86,arm}` was gated `feature = "debug-acpi"` so
   default builds never set `LAPIC_BASE_VA`; `timer_periodic()` silently
   no-op'd. Removed the gate. Audited the other 35 `cfg(feature =
   "debug-*")` gates — all klog/smoke only, none hid functionality.

2. **`94ced16`** `fix(irq): drop schedule_from_irq from timer ISR
   (cooperative-only)` — with the LAPIC now firing, the timer ISR was
   exercising the known iretq-frame protocol gap. Cooperative-only
   for now; `tick_poll()` still runs inline so UART RX wakes stdin.

## Open work

### The CAT-smoke wedge is the real login blocker (NOT YET FIXED)

Trace consistently stops at:
```
yo\r\nhi\r\nALinux version 5.15.0-oxide (oxide@build) #1 SMP PREEMPT\r
```
This is the kernel-spawned smoke ELF in `kernel/src/smoke/elf.rs::
build_elf()` running iteration 4 (CAT: open `/proc/version` + read +
write). `VERSION_BODY` (`procfs/mod.rs:269`) is 56 bytes ending in
`\n`; `ConsoleInode::write` (`kernel/src/dev/console.rs:84`) does the
ONLCR `\n → \r\n` byte-by-byte via `console_emit`. We emit 55 body
bytes + the `\r` of the final NL expansion, then hang.

Not a regression from `bf8e5a5` / `94ced16`: same byte-exact stop
point both before and after the LAPIC fix. The wedge sits somewhere
in the LAST `console_emit(b"\r\n")` call (or returning from it
into `sys_write`'s tail / `sys_close` / `sys_exit`).

Adding any klog probe inside `sys_writev` unwedges it — strong
yield-point gap somewhere on the return path.

**Approach for next session:**
1. Instrument `sys_close`+`sys_exit_group` with a one-line
   `klog::write_raw(b"[CLOSE]\\n")` / `b"[EXIT]\\n"` probe at fn
   head. Boot once. Does CAT reach close or exit?
   - If yes → wedge is in parent's `wait4` or the return-to-boot
     path in `smoke/elf.rs::run_as_task`.
   - If no → wedge is in `ConsoleInode::write` final-byte path
     OR in the UART driver for the very last `\n`.
2. If wedge is in `ConsoleInode::write`: check whether
   `lock_irqsave` ever yields on the BOOT_UART spinlock contention;
   check whether the 16550 LSR THRE bit ever clears when the FIFO
   is full (115200 baud × 14-byte FIFO).
3. If wedge is in close/exit: parent wait4 likely sleeping on a
   parked child whose Zombie state never publishes.

### Display + input on GTK (parked)
`make qemu-x86` opens GTK by default (`tools/xtask/src/image_qemu.rs:373`).
Set `OXIDE_QEMU_HEADLESS=1` to suppress. Block-glyphs (fbcon font
in virtio-gpu fb) and dead keyboard (virtio-input not delivered to
userspace) are separate from the serial-path login work.

### Real PTRACE_SINGLESTEP (parked)
F49-F51 framework exists; SIGSTOP/SIGTRAP race wedges
`ptrace_singlestep_smoke`. rcS still skips it.

## First task next session

```sh
# 1) Add the close/exit probes (kernel/src/syscalls/mod.rs, sys_close
#    + sys_exit_group, or wherever they dispatch) — single
#    klog::write_raw line each, ungated.
# 2) Build + boot headless:
make x86 && cargo run -p xtask -- image --arch x86_64 --features debug-boot
qemu-mcp qemu_start arch=x86_64
qemu_run_until pattern="[EXIT]|[CLOSE]|oxide login:" timeout=60
# 3) Use the result to pick branch above.
```

## Useful pointers

- Smoke ELF + CAT iter: `kernel/src/smoke/elf.rs:32` (build_elf),
  `kernel/src/smoke/elf.rs:254` (build_cat_blob).
- VERSION_BODY (56 bytes): `kernel/src/procfs/mod.rs:269`.
- ConsoleInode::write ONLCR loop: `kernel/src/dev/console.rs:84`.
- klog write_raw → boot_emit → BOOT_UART: `crates/shared/klog/src/lib.rs:289`
  → `crates/arch/boot-x86_64/src/lib.rs:72` →
  `crates/arch/boot-x86_64/src/uart.rs:124`.
- sys_writev: `kernel/src/syscalls/fs.rs:718`.
- Headless boot: set `OXIDE_QEMU_HEADLESS=1`.
