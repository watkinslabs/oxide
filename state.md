# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `c6a26d0`.

## What shipped this run

1. **`bf8e5a5`** `fix(irq): ungate LAPIC/GIC bring-up (was hidden by debug-acpi)`.
2. **`94ced16`** `fix(irq): drop schedule_from_irq from timer ISR (cooperative-only)`.
3. **`6ac5a90`** `refactor(console): batch ONLCR writes — one console_emit per NL-free run`.
4. **`32d9a59`** `fix(uart): bounded spin in Uart16550::write_byte (drop byte on cap)`.
5. **`25fa9a3`** `fix(fbcon): disable klog aux sink — fbcon_flush_pixels wedges boot` ← **CAT WEDGE FIX**.
6. **`c6a26d0`** `diag(uart): UART_DROPS atomic counter for bounded-spin drops`.

## CAT wedge — CLOSED 🎯
fbcon klog aux sink wedged in `fbcon_flush_pixels` (virtio-gpu submit). Disabled. Full boot now runs through smokes → init → rcS → getty issue banner.

## Getty login-prompt stall — bisect this session

Added `<WV` entry probe + `+>` exit probe to `sys_writev`, plus a
timer-ISR heartbeat dot. Trace:

```
<WV\r\r\n+>                    ← writev #1: entered, exited cleanly
<WVoxide Linux on /dev/ttyS0\r\n+>   ← writev #2: entered, exited
<WV\r\r                        ← writev #3: ENTERED, emitted "\r\r", NO EXIT
```

**Decisive finding: writev #3 wedges inside the kernel body** (no
`+>` marker). Also only ONE heartbeat dot for the entire 60s run —
timer IRQs stop firing once init starts (IF=0 throughout the wedge).

Combined evidence: the kernel is stuck in a tight loop inside
`sys_writev` → `File::write` → `ConsoleInode::write` → `console_emit`
→ `boot_emit`, holding BOOT_UART under `lock_irqsave` (cli'd) with
no path out. Bounded spin from `32d9a59` should drop bytes after
100M iters but apparently isn't triggering, or each cycle is
slow enough that 60s isn't enough.

### Strongest remaining hypothesis

QEMU's emulated 16550 is fully unresponsive after some threshold —
THRE stays clear forever, our `inb` keeps reading 0. The bounded
spin counter (`SPIN_CAP=100M`) does fire eventually but TCG runs
those 100M iterations slowly enough that 60s only gets us through
1-2 bytes of writev #3.

OR the lock_irqsave for BOOT_UART is held by an earlier panic /
fault path that didn't release it, and writev #3's CAS spins on
the held lock forever (single-CPU lock_irqsave deadlock).

### First task next session

1. **Drop SPIN_CAP to 1M** (or even 100K) in `crates/arch/boot-x86_64/src/uart.rs:127`. With 100K iters/byte, 60s lets us drop ~600K bytes — login: prompt fits trivially.
2. **Add a "spin entered" probe** alongside the drop counter so we see whether write_byte's spin path is actually being taken.
3. **Read UART_DROPS after a wedged run via `qemu_mem`** (`0xffffffff8112a000`, 8 bytes). If >0, bounded spin is firing; tune SPIN_CAP. If ==0, the wedge is elsewhere (likely the BOOT_UART CAS spin from a leaked lock).

```sh
make x86 && cargo run -p xtask -- image --arch x86_64 --features debug-boot
qemu_start arch=x86_64
qemu_run_until pattern="oxide login:" timeout=120
# Then if wedged, inspect UART_DROPS:
qemu_mem addr=0xffffffff8112a000 length=8
```

## Open work (carried)

- **Proper fbcon fix** — re-enable klog_sink without the virtio-gpu wedge.
- **Display + input on GTK** — `OXIDE_QEMU_HEADLESS=1` skips GTK.
- **Real PTRACE_SINGLESTEP** — F49-F51 framework; SIGSTOP/SIGTRAP race.

## Useful pointers

- fbcon aux-sink (currently commented out): `kernel/src/lib.rs:662`.
- UART bounded spin + drop counter: `crates/arch/boot-x86_64/src/uart.rs:124-150`.
- UART_DROPS symbol: `0xffffffff8112a000` (verify with `nm <kernel-elf> | grep UART_DROPS`).
- sys_writev: `kernel/src/syscalls/fs.rs:718`.
- ConsoleInode batched write: `kernel/src/dev/console.rs:84`.
- boot_emit + write_byte: `crates/arch/boot-x86_64/src/lib.rs:72` / `crates/arch/boot-x86_64/src/uart.rs:124`.
- Headless boot: `OXIDE_QEMU_HEADLESS=1 make qemu-x86`.
