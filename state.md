# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `c3c6e90`.

## Headline

**`oxide login:` reaches the user.** Wedge was qemu-mcp's pty consumer, not the kernel. Confirmed by running `OXIDE_QEMU_HEADLESS=1 make qemu-x86` direct: login prompt prints reliably (line 171 of `/tmp/qemu-direct.log`). Earlier "wedge after issue banner" was an artifact of qemu-mcp interfering with chardev draining; nothing in the kernel UART TX path is broken.

## Next concrete problem: no UART RX

Piped `root\n` into stdin → no echo, no `Password:`. COM1 is TX-only — `crates/arch/boot-x86_64/src/uart.rs` has no IER setup, no IRQ4 handler, no path from chardev → console tty input ring. Nothing wires keyboard/serial bytes into the getty's `read()`.

To get past login, need:
1. Enable IER bit 0 (RX-data-available) on COM1 init.
2. Wire IRQ4 (or LAPIC equivalent) into the kernel IRQ dispatcher — handler that drains RBR while LSR.DR=1.
3. Push each byte into the console VT input ring (the path `vt_input_push` or equivalent already exists for virtio-input; reuse it).
4. Make sure `ConsoleInode::read()` blocks/wakes on that ring.

## What shipped this session

1. `bf8e5a5` `fix(irq): ungate LAPIC/GIC bring-up (was hidden by debug-acpi)`.
2. `94ced16` `fix(irq): drop schedule_from_irq from timer ISR` — reverted in `c3c6e90`.
3. `6ac5a90` `refactor(console): batch ONLCR writes`.
4. `32d9a59` `fix(uart): bounded spin in Uart16550::write_byte`.
5. `25fa9a3` `fix(fbcon): disable klog aux sink` — **CAT WEDGE FIX**.
6. `c6a26d0` `diag(uart): UART_DROPS counter`.
7. `9f2fa00` `diag: dtrace framework — structured probes via direct COM1`.
8. `c3c6e90` `fix(irq): restore timer-driven schedule_from_irq in VEC_TIMER`.

## Where boot gets to

```
yo / hi / A / Linux version (CAT smoke)
init-fork-exec works
BARE3-START argv0=/bin/bare3
dl: hello / hello-from-dyn
oxide Linux on /dev/ttyS0
oxide login:                ← prompt visible, kernel waiting on read()
```

## First task next session

Implement UART RX (sequence in §"Next concrete problem"). Pointers:
- Console VT input ring: `grep vt_input_push crates/kernel/tty/src/live.rs`.
- IRQ dispatcher: `crates/arch/hal-x86_64/src/fault.rs` + `crates/kernel/arch-irq/src/lapic.rs`.
- COM1 base: `crates/arch/boot-x86_64/src/uart.rs:19` `COM1: u16 = 0x3f8`.

## Open work (carried)

- Re-enable `fbcon` klog aux sink after debugging `fbcon_flush_pixels` virtio-gpu submit wedge (currently disabled at `kernel/src/lib.rs:662`).
- qemu-mcp pty consumer wedges late writes — separate fix; for now use `OXIDE_QEMU_HEADLESS=1`.
- Real PTRACE_SINGLESTEP — F49-F51 framework.

## Useful pointers

- dtrace framework: `kernel/src/debug_macros.rs:42-94`. Build with `--features debug-boot,debug-trace`. `dtrace!(b"TAG")` / `dtrace!(b"TAG", val)`.
- Probes already in tree: `kernel/src/syscalls/fs.rs:718` (sys_writev), `kernel/src/dev/console.rs:84` (ConsoleInode::write).
- UART bounded spin + drop counter: `crates/arch/boot-x86_64/src/uart.rs:124-150`.
- Headless boot: `OXIDE_QEMU_HEADLESS=1 make qemu-x86` (bypasses qemu-mcp).
