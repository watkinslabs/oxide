# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `c3c6e90`.

## What shipped this session (8 commits)

1. **`bf8e5a5`** `fix(irq): ungate LAPIC/GIC bring-up (was hidden by debug-acpi)`.
2. **`94ced16`** `fix(irq): drop schedule_from_irq from timer ISR` — **REVERTED** in `c3c6e90`; the concern that motivated it was actually the fbcon wedge.
3. **`6ac5a90`** `refactor(console): batch ONLCR writes`.
4. **`32d9a59`** `fix(uart): bounded spin in Uart16550::write_byte`.
5. **`25fa9a3`** `fix(fbcon): disable klog aux sink` — **CAT WEDGE FIX**.
6. **`c6a26d0`** `diag(uart): UART_DROPS counter`.
7. **`9f2fa00`** `diag: dtrace framework — structured probes via direct COM1`.
8. **`c3c6e90`** `fix(irq): restore timer-driven schedule_from_irq in VEC_TIMER`.

## Where boot gets to

```
yo / hi / A / Linux version (CAT smoke)
init-fork-exec works                ← oxide-smokes
BARE3-START argv0=/bin/bare3
dl: hello
hello-from-dyn
\r\r\n
oxide Linux on /dev/ttyS0\r\n      ← getty issue banner
\r\r                                ← getty's next writev (starts but doesn't complete)
```

Pre-session state per old state.md: `oxide login:` was reaching the UART intermittently (timing-sensitive, probes made it appear). After this session's commits, the issue banner appears reliably but the login prompt writev never completes.

## What we still don't know

The dtrace bisect localised the wedge to **inside `boot_emit` after `write_byte(\r)`**, where `write_byte(\n)` never returns. Tested with bounded spin at 10K, 100, AND with NO THRE check at all — wedge persists. Per-byte dtrace markers WITHOUT the kernel build (just probes embedded in boot_emit) didn't emit either (build cache issue? need verification).

Conclusion: the wedge is NOT in the kernel UART path. Either:
- QEMU vCPU stalling on a back-pressured chardev (most likely — `chardev stdio,mux=on` in `tools/xtask/src/image_qemu.rs:364`)
- The kernel IS running, and we're not seeing further bytes because qemu_run_until's pattern matcher gives up before they arrive

## First task next session

Cheap, decisive tests in order:

1. **Switch QEMU `-chardev stdio` to `-chardev socket` or `-chardev pipe`** in `image_qemu.rs:364-365` and re-test. If wedge persists, it's not chardev-back-pressure.

2. **Run with `OXIDE_QEMU_HEADLESS=1`** + a fresh terminal directly running `qemu-system-x86_64` without qemu-mcp (qemu-mcp's GDB attach may itself affect chardev draining):
   ```
   OXIDE_QEMU_HEADLESS=1 make qemu-x86
   ```
   If `oxide login:` appears, the wedge is qemu-mcp's pty consumer, not the kernel.

3. **Force-flush BOOT_UART** every Nth byte by issuing `outb` of `LCR.STKY` + `MCR.LOOP` toggle to force QEMU to pump (drastic, but probes the QEMU vs kernel boundary).

4. **Get qemu_break working** at a known kernel address (e.g. `oxide_irq_dispatch`) so we can interrupt the wedged session and dump RIP. Currently `qemu_interrupt` times out — GDB stub may be unresponsive after long runs but might work fresh.

## Open work (carried)

- **Proper fbcon fix** — re-enable `klog::set_aux_sink(fbcon::kernel::klog_sink)` after debugging `fbcon_flush_pixels` (currently disabled at `kernel/src/lib.rs:662`). That's a separate F-branch.
- **Display + input on GTK** — `OXIDE_QEMU_HEADLESS=1` skips GTK; block-glyphs + dead virtio-input are separate.
- **Real PTRACE_SINGLESTEP** — F49-F51 framework.

## Useful pointers

- **dtrace framework** (permanent debugging tool): `kernel/src/debug_macros.rs:42-94`. Enable with `--features debug-boot,debug-trace`.
- Probes: `kernel/src/syscalls/fs.rs:718` (sys_writev), `kernel/src/dev/console.rs:84` (ConsoleInode::write).
- Add: `dtrace!(b"TAG")` for markers, `dtrace!(b"TAG", val)` for tag+u64.
- UART bounded spin + drop counter: `crates/arch/boot-x86_64/src/uart.rs:124-150`.
- UART_DROPS symbol: `nm <kernel-elf> | grep UART_DROPS`.
- fbcon aux-sink (commented out): `kernel/src/lib.rs:662`.
- QEMU chardev config: `tools/xtask/src/image_qemu.rs:364-365`.
- Headless boot: `OXIDE_QEMU_HEADLESS=1 make qemu-x86`.
