# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `25fa9a3`.

## What shipped this run

1. **`bf8e5a5`** `fix(irq): ungate LAPIC/GIC bring-up (was hidden by debug-acpi)`.
2. **`94ced16`** `fix(irq): drop schedule_from_irq from timer ISR (cooperative-only)`.
3. **`6ac5a90`** `refactor(console): batch ONLCR writes — one console_emit per NL-free run`.
4. **`32d9a59`** `fix(uart): bounded spin in Uart16550::write_byte (drop byte on cap)`.
5. **`25fa9a3`** `fix(fbcon): disable klog aux sink — fbcon_flush_pixels wedges boot` ← **CAT WEDGE ROOT CAUSE**.

## CAT smoke wedge — RESOLVED 🎯

Diagnostic emergency UART dump (bypassing BOOT_UART lock) at the head
of `oxide_fault_print_rust` surfaced many silent demand-page #PFs
throughout the smoke. The LAST one before the wedge was kernel-mode
at `ffffffff8000aa18` inside `drv_virtio_gpu::post_init::fbcon_flush_pixels`
(the submit_one virtio queue tail). With the fbcon klog aux sink
disabled, boot now proceeds through:

- All 4 smoke ELF iterations (yo, hi, A=ECHO, /proc/version=CAT)
- Kernel-acceptance smokes (bare3, sem_smoke, msg_smoke, mq_smoke, mprotect_smoke, hello_dyn)
- busybox-init + rcS (4 mounts, hostname, ifconfig)
- Getty's `print_login_issue` ("oxide Linux on /dev/ttyS0")

**Proper fix is pending**: re-debug fbcon_flush_pixels's virtio submit
path. Suspected: missing device-MMIO map for the q0 notify register,
or a softirq re-entry race with the IRQ-tail sti window. The fbcon
aux sink is the wrong design anyway — every klog byte triggering a
full-frame transfer-to-host-2d + resource-flush is wasteful. Should
be coalesced behind a higher-rate timer drain or done lazily.

## Remaining work: getty stalls between issue and login prompt

Boot trace ends at:
```
oxide Linux on /dev/ttyS0\r\n
```
and never reaches `oxide login: `. Getty wrote the issue (4 writev
calls), but its 5th writev (the login prompt) doesn't fire within
180s.

This is the SAME "login prompt timing" issue noted in pre-CAT-fix
state.md — adding any klog probe in `sys_writev` makes the prompt
appear within a few seconds. Acts as a yield point that wakes
getty's next syscall.

### Hypotheses

- Getty parks on a poll/select/tcsetattr between writevs that the
  cooperative scheduler doesn't wake quickly.
- Getty's 5th writev itself goes through some path that needs a
  yield to make progress.
- The bounded UART spin (`32d9a59`) is silently dropping bytes
  of the prompt — verify by adding bound counter, or temporarily
  bumping the cap to a huge number.

### First task next session

```sh
# Confirm getty actually attempts the prompt writev.
# Add klog::write_raw probe inside sys_writev (cfg-gated under
# debug-syscall before commit). If [WV] fires after the issue lines,
# getty IS issuing the prompt syscall but its bytes aren't reaching
# the UART. Check the bounded-spin drop counter.
make x86 && cargo run -p xtask -- image --arch x86_64 --features debug-boot
qemu_start arch=x86_64
qemu_run_until pattern="oxide login:|panic" timeout=180
```

If prompt bytes are dropped: increase the UART spin cap or fix
QEMU's pty consumer. If prompt syscall never fires: investigate
getty's pre-prompt state (termios, fd setup, poll).

## Open work (carried)

- **Proper fbcon fix** — re-enable klog_sink without the wedge.
- **Display + input on GTK** — `OXIDE_QEMU_HEADLESS=1` skips GTK.
- **Real PTRACE_SINGLESTEP** — F49-F51 framework; SIGSTOP/SIGTRAP race.

## Useful pointers

- fbcon aux-sink install site (commented out): `kernel/src/lib.rs:662`.
- fbcon_flush_pixels: `crates/drivers/drv-virtio-gpu/src/post_init.rs:358`.
- fbcon::klog_sink: `crates/drivers/fbcon/src/lib.rs:736`.
- softirq dispatch: `crates/kernel/softirq/src/lib.rs:115`.
- UART bounded spin: `crates/arch/boot-x86_64/src/uart.rs:124-140`.
- sys_writev: `kernel/src/syscalls/fs.rs:718`.
- Headless boot: `OXIDE_QEMU_HEADLESS=1 make qemu-x86`.
