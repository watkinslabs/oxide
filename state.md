# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `6ac5a90`.

## What shipped this run

1. **`bf8e5a5`** `fix(irq): ungate LAPIC/GIC bring-up (was hidden by debug-acpi)`.
2. **`94ced16`** `fix(irq): drop schedule_from_irq from timer ISR (cooperative-only)`.
3. **`6ac5a90`** `refactor(console): batch ONLCR writes — one console_emit per NL-free run`.

## CAT smoke wedge — investigation log

Reliable boot stop at the byte after `PREEMPT\r`. The trailing `\r` is
byte 1 of the ONLCR `\n → \r\n` expansion for the final NL of
`VERSION_BODY`. Subsequent `\n` byte never emits.

**Unwedge confirmed**: adding `klog::write_raw(b"[CLOSE]\\n")` /
`b"[EXIT]\\n"` to `sys_close` / `sys_exit_group` head lets boot proceed
past CAT to `[CLOSE]\n[EXIT]\n[EXIT]`.

**Hypotheses tried and rejected this session**:

| Theory | Test | Result |
|---|---|---|
| %rbx clobber across syscall | Audited `crates/arch/hal-x86_64/src/syscall.rs:123,169` | Save+restore present |
| Per-byte BOOT_UART lock contention | Batched ONLCR (`6ac5a90`) | Same hang byte-exact |
| Timer-IRQ→schedule corruption | `94ced16` neutered schedule_from_irq | Hang persists |
| Smoke iter 4 (CAT) reorder | Removed iter 4 from `build_elf` | Wedged EARLIER on HI |
| 16550 FIFO back-pressure | Tried FCR=0 (FIFO off) | Same hang byte-exact (reverted) |

**Not yet tried**:
- Timing inside `console_emit` for the last call: instrument `klog::write_raw` with a per-call byte-count probe to see how many UART writes actually happen before the spin.
- GDB break at `Uart16550::write_byte` mid-hang (`qemu_break` + `qemu_regs`) — see whether RIP is in the THRE spin or somewhere else entirely.
- Step `sys_writev` with a probe at exit (just before return-to-user) — does the syscall return? If yes, wedge is in user mode (and CAT user code post-write is `mov` + `syscall close`, so wedge would be at the second syscall entry). If no, wedge is in the kernel write path.

That last one (probe at sys_writev exit) cleanly bisects user vs
kernel. Should be the first move next session.

## First task next session

```rust
// kernel/src/syscalls/fs.rs::sys_writev, just before the final return:
klog::write_raw(b"[WV_OUT]\n");
return n;
```

Then boot. If `[WV_OUT]` shows after `...PREEMPT\r` (still mid-line),
sys_writev returned but next syscall-entry from user wedges → look
at syscall entry asm. If no `[WV_OUT]`, sys_writev itself wedges →
look at the kernel write path (probably inside ConsoleInode::write
or boot_emit's spin).

Remember `[WV_OUT]` is a band-aid probe — gate it under
`debug-syscall` per R06 before any commit, or revert after diagnosis.

## Open work (carried)

- **Init silent post-CAT** — addressed after CAT wedge.
- **Display + input on GTK** — `OXIDE_QEMU_HEADLESS=1` skips GTK;
  block-glyphs + dead virtio-input are separate.
- **Real PTRACE_SINGLESTEP** — F49-F51 framework; SIGSTOP/SIGTRAP race.

## Useful pointers

- UART write_byte spin: `crates/arch/boot-x86_64/src/uart.rs:124-134`.
- Syscall asm save/restore (rbx confirmed): `crates/arch/hal-x86_64/src/syscall.rs:123,169`.
- ConsoleInode batched write: `kernel/src/dev/console.rs:84`.
- sys_writev: `kernel/src/syscalls/fs.rs:718`.
- CAT smoke at `kernel/src/smoke/elf.rs:254` (build_cat_blob); fd→`%rbx` at offset 16.
- VERSION_BODY (56 bytes): `kernel/src/procfs/mod.rs:269`.
- Headless boot: `OXIDE_QEMU_HEADLESS=1 make qemu-x86`.
