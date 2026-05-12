# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `4fe6ba0`.

## Headline

**`oxide login:` reaches the user.** The earlier "wedge after issue banner" was qemu-mcp's pty consumer interfering with chardev draining, not the kernel. Run `OXIDE_QEMU_HEADLESS=1 make qemu-x86` direct to verify — prompt prints reliably (line 171 of /tmp/qemu-h.log).

## Next concrete problem: timer ticks not firing post-handoff

Typed input (`root\n` via piped stdin) is not getting echoed/processed. Investigation:

- LAPIC timer is re-armed in `kernel/src/smoke/elf.rs:624` (`timer_periodic(1_000_000)`) before PID 1 starts.
- Hook is installed via `arch_irq::set_tick_poll_hook(tick_poll_combined)` in `kernel/src/lib.rs:519`.
- Hook chain: timer IRQ vec 0x40 in `crates/kernel/arch-irq/src/lapic.rs:107` → `crate::tick_poll()` → `tick_poll_combined` → `tty::live::tick_poll_uart` (`crates/kernel/tty/src/live.rs:181`).
- Empirical test (heartbeat emit every 16384 calls inside `tick_poll_uart`): **zero** beats observed in a 40s run after `oxide login:` printed. → `tick_poll_uart` is never called after userspace starts.

This means timer IRQs stop firing after the boot smokes (or fire only the 1–2 times seen in `lapic-self-fire pre=1 post=2 delta=1` log). The re-arm at `smoke/elf.rs:624` may not stick — likely culprits:

1. LVT timer write-volatile at `lapic.rs:293` (`0x40 | (1 << 17)`) needs the LAPIC SVR enabled bit; verify `enable()` ran and didn't get reset.
2. IDT entry for vec 0x40 may be missing after late-boot reinstall of GDT/IDT (CR-saving paths in `crates/arch/hal-x86_64/src/regs.rs`).
3. iretq frame may have IF=0 in userspace mode — though `sti` is called and we see one tick.
4. Periodic mode but ICR=0 after first fire — the initial count register needs to be written *after* LVT_TIMER per Intel SDM; ours writes it after, which is correct, but a single zero-write would stop it.

### First task next session

Re-add a heartbeat probe (kernel/src/dev/console.rs or a tiny dedicated dbg call in lapic.rs at vec=0x40) that fires per IRQ entry **before** any hook runs. That isolates "no IRQs at all" vs "IRQs fire but hook is null/wrong". Once isolated:

- If IRQs aren't firing: check IDT entry for 0x40 in `crates/arch/hal-x86_64/src/idt.rs` after busybox starts; check LAPIC LVT_TIMER register read-back from a controlled probe; check timer_periodic return value at `smoke/elf.rs:624` (currently `let _ =`).
- If IRQs fire but tick_poll_combined isn't reached: check `TICK_POLL_HOOK` atomic load.
- Once tick_poll_uart fires, RX should follow (LSR.DR test is straightforward).

## Commits this session

1. `bf8e5a5` `fix(irq): ungate LAPIC/GIC bring-up (was hidden by debug-acpi)`.
2. `94ced16` reverted in `c3c6e90`.
3. `6ac5a90` `refactor(console): batch ONLCR writes`.
4. `32d9a59` `fix(uart): bounded spin in Uart16550::write_byte`.
5. `25fa9a3` `fix(fbcon): disable klog aux sink` — **CAT WEDGE FIX**.
6. `c6a26d0` `diag(uart): UART_DROPS counter`.
7. `9f2fa00` `diag: dtrace framework`.
8. `c3c6e90` `fix(irq): restore timer-driven schedule_from_irq`.
9. `4fe6ba0` `doc(state): oxide login: reaches user`.
10. (uncommitted) `tools/xtask/src/image_qemu.rs` chardev fix: drop `mux=on` under `OXIDE_QEMU_HEADLESS=1` (mux multiplexer was swallowing piped stdin).

## Useful pointers

- dtrace framework: `kernel/src/debug_macros.rs:42-94`. Build with `--features debug-boot,debug-trace`. `dtrace!(b"TAG")` / `dtrace!(b"TAG", val)`.
- LAPIC timer setup: `crates/kernel/arch-irq/src/lapic.rs:287` `timer_periodic`.
- Timer ISR vec 0x40: `crates/kernel/arch-irq/src/lapic.rs:107`.
- Userspace timer re-arm (post-smoke): `kernel/src/smoke/elf.rs:624`.
- tick_poll_uart: `crates/kernel/tty/src/live.rs:181`.
- TICK_POLL_HOOK install: `kernel/src/lib.rs:519` → `tick_poll_combined` at 840.
- Headless boot: `OXIDE_QEMU_HEADLESS=1 make qemu-x86`. Feed stdin via `printf 'root\n' | OXIDE_QEMU_HEADLESS=1 make qemu-x86`.

## Open work (carried)

- Re-enable `fbcon` klog aux sink after debugging `fbcon_flush_pixels` virtio-gpu submit wedge (currently disabled at `kernel/src/lib.rs:662`).
- qemu-mcp pty consumer wedges late writes — separate fix; use `OXIDE_QEMU_HEADLESS=1` to bypass.
- Real PTRACE_SINGLESTEP — F49-F51 framework.
