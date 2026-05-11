# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. Latest local commit `bf8e5a5` (LAPIC ungate); push'd to origin.

## What shipped this run

`bf8e5a5` **fix(irq): ungate LAPIC/GIC bring-up (was hidden by debug-acpi)** —
`smoke_device_map_{x86,arm}` was gated `feature = "debug-acpi"`, so in
default builds it never ran. That left `LAPIC_BASE_VA = 0` →
`lapic::timer_periodic()` silently no-op'd → no timer IRQs ever fired
→ cooperative-only scheduling. Removed the gate on the module decl in
`kernel/src/smoke/mod.rs` and on the call sites in `kernel/src/lib.rs`.
The smoke's internal klog probes stay `debug_irq!` / `debug_vmm!`
gated; the device map + LAPIC enable itself is always-on.

Audit of the other 35 `cfg(feature = "debug-*")` gates: all klog-only
or smoke-only (no hidden functionality). Only this one gated real init.

## Open work

### CAT-smoke iteration wedges mid-write of /proc/version (NEW root cause for login hang)

Traced the "boot hangs before `oxide login:`" to the kernel-spawned
ELF smoke in `kernel/src/smoke/elf.rs::build_elf()`. It runs 4
iterations of fork+exec+wait4: YO ("yo\n"), HI ("hi\n"), ECHO
(read+write 1 byte), CAT (open `/proc/version` + read 64 + write).

The boot trace consistently ends at:
```
yo\r\nhi\r\nALinux version 5.15.0-oxide (oxide@build) #1 SMP PREEMPT\r
```
The trailing `\r` (no `\n`) is `VERSION_BODY` (`procfs/mod.rs:269`,
56 bytes ending in `\n`) part-way through ONLCR. CAT's `write(1,buf,56)`
emits 55 bytes then stalls; init never gets to fork the busybox-init
that would print `oxide login:`. Pre-LAPIC-fix behaviour was the
**same** — `bf8e5a5` doesn't regress, the smoke hang is pre-existing.

Hypothesis to test next: write is blocking inside the tty layer
during the final `\n`→`\r\n` ONLCR step, possibly waiting on a
softirq drain that never runs because nothing yields. The fact
that adding any klog probe in sys_writev unblocks it (see prior
state) supports a yield-point gap.

Probe candidates (don't ship gated — instrument and remove):
- count bytes actually written to UART vs requested length;
- log every entry to `console_emit` / `tty::output` ONLCR path;
- check whether the CAT child reaches `sys_close` / `sys_exit` (it
  shouldn't if write hangs — confirm).

### Display + input on GTK (still parked)
User reported: `make qemu-x86` opens GTK, fbcon shows block-glyphs,
keyboard input doesn't propagate. Separate from the serial path;
`OXIDE_QEMU_HEADLESS=1 make qemu-x86` avoids GTK entirely.

### Real PTRACE_SINGLESTEP (parked)
F49–F51 framework exists; SIGSTOP/SIGTRAP race wedges
`ptrace_singlestep_smoke`. rcS still skips it.

## First task next session

```sh
# Confirm CAT child reaches close+exit, or is stuck mid-write.
# Add a one-shot klog::write_raw probe at the head of sys_close and
# sys_exit_group emitting the tid; rebuild; boot; observe whether
# either fires after the truncated VERSION_BODY line.
make x86 && OXIDE_QEMU_HEADLESS=1 make qemu-x86  # serial-only
```

## Useful pointers

- LAPIC ungate diff: commit `bf8e5a5`; `kernel/src/lib.rs:333` + `kernel/src/smoke/mod.rs:8`.
- CAT smoke: `kernel/src/smoke/elf.rs::build_cat_blob()` lines 254–316.
- VERSION_BODY (56 bytes): `kernel/src/procfs/mod.rs:269`.
- sys_writev: `kernel/src/syscalls/fs.rs:718`.
- ConsoleInode::write → klog::write_raw: `kernel/src/dev/console.rs:24`.
- qemu invocation flags: `tools/xtask/src/image_qemu.rs:328`; `OXIDE_QEMU_HEADLESS` env toggles `-display none` vs `gtk`.
