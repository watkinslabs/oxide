# State 2026-05-11

## Branch
`main`. Last merged: PR #1007 (F02: runtime-loadable keymap).
`make ci` green; `cargo run -p xtask -- spec-lint` clean.

## What shipped this run

Linux-style input + display foundation:

- **#1003 B07** — klog multi-sink + virtio-gpu scanout ctx + fbcon Console wiring (mechanism in place).
- **#1004 B08** — fbcon bg-fill + try_lock guards (kernel_init sanity test wrote 6816 white pixels via GPU, proving Console→fb_va→virtio-gpu path is functional).
- **#1005 F00** — `crates/kernel/softirq` Linux-style deferred-work primitive: 32-slot bitmask, `raise()` / `run_pending()`, IN_PROGRESS re-entry guard. Wired into x86 LAPIC + aarch64 GIC timer ISR tails (`sti`/`run_pending`/`cli` envelope; daifclr/daifset on arm). fbcon converted: `klog_sink` raises `Slot::FbconFlush`; handler does the GPU submit from IRQs-on context, no more "submit polls device IRQ while masked" deadlock.
- **#1006 F01** — first softirq consumer. `drv-virtio-input::drain`: pre-fills q0 with `qsize` write-only event-buffer descriptors, installs the softirq handler, kicks notify. Drain walks used ring, parses 8-byte `VirtioInputEvent`, recycles descriptors. `tty::live::input_push_byte` exposes the foreground-VT push. LAPIC VEC_MSI raises `Slot::InputDrain` and drains immediately.
- **#1007 F02** — runtime-loadable keymap. `crates/drivers/drv-virtio-input/src/keymap.rs` parses `/etc/keymap` text at boot, four tables (plain/shift/altgr/shift_altgr), full modifier tracking (SHIFT/CTRL/ALT/ALTGR/META/CAPS/NUM/SCROLL), per-side flags, Linux semantics: Ctrl+letter→ctrl code, AltGr layers, Alt→ESC-prefix Meta. `userspace/keymaps/us.kmap` ships in rootfs as `/etc/keymap` + `/usr/share/keymaps/us.kmap`. 7 hosted parser+translate tests pass. Boot logs `[INFO] keymap loaded: US QWERTY`.

## Verified at boot

- `make ci` green both arches.
- x86 qemu boot reaches `oxide Linux on /dev/tty1` cleanly.
- `[INFO] keymap loaded: US QWERTY` appears post-ext4 mount.
- softirq foundation runs from timer ISR tail and MSI VEC_MSI arm.

## Open work

### rcS pre-existing wedge (B12, parked)
busybox sh emits `can't open '/etc/init.d/rcS': No error information` despite:
- ext4 image *has* `/etc/init.d/rcS` (verified via `debugfs -R "ls /etc/init.d"`)
- Kernel `ext4::rootfs::read_file(b"/etc/init.d/rcS")` returns Some(308 bytes)
- Probes on sys_open / sys_openat / sys_stat / sys_access / sys_faccessat **none** fire with that path

Conclusion: the error path is *inside* busybox sh and never reaches the kernel — likely a libc/stdio routing bug or a path check that fails before the syscall. Next session: probe sys_execve's shebang chain or run busybox sh under ptrace to identify the offending step.

### Display visibility on GTK (parked)
B07/B08 confirmed Console→fb_va→virtio-gpu writes work end-to-end. The boot-time bg paint + sanity glyphs show in QMP screendumps. Live klog stream into fbcon depends on the softirq draining, which now works architecturally — verifying the *rendered* output through a GTK window requires interactive QEMU which the headless qemu-mcp can't drive.

### Serial input doesn't echo (parked)
`qemu_send_serial("echo HELLO")` produces no echo on serial output. tick_poll_uart reads 0x3F8 every timer tick → push_and_wake_fg. Likely a getty-side issue downstream of rcS — addressed when rcS is unblocked.

## Followups ready to stack

- Ship UK/DE/FR/ES keymap files under `userspace/keymaps/`.
- `loadkeys <name>` userspace helper: read `/usr/share/keymaps/<name>.kmap`, install via a `KDSKBENT`-equivalent ioctl on `/dev/console`.
- Mouse pointer: virtio-input EV_REL / EV_ABS handling (drain currently consumes EV_KEY only); GPU cursor sprite.
- B12 deep-trace: instrument sys_execve's shebang resolver to log the exact step that fails for `/etc/init.d/rcS`.

## First task next session

```sh
git checkout -b F03-keymap-locales
# Ship userspace/keymaps/{uk,de,fr,es}.kmap text files. Each is a
# straight rewrite of us.kmap with the locale-specific shift +
# altgr columns filled in. Mechanism is identical — only the table
# bytes change.
```

Alt pivots:
- B12 sys_execve trace (resolves rcS wedge, unblocks getty input testing).
- F03 mouse drain layer (extends virtio-input beyond EV_KEY).
- D-spec for the keymap text format (formalize the `keymap "..."` / `keycode N plain=… shift=…` grammar in `docs/46`).

## Useful pointers

- Softirq API: `crates/kernel/softirq/src/lib.rs` (`Slot`, `raise`, `run_pending`, `set_handler`).
- virtio-input drain: `crates/drivers/drv-virtio-input/src/drain.rs`.
- Keymap: `crates/drivers/drv-virtio-input/src/keymap.rs`; text source `userspace/keymaps/us.kmap`.
- Timer ISR tail (where softirq runs): `crates/kernel/arch-irq/src/lapic.rs` (x86), `src/gic.rs` (arm).
