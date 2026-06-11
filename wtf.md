# WTF validation note

Validated against code, not just the docs.

## Confirmed real

- **VT process-mode fixes are implemented**: deferred `VT_ACTIVATE`, owner validation in `VT_RELDISP`, owner `(vpid, tid)` tracking, and `VT_WAITACTIVE` sleep/wakeup are present in:
  - `crates/drivers/vt/src/lib.rs:344-438`
  - `crates/kernel/syscalls/src/016_ioctl.rs:459-495`
- **fbdev is real, not fake**: `FBIOGET/PUTCMAP`, `FBIOGET_VBLANK`, `FBIO_WAITFORVSYNC`, `FBIOBLANK`, `FBIOPAN_DISPLAY`, and mmap backing are present in:
  - `crates/drivers/fbdev/src/devfs.rs:85-237`
  - `crates/drivers/fbdev/src/lib.rs:235-260`
- **These driver crates exist in the workspace**:
  - `drv-uart-16550`
  - `drv-uart-pl011`
  - `drv-virtio-rng`
  - `drv-ps2-keyboard`
  - `drv-nvme`
  - `drv-ahci`
  - `drv-virtio-vsock`
- **`drv-virtio-console` does not exist**.

## Main mismatch with the docs/changelog

The strongest claim — **“one unified TTY stack, legacy `tty::live` retired”** — does **not** match the code.

`tty::live` is still in live paths:

- `crates/drivers/vt/src/lib.rs:337,395` → `tty::live::set_foreground`
- `crates/drivers/drv-virtio-input/src/drain.rs:143` → `tty::live::input_push_byte`
- `crates/kernel/kmain/src/kmain.rs:386` → `tty::live::set_kbd_sink(...)`

So the truthful status is:

> **partially unified TTY stack, with active `tty::live` dependencies still in the console/input path**

## Additional nuance

- `crates/kernel/console/src/vt_tty.rs` is real progress toward numbered VTs on `TtyStruct`/`NTty`.
- The driver model is also mixed: `drv::model` exists, but the old flat `DriverEntry` / `register` / `probe_all` API still exists in `crates/drivers/drv/src/lib.rs:43-83`.

## Validation commands run

- `cargo test -q -p vt -p fbdev -p fbcon -p drv -p drv-virtio-rng -p drv-ps2-keyboard -p drv-nvme -p drv-ahci -p drv-virtio-vsock -p drv-uart-16550 -p drv-uart-pl011`
- `cargo test -q -p tty -p serialtty`

Both passed.
