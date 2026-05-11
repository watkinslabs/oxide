# State 2026-05-11

## Branch
`main`. Last merged: PR #1003 (B07: mirror klog to virtio-gpu fbcon).
`make ci` green: both arches, default + debug-all, hosted, spec-lint clean.

## What just shipped (this session)

B07 — kernel-side fbcon klog mirror:
- `klog::set_aux_sink` + multi-sink (BYTE_SINK + AUX_SINK); UART path unchanged.
- `drv-virtio-gpu::post_init::install_scanout_ctx` stashes FB+queues so post-boot flushes work; `fbcon_flush_pixels` issues transfer+flush.
- `fbcon::kernel` Console-in-Spinlock + DIRTY flag drained by the timer-tick hook (avoids 4 MiB+queue-submit per klog event).
- `kernel/lib.rs` wires the fbcon kernel_init after pci_boot and combines UART poll + fbcon drain in one tick hook.

Boot to `oxide Linux on /dev/tty1` verified.

## Open work

**Display rendering not visible** (pre-existing, NOT B07):
- QMP screendump of the 1280x800 virtio-gpu scanout is all-zero pixels even after setup_scanout's gradient + glyph paint.
- setup_scanout commands all ACK NODATA_OK (create/attach/setscanout/transfer/flush = 0x1100).
- Suspects: HHDM not covering alloc_contig PA range, attach-backing mem-entry mis-ordered vs. FB write, or transfer_to_host_2d reading from a different address than we wrote.
- Investigate by: dumping the actual base_pa bytes via `qemu_mem` after setup_scanout, comparing to console.fb glyph data; if pixels are present in RAM but not on the resource, the bug is in attach/transfer; if pixels are absent from RAM, the bug is in the HHDM byte-copy.

**Five over-cap shims** (state from prior session) still need Tier-2 extraction:
- `sys_statx`, `sys_select`, `sys_unshare`, `sys_rt_sigtimedwait`, `sys_setsockopt`

## First task next session

```sh
git checkout -b R79-statx-extract
# kernel/src/syscalls/fs.rs:193 sys_statx. Design vfs::file::statx
# Tier-2 work fn (mask + AT_EMPTY_PATH fd path). Pattern: R77
# (vmm::mremap) for an mm-side extraction.
```

Or pivot:
- B08 fbcon visibility debug (see Open work above)
- virtio-blk driver bring-up
- ARM interactivity debug

## Useful pointers

- Layering spec: `docs/53-syscall-layering.md`
- Reference Tier-3 shim: `sys_read` (`kernel/src/syscalls/mod.rs:32`)
- Reference net Tier-2: `net::sock::bind/connect/sendto/recvfrom/accept/listen`
- Reference mm Tier-2: `vmm::AddressSpace::mremap`
- klog multi-sink: `crates/shared/klog/src/lib.rs`
- fbcon kernel hook: `crates/drivers/fbcon/src/lib.rs` module `kernel`
- Scanout ctx: `crates/drivers/drv-virtio-gpu/src/post_init.rs` `ScanoutCtx`
