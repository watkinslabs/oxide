# Driver status audit

## Verdict

Not 100% Linux compliant. Current driver code is a mix of solid infrastructure, some usable runtime engines, and several explicit stubs/placeholders. The frozen specs in `docs/35-drivers.md` and `docs/45-50` describe a much larger Linux-equivalent surface than the code currently implements.

The driver crate tests pass, but they are mostly hosted unit tests for layout/encoding/state transitions; they do not demonstrate full Linux-visible behavior.

## Mandatory drivers (`docs/35§4`)

| Driver | Status | Finding | Evidence |
|---|---|---|---|
| `drv-uart-16550` | **Partial** | Implemented only as part of `drv-serial`, not as its own crate; provides console TX/RX, but not the full split driver model from `35§2-5`. | `crates/drivers/drv-serial/src/lib.rs` |
| `drv-uart-pl011` | **Partial** | Same issue as 16550: functional pieces exist inside `drv-serial`, but not as a separate Linux-style driver crate with full lifecycle/sysfs/remove paths. | `crates/drivers/drv-serial/src/lib.rs` |
| `drv-virtio-blk` | **Substantial, not complete** | Real runtime engine exists, but it is kernel-glue driven rather than a spec-complete `drv-*` probe/remove driver. Compliance gaps remain around driver-model integration, lifecycle, sysfs publication, and full Linux block-driver expectations. | `crates/drivers/drv-virtio-blk/src/modern.rs`, `crates/drivers/drv-virtio-blk/src/tests.rs` |
| `drv-virtio-net` | **Substantial, not complete** | Modern and legacy runtime code exists, including TX/RX handling, but code is explicitly phased/v1, uses simplified single-buffer/shared-cache paths, and is not yet the full Linux-equivalent driver surface. | `crates/drivers/drv-virtio-net/src/modern.rs`, `crates/drivers/drv-virtio-net/src/legacy.rs` |
| `drv-virtio-rng` | **Missing** | No crate present. | `crates/drivers/` tree |
| `drv-virtio-console` | **Missing** | No crate present. | `crates/drivers/` tree |
| `drv-virtio-vsock` | **Missing** | No crate present. | `crates/drivers/` tree |
| `drv-virtio-input` | **Partial** | The crate has constants, keymap work, event-queue plumbing, and evdev helpers, but `probe()` still returns `NoMatch`, ioctl dispatch is mostly admit/ack behavior, and the public driver surface is not yet spec-complete. | `crates/drivers/drv-virtio-input/src/lib.rs`, `src/devfs.rs`, `src/drain.rs`, `src/evdev_queue.rs` |
| `drv-virtio-gpu` | **Partial** | Good protocol constants/encoders and boot scanout bring-up exist, but `probe()` still returns `NoMatch` and the crate is not yet a full Linux-compliant virtio-gpu driver. | `crates/drivers/drv-virtio-gpu/src/lib.rs`, `src/post_init.rs` |
| `drv-nvme` | **Missing** | No crate present. | `crates/drivers/` tree |
| `drv-ahci` | **Missing** | No crate present. | `crates/drivers/` tree |
| `drv-ps2-keyboard` | **Missing** | No crate present. | `crates/drivers/` tree |

## Supporting driver-stack crates

| Crate | Status | Finding | Evidence |
|---|---|---|---|
| `drv` | **Not spec-compliant** | The frozen spec requires `Driver`/`DriverInstance`, `Device` matching, and `linkme` registration. Current code is a flat `DriverEntry { name, probe }` list with no lifecycle/remove/sysfs publication. | `crates/drivers/drv/src/lib.rs`, `docs/35-drivers.md` |
| `pci` | **Useful infrastructure** | Enumeration/capability/BAR parsing is present, but this is bus infrastructure, not end-state Linux PCI driver compliance. | `crates/drivers/pci/src/lib.rs` |
| `virtio` | **Useful infrastructure** | Shared queue/PCI/blk/net helpers exist; this is transport support, not a finished driver surface by itself. | `crates/drivers/virtio/src/*.rs` |
| `drm` | **Far from Linux DRM/KMS compliance** | Only a small subset of ioctls behaves meaningfully. Many paths are fallback/placeholder behavior: `GETRESOURCES` counts only, `GETCRTC/GETCONNECTOR/GETENCODER` return `EINVAL`, `ATOMIC` mostly accepts only trivial `TEST_ONLY`. | `crates/drivers/drm/src/lib.rs`, `src/node.rs` |
| `fbdev` | **Partial** | `read`/`write`/`mmap` and a handful of `FBIO*` ioctls exist, but mode changes, pan, cmap, vsync, and blanking are reduced to accept-current/no-op/immediate-return behavior rather than full Linux semantics. | `crates/drivers/fbdev/src/lib.rs`, `src/devfs.rs` |
| `fbcon` | **Substantial, not complete** | The console renderer is real and fairly advanced, with glyph rendering, scroll, colors, UTF-8, and per-VT kernel plumbing. It still falls short of the full spec surface in `docs/49`: OSC/DCS/xterm parity, all console features, and the full runtime font/terminal stack are not all present in the current code. | `crates/drivers/fbcon/src/lib.rs`, `src/kernel.rs`, `src/font.rs`, `src/vcrender.rs` |
| `vt` | **Substantial, not complete** | VT allocation/switching, key modes, lock switching, and process-controlled switching exist, but the full Linux `kd.h`/`vt.h`/keyboard surface from `docs/50` is not implemented end to end. | `crates/drivers/vt/src/lib.rs` |

## Largest blockers to Linux compliance

1. **Driver-model mismatch**: the code does not yet implement the frozen `35` driver contract (`Driver`, `DriverInstance`, `Device`, distributed registration, probe/remove/shutdown symmetry, sysfs publication).
2. **Missing mandatory drivers**: `virtio-rng`, `virtio-console`, `virtio-vsock`, `nvme`, `ahci`, and `ps2-keyboard` are absent.
3. **Probe stubs remain**: `drv-virtio-gpu::probe()` and `drv-virtio-input::probe()` still return `drv::Error::NoMatch`.
4. **DRM/fbdev userspace UAPI is incomplete**: current implementations are enough for limited probing and boot-console work, not for Linux-equivalent compositor/libdrm/Xorg behavior.
5. **Current tests are necessary but not sufficient**: they validate encoders/layouts/state machines, not the full Linux-visible contracts promised by the frozen specs.

## Bottom line

Current status is **partial implementation, not Linux-complete drivers**. The most mature pieces are `drv-serial`, `drv-virtio-blk`, `drv-virtio-net`, `fbcon`, and `vt`. The biggest gaps are the missing mandatory drivers, the incomplete `drv` model, and the still-incomplete Linux UAPIs around DRM/fbdev/input/gpu.
