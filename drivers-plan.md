# Drivers → fix the issues in drivers.md (Part C)

Authority = `drivers.md` (the audit) ONLY. Do NOT consult or cite `docs/*` —
they may be drifted/inaccurate. Each item below maps 1:1 to a drivers.md
finding. Runs AFTER console-plan.md Part B.

MANDATE: BE Linux, no stubs/fakes/accept-as-no-op. A probe that returns NoMatch,
or an ioctl that fakes success, is NOT done. Each item = its own branch+PR,
host-tested + both-arch boot-verified (`oxide login:` x86 AND arm; real login —
serial + framebuffer — where the change touches console/input), spec-lint clean.

## Order (driver-model first — the audit's blocker #1)

### D1 — `drv` driver model (drivers.md: "drv — Not spec-compliant", blocker #1)
drivers.md: current `drv` is a flat `DriverEntry { name, probe }` with no
lifecycle/remove/sysfs; it should provide `Driver`/`DriverInstance`,
`Device` matching, and distributed (`linkme`) registration with
probe/remove/shutdown symmetry + sysfs publication. Build that; migrate the
live drivers (virtio-blk/net/gpu/input, serial) onto it in lockstep (no
legacy+fallback). Split D1a (model+registration+sysfs) / D1b (migrate) if big.

### D2 — kill the probe stubs (drivers.md: blocker #3)
`drv-virtio-gpu::probe()` and `drv-virtio-input::probe()` return
`drv::Error::NoMatch`; bring-up currently rides boot-glue. Make them real
`probe()` impls on the D1 model that match the device + bind a DriverInstance.
Gate: gpu scanout + keyboard still work (kbd-login smoke).

### D3 — missing mandatory drivers (drivers.md: "Missing", blocker #2)
Each a real driver with real I/O + a boot smoke (add the QEMU device):
- `drv-virtio-rng` (absent) — entropy → /dev/hwrng + kernel RNG.
- `drv-virtio-console` (absent) — virtio-serial ports → /dev/hvc*.
- `drv-virtio-vsock` (absent) — AF_VSOCK transport.
- `drv-ps2-keyboard` (absent) — i8042 PS/2 (x86; #[cfg]-gate so arm still builds).
- `drv-nvme` (absent) — NVMe block device.
- `drv-ahci` (absent) — AHCI/SATA block device.

### D4 — UART split drivers (drivers.md: uart-16550 + uart-pl011 "Partial")
Both exist only inside `drv-serial`, not as their own driver crates with the
full lifecycle/remove path. Extract `drv-uart-16550` + `drv-uart-pl011` as
proper driver crates; `drv-serial` becomes shared serial-core. Keep the console
serial-login path working.

### D5 — DRM/KMS UAPI (drivers.md: drm "Far from compliance")
drivers.md: GETRESOURCES counts only; GETCRTC/GETCONNECTOR/GETENCODER return
EINVAL; ATOMIC mostly accepts only TEST_ONLY. Implement the real modeset UAPI
(resources, crtc/connector/encoder/plane, mode get/set, dumb-buffer
create/map/destroy, atomic commit) against the virtio-gpu backend.

### D6 — fbdev full semantics (drivers.md: fbdev "Partial")
drivers.md: mode changes, pan, cmap, vsync, blanking are reduced to
accept-current/no-op/immediate-return. Implement real FBIOPUTCMAP/GETCMAP,
FBIOPAN_DISPLAY, FBIO_WAITFORVSYNC, FBIOBLANK, FBIOPUT_VSCREENINFO mode change —
or honest EINVAL for genuinely-unsupported modes, never fake success.

### D7 — block/net driver-model + lifecycle (drivers.md: virtio-blk/net "Substantial, not complete")
Spec-complete probe/remove + sysfs publication; remove the v1/phased
single-buffer/shared-cache shortcuts the audit calls out; full ring semantics.

## Notes (from drivers.md)
- Driver-model (D1) first — D2-D7 bind to it; don't build on the flat list then re-migrate.
- "Current tests are necessary but not sufficient" (blocker #5): add tests that
  exercise the Linux-visible behavior, not just encode/layout/state machines.
- Lockstep: every driver builds + boots on BOTH arches.
- (fbcon / vt "substantial, not complete" in drivers.md overlap console-plan
  Part A/B work; revisit only for gaps Part B didn't close.)
