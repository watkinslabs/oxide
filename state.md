# State 2026-05-10

## Branch

`F156-mm-linux-conformance` — PR #920 against `main`. ~28 commits, all pushed.

## What's working end-to-end

- x86_64 boots through Limine → kernel → busybox-init → getty → login.
- `oxide login: root` → `Welcome to oxide.` → `/ # echo hello` → `hello`.
- All virtio drivers initialize: blk, net, gpu, input (kbd + mouse).
- `virtio-gpu scanout: 1280x800 painted` (host-side commands all `RESP_OK_NODATA`).
- Hosted tests: 1015 pass, 0 fail. Both arches build, spec-lint clean.

## Last-session fixes (relevant SHAs)

- `de9b6a6` — boot init user stack moved off 0x501000 (was chopping busybox `.text`); root cause of session 55's `0x4250df` red herring.
- `c423ac2` — kernel heap 16→32 MiB; panic handler now renders `format_args!` so OOM prints actual size.
- `3472310` — rootfs `mkfs.ext4 -b 4096 -F count=16` so debugfs `ln` doesn't run out of dir space silently dropping `/bin/login` etc.
- `7a33d0a` — virtio vendor-id typo `0x1A` → `0x1AF4` (was wedging GPU + input + early-net).
- `20eaad9` — virtio-gpu single-mem-entry `RESOURCE_ATTACH_BACKING` (was overflowing 4 KiB cmd_buf w/ 16 KiB of mem-entries) + xtask + qemu-mcp `-vga none`.
- `409dfb3` — re-enable virtio-input cleanly.

## Open / next session

1. **GTK display still black via qemu-mcp.** xtask launcher has `-vga none` (`20eaad9`); qemu-mcp `server.py` got the same edit but the running MCP server hadn't reloaded. Verify on next-session restart with `qemu_screen` or just `cargo run -p xtask -- qemu --arch x86_64` and eyeball the painted scanout. If still black after the qemu-mcp restart, the stdvga isn't the culprit — chase the virtio-gpu→GTK binding next.
2. **`/etc/init.d/rcS` Exec format error** — script lacks `#!` handling in our execve; busybox doesn't retry via shell, so rcS never mounts /proc, sets hostname, brings up loopback. Pick: handle shebang in execve, or have busybox-init fall back to /bin/sh.
3. **`login: can't change directory to '/root'`** — rootfs missing `/root` dir; xtask FHS list claims to mkdir it, check why it didn't land.
4. **aarch64 end-to-end** — builds clean, never booted to login on ARM. `make qemu-arm` + login test before claiming F156 done.

## First task next session

```
cargo run -p xtask -- qemu --arch x86_64
# log in as root, eyeball GTK window
# if blank, diff virtio-gpu paint vs known-good ref kernel
```

If GTK is fine, switch to `make qemu-arm` parity.
