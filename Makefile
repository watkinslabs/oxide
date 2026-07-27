# oxide2 — convenience wrapper around `cargo run -p xtask`.
# All real logic lives in `tools/xtask`; this file is just shorter
# names + grouped targets for humans.

CARGO    ?= cargo
XTASK    := $(CARGO) run -p xtask --
FEATURES ?=

# ---- rootfs-cache bounding -------------------------------------------------
# target/rootfs-cache holds one content-addressed root+home image pair
# (~426MB) per distinct boot-config. On the `make qemu-*` path it was never
# auto-trimmed (only `make clean-builds` did, which nothing invoked), so it grew
# unbounded (observed 33G / 324 images). The qemu targets below run this trim
# BEFORE building — it always fires even when the previous boot was Ctrl-C'd —
# keeping the ROOTFS_CACHE_KEEP most-recent pairs. `--keep` is set high so ONLY
# the image cache is trimmed, never build namespaces (use `make clean-builds`
# for those). Reuses the guarded LRU trim in `xtask gc`.
# Override the working-set size, e.g.:  make qemu-x86 ROOTFS_CACHE_KEEP=10
ROOTFS_CACHE_KEEP ?= 6
TRIM_ROOTFS_CACHE  = $(XTASK) gc --keep 1000000 --cache-keep $(ROOTFS_CACHE_KEEP)

# `make build`           — kernel libs + bin shims, both arches, default features.
# `make x86 / arm`       — single arch.
# `make *-debug`         — same with `--features debug-all`.
# `make test`            — hosted unit tests (no kernel target).
# `make lint`            — `xtask spec-lint`.
# `make stats`           — `xtask stats` (use `STATS_ARGS=...` for flags).
# `make ci`              — what PR gate runs: spec-lint, test, both arches default + debug-all.
# `make qemu-x86 / qemu-arm` — boot under QEMU with `--features debug-all`.
# `make qemu-mcp`        — print the MCP tool list (interactive QEMU debug).
# `make artifacts`       — export stable packaging artifacts to target/artifacts.
# `make clean`           — `cargo clean`.

.PHONY: all build x86 arm \
        build-debug x86-debug arm-debug \
        test lint stats ci \
        qemu-x86 qemu-arm qemu-x86-debug qemu-arm-debug qemu-mcp \
        qemu-x86-grub \
        smoke-af-packet-diff-x86 smoke-af-packet-diff-arm smoke-af-packet-diff \
        smoke-wait-diff-x86 smoke-wait-diff-arm smoke-wait-diff wait-diff-selftest \
        frame-gate frame-gate-x86 frame-gate-arm \
        clean clean-builds help

all: build

# ---- builds ---------------------------------------------------------------

build: x86 arm

x86:
	$(XTASK) kernel --arch x86_64  $(if $(FEATURES),--features $(FEATURES),)

arm:
	$(XTASK) kernel --arch aarch64 $(if $(FEATURES),--features $(FEATURES),)

build-debug: x86-debug arm-debug

x86-debug:
	$(XTASK) kernel --arch x86_64  --features debug-all

arm-debug:
	$(XTASK) kernel --arch aarch64 --features debug-all

# ---- checks ---------------------------------------------------------------

test:
	$(XTASK) test

lint:
	$(XTASK) spec-lint

stats:
	$(XTASK) stats $(STATS_ARGS)

# Mirror of the PR-time gate per `docs/40§2`: spec-lint clean, hosted tests
# green, both arches build default AND with debug-all on.
ci: lint test build build-debug

# ---- qemu -----------------------------------------------------------------

# `debug-boot` is required for the boot UART sink to install (without
# it, klog drops everything — including /dev/console writes from
# userspace, so login never appears). It also enables operational-
# pulse log lines like `[INFO] boot: kernel ready, halting` so you
# can tell the kernel is alive while waiting for the login prompt.
# `debug-sched` is intentionally excluded — that's the per-syscall
# trace flood. FEATURES=... appends extras (e.g. FEATURES=debug-irq).
comma := ,
QEMU_FEATURES_X86 := debug-boot$(if $(FEATURES),$(comma)$(FEATURES),)
QEMU_FEATURES_ARM := debug-boot$(if $(FEATURES),$(comma)$(FEATURES),)

# SMP CPU count for qemu (default 1). The boot-smoke gate sets SMP=2 so
# AP bring-up + the periodic load balancer are exercised every push.
SMP ?= 1

# Limine is gone on BOTH arches — x86 boots via the GRUB multiboot2 path
# and aarch64 via the GRUB EFI-stub `linux` path (`xtask grub` dispatches
# on --arch). The old `xtask qemu` (Limine ISO + check_vendor for
# vendor/limine/*) is dead. `cmd_grub` takes --arch/--smp/--features.
qemu-x86:
	$(TRIM_ROOTFS_CACHE)
	$(XTASK) grub --arch x86_64  --smp $(SMP) --features "$(QEMU_FEATURES_X86)"

qemu-arm:
	$(TRIM_ROOTFS_CACHE)
	$(XTASK) grub --arch aarch64 --smp $(SMP) --features "$(QEMU_FEATURES_ARM)"

# GRUB self-bootstrap path: build a GRUB ISO that multiboot2-loads the
# kernel directly (replacing Limine) and boot it. WIP — see F372.
qemu-x86-grub:
	$(TRIM_ROOTFS_CACHE)
	$(XTASK) grub --arch x86_64 --smp $(SMP)

# Same but with `--features debug-all` (every syscall trace + LAPIC
# tick + boot-pulse log). Useful for kernel debugging; not what you
# want when just trying to log in and use it.
qemu-x86-debug:
	$(TRIM_ROOTFS_CACHE)
	$(XTASK) grub --arch x86_64  --features debug-all

qemu-arm-debug:
	$(TRIM_ROOTFS_CACHE)
	$(XTASK) grub --arch aarch64 --features debug-all

# Boot-smoke gates — run kernel under qemu headless and wait for
# `oxide login:` on serial within SMOKE_TIMEOUT seconds (default
# 600). PR-time CI uses these; locally a 30-60s dev-box boot is
# typical, but TCG on a hosted runner needs 5-15min, hence the
# higher default. Override via `make smoke-x86 SMOKE_TIMEOUT=900`.
smoke-x86: x86
	./tools/boot-smoke.sh x86 $(SMOKE_TIMEOUT)

smoke-arm: arm
	./tools/boot-smoke.sh arm $(SMOKE_TIMEOUT)

smoke: smoke-x86 smoke-arm

# Stack-frame size gate (Linux CONFIG_FRAME_WARN; `skizm.md` Step 6). Reads
# prologue reservations out of an already-built kernel ELF, so it needs no
# rebuild and no extra codegen flags. Ratcheted: frames already over the
# ceiling are recorded in tools/frame-size-baseline-<arch>.txt and tolerated at
# or below their recorded size; a NEW or WORSENED frame fails.
# Requires the artifacts to exist: `make x86 && cargo run -p xtask -- artifacts
# --arch x86_64` (building alone does NOT export to target/artifacts).
frame-gate-x86:
	python3 tools/frame-size-gate.py target/artifacts/x86_64/kernel.elf \
	  --baseline tools/frame-size-baseline-x86_64.txt
frame-gate-arm:
	python3 tools/frame-size-gate.py target/artifacts/aarch64/kernel.elf \
	  --baseline tools/frame-size-baseline-aarch64.txt
frame-gate: frame-gate-x86 frame-gate-arm

DRIVER_PATH_SMOKE_TIMEOUT ?= 900
smoke-driver-path-x86: x86
	./tools/boot-smoke-driver-path.sh x86 $(DRIVER_PATH_SMOKE_TIMEOUT)
smoke-driver-path-arm: arm
	./tools/boot-smoke-driver-path.sh arm $(DRIVER_PATH_SMOKE_TIMEOUT)
smoke-driver-path: smoke-driver-path-x86 smoke-driver-path-arm

SYSBLOCK_SMOKE_TIMEOUT ?= 900
smoke-sysblock-x86: x86
	./tools/boot-smoke-sysblock.sh x86 $(SYSBLOCK_SMOKE_TIMEOUT)
smoke-sysblock-arm: arm
	./tools/boot-smoke-sysblock.sh arm $(SYSBLOCK_SMOKE_TIMEOUT)
smoke-sysblock: smoke-sysblock-x86 smoke-sysblock-arm

SYSBUS_BIND_SMOKE_TIMEOUT ?= 600
smoke-sysbus-bind-x86: x86
	./tools/boot-smoke-sysbus-bind.sh x86 $(SYSBUS_BIND_SMOKE_TIMEOUT)
smoke-sysbus-bind-arm: arm
	./tools/boot-smoke-sysbus-bind.sh arm $(SYSBUS_BIND_SMOKE_TIMEOUT)
smoke-sysbus-bind: smoke-sysbus-bind-x86 smoke-sysbus-bind-arm

SHUTDOWN_SMOKE_TIMEOUT ?= 600
smoke-shutdown-x86: x86
	./tools/boot-smoke-shutdown.sh x86 $(SHUTDOWN_SMOKE_TIMEOUT)
smoke-shutdown-arm: arm
	./tools/boot-smoke-shutdown.sh arm $(SHUTDOWN_SMOKE_TIMEOUT)
smoke-shutdown: smoke-shutdown-x86 smoke-shutdown-arm

VIRTIO_SND_MULTIDEV_SMOKE_TIMEOUT ?= 900
smoke-virtio-snd-multidev-x86: x86
	./tools/boot-smoke-virtio-snd-multidev.sh x86 $(VIRTIO_SND_MULTIDEV_SMOKE_TIMEOUT)
smoke-virtio-snd-multidev-arm: arm
	./tools/boot-smoke-virtio-snd-multidev.sh arm $(VIRTIO_SND_MULTIDEV_SMOKE_TIMEOUT)
smoke-virtio-snd-multidev: smoke-virtio-snd-multidev-x86 smoke-virtio-snd-multidev-arm

VIRTIO_GPU_MULTIDEV_SMOKE_TIMEOUT ?= 900
smoke-virtio-gpu-multidev-x86: x86
	./tools/boot-smoke-virtio-gpu-multidev.sh x86 $(VIRTIO_GPU_MULTIDEV_SMOKE_TIMEOUT)
smoke-virtio-gpu-multidev-arm: arm
	./tools/boot-smoke-virtio-gpu-multidev.sh arm $(VIRTIO_GPU_MULTIDEV_SMOKE_TIMEOUT)
smoke-virtio-gpu-multidev: smoke-virtio-gpu-multidev-x86 smoke-virtio-gpu-multidev-arm

VIRTIO_NET_MULTIDEV_SMOKE_TIMEOUT ?= 900
smoke-virtio-net-multidev-x86: x86
	./tools/boot-smoke-virtio-net-multidev.sh x86 $(VIRTIO_NET_MULTIDEV_SMOKE_TIMEOUT)
smoke-virtio-net-multidev-arm: arm
	./tools/boot-smoke-virtio-net-multidev.sh arm $(VIRTIO_NET_MULTIDEV_SMOKE_TIMEOUT)
smoke-virtio-net-multidev: smoke-virtio-net-multidev-x86 smoke-virtio-net-multidev-arm

VIRTIO_BLK_MULTIDEV_SMOKE_TIMEOUT ?= 900
smoke-virtio-blk-multidev-x86: x86
	./tools/boot-smoke-virtio-blk-multidev.sh x86 $(VIRTIO_BLK_MULTIDEV_SMOKE_TIMEOUT)
smoke-virtio-blk-multidev-arm: arm
	./tools/boot-smoke-virtio-blk-multidev.sh arm $(VIRTIO_BLK_MULTIDEV_SMOKE_TIMEOUT)
smoke-virtio-blk-multidev: smoke-virtio-blk-multidev-x86 smoke-virtio-blk-multidev-arm

STORAGE_MULTICTRL_SMOKE_TIMEOUT ?= 900
smoke-storage-multictrl-x86: x86
	./tools/boot-smoke-storage-multictrl.sh x86 $(STORAGE_MULTICTRL_SMOKE_TIMEOUT)
smoke-storage-multictrl-arm: arm
	./tools/boot-smoke-storage-multictrl.sh arm $(STORAGE_MULTICTRL_SMOKE_TIMEOUT)
smoke-storage-multictrl: smoke-storage-multictrl-x86 smoke-storage-multictrl-arm

USERSPACE_SEAT_SMOKE_TIMEOUT ?= 900
smoke-userspace-seat-x86: x86
	./tools/boot-smoke-userspace-seat.sh x86 $(USERSPACE_SEAT_SMOKE_TIMEOUT)
smoke-userspace-seat-arm: arm
	./tools/boot-smoke-userspace-seat.sh arm $(USERSPACE_SEAT_SMOKE_TIMEOUT)
smoke-userspace-seat: smoke-userspace-seat-x86 smoke-userspace-seat-arm

DRM_RENDER_SMOKE_TIMEOUT ?= 900
smoke-drm-render-x86: x86
	./tools/boot-smoke-drm-render.sh x86 $(DRM_RENDER_SMOKE_TIMEOUT)
smoke-drm-render-arm: arm
	./tools/boot-smoke-drm-render.sh arm $(DRM_RENDER_SMOKE_TIMEOUT)
smoke-drm-render: smoke-drm-render-x86 smoke-drm-render-arm

AF_PACKET_DIFF_SMOKE_TIMEOUT ?= 900
smoke-af-packet-diff-x86:
	./tools/boot-smoke-af-packet-diff.sh x86 $(AF_PACKET_DIFF_SMOKE_TIMEOUT)
smoke-af-packet-diff-arm:
	./tools/boot-smoke-af-packet-diff.sh arm $(AF_PACKET_DIFF_SMOKE_TIMEOUT)
# Recursive makes keep the two boots sequential even under a top-level -j.
smoke-af-packet-diff:
	$(MAKE) smoke-af-packet-diff-x86
	$(MAKE) smoke-af-packet-diff-arm

# Interruptible-wait / restart-semantics differential (F753). The selftest
# is host-only (~2min, no boot) and proves every probe case can fail; run
# it before trusting a green smoke.
WAIT_DIFF_SMOKE_TIMEOUT ?= 900
wait-diff-selftest:
	./tools/wait-diff-selftest.sh
smoke-wait-diff-x86:
	./tools/boot-smoke-wait-diff.sh x86 $(WAIT_DIFF_SMOKE_TIMEOUT)
smoke-wait-diff-arm:
	./tools/boot-smoke-wait-diff.sh arm $(WAIT_DIFF_SMOKE_TIMEOUT)
smoke-wait-diff:
	$(MAKE) smoke-wait-diff-x86
	$(MAKE) smoke-wait-diff-arm

# GRUB self-bootstrap smoke (F372). Boots the GRUB multiboot2 ISO
# headless and waits for $SMOKE_MARKER (default `oxide login:`). During
# bring-up, override the marker for an intermediate milestone, e.g.
# `make smoke-grub SMOKE_MARKER='MB2' SMOKE_TIMEOUT=180`.
smoke-grub:
	./tools/boot-smoke.sh grub $(SMOKE_TIMEOUT)

# B18: console-login regression. Drives `alice`/`swordfish` at the
# oxide login: prompt and checks `id` reports uid=1000. Catches
# SysV stack ordering, PAM, TIOCSCTTY-foreground_pgid, and shell
# job-control regressions in one shot.
LOGIN_SMOKE_TIMEOUT ?= 600
smoke-login-x86: x86
	./tools/boot-smoke-login.sh x86 $(LOGIN_SMOKE_TIMEOUT)
smoke-login-arm: arm
	./tools/boot-smoke-login.sh arm $(LOGIN_SMOKE_TIMEOUT)
smoke-login: smoke-login-x86 smoke-login-arm

# F155: end-to-end DHCP path smoke. Boots with OXIDE_UDHCPC_ENABLE=1
# so udhcpc, online_smoke, tcp_smoke run from rcS; checks for the
# lease confirmation line on serial. ARM TCG can't reach login
# inside a 180s window with the full chain, so default to 600s.
DHCP_SMOKE_TIMEOUT ?= 600
smoke-dhcp-x86: x86
	OXIDE_UDHCPC_ENABLE=1 ./tools/boot-smoke-dhcp.sh x86 $(DHCP_SMOKE_TIMEOUT)
smoke-dhcp-arm: arm
	OXIDE_UDHCPC_ENABLE=1 ./tools/boot-smoke-dhcp.sh arm $(DHCP_SMOKE_TIMEOUT)
# `smoke-dhcp` aggregate runs x86 only. ARM TCG is too slow under
# the boot+udhcpc+default.script chain to land the lease inside a
# reasonable CI window; run `make smoke-dhcp-arm` explicitly when
# needed (still completes the lease per F152, just not the
# default.script echo confirmation).
smoke-dhcp: smoke-dhcp-x86

# F210 end-to-end ssh smoke. Boots qemu, waits for sshd Server
# listening line + oxide login, then runs N back-to-back ssh
# sessions (echo, id, cat /etc/passwd, uname -m, pwd) — every
# session must rv=0 with expected output. Catches regressions in
# KEX, auth, cred-emulate-setxuid, channel/exec, fork-exec, and
# socket teardown in one shot.
SSH_SMOKE_TIMEOUT ?= 600
# Connections to drive in sequence per smoke. Cumulative kernel/sshd
# slowdown on ARM TCG starts biting >~16, so the default is 16 even
# though the CMDS[] rotation now defines 18+ entries. Bump explicitly
# on x86 KVM (much faster) when validating new tools.
SSH_SMOKE_CONNECTIONS ?= 4
smoke-ssh-x86: x86
	./tools/boot-smoke-ssh.sh x86 $(SSH_SMOKE_TIMEOUT) $(SSH_SMOKE_CONNECTIONS)
smoke-ssh-arm: arm
	./tools/boot-smoke-ssh.sh arm $(SSH_SMOKE_TIMEOUT) $(SSH_SMOKE_CONNECTIONS)
smoke-ssh: smoke-ssh-x86 smoke-ssh-arm

# D3.3 virtio-vsock host↔guest round-trip smoke. Starts a host AF_VSOCK
# echo server, rebuilds the rootfs with OXIDE_VSOCK_SMOKE=1 so rcS runs
# /bin/vsock_probe, boots, and checks for `vsock_probe: PASS` +
# `virtio-vsock installed cid=3` on serial. Needs /dev/vhost-vsock on
# the host (skips cleanly otherwise).
VSOCK_SMOKE_TIMEOUT ?= 600
smoke-vsock-x86: x86
	./tools/boot-smoke-vsock.sh x86 $(VSOCK_SMOKE_TIMEOUT)
smoke-vsock-arm: arm
	./tools/boot-smoke-vsock.sh arm $(VSOCK_SMOKE_TIMEOUT)
smoke-vsock: smoke-vsock-x86

VIRTIO_RNG_REBIND_SMOKE_TIMEOUT ?= 600
smoke-virtio-rng-rebind-x86: x86
	./tools/boot-smoke-virtio-rng-rebind.sh x86 $(VIRTIO_RNG_REBIND_SMOKE_TIMEOUT)
smoke-virtio-rng-rebind-arm: arm
	./tools/boot-smoke-virtio-rng-rebind.sh arm $(VIRTIO_RNG_REBIND_SMOKE_TIMEOUT)
smoke-virtio-rng-rebind: smoke-virtio-rng-rebind-x86 smoke-virtio-rng-rebind-arm

VIRTIO_PARENT_CHILD_REBIND_SMOKE_TIMEOUT ?= 600
smoke-virtio-parent-child-rebind-x86: x86
	./tools/boot-smoke-virtio-parent-child-rebind.sh x86 $(VIRTIO_PARENT_CHILD_REBIND_SMOKE_TIMEOUT)
smoke-virtio-parent-child-rebind-arm: arm
	./tools/boot-smoke-virtio-parent-child-rebind.sh arm $(VIRTIO_PARENT_CHILD_REBIND_SMOKE_TIMEOUT)
smoke-virtio-parent-child-rebind: smoke-virtio-parent-child-rebind-x86 smoke-virtio-parent-child-rebind-arm

UART_REBIND_SMOKE_TIMEOUT ?= 600
smoke-uart-rebind-x86: x86
	./tools/boot-smoke-uart-rebind.sh x86 $(UART_REBIND_SMOKE_TIMEOUT)
smoke-uart-rebind-arm: arm
	./tools/boot-smoke-uart-rebind.sh arm $(UART_REBIND_SMOKE_TIMEOUT)
smoke-uart-rebind: smoke-uart-rebind-x86 smoke-uart-rebind-arm

PS2_REBIND_SMOKE_TIMEOUT ?= 600
smoke-ps2-rebind-x86: x86
	./tools/boot-smoke-ps2-rebind.sh x86 $(PS2_REBIND_SMOKE_TIMEOUT)
smoke-ps2-rebind-arm: arm
	./tools/boot-smoke-ps2-rebind.sh arm $(PS2_REBIND_SMOKE_TIMEOUT)
smoke-ps2-rebind: smoke-ps2-rebind-x86 smoke-ps2-rebind-arm

VIRTIO_INPUT_REBIND_SMOKE_TIMEOUT ?= 600
smoke-virtio-input-rebind-x86: x86
	./tools/boot-smoke-virtio-input-rebind.sh x86 $(VIRTIO_INPUT_REBIND_SMOKE_TIMEOUT)
smoke-virtio-input-rebind-arm: arm
	./tools/boot-smoke-virtio-input-rebind.sh arm $(VIRTIO_INPUT_REBIND_SMOKE_TIMEOUT)
smoke-virtio-input-rebind: smoke-virtio-input-rebind-x86 smoke-virtio-input-rebind-arm

# Rebuild target/builds/default/root-<arch>.img from userspace/ sources. Run after
# editing any userspace/<name>/<name>.c so include_bytes! picks up
# the new bytes on the next kernel build.
rootfs:
	$(XTASK) rootfs

artifacts:
	$(XTASK) artifacts

# Interactive QEMU + GDB debugging via MCP. Claude Code auto-loads
# `tools/qemu-mcp/server.py` per `.mcp.json` at the repo root; this
# target is just a sanity check that the server module imports + lists
# its tools. See `tools/qemu-mcp/README.md` for the tool surface.
qemu-mcp:
	@python3 -c "import sys; sys.path.insert(0, 'tools/qemu-mcp'); import server; \
	  tools = sorted(t.fn.__name__ for t in server.mcp._tool_manager._tools.values()); \
	  print('qemu-mcp tools:'); \
	  [print(f'  {t}') for t in tools]"

# ---- misc -----------------------------------------------------------------

clean:
	$(CARGO) clean

# Reclaim dead build namespaces + LRU-trim the rootfs cache (see tools/xtask gc).
# Pass flags via GC_ARGS, e.g. `make clean-builds GC_ARGS="--all"` or `--dry-run`.
clean-builds:
	$(CARGO) run -q -p xtask -- gc $(GC_ARGS)

help:
	@awk '/^# `make / { sub(/^# /,""); print }' $(firstword $(MAKEFILE_LIST))
