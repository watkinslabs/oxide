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
        smoke-cmdline-x86 smoke-cmdline-arm smoke-cmdline \
        smoke-af-packet-diff-x86 smoke-af-packet-diff-arm smoke-af-packet-diff \
        smoke-wait-diff-x86 smoke-wait-diff-arm smoke-wait-diff wait-diff-selftest \
        frame-gate frame-gate-x86 frame-gate-arm \
        stack-gate stack-gate-x86 stack-gate-arm \
        feature-gate feature-gate-x86 feature-gate-arm feature-gate-atexit \
        hosted-gate \
        smoke-ping smoke-ping-x86 smoke-ping-arm \
        stack-gate-baseline-x86 stack-gate-baseline-arm stack-report \
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

# Informational: show the next free number per branch type. Claiming is atomic
# via `tools/next-branch.sh --claim <TYPE> <title>`, so there is nothing to gate.
counters:
	@for t in F B D R Z C; do printf '%-3s %s\n' "$$t" "$$(tools/next-branch.sh $$t)"; done

# Mirror of the PR-time gate per `docs/40§2`: spec-lint clean, hosted tests
# green, both arches build default AND with debug-all on.
ci: lint matrix-gate hosted-gate test build build-debug

# Structural gate on the syscall compliance ledger: one row per syscall number,
# the declared column count on every row (escape-aware, so `\|` inside a cell is
# a cell and not a column), and a Status drawn from the file's own legend.
#
# Every invariant here is a defect that reached main. The duplicate-row check in
# particular: F784 read the matrix with a parser that split on `|` without
# honouring the escape, silently skipped all 65 pipe-bearing rows, concluded
# those syscalls had no row, and appended 65 duplicates with conflicting Status.
# This lint already existed and already printed those exact 65 rows as a note --
# it was never wired into a gate, so nobody saw it. A warning nothing reads is
# not verification.
matrix-gate:
	python3 tools/matrix-lint.py

# ---- qemu -----------------------------------------------------------------

# `debug-boot` is required for the boot UART sink to install (without
# it, klog drops everything — including /dev/console writes from
# userspace, so login never appears). It also enables operational-
# pulse log lines like `[INFO] boot: kernel ready, halting` so you
# can tell the kernel is alive while waiting for the login prompt.
# `debug-sched` is intentionally excluded — that's the per-syscall
# trace flood. FEATURES=... appends extras (e.g. FEATURES=debug-irq).
#
# B1474: `debug-boot` is the OPERATIONAL PULSE, nothing else. Because this
# target turns it on unconditionally, any trace that fires per syscall, per
# signal, per fault, per exec or per journald datagram belongs to its own
# feature — on `debug-boot` such a trace slowed a live-gnome guest by an order
# of magnitude, far enough to blow userspace D-Bus activation timeouts, so the
# instrument changed the result instead of measuring it. Opt in per lane:
#   FEATURES=debug-sigdeliv   [SIGDELIV]  per-delivery signal trace
#   FEATURES=debug-ustack     [USTACK]    futex user return-address walk
#   FEATURES=debug-desktop    [MUTTER*]/[DRMPROP]/[LGD] compositor+KMS ledger
#   FEATURES=debug-execload   [EXECLOAD]  per-exec image + ELF interp trace
#   FEATURES=debug-journal    [B288]      FULL journald records (debug-boot
#                                         already keeps each MESSAGE= line)
#   FEATURES=debug-taskdrop   [TASK-DROP] per-task teardown record
#   FEATURES=debug-faultdiag  [FAULT-*]   per-page-fault VMA/resolve trace
comma := ,
QEMU_FEATURES_X86 := debug-boot$(if $(FEATURES),$(comma)$(FEATURES),)
QEMU_FEATURES_ARM := debug-boot$(if $(FEATURES),$(comma)$(FEATURES),)

# SMP CPU count for qemu (default 1). The boot-smoke gate sets SMP=2 so
# AP bring-up + the periodic load balancer are exercised every push.
SMP ?= 1

# Limine is gone on BOTH arches — x86 boots via the GRUB multiboot2 path
# and aarch64 via the GRUB EFI-stub `linux` path (`xtask grub` dispatches
# on --arch). `cmd_grub` takes --arch/--smp/--features.
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

# Boot-cmdline propagation gate — asserts the BOOTLOADER's command line
# reaches /proc/cmdline on both arches (different transport per arch:
# multiboot2 tag on x86_64, EFI LoadOptions on aarch64).
CMDLINE_SMOKE_TIMEOUT ?= 900
# Echo-probe gate — runs the distribution's own ping(8) inside the guest as an
# ordinary user with no capabilities, over the serial debug shell (no guest
# networking, no sshd). A pass proves the ICMP datagram endpoint class end to
# end: group admission, kernel-assigned identifier, and reply demultiplexing.
smoke-ping-x86:
	python3 tools/guest-ping-check.py x86 $(SMOKE_TIMEOUT)
smoke-ping-arm:
	python3 tools/guest-ping-check.py arm $(SMOKE_TIMEOUT)
smoke-ping: smoke-ping-x86 smoke-ping-arm

smoke-cmdline-x86: x86
	./tools/boot-smoke-cmdline.sh x86 $(CMDLINE_SMOKE_TIMEOUT)
smoke-cmdline-arm: arm
	./tools/boot-smoke-cmdline.sh arm $(CMDLINE_SMOKE_TIMEOUT)
smoke-cmdline: smoke-cmdline-x86 smoke-cmdline-arm

# WHICH ELF THE STACK GATES READ (B1632)
# --------------------------------------
# The RELEASE, default-feature kernel each arch's build target produces —
# exactly what CI's `stack gates` job builds — and never target/artifacts.
# target/artifacts holds whatever build last EXPORTED: `make qemu-*` builds
# with `--features debug-boot`, whose frames and crate hashes both differ, so
# gating that file made the verdict depend on which build ran last. The gates
# therefore depend on the arch build target and read its output directly.
KERNEL_ELF_x86_64 ?= target/x86_64-unknown-oxide-kernel/release/oxide-x86_64
KERNEL_ELF_aarch64 ?= target/aarch64-unknown-oxide-kernel/release/oxide-aarch64

# Stack-frame size gate (Linux CONFIG_FRAME_WARN; `skizm.md` Step 6). Reads
# prologue reservations out of an already-built kernel ELF, so it needs no
# extra codegen flags. Ratcheted: frames already over the ceiling are recorded
# in tools/frame-size-baseline-<arch>.txt, keyed on the DEMANGLED path so a
# rebuild cannot rename them, and tolerated at or below their recorded size; a
# NEW or WORSENED frame fails, and a baseline entry naming a frame that no
# longer exists fails as stale.
frame-gate-x86: x86
	python3 tools/frame-size-gate.py --self-test
	python3 tools/frame-size-gate.py $(KERNEL_ELF_x86_64) \
	  --baseline tools/frame-size-baseline-x86_64.txt
frame-gate-arm: arm
	python3 tools/frame-size-gate.py $(KERNEL_ELF_aarch64) \
	  --baseline tools/frame-size-baseline-aarch64.txt
frame-gate: frame-gate-x86 frame-gate-arm

# Stack-DEPTH gate: worst-case bytes along a static call path, not per-function.
# Catches what frame-gate structurally cannot — a chain of individually-legal
# frames that sums past the 16 KiB kernel stack (the virtio child-probe
# overflow was 8448 + 6064 with an 8192 per-function ceiling in force, and
# frame-gate passed on that binary).
#
# Ceiling 13000 B of the 16384 B stack; paths already over it are recorded with
# a reason in tools/stack-depth-allow-<arch>.txt and tolerated at or below the
# recorded budget, so a NEW or DEEPER path fails.
STACK_DEPTH_CEILING ?= 13000
stack-gate-x86: x86
	python3 tools/stack-depth-gate.py --self-test
	python3 tools/stack-depth-gate.py $(KERNEL_ELF_x86_64) \
	  --arch x86_64 --fail $(STACK_DEPTH_CEILING) \
	  --allowlist tools/stack-depth-allow-x86_64.txt
stack-gate-arm: arm
	python3 tools/stack-depth-gate.py $(KERNEL_ELF_aarch64) \
	  --arch aarch64 --fail $(STACK_DEPTH_CEILING) \
	  --allowlist tools/stack-depth-allow-aarch64.txt
stack-gate: stack-gate-x86 stack-gate-arm

# Feature-gated compile gate. The routine gates (`xtask kernel`, hosted tests,
# stack-gate) all build WITHOUT features, so code inside `debug_boot! { … }` and
# every other `#[cfg(feature = …)]` block is not compiled by any of them. A
# branch that does not compile can therefore pass the entire local gate set and
# then fail `make qemu-*`, which sets `debug-boot` — the build dies before QEMU
# starts, so the boot log is empty and reads like a boot failure rather than a
# build one. B1641 lost a lane to exactly that.
#
# `debug-all` is NOT the whole debug surface — it is a curated aggregate of ~11
# features, so gating on it alone left ~75 debug features uncompiled by anything
# routine, and three of them (`debug-stderr`, `debug-memtest`, `debug-atexit`)
# had been broken for months (B1671). The gate therefore enumerates EVERY
# `debug-*` feature declared in kmain's `[features]` table, so a feature added
# later is covered without editing this file.
#
# `debug-atexit` is the one exclusion: it and `debug-stderr` are mutually
# exclusive by design (`020_writev` picks the richer `[DYNERR]` tracer when
# atexit is on), so enabling both hides the `debug-stderr` writev block from the
# type checker. `make feature-gate-atexit` covers it as a separate, non-routine
# pass — it is a distinct feature set, so it recompiles rather than reusing the
# routine gate's artifacts.
#
# `--check` (type-check, no codegen/link/snapshot/rootfs) is what keeps this
# usable as a ROUTINE gate: the defect class is a compile error inside a
# feature-gated block, which `cargo check` reports identically to a full build
# at a fraction of the cost. `.githooks/pre-push` runs it on every branch push
# that touches kernel sources; `make build-debug` remains the full codegen+link
# form for the merge path.
GATE_FEATURES = $(shell awk '/^\[features\]/{f=1;next} /^\[/{f=0} f && /^debug-[a-z0-9-]* *=/{print $$1}' \
	crates/kernel/kmain/Cargo.toml | grep -v '^debug-atexit$$' | paste -sd,)

feature-gate-x86:
	cargo run --quiet -p xtask -- kernel --arch x86_64 --features $(GATE_FEATURES) --check
feature-gate-arm:
	cargo run --quiet -p xtask -- kernel --arch aarch64 --features $(GATE_FEATURES) --check
feature-gate: feature-gate-x86 feature-gate-arm

# The mutually-exclusive half: `debug-atexit` instead of `debug-stderr`.
feature-gate-atexit:
	cargo run --quiet -p xtask -- kernel --arch x86_64 --features debug-atexit,debug-all --check
	cargo run --quiet -p xtask -- kernel --arch aarch64 --features debug-atexit,debug-all --check

# Type-check every workspace crate ON ITS OWN for the host, with its own
# default features. `cargo check --workspace` does NOT cover this: cargo
# unifies features across one invocation, so a dependant that asks for
# `net/hosted` hides a crate that only compiles with that feature on. Neither
# do the routine gates — `cargo test` turns the same gate on through
# `cfg(test)`, and both kernel builds turn it on through `target_os`. B1660
# reached main red for `cargo check -p net` with every one of them green.
#
# ~5 s when nothing changed, ~12 s after a core crate is touched, on 24 jobs.
hosted-gate:
	./tools/hosted-check.sh

# Regenerate the allowlists. Reasons must be edited in by hand afterwards —
# the gate refuses an entry that is not under a `#` reason block.
stack-gate-baseline-x86: x86
	python3 tools/stack-depth-gate.py $(KERNEL_ELF_x86_64) \
	  --arch x86_64 --fail $(STACK_DEPTH_CEILING) \
	  --allowlist tools/stack-depth-allow-x86_64.txt --write-allowlist
stack-gate-baseline-arm: arm
	python3 tools/stack-depth-gate.py $(KERNEL_ELF_aarch64) \
	  --arch aarch64 --fail $(STACK_DEPTH_CEILING) \
	  --allowlist tools/stack-depth-allow-aarch64.txt --write-allowlist

# The deepest paths, frame by frame — the debugging view. `make stack-report ARCH=aarch64`
ARCH ?= x86_64
stack-report:
	python3 tools/stack-depth-gate.py $(KERNEL_ELF_$(ARCH)) \
	  --arch $(ARCH) --fail 99999 --top 20 --show-path

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
# Serial-driven kernel smokes with no in-guest probe: the /proc /dev /sys
# sweep and the framebuffer-keyboard login. Both worked but had no target.
FS_SMOKE_TIMEOUT ?= 600
smoke-fs-x86: x86
	./tools/boot-smoke-fs.sh x86 $(FS_SMOKE_TIMEOUT)
smoke-fs-arm: arm
	./tools/boot-smoke-fs.sh arm $(FS_SMOKE_TIMEOUT)
smoke-fs: smoke-fs-x86 smoke-fs-arm

KBD_LOGIN_SMOKE_TIMEOUT ?= 600
smoke-kbd-login-x86: x86
	./tools/boot-smoke-kbd-login.sh x86 $(KBD_LOGIN_SMOKE_TIMEOUT)
smoke-kbd-login-arm: arm
	./tools/boot-smoke-kbd-login.sh arm $(KBD_LOGIN_SMOKE_TIMEOUT)
smoke-kbd-login: smoke-kbd-login-x86 smoke-kbd-login-arm

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

INPUT_DELIVERY_SMOKE_TIMEOUT ?= 900
smoke-mouse-x86: x86
	./tools/boot-smoke-mouse.sh x86 $(INPUT_DELIVERY_SMOKE_TIMEOUT)
smoke-mouse-arm: arm
	./tools/boot-smoke-mouse.sh arm $(INPUT_DELIVERY_SMOKE_TIMEOUT)
smoke-mouse: smoke-mouse-x86 smoke-mouse-arm

VIRTIO_INPUT_REBIND_SMOKE_TIMEOUT ?= 900
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
