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
# `make qemu-x86 / qemu-arm` — boot under QEMU with NO debug features;
#                          `qemu-*-debug` is the firehose.
# `make qemu-mcp`        — print the MCP tool list (interactive QEMU debug).
# `make artifacts`       — export stable packaging artifacts to target/artifacts.
# `make clean`           — `cargo clean`.

.PHONY: all build x86 arm \
        build-debug x86-debug arm-debug \
        test lint lint-ratchet lint-ratchet-update audit-counts stats ci \
        qemu-x86 qemu-arm qemu-x86-debug qemu-arm-debug qemu-mcp \
        qemu-x86-grub \
        smoke-cmdline-x86 smoke-cmdline-arm smoke-cmdline \
        smoke-af-packet-diff-x86 smoke-af-packet-diff-arm smoke-af-packet-diff \
        smoke-wait-diff-x86 smoke-wait-diff-arm smoke-wait-diff wait-diff-selftest \
        frame-gate frame-gate-x86 frame-gate-arm \
        stack-gate stack-gate-x86 stack-gate-arm \
        irq-gate irq-gate-x86 irq-gate-arm \
        feature-gate feature-gate-x86 feature-gate-arm feature-gate-atexit \
        hosted-gate test-build-gate \
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

# Ratchet gate (~0.8 s). `make lint` reports a 2696-finding historical backlog,
# so it cannot gate a push today; what CAN gate is the derivative. The baseline
# in `tools/spec-lint/baseline.tsv` holds the count per (crate, rule) and the
# gate fails when any key exceeds it — a new violation in a crate that already
# has 500 still fails, because nothing is compared tree-wide.
#
# Tightening is part of the definition of done for every burndown PR: slack below
# the baseline FAILS, because a fixed finding that is not locked in can be
# reintroduced with the gate still green. `make lint` stays the full report and
# stays the target to run while burning the backlog down.
#
# The baseline only ever shrinks: `--update` writes `min(current, baseline)` per
# key and refuses to raise one without `--allow-growth`, which prints every
# loosened key.
lint-ratchet:
	$(CARGO) run --quiet -p spec-lint -- ratchet

# Enforced-vs-raw-grep counts for the rules `07§5` scopes to the kernel build.
# An audit must quote the enforced column: a `grep -c` does not apply the cfg
# scoping the rules are written in, so it returns a much larger number that is
# not a violation count. `extern crate std` was escalated as 18-73 violations
# and `panic!(fmt)` as 113 on exactly that mistake; both are enforced at 0.
# Fails if any scoped rule leaves zero.
audit-counts:
	$(CARGO) run --quiet -p spec-lint -- audit

lint-ratchet-update:
	$(CARGO) run --quiet -p spec-lint -- ratchet --update

stats:
	$(XTASK) stats $(STATS_ARGS)

# Informational: show the next free number per branch type. Claiming is atomic
# via `tools/next-branch.sh --claim <TYPE> <title>`, so there is nothing to gate.
counters:
	@for t in F B D R Z C; do printf '%-3s %s\n' "$$t" "$$(tools/next-branch.sh $$t)"; done

# Mirror of the PR-time gate per `docs/40§2`: spec-lint clean, hosted tests
# green, both arches build default AND with debug-all on.
#
# `lint-ratchet`, not `lint`: the full spec-lint has a 2696-finding backlog
# (C255), so `make ci` has been unconditionally red and therefore unread. The
# ratchet holds the line while the backlog is burned down; swap it back to
# `lint` once the count reaches zero.
ci: lint-ratchet audit-counts matrix-gate hosted-gate test-build-gate test build build-debug frame-gate stack-gate irq-gate

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

# `make qemu-x86` / `make qemu-arm` boot with NO debug features.
#
# The display is the console and the serial port mirrors it; both are
# unconditional. `debug-boot` is a macro gate ONLY (`kmacros::debug_boot!`
# expands to the body or to nothing) — nothing in `crates/kernel/console`,
# `crates/drivers/fbcon` or `crates/kernel/vt` is gated on it. This target used
# to force it on, under a comment claiming the UART sink required it and that
# login would not appear without it. That was false, and it is why every
# default boot carried thousands of lines of operational-pulse log.
#
# What `debug-boot` actually enables: `[INFO]`-tagged operational-pulse lines
# such as `[INFO] boot: kernel ready, halting`. Useful when you want to watch
# the kernel come up; noise on an ordinary boot. `make qemu-x86-debug` /
# `qemu-arm-debug` turn on `debug-all`, and `FEATURES=...` adds any single
# feature to the default-quiet boot (e.g. `make qemu-x86 FEATURES=debug-irq`).
#
# B1474: any trace that fires per syscall, per signal, per fault, per exec or
# per journald datagram belongs to its own feature — carried on a default boot
# such a trace slowed a live-gnome guest by an order of magnitude, far enough
# to blow userspace D-Bus activation timeouts, so the instrument changed the
# result instead of measuring it. Opt in per lane:
#   FEATURES=debug-sigdeliv   [SIGDELIV]  per-delivery signal trace
#   FEATURES=debug-ustack     [USTACK]    futex user return-address walk
#   FEATURES=debug-desktop    [MUTTER*]/[DRMPROP]/[LGD] compositor+KMS ledger
#   FEATURES=debug-execload   [EXECLOAD]  per-exec image + ELF interp trace
#   FEATURES=debug-journal    [B288]      FULL journald records (debug-boot
#                                         already keeps each MESSAGE= line)
#   FEATURES=debug-taskdrop   [TASK-DROP] per-task teardown record
#   FEATURES=debug-faultdiag  [FAULT-*]   per-page-fault VMA/resolve trace
#   FEATURES=debug-boot       [INFO]      the operational boot pulse itself
QEMU_FEATURES_X86 := $(FEATURES)
QEMU_FEATURES_ARM := $(FEATURES)

# SMP CPU count for qemu (default 1). The boot-smoke gate sets SMP=2 so
# AP bring-up + the periodic load balancer are exercised every push.
SMP ?= 1

# Both arches boot via GRUB — x86 through the multiboot2 path, aarch64
# through the EFI-stub `linux` path (`xtask grub` dispatches on --arch).
# `cmd_grub` takes --arch/--smp/--features.
qemu-x86:
	$(TRIM_ROOTFS_CACHE)
	$(XTASK) grub --arch x86_64  --smp $(SMP) $(if $(QEMU_FEATURES_X86),--features "$(QEMU_FEATURES_X86)",)

qemu-arm:
	$(TRIM_ROOTFS_CACHE)
	$(XTASK) grub --arch aarch64 --smp $(SMP) $(if $(QEMU_FEATURES_ARM),--features "$(QEMU_FEATURES_ARM)",)

# Compatibility spelling for the former bootloader-specific target. Keep one
# canonical recipe so `FEATURES=` has identical meaning on both spellings.
qemu-x86-grub: qemu-x86

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

# Both arches at once. The builds are prerequisites, so they finish first
# (cargo serialises them through its own lock anyway); only the two BOOTS
# overlap, and they contend for nothing — separate build namespaces, separate
# root images, separate qemu instances. Running them back to back doubles the
# wall clock of every lockstep check for no benefit, which is the whole cost of
# this gate. Both exit statuses are collected: a failure on either arch fails
# the target, and neither cancels the other, so one run reports both answers.
smoke: x86 arm
	@rc=0; \
	./tools/boot-smoke.sh x86 $(SMOKE_TIMEOUT) & p1=$$!; \
	./tools/boot-smoke.sh arm $(SMOKE_TIMEOUT) & p2=$$!; \
	wait $$p1 || rc=1; \
	wait $$p2 || rc=1; \
	exit $$rc

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

# Interrupt-stack DEPTH gate — a SECOND budget domain, and the only one that
# looks at the stack the `#DF` actually overflowed.
#
# `stack-gate` above measures task stacks and, because the walker follows
# direct call edges only, it stops dead at the first function pointer. Every
# hardware interrupt handler here is reached through one, so the receive path
# measured 8 bytes deep. `tools/irq-edges-<arch>.tsv` names the targets of each
# dispatch table (MSI vectors, line handlers, the nine softirq slots, the NAPI
# poll list, the tick-poll and exit-to-user hooks), which is what makes the
# interrupt path visible at all.
#
# Ceiling 12000 of the same 16384 B stack, and the 4 KiB difference is the
# point: the entry asm does NOT re-switch when an interrupt arrives while
# already on this stack, and the softirq drain runs with interrupts unmasked,
# so a second entry lands on top of whatever the drain has spent. The headroom
# is not slack, it is the nested interrupt's stack.
IRQ_DEPTH_CEILING ?= 12000
irq-gate-x86: x86
	python3 tools/stack-depth-gate.py $(KERNEL_ELF_x86_64) \
	  --arch x86_64 --fail 99999 \
	  --indirect-map tools/irq-edges-x86_64.tsv \
	  --irq-roots tools/irq-roots-x86_64.txt --irq-fail $(IRQ_DEPTH_CEILING)
irq-gate-arm: arm
	python3 tools/stack-depth-gate.py $(KERNEL_ELF_aarch64) \
	  --arch aarch64 --fail 99999 \
	  --indirect-map tools/irq-edges-aarch64.tsv \
	  --irq-roots tools/irq-roots-aarch64.txt --irq-fail $(IRQ_DEPTH_CEILING)
irq-gate: irq-gate-x86 irq-gate-arm

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

# The same isolation, one step further along: BUILD each crate's test targets
# with only that crate's own features. `cargo check -p <crate>` compiles no
# test targets, so `hosted-gate` says nothing about whether
# `cargo test -p <crate>` builds — `cargo test -p procfs` did not build on
# main while every routine gate was green, and its 155 tests ran only under
# `cargo test --workspace`, where a sibling's dev-dependency unified
# `sched/hosted` on.
#
# ~2 s when nothing changed, ~2.5 min from a fully cold target directory.
test-build-gate:
	./tools/test-build-check.sh

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
	./tools/boot-smoke.sh x86 $(SMOKE_TIMEOUT)

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

# Request-key construction smoke. The probe reports both PASS and FAIL, so the
# success marker must include PASS; a prefix marker accepts either verdict.
REQUEST_KEY_SMOKE_TIMEOUT ?= 600
smoke-request-key-x86: x86
	OXIDE_REQUEST_KEY_SMOKE=1 SMOKE_MARKER='REQUEST-KEY-PROBE: PASS' ./tools/boot-smoke.sh x86 $(REQUEST_KEY_SMOKE_TIMEOUT)
smoke-request-key-arm: arm
	OXIDE_REQUEST_KEY_SMOKE=1 SMOKE_MARKER='REQUEST-KEY-PROBE: PASS' ./tools/boot-smoke.sh arm $(REQUEST_KEY_SMOKE_TIMEOUT)
smoke-request-key: smoke-request-key-x86 smoke-request-key-arm

# Ext4 swapfile + memcg pageout smoke. The shared probe helper emits the
# lowercase probe name, so keep the marker exact rather than accepting a prefix.
SWAPFILE_SMOKE_TIMEOUT ?= 600
smoke-swapfile-x86: x86
	OXIDE_SWAPFILE_SMOKE=1 SMOKE_MARKER='swapfile_probe: PASS' ./tools/boot-smoke.sh x86 $(SWAPFILE_SMOKE_TIMEOUT)
smoke-swapfile-arm: arm
	OXIDE_SWAPFILE_SMOKE=1 SMOKE_MARKER='swapfile_probe: PASS' ./tools/boot-smoke.sh arm $(SWAPFILE_SMOKE_TIMEOUT)
smoke-swapfile: smoke-swapfile-x86 smoke-swapfile-arm

# GNOME input classification smoke. Its injected script reports a single
# tagged PASS/FAIL line; require the passing verdict from the boot log.
GNOME_INPUT_CLASSIFY_SMOKE_TIMEOUT ?= 600
smoke-gnome-input-classify-x86: x86
	OXIDE_GNOME_INPUT_CLASSIFY_SMOKE=1 SMOKE_MARKER='gnome_input_classify: PASS' ./tools/boot-smoke.sh x86 $(GNOME_INPUT_CLASSIFY_SMOKE_TIMEOUT)
smoke-gnome-input-classify-arm: arm
	OXIDE_GNOME_INPUT_CLASSIFY_SMOKE=1 SMOKE_MARKER='gnome_input_classify: PASS' ./tools/boot-smoke.sh arm $(GNOME_INPUT_CLASSIFY_SMOKE_TIMEOUT)
smoke-gnome-input-classify: smoke-gnome-input-classify-x86 smoke-gnome-input-classify-arm

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
