# oxide2 — convenience wrapper around `cargo run -p xtask`.
# All real logic lives in `tools/xtask`; this file is just shorter
# names + grouped targets for humans.

CARGO    ?= cargo
XTASK    := $(CARGO) run -p xtask --
WARNING_RUN := python3 tools/warnings-gate.py --
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
#                          x86 defaults to the firmware framebuffer.
# `make qemu-x86-virtio-gpu` — primary virtio-GPU driver validation topology.
# `qemu-*-debug` is the firehose.
# `make boot-debug-x86 / boot-debug-arm` — boot with the narrating cmdline
#                          (keep_bootcon + initcall_debug + ignore_loglevel) on
#                          top of the console parameters every boot carries.
# `make smoke-debug`     — same, headless, serial log KEPT at a stable name.
# EVERY boot writes its serial log to $(BOOT_LOG_DIR)/<arch>-<stamp>.log, with
# <arch>-latest.log pointing at the newest. OXIDE_SERIAL_LOG=<path> names one;
# OXIDE_SERIAL_LOG=0 declines.
# `make qemu-mcp`        — print the MCP tool list (interactive QEMU debug).
# `make artifacts`       — export stable packaging artifacts to target/artifacts.
# `make clean`           — `cargo clean`.

.PHONY: all build x86 arm kpi-layout \
        build-debug x86-debug arm-debug \
        test lint lint-ratchet lint-ratchet-update audit-counts profile-policy warnings-control stats ci \
        qemu-x86 qemu-arm qemu-x86-virtio-gpu qemu-x86-image qemu-arm-image qemu-x86-existing qemu-arm-existing qemu-x86-debug qemu-arm-debug qemu-mcp verify-native-q35 smoke-native-pci-x86 smoke-native-pci-e1000-x86 \
        hardware-audit-image-x86 \
        boot-debug-x86 boot-debug-arm smoke-debug smoke-debug-x86 smoke-debug-arm smoke-taskdump-arm \
        qemu-x86-grub qemu-x86-uefi smoke-uefi-x86 \
        smoke-up smoke-up-x86 smoke-up-arm \
        smoke-cmdline-x86 smoke-cmdline-arm smoke-cmdline \
        smoke-devpts-x86 smoke-devpts-arm smoke-devpts \
        smoke-af-packet-diff-x86 smoke-af-packet-diff-arm smoke-af-packet-diff \
        smoke-wait-diff-x86 smoke-wait-diff-arm smoke-wait-diff wait-diff-selftest \
        smoke-sockopt-diff-x86 smoke-sockopt-diff-arm smoke-sockopt-diff \
        frame-gate frame-gate-x86 frame-gate-arm s3-resume-gate-x86 accept-s3-resume-x86 \
        uaccess-extable-gate uaccess-extable-gate-x86 uaccess-extable-gate-arm \
        stack-gate stack-gate-x86 stack-gate-arm \
        irq-gate irq-gate-x86 irq-gate-arm \
        feature-gate feature-gate-x86 feature-gate-arm feature-gate-atexit \
        smoke-hda smoke-hda-x86 smoke-hda-arm \
        smoke-v4l2 smoke-v4l2-x86 smoke-v4l2-arm \
        smoke-ata-identity smoke-ata-identity-x86 smoke-ata-identity-arm \
        smoke-ata-sat smoke-ata-sat-x86 smoke-ata-sat-arm \
        smoke-usb-scsi smoke-usb-scsi-x86 smoke-usb-scsi-arm \
        hosted-gate test-build-gate test-build-check-selftest \
        smoke-hostshare smoke-hostshare-x86 smoke-hostshare-arm \
        smoke-ping smoke-ping-x86 smoke-ping-arm smoke-network-native-pci-x86 \
        stack-gate-baseline-x86 stack-gate-baseline-arm stack-report \
        clean clean-builds help

all: build

# Compile the C module ABI assertions which pair with the Rust mirror tests.
kpi-layout:
	$(CC) -std=c11 -Wall -Werror -I kpi/include tools/kpi-layout-smoke.c -o /tmp/oxide-kpi-layout-smoke
	/tmp/oxide-kpi-layout-smoke

# ---- builds ---------------------------------------------------------------

build: x86 arm

x86:
	$(WARNING_RUN) $(XTASK) kernel --arch x86_64  $(if $(FEATURES),--features $(FEATURES),)

arm:
	$(WARNING_RUN) $(XTASK) kernel --arch aarch64 $(if $(FEATURES),--features $(FEATURES),)

build-debug: x86-debug arm-debug

x86-debug:
	$(WARNING_RUN) $(XTASK) kernel --arch x86_64  --features debug-all

arm-debug:
	$(WARNING_RUN) $(XTASK) kernel --arch aarch64 --features debug-all

# ---- checks ---------------------------------------------------------------

test:
	$(WARNING_RUN) $(XTASK) test

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
lint-ratchet: profile-policy
	$(WARNING_RUN) $(CARGO) run --quiet -p spec-lint -- ratchet

# Wrong-code prevention for the pinned nightly. B1855 reproduced a neighbouring
# match arm returning the edited arm's value only with incremental codegen.
profile-policy:
	python3 tools/profile-policy.py

# Enforced-vs-raw-grep counts for the rules `07§5` scopes to the kernel build.
# An audit must quote the enforced column: a `grep -c` does not apply the cfg
# scoping the rules are written in, so it returns a much larger number that is
# not a violation count. `extern crate std` was escalated as 18-73 violations
# and `panic!(fmt)` as 113 on exactly that mistake; both are enforced at 0.
# Fails if any scoped rule leaves zero.
audit-counts:
	$(WARNING_RUN) $(CARGO) run --quiet -p spec-lint -- audit

lint-ratchet-update:
	$(WARNING_RUN) $(CARGO) run --quiet -p spec-lint -- ratchet --update

# Rust's CONFIG_WERROR equivalent. The red control starts with `-A warnings`
# and proves the wrapper's final `-Dwarnings` still wins; the green control
# proves a clean crate passes. Every routine compile target below uses the same
# wrapper, so warnings are compiler errors rather than unread log text.
warnings-control:
	python3 tools/warnings-gate.py --self-test

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
# Keep this prerequisite order even under `make -j`: debug-all and default use
# the same canonical ELF paths, and the size/depth gates contractually inspect
# the default binary. Build debug-all first, then overwrite it with default.
.NOTPARALLEL: ci
ci: warnings-control lint-ratchet audit-counts matrix-gate hosted-gate test-build-gate test build-debug build uaccess-extable-gate s3-resume-gate-x86 frame-gate stack-gate irq-gate

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
	python3 tools/matrix-lint.py --self-test
	python3 tools/matrix-lint.py

# Process-global state a hosted test suite can reach without owning it. Four
# lanes (B1949, B1955, B1956, B1957) each found this defect by accident, after
# it had flaked for months; the fifth is meant to be found here instead. The
# gate fails on a NEW unguarded candidate and on a backlog row whose candidate
# has since been guarded, so `tools/hosted-global-state-backlog.tsv` can only
# shrink. `--list` prints the full audit including the guarded candidates.
# Not in `ci`: the audit's result currently depends on which worktree runs
# it -- the same commit, with identical tracked files and an identical set
# of scanned sources, reports clean in one checkout and reports problems in
# another, deterministically in each. Until that is understood the gate
# cannot decide a PR. Run it by hand; the tool, its backlog and its findings
# stay live so the audit data is not lost.
hosted-global-gate:
	python3 tools/hosted-global-audit.py --self-test
	python3 tools/hosted-global-audit.py

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

# The native virtio-GPU path intentionally has no firmware scanout fallback.
# Keep it opt-in so ordinary QEMU boots immediately show the generic console.
qemu-x86-virtio-gpu:
	$(TRIM_ROOTFS_CACHE)
	OXIDE_QEMU_VIRTIO_GPU=1 $(XTASK) grub --arch x86_64 --smp $(SMP) $(if $(QEMU_FEATURES_X86),--features "$(QEMU_FEATURES_X86)",)

qemu-arm:
	$(TRIM_ROOTFS_CACHE)
	$(XTASK) grub --arch aarch64 --smp $(SMP) $(if $(QEMU_FEATURES_ARM),--features "$(QEMU_FEATURES_ARM)",)

# Split image preparation from launching an existing image. boot-smoke uses
# these so SMOKE_TIMEOUT measures guest runtime, never a feature build.
qemu-x86-image:
	$(TRIM_ROOTFS_CACHE)
	$(XTASK) image --arch x86_64 $(if $(QEMU_FEATURES_X86),--features "$(QEMU_FEATURES_X86)",)

qemu-arm-image:
	$(TRIM_ROOTFS_CACHE)
	$(XTASK) image --arch aarch64 $(if $(QEMU_FEATURES_ARM),--features "$(QEMU_FEATURES_ARM)",)

qemu-x86-existing:
	$(XTASK) grub --arch x86_64 --smp $(SMP) --id default --run-existing

qemu-arm-existing:
	$(XTASK) grub --arch aarch64 --smp $(SMP) --id default --run-existing

# Compatibility spelling for the former bootloader-specific target. Keep one
# canonical recipe so `FEATURES=` has identical meaning on both spellings.
qemu-x86-grub: qemu-x86

# Same ISO, same GRUB handoff, UEFI firmware instead of the legacy BIOS.
# grub2-mkrescue already writes BOTH an El Torito BIOS image and an EFI one,
# so the firmware is the only variable this target changes — which is what
# makes it a usable answer to "does this kernel boot a board without a CSM".
qemu-x86-uefi:
	$(TRIM_ROOTFS_CACHE)
	OXIDE_QEMU_UEFI=1 $(XTASK) grub --arch x86_64 --smp $(SMP) $(if $(QEMU_FEATURES_X86),--features "$(QEMU_FEATURES_X86)",)

# Same but with `--features debug-all` (every syscall trace + LAPIC
# tick + boot-pulse log). Useful for kernel debugging; not what you
# want when just trying to log in and use it.
qemu-x86-debug:
	$(TRIM_ROOTFS_CACHE)
	$(XTASK) grub --arch x86_64  --features debug-all

qemu-arm-debug:
	$(TRIM_ROOTFS_CACHE)
	$(XTASK) grub --arch aarch64 --features debug-all

# Boot debugging — the answer to "it hangs and prints nothing".
#
# Every boot already carries `earlycon printk.time=1 console=<serial>,115200
# console=tty0`, and a registering console is replayed the records the ring
# already holds, so an ordinary boot's serial log starts at the beginning.
# What is left for this preset is narration, not visibility.
#
# `OXIDE_CMDLINE_DEBUG=1` makes the ONE cmdline composer
# (tools/xtask/src/image_qemu/bootargs.rs) add `keep_bootcon initcall_debug
# ignore_loglevel` plus the systemd side. `initcall_debug` makes each init step
# name itself BEFORE it runs, so a boot that hangs names the step it stopped
# in; `ignore_loglevel` prints every record whatever its level. Add anything
# else with `OXIDE_CMDLINE_EXTRA='panic=30 oops=panic'` — it composes with the
# preset rather than replacing it.
#
# `make boot-debug-x86` / `boot-debug-arm` — interactive, output on the terminal.
boot-debug-x86:
	$(TRIM_ROOTFS_CACHE)
	OXIDE_CMDLINE_DEBUG=1 $(XTASK) grub --arch x86_64  --smp $(SMP) $(if $(QEMU_FEATURES_X86),--features "$(QEMU_FEATURES_X86)",)

boot-debug-arm:
	$(TRIM_ROOTFS_CACHE)
	OXIDE_CMDLINE_DEBUG=1 $(XTASK) grub --arch aarch64 --smp $(SMP) $(if $(QEMU_FEATURES_ARM),--features "$(QEMU_FEATURES_ARM)",)

# Captured variants: same boot, serial log kept at a stable path whether the
# boot passes or fails. `boot-smoke.sh` deletes its temp log on exit, so a
# passing boot's early output is otherwise unrecoverable — the case where the
# question is "what did the slow one do differently", not "did it fail".
BOOT_LOG_DIR ?= target/boot-logs

smoke-debug-x86:
	@mkdir -p $(BOOT_LOG_DIR)
	OXIDE_CMDLINE_DEBUG=1 SMOKE_KEEP_LOG=$(BOOT_LOG_DIR)/x86.log \
	    SMOKE_KEEP_LOG_DIR=$(BOOT_LOG_DIR) ./tools/boot-smoke.sh x86 $(SMOKE_TIMEOUT)
	@echo "serial log kept: $(BOOT_LOG_DIR)/x86.log"

smoke-debug-arm:
	@mkdir -p $(BOOT_LOG_DIR)
	OXIDE_CMDLINE_DEBUG=1 SMOKE_KEEP_LOG=$(BOOT_LOG_DIR)/arm.log \
	    SMOKE_KEEP_LOG_DIR=$(BOOT_LOG_DIR) ./tools/boot-smoke.sh arm $(SMOKE_TIMEOUT)
	@echo "serial log kept: $(BOOT_LOG_DIR)/arm.log"

# One retained ARM diagnostic boot.  The distro sysctl unit deliberately
# replaces the boot-line SysRq mask with its production-safe policy; masking
# that unit HERE leaves serial task/CPU dumps available only to this image.
# Normal smoke targets retain the distribution policy.  The feature list is
# passed to image preparation through the boot-smoke child make, so the
# periodic task dump and wake-placement trace are in the built kernel.
smoke-taskdump-arm:
	@mkdir -p $(BOOT_LOG_DIR)
	OXIDE_SMOKE_ATTEMPTS=1 FEATURES="$(strip $(FEATURES) debug-taskdump debug-watchdog)" OXIDE_CMDLINE_DEBUG=1 \
	    OXIDE_CMDLINE_EXTRA="$(strip $(OXIDE_CMDLINE_EXTRA) systemd.mask=systemd-sysctl.service)" \
	    SMOKE_KEEP_LOG=$(BOOT_LOG_DIR)/arm.log SMOKE_KEEP_LOG_DIR=$(BOOT_LOG_DIR) \
	    ./tools/boot-smoke.sh arm $(SMOKE_TIMEOUT)
	@echo "serial log kept: $(BOOT_LOG_DIR)/arm.log"

# Both arches concurrently, same rationale as `smoke`: they contend for
# nothing, and running them back to back doubles the wall clock for no answer.
smoke-debug:
	@mkdir -p $(BOOT_LOG_DIR); rc=0; \
	OXIDE_CMDLINE_DEBUG=1 SMOKE_KEEP_LOG=$(BOOT_LOG_DIR)/x86.log SMOKE_KEEP_LOG_DIR=$(BOOT_LOG_DIR) ./tools/boot-smoke.sh x86 $(SMOKE_TIMEOUT) & p1=$$!; \
	OXIDE_CMDLINE_DEBUG=1 SMOKE_KEEP_LOG=$(BOOT_LOG_DIR)/arm.log SMOKE_KEEP_LOG_DIR=$(BOOT_LOG_DIR) ./tools/boot-smoke.sh arm $(SMOKE_TIMEOUT) & p2=$$!; \
	wait $$p1 || rc=1; \
	wait $$p2 || rc=1; \
	echo "serial logs kept under $(BOOT_LOG_DIR)/"; \
	exit $$rc

# Boot-smoke gates — run kernel under qemu headless and wait for
# `oxide login:` on serial within SMOKE_TIMEOUT seconds (default
# 600). PR-time CI uses these; locally a 30-60s dev-box boot is
# typical, but TCG on a hosted runner needs 5-15min, hence the
# higher default. Override via `make smoke-x86 SMOKE_TIMEOUT=900`.
smoke-x86:
	./tools/boot-smoke.sh x86 $(SMOKE_TIMEOUT)

# Q35 with the PCIe Intel e1000e model, AHCI-root disks, NVMe, xHCI USB HID,
# VT-d interrupt remapping and a physical framebuffer handoff. This contains
# no virtio device on the boot path.
smoke-native-pci-x86:
	OXIDE_QEMU_PROFILE=native-pci ./tools/boot-smoke.sh x86 $(SMOKE_TIMEOUT)

# Construct the complete native-Q35 graph, then stop QEMU before guest code
# executes. This validates QEMU accepts the actual AHCI/NVMe/e1000e/xHCI/VT-d
# contract without turning a device-argument change into a boot loop.
verify-native-q35:
	./tools/qemu-native-q35-accept.sh

# Same topology with QEMU's older discrete Intel e1000 model. Keep this as a
# separate compatibility smoke; the primary native profile is e1000e.
smoke-native-pci-e1000-x86:
	OXIDE_QEMU_PROFILE=native-pci OXIDE_QEMU_NIC=e1000 ./tools/boot-smoke.sh x86 $(SMOKE_TIMEOUT)

smoke-arm:
	./tools/boot-smoke.sh arm $(SMOKE_TIMEOUT)

# The UEFI half of the x86 boot contract. Identical kernel, identical ISO,
# identical marker — only the firmware differs, so a failure here is a UEFI
# handoff regression and nothing else. Kept separate from `smoke` because it
# boots the same kernel a second time; run it when the boot path, the ISO
# builder or the multiboot2 header changes.
smoke-uefi-x86:
	OXIDE_QEMU_UEFI=1 ./tools/boot-smoke.sh x86 $(SMOKE_TIMEOUT)

# Both arches at once. Each smoke prepares its image first, then only the two
# QEMU runs overlap. Both exit statuses are collected: a failure on either arch
# fails the target, and neither cancels the other, so one run reports both answers.
smoke:
	@rc=0; \
	./tools/boot-smoke.sh x86 $(SMOKE_TIMEOUT) & p1=$$!; \
	./tools/boot-smoke.sh arm $(SMOKE_TIMEOUT) & p2=$$!; \
	wait $$p1 || rc=1; \
	wait $$p2 || rc=1; \
	exit $$rc

# UNIPROCESSOR boot gate. `smoke` above runs both arches at OXIDE_SMP=2, which
# is what every other gate in this tree does too — so a defect whose only
# symptom is "this CPU waits for work no other CPU will do" is invisible to all
# of them. A kernel that hangs on one CPU is a broken kernel; Linux boots on
# one CPU. These targets boot the same image with a single vCPU so that class
# fails here instead of on somebody's single-core board.
#
# Same-arch boots CANNOT overlap: both use the default build namespace and
# would fight over root-<arch>.img (an image lock, which produces a log with no
# kernel output at all and reads exactly like a boot failure). So this is a
# separate target from `smoke`, and the two arches inside it — which share
# nothing — are the only things that run concurrently.
smoke-up-x86: x86
	OXIDE_SMP=1 ./tools/boot-smoke.sh x86 $(SMOKE_TIMEOUT)

smoke-up-arm: arm
	OXIDE_SMP=1 ./tools/boot-smoke.sh arm $(SMOKE_TIMEOUT)

smoke-up: x86 arm
	@rc=0; \
	OXIDE_SMP=1 ./tools/boot-smoke.sh x86 $(SMOKE_TIMEOUT) & p1=$$!; \
	OXIDE_SMP=1 ./tools/boot-smoke.sh arm $(SMOKE_TIMEOUT) & p2=$$!; \
	wait $$p1 || rc=1; \
	wait $$p2 || rc=1; \
	exit $$rc

# Devpts mount-instance gate. The guest opens a real PTY through /dev/ptmx and
# reports the created slave's mode/owner; the probe cannot pass on command echo
# because the complete marker exists only in Python's formatted output.
DEVPTS_SMOKE_TIMEOUT ?= 600
smoke-devpts-x86: x86
	./tools/boot-smoke-devpts.sh x86 $(DEVPTS_SMOKE_TIMEOUT)
smoke-devpts-arm: arm
	./tools/boot-smoke-devpts.sh arm $(DEVPTS_SMOKE_TIMEOUT)
smoke-devpts: x86 arm
	@rc=0; \
	./tools/boot-smoke-devpts.sh x86 $(DEVPTS_SMOKE_TIMEOUT) & p1=$$!; \
	./tools/boot-smoke-devpts.sh arm $(DEVPTS_SMOKE_TIMEOUT) & p2=$$!; \
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

# A target check parses but does not assemble `global_asm!`; a linked kernel can
# therefore be the first artifact able to prove each faultable user atomic has
# a recovery entry. x86 has one faultable cmpxchg; arm has load+store-exclusive.
uaccess-extable-gate-x86: x86
	python3 tools/uaccess-extable-gate.py $(KERNEL_ELF_x86_64) --expected 1
uaccess-extable-gate-arm: arm
	python3 tools/uaccess-extable-gate.py $(KERNEL_ELF_aarch64) --expected 2
uaccess-extable-gate: uaccess-extable-gate-x86 uaccess-extable-gate-arm

# Execute the linked S3 real-mode blob at the physical waking vector under a
# minimal firmware-shaped guest. The payload asserts the CR0/CR3/CR4/EFER and
# selector state after the blob's 16 -> 32 -> 64-bit transition.
s3-resume-gate-x86: x86
	python3 tools/s3-resume-gate.py --self-test $(KERNEL_ELF_x86_64)

# Hardware-shaped acceptance: Q35/SeaBIOS enters ACPI S3, QMP posts the wake,
# and the guest must return through the saved processor context to its shell.
accept-s3-resume-x86:
	python3 tools/s3-resume-accept.py

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
# THIRD budget domain: the exception-entry RESERVE (`--entry-roots`). A
# kernel-mode exception is not dispatched on a stack of its own the way an
# interrupt is — the vector pushes its 288-byte frame onto the INTERRUPTED
# task's stack and calls the handler there — so its whole chain is spent on top
# of whatever that path had already used. Measured 6032 B on aarch64 (the
# demand-page resolver plus the blocking tail), ceiling 6100.
#
# It follows that the honest task ceiling is `16384 - 288 - 6100 = 9996`, not
# the 13000 above: the deepest task paths measure 11904 B, so a maximal path
# taking one demand page overflows by ~1800 B. That is the `[BADSTACK] BELOW-LO
# by 32` class, and burning it down is tracked in `scratch/known_issues.md`.
# Pinning the reserve here is what stops the OTHER half of the sum growing
# while that work is outstanding.
ENTRY_RESERVE_CEILING ?= 6100
# x86_64 measures 7152 B for the same chain (an ordinary `#PF` is not IST-routed,
# so it too runs on the interrupted task's stack). Its deepest task path is
# 12720 B, so that arch is over the same sum by more — it has simply never been
# unlucky enough to take a demand page at the bottom of a driver probe.
ENTRY_RESERVE_CEILING_x86 ?= 7200
stack-gate-x86: x86
	python3 tools/stack-depth-gate.py --self-test
	python3 tools/stack-depth-gate.py $(KERNEL_ELF_x86_64) \
	  --arch x86_64 --fail $(STACK_DEPTH_CEILING) \
	  --stack-switch-map tools/stack-switches-x86_64.tsv \
	  --allowlist tools/stack-depth-allow-x86_64.txt \
	  --indirect-map tools/entry-edges-x86_64.tsv \
	  --entry-roots tools/entry-roots-x86_64.txt --entry-fail $(ENTRY_RESERVE_CEILING_x86)
stack-gate-arm: arm
	python3 tools/stack-depth-gate.py $(KERNEL_ELF_aarch64) \
	  --arch aarch64 --fail $(STACK_DEPTH_CEILING) \
	  --allowlist tools/stack-depth-allow-aarch64.txt \
	  --indirect-map tools/entry-edges-aarch64.tsv \
	  --entry-roots tools/entry-roots-aarch64.txt --entry-fail $(ENTRY_RESERVE_CEILING)
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
	$(WARNING_RUN) cargo run --quiet -p xtask -- kernel --arch x86_64 --features $(GATE_FEATURES) --check
feature-gate-arm:
	$(WARNING_RUN) cargo run --quiet -p xtask -- kernel --arch aarch64 --features $(GATE_FEATURES) --check
feature-gate: feature-gate-x86 feature-gate-arm

# The mutually-exclusive half: `debug-atexit` instead of `debug-stderr`.
feature-gate-atexit:
	$(WARNING_RUN) cargo run --quiet -p xtask -- kernel --arch x86_64 --features debug-atexit,debug-all --check
	$(WARNING_RUN) cargo run --quiet -p xtask -- kernel --arch aarch64 --features debug-atexit,debug-all --check

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
	$(WARNING_RUN) ./tools/hosted-check.sh

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
	$(WARNING_RUN) ./tools/test-build-check.sh

test-build-check-selftest:
	./tools/test-build-check-selftest.sh

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

# SOL_NETLINK / SOL_SOCKET-on-netlink-fd differential — the level pair
# af_packet_diff (SOL_PACKET) and glibc_conformance (neither) don't cover.
SOCKOPT_DIFF_SMOKE_TIMEOUT ?= 900
smoke-sockopt-diff-x86:
	./tools/boot-smoke-sockopt-diff.sh x86 $(SOCKOPT_DIFF_SMOKE_TIMEOUT)
smoke-sockopt-diff-arm:
	./tools/boot-smoke-sockopt-diff.sh arm $(SOCKOPT_DIFF_SMOKE_TIMEOUT)
# Recursive makes keep the two boots sequential even under a top-level -j.
smoke-sockopt-diff:
	$(MAKE) smoke-sockopt-diff-x86
	$(MAKE) smoke-sockopt-diff-arm

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
# F1173: HD-Audio acceptance. Boots with an intel-hda controller and a duplex
# codec attached and asks the guest whether the second sound card's nodes
# exist — they appear only after the controller reset, a codec answered, the
# generic parser found a route and the ALSA card registered.
V4L2_SMOKE_TIMEOUT ?= 900
LDT_SMOKE_TIMEOUT ?= 600
ATA_IDENTITY_SMOKE_TIMEOUT ?= 900
ATA_SAT_SMOKE_TIMEOUT ?= 900
USB_SCSI_SMOKE_TIMEOUT ?= 900
HDA_SMOKE_TIMEOUT ?= 900
# V4L2 acceptance. The probe is injected into a disposable boot root and run
# as a unit before basic.target, so the verdict lands on the serial console
# without a shell in the loop. It captures real frames through /dev/video0 and
# asserts the mapped pages are no longer zero — a node in /dev proves
# publication and nothing else.
smoke-v4l2-x86:
	OXIDE_V4L2_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='v4l2_probe: PASS' ./tools/boot-smoke.sh x86 $(V4L2_SMOKE_TIMEOUT)
smoke-v4l2-arm:
	OXIDE_V4L2_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='v4l2_probe: PASS' ./tools/boot-smoke.sh arm $(V4L2_SMOKE_TIMEOUT)
smoke-v4l2:
	OXIDE_V4L2_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='v4l2_probe: PASS' ./tools/boot-smoke.sh x86 $(V4L2_SMOKE_TIMEOUT) & p1=$$!; \
	OXIDE_V4L2_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='v4l2_probe: PASS' ./tools/boot-smoke.sh arm $(V4L2_SMOKE_TIMEOUT) & p2=$$!; \
	 rc=0; wait $$p1 || rc=1; wait $$p2 || rc=1; exit $$rc

# x86 LDT acceptance: install a descriptor, load DS, and keep a second thread
# on CPU1 while the CPU0 syscall converges the address space's LDT remotely.
smoke-ldt-x86:
	OXIDE_LDT_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='ldt_probe: PASS' ./tools/boot-smoke.sh x86 $(LDT_SMOKE_TIMEOUT)

# Both default QEMU profiles provide the same emulated AHCI disk. This
# acceptance opens its real `sd*` node and checks the IDENTIFY page copied
# through its ioctl, keeping the runtime contract in lockstep on both arches.
smoke-ata-identity-x86:
	OXIDE_ATA_IDENTITY_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='ata_identity_probe: PASS' ./tools/boot-smoke.sh x86 $(ATA_IDENTITY_SMOKE_TIMEOUT)

smoke-ata-identity-arm:
	OXIDE_ATA_IDENTITY_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='ata_identity_probe: PASS' ./tools/boot-smoke.sh arm $(ATA_IDENTITY_SMOKE_TIMEOUT)

smoke-ata-identity: smoke-ata-identity-x86 smoke-ata-identity-arm

# ATA PASS-THROUGH(16)/(32) reaches the AHCI taskfile owner through shared
# SG_IO. The serial debug shell invokes the probe after AHCI publishes `sd*`,
# before unrelated user-session services can affect the result.
smoke-ata-sat-x86:
	OXIDE_ATA_SAT_SMOKE=1 SMOKE_MARKER='ata_sat_probe: PASS' SMOKE_ALIVE_CMD=/usr/local/bin/ata_sat_probe SMOKE_ALIVE_MARKER='ata_sat_probe: PASS' ./tools/boot-smoke.sh x86 $(ATA_SAT_SMOKE_TIMEOUT)

smoke-ata-sat-arm:
	OXIDE_ATA_SAT_SMOKE=1 SMOKE_MARKER='ata_sat_probe: PASS' SMOKE_ALIVE_CMD=/usr/local/bin/ata_sat_probe SMOKE_ALIVE_MARKER='ata_sat_probe: PASS' ./tools/boot-smoke.sh arm $(ATA_SAT_SMOKE_TIMEOUT)

smoke-ata-sat: smoke-ata-sat-x86 smoke-ata-sat-arm

# The x86 native PCI profile and ARM's default topology each carry a native
# PCI xHCI controller and USB Bulk-Only disk. The serial-shell probe proves
# shared SCSI discovery and commands rather than controller enumeration alone.
# Start that command only after udev is serving the published block-device
# kobjects; the serial debug shell itself is available earlier.
smoke-usb-scsi-x86:
	OXIDE_QEMU_PROFILE=native-pci OXIDE_USB_SCSI_SMOKE=1 SMOKE_MARKER='usb_scsi_probe: PASS' SMOKE_ALIVE_READY_MARKER='Started systemd-udevd.service' SMOKE_ALIVE_CMD=/usr/local/bin/usb_scsi_probe SMOKE_ALIVE_MARKER='usb_scsi_probe: PASS' ./tools/boot-smoke.sh x86 $(USB_SCSI_SMOKE_TIMEOUT)

smoke-usb-scsi-arm:
	OXIDE_USB_SCSI_SMOKE=1 SMOKE_MARKER='usb_scsi_probe: PASS' SMOKE_ALIVE_READY_MARKER='Started systemd-udevd.service' SMOKE_ALIVE_CMD=/usr/local/bin/usb_scsi_probe SMOKE_ALIVE_MARKER='usb_scsi_probe: PASS' ./tools/boot-smoke.sh arm $(USB_SCSI_SMOKE_TIMEOUT)

smoke-usb-scsi:
	$(MAKE) smoke-usb-scsi-x86
	$(MAKE) smoke-usb-scsi-arm

smoke-hda-x86: x86
	./tools/boot-smoke-hda.sh x86 $(HDA_SMOKE_TIMEOUT)
smoke-hda-arm: arm
	./tools/boot-smoke-hda.sh arm $(HDA_SMOKE_TIMEOUT)
smoke-hda: smoke-hda-x86 smoke-hda-arm

FS_SMOKE_TIMEOUT ?= 600
smoke-fs-x86: x86
	./tools/boot-smoke-fs.sh x86 $(FS_SMOKE_TIMEOUT)
smoke-fs-arm: arm
	./tools/boot-smoke-fs.sh arm $(FS_SMOKE_TIMEOUT)
smoke-fs: smoke-fs-x86 smoke-fs-arm

# Host-share acceptance: the guest mounts a QEMU-exported host directory and
# reads a file the host wrote. The only check that exercises a real descriptor
# chain; everything above it is hosted (`63§9`).
smoke-hostshare-x86: x86
	./tools/boot-smoke-hostshare.sh x86 $(FS_SMOKE_TIMEOUT)
smoke-hostshare-arm: arm
	./tools/boot-smoke-hostshare.sh arm $(FS_SMOKE_TIMEOUT)
smoke-hostshare: smoke-hostshare-x86 smoke-hostshare-arm

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
	OXIDE_REQUEST_KEY_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='REQUEST-KEY-PROBE: PASS' ./tools/boot-smoke.sh x86 $(REQUEST_KEY_SMOKE_TIMEOUT)
smoke-request-key-arm: arm
	OXIDE_REQUEST_KEY_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='REQUEST-KEY-PROBE: PASS' ./tools/boot-smoke.sh arm $(REQUEST_KEY_SMOKE_TIMEOUT)
smoke-request-key: smoke-request-key-x86 smoke-request-key-arm

# Ext4 swapfile + memcg pageout smoke. The shared probe helper emits the
# lowercase probe name, so keep the marker exact rather than accepting a prefix.
SWAPFILE_SMOKE_TIMEOUT ?= 600
smoke-swapfile-x86: x86
	OXIDE_SWAPFILE_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='swapfile_probe: PASS' ./tools/boot-smoke.sh x86 $(SWAPFILE_SMOKE_TIMEOUT)
smoke-swapfile-arm: arm
	OXIDE_SWAPFILE_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='swapfile_probe: PASS' ./tools/boot-smoke.sh arm $(SWAPFILE_SMOKE_TIMEOUT)
smoke-swapfile: smoke-swapfile-x86 smoke-swapfile-arm

# GNOME input classification smoke. Its injected script reports a single
# tagged PASS/FAIL line; require the passing verdict from the boot log.
GNOME_INPUT_CLASSIFY_SMOKE_TIMEOUT ?= 600
smoke-gnome-input-classify-x86: x86
	OXIDE_GNOME_INPUT_CLASSIFY_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='gnome_input_classify: PASS' ./tools/boot-smoke.sh x86 $(GNOME_INPUT_CLASSIFY_SMOKE_TIMEOUT)
smoke-gnome-input-classify-arm: arm
	OXIDE_GNOME_INPUT_CLASSIFY_SMOKE=1 SMOKE_ALIVE_PROBE= SMOKE_MARKER='gnome_input_classify: PASS' ./tools/boot-smoke.sh arm $(GNOME_INPUT_CLASSIFY_SMOKE_TIMEOUT)
smoke-gnome-input-classify: smoke-gnome-input-classify-x86 smoke-gnome-input-classify-arm

LOGIN_SMOKE_TIMEOUT ?= 600
smoke-login-x86: x86
	./tools/boot-smoke-login.sh x86 $(LOGIN_SMOKE_TIMEOUT)
smoke-login-arm: arm
	./tools/boot-smoke-login.sh arm $(LOGIN_SMOKE_TIMEOUT)
smoke-login: smoke-login-x86 smoke-login-arm

# Native-Q35 traffic gate. Fedora's production image uses NetworkManager, so
# this waits for a real eth0 IPv4 lease and then pings the QEMU gateway over
# the 82574L/e1000e path. It stages the image before the guest deadline.
NETWORK_SMOKE_TIMEOUT ?= 600
smoke-network-native-pci-x86:
	OXIDE_QEMU_PROFILE=native-pci python3 tools/guest-network-check.py x86 $(NETWORK_SMOKE_TIMEOUT)

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

# Produce the x86_64 GRUB ISO and companion root image with the manual
# physical-hardware auditor at /usr/local/bin/oxide-hardware-audit.  The
# current physical boot path still needs a root-device handoff; this target
# makes the diagnostic available as soon as that image has booted.
hardware-audit-image-x86:
	OXIDE_HARDWARE_AUDIT=1 $(XTASK) image --arch x86_64

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
