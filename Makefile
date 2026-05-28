# oxide2 — convenience wrapper around `cargo run -p xtask`.
# All real logic lives in `tools/xtask`; this file is just shorter
# names + grouped targets for humans.

CARGO    ?= cargo
XTASK    := $(CARGO) run -p xtask --
FEATURES ?=

# `make build`           — kernel libs + bin shims, both arches, default features.
# `make x86 / arm`       — single arch.
# `make *-debug`         — same with `--features debug-all`.
# `make test`            — hosted unit tests (no kernel target).
# `make lint`            — `xtask spec-lint`.
# `make ci`              — what PR gate runs: spec-lint, test, both arches default + debug-all.
# `make qemu-x86 / qemu-arm` — boot under QEMU with `--features debug-all`.
# `make qemu-mcp`        — print the MCP tool list (interactive QEMU debug).
# `make clean`           — `cargo clean`.

.PHONY: all build x86 arm \
        build-debug x86-debug arm-debug \
        test lint ci \
        qemu-x86 qemu-arm qemu-x86-debug qemu-arm-debug qemu-mcp \
        clean help

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

qemu-x86:
	$(XTASK) qemu --arch x86_64  --features "$(QEMU_FEATURES_X86)"

qemu-arm:
	$(XTASK) qemu --arch aarch64 --features "$(QEMU_FEATURES_ARM)"

# Same but with `--features debug-all` (every syscall trace + LAPIC
# tick + boot-pulse log). Useful for kernel debugging; not what you
# want when just trying to log in and use it.
qemu-x86-debug:
	$(XTASK) qemu --arch x86_64  --features debug-all

qemu-arm-debug:
	$(XTASK) qemu --arch aarch64 --features debug-all

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
# Default 6 so the rotation reaches every CMDS[]/WANTS[] entry
# (echo, id, /etc/passwd, uname, pwd, /bin/bash).
SSH_SMOKE_CONNECTIONS ?= 6
smoke-ssh-x86: x86
	./tools/boot-smoke-ssh.sh x86 $(SSH_SMOKE_TIMEOUT) $(SSH_SMOKE_CONNECTIONS)
smoke-ssh-arm: arm
	./tools/boot-smoke-ssh.sh arm $(SSH_SMOKE_TIMEOUT) $(SSH_SMOKE_CONNECTIONS)
smoke-ssh: smoke-ssh-x86 smoke-ssh-arm

# Rebuild kernel/blobs/rootfs.img from userspace/ sources. Run after
# editing any userspace/<name>/<name>.c so include_bytes! picks up
# the new bytes on the next kernel build.
rootfs:
	$(XTASK) rootfs

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

help:
	@awk '/^# `make / { sub(/^# /,""); print }' $(firstword $(MAKEFILE_LIST))
