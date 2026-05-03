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
        qemu-x86 qemu-arm qemu-mcp \
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

qemu-x86:
	$(XTASK) qemu --arch x86_64  --features debug-all

qemu-arm:
	$(XTASK) qemu --arch aarch64 --features debug-all

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
