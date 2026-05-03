# qemu-mcp

Interactive QEMU + GDB control surface, exposed as an MCP server so
Claude Code can drive kernel debugging without round-tripping through
shell scripts.

Built specifically for the silent-fault investigations P1-93
(kernel-owned GDT) and P1-86c (page-fault recovery) ran into — both
needed gdb-stub single-stepping that the shell-only flow couldn't
provide.

## Tool surface

```
qemu_start(arch)           build image, spawn paused QEMU + GDB
qemu_break(target)         set breakpoint at symbol or 0xADDR
qemu_continue()            resume; blocks until next stop
qemu_stepi(count=1)        single-instruction step
qemu_step(count=1)         source-level step
qemu_finish()              step out of current frame
qemu_regs()                all CPU registers
qemu_mem(addr, count=64)   raw bytes
qemu_disasm(addr, n=8)     disassemble n insns
qemu_backtrace()           call stack
qemu_info(what)            `info <what>` (registers, breakpoints, ...)
qemu_serial(clear=False)   accumulated kernel stdout
qemu_stop()                tear down session
```

## Typical session

```
qemu_start("x86_64")
qemu_break("install_kernel_gdt")
qemu_continue()                        # runs until breakpoint
qemu_disasm("$pc", 16)                 # see the asm we're about to run
qemu_stepi(1)                          # step one instruction
qemu_regs()                            # inspect CR0, RFLAGS, segment regs
qemu_info("registers")                 # human-readable `info registers`
qemu_mem("&GDT", 64)                   # dump the GDT
qemu_continue()
qemu_serial()                          # any kernel klog output so far
qemu_stop()
```

## Implementation

Pure stdlib + the `mcp` Python package (already on Claude Code's
path). No `pygdbmi` / `pwntools` / venv requirement.

* `qemu_start` runs `cargo run -p xtask -- image --arch <arch> --features debug-all`,
  then spawns `qemu-system-<arch>` with the same args as
  `xtask qemu` plus `-s -S` (gdb-stub on :1234, paused at entry).
* `gdb --interpreter=mi3 <kernel.elf>` is spawned alongside;
  background reader threads drain stdout into ring buffers.
* Tools forward GDB/MI commands and block on the next `(gdb)`
  prompt; `qemu_continue` extends that to wait for the next
  `*stopped` MI record.
* `qemu_stop` SIGTERMs the QEMU process group and tells GDB
  `-gdb-exit`. Idempotent.

## Registering with Claude Code

The repo's `.mcp.json` declares the server; Claude Code auto-loads it
on session start when the user opens a chat in this repo. Manual
launch for testing: `python3 tools/qemu-mcp/server.py` (it reads MCP
messages on stdin / writes on stdout — you'd usually let Claude
manage it).

## Why dev-only

Per `docs/02§*` (spec lifecycle), this tool sits outside any kernel
artifact and is not on the PR-time CI gate. It's a Claude-Code
ergonomic — kernel bring-up at QEMU level. The `make` / `xtask`
flows remain the canonical CI / human entrypoints.
