# Session hand-off

## Headline
Two things shipped this session; three live-test bugs diagnosed (NOT fixed),
all PRE-EXISTING (not caused by the namei work).

- **PR #1526** `F377-namei-unified-walk` (stacked on F376/#1525): unified
  every `*at` syscall behind one `pathresolve::lookupat` (Linux nameidata)
  + open(2) stores the canonical walk dentry. **Fixes `find /` ENOENT
  (OPEN BUG 1) → FIND_NOENT=0 on both arches.** Boots both arches, make
  test green, spec-lint clean.
- **C14** `C14-qemu-mcp-x86-seabios` (pushed, no PR yet): MCP x86 boots via
  SeaBIOS (dropped `-bios OVMF`, which crashed "no suitable video mode").
  **Needs an MCP/Claude restart to take effect** — then `qemu_screen`
  (framebuffer) + gdb memory inspection work again.

## CRITICAL gotcha (cost ~8 boots): faccessat empty-path errno
`faccessat` MUST return **EINVAL, not ENOENT**, for an empty path. systemd
probes fds with `faccessat(fd,"",AT_EMPTY_PATH)`; EINVAL = "fall back",
ENOENT = "target gone" → PID1 aborts ("Failed to allocate manager object").
Already handled in #1526; don't regress it.

## THREE OPEN BUGS (live-test; user wants all fixed; pre-existing)

### BUG A — no input echo at shell prompt (gtk console)
- Username echoes; password doesn't (correct); shell prompt: typed chars
  invisible, program output renders fine.
- Shell prompt termios = `c_lflag=0x8a31` (raw, ICANON off, ECHO off) →
  readline self-echoes. **Echo WORKS on serial/UART** (proven: injected
  `qwer` echoes). gtk renders program output but NOT echo.
- Both echo (`tty_emit`) and output (`console_emit`) = `klog::write_raw`
  → `invoke_sink` → AUX_SINK = `fbcon::kernel::klog_sink`
  (crates/drivers/fbcon/src/lib.rs:821). klog_sink does `CONSOLE.try_lock()`
  (DROPS byte on contention) + defers GPU flush to softirq FbconFlush;
  old timer `tick_drain` is a NO-OP. Suspect: echo (IRQ/softirq ctx) byte
  dropped, or flush not landing on fbcon while output's does.
- **BLOCKER: can't see the framebuffer.** Boot harness is headless (UART
  only). Need MCP `qemu_screen` (post C14 restart) to watch fbcon while
  typing, then fix klog_sink/flush + verify visually.

### BUG B — python `import` segfaults
- `python3 -c "print(1)"` + `--version` WORK. `import json` (script OR
  REPL) → **SIGSEGV (PYRC=139)**. Proven pre-existing on base 6b53cd21.
- Kernel fault (debug-irq): **#GP vec=0x0d**, err=0, `rip=0x4003c02c`
  (a lib mmap'd ~0x40000000). bytes@rip = `f4 4c 63 ca 4c 39 cf 73 ...`
  → first byte **0xf4 = HLT** (privileged → #GP). Bytes after are valid
  code ⇒ an **indirect transfer (GOT/PLT/fnptr/ret) jumped to a bad
  address** in a DYNAMICALLY-linked lib. python3-x86_64 is dynamic
  (interp /lib/ld-musl), NOT static despite rootfs.rs comment.
- Likely a **dynamic-linker relocation/GOT bug** (dyn linker = phase 13);
  `import` hits a reloc path `-c print` doesn't.
- **NEXT:** gdb the GOT/call site at the fault (needs MCP, post-restart),
  OR pragmatic fix = ship a genuinely STATIC python (rootfs.rs intent).

### BUG C — cgroup "Directory not empty" on destroy (non-fatal)
- systemd: "Failed to destroy cgroup /system.slice/console-getty.service,
  ignoring: Directory not empty". `cgroup/tree.rs:244` remove()=ENOTEMPTY
  while procs/children remain. `cgroup_kill_hook` (cgroup_boot.rs:12) only
  POSTS the signal; the task leaves the cgroup later via sys_exit→
  `cgroup::on_exit` (mod.rs:316) → kill→rmdir RACE. systemd ignores it.
- Correct fix needs systemd reproduction; the "yank not-yet-dead task from
  cgroup" quick fix is a façade (project forbids). Lowest priority.

## Diagnostic recipes that worked (avoid re-discovering)
- Boot alongside the user's live qemu WITHOUT conflict (rootfs write-lock
  + port 2222 collide): `cp kernel/blobs/rootfs-x86_64.img
  /tmp/rootfs-test-x86.img`; sed `tools/xtask/src/image_qemu.rs` hostfwd
  2222→2223 AND the x86 rootfs path → the /tmp copy. REVERT before commit.
- `[FAULT]` rip/cr2/PFEC + GPR dump: build `--features debug-boot,debug-irq`.
  User #GP/#PF prints "sigsegv: kill" via
  crates/kernel/mm-pmm/src/user_as/signal.rs `sigsegv_terminate_x86`.
- bytes@rip (decode faulting insn w/o gdb): temporary read_volatile loop
  over `_rip` in that fn's debug-irq block.
- per-keystroke echo lflag: temporary NON-locking `out dx,al` to COM2
  (0x2F8) in crates/kernel/tty/src/live.rs `push_and_wake_fg`; add
  `-serial file:/tmp/oxide-com2.log` to qemu. (COM1 dtrace! pollutes the
  console parse; COM2 keeps it clean. push_and_wake_fg runs in IRQ ctx —
  do NOT call locking klog there or you deadlock the boot.)

## First commands next session
```
cd /home/nd/oxide2 && git log --oneline -6 && git branch
```
1. After restart (C14 loaded), MCP works: `qemu_start arch=x86_64` →
   `qemu_screen` for BUG A; gdb the GOT for BUG B.
2. Branches: F377 (#1526) + C14 pushed; B53-python-script-segfault is an
   empty placeholder. F376/#1525 still open (base of #1526).
3. Decide on BUG B: static python vs implement the dynamic-linker reloc.
