# Session hand-off

## Headline
Branch `B53-python-script-segfault` (stacked on F377 #1526 / F376 #1525).
Of the 3 pre-existing live-test bugs: **BUG B FIXED + verified both arches**;
**BUG A root-caused to userspace bash/readline (kernel exonerated)**;
**BUG C confirmed cosmetic**. Net new: 1 real kernel fix + 10 regression probes.

## BUG B — python `import` SIGSEGV → **FIXED** (commit e27a7986)
- **Root cause:** `sys_mremap` (kernel/src/syscalls/proc.rs) only evicted the
  source range on the MREMAP_DONTUNMAP path. The normal **move/grow** and
  **shrink** paths removed the source *VMA* via `AddressSpace::munmap`
  (VMA-bookkeeping only) but left the old VA's **PTEs mapped + frames
  allocated**. The vacated VA became an allocatable hole; a later mmap reused
  it, hit the stale PTE (no demand-fault), and aliased the old frame's stale
  contents. musl mallocng read non-zero where a fresh group must be zero →
  `a_crash()` (#GP vec 0x0d at ld-musl, rip in a_crash/hlt).
- **Fix:** evict source PTEs+frames (`pmm::user_as::evict_pages_in_range`) on
  the move (`va != old`) and shrink (`new_size < old_size`) paths too.
- **Why C probes initially passed:** the bug needs mremap (mallocng realloc of
  large blocks). Single-allocator churn never recycled the leaked VA.
- **Diagnosis path (reusable):** see `/tmp/oxide_drive.py` — self-contained
  QEMU driver (SeaBIOS x86 / OVMF arm, KVM, serial-socket expect/send, QMP
  screendump, optional gdb). Vendored python+musl run PERFECTLY on the host
  kernel (differential test) → proved it was an oxide kernel bug. sigsegv
  handler stack-scan (commit 16192c28) recovered the mallocng call chain.

### BUG B metrics (x86_64 + aarch64, 0 SIGSEGV after fix)
| test | pre-fix | post-fix |
|---|---|---|
| `python3 -c "import json,re,enum,collections"` | SEGV(139) | PASS |
| `[bytearray(2000) for _ in range(200000)]` (400MB) | SEGV(139) | PASS |
| PYTHONMALLOC={malloc,pymalloc,*_debug} import | SEGV | PASS |
| `/bin/mremap_alias_smoke` (negative control) | FAIL rc=1 STALE | PASS |
| mmchurn/mallocstress(static+dyn)/mtmalloc/sigmalloc | PASS | PASS |
- **Negative control proven:** with the fix reverted, mremap_alias_smoke
  FAIL(rc=1) + python SEGV(139); with fix, all PASS. The test has teeth.

## BUG A — no echo at bash prompt → **userspace readline, NOT kernel**
state.md's old klog_sink-byte-drop hypothesis is **DISPROVEN**.
- `/bin/sh` is **bash 5.2** (readline → raw mode → self-echo). At the prompt
  bash **reads each char per-char** (`read(,1)` returns immediately, proven via
  COM2 trace) but issues **zero echo writes until Enter**, then echoes the whole
  line. So readline suppresses incremental echo.
- **Kernel exonerated** — every tty mechanism readline uses is verified correct
  via probes (commit 154916b9): rawecho (raw blocking-read+write echo 14/14),
  pollecho (poll(POLLIN)+read 8/8), termios_rt (ICANON|ECHO clear round-trips),
  isatty(0/1/2)=1, kernel canonical echo works (cat echoes on serial+fbcon),
  raw per-char RX delivery to VT_RINGS, TIOCGWINSZ=24×80, writev to console,
  /dev/tty, stdio line-buffering+fflush. cooked lflag readline reads = 0x3b
  (ECHO ON) so `readline_echoing_p` should be TRUE.
- **Reproduces identically on serial and gtk** → not fbcon-specific.
- **Next step (userspace):** white-box readline (gdb on the bash binary with
  readline symbols) to find why incremental redisplay is deferred despite
  echoing_p TRUE + correct input-availability; OR rebuild bash/readline. NOT a
  kernel fix — do not fabricate one.

## BUG C — cgroup ENOTEMPTY on destroy → cosmetic, lowest priority
systemd kills cgroup procs then rmdirs; SIGKILL'd procs leave the cgroup
asynchronously via `cgroup::on_exit` (sys_exit), so rmdir races and gets
ENOTEMPTY — which systemd logs as "ignoring" (non-fatal, matches Linux's own
transient). The "yank live task from cgroup" quick fix is a façade (forbidden).
A correct fix = synchronous kill-drain or systemd cgroup.events polling; needs
systemd-side repro. Left as-is.

## First commands next session
```
cd /home/nd/oxide2 && git log --oneline -6 && git branch
```
1. BUG B commits: e27a7986 (fix) + 1835bb61 (mm probes) + 16192c28 (diag) +
   154916b9 (tty probes), on B53 (stacked on F377 #1526 / F376 #1525).
   Push + PR base=F377 once F376/F377 merge, or rebase onto main after.
2. BUG A: attach gdb to the bash binary (readline) to finish the readline
   echo-defer root cause; kernel side is done.
3. Driver harness `/tmp/oxide_drive.py` + probes in `userspace/*_smoke/`.
