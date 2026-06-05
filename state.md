# Session hand-off

## Headline
Working the 3 live-test bugs (A/B/C). **B FIXED + shipped.** A in progress
(proven userspace readline, kernel exonerated). C needs a verdict. Plus two
cleanups (Limine arm remnant, libpam debug). Active branch: `B57-readline-echo`.

## PRs / branches
- **#1529** (`B56-mremap-source-leak` → main, OPEN): BUG B fix, standalone off
  main. Replaces the stacked #1527 (closed).
- **#1528** (`C76-block-ai-attribution` → main, OPEN): commit-msg hook banning
  AI/tool attribution (Claude/Copilot/Codex/…). 62 PR bodies already stripped.
- **`B57-readline-echo`** (current, off main, NOT pushed): 2 commits —
  `841b0d8a` make qemu-x86{,-debug}→GRUB (kill dead Limine target),
  `56b37f15` select/poll/pselect/ppoll block on a wait queue (Linux way, not
  busy-yield). Both validated; neither fixes the echo.
- F376 #1525 (arm GRUB) + F377 #1526 still open (pre-existing).

## BUG B — python `import` SIGSEGV → FIXED (#1529)
mremap normal move/shrink removed the source VMA but left its PTEs+frames
mapped → vacated VA recycled by a later mmap → stale-frame alias → musl
mallocng `a_crash()`. Fix: `sys_mremap` evicts the source range's PTEs+frames
on move (`va!=old`) and shrink. Verified x86+arm (python import + 400MB
bytearray stress PASS; negative control `mremap_alias_smoke` FAIL→PASS).
10 mm/tty regression probes in `userspace/*_smoke`.

## BUG A — no echo at bash prompt → IN PROGRESS (kernel exonerated)
NOT a bash bug — readline works everywhere, so oxide violates a contract it
relies on. Established:
- readline reads each keystroke (1-byte `read`, confirmed) but emits the
  **prompt** and suppresses the **per-keystroke redisplay** until Enter.
- Every kernel tty contract verified correct: raw per-char RX, blocking read,
  `poll()` readiness (p=empty/P=ready), termios get/set round-trip, winsize
  24×80, isatty 0/1/2, writev, canonical kernel echo (`cat` echoes), cooked
  lflag reads ECHO=on. `bash --noediting` (kernel canonical echo) works.
- Ruled out: terminfo `linux` (present, byte-identical to host), /etc/termcap
  (added, no effect), all TERM values, select/poll busy-poll (fixed in B57 —
  echo still broken, so the wait model was NOT the cause).
- **NEXT (the only path left):** white-box readline — build a readline-linked
  binary WITH symbols from `vendor/bash/bash-5.2.37` sources, run on oxide,
  gdb/trace `rl_redisplay` to find which oxide syscall return it reacts to.
  bash's bundled readline is stripped+static, so can't gdb it directly.

## BUG C — cgroup ENOTEMPTY on destroy → PENDING VERDICT
systemd SIGKILLs a service's procs then rmdir's its cgroup; killed procs leave
the cgroup async via `cgroup::on_exit` (sys_exit) → rmdir races → ENOTEMPTY,
systemd logs "ignoring". UNKNOWN: benign transient (self-heals, matches Linux)
vs real leak (cgroup never reaped). NEXT: reproduce on an isolated rootfs —
does SIGKILL promptly kill a blocked proc, and does the cgroup eventually get
removed? No façade (don't yank live tasks from the cgroup).

## Cleanups (task #8)
- Limine: x86 default targets now GRUB; dead `cmd_image`/`cmd_qemu`/
  `check_vendor` Limine code + the aarch64 Limine boot path remain. aarch64
  needs a GRUB/EFI-stub path (F376) before the Limine code deletes lockstep.
- libpam prints `[../libpam/...]` debug to stderr on login (pam.d configs are
  clean → debug-compiled libpam). Rebuild `vendor/pam` without debug to silence.

## Environment gotchas (cost hours this session)
- NEVER build/copy the shared `kernel/blobs/rootfs-x86_64.img` while a qemu has
  it open (write-lock) — corrupts the running guest. Use a /tmp rootfs copy +
  the shared `-cdrom` ISO (read-only) for test boots. Driver: `/tmp/oxide_drive.py`.
- `make qemu-x86` now = GRUB (was stale-Limine). `make qemu-arm` still Limine
  (broken until F376). Build via `cargo run -p xtask -- grub --arch x86_64`.

## First command next session
```
cd /home/nd/oxide2 && git log --oneline -6 && git branch --show-current
# echo white-box: build a readline test binary w/ symbols, boot, gdb rl_redisplay
```
