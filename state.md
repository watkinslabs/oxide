# Session hand-off

## Headline
**OXIDE distro: roadmap items 1-4 DONE.** systemd PID1 → `oxide login:` on
x86_64 AND aarch64; GNU /bin userland; and **CPython 3.13.1 at /usr/bin/python3
— DYNAMIC, with ctypes + ssl + full stdlib** on both arches. 27 PRs this
session (#1482-#1504). main @ 827d6e93. Only roadmap item 3 (GRUB) remains,
DEFERRED for user scoping.

## Python — DONE (dynamic, Linux-class), #1501/#1502/#1503/#1504
- vendor/python/{build.sh,python3-x86_64,python3-aarch64,python313.zip} +
  tools/fetch-python.sh. CPython 3.13.1 cross-built musl, **DYNAMIC exe**
  (PT_INTERP=/lib/ld-musl-<arch>.so.1 — same loader path as bash/sshd).
- All stdlib C extensions BUILTIN (Setup.local *shared*->*static*); pure-py
  stdlib zipped 2.6M at /usr/lib/python313.zip (getpath auto-adds it → no
  env vars). **_ssl + _hashlib** via vendored static openssl .a (#1503).
  **_ctypes** via vendored static libffi 3.4.6 (#1504 — needed DYNAMIC so
  PyDLL/dlopen works; a static musl binary has no dynamic linker).
- DT_NEEDED = libssl.so.3/libcrypto.so.3/ld-musl, ALL staged (/usr/lib,/lib).
- Host-verified (exact binary + vendored ld-musl): import os/json/re/zlib/
  socket/hashlib/ssl/ctypes; CDLL(None).strlen=5; ssl.OPENSSL_VERSION=3.0.15.
  Both arches boot-smoke PASS with python staged (x86 34s, arm 40s).
- Remaining stdlib gaps (low value): _curses/_dbm/_gdbm/_tkinter/_bz2/_lzma
  (terminal/db/compression libs not vendored). _ctypes/dlopen now WORK →
  pip + native wheels are unblocked (future).
- NOTE: F364's static openssl .a (vendor/openssl/install-*/lib/*.a) are now
  unused by the dynamic python (it links the .so) — harmless, left in place.

## REAL BUG FOUND: kernel console-RX → getty delivery gap (login can't complete)
Tried hard to drive an interactive `python3 -c` in-kernel (definitive proof).
Characterised the blockers precisely:
1. **SMP polarity (CORRECTED — stale notes had it BACKWARDS)**: SMP=2 reaches
   `oxide login:` cleanly; SMP=1 wedges at the cat-smoke "A". boot-smoke uses
   OXIDE_SMP=2. Use SMP=2 for any login/interactive boot.
2. **serial input path**: piped-stdin→stdio chardev is unreliable BY DESIGN
   (image_qemu.rs:341); canonical = OXIDE_QEMU_UART_SOCK=<path> unix socket +
   external bridge. Built /tmp/sockdrive.py to drive it.
3. **THE BUG**: even via the canonical UART socket at SMP=2, with the boot
   cleanly at `oxide login:`, typed `root\n` is NOT consumed — no echo, no
   password prompt, no shell. So it's a KERNEL console-RX→getty gap, not a
   harness issue. tick_poll_uart IS armed during userspace (elf.rs:625) and
   pushes COM1 bytes to the foreground VT's waiters (tty/src/live.rs:181,
   push_and_wake_fg). Hypotheses to trace (klog, B22-style): (a) the
   console-getty agetty reads a VT != the fg VT push_and_wake_fg targets;
   (b) agetty's read() isn't registered as a VT waiter (poll vs blocking
   read?); (c) systemd console-getty's TIOCSCTTY/foreground-pgid setup breaks
   RX routing (/dev/console==/dev/ttyS0==ConsoleInode vt0 per devfs.rs:37/40,
   so likely job-control/fg-pgid, not the device). This blocks the distro
   endpoint ("boot→login→bash") — interactive login does not complete.
   python itself is verified by host-exec(exact artifacts) + both boot-smokes
   + same dynamic ELF class as in-kernel-proven bash; this bug is unrelated to
   python. **Tools left for the next session: /tmp/sockdrive.py (UART-socket
   driver), /tmp/py-login-proof.sh (set SMP=2).**

## NEXT (one PR each, both-arch gate) — pick lowest-risk highest-value
1. **pip/ensurepip** — now feasible (dynamic python + ssl + ctypes). Bundle
   pip (CPython ensurepip _bundled wheels, currently excluded), run
   `python -m ensurepip`, test `python3 -m pip --version` + install a
   pure-python wheel. Native-ext wheels need a target compiler (bigger; skip).
2. **Fix qemu-x86 cat-smoke wedge + console login-input** — unblocks
   interactive verification (incl. the python in-kernel proof). Investigate
   the kernel CAT smoke spin under qemu-x86 features vs smoke-x86; and the
   tty RX path for getty (TIOCSCTTY/foreground-pgid, console.rs park/wake).
   Could be deep — timebox.
3. **systemd sysinit chain** — build systemd-tmpfiles/-remount-fs helpers
   (ninja targets in vendor/systemd/build.sh) → clears the ask-password
   watch warning + a real sysinit.
4. **GRUB (item 3) — DEFERRED, user scoping.** Limine-native kernel
   (crates/arch/boot-x86_64 via Limine proto); GRUB = Multiboot2/EFI boot
   rewrite on both arches. High-risk, multi-PR. Advise-then-act first.
5. usr-merge (clears unmerged-usr taint; rootfs.rs at 991 → compact first).

## libffi recipe (for reference; vendored #1504)
github v3.4.6 sha256=b0dea9df23c863a7a50e825440f3ebffabd65df1497108e5d437747843895a4e;
`./configure --host=<triple> --disable-shared --enable-static
--disable-exec-static-tramp`; normalise x86 lib64→lib.

## CRITICAL harness rules (bit me repeatedly this session)
- Build/boot cmds run_in_background ALONE. NEVER a pkill/sleep/grep PREFIX in
  the same compound as make — dev shell `set -e` + BLOCKED foreground-sleep +
  pkill-returns-1-when-nothing-to-kill aborts the whole compound → missing/
  empty capture file = FALSE "failure". pkill in its OWN separate call
  (exit 1 = nothing running, fine). NEVER `&` inside (orphans redirect).
- boot SMP=1 (x86 cat-smoke spins under SMP=2). grep -a. Stale qemu squats
  :2222 → clear first.
- qemu MCP is TCG (slow) + flaky — wedged at UEFI this session. Use
  `make smoke-x86/smoke-arm` for boot status (KVM, ~35s to login).
- **rootfs-*.img** are build artifacts regenerated by `xtask rootfs`; tracked
  copies are stale 32M placeholders. GitHub rejects >100M — NEVER git-add the
  rebuilt 128M imgs. Commit only recipes (rootfs.rs).
- NEVER git-add vendor source trees (Python-3.13.1/, libffi-3.4.6/) or
  install-*/lib/pkgconfig. NEVER `git branch -D` an unmerged branch without
  asking (flagged this session). Gate: both `make smoke-*` PASS →
  SKIP_SMOKE=1 push + `gh pr merge --merge --delete-branch=true`. spec-lint
  clean before commit/PR. Files <1000 lines. No Co-Authored-By. Default PID1
  = systemd.

## DONE earlier this session
systemd PID1 bring-up (#1482-#1491: B22 arm dyn-loader entry, F357 flip),
xtask split (#1495), busybox→GNU /bin (#1493/#1496/#1497), run-dirs (#1499).
git log is the archaeology; don't restate.
