# Session hand-off — 2026-05-30

## TL;DR
Branch `B18-login-smoke-fix`. Major refactor: deleted hand-rolled
`userspace/pam_modules/`, now build the **real upstream Linux-PAM
1.7.2** modules (`pam_unix.so`, `pam_permit.so`, etc.) as proper
shared libraries linked against a shared `libpam.so.0`. login and
sshd both DT_NEEDED libpam.so.0 now (no more `--export-dynamic`
hacks, no `--whole-archive` libpam embedded into the modules, no
`-Bsymbolic`).

Login still does NOT work, but for a NEW reason that's a real
kernel bug. Diagnosed below.

## Real root cause (kernel bug, B18 follow-up)
`/bin/pamtest alice swordfish` (a tiny test driver we ship in the
rootfs at `/bin/pamtest`) shows:

  pam_start                                                rc=0  ✓
  conv called with "Password: "                                  ✓
  pam_authenticate                                         rc=7  ✗
  pam_acct_mgmt                                            rc=7

PAM_DEBUG-enabled trace shows the failure point is inside
`_unix_run_helper_binary`. The helper is **invoked** (we proved
this by replacing /usr/sbin/unix_chkpwd with an ELF stub that
writes a beacon file then `_exit(42)` — the beacon gets written).
But the parent's `waitpid(child)` ends with `!WIFEXITED` —
pam_unix maps that to PAM_AUTH_ERR (7).

Why does child die abnormally? Bisected to libpam.so's
`pam_modutil_sanitize_helper_fds`:

  fork+_exit                              → exit 13   ✓ fork ok
  fork+open(badpath)+errno                → exit ENOENT ✓ syscalls ok
  fork+pam_strerror (libpam.so call)      → exit 14   ✓ libpam.so ok
  fork+manual close-loop 4095..3          → exit 15   ✓
  fork+getrlimit+close-loop               → exit 17   ✓
  fork+pam_modutil_sanitize_helper_fds    → SIGSEGV   ✗
  fork+sanitize after parent-resolves it  → SIGSEGV   ✗
  pam_modutil_sanitize_helper_fds WITHOUT fork (--san-only) → ✓ rc=0

So the sanitize function itself works (when called from the main
process). It only SIGSEGVs when called from a forked child. My
manual replication of the same function logic in pamtest's own
code (pipe + dup2 + getrlimit + close loop) works fine from a
forked child. Only the call **through libpam.so's compiled copy**
from a forked child SEGVs.

That points at a kernel-side fork/COW interaction with shared
libraries that's NOT exercised by simple `fork+libpam call` but IS
exercised by `fork+specific-libpam-function`. Possibly something
about the page that holds `pam_modutil_sanitize_helper_fds` text
or the surrounding .rodata literal pool that doesn't get the right
COW treatment in fork. Worth checking `parent_mm.fork_cow_pages`
in `kernel/src/syscalls/clone.rs` for mappings flagged differently.

## What landed (committable)
- `userspace/pam_modules/` **DELETED** — no more hand-rolled PAM.
- `vendor/pam/build.sh` rewritten: builds **shared** libpam.so.0,
  libpam_misc.so.0, and the upstream modules (pam_unix, pam_permit,
  pam_deny, pam_nologin, pam_warn, pam_rootok) + unix_chkpwd helper.
  All from pristine `vendor/pam/Linux-PAM-1.7.2/`. Pass
  `-Dpam-debug=true` so PAM_DEBUG D() macros emit on stderr for
  diagnostics. NO vendor source patching.
- `vendor/util-linux/build.sh`: links login dynamically against
  libpam.so.0 (`-L${pam_root} -L${pam_root}/lib -Wl,-rpath,/usr/lib`).
- `vendor/openssh/build.sh`: same shared-libpam linkage for sshd.
- `tools/xtask/src/main.rs`:
  - stages libpam.so.0.85.1 + libpam_misc.so.0.82.1 at /usr/lib/ +
    `libpam.so.0` / `libpam.so` hardlinks (debugfs `ln`).
  - stages the upstream modules at /usr/lib/security/.
  - stages unix_chkpwd at /usr/sbin/.
  - ships /bin/sptest (proves getspnam() works) and /bin/pamtest
    (the diagnostic above) for next-session debugging.
  - rcS now starts `syslogd -O /var/log/messages` so libpam's
    pam_syslog calls land in a readable file (once /dev/log is
    available as AF_UNIX socket — currently not registered, see
    devfs change).
- `kernel/src/devfs.rs`: /dev/log no longer pre-registered as a
  NullInode; userspace syslogd needs to bind it as a unix socket.
  (devtmpfs needs to permit that — separate task.)
- `kernel/src/dev/console.rs`: read() now drains the full ring after
  the first byte instead of returning Ok(1) per syscall. Fixes the
  "password came through as next username" symptom on console login
  (misc_conv reads with `INPUTSIZE-1` and treated the single byte as
  the entire password).

## What's still broken
- Console + SSH login both fail with the kernel bug above.
- /dev/log unix-socket binding needs devtmpfs support so syslogd
  can publish PAM's syslog calls.

## Next session — first thing to do
1. `make qemu-x86`, type alice + swordfish at oxide login: prompt,
   confirm it still says "Login incorrect".
2. Read `/etc/init.d/oxide-smokes`'s pamtest output to confirm the
   `pam_authenticate rc=7` symptom is still present.
3. Reproduce the fork+sanitize SIGSEGV via `/bin/pamtest` and dig
   into `kernel/src/syscalls/clone.rs:fork_cow_pages` (likely
   missing-flag on the libpam.so .text or .rodata VMA). Compare
   how mmap'd shared-library pages are flagged at clone time vs
   how anonymous COW pages from heap/stack are flagged.

## What MUST go into TASKS.md when next session opens
- B18 console login (PAM): blocked on kernel fork+libpam.so bug.
- T14 pam_unix: superseded — we now ship UPSTREAM pam_unix.so.
- New: K-ish task "fork+shared-library page-fault interaction"
  — kernel bug, see state.md for the bisection.

## Mechanics / gotchas (root-caused this session, do not relearn)
- B18 fixed: `/dev/console` and `/dev/ttyS0` `read()` was returning
  Ok(1) per syscall. misc_conv reads with INPUTSIZE-1 buffer; with
  Ok(1) it took the first byte as the whole password and left the
  rest of the typed line as stale input for the next read (which
  agetty then saw as "next username"). Fix: kernel drains the ring
  into the user buffer after the first byte.
- vendor/util-linux's `login` needs the PAM headers at BOTH
  `install-<arch>/security/*.h` and `install-<arch>/include-security/*.h`
  paths — its configure uses `#include <security/pam_appl.h>`.
- pam-debug option: meson `-Dpam-debug=true` enables the upstream
  `D()` macros in libpam. They write to stderr. Combined with login
  attaching stderr to the user tty, you can see every internal pam
  decision on serial. KEEP this on while B18 is unsolved.
- `/usr/sbin/unix_chkpwd` is dynamic-linked against ld-musl only
  (no libpam). It reads /etc/shadow directly, crypts, compares,
  exits 0 on success / nonzero on failure. Standalone (driven by
  the right pipe protocol — len-prefix-NUL-terminated password)
  it works. Inside pam_unix's helper fork it never gets a chance
  because the child SEGVs first in sanitize.
- syslogd needs /dev/log as a unix socket. Our devfs no longer
  shadows the path with a NullInode, but devtmpfs needs to permit
  `bind(AF_UNIX, /dev/log)` to work for syslogd to actually start.
- Don't commit `vendor/pam/install-*` library directories — they
  are build artifacts (regenerated by vendor/pam/build.sh).
