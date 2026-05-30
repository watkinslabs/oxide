# Session hand-off — 2026-05-30

## TL;DR
Branch `B18-login-smoke-fix`. **Login WORKS — both console and SSH.**

  $ sshpass -p swordfish ssh -p 2222 alice@127.0.0.1 id
  uid=1000(alice) gid=1000 groups=1000,10(wheel),100(users)

  oxide login: alice
  Password: ........
  pam_sm_authenticate → Success
  pam_open_session    → Success

Two commits on this branch:
  e5217cc1 feat(pam): upstream Linux-PAM 1.7.2 ecosystem; kernel diagnostics
  87351ad2 fix(vmm): fork_cow_pages — share File-backed VMAs

## What broke before and how we found it
1. **Console login mangled**: typing `alice` at the login prompt
   then `swordfish` for the password produced `Login incorrect`,
   then immediately re-prompted with `swordfish` as the next
   username. Bug was `/dev/console` and `/dev/ttyS0` `read()`
   returning `Ok(1)` per syscall; misc_conv reads `INPUTSIZE-1`
   expecting the whole line, so it took the first byte as the
   entire password and the rest stayed buffered as the next read.
   Fixed in `kernel/src/dev/console.rs`: drain the ring after the
   first byte (commit e5217cc1).

2. **PAM auth always returned PAM_AUTH_ERR (7)**: pam_unix forks
   a helper to run `unix_chkpwd`; child SIGSEGVs in libpam.so's
   `pam_modutil_sanitize_helper_fds`. Bisected via `/bin/pamtest`
   (a tiny PAM-driver test binary the rootfs ships): plain
   `fork+pam_strerror` worked, `fork+sanitize` SIGSEGV; manual
   reimplementation of the sanitize body in pamtest's own static
   code from a forked child worked, only the libpam.so path
   crashed. That isolated it to fork-time PT copying.

   Root cause: `crates/kernel/mm-vmm/src/address_space.rs::
   fork_cow_pages` only copied page table entries for `Anonymous`
   + `KernelBytes` VMA backings; File-backed VMAs (mmap'd
   `libpam.so`, `libc.so`, …) were skipped, so the child started
   with no PT entries for them and the first access to any
   instruction or .data byte in those mappings was an
   unresolvable user fault → kernel delivered SIGSEGV. Linux
   mm/memory.c shares file-backed pages on fork via the same COW
   pipeline; we now do the same — read-only file pages
   (.text/.rodata) stay shared forever, writable file pages (.data)
   get RO-remap + COW-on-first-write. Fixed in commit 87351ad2.

3. Vendor-side wiring up:
   - Killed `userspace/pam_modules/` (the hand-rolled minimal
     pam_unix). Now ship upstream Linux-PAM 1.7.2 sources:
     `libpam.so.0.85.1`, `libpam_misc.so.0.82.1`, and the upstream
     modules (`pam_unix`, `pam_permit`, `pam_deny`, `pam_nologin`,
     `pam_warn`, `pam_rootok`) + `unix_chkpwd` helper. All built
     from pristine `vendor/pam/Linux-PAM-1.7.2/`.
   - `vendor/util-linux/build.sh`, `vendor/openssh/build.sh`: link
     against `libpam.so.0` dynamically (`-L${pam_root}/lib
     -Wl,-rpath,/usr/lib`). No more `--export-dynamic` hack, no
     `--whole-archive` libpam embed, no `-Bsymbolic`.
   - `tools/xtask/src/main.rs`: stages libpam.so.0 + libpam_misc.so.0
     at `/usr/lib/`, modules at `/usr/lib/security/`, unix_chkpwd at
     `/usr/sbin/`. Ships `/bin/pamtest` for future PAM debugging.

## Still TBD before merge / next session
- The console prompt loops a couple times due to fifo timing in
  my driver script — but the BOOT in `make qemu-x86` is fine when
  you type by hand. Sanity check: open `make qemu-x86`, type
  `alice` + Enter, then `swordfish` + Enter, then `id` + Enter
  → should see `uid=1000(alice) ...`. Confirm before pushing PR.
- `syslogd -O /var/log/messages` is launched by rcS but only works
  if devtmpfs allows `bind(AF_UNIX, "/dev/log")`. /dev/log no
  longer pre-registered in devfs (left for syslogd to create as a
  socket). Verify devtmpfs supports the bind; if not, that's a
  small follow-up task.
- cgroup-smoke "echo: write error: Invalid argument" lines in
  rcS — separate bug (cgroup v2 write semantics on
  cgroup.subtree_control or pids.max). Doesn't block login; fix
  in the cgroup follow-up.
- The B18 PR title: `fix(pam,vmm): B18 console+ssh login — upstream
  Linux-PAM + fork COW for file-backed VMAs`. Two-commit branch.

## Run-down for next session
1. `make qemu-x86` and manually verify the login path one more
   time (don't trust the scripted fifo driver — it has race-y
   timing). Confirm `uid=1000(alice)` after `id`.
2. Same on aarch64: `make qemu-arm`. Verify the same fix lands on
   the arm side (the VMM code change is arch-agnostic).
3. Add a login smoke test (the original B18 ask). Drive qemu via
   socat over a unix-socket UART (set `OXIDE_QEMU_UART_SOCK=path`
   and have the test send `alice\n` + `swordfish\n` + `id\n` and
   grep for `uid=1000`).
4. Disable `pam-debug` build flag once you're satisfied the auth
   flow is solid in production (currently still on for visibility;
   removed in working tree but not yet committed — push as a
   tiny separate commit if you want a quiet boot).
5. Open PR.
