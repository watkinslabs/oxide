# Session hand-off — 2026-05-30

## TL;DR
Branch `B18-login-smoke-fix`, six commits. Console login works
end-to-end on both arches: typing `alice`/`swordfish` at
`oxide login:` reaches `oxide:~$` and `id` reports
`uid=1000(alice) gid=1000`. New `make smoke-login` regression
test guards it. PR not yet opened — open it next.

## Commits
- e5217cc1 — upstream Linux-PAM 1.7.2 ecosystem (deleted the
  hand-rolled `userspace/pam_modules/`); `/dev/console::read`
  drains ring instead of returning Ok(1).
- 87351ad2 — `fork_cow_pages` COW-shares File-backed VMAs
  (child SIGSEGV'd on first libpam.so access pre-fix).
- ad1dc5b4 — drop `-Dpam-debug=true` build flag.
- c9932bb2 — TIOCSCTTY VT branch seeds `foreground_pgid`;
  ships `login_sim` reproducer.
- f3692654 — **root cause**: SysV stack envp strings now sit
  ABOVE argv strings (matches Linux). util-linux login's
  `process_title_init` computed `argv_lth = envp[last] +
  strlen - argv[0]`; with our reversed layout that underflowed
  to ~2^63, the subsequent `memset` SIGSEGV'd login between
  `init_environ` and `fork_session`.
- 42e40465 — `tools/boot-smoke-login.sh` + Makefile wiring;
  split `address_space.rs`→`mremap.rs` and `xtask/main.rs`→
  `cmds.rs` to clear the 1000-line cap.

## How the bug was found
Added file-logged checkpoints (`dlog` → /tmp/login.dbg with
O_APPEND so writes survive parent close(0/1/2)) to
vendor/util-linux/login.c, booted, ssh'd in to read the log.
Last visible step before exit was `before process_title_update`,
missing `before log_syslog`. Pointed at the `memset(argv0[0],
0, argv_lth)` in `process_title_update` → traced argv_lth back
to `process_title_init` → cross-checked our stack builder vs
Linux `fs/binfmt_elf.c::copy_strings`. Diagnostic source was
then deleted from the gitignored vendor tree and a pristine
re-extract verified the kernel-only fix.

## Verified
- `OXIDE_QEMU_KVM=1 ./tools/boot-smoke-login.sh x86 120` → PASS in 25s
- `./tools/boot-smoke-login.sh arm 600` → PASS in 31s
- `cargo run -p xtask --release -- spec-lint` → clean
- Both arches build clean

## Open / cosmetic
- `sh: child setpgid (62 to 62): No such process` cosmetic
  warning from busybox after login — doesn't break the shell.
  Worth a follow-up; not B18-blocking.
- `vhangup` still broadcasts SIGHUP to whole session, not just
  processes whose ctty matches. Tracked separately.
- /dev/log AF_UNIX bind for syslogd capture of pam_syslog
  (currently those messages drop on the floor). Tracked.
- B18 originally asked for the smoke to also drive sshd login
  in the same harness; sshd login works (verified manually via
  sshpass) but isn't exercised by `boot-smoke-login.sh`. Add a
  second smoke or extend the existing one in a follow-up.

## Run-down for next session
1. `gh pr create` for B18-login-smoke-fix → main. Title:
   "feat(login): B18 console login end-to-end + smoke gate".
   Body should highlight the stack-ordering root cause and
   the new `make smoke-login` target.
2. After merge: pick the next phase per `docs/00§3`. The
   distro track (phases 13–17) is what console login was
   unblocking; phase 13 (dynamic linker) and 14 (libc/NSS/PAM)
   are now largely done in spirit — audit and freeze the
   corresponding specs.
3. Optional follow-up: the cosmetic setpgid race in busybox
   when launched as login shell, the vhangup ctty-scoping fix,
   and AF_UNIX `/dev/log` for syslogd capture.
