# state — hand-off

Branch: `F237-sigchld-siginfo` (open, no commits yet — placeholder for
the next iteration's SIGCHLD siginfo work). Main is 7 PRs ahead of
the prior state.md baseline; SSH is end-to-end working on x86 with
real PAM dlopen + dynamic distro userspace.

## Shipped since last state.md (7 merged PRs)

- **#1312 F229** — openssh-portable 9.9p2 rebuilt with libpam.a +
  libz.a statically linked; sshd_config keeps UsePAM=no at this stage
  because dlopen needs a dynamic loader; /etc/pam.d/sshd written.
- **#1313 F230** — vendor real musl `ld-musl-<arch>.so.1` (from
  Fedora host on x86 + the cross toolchain on ARM); kernel
  `place_image` skips pre-relocation when PT_INTERP is present
  (was double-relocating dynamic execs); `glue_munmap` targets
  `cur.mm` not the global boot AS so MAP_FIXED overlap-clear hits
  the right address space; RLIMIT_STACK-driven `mmap_base` layout
  (stack reservation top, mmap arena 128 MiB below, multi-GB gap
  matching Linux `arch_pick_mmap_base`).
- **#1314 F231** — vendor/openssh rebuilt DYNAMIC (`-static` dropped,
  `--export-dynamic` added); userspace/pam_modules/{pam_permit,pam_deny}.c
  built `-shared -fPIC -nostdlib`; staged at /usr/lib/security/ (matches
  libpam's baked DEFAULT_MODULE_PATH); UsePAM=yes; sshd's libpam
  dlopens pam_permit.so end-to-end. `smoke-ssh-x86` PASS through PAM
  on every connection.
- **#1315 F232** — `sys_waitid` decodes real (si_code, si_status) from
  the wait4 wstat; was previously hardcoded si_status=0.
  `userspace/exit_test/exit_test.c` smoke confirms wstat encoding
  correct: A=0x2a00 (fork+ret 42), B=0x0000 (true), C=0x0100 (false).
- **#1316 F233** — GNU bash 5.2.37 dynamic (was static-pie). 600 KB
  x86 / 820 KB ARM stripped.
- **#1317 F234** — sed, grep, coreutils, tar, diffutils, patch,
  gawk, findutils, make, gzip all dynamic. /usr/bin shrinks ~70%.
  xz kept static (libtool/liblzma needs separate plumbing).
- **#1319 F236** — ARM `/lib/libc.so` second-name for ld-musl
  (ARM cross-musl-gcc emits DT_NEEDED="libc.so" not the loader name).

## End-to-end proof, both arches

- `make smoke-ssh-x86 SSH_SMOKE_CONNECTIONS=1` PASS — 1 ssh + 9
  tail-tools (find, gawk, diff, patch, bzip2, xz, ...) + 1 pty,
  ALL through dynamic distro tools + real PAM dlopen.
- ARM boot-smoke PASS in 22s.
- ARM ssh: PAM dlopen confirmed working (`Accepted
  keyboard-interactive/pam` for 8+ sessions); SSH smoke times out
  somewhere later — suspected the long-standing CLOSE_WAIT leak
  (task #11), orthogonal to PAM.

## Open defects (queue for next session)

1. **Task #11 — ARM TCP CLOSE_WAIT leak.** Accept'd sockets never
   close on ARM cumulative SSH; `InetSocket::Drop` never fires.
   Caps `SSH_SMOKE_CONNECTIONS=4` on ARM TCG.
2. **Task #12 — busybox-ash `$?=255` on clean exit.** Kernel wait4
   wstat encoding is correct (proved by exit_test); bash decodes
   correctly. busybox-ash gets garbage — likely needs SIGCHLD
   siginfo_t (we currently deliver SIGCHLD as a single pending
   bit, no per-event si_status). F237 branch placeholder.
3. **Task #14 — real `pam_unix.so`.** Replace pam_permit.so with
   real `/etc/shadow` + crypt() auth. Requires (a) libpam.so
   shared (1.7.2 meson rebuild), (b) libcrypt (vendor or
   in-tree), (c) `pam_unix.so` shared module with /etc/shadow read.
4. **Task #15 — ARM dynamic bash as `/bin/sh` wedges init.** Bash at
   /bin/bash works on ARM; using it as `/bin/sh` causes boot wedge
   silently. Root cause unknown; deferred. busybox-ash stays
   `/bin/sh` on ARM.

## Repro patterns

    # End-to-end SSH smoke on x86
    pkill -f qemu-system; sleep 2
    bash -c "trap '' SIGURG; make smoke-ssh-x86 SSH_SMOKE_CONNECTIONS=1"

    # Both arches boot smoke
    bash tools/boot-smoke.sh x86 90
    bash tools/boot-smoke.sh arm 600

    # Direct kernel-wait4 smoke check
    /bin/exit_test                  # in-guest: prints A=00002a00 etc.

## Pick up

Resume from F237-sigchld-siginfo. First task: build SIGCHLD siginfo
queue (per-task) so SA_SIGINFO handlers see proper si_status / si_pid.
That's the root-cause fix for task #12.
