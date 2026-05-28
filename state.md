# state — hand-off

Branch: `F210-replace-dropbear-with-openssh` (PR #1293, open). On
top of main (post-history-rewrite). `make qemu-x86` reaches `oxide
login:` with openssh sshd daemonized; `make qemu-arm` reaches
`Server listening` but not `oxide login:` (separate ARM scheduling
follow-up).

## Shipped this branch (3 commits ahead of main)

- **F210 (3f5824f5)** — vendor openssh-portable 9.9p2; replaces
  dropbear. `tools/fetch-openssh.sh` + `vendor/openssh/build.sh`
  static-musl build of `sshd` + `sshd-session` + `ssh-keygen` +
  `ssh` (`--without-openssl` → chacha20-poly1305 + curve25519 +
  ed25519; `--with-sandbox=no` → no seccomp filter).
  `xtask rootfs` installs to `/usr/sbin/sshd`,
  `/usr/libexec/sshd-session`, `/usr/bin/ssh-keygen`. sshd_config:
  `AddressFamily inet` (our IPv4 wildcard listener-lookup fallback
  doesn't match sshd's default IPv6 dual-stack bind). Switch motivated
  by dropbear's `check_close → close-PTY-master on CHANNEL_EOF`
  defect — reproduces on real-Linux dropbear too, so it's upstream
  behavior, not our kernel.

- **F211 (470a70ee)** — CFS sleeper credit on wake-from-blocking-wait
  + Linux-PAM 1.7.2 vendored static build.
  - `Task::set_vruntime_to_floor(floor)` *sets* vruntime to floor
    unconditionally (vs. `lift_vruntime` which only raises). Used
    from `wake_wait4_parent`, `WaitList::enqueue_runnable`,
    `wake_if_sleeping`. Mirrors Linux `place_entity()`
    GENTLE_FAIR_SLEEPERS. Fixes the daemonize-vs-wait4 starvation
    (shell with high vruntime kept losing the CFS pick to its
    just-spawned daemonize child whose vruntime started at 0).
  - `tools/fetch-pam.sh` + `vendor/pam/build.sh` → meson static
    build of `libpam.a` + `libpam_misc.a` for both arches. PAM
    modules build as separate `.o` files in
    `_build-$arch/modules/<name>/`; NOT embedded in libpam.a
    (Linux-PAM 1.7.2 dropped autotools' `--enable-static-modules`).

- **F211 rcS (0394cd0e)** — per-arch sshd launch. ARM uses
  `sshd -D -e 2>&1 &` (bg-shell wrapper); x86 uses default
  daemonize. Selection via `/etc/oxide-arch-is-aarch64` marker
  written by `xtask rootfs --arch aarch64`.

## Open work — pick where to resume

### A. openssh KEX_ECDH_REPLY stall

sshd accepts the SSH connection, exchanges banner + KEXINIT, gets
client's KEX_ECDH_INIT, then never replies with KEX_ECDH_REPLY. ssh
client times out at 30s. With `FEATURES=debug-ssh` enabled (per-
syscall klog overhead changes timing) the KEX completes far enough
to see ECDH_REPLY go out. Suggests a busy-poll race in our
`pselect6`/`ppoll` (`crates/kernel/sched/src/live/schedule.rs::tick_yield`
+ `kernel/src/syscalls/select.rs` + `kernel/src/syscalls/poll.rs`)
— the tick-yield + hlt-on-IRQ loop doesn't wait long enough for
sshd-session's compute, OR there's a missed wakeup against the
TCP socket's recv_buf.

A diagnosis agent ran in background; its report is in
`/tmp/claude-1000/-home-nd-oxide2/.../tasks/a9f885757af1d2338.output`.

### B. ARM init/getty respawn after daemonize

`make qemu-arm` doesn't reach `oxide login:` after sshd
daemonization even though `Server listening` does appear. Workaround
is the `-D + bg-shell` path in rcS. Probably scheduler starvation
by sshd's tight `rt_sigprocmask + ppoll` loop; F211 likely
insufficient on ARM TCG.

### C. PAM not yet wired into openssh

`vendor/pam/install-{x86_64,aarch64}/libpam.a` is built but
openssh `build.sh` still passes `--without-pam`. Wiring needs
the modules (pam_unix + pam_deny + pam_permit + pam_nologin)
linked statically — Linux-PAM 1.7.2's meson build didn't surface
those as artifacts. Requires either downgrading to PAM 1.5.x
(autotools, has `--enable-static-modules`) or hand-linking the
module `.o` files from `_build-$arch/modules/<name>/`.

## Repro patterns

    # x86 KVM + openssh, expected to reach login + sshd listen
    OXIDE_QEMU_KVM=1 OXIDE_QEMU_HEADLESS=1 make qemu-x86

    # SSH connection attempt (stalls at KEX_ECDH_REPLY today)
    timeout 30 sshpass -p swordfish \
      ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -p 2222 alice@127.0.0.1 'echo HI'

    # Same with kernel-side syscall-trace overhead — KEX progresses further
    FEATURES=debug-ssh OXIDE_QEMU_KVM=1 OXIDE_QEMU_HEADLESS=1 make qemu-x86

## See also

- PR #1290 (merged) — C13 KVM-default fix: STAR RPL=3 + LAPIC timer disarm.
- PAM agent report: `/tmp/claude-1000/.../tasks/aa06e90592a74036a.output`.
- Daemonize-audit report: `/tmp/claude-1000/.../tasks/a9d3bf255fd80df91.output`.
