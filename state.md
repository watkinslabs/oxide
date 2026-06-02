# Session hand-off

## Headline
**OXIDE distro: roadmap items 1-4 DONE** (systemd PID1→login both arches, GNU
userland, dynamic CPython 3.13.1 w/ ctypes+ssl+stdlib). Now mid **systemd
boot-log cleanup sweep**. main @ c283eac2. ~29 PRs this session.

## systemd-log cleanup — progress
**CLEARED + MERGED (22 warning instances, verified x86+arm):**
- #1505 fix(fstat): `sys_fstat` hardcoded `st_mode=type|0o600` + never wrote
  uid/gid → EVERY fstat'd file reported 0600. systemd open+fstat's each unit
  → all ~18 "Configuration file ... world-inaccessible". Now uses
  inode.perm()/uid()/gid() like statx. **Real kernel bug** (all fstat callers
  got wrong perms/owner). Found via a debug printf in systemd
  stat_warn_permissions showing kernel returned 0600 for a 0644-on-disk file.
- #1506: (a) `sys_fsconfig` returns EINVAL for FSCONFIG_SET_FD (was 0) →
  systemd mount_option_supported() probe no longer -EAGAIN → cleared the
  tmpfs-usrquota + 2 cgroupfs (memory_recursiveprot/hugetlb) warnings.
  (b) `handle_vt_ioctl` accepts KDSIGACCEPT no-op → cleared "kbrequest ... Not
  a tty".
- Also staged systemd unit .target/.service as 0644 (rootfs.rs, mode 0100644
  KEEPING S_IFREG — bare 0644 zeroes the file type → ext4 EIO → PID1 freeze;
  hit+reverted that once).

**ABANDONED (regressed boot — reverted, NOT merged):**
- netlink getsockopt(SO_PROTOCOL)+NETLINK_LIST_MEMBERSHIPS fix: it DID clear
  "Failed to open netlink" (#6), but making sd_netlink_open() SUCCEED led
  systemd to attempt loopback (lo) config (RTM_NEWADDR/RTM_SETLINK) our rtnl
  can't service → **boot stopped at the machine-id line, never reached login**
  (2 consecutive boots; partial-fix boot WITH the netlink warning reached
  login fine). LESSON: enabling netlink-open without full rtnl link-config is
  worse than the non-fatal "ignoring" warning. To do properly: implement rtnl
  RTM_NEWADDR/RTM_NEWLINK (bring lo up + add 127.0.0.1/::1) so systemd's
  synchronous sd_netlink_call gets real acks. Substantial; defer.

## REMAINING systemd warnings (all NON-FATAL — boot reaches login)
Root causes diagnosed; each needs real work + a ~10min TCG boot to verify:
1. **/run cluster** — "/run/systemd/ask-password No such file", "/run/machine-id
   mount ... No such file", "acquire watch fd No such file". systemd
   tmpfs-mounts /run (standard) → baked dirs vanish → no systemd-tmpfiles to
   recreate. FIX: build systemd-tmpfiles binary (ninja target in
   vendor/systemd/build.sh) + a systemd-tmpfiles-setup.service early in
   sysinit + tmpfiles.d/systemd.conf. Clears 2-3 at once. SUBSTANTIAL.
2. **timezone "Bad file descriptor"** — sd_event_add_inotify on /etc dir
   (IN_CREATE|IN_MOVED_TO|IN_ONLYDIR) → EBADF. kernel inotify/event-loop gap.
3. **"is our child ... Not a tty"** — pidref_is_my_child → pidref_get_ppid
   (reads ppid via /proc or pidfd) → ENOTTY. non-fatal.
4. **netlink** — see ABANDONED above (needs full rtnl).
5. **autofs4 module** — systemd modprobe(autofs4); no module loader. cosmetic.
6. time-advanced-to-epoch — informational (no RTC). leave.

## KEY diagnostic technique (worked twice)
Add a debug printf IN the failing systemd component (it's vendored C source at
vendor/systemd/systemd-259/src; ninja -C build-x86_64 <targets>, cp to
install-x86_64/lib + /lib/systemd/, rebuild rootfs, boot, read). The kernel
klog only takes &'static str so can't printf values — debug in systemd/C
instead. ALWAYS revert the debug + ninja-rebuild clean + `git checkout --
vendor/systemd/install-x86_64` before finalizing (the install binaries are
tracked; a rebuild changes bytes spuriously).

## CRITICAL harness rules (cost hours this session)
- build/boot run_in_background ALONE. NEVER a pkill/kill/sleep/grep/for-loop
  PREFIX in the same compound as the real cmd, and NEVER a trailing `&` — dev
  shell set -e + blocked foreground-sleep + pkill/kill-rc1-when-nothing aborts
  the compound → missing/empty capture = FALSE failure. pkill/kill in their
  OWN call guarded ||true. Foreground sleep>~a few s is BLOCKED — use
  run_in_background sleep or just poll.
- `make qemu-x86/qemu-arm` REBUILDS the rootfs every run (user confirmed) +
  sits at login forever (poll the >file then kill; it never exits on its own).
- Stale qemu squats :2222 → "Could not set up host forwarding". Kill the
  holder by pid: `ss -ltnp|grep 2222` → kill -9. Recurs constantly with many
  concurrent boots — kill before each boot.
- OXIDE_SMP=2 reaches login; SMP=1 wedges at the cat-smoke "A" (stale notes had
  this BACKWARDS). TCG boot ~8-12min to systemd. Host gets loaded with
  concurrent boots → spurious timeouts; run ONE boot at a time.
- debugfs `sif mode` needs FULL mode incl S_IFREG (0100644 not 0644).
- grep -a + `sed 's/\x1b\[[0-9;]*[a-zA-Z]//g'` to strip ANSI from boot logs.
- console login-INPUT doesn't reach the getty (kernel console-RX gap, separate
  from SMP) — interactive in-kernel verification is blocked; verify via boot
  console output (systemd logs) not interactive typing. qemu MCP is TCG+flaky.
- rootfs-*.img NEVER git-add (>100MB GitHub reject). Never git-add vendor
  source trees (Python-3.13.1/, libffi-3.4.6/) or install-*/lib/pkgconfig.
  NEVER `git branch -D` an unmerged branch w/o asking (rename with -m).
- Gate: both `make smoke-*` PASS (or manual login-confirm) → SKIP_SMOKE=1 push
  + gh pr merge --merge --delete-branch=true. spec-lint clean before commit.

## NEXT
Highest-leverage remaining: systemd-tmpfiles (clears the /run cluster, 2-3
warnings, "build out what's missing"). Then inotify EBADF, pidref, autofs.
netlink needs full rtnl (link-config) — biggest, and risks boot stability so
needs the rtnl write path done first. Python pip also unblocked (dynamic
python). GRUB (roadmap item 3) still DEFERRED (Limine-native, Multiboot2/EFI
rewrite). dynamic-python-for-ctypes already DONE.
