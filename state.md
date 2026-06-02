# Session hand-off

## Headline
**OXIDE distro: roadmap items 1-4 DONE** (systemd PID1→login both arches, GNU
userland, dynamic CPython 3.13.1 w/ ctypes+ssl+stdlib). systemd boot-log
cleanup sweep cleared the meaningful noise. main @ 3641e135.

## systemd-log sweep — RESULT
**CLEARED + MERGED (25 warning instances, both-arch, verified):**
- #1505 fix(fstat): real kernel bug — sys_fstat hardcoded st_mode=type|0o600
  + never wrote uid/gid → every fstat'd file 0600 → systemd saw all ~18 units
  "world-inaccessible". Now uses inode.perm()/uid()/gid(). (Found via debug
  printf in systemd stat_warn_permissions.)
- #1506: fsconfig(SET_FD)→EINVAL (3 mount-option-probe warnings:
  tmpfs-usrquota, cgroup memory_recursiveprot/hugetlb) + KDSIGACCEPT no-op
  (kbrequest).
- #1507: inotify add_watch devfs-only → full vfs::mount::lookup (timezone
  EBADF + acquire-watch + /run/systemd/ask-password — 3 warnings).
- (unit files staged 0644 via mode 0100644 keeping S_IFREG.)

**ATTEMPTED + REVERTED (2 — deeper items, not quick fixes):**
- netlink getsockopt(SO_PROTOCOL)/LIST_MEMBERSHIPS: cleared "Failed to open
  netlink" but made sd_netlink_open SUCCEED → systemd lo-config (RTM_NEWADDR/
  SETLINK) our rtnl can't service → BOOT DIED before login. Needs full rtnl
  write path. DEFERRED.
- pidfd ioctl→EOPNOTSUPP (for "is our child ... Not a tty"): didn't clear it
  (systemd pidfd_get_info / pidref_get_ppid still returns ENOTTY through a
  path the EOPNOTSUPP didn't catch, or /proc/PID/stat ppid fallback also
  fails). Reverted (no benefit).

## REMAINING systemd warnings — all NON-FATAL (boot reaches login)
Diminishing returns; each is cosmetic OR a substantial/risky feature:
1. "Can't determine if process N is our child ... Not a tty" — pidref/pidfd;
   needs PIDFD_GET_INFO impl OR /proc/PID/stat ppid (vpid-translated like
   #1482 did for other fields). Cosmetic.
2. "/run/machine-id mount ... No such file" — systemd bind-mounts machine-id
   via /proc/self/fd/4; needs /proc/self/fd magic-symlink mount target +
   /run tmpfiles. Complex, non-fatal.
3. "Failed to open netlink: I/O error" — needs FULL rtnl link-config (see
   reverted above). Substantial + boot-regression-prone.
4. "Failed to find module autofs4" — no module loader. Cosmetic.
5. "System is tainted: unmerged-usr:unmerged-bin:var-run-bad" — usr-merge
   (/bin→/usr/bin etc. symlinks) + /var/run→/run. Real distro-structure item,
   MEDIUM risk (every path resolves through the symlinks). rootfs.rs at 999
   lines → compact/split FIRST.

## NEXT — real high-value items (systemd cosmetics are diminishing)
- **python pip** — dynamic python is ready; self-contained, doesn't touch
  boot. bundle ensurepip wheels, `python3 -m ensurepip`, stage pip. (roadmap
  item 4 endgame). LOW risk.
- **usr-merge** — clears the tainted line; real FHS structure. MEDIUM risk;
  rootfs.rs compact first.
- **systemd-tmpfiles** — build the binary (ninja target in
  vendor/systemd/build.sh) + tmpfiles-setup unit; clears machine-id + a real
  sysinit chain. SUBSTANTIAL.
- **full rtnl + lo** — RTM_NEWADDR/RTM_NEWLINK so netlink-open + lo config
  works (clears netlink warning, real net correctness). SUBSTANTIAL.
- GRUB (roadmap item 3) still DEFERRED — Limine-native, Multiboot2/EFI rewrite.

## KEY techniques + harness (cost hours; internalize)
- Debug-print IN the failing systemd C component (vendor/systemd/.../src;
  ninja -C build-x86_64 <targets>; cp to install-x86_64/lib + /lib/systemd/;
  rebuild rootfs; boot; read) is how you get ground truth — kernel klog is
  &'static-str-only so can't printf values. ALWAYS revert debug + ninja-clean
  + `git checkout -- vendor/systemd/install-x86_64` after.
- build/boot run_in_background ALONE; NEVER pkill/kill/sleep/grep/for-loop
  PREFIX in the same compound, NEVER trailing `&` (set -e + blocked
  foreground-sleep + rc1 aborts → empty capture = FALSE failure); pkill/kill
  in OWN call ||true. Foreground sleep>~5s is BLOCKED.
- Clear :2222 squat before each boot: `ss -ltnp|grep 2222` → kill -9 pid.
- OXIDE_SMP=2 reaches login (SMP=1 wedges at cat-smoke "A"). make qemu-*
  REBUILDS rootfs each run + sits at login forever (poll the >file then kill;
  never exits on its own). TCG ~8-12min to systemd. grep -a + sed strip-ANSI.
- console login-INPUT doesn't reach the getty (kernel console-RX gap) →
  interactive in-kernel testing blocked; verify via boot console output.
- debugfs `sif mode` needs FULL mode incl S_IFREG (0100644 not 0644).
- rootfs-*.img NEVER git-add (>100MB). Never git-add vendor source trees or
  install-*/lib/pkgconfig. NEVER `git branch -D` unmerged (rename with -m).
  spec-lint clean before commit; files <1000 lines; SKIP_SMOKE=1 push +
  gh pr merge --merge --delete-branch=true. default PID1 = systemd.
