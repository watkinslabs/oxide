# Session hand-off

## Headline
**systemd 259 PID1 boots deep on oxide** — through console setup, chroot gate,
DSR terminal probe, mount_setup, and **manager_new** (executor pinned), into
**unit-file loading**, where it now wedges because **no systemd units are staged
in the rootfs**. 4 F350 fixes merged this session. main clean @ #1476.

## F350 fixes merged this session
| PR | Gap | systemd reaches |
|----|-----|-----------------|
| #1471 | /dev/console honors O_NONBLOCK | past first console read |
| #1473 | name_to_handle_at + /proc/<pid> magic symlinks | past running_in_chroot() |
| #1475 | /dev/console poll() real readiness | past DSR terminal-size probe |
| #1476 | build + stage systemd-executor binary | past manager_new() |
(plus #1472 xtask stats recovery, #1474/#1477-ish state docs)

## NEXT — F350 #5: stage systemd's unit tree (a MILESTONE, not a one-file fix)
systemd PID1 reaches "Looking for unit files in (/etc/systemd/system,
/usr/lib/systemd/system, ...)" then "Unit type .automount is not supported" and
WEDGES — those dirs are empty/missing, so there's no default.target to load.
Confirmed reproducible (sd11, sd12 both stop there).

**Plan (Linux way — use systemd's OWN units, not hand-written hacks):**
- `ninja install` / `meson install` DON'T work: they rebuild all tests (one fails
  to compile) or try to install unbuilt binaries (udevadm). So stage manually.
- Source units live in `vendor/systemd/systemd-259/units/` (static `.target` text
  + `.service.in` needing simple @path@ substitution). The `.wants/` symlink graph
  is defined in `vendor/systemd/systemd-259/units/meson.build` ('symlinks' keys).
- Stage the MINIMAL real chain to reach a console login:
  default.target→multi-user.target; multi-user wants basic.target+getty.target;
  basic wants sysinit.target (+sockets/paths/slices/timers); a console getty
  (console-getty.service or serial-getty@ttyS0.service running agetty) OR a
  debug-shell.service running /bin/sh on /dev/console for first light.
- Add a staging helper (build.sh or xtask) that copies the units + creates the
  .wants symlinks + default.target symlink, into /usr/lib/systemd/system +
  /etc/systemd/system. mkdir those dirs in cmd_rootfs.
- agetty/login: util-linux L2 has agetty? else busybox getty. Check before wiring.
- EXPECT a cascade: each unit systemd STARTS exercises more kernel/syscall paths
  (sockets, cgroup writes, fork+exec of services, dbus). Iterate one gap per PR.

## Recon recipe (proven this session)
kernel/src/smoke/elf.rs: PID1 lookup→/lib/systemd/systemd (line ~639) + argv
(~658) + envp SYSTEMD_LOG_LEVEL=debug (build_user_stack ~line 795). Boot bare
`OXIDE_QEMU_HEADLESS=1 make SMP=2 qemu-x86 >/tmp/sd.txt 2>&1`. REVERT before commit.
**DO NOT klog-trace inside sys_openat — it wedges the boot under SMP (proven).**
Trace syscall NRs at oxide_syscall_dispatch (mod.rs) gated `c.vtid==1` instead.

## First command (next session)
Re-recon, boot, confirm the wedge is "no default.target"; then write the unit
staging helper + minimal real unit set + a console getty/debug-shell; boot;
iterate each surfaced gap.

## CRITICAL harness rules
- dev shell is `set -e`: guard EVERY pgrep/grep/ss/pkill/[ test ] with `|| true`
  or the whole cmd aborts with NO output / no file created. Lost time to this.
- Boots: bare `make` in run_in_background (no prefix pkill in same compound);
  poll output-file in a SEPARATE guarded bg cmd; `pkill -9 -f qemu-system-x86_64`
  only at END, NEVER `pkill -f qemu` (self-kill). Clear ports 2222/1234 first.
  Rootfs rebuild runs ~90s BEFORE qemu launches — wait for systemd log lines, not
  file existence; don't kill at the wrong moment.
- Both-arch gate: `git push --dry-run origin <branch>` runs the pre-push hook
  (= both-arch boot-smoke) WITHOUT pushing; on "PASS on both arches" → real-push
  `SKIP_SMOKE=1` + `gh pr merge --merge --delete-branch=true` (that ONE cmd deletes
  local+remote — do NOT add a separate `git branch -D`, it trips the perm prompt).
- spec-lint clean before commit. main.rs + procfs/mod.rs at the 1000-line cap —
  count lines after edits, trim comments to fit. Branch per change; explicit
  git add. NEVER add vendor/*/install-*/lib/pkgconfig. A tree-wide cargo fmt is
  NOT wanted (manual alignment per docs/08/09) — if 100s of files show fmt churn,
  stash+drop, don't commit.
- Default PID1 is still busybox → busybox login smoke stays green; flip default
  PID1 to systemd only once systemd reaches a target/getty.
