# state.md — session handoff

## Headline
Two more mount-namespace bugs FOUND + FIXED this session (measured, committed,
pushed on branch B318). Both are the SAME class: the mount engine re-derived a
mount's parent/dest from a bare dentry via `parent_by_dentry`, which is
AMBIGUOUS under bind-sharing (bind mounts share the underlying dentries), so
mounts created/moved onto a bind of `/` were mis-placed. Fixed by threading the
walked `path->mnt` (which the syscall layer already knows) as an explicit hint.
Greeter STILL not rendering — root cause is NOT mount (measured: mount(2) has ~0
failures now). The live blocker is `CAN_GRAPHICAL=0` because udevd never
processes card0's uevent, plus gdm exits code=1 downstream of that.

## Fixes landed this session (branch B318, pushed)
- b71fb455 fix(devfs): register /dev/hugepages mount-point dir (systemd
  per-service sandbox binds it; was ENOENT).
- 29194e13 fix(vfs): thread walked DEST mnt_id through MS_MOVE
  (`move_mount_by_id_to`) — bind-shared dentry defeated parent_by_dentry, so
  MS_MOVE onto /run/systemd/mount-rootfs/<sub> was falsely rejected "dest within
  source subtree". Fixed 12/13 namespace MS_MOVEs.
- e66f8386 fix(vfs): thread walked PARENT mnt_id through mount graft
  (`register_at`/`register_bind_at`/`attach_sb_with_flags_at` + parent_hint in
  attach/graft_realized). systemd creates the apivfs at /run/systemd/namespace-X
  AFTER rbinding / onto /run/systemd/mount-rootfs, so the /run root dentry is
  bind-shared and the new mount was BORN parented under mount-rootfs/run
  (rendered /run/systemd/mount-rootfs/... — unreachable via real /run). Now
  renders correctly. 41 hosted vfs mount tests green.
- crates/kernel/vfs/tests/sandbox_nested_primary.rs added (passes; note: the
  string-keyed hosted fixture can't reproduce true bind-dentry ambiguity, so it's
  a non-regression guard, not the repro — the repro is the boot trace).

## KEY measured finding: code=265 storm is NOT the greeter blocker
- mount(2) failures ≈ 0 after the two mount fixes (was assumed to be the cause —
  it was NOT; measure-don't-guess paid off).
- ~25 `code=265` exits are `sd-executor` (`/proc/self/fd/9`) probe-forks that
  exit after `waitid=ECHILD` + `pause=EINTR`; 265 > systemd's EXIT_ range
  (max ~246) so it's not EXIT_NAMESPACE. Services like upower still reach
  "Started" afterward. Treat 265 as a red herring until proven otherwise.

## NEXT frontier — CAN_GRAPHICAL=0: udevd never processes card0  [START HERE]
Measured chain (single boot, OXDIAG probe in image dumps /run/udev state):
- seat0 file: `CAN_GRAPHICAL=0`, `CAN_TTY=0`.
- `/run/udev/tags/systemd/` contains ONLY `b254:0` — card0 (c226:0) is NOT
  tagged systemd/master-of-seat. `cat /run/udev/data/c226:0` → ENOENT (no db
  entry written → udevd never finished card0).
- card0 = SEQNUM 50: logged "Device is queued" + "ready for processing" at ~23s
  but NO "Worker forked for SEQNUM=50" ever, and "Device processed" reaches
  ~41/47/48/49 then HALTS (42-46, 50, 51 never processed). udevd prints
  "Cleaning up idle workers" ~30.5s thinking the queue is drained.
- children_max=15 but only 8 workers ever fork (51-58); ALL exit together at
  ~30.8-31.0s after being busy ~10-20s each doing `kmod load` / "Loading module:
  pci:..." (138 kmod loads total). Boot is ~2.5-4.5 min to graphical.
- HYPOTHESIS (unproven): card0 waits on its PCI/virtio-gpu PARENT event
  (one of SEQNUM 42-46) that is stuck in a slow/looping worker; OR udevd stops
  dispatching the queue. Next measure: identify card0's parent devpath and
  whether that parent's uevent ever completes; time a single `kmod load` /
  finit_module (313_finit_module.rs reads whole .ko over ext4 — likely the
  per-worker slowness). If module-load-for-builtin is the stall, make
  kmod/finit_module fail-fast for built-in modules.
- gdm exits code=1 (059_execve shows it only execs plymouth=ENOENT, non-fatal);
  most likely gdm exits because CAN_GRAPHICAL=0 (no graphical seat). Fix
  CanGraphical reliability first, then re-check gdm.

## Diagnostic method (measure, don't guess — enforced this session)
- Mount parent/dest bugs cracked by: trace each EINVAL return tag in
  move_mount_m; dump the mount table (id, parent_id, rendered_path) at the
  reject; then a [GRAFT] trace at creation showing the mount born with the wrong
  parent. All traces reverted after use.
- The bind-dentry ambiguity is the recurring theme (see auto-memory
  "mount-dentry-sharing-gotcha"): ALWAYS pass the walked path->mnt, never
  re-derive a mount from a bare dentry when binds are in play.

## Boot harness
`bash <scratchpad>/boot.sh <log> 200` (kills stale qemu, boots live-gnome ISO,
serial→log). Build: `cd ../oxide-images && make kernel ARCH=x86_64 && cd
../kernel && cargo run -q -p xtask -- artifacts --arch x86_64 && cd
../oxide-images && cargo run -q -p imagectl -- build-boot --profile live-gnome
--arch x86_64`. STALE-ARTIFACT TRAP: a compile FAIL still lets `xtask artifacts`
export the last-good kernel — always confirm the build `Finished` line.
Checks: `grep CAN_GRAPHICAL <log>`; `grep -c code=265 <log>`;
udev queue: `grep 'Device processed' <log>`; card0: `grep -i card0 <log>`.

## Ledger
metadata/index.md: B next=319 (318 in use this session), D next=120, F next=650.
