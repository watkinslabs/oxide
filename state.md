# state.md — session handoff

## Headline
GNOME greeter still not rendered. This session TRACED the blocker end-to-end to a
single fact and narrowed the mechanism, but did NOT land the fix. Root-cause
graph (artifact): the greeter chain + logind's ns-14 mount tree.

## THE bulletproof fact
`systemd-logind`'s own `openat(/sys, "dev")` returns **ENOENT**. Therefore:
`sd_device_new_from_device_id("c226:0")` fails → card0 never attached to a seat →
`/run/systemd/seats/seat0` never created → seat0 not CanGraphical → gdm greeter
child exits code 1 → no greeter. Every step above is observed in real boots, not
inferred. Everything UPSTREAM works: card0 IS tagged master-of-seat, the tag dir
`/run/udev/tags/master-of-seat/c226:0` is present and readable at logind-enumerate
time, logind's getdents returns `c226:0`.

## Mechanism — strong but CAVEATED (measurement suspect)
Boot-side traces showed logind's `/sys` resolving to fsid `0x1` (ext4 underlay),
NOT sysfs (`0x0102199400000002`) — i.e. the sysfs mount not crossed in logind's
sandbox namespace. Observed ns-14 tree: sysfs mnts 403/404 parented to a `bind`
sandbox root (397), keyed on the live `/sys` dentry `0x825e8718`; the walk rooted
on ext4 (381) whose `/sys` mount (384) is keyed on a DIFFERENT dentry
`0x80f78fd0`. `__lookup_mnt` keys strictly on `(parent_mnt_id, dentry_ptr)` →
miss → `/sys` = empty ext4 dir.

**BUT** (docs/CLAUDE lesson 4 — clean repro contradicts boot → suspect the
measurement): faithful HOSTED repros of the systemd sequence ALL PASS, so either
the exact trigger is unmodeled OR the boot-side `resolve()`/`resolve_path()`
traces measured the INIT-ns view (global root provider), not logind's real
`task->root`. Only logind's own ENOENT is unimpeachable.

## First task next session — RESOLVE THE CAVEAT
1. Add a boot trace that resolves `/sys` (and `/sys/dev`) using logind's ACTUAL
   `current()->root` dentry + its mount ns — NOT `pathresolve::resolve()` (which
   may use the global root provider). This confirms/refutes "logind's /sys = ext4
   underlay." That single measurement decides the fix direction.
2. IF confirmed (sysfs not crossed in logind's ns): extend the hosted repro
   `crates/kernel/vfs/tests/greeter_sysfs_after_pivot.rs` (4 tests, all PASS
   today) with the missing wrinkle until one goes RED — candidates in priority:
   the RO bind-remount pass systemd runs (`ProtectSystem=strict` bind-remounts
   every mount ro), a `d_drop`-driven re-creation of the `/sys` mountpoint dentry
   that orphans the mount keyed on the old pointer, or ProtectControlGroups/
   ProtectKernelTunables overmounts. Fix is then in `vfs::mount` (rebuild_ns_index
   / follow_mount_down `__lookup_mnt`) or the dentry lifetime, against the red test.
3. IF refuted (logind's /sys IS sysfs): the ENOENT is a `/sys/dev`-specific
   negative-dentry / op_lookup issue — re-open that thread (op_lookup never
   missed "dev"; raw PseudoDir had dev+dev/char; a cached negative shadowed it).

## Landed this session (branch B318, PR pending)
- **`crates/kernel/sysfs/src/bus.rs` `dev_index_target`** — real correctness fix:
  `/sys/dev/char/226:0` pointed at dangling `devices/platform/dri/card0`
  (dev_root_canon fallthrough); now `devices/virtual/drm/card0` (the dir
  sysfs::drm actually builds). Needed for the drm device-id chase once the mount
  bug is fixed; does NOT by itself render the greeter (blocked upstream by the
  /sys resolution).
- **`crates/kernel/vfs/tests/greeter_sysfs_after_pivot.rs`** — 4 hosted regression
  tests for sysfs reachability across sandbox relocation (copy_mnt_ns + rbind +
  MS_MOVE/pivot + stacked fresh sysfs + shared→slave prop). All PASS — they are
  the scaffold to EXTEND into a red repro per step 2.

## Diagnostic tooling (all reverted — do not re-add blindly)
This session added ~14 files of klog traces (TAGOPEN/DEVIDX/DRMOPEN/NSTREE/
DDELETE/SYSDEVMISS…) to pin the chain, then reverted them. The winning probes
were: (a) dump a sysfs dir's entries INLINE on open (bypasses getdents/absolute_
path fragility), (b) log `current()->exe_path` to identify the process, (c) dump
the ns mount tree with `(mnt_id, parent_id, fs, mountpoint dptr)` and compare to
the walk's dentry ptr. Re-derive from those, don't re-add all 14.

## Boot harness
`bash <scratchpad>/boot.sh <log> 90` — kills stale qemu, boots live-gnome ISO,
serial→log. Build: `cd ../oxide-images && make kernel ARCH=x86_64 && cd ../kernel
&& cargo run -q -p xtask -- artifacts --arch x86_64 && cd ../oxide-images &&
cargo run -q -p imagectl -- build-boot --profile live-gnome --arch x86_64`.
STALE-ARTIFACT TRAP: a compile FAIL still lets `xtask artifacts` export the
last-good kernel → you boot a stale binary. Always confirm the build `Finished`
line before trusting a boot.

## Ledger
metadata/index.md: B next=318 (used here → bump to 319), D next=120, F next=650.
