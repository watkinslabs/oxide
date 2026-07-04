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

## Mechanism — CONFIRMED (measurement now unimpeachable)
The decisive probe logged the fsid of the ACTUAL inode logind's `openat("/sys")`
returns (no re-resolve, no root-provider ambiguity): **159 `/sys` opens →
sysfs (0x0102199400000002); exactly ONE → ext4 (0x1), and it is logind (mnt
381).** So logind's `/sys` really is the empty ext4 underlay — the sysfs mount is
NOT crossed, SPECIFIC to logind.

WHY: a `d_add` probe (name=="sys", parent inode is the ext4 root ino
0x6e54…0002) showed the ext4 `/sys` dentry created MANY times, each under a
DIFFERENT parent dentry pointer → **the ext4 ROOT directory inode has many
dentry aliases.** Linux forbids this (a dir inode has exactly one dentry via
`d_splice_alias`). `__lookup_mnt` keys on `(parent_mnt_id, dentry_ptr)`, so sysfs
mounted on alias-A's `/sys` is invisible when logind walks alias-B's `/sys`.

ROOT CAUSE: **bind mounts build a parallel dentry tree.** `register_bind` →
`build_sb` → `SuperBlock::for_backend` → `d_make_root(inode)` mints a FRESH root
dentry per SB, and each bind of `/` (systemd does many, one per sandboxed
service) uses `BindFs` = a NEW SuperBlock, so a NEW ext4-root alias with its own
`/sys` child. Linux `clone_mnt` instead does `mnt->mnt_root = dget(old->mnt_root)`
— a bind SHARES the source's sb + root dentry, so submounts stay visible.

## First task next session — THE FIX (bind dentry sharing)
Make bind mounts SHARE the source's dentry tree instead of building a `BindFs`
parallel one. Options, cheapest first:
1. In the bind attach path (`syscalls/165_mount.rs` MS_BIND → `vfs::mount::
   register_bind`/`attach`), set the bind mount's `s_root`/`mnt_root` to the
   SOURCE's existing root dentry (`dget`) and share the source's SuperBlock,
   rather than `build_sb`+`d_make_root` minting a fresh alias. This is the Linux
   `clone_mnt` shape and removes the multi-alias at its source.
2. If (1) is too invasive, enforce the dir-single-dentry invariant in
   `d_make_root`/`d_add`: for a directory inode that already has a dentry alias,
   RETURN that alias (Linux `d_splice_alias`) instead of a fresh one.
VERIFY LEFT: extend `crates/kernel/vfs/tests/greeter_sysfs_after_pivot.rs` (5
tests, all PASS today because they use `register_bind` with a NamedFs that
SHARES the inode — they do NOT exercise the `BindFs`-per-SB alias path). Add a
test that mounts sysfs at `/sys`, then binds `/` via a SECOND SuperBlock over the
same root inode (the BindFs shape), and asserts `/sys` still crosses when walked
through the original mount → this goes RED with today's code, GREEN after the fix.

## Also landed (correct invariant, not the primary fix)
`vfs::dcache::d_drop` now no-ops on a dentry with `D_MOUNTED` (a mounted dentry
must stay hashed/canonical — Linux `__d_drop` never unhashes a live mountpoint).
Closes a real orphaning hole; 98+ vfs tests green; boot reaches graphical.target.
Did NOT by itself fix the greeter (the alias source is BindFs SB creation, not
d_drop), but it is correct hardening.

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
