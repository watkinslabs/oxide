# Session hand-off

## Headline
Branch `F376-arm-selfbootstrap` (PR #1525). Limine fully removed; both arches
boot to login at SMP=1. This session also: arm PSCI SMP=2 + x86 INIT-SIPI
SMP=2 (APs reach `online`), ACPI/PCI/**display** restored, device-init
un-gated, DTB-parse bug fixed. **qemu-mcp server fixed** (was broken by the
Limine removal). TWO open bugs found via the user's live test — see below.

## qemu-mcp: FIXED — restart it to use it
`c4d902c4`: the MCP built via the removed `xtask image`. Added a build-only
`xtask image --arch X [--features Y]` (rootfs+kernel+GRUB ISO, prints
`image=<path>`); `server.py` now boots `target/oxide-<arch>-grub.iso`
(`-cdrom`/`-boot d` + rootfs virtio-blk + socket-serial/QMP/`-s -S`).
**Action: restart the MCP server (or Claude) so qemu_start works.**

## OPEN BUG 1 — `find /` ENOENTs into directories (dirfd-relative resolve)
Symptom: `find / | grep No` → "No such file or directory" for many DIRS
(/etc/init.d, /usr/share, /home/alice, …). NARROWED:
- Image on-disk is correct (all dirs/inodes present; identical metadata).
- Boot-time `pathresolve::resolve("/etc/init.d")` = OK (all dirs).
- Interactive `ls /etc/init.d`, `cd /etc/init.d`, `ls /usr/share`,
  `python3 --version` ALL WORK.
- So ONLY `find`'s **dirfd-relative** walk fails: `openat(parent_dir_fd,
  child)` / `fstatat(parent_dir_fd, child)` (find uses FTS_CWDFD). Absolute +
  AT_FDCWD-relative + boot resolve all work.
- Locus: `pathresolve::resolve_at` (kernel/src/syscalls/pathresolve.rs:122)
  for a REAL dirfd uses `f.dentry().absolute_path()` as the base. `install_open`
  (vfs/src/file.rs:348) stores a standalone `Dentry::new(None, full_path, inode)`;
  `absolute_path()` (dentry.rs) special-cases that. Trace says it SHOULD give
  the right base — but find empirically fails. NEXT: write a tiny C probe doing
  `int d=open("/etc",O_DIRECTORY); openat(d,"init.d",O_DIRECTORY); fstatat(d,"init.d",..)`
  and run it (shell or boot ELF) — reproduces; then trace `resolve_at` +
  `absolute_path()` for the dir fd with the (now-fixed) qemu-mcp single-step.
  Likely the dir fd's stored dentry path is wrong, OR a deep-traversal fd issue.

## OPEN BUG 2 — interactive python3 segfaults (the original item 3)
`/usr/bin/python3 --version` / `-c` / scripts WORK; the interactive REPL
SEGVs (musl mallocng a_crash heap corruption). Reproduces in normal use
(earlier "non-reproducing" was instrumentation-only). NEXT: catch the
`[FAULT] sigsegv rip=/far=` on serial when it crashes → diagnose the kernel
MM gap (the REPL's readline/tty alloc pattern triggers it).

## SMP=2 — APs start, but participation races late boot (gate stays SMP=1)
`99c994a6` + earlier: x86 INIT-SIPI real-mode trampoline (ap_tramp_x86.rs) +
arm PSCI both bring APs to `[ap]/[sipi] online`. 5 x86 trampoline bugs fixed
(assembler mis-encode, identity map, kernel GDT, EFER.NXE). BUT when the AP
then SCHEDULES during late boot it races the BSP: x86 PMM double-free, arm
hang, both right after `keymap loaded` (the pre-existing B51 race, now ~always).
Gate reverted to SMP=1 (reliable; AP code is no-op at -smp 1). FIX (next):
defer AP scheduler participation (timer+runqueue) until boot is quiescent, OR
make the boot-phase scheduler/PMM SMP-safe. TASKS.md S4a-smp-regress.

## First command next session
```
cd /home/nd/oxide2 && git log --oneline -6
```
Then (MCP restarted): reproduce OPEN BUG 1 with a C probe / qemu_start, fix
`resolve_at`/`install_open` dentry-path for dir fds; then OPEN BUG 2; then the
SMP=2 participation race.
