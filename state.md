# State 2026-05-10

## Branch
`main`. Last merged: PR #998 (R78: sys_fcntl compress).

## What just shipped (this session)

Layering spec + fs unification + per-syscall Tier-3 migration:

- **D60 #979** — `docs/53-syscall-layering.md` (three-tier architecture, DRAFT living)
- **R60 #980** — flatten `sched::syscalls::*` → `sched::*` per spec §6
- **R61–R65** — reference Tier-3 shims (read/write/close/dup×3/lseek), getpid family, mass-rename 240 fns `kernel_sys_*` → `sys_*`
- **R66 #986** — `vfs::fs::FileSystem` trait + per-backend impls (devfs/tmpfs/ext4/procfs)
- **R67 #987** — `vfs::mount::Table` + `vfs::mount::lookup` unified entry
- **R68 #988** — collapse open/truncate/perms/utime chains; sys_open 77→46 LOC; `vfs::file::install_open` helper
- **R69 #989** — `block::registry` named device table; ext4 rootfs self-registers
- **R70–R71** — chdir/access/statx/stat + namei (unlink/rename) collapsed to `vfs::mount::lookup`
- **R72–R76** — net family Tier-2 extraction (bind/connect/listen/accept/sendto/recvfrom). Adds `BoundAddr`, `RemoteAddr`, `SenderCreds`, `Accepted`, `Received` typed enums in `net::sock`
- **R77 #997** — sys_mremap → `vmm::AddressSpace::mremap` (84→24 LOC)
- **R78 #998** — sys_fcntl compress (66→31 LOC)

## Spec docs/53 in place

Three tiers: foundational `syscall` crate (Tier 1) / typed subsystem work fns (Tier 2) / ABI shims in `kernel/src/syscalls/` (Tier 3). Forbids `<sub>::syscalls::*` sub-namespaces. Target shim ≤ 50 LOC.

## Open work

**Five genuine over-cap shims** needing real Tier-2 extraction:
- `sys_statx` (99) — mask + AT_EMPTY_PATH dual path
- `sys_select` (70) — per-fd readiness, pty special-cases
- `sys_unshare` (67) — per-NS allocation
- `sys_rt_sigtimedwait` (63) — signal subsystem
- `sys_setsockopt` (52) — net

**Five orchestrators** that stay per spec §7 (Linux `kernel/` pattern):
- `sys_execve` ×2, `sys_clone_dispatch`, `sys_ioctl`, `sys_ptrace`

**False positives** in the over-cap audit (counter caught docstrings):
- `sys_pwritev`/`sys_preadv` are 1-line aliases
- `sys_getdents64`, `sys_poll` are similar wrappers

## kernel/src/ shape

~16K LOC. After R72-R78 the syscalls/ tree is mostly Tier-3 shape-conformant. Big remaining files: `syscalls/` (21 files, ~7K LOC, handlers), `smoke/` (12 files, ~3.5K), `pci_boot/` (~1.6K, integration glue per spec §7), `procfs/` + `dev/` (boot bootstraps).

## ARM interactivity issue (still parked)

ARM boots to `oxide login:`, init forks + child reaches execve cleanly. Keystrokes after the prompt don't reach busybox. Comes back when this migration track settles.

## First task next session

```sh
git checkout -b R79-statx-extract
# Read sys_statx (kernel/src/syscalls/fs.rs:193); design a
# vfs::file::statx Tier-2 work fn for the typed mask + AT_EMPTY_PATH
# fd path. Pattern: see R77 (vmm::mremap) for an mm extraction and
# R72-R76 (net::sock::*) for the typed-enum + work-fn pattern.
```

Or pivot:
- virtio-blk driver bring-up (now feasible — `block::registry` exists)
- procfs/sysfs body extraction via `vfs::FileSystem`
- ARM interactivity debug

## Useful pointers

- Layering spec: `docs/53-syscall-layering.md`
- Reference Tier-3 shim: `sys_read` (`kernel/src/syscalls/mod.rs:32`)
- Reference net Tier-2: `net::sock::bind/connect/sendto/recvfrom/accept/listen`
- Reference mm Tier-2: `vmm::AddressSpace::mremap`
- Mount table API: `vfs::mount::register / lookup / resolve_mount`
- Block registry: `block::registry::register / by_name / by_index`
