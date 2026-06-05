# Syscall Audit

Sources of truth: Linux x86_64 syscall table (`arch/x86/entry/syscalls/syscall_64.tbl` from Linux mainline), repo constants in `crates/kernel/syscall/src/nrs.rs`, and the live dispatcher rooted at `kernel/src/syscalls/mod.rs` plus helper dispatchers in `kernel/src/syscalls/{misc,perms}.rs`, `crates/kernel/sched/src/{cred,timers,compat}.rs`, and `crates/kernel/fs/src/{xattr,keyring}.rs`.

**Numbering result:** existing `NR_*` constants are correctly numbered against Linux mainline (`0` misnumbered). Missing support is split between **35** Linux syscalls with no `NR_*` constant in this repo and **26** syscalls that have a correctly numbered constant but no live route in the current dispatcher/helper chain.

## Disposition reconciled (R06, 2026-06-05)

`docs/15` no longer uses `V1/V2/NEVER` (deferral labels that drifted from this
audit). Every syscall is **IMPL** (full Linux semantics, mandatory) except 17
**OBSOLETE** numbers that modern Linux itself ENOSYS's. The old `status` column
below is historical; treat **every non-OBSOLETE row as a target for full Linux
correctness**. The 35 missing `NR_*` are now registered in `nrs.rs` (R06 block).
This file is the live tracker — tick items off here as the sweep lands.

## Fix plan (prioritized — work top-down, verify each, update this file)

1. **Wire the dispatcher (registration).** Route every newly-registered number
   in `kernel/src/syscalls/mod.rs`: the 17 OBSOLETE → deliberate `sys_enosys`
   (match Linux); the 26 numbered-but-unmapped + the modern additions
   (`fchmodat2`, futex2 `futex_wake/wait/requeue`, `statmount`/`listmount`,
   `*xattrat`, `mseal`, `cachestat`, `ioprio_*`, `sched_setattr/getattr`,
   `open_by_handle_at`, the libaio `io_*` family, `swapon/off`, `acct`,
   `quotactl[_fd]`, `remap_file_pages`, `ustat`, `sysfs`, `modify_ldt`) → real
   Tier-2-backed shims. **First** the ones real programs call (sched_setattr,
   ioprio, fchmodat2, futex2, cachestat); the truly-rare aio/quota later but
   still IMPL.
2. **Fix the partial/hack/subset IMPL syscalls** flagged "Subset"/"Hack" in the
   matrix to full Linux semantics — notably `open` (path/fd-link shims),
   `access` (existence-only → real perm check), `pipe`, `select`/`poll`
   (synthetic readiness), `socket`/`sendto`/`recvfrom`/`sendmsg`/`recvmsg`
   (netlink/AF_PACKET/cmsg special-cases), SysV `shm*`/`sem*`/`msg*`
   (registry tricks → real substrate), `utime` (overlay fallback).
3. **Move Tier-3-leaked work to Tier-2** per `53§4.1`: `read`/`write`/`brk`/
   `pipe`/`getpid` and the net special-cases — push the work fn into the owning
   crate; the shim shrinks to parse→call→encode.
4. **Delete the dead dispatcher** `crates/kernel/syscall/src/dispatch.rs` — one
   source of truth (`kernel/src/syscalls/mod.rs`).
5. **Magic-number sweep** in syscall shims/helpers → typed constants per `07§5`.

Method: per syscall, a hosted test over a real fixture where possible, then a
boot verify; flip its matrix row to "done" here. No stubs — `IMPL` means done.

## Crate extraction design (own crate, one file per syscall)

Goal: syscalls live in their **own crate** `crates/kernel/syscalls` (pkg
`syscalls`), NOT in the `kernel` crate — kernel is a hollow shell. One file per
syscall, named **`NNN_name.rs`** (e.g. `000_read.rs`, `002_open.rs`,
`452_fchmodat2.rs`); since a Rust module can't start with a digit, each is wired
in `lib.rs` via `#[path="NNN_name.rs"] pub mod sNNN_name;` so the **filename
keeps the number+name**. Each file: one `pub fn sys_<name>(args:&SyscallArgs)
-> i64` — parse/validate/fetch/call-one-Tier-2-fn/encode, zero work logic.

Why feasible: `kernel/src/syscalls/` is already inside the `kernel` crate (which
depends on every Tier-2 crate). The Tier-3 helpers it uses
(`validate_user_buf[_writable]`, `read_user_cstr`, `pathresolve`, `netlink_fd`)
use only crate deps (hal/vmm/sched/vfs) — so they move into the new crate too.

Bounded-blast-radius procedure (strangler; keep it compiling + booting every step):
1. Create `crates/kernel/syscalls` (deps: syscall, sched, vfs, vmm, hal, klog,
   net, ipc, devfs, …). Add to workspace `members`.
2. Move the shared Tier-3 helpers in first (`userptr` validators, `pathresolve`,
   `read_user_cstr`, `netlink_fd`). For anything still kernel-side, install a
   `fn`-pointer hook at boot (e.g. netlink is_netlink/read) so the crate stays
   decoupled.
3. `kernel`'s `Cargo.toml` gains `syscalls = { path = ... }`. `kernel/src/
   syscalls/mod.rs` **re-exports** the crate's items (`pub use syscalls::*`) so
   existing `crate::syscalls::X` call sites compile unchanged during migration.
4. Migrate syscalls 0→end: move each shim into `NNN_name.rs`, fix to full Linux
   (close its `syscal_anal.md` gap), repoint its dispatch arm at
   `syscalls::sNNN_name::sys_<name>`, delete the old inline/per-sub copy.
5. When the last syscall is migrated: delete the dead
   `crates/kernel/syscall/src/dispatch.rs`; `kernel/src/syscalls/mod.rs` shrinks
   to the table install only.
Gate each batch: `cargo build` both arches + `make smoke` (boot to login).

### Full crate decomposition (kernel = pure glue; every concern is a crate)

Execute in dependency order; build both arches + `make smoke` after each.

1. **`kmacros`** (crates/shared) — the `debug_pmm/vmm/irq/acpi/sched/boot/cgroup/
   syscall/ssh` + `dtrace` gating macros (from kernel/src/debug_macros.rs). No
   deps. `#[macro_export]` each; users do `#[macro_use] extern crate kmacros`.
   Features: `debug-pmm/...` (10). Kernel forwards its `debug-*` → `kmacros/*`.
2. **`smoke`** (crates/kernel) — kernel/src/smoke/* (elf/ksched/mmuops/preempt/
   canary/device_map/pf_recover/user_map/elf_arm) + per-subsystem boot smokes
   (pty/etc.). Deps: the subsystems it tests + kmacros. Kernel calls
   `smoke::run_*()` at boot (glue).
3. **`devpts`** — kernel/src/dev/pty.rs (/dev/ptmx + /dev/pts). Deps: tty, vfs,
   devfs, sched, hal, kmacros. Its smokes live in the `smoke` crate.
4. **`pidfd`→`fs`**, **drm node→`drm`** — kernel/src/dev/{pidfd,drm}.rs.
5. **`syscalls`** (crates/kernel) — kernel/src/syscalls/* → one file per syscall
   (`NNN_name.rs`). `vdso`+`vvar` move INTO it (syscall/time-area). Deps: syscall,
   sched, vfs, vmm, net, ipc, devfs, security, nscg, kmacros, devpts, drm, fs.
   Kernel: `pub use syscalls;` for call-site compat.

After this the kernel binary holds only: boot/init bring-up, the dev-node
registration glue, the dispatch-table install, and `vvar` publish — pure glue.

### Coupling map (the only real blockers — measured)

Across `kernel/src/syscalls/` the only `crate::` refs that are NOT already
crates (so they block a clean lift) are 7 kernel-local modules (~23 refs).
Move each into a crate ("all the shit in crates"), then the syscall layer lifts
wholesale:

| kernel-local | used by | target crate |
|---|---|---|
| `rlimit::DEFAULT_RLIMITS` | getrlimit/prlimit | `sched` |
| `seccomp::{check,sys_seccomp}` | dispatch gate, seccomp(2) | `security` |
| `dev_bpf::sys_bpf` | bpf(2) | new `bpf` crate |
| `vdso::map_into_current` | execve/clone | `exec` |
| `dev_proc_ns::{NsInode,setns_apply,user_ns_record,has_cap_for}` | setns/unshare | `nscg` |
| `dev::{drm,pidfd,pty}` | ioctl/pidfd_open | `drm`/`fs`/`tty` |
| `smoke::elf` | test-only | stays kernel-side via boot-installed hook |

Everything else (`devfs`,`sched`,`vfs`,`vmm`,`net`,`ipc`,`netlink`,`security`,…)
is already a crate. `crate::syscalls::*` (306) are self-refs → internal to the
new crate. `kernel/src/lib.rs`: `pub use syscalls;` keeps every external
`crate::syscalls::X` call site compiling.

### Refined (measured 2026-06-05) — the work is small

- **Already crates, zero move:** `crate::seccomp`=`security::seccomp`,
  `crate::dev_bpf`=`security::bpf`, `crate::dev_proc_ns`=`nscg::proc_ns`,
  `crate::rlimit`→`sched::rlimit` (DEFAULT_RLIMITS lives in `sched`). The
  syscalls crate just depends on `security`/`nscg`/`sched`.
- **Move INTO the syscalls crate (syscall-area, not separate crates):**
  `vdso` (kernel/src/vdso.rs, 121L) and `vvar` (kernel/src/vvar.rs, 100L).
  vvar↔`syscalls::time` is a cycle ONLY across crates — with both inside the
  syscalls crate it's intra-crate, no untangle. Kernel boot's `crate::vvar::
  {publish,monotonic_now_ns}` → `syscalls::vvar::*`. `dev::pidfd` (fd-area, 221L)
  also moves into the syscalls crate.
- **Relocate to existing device crates:** `dev::pty` (351L, only dep `devfs` —
  a crate) → `tty`; `dev::drm` (269L) → `drm`. Update the ~4 syscall + lib.rs
  refs.
- **Hook (test-only):** `smoke::elf` (2 refs) — kernel installs a fn-ptr at boot.

So the genuine external moves are just pty→tty and drm→drm; everything else is
either already a crate or rides into the syscalls crate. Execute as one focused
run gated on `cargo build` (both arches) + `make smoke`.

## Summary

| Metric | Count |
|---|---:|
| Linux x86_64 syscalls audited | 385 |
| Repo `NR_*` constants present | 350 |
| Misnumbered repo constants | 0 |
| Live-mapped syscalls | 324 |
| Correctly-numbered but unmapped syscalls | 26 |
| Linux syscalls missing from `nrs.rs` | 35 |

## Cross-cutting findings

| Finding | Why it matters | Evidence |
|---|---|---|
| `futimesat` is live-routed to `utimensat` | ABI/spec drift: docs mark `futimesat` as `NEVER`, but the live dispatcher maps it. | `kernel/src/syscalls/mod.rs:820`; `docs/15-syscall-abi.md:362` |
| `get_mempolicy` has split ownership | The live dispatcher points `GET_MEMPOLICY` directly to `syscall::numa::sys_get_mempolicy`, while `kernel/src/syscalls/misc.rs` also owns the NUMA tail. | `kernel/src/syscalls/mod.rs:818-823`; `kernel/src/syscalls/misc.rs:29-48` |
| Old stub vs live dispatcher divergence | `crates/kernel/syscall/src/dispatch.rs` still looks authoritative, but the real kernel path is `kernel/src/syscalls/mod.rs`; easy to audit the wrong surface. | `crates/kernel/syscall/src/dispatch.rs:1-8,36-45,355-365`; `kernel/src/syscalls/mod.rs:548-580` |
| ABI magic numbers are widespread in syscall code | Raw flag/mask/index literals remain in syscall shims and helpers despite `docs/07§5` banning them for ABI constants. | `docs/07-toolchain-and-targets.md:163-170`; `kernel/src/syscalls/mod.rs:18,102-103,249-250,864-865`; `kernel/src/syscalls/misc.rs:21-25,63-77,92,223-258`; `kernel/src/syscalls/perms.rs:23,95,109,136` |

## Detailed matrix

Interpretation: **Numbering OK?** compares `crates/kernel/syscall/src/nrs.rs` against Linux mainline. **Live mapped?** means routed by the current kernel dispatcher/helper chain, not the older stub table in `crates/kernel/syscall`. Rows that say **No material issue found** were live-mapped and did not surface a concrete defect beyond any doc-status drift found in this audit pass.

| Nr | Syscall | docs/15 status | Numbering OK? | Live mapped? | Linux standard | Wrong with it | Hack? | Wrong subsystem? | Magic numbers? | Evidence |
|---:|---|---|---|---|---|---|---|---|---|---|
| 0 | read | V1 | Yes | Yes | Yes | No material defect found beyond large shim ownership. | No | Maybe — Tier-3 still owns core work | No | kernel/src/syscalls/mod.rs:45-95,183-195 |
| 1 | write | V1 | Yes | Yes | Yes | No material defect found beyond large shim ownership. | No | Maybe — Tier-3 still owns core work | No | kernel/src/syscalls/mod.rs:45-95,183-195 |
| 2 | open | V2 | Yes | Yes | Subset | Special-case reopen/path shims; not full Linux open semantics. | Yes — fd-link/path shim | No | Yes — raw O_* / AT_* literals | kernel/src/syscalls/open.rs:43-54,129-185,230-305 |
| 3 | close | V1 | Yes | Yes | Yes | No material defect found beyond large shim ownership. | No | Maybe — Tier-3 still owns core work | No | kernel/src/syscalls/mod.rs:45-95,183-195 |
| 4 | stat | NEVER | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it never. | No | No | No | kernel/src/syscalls/mod.rs:897 |
| 5 | fstat | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:603 |
| 6 | lstat | NEVER | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it never. | No | No | No | kernel/src/syscalls/mod.rs:898 |
| 7 | poll | V2 | Yes | Yes | Subset | Readiness is partly synthetic via inode.poll() and custom loops. | No | No | Yes — hardcoded caps | kernel/src/syscalls/poll.rs:25-123 |
| 8 | lseek | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:621 |
| 9 | mmap | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:593 |
| 10 | mprotect | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:851 |
| 11 | munmap | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:594 |
| 12 | brk | V1 | Yes | Yes | Yes | Shim contains cgroup memory.max charge/uncharge policy logic. | Yes — policy shortcut in shim | Yes — work leaked into Tier 3 | Yes — raw RLIMIT indexes/limits | kernel/src/syscalls/mod.rs:149-180 |
| 13 | rt_sigaction | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:854 |
| 14 | rt_sigprocmask | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:855 |
| 15 | rt_sigreturn | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:905 |
| 16 | ioctl | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:604 |
| 17 | pread64 | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:734 |
| 18 | pwrite64 | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:735 |
| 19 | readv | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:616 |
| 20 | writev | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:615 |
| 21 | access | V2 | Yes | Yes | No | Only checks existence; ignores real permission/mode semantics. | Yes — existence-only shim | No | Yes — raw AT_FDCWD sentinel | kernel/src/syscalls/fs.rs:679-724 |
| 22 | pipe | V2 | Yes | Yes | Subset | Creates pipe inode directly and writes fd pair to user memory from shim. | Yes — direct user write / synthetic inode | No | Yes — raw flags / pointer arithmetic | kernel/src/syscalls/mod.rs:97-146,881-890 |
| 23 | select | NEVER | Yes | Yes | Subset | Uses synthetic wake loops over inode.poll(); not full Linux readiness semantics. | No | No | Yes — hardcoded caps/rescan interval | kernel/src/syscalls/select.rs:13-154 |
| 24 | sched_yield | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:612 |
| 25 | mremap | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:686 |
| 26 | msync | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:687 |
| 27 | mincore | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:688 |
| 28 | madvise | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:852 |
| 29 | shmget | NEVER | Yes | Yes | No | SysV SHM uses registry/clone tricks, not real shared memory frames. | Yes | No | Yes — raw IPC commands/layout assumptions | crates/kernel/ipc/src/sysv_shm.rs:70-214 |
| 30 | shmat | NEVER | Yes | Yes | No | SysV SHM uses registry/clone tricks, not real shared memory frames. | Yes | No | Yes — raw IPC commands/layout assumptions | crates/kernel/ipc/src/sysv_shm.rs:70-214 |
| 31 | shmctl | NEVER | Yes | Yes | No | SysV SHM uses registry/clone tricks, not real shared memory frames. | Yes | No | Yes — raw IPC commands/layout assumptions | crates/kernel/ipc/src/sysv_shm.rs:70-214 |
| 32 | dup | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:861 |
| 33 | dup2 | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:862 |
| 34 | pause | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:695 |
| 35 | nanosleep | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:857 |
| 36 | getitimer | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:696 |
| 37 | alarm | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:694 |
| 38 | setitimer | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:697 |
| 39 | getpid | V1 | Yes | Yes | Yes | PID namespace behavior is synthetic via shadow fields. | No | No | Yes — raw namespace/visibility rules | kernel/src/syscalls/mod.rs:197-224 |
| 40 | sendfile | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:760 |
| 41 | socket | V1 | Yes | Yes | Subset | Admits some raw-socket requests as UDP-like sockets. | Yes | No | Yes — raw family/type literals | kernel/src/syscalls/net.rs:37-83 |
| 42 | connect | V1 | Yes | Yes | Subset | v4-mapped IPv6 and timeout behavior are custom. | No | No | Yes — raw family/timeouts | kernel/src/syscalls/net.rs:513-562 |
| 43 | accept | V2 | Yes | Yes | Subset | Blocking and flag handling are custom; accept4 shares accept path. | No | No | Yes — raw SOCK_* bits | kernel/src/syscalls/net.rs:437-511 |
| 44 | sendto | V1 | Yes | Yes | Subset | Netlink and AF_PACKET use special-case paths outside the generic socket path. | Yes | No | Yes — raw sockaddr parsing | kernel/src/syscalls/net.rs:270-354 |
| 45 | recvfrom | V1 | Yes | Yes | Subset | Netlink special-case path and custom timeout/park logic. | Yes | No | Yes — raw sockaddr/time fields | kernel/src/syscalls/net_recv.rs:17-111 |
| 46 | sendmsg | V1 | Yes | Yes | Spec mismatch | Control-message handling is special-cased and incomplete. | Yes | No | Yes — raw cmsg parsing constants | kernel/src/syscalls/net.rs:565-605; kernel/src/syscalls/cmsg_parse.rs:17-45 |
| 47 | recvmsg | V1 | Yes | Yes | Spec mismatch | AF_UNIX cmsg handling is split out and msghdr semantics are partial. | Yes | No | Yes — raw cmsg parsing constants | kernel/src/syscalls/net.rs:607-653; kernel/src/syscalls/cmsg_parse.rs:208-260 |
| 48 | shutdown | V1 | Yes | Yes | Subset | Non-TCP/UNIX shutdown handling is narrow. | No | No | Yes — raw how values | kernel/src/syscalls/net.rs:698-730 |
| 49 | bind | V1 | Yes | Yes | Subset | AF_UNIX and AF_PACKET use string/raw-layout shortcuts. | Yes | No | Yes — raw sockaddr/ifindex fields | kernel/src/syscalls/net.rs:186-267 |
| 50 | listen | V1 | Yes | Yes | Subset | No major issue found; still limited by simplified socket substrate. | No | No | No | kernel/src/syscalls/net.rs:421-435 |
| 51 | getsockname | V1 | Yes | Yes | Subset | Mostly works, but remains limited by simplified stored peer state. | No | No | No | kernel/src/syscalls/net.rs:657-695 |
| 52 | getpeername | V1 | Yes | Yes | Subset | Mostly works, but remains limited by simplified stored peer state. | No | No | No | kernel/src/syscalls/net.rs:657-695 |
| 53 | socketpair | V1 | Yes | Yes | No | Uses InetSocket as AF_UNIX carrier; fd-passing/stream semantics are ad hoc. | Yes | Yes — wrong owner/type | Yes — raw control message constants | kernel/src/syscalls/net.rs:356-418 |
| 54 | setsockopt | V1 | Yes | Yes | Spec mismatch | Unsupported options are often ignored/smoothed over instead of matching Linux errors. | Yes | No | Yes — raw SOL_SOCKET/IPPROTO_TCP constants | kernel/src/syscalls/net.rs:733-799 |
| 55 | getsockopt | V1 | Yes | Yes | Spec mismatch | Unsupported options can return success with zeroed output. | Yes | No | Yes — raw option constants | kernel/src/syscalls/net.rs:808-864 |
| 56 | clone | V2 | Yes | Yes | Spec mismatch | Deep-copies CLONE_SIGHAND, ignores CLONE_FS, and has child-tid caveats. | Yes | Yes — too much work in shim | Yes — raw clone flag literals | kernel/src/syscalls/clone.rs:17-27,189-232 |
| 57 | fork | V2 | Yes | Yes | Spec mismatch | Implemented through clone dispatch despite docs marking it V2. | Yes — fork->clone shim | No | Yes — raw SIGCHLD literal | kernel/src/syscalls/mod.rs:864 |
| 58 | vfork | NEVER | Yes | Yes | Spec mismatch | Implemented through clone dispatch despite docs marking it NEVER. | Yes — vfork->clone shim | No | Yes — raw CLONE_VM\|CLONE_VFORK\|SIGCHLD literal | kernel/src/syscalls/mod.rs:865 |
| 59 | execve | V1 | Yes | Yes | Yes | Mostly works, but the shim still performs heavy ABI/state orchestration. | No | Yes — large Tier-3 orchestration | Yes — AT_EMPTY_PATH and frame layout constants | kernel/src/syscalls/execve.rs:11-260 |
| 60 | exit | V1 | Yes | Yes | Spec mismatch | exit_group is routed to sys_exit, so full thread-group exit semantics are wrong. | Yes — exit_group reuses sys_exit | No | Yes — direct status encoding | kernel/src/syscalls/mod.rs:294-368,892 |
| 61 | wait4 | V2 | Yes | Yes | Subset | Works, but child-stop/cleanup behavior is still ad hoc. | Yes | No | Yes — raw wait status/siginfo packing | kernel/src/syscalls/wait.rs:14-88 |
| 62 | kill | V1 | Yes | Yes | Yes | kill(-1, sig) returns EPERM instead of broadcasting. | Yes | No | Yes — raw signal/pid special cases | kernel/src/syscalls/signal.rs:134-185 |
| 63 | uname | V1 | Yes | Yes | Yes | Mostly synthetic fixed strings. | No | No | Yes — fixed string/version literals | kernel/src/syscalls/uname.rs:42-63 |
| 64 | semget | NEVER | Yes | Yes | Subset | Registry-backed SysV semaphores are simplified but mostly Linux-shaped. | No | No | Yes — raw cmd/flag values | crates/kernel/ipc/src/live/sysv_sem.rs:95-251 |
| 65 | semop | NEVER | Yes | Yes | Subset | Registry-backed SysV semaphores are simplified but mostly Linux-shaped. | No | No | Yes — raw cmd/flag values | crates/kernel/ipc/src/live/sysv_sem.rs:95-251 |
| 66 | semctl | NEVER | Yes | Yes | Spec mismatch | Uses raw cmd numbers and only a partial command set. | Yes | No | Yes — raw semctl command ids | crates/kernel/ipc/src/live/sysv_sem.rs:253-260 |
| 67 | shmdt | NEVER | Yes | Yes | No | SysV SHM uses registry/clone tricks, not real shared memory frames. | Yes | No | Yes — raw IPC commands/layout assumptions | crates/kernel/ipc/src/sysv_shm.rs:70-214 |
| 68 | msgget | NEVER | Yes | Yes | Subset | Registry-backed SysV queue; simplified but broadly Linux-shaped. | No | No | Yes — raw IPC flags | crates/kernel/ipc/src/live/sysv_msg.rs:95-112 |
| 69 | msgsnd | NEVER | Yes | Yes | Spec mismatch | Queue caps and blocking/type semantics are simplified. | No | No | Yes — raw queue limits/flags | crates/kernel/ipc/src/live/sysv_msg.rs:114-277 |
| 70 | msgrcv | NEVER | Yes | Yes | Spec mismatch | Queue caps and blocking/type semantics are simplified. | No | No | Yes — raw queue limits/flags | crates/kernel/ipc/src/live/sysv_msg.rs:114-277 |
| 71 | msgctl | NEVER | Yes | Yes | Spec mismatch | Many commands only validate and succeed without full effect. | Yes | No | Yes — raw cmd ids | crates/kernel/ipc/src/live/sysv_msg.rs:279-313 |
| 72 | fcntl | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:626 |
| 73 | flock | V1 | Yes | Yes | Subset | Blocking locks return EAGAIN instead of sleeping. | Yes — admit/no-wait behavior | No | Yes — raw LOCK_* bits | crates/kernel/fs/src/flock.rs:40-120 |
| 74 | fsync | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:783 |
| 75 | fdatasync | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:783 |
| 76 | truncate | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:757 |
| 77 | ftruncate | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:758 |
| 78 | getdents | NEVER | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it never. | No | No | No | kernel/src/syscalls/mod.rs:732 |
| 79 | getcwd | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:605 |
| 80 | chdir | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:606 |
| 81 | fchdir | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:607 |
| 82 | rename | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:754 |
| 83 | mkdir | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:749 |
| 84 | rmdir | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:751 |
| 85 | creat | NEVER | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it never. | No | No | No | kernel/src/syscalls/mod.rs:891 |
| 86 | link | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:827 |
| 87 | unlink | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:752 |
| 88 | symlink | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:829 |
| 89 | readlink | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:622 |
| 90 | chmod | V2 | Yes | Yes | Subset | Falls back to inode overlay metadata instead of persistent inode storage. | Yes — overlay metadata fallback | No | Yes — raw AT_EMPTY_PATH / AT_SYMLINK_NOFOLLOW | kernel/src/syscalls/perms.rs:59-139 |
| 91 | fchmod | V1 | Yes | Yes | Subset | Falls back to inode overlay metadata instead of persistent inode storage. | Yes — overlay metadata fallback | No | Yes — raw AT_EMPTY_PATH / AT_SYMLINK_NOFOLLOW | kernel/src/syscalls/perms.rs:59-139 |
| 92 | chown | V2 | Yes | Yes | Subset | Falls back to inode overlay metadata instead of persistent inode storage. | Yes — overlay metadata fallback | No | Yes — raw AT_EMPTY_PATH / AT_SYMLINK_NOFOLLOW | kernel/src/syscalls/perms.rs:59-139 |
| 93 | fchown | V1 | Yes | Yes | Subset | Falls back to inode overlay metadata instead of persistent inode storage. | Yes — overlay metadata fallback | No | Yes — raw AT_EMPTY_PATH / AT_SYMLINK_NOFOLLOW | kernel/src/syscalls/perms.rs:59-139 |
| 94 | lchown | V2 | Yes | Yes | Subset | Falls back to inode overlay metadata instead of persistent inode storage. | Yes — overlay metadata fallback | No | Yes — raw AT_EMPTY_PATH / AT_SYMLINK_NOFOLLOW | kernel/src/syscalls/perms.rs:59-139 |
| 95 | umask | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:727 |
| 96 | gettimeofday | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:587 |
| 97 | getrlimit | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:681 |
| 98 | getrusage | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:683 |
| 99 | sysinfo | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:685 |
| 100 | times | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:684 |
| 101 | ptrace | V1 | Yes | Yes | Subset | Many requests remain partial or silent-0; raw frame pokes back parts of the ABI. | Yes | Yes — large syscall-layer implementation | Yes — raw request/frame constants | kernel/src/syscalls/ptrace.rs:10-380 |
| 102 | getuid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:577 |
| 103 | syslog | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:903 |
| 104 | getgid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:579 |
| 105 | setuid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:583 |
| 106 | setgid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:584 |
| 107 | geteuid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:578 |
| 108 | getegid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:580 |
| 109 | setpgid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:725 |
| 110 | getppid | V1 | Yes | Yes | Yes | PID namespace behavior is synthetic via shadow fields. | No | No | Yes — raw namespace/visibility rules | kernel/src/syscalls/mod.rs:197-224 |
| 111 | getpgrp | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:691 |
| 112 | setsid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:726 |
| 113 | setreuid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:585 |
| 114 | setregid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:586 |
| 115 | getgroups | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:591 |
| 116 | setgroups | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:592 |
| 117 | setresuid | V1 | Yes | Yes | Subset | Uses u32::MAX as no-change sentinel and keeps heavy cred logic in dispatcher-owned code. | Yes | No | Yes — sentinel literal | crates/kernel/sched/src/cred.rs:15-17,155-208 |
| 118 | getresuid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:581 |
| 119 | setresgid | V1 | Yes | Yes | Subset | Uses u32::MAX as no-change sentinel and keeps heavy cred logic in dispatcher-owned code. | Yes | No | Yes — sentinel literal | crates/kernel/sched/src/cred.rs:15-17,155-208 |
| 120 | getresgid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:582 |
| 121 | getpgid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:723 |
| 122 | setfsuid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:589 |
| 123 | setfsgid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:590 |
| 124 | getsid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:724 |
| 125 | capget | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:593 |
| 126 | capset | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | crates/kernel/sched/src/cred.rs:594 |
| 127 | rt_sigpending | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:875 |
| 128 | rt_sigtimedwait | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:877 |
| 129 | rt_sigqueueinfo | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:878 |
| 130 | rt_sigsuspend | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:876 |
| 131 | sigaltstack | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:856 |
| 132 | utime | V2 | Yes | Yes | Subset | Timestamp updates fall back to inode overlay when inode storage is missing. | Yes — overlay metadata fallback | No | Yes — raw UTIME_/AT_* constants or layout assumptions | kernel/src/syscalls/utime.rs:10-12,76-180 |
| 133 | mknod | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:831 |
| 134 | uselib | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 135 | personality | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:813 |
| 136 | ustat | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 137 | statfs | V1 | Yes | Yes | Spec mismatch | Uses path-prefix magic table and synthetic usage tokens, not real fs accounting. | Yes — synthetic fs identity | Yes — fs identity in syscall layer | Yes — hardcoded fs magics | kernel/src/syscalls/statfs.rs:16-114 |
| 138 | fstatfs | V1 | Yes | Yes | Spec mismatch | Classifies filesystem by opened path string, not live superblock. | Yes — pathname heuristic | Yes — fs identity in syscall layer | Yes — hardcoded fs magics | kernel/src/syscalls/statfs.rs:116-137 |
| 139 | sysfs | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 140 | getpriority | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:692 |
| 141 | setpriority | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:693 |
| 142 | sched_setparam | V1 | Yes | No | No | Correctly numbered `NR_*`, but no live dispatcher/helper route. docs/15=V1. | No | No | No | crates/kernel/syscall/src/nrs.rs; absent from live dispatch matrix |
| 143 | sched_getparam | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:836 |
| 144 | sched_setscheduler | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:837 |
| 145 | sched_getscheduler | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:837 |
| 146 | sched_get_priority_max | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:839 |
| 147 | sched_get_priority_min | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:841 |
| 148 | sched_rr_get_interval | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:611 |
| 149 | mlock | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:689 |
| 150 | munlock | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:689 |
| 151 | mlockall | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:689 |
| 152 | munlockall | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:689 |
| 153 | vhangup | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:819 |
| 154 | modify_ldt | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 155 | pivot_root | V1 | Yes | Yes | Subset | Only rewrites synthetic registry paths; not full Linux pivot_root semantics. | Yes | Yes | Yes — raw path/cap handling | kernel/src/syscalls/mount.rs:96-119 |
| 156 | _sysctl | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 157 | prctl | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:847 |
| 158 | arch_prctl | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:583 |
| 159 | adjtimex | V2 | Yes | Yes | No | Compat tail hard-refuses with EPERM instead of real implementation. | Yes | Yes | No | crates/kernel/sched/src/compat.rs:70-83 |
| 160 | setrlimit | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:682 |
| 161 | chroot | V1 | Yes | Yes | No | Mutates a task root prefix instead of real VFS root semantics. | Yes | Yes | No | kernel/src/syscalls/chroot.rs:1-41 |
| 162 | sync | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:781 |
| 163 | acct | V2 | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 164 | settimeofday | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:588 |
| 165 | mount | V2 | Yes | Yes | Subset | Compat/new-mount path rides synthetic/global mount substrate, not full Linux mount namespaces. | Yes | Yes | Yes — raw mount flags/fstype handling | kernel/src/syscalls/mount.rs:132-260; kernel/src/syscalls/fsmount.rs:120-305 |
| 166 | umount2 | V1 | Yes | Yes | Subset | Runs on the same synthetic/global mount substrate. | Yes | Yes | Yes — raw flags | kernel/src/syscalls/mount.rs:132-260 |
| 167 | swapon | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 168 | swapoff | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 169 | reboot | V1 | Yes | Yes | Subset | Uses hardcoded Linux magic constants and platform-specific reset shortcuts. | Yes | No | Yes — raw reboot magics | kernel/src/syscalls/misc.rs:263-285; crates/kernel/power/src/lib.rs:33-170 |
| 170 | sethostname | V1 | Yes | Yes | Subset | Global hostname/domain buffers, not a full Linux UTS namespace model. | No | Yes | No | kernel/src/syscalls/hostname.rs:1-95 |
| 171 | setdomainname | V1 | Yes | Yes | Subset | Global hostname/domain buffers, not a full Linux UTS namespace model. | No | Yes | No | kernel/src/syscalls/hostname.rs:1-95 |
| 172 | iopl | NEVER | Yes | Yes | No | Compat tail hard-refuses with EPERM instead of real implementation. | Yes | Yes | No | crates/kernel/sched/src/compat.rs:70-83 |
| 173 | ioperm | NEVER | Yes | Yes | No | Compat tail hard-refuses with EPERM instead of real implementation. | Yes | Yes | No | crates/kernel/sched/src/compat.rs:70-83 |
| 174 | create_module | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:174; no repo constant |
| 175 | init_module | NEVER | Yes | Yes | No | Module load/unload is index/blob-based and lacks Linux verification/name semantics. | Yes | Yes | Yes — raw module size/index encoding | kernel/src/syscalls/mod.rs:232-291; crates/kernel/modules/src/registry.rs:33-76 |
| 176 | delete_module | V1 | Yes | Yes | No | Module load/unload is index/blob-based and lacks Linux verification/name semantics. | Yes | Yes | Yes — raw module size/index encoding | kernel/src/syscalls/mod.rs:232-291; crates/kernel/modules/src/registry.rs:33-76 |
| 177 | get_kernel_syms | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:177; no repo constant |
| 178 | query_module | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:178; no repo constant |
| 179 | quotactl | V2 | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 180 | nfsservctl | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:180; no repo constant |
| 181 | getpmsg | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:181; no repo constant |
| 182 | putpmsg | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:182; no repo constant |
| 183 | afs_syscall | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:183; no repo constant |
| 184 | tuxcall | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:184; no repo constant |
| 185 | security | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:185; no repo constant |
| 186 | gettid | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:613 |
| 187 | readahead | V1 | Yes | Yes | Spec mismatch | Validate-then-0 compat tail, not the full behavior docs/15 suggests. | Yes | Yes — lives in compat tail | No | crates/kernel/sched/src/compat.rs:36-37,164-182 |
| 188 | setxattr | V1 | Yes | Yes | Subset | Xattrs live in an in-memory overlay; no on-disk persistence. | Yes — overlay-only storage | Maybe | Yes — raw xattr command/value literals | crates/kernel/fs/src/xattr.rs:1-240 |
| 189 | lsetxattr | V1 | Yes | Yes | Subset | Xattrs live in an in-memory overlay; no on-disk persistence. | Yes — overlay-only storage | Maybe | Yes — raw xattr command/value literals | crates/kernel/fs/src/xattr.rs:1-240 |
| 190 | fsetxattr | V1 | Yes | Yes | Subset | Xattrs live in an in-memory overlay; no on-disk persistence. | Yes — overlay-only storage | Maybe | Yes — raw xattr command/value literals | crates/kernel/fs/src/xattr.rs:1-240 |
| 191 | getxattr | V1 | Yes | Yes | Subset | Xattrs live in an in-memory overlay; no on-disk persistence. | Yes — overlay-only storage | Maybe | Yes — raw xattr command/value literals | crates/kernel/fs/src/xattr.rs:1-240 |
| 192 | lgetxattr | V1 | Yes | Yes | Subset | Xattrs live in an in-memory overlay; no on-disk persistence. | Yes — overlay-only storage | Maybe | Yes — raw xattr command/value literals | crates/kernel/fs/src/xattr.rs:1-240 |
| 193 | fgetxattr | V1 | Yes | Yes | Subset | Xattrs live in an in-memory overlay; no on-disk persistence. | Yes — overlay-only storage | Maybe | Yes — raw xattr command/value literals | crates/kernel/fs/src/xattr.rs:1-240 |
| 194 | listxattr | V1 | Yes | Yes | Subset | Xattrs live in an in-memory overlay; no on-disk persistence. | Yes — overlay-only storage | Maybe | Yes — raw xattr command/value literals | crates/kernel/fs/src/xattr.rs:1-240 |
| 195 | llistxattr | V1 | Yes | Yes | Subset | Xattrs live in an in-memory overlay; no on-disk persistence. | Yes — overlay-only storage | Maybe | Yes — raw xattr command/value literals | crates/kernel/fs/src/xattr.rs:1-240 |
| 196 | flistxattr | V1 | Yes | Yes | Subset | Xattrs live in an in-memory overlay; no on-disk persistence. | Yes — overlay-only storage | Maybe | Yes — raw xattr command/value literals | crates/kernel/fs/src/xattr.rs:1-240 |
| 197 | removexattr | V1 | Yes | Yes | Subset | Xattrs live in an in-memory overlay; no on-disk persistence. | Yes — overlay-only storage | Maybe | Yes — raw xattr command/value literals | crates/kernel/fs/src/xattr.rs:1-240 |
| 198 | lremovexattr | V1 | Yes | Yes | Subset | Xattrs live in an in-memory overlay; no on-disk persistence. | Yes — overlay-only storage | Maybe | Yes — raw xattr command/value literals | crates/kernel/fs/src/xattr.rs:1-240 |
| 199 | fremovexattr | V1 | Yes | Yes | Subset | Xattrs live in an in-memory overlay; no on-disk persistence. | Yes — overlay-only storage | Maybe | Yes — raw xattr command/value literals | crates/kernel/fs/src/xattr.rs:1-240 |
| 200 | tkill | V2 | Yes | Yes | Spec mismatch | Mapped to sys_kill, so tid-only semantics are lost. | Yes — tkill->kill alias | No | No | kernel/src/syscalls/mod.rs:874; kernel/src/syscalls/signal.rs:141-185 |
| 201 | time | NEVER | Yes | Yes | Spec mismatch | Live-mapped even though docs mark it NEVER. | Yes — legacy syscall kept live | No | No | kernel/src/syscalls/time.rs:171-182 |
| 202 | futex | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:848 |
| 203 | sched_setaffinity | V1 | Yes | Yes | Yes | Truncates affinity to one u64 mask. | No | No | Yes — one-word mask assumption | kernel/src/syscalls/affinity.rs:19-60 |
| 204 | sched_getaffinity | V1 | Yes | Yes | Yes | Truncates affinity to one u64 mask. | No | No | Yes — one-word mask assumption | kernel/src/syscalls/affinity.rs:19-60 |
| 205 | set_thread_area | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:205; no repo constant |
| 206 | io_setup | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 207 | io_destroy | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 208 | io_getevents | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 209 | io_submit | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 210 | io_cancel | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 211 | get_thread_area | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:211; no repo constant |
| 212 | lookup_dcookie | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 213 | epoll_create | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:716 |
| 214 | epoll_ctl_old | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:214; no repo constant |
| 215 | epoll_wait_old | NEVER | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=NEVER. | No | No | N/A | Linux syscall_64.tbl:215; no repo constant |
| 216 | remap_file_pages | V2 | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 217 | getdents64 | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:732 |
| 218 | set_tid_address | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:614 |
| 219 | restart_syscall | V1 | Yes | Yes | Spec mismatch | Hardcoded -EINTR, not real restart semantics. | Yes | Yes | No | crates/kernel/sched/src/compat.rs:39-40 |
| 220 | semtimedop | NEVER | Yes | Yes | No | Timeout is ignored and it aliases semop behavior. | Yes | No | No | crates/kernel/ipc/src/live/sysv_sem.rs:1-17 |
| 221 | fadvise64 | V1 | Yes | Yes | Spec mismatch | Validate-then-0 compat tail, not the full behavior docs/15 suggests. | Yes | Yes — lives in compat tail | No | crates/kernel/sched/src/compat.rs:36-37,164-182 |
| 222 | timer_create | V1 | Yes | Yes | Subset | SIGEV_THREAD/THREAD_ID collapse to signal mode; timer semantics are simplified. | Yes | No | Yes — raw SIGEV/sentinel constants | crates/kernel/sched/src/timers.rs:21-247 |
| 223 | timer_settime | V1 | Yes | Yes | Subset | SIGEV_THREAD/THREAD_ID collapse to signal mode; timer semantics are simplified. | Yes | No | Yes — raw SIGEV/sentinel constants | crates/kernel/sched/src/timers.rs:21-247 |
| 224 | timer_gettime | V1 | Yes | Yes | Subset | SIGEV_THREAD/THREAD_ID collapse to signal mode; timer semantics are simplified. | Yes | No | Yes — raw SIGEV/sentinel constants | crates/kernel/sched/src/timers.rs:21-247 |
| 225 | timer_getoverrun | V1 | Yes | Yes | Subset | SIGEV_THREAD/THREAD_ID collapse to signal mode; timer semantics are simplified. | Yes | No | Yes — raw SIGEV/sentinel constants | crates/kernel/sched/src/timers.rs:21-247 |
| 226 | timer_delete | V1 | Yes | Yes | Subset | SIGEV_THREAD/THREAD_ID collapse to signal mode; timer semantics are simplified. | Yes | No | Yes — raw SIGEV/sentinel constants | crates/kernel/sched/src/timers.rs:21-247 |
| 227 | clock_settime | V1 | Yes | Yes | Yes | Only CLOCK_REALTIME is really honored; other clocks silently succeed. | No | No | Yes — raw clock ids | kernel/src/syscalls/time.rs:115-134 |
| 228 | clock_gettime | V1 | Yes | Yes | Yes | clock_id handling is narrow; non-REALTIME cases collapse to monotonic behavior. | No | No | Yes — raw clock ids/layout | kernel/src/syscalls/time.rs:62-97 |
| 229 | clock_getres | V1 | Yes | Yes | Yes | Ignores clock_id and always reports 1ns. | No | No | Yes — hardcoded 1ns | kernel/src/syscalls/time.rs:99-113 |
| 230 | clock_nanosleep | V1 | Yes | Yes | Yes | Ignores rem and narrows clock handling. | No | No | Yes — raw clock ids/flags | kernel/src/syscalls/clock_nanosleep.rs:9-47 |
| 231 | exit_group | V1 | Yes | Yes | Spec mismatch | exit_group is routed to sys_exit, so full thread-group exit semantics are wrong. | Yes — exit_group reuses sys_exit | No | Yes — direct status encoding | kernel/src/syscalls/mod.rs:294-368,892 |
| 232 | epoll_wait | V2 | Yes | Yes | Subset | Uses readiness scans over inode.poll(), not full kernel poll-table semantics. | Yes — readiness-scan shim | No | Yes — raw EPOLL_* / interval literals | crates/kernel/fs/src/epoll.rs:133-370 |
| 233 | epoll_ctl | V1 | Yes | Yes | Subset | Uses readiness scans over inode.poll(), not full kernel poll-table semantics. | Yes — readiness-scan shim | No | Yes — raw EPOLL_* / interval literals | crates/kernel/fs/src/epoll.rs:133-370 |
| 234 | tgkill | V1 | Yes | Yes | Subset | Mostly works, but delivery is still bitmap-based, not full Linux stop/job-control semantics. | Yes | No | Yes — raw signal bits | kernel/src/syscalls/signal.rs:598-634 |
| 235 | utimes | V2 | Yes | Yes | Subset | Timestamp updates fall back to inode overlay when inode storage is missing. | Yes — overlay metadata fallback | No | Yes — raw UTIME_/AT_* constants or layout assumptions | kernel/src/syscalls/utime.rs:10-12,76-180 |
| 236 | vserver | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 237 | mbind | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:786 |
| 238 | set_mempolicy | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:786 |
| 239 | get_mempolicy | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:786 |
| 240 | mq_open | V2 | Yes | Yes | Subset | Registry-backed POSIX mqueue implementation is simplified. | No | No | Yes — raw attr/flag values | crates/kernel/ipc/src/live/posix_mq.rs:139-213 |
| 241 | mq_unlink | V2 | Yes | Yes | Subset | Registry-backed POSIX mqueue implementation is simplified. | No | No | Yes — raw attr/flag values | crates/kernel/ipc/src/live/posix_mq.rs:139-213 |
| 242 | mq_timedsend | V2 | Yes | Yes | Spec mismatch | Absolute timeout is ignored. | Yes | No | Yes — raw mq_attr/timeout handling | crates/kernel/ipc/src/live/posix_mq.rs:226-357 |
| 243 | mq_timedreceive | V2 | Yes | Yes | Spec mismatch | Absolute timeout is ignored. | Yes | No | Yes — raw mq_attr/timeout handling | crates/kernel/ipc/src/live/posix_mq.rs:226-357 |
| 244 | mq_notify | V2 | Yes | Yes | Spec mismatch | Single-notifier registry and non-Linux SIGEV behavior. | Yes | No | Yes — raw sigevent offsets/constants | crates/kernel/ipc/src/live/posix_mq.rs:359-400 |
| 245 | mq_getsetattr | V2 | Yes | Yes | Spec mismatch | Only O_NONBLOCK is honored; other attrs are effectively ignored. | Yes | No | Yes — raw attr bits | crates/kernel/ipc/src/live/posix_mq.rs:402-460 |
| 246 | kexec_load | V2 | Yes | Yes | No | Compat tail hard-refuses with EPERM instead of real implementation. | Yes | Yes | No | crates/kernel/sched/src/compat.rs:70-83 |
| 247 | waitid | V1 | Yes | Yes | Subset | P_PIDFD is treated as PID and siginfo packing is partial. | Yes | No | Yes — raw siginfo/status packing | kernel/src/syscalls/waitid.rs:23-97 |
| 248 | add_key | V2 | Yes | Yes | Subset | Single global key store; partial keyctl semantics and synthetic ids. | Yes — global synthetic keyring | Yes — keyring logic behind fs dispatch helper | Yes — sentinel keyring id | crates/kernel/fs/src/keyring.rs:7-198 |
| 249 | request_key | V2 | Yes | Yes | Subset | Single global key store; partial keyctl semantics and synthetic ids. | Yes — global synthetic keyring | Yes — keyring logic behind fs dispatch helper | Yes — sentinel keyring id | crates/kernel/fs/src/keyring.rs:7-198 |
| 250 | keyctl | V2 | Yes | Yes | Subset | Single global key store; partial keyctl semantics and synthetic ids. | Yes — global synthetic keyring | Yes — keyring logic behind fs dispatch helper | Yes — sentinel keyring id | crates/kernel/fs/src/keyring.rs:7-198 |
| 251 | ioprio_set | V2 | Yes | No | No | Correctly numbered `NR_*`, but no live dispatcher/helper route. docs/15=V2. | No | No | No | crates/kernel/syscall/src/nrs.rs; absent from live dispatch matrix |
| 252 | ioprio_get | V2 | Yes | No | No | Correctly numbered `NR_*`, but no live dispatcher/helper route. docs/15=V2. | No | No | No | crates/kernel/syscall/src/nrs.rs; absent from live dispatch matrix |
| 253 | inotify_init | V2 | Yes | Yes | Subset | Partial event model; watch substrate is inode-pointer keyed. | Yes — partial event shim | No | Yes — raw IN_* masks | crates/kernel/fs/src/inotify.rs:219-329 |
| 254 | inotify_add_watch | V1 | Yes | Yes | Subset | Partial event model; watch substrate is inode-pointer keyed. | Yes — partial event shim | No | Yes — raw IN_* masks | crates/kernel/fs/src/inotify.rs:219-329 |
| 255 | inotify_rm_watch | V1 | Yes | Yes | Subset | Partial event model; watch substrate is inode-pointer keyed. | Yes — partial event shim | No | Yes — raw IN_* masks | crates/kernel/fs/src/inotify.rs:219-329 |
| 256 | migrate_pages | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:786 |
| 257 | openat | V1 | Yes | Yes | Subset | Dirfd open mostly works, but still uses special-case lexical/path shims. | Yes — fd-link/path shim | No | Yes — raw O_* literals | kernel/src/syscalls/open.rs:188-305 |
| 258 | mkdirat | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:750 |
| 259 | mknodat | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:832 |
| 260 | fchownat | V1 | Yes | Yes | Subset | Falls back to inode overlay metadata instead of persistent inode storage. | Yes — overlay metadata fallback | No | Yes — raw AT_EMPTY_PATH / AT_SYMLINK_NOFOLLOW | kernel/src/syscalls/perms.rs:59-139 |
| 261 | futimesat | NEVER | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it never. | No | No | No | kernel/src/syscalls/mod.rs:820 |
| 262 | newfstatat | V1 | Yes | Yes | Subset | Works, but mixes path-walk and inode overlay fallbacks. | Yes — overlay metadata fallback | No | Yes — raw AT_* flags | kernel/src/syscalls/newfstatat.rs:13-129 |
| 263 | unlinkat | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:753 |
| 264 | renameat | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:755 |
| 265 | linkat | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:828 |
| 266 | symlinkat | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:830 |
| 267 | readlinkat | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:623 |
| 268 | fchmodat | V2 | Yes | Yes | Subset | Falls back to inode overlay metadata instead of persistent inode storage. | Yes — overlay metadata fallback | No | Yes — raw AT_EMPTY_PATH / AT_SYMLINK_NOFOLLOW | kernel/src/syscalls/perms.rs:59-139 |
| 269 | faccessat | V2 | Yes | Yes | No | Only checks existence; ignores real permission/mode semantics. | Yes — existence-only shim | No | Yes — raw AT_FDCWD sentinel | kernel/src/syscalls/fs.rs:679-724 |
| 270 | pselect6 | NEVER | Yes | Yes | Spec mismatch | Best-effort wrapper over select; simplified mask/timeout handling. | Yes — wrapper shim | No | Yes — raw mask-size/bit literals | kernel/src/syscalls/select.rs:168-275 |
| 271 | ppoll | V1 | Yes | Yes | Spec mismatch | Best-effort wrapper over poll; simplified sigmask handling. | Yes — wrapper shim | No | Yes — raw sigset-size literal | kernel/src/syscalls/poll.rs:125-168 |
| 272 | unshare | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:629 |
| 273 | set_robust_list | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:901 |
| 274 | get_robust_list | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:902 |
| 275 | splice | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:762 |
| 276 | tee | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:763 |
| 277 | sync_file_range | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:783 |
| 278 | vmsplice | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:764 |
| 279 | move_pages | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:786 |
| 280 | utimensat | V1 | Yes | Yes | Subset | Timestamp updates fall back to inode overlay when inode storage is missing. | Yes — overlay metadata fallback | No | Yes — raw UTIME_/AT_* constants or layout assumptions | kernel/src/syscalls/utime.rs:10-12,76-180 |
| 281 | epoll_pwait | V1 | Yes | Yes | Subset | Uses readiness scans over inode.poll(), not full kernel poll-table semantics. | Yes — readiness-scan shim | No | Yes — raw EPOLL_* / interval literals | crates/kernel/fs/src/epoll.rs:133-370 |
| 282 | signalfd | V2 | Yes | Yes | Subset | Only narrow mask/update semantics are supported. | Yes — update-only shim | No | Yes — raw mask-size / SFD_* literals | crates/kernel/fs/src/signalfd.rs:63-116 |
| 283 | timerfd_create | V1 | Yes | Yes | Subset | Functional but simplified validation/clock coverage. | No | No | Yes — raw TFD_* and layout assumptions | crates/kernel/fs/src/timerfd.rs:109-231 |
| 284 | eventfd | V2 | Yes | Yes | Subset | Semaphore mode is only partially honored. | Yes — partial mode support | No | Yes — raw EFD_* bits | kernel/src/syscalls/anonfd.rs:12-40 |
| 285 | fallocate | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:759 |
| 286 | timerfd_settime | V1 | Yes | Yes | Subset | Functional but simplified validation/clock coverage. | No | No | Yes — raw TFD_* and layout assumptions | crates/kernel/fs/src/timerfd.rs:109-231 |
| 287 | timerfd_gettime | V1 | Yes | Yes | Subset | Functional but simplified validation/clock coverage. | No | No | Yes — raw TFD_* and layout assumptions | crates/kernel/fs/src/timerfd.rs:109-231 |
| 288 | accept4 | V1 | Yes | Yes | Subset | Blocking and flag handling are custom; accept4 shares accept path. | No | No | Yes — raw SOCK_* bits | kernel/src/syscalls/net.rs:437-511 |
| 289 | signalfd4 | V1 | Yes | Yes | Subset | Only narrow mask/update semantics are supported. | Yes — update-only shim | No | Yes — raw mask-size / SFD_* literals | crates/kernel/fs/src/signalfd.rs:63-116 |
| 290 | eventfd2 | V1 | Yes | Yes | Subset | Semaphore mode is only partially honored. | Yes — partial mode support | No | Yes — raw EFD_* bits | kernel/src/syscalls/anonfd.rs:12-40 |
| 291 | epoll_create1 | V1 | Yes | Yes | Subset | Uses readiness scans over inode.poll(), not full kernel poll-table semantics. | Yes — readiness-scan shim | No | Yes — raw EPOLL_* / interval literals | crates/kernel/fs/src/epoll.rs:133-370 |
| 292 | dup3 | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:863 |
| 293 | pipe2 | V1 | Yes | Yes | Subset | Creates pipe inode directly and writes fd pair to user memory from shim. | Yes — direct user write / synthetic inode | No | Yes — raw flags / pointer arithmetic | kernel/src/syscalls/mod.rs:97-146,881-890 |
| 294 | inotify_init1 | V1 | Yes | Yes | Subset | Partial event model; watch substrate is inode-pointer keyed. | Yes — partial event shim | No | Yes — raw IN_* masks | crates/kernel/fs/src/inotify.rs:219-329 |
| 295 | preadv | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:736 |
| 296 | pwritev | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:737 |
| 297 | rt_tgsigqueueinfo | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:879 |
| 298 | perf_event_open | V2 | Yes | Yes | Spec mismatch | Returns synthetic monotonic samples, not real PMU-backed events. | Yes — synthetic perf fd | No | Yes — raw PERF_EVENT_IOC_* values | crates/kernel/fs/src/perf.rs:99-140 |
| 299 | recvmmsg | V1 | Yes | Yes | No | Timeout is ignored. | Yes | No | Yes — raw timeout/stride handling | kernel/src/syscalls/mmsg.rs:45-74 |
| 300 | fanotify_init | V2 | Yes | Yes | No | Fanotify is routed through inotify substrate, not real fanotify semantics. | Yes — fanotify->inotify shim | Yes — wrong owner/substrate | Yes — raw FAN_* / IN_* masks | crates/kernel/fs/src/inotify.rs:335-403 |
| 301 | fanotify_mark | V2 | Yes | Yes | No | Fanotify is routed through inotify substrate, not real fanotify semantics. | Yes — fanotify->inotify shim | Yes — wrong owner/substrate | Yes — raw FAN_* / IN_* masks | crates/kernel/fs/src/inotify.rs:335-403 |
| 302 | prlimit64 | V1 | Yes | Yes | Subset | Only some limits are enforced; others are mostly stored and reported. | Yes — partial enforcement | No | No | kernel/src/syscalls/proc.rs:202-246 |
| 303 | name_to_handle_at | V2 | Yes | Yes | Spec mismatch | Returns inode-number pseudo handles, not real export handles. | Yes — inode-number handle shim | Yes — handle ABI in syscall layer | Yes — raw AT_* and FID size constants | kernel/src/syscalls/handle.rs:28-120 |
| 304 | open_by_handle_at | V2 | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 305 | clock_adjtime | V2 | Yes | Yes | No | Compat tail hard-refuses with EPERM instead of real implementation. | Yes | Yes | No | crates/kernel/sched/src/compat.rs:70-83 |
| 306 | syncfs | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:783 |
| 307 | sendmmsg | V1 | Yes | Yes | Spec mismatch | Iterates sendmsg with hardcoded mmsghdr handling. | No | No | Yes — raw stride/caps | kernel/src/syscalls/mmsg.rs:14-43 |
| 308 | setns | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:630 |
| 309 | getcpu | V1 | Yes | Yes | Subset | Hardcoded single-CPU/NUMA-0 answer. | Yes | No | No | kernel/src/syscalls/proc.rs:737-751 |
| 310 | process_vm_readv | V1 | Yes | Yes | Yes | Only flags==0 path is supported. | No | No | Yes — raw iovec/flag checks | kernel/src/syscalls/pvmrw.rs:43-137 |
| 311 | process_vm_writev | V1 | Yes | Yes | Yes | Only flags==0 path is supported. | No | No | Yes — raw iovec/flag checks | kernel/src/syscalls/pvmrw.rs:43-137 |
| 312 | kcmp | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:786 |
| 313 | finit_module | V1 | Yes | Yes | No | Module load/unload is index/blob-based and lacks Linux verification/name semantics. | Yes | Yes | Yes — raw module size/index encoding | kernel/src/syscalls/mod.rs:232-291; crates/kernel/modules/src/registry.rs:33-76 |
| 314 | sched_setattr | V1 | Yes | No | No | Correctly numbered `NR_*`, but no live dispatcher/helper route. docs/15=V1. | No | No | No | crates/kernel/syscall/src/nrs.rs; absent from live dispatch matrix |
| 315 | sched_getattr | V1 | Yes | No | No | Correctly numbered `NR_*`, but no live dispatcher/helper route. docs/15=V1. | No | No | No | crates/kernel/syscall/src/nrs.rs; absent from live dispatch matrix |
| 316 | renameat2 | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:756 |
| 317 | seccomp | V1 | Yes | Yes | Subset | cBPF filter path is narrow; several actions collapse to EPERM/allow behavior. | Yes | Yes | Yes — raw seccomp action constants | crates/kernel/security/src/seccomp.rs:311-389 |
| 318 | getrandom | V1 | Yes | Yes | Subset | Falls back to a per-boot LCG when hardware RNG is unavailable. | Yes | Yes | No | kernel/src/syscalls/hwrng.rs:34-73; kernel/src/syscalls/mod.rs:371-394 |
| 319 | memfd_create | V1 | Yes | Yes | Subset | Tmpfs-backed anon inode; not full memfd feature set. | Yes — anon-inode shim | No | Yes — raw MFD_* bits | kernel/src/syscalls/anonfd.rs:43-86 |
| 320 | kexec_file_load | V2 | Yes | Yes | No | Compat tail hard-refuses with EPERM instead of real implementation. | Yes | Yes | No | crates/kernel/sched/src/compat.rs:70-83 |
| 321 | bpf | V2 | Yes | Yes | No | Only a narrow fd-creating/map subset exists; no real verifier/JIT execution model. | Yes | Yes | Yes — raw BPF cmd constants | crates/kernel/security/src/bpf.rs:63-91 |
| 322 | execveat | V1 | Yes | Yes | Yes | Mostly works, but the shim still performs heavy ABI/state orchestration. | No | Yes — large Tier-3 orchestration | Yes — AT_EMPTY_PATH and frame layout constants | kernel/src/syscalls/execve.rs:11-260 |
| 323 | userfaultfd | V1 | Yes | Yes | Spec mismatch | FD exists, but page-fault interception is incomplete; empty reads return 0. | Yes — admit-but-not-real fault handling | No | Yes — raw UFFD ioctl/event numbers | crates/kernel/fs/src/userfaultfd.rs:12-31,159-292 |
| 324 | membarrier | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:628 |
| 325 | mlock2 | V1 | Yes | Yes | Spec mismatch | Validate-then-0 compat tail, not the full behavior docs/15 suggests. | Yes | Yes — lives in compat tail | No | crates/kernel/sched/src/compat.rs:36-37,164-182 |
| 326 | copy_file_range | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:761 |
| 327 | preadv2 | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:738 |
| 328 | pwritev2 | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:739 |
| 329 | pkey_mprotect | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:786 |
| 330 | pkey_alloc | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:786 |
| 331 | pkey_free | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:786 |
| 332 | statx | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:624 |
| 333 | io_pgetevents | NEVER | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 334 | rseq | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:627 |
| 335 | uretprobe | — | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. | No | No | N/A | Linux syscall_64.tbl:335; no repo constant |
| 336 | uprobe | — | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. | No | No | N/A | Linux syscall_64.tbl:336; no repo constant |
| 424 | pidfd_send_signal | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:700 |
| 425 | io_uring_setup | V2 | Yes | Yes | No | io_uring is synchronous/partial; register is silent-0 no-op. | Yes | No | Yes — raw ring/opcode constants | kernel/src/io_uring.rs:10-280 |
| 426 | io_uring_enter | V2 | Yes | Yes | No | io_uring is synchronous/partial; register is silent-0 no-op. | Yes | No | Yes — raw ring/opcode constants | kernel/src/io_uring.rs:10-280 |
| 427 | io_uring_register | V2 | Yes | Yes | No | io_uring is synchronous/partial; register is silent-0 no-op. | Yes | No | Yes — raw ring/opcode constants | kernel/src/io_uring.rs:10-280 |
| 428 | open_tree | V1 | Yes | Yes | Subset | New mount API returns fake context/mount fds and only narrow semantics are real. | Yes | Yes | Yes — raw mount/open_tree constants | kernel/src/syscalls/fsmount.rs:21-305 |
| 429 | move_mount | V1 | Yes | Yes | Subset | New mount API returns fake context/mount fds and only narrow semantics are real. | Yes | Yes | Yes — raw mount/open_tree constants | kernel/src/syscalls/fsmount.rs:21-305 |
| 430 | fsopen | V1 | Yes | Yes | Subset | New mount API returns fake context/mount fds and only narrow semantics are real. | Yes | Yes | Yes — raw mount/open_tree constants | kernel/src/syscalls/fsmount.rs:21-305 |
| 431 | fsconfig | V1 | Yes | Yes | Subset | New mount API returns fake context/mount fds and only narrow semantics are real. | Yes | Yes | Yes — raw mount/open_tree constants | kernel/src/syscalls/fsmount.rs:21-305 |
| 432 | fsmount | V1 | Yes | Yes | Subset | New mount API returns fake context/mount fds and only narrow semantics are real. | Yes | Yes | Yes — raw mount/open_tree constants | kernel/src/syscalls/fsmount.rs:21-305 |
| 433 | fspick | V1 | Yes | Yes | Subset | New mount API returns fake context/mount fds and only narrow semantics are real. | Yes | Yes | Yes — raw mount/open_tree constants | kernel/src/syscalls/fsmount.rs:21-305 |
| 434 | pidfd_open | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:698 |
| 435 | clone3 | V1 | Yes | Yes | Subset | Modern clone path exists, but shares clone implementation limits. | Yes — clone3 over existing clone substrate | Yes — heavy Tier-3 work | No | kernel/src/syscalls/mod.rs:850; kernel/src/syscalls/clone.rs:17-232 |
| 436 | close_range | V1 | Yes | Yes | Subset | CLOSE_RANGE_UNSHARE is accepted as a no-op. | Yes — flag admit | No | Yes — raw CLOEXEC bit literal | kernel/src/syscalls/fs.rs:646-676 |
| 437 | openat2 | V1 | Yes | Yes | No | Ignores resolve fields; just copies flags/mode then calls openat. | Yes — openat2->openat shim | Yes — ABI handling stays in shim | Yes — raw struct offsets 0/8 | kernel/src/syscalls/mod.rs:766-779 |
| 438 | pidfd_getfd | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:699 |
| 439 | faccessat2 | V1 | Yes | Yes | No | Only checks existence; ignores real permission/mode semantics. | Yes — existence-only shim | No | Yes — raw AT_FDCWD sentinel | kernel/src/syscalls/fs.rs:679-724 |
| 440 | process_madvise | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:786 |
| 441 | epoll_pwait2 | V1 | Yes | Yes | Subset | Uses readiness scans over inode.poll(), not full kernel poll-table semantics. | Yes — readiness-scan shim | No | Yes — raw EPOLL_* / interval literals | crates/kernel/fs/src/epoll.rs:133-370 |
| 442 | mount_setattr | V1 | Yes | Yes | Subset | New mount API returns fake context/mount fds and only narrow semantics are real. | Yes | Yes | Yes — raw mount/open_tree constants | kernel/src/syscalls/fsmount.rs:21-305 |
| 443 | quotactl_fd | V2 | Yes | No | No | Correctly reserved/unimplemented in policy, but absent from live implementation and/or forced through compat ENOSYS. | No | Yes — compat tail owns policy | No | crates/kernel/sched/src/compat.rs:97-158 |
| 444 | landlock_create_ruleset | V2 | Yes | Yes | Subset | Landlock is fd/registry-based with partial rule/enforcement semantics. | Yes | Yes | Yes — raw ABI version and rule constants | kernel/src/syscalls/landlock.rs:38-155 |
| 445 | landlock_add_rule | V2 | Yes | Yes | Subset | Landlock is fd/registry-based with partial rule/enforcement semantics. | Yes | Yes | Yes — raw ABI version and rule constants | kernel/src/syscalls/landlock.rs:38-155 |
| 446 | landlock_restrict_self | V2 | Yes | Yes | Subset | Landlock is fd/registry-based with partial rule/enforcement semantics. | Yes | Yes | Yes — raw ABI version and rule constants | kernel/src/syscalls/landlock.rs:38-155 |
| 447 | memfd_secret | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:745 |
| 448 | process_mrelease | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:786 |
| 449 | futex_waitv | V1 | Yes | Yes | Yes | No material issue found in this pass. | No | No | No | kernel/src/syscalls/mod.rs:849 |
| 450 | set_mempolicy_home_node | V2 | Yes | Yes | Spec mismatch | Live-mapped even though docs/15 marks it v2. | No | No | No | kernel/src/syscalls/mod.rs:786 |
| 451 | cachestat | V1 | Yes | No | Spec mismatch | Silent-0 compat admit even though docs mark it V1. | Yes | Yes | Yes — cached-stat ABI is stubbed | crates/kernel/sched/src/compat.rs:42-66 |
| 452 | fchmodat2 | V1 | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=V1. | No | No | N/A | Linux syscall_64.tbl:452; no repo constant |
| 453 | map_shadow_stack | V2 | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=V2. | No | No | N/A | Linux syscall_64.tbl:453; no repo constant |
| 454 | futex_wake | V1 | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=V1. | No | No | N/A | Linux syscall_64.tbl:454; no repo constant |
| 455 | futex_wait | V1 | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=V1. | No | No | N/A | Linux syscall_64.tbl:455; no repo constant |
| 456 | futex_requeue | V1 | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=V1. | No | No | N/A | Linux syscall_64.tbl:456; no repo constant |
| 457 | statmount | V1 | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=V1. | No | No | N/A | Linux syscall_64.tbl:457; no repo constant |
| 458 | listmount | V1 | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=V1. | No | No | N/A | Linux syscall_64.tbl:458; no repo constant |
| 459 | lsm_get_self_attr | V2 | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=V2. | No | No | N/A | Linux syscall_64.tbl:459; no repo constant |
| 460 | lsm_set_self_attr | V2 | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=V2. | No | No | N/A | Linux syscall_64.tbl:460; no repo constant |
| 461 | lsm_list_modules | V2 | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. docs/15=V2. | No | No | N/A | Linux syscall_64.tbl:461; no repo constant |
| 462 | mseal | — | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. | No | No | N/A | Linux syscall_64.tbl:462; no repo constant |
| 463 | setxattrat | — | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. | No | No | N/A | Linux syscall_64.tbl:463; no repo constant |
| 464 | getxattrat | — | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. | No | No | N/A | Linux syscall_64.tbl:464; no repo constant |
| 465 | listxattrat | — | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. | No | No | N/A | Linux syscall_64.tbl:465; no repo constant |
| 466 | removexattrat | — | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. | No | No | N/A | Linux syscall_64.tbl:466; no repo constant |
| 467 | open_tree_attr | — | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. | No | No | N/A | Linux syscall_64.tbl:467; no repo constant |
| 468 | file_getattr | — | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. | No | No | N/A | Linux syscall_64.tbl:468; no repo constant |
| 469 | file_setattr | — | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. | No | No | N/A | Linux syscall_64.tbl:469; no repo constant |
| 470 | listns | — | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. | No | No | N/A | Linux syscall_64.tbl:470; no repo constant |
| 471 | rseq_slice_yield | — | No | No | No | Missing `NR_*` constant in `crates/kernel/syscall/src/nrs.rs`; not live-mapped. | No | No | N/A | Linux syscall_64.tbl:471; no repo constant |
