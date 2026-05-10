# 52a Stage A — `kernel/src` ownership classification

DRAFT (living). Dep:`52`. Provides:per-file owning-crate map for the migration in `52§9`.

## 1 Purpose

Stage A artifact per `52§9`. Classifies every `kernel/src/*.rs`
file by its owning crate so Stages B/C/D have an explicit target
for each move. Numbers from `2026-05-10` snapshot: 119 files,
34,089 LOC.

## 2 Method

1. One row per `kernel/src/*.rs` file (absolute path from repo root).
2. `LOC` is `wc -l` at snapshot time.
3. `Target` is the destination crate after Stage B per `52§4` layout:
   - existing crate → identical path (`crates/<name>`)
   - new crate → proposed path (`crates/{kernel,drivers,arch}/<name>`)
4. `Action` is one of:
   - `move` — file moves wholesale into target crate
   - `fold` — content merges into an existing module in the target
   - `split` — single file produces multiple target files (e.g. by
     domain — applies to `syscall_glue.rs`, `lib.rs`)
   - `keep` — stays in `kernel/` (integration-only)
   - `rename` — stays in same crate but path changes per `52§6`

## 3 Buckets

Files split into six buckets that match the migration order
recommended in `52§9` (least-invasive moves first):

1. Domain crate exists today → just move (B1)
2. Driver crate exists today → just move (B2)
3. Arch-specific code mis-shelved in `kernel/src` → move (B3)
4. New domain crate required → create + move (B4)
5. `syscall_glue_*` decomposition → split by domain (B5)
6. Integration / smoke / orchestration → keep in `kernel/` (B6)

## 4 Bucket B1 — owning domain crate exists

| File | LOC | Target | Action | Notes |
|---|---:|---|---|---|
| `kernel/src/procfs.rs` | 999 | `crates/procfs` | move | Pressing 1000-line cap; split by topic on landing |
| `kernel/src/procfs_static.rs` | 357 | `crates/procfs` | fold | Static read-only entries |
| `kernel/src/procfs_net.rs` | 292 | `crates/procfs` | fold | `/proc/net/*` synth |
| `kernel/src/procfs_smaps.rs` | 160 | `crates/procfs` | fold | F156 rmap-aware smaps |
| `kernel/src/procfs_meminfo.rs` | 61 | `crates/procfs` | fold | |
| `kernel/src/procfs_pid_status.rs` | 58 | `crates/procfs` | fold | |
| `kernel/src/tty.rs` | 541 | `crates/tty` | move | |
| `kernel/src/tmpfs.rs` | 198 | (new) `crates/tmpfs` | move | Was inline; promote to standalone |
| `kernel/src/io_uring.rs` | 294 | `crates/iouring` | move | |
| `kernel/src/keyring.rs` | 280 | (new) `crates/keyring` | move | |
| `kernel/src/xattr_overlay.rs` | 262 | `crates/vfs` | fold | xattr is a VFS concern |
| `kernel/src/devfs.rs` | 334 | (new) `crates/devfs` | move | Or fold into `vfs` — see `§6 OQ-Devfs` |
| `kernel/src/coredump.rs` | 165 | (new) `crates/coredump` | move | |
| `kernel/src/inode_times.rs` | 92 | `crates/vfs` | fold | |
| `kernel/src/flock.rs` | 122 | (new) `crates/flock` | move | |
| `kernel/src/futex.rs` | 130 | (new) `crates/futex` | move | |
| `kernel/src/perf.rs` | 135 | (new) `crates/perf` | move | |
| `kernel/src/hostname.rs` | 96 | (new) `crates/hostname` | move | |
| `kernel/src/dev_modules.rs` | 125 | `crates/modules` | fold | |
| `kernel/src/dev_ext4.rs` | 551 | `crates/ext4` | fold | Currently glue → real ext4 |
| `kernel/src/elf_load.rs` | 476 | `crates/elf` | fold | |
| `kernel/src/exec_stack.rs` | 210 | (new) `crates/exec` | move | New crate also receives execve handler |
| `kernel/src/syscall_compat.rs` | 183 | `crates/syscall` | fold | |
| `kernel/src/syscall_nrs.rs` | 364 | `crates/syscall` | fold | x86_64 NR table |
| `kernel/src/syscall_trace.rs` | 30 | `crates/syscall` | fold | Adapter — survives `*_glue` filter |
| `kernel/src/sched_stop.rs` | 41 | `crates/sched` | fold | |
| `kernel/src/sched/mod.rs` | 44 | `crates/sched` | move | |
| `kernel/src/sched/balance.rs` | 121 | `crates/sched` | move | |
| `kernel/src/sched/registry.rs` | 35 | `crates/sched` | move | |
| `kernel/src/sched/runqueue.rs` | 205 | `crates/sched` | move | |
| `kernel/src/sched/schedule.rs` | 397 | `crates/sched` | move | |
| `kernel/src/sched/spawn.rs` | 393 | `crates/sched` | move | |
| `kernel/src/sched/wait_list.rs` | 118 | `crates/sched` | move | |
| `kernel/src/sched/zombies.rs` | 169 | `crates/sched` | move | |
| `kernel/src/kthread.rs` | 158 | `crates/sched` | fold | Renames to `sched::kthread` |
| `kernel/src/ksched.rs` | 79 | `crates/sched` | fold | RR smoke; `sched::tests` |
| `kernel/src/preempt.rs` | 86 | `crates/sched` | fold | |
| `kernel/src/sysv_shm.rs` | 215 | `crates/ipc` | fold | |
| `kernel/src/sysv_sem.rs` | 329 | `crates/ipc` | fold | |
| `kernel/src/sysv_msg.rs` | 314 | `crates/ipc` | fold | |
| `kernel/src/posix_mq.rs` | 452 | `crates/ipc` | fold | |
| `kernel/src/dev_pty.rs` | 323 | `crates/tty` | fold | PTY pairs are tty-line-discipline |
| `kernel/src/dev_pipe.rs` | 237 | (new) `crates/pipe` | move | Or fold into `vfs` |
| `kernel/src/dev_inotify.rs` | 380 | (new) `crates/inotify` | move | |
| `kernel/src/dev_epoll.rs` | 202 | (new) `crates/epoll` | move | |
| `kernel/src/dev_signalfd.rs` | 88 | (new) `crates/signalfd` | move | Or fold into `signal` once that exists |
| `kernel/src/dev_pidfd.rs` | 157 | (new) `crates/pidfd` | move | |
| `kernel/src/dev_timerfd.rs` | 210 | (new) `crates/timerfd` | move | |
| `kernel/src/dev_misc.rs` | 145 | (new) `crates/dev-null-zero-random` | move | `/dev/null` `/dev/zero` `/dev/random` etc |
| `kernel/src/dev_console.rs` | 118 | (new) `crates/console` | move | tty/0 + tty/1 + console fds |
| `kernel/src/dev_tracefs.rs` | 46 | (new) `crates/tracefs` | move | |
| `kernel/src/dev_net.rs` | 312 | `crates/net` | fold | Was `dev_*` glue; move into net |
| `kernel/src/dev_drm.rs` | 196 | `crates/drm` | fold | |
| `kernel/src/dev_fbdev.rs` | 76 | `crates/fbdev` | fold | |
| `kernel/src/dev_input.rs` | 83 | (new) `crates/input` | move | |
| `kernel/src/userfaultfd.rs` | 280 | (new) `crates/userfaultfd` | move | |
| `kernel/src/sig_dispatch.rs` | 272 | (new) `crates/signal` | move | New owner for signal delivery + handlers |
| `kernel/src/ptrace_singlestep.rs` | 163 | (new) `crates/ptrace` | move | |
| `kernel/src/cpu_topology.rs` | 154 | (new) `crates/cpu` | move | sysfs cpu topology, cpuid bits |
| `kernel/src/smp.rs` | 128 | (new) `crates/smp` | move | Cross-CPU IPI plumbing |
| `kernel/src/pmm_setup.rs` | 563 | (new) `crates/pmm-setup` | move | Bridges `pmm` + `vmm` + boot memmap |

## 5 Bucket B2 — driver crate exists or proposed

| File | LOC | Target | Action | Notes |
|---|---:|---|---|---|
| `kernel/src/dev_virtio_net.rs` | 650 | (new) `crates/drivers/virtio-net` | move | |
| `kernel/src/dev_virtio_net_modern.rs` | 571 | (new) `crates/drivers/virtio-net` | fold | Modern transport variant |
| `kernel/src/dev_virtio_gpu_modern.rs` | 306 | `crates/drv-virtio-gpu` | fold | |
| `kernel/src/pci_boot/mod.rs` | 656 | `crates/pci` | fold | |
| `kernel/src/pci_boot/virtio_drv.rs` | 986 | `crates/virtio` | fold | Pressing 1000-line cap |

## 6 Bucket B3 — arch-specific (mis-shelved)

| File | LOC | Target | Action | Notes |
|---|---:|---|---|---|
| `kernel/src/lapic.rs` | 457 | `crates/hal-x86_64` | move | |
| `kernel/src/smp_x86.rs` | 169 | `crates/hal-x86_64` | move | |
| `kernel/src/gic.rs` | 495 | `crates/hal-aarch64` | move | |
| `kernel/src/its.rs` | 658 | `crates/hal-aarch64` | move | |
| `kernel/src/msi.rs` | 68 | `crates/hal-aarch64` | move | Arm GIC-MSI specifics |
| `kernel/src/pl011.rs` | 147 | `crates/hal-aarch64` | move | UART driver |
| `kernel/src/arm_timer.rs` | 95 | `crates/hal-aarch64` | move | |
| `kernel/src/psci.rs` | 122 | `crates/hal-aarch64` | move | |
| `kernel/src/smp_arm.rs` | 123 | `crates/hal-aarch64` | move | |
| `kernel/src/syscall_arm_abi.rs` | 172 | `crates/hal-aarch64` | move | aarch64 → x86_64 nr remap |

## 7 Bucket B5 — `syscall_glue_*` decomposition

`52§5` defines `*_glue*` files as adapter-only. The current
`syscall_glue_*.rs` files contain real syscall semantics — they are
not glue. Each splits by domain into the owning subsystem crate's
`syscalls.rs` module. Naming target per `52§6`:
`crates/<domain>/src/syscalls.rs` (or `crates/<domain>/src/syscalls/<topic>.rs`
when a single file exceeds the 500-line soft target).

| File | LOC | Target | Action | Notes |
|---|---:|---|---|---|
| `kernel/src/syscall_glue.rs` | 999 | `kernel/` (dispatch) + per-crate `syscalls.rs` | split | Pressing cap; the dispatch table assembly stays in `kernel/`, individual handlers move |
| `kernel/src/syscall_glue_proc.rs` | 1000 | `crates/sched` + `crates/cpu` | split | At cap — must split this PR cycle |
| `kernel/src/syscall_glue_fs.rs` | 936 | `crates/vfs` | move | |
| `kernel/src/syscall_glue_net.rs` | 927 | `crates/net` | move | |
| `kernel/src/syscall_glue_signal.rs` | 821 | `crates/signal` | move | |
| `kernel/src/syscall_glue_execve.rs` | 669 | `crates/exec` | move | F156 shebang chain lives here |
| `kernel/src/syscall_glue_cred.rs` | 521 | `crates/security` | move | |
| `kernel/src/syscall_glue_clone.rs` | 345 | `crates/sched` | move | F156 fork_cow_pages ABI |
| `kernel/src/syscall_glue_ioctl.rs` | 322 | `crates/vfs` | fold | |
| `kernel/src/syscall_glue_misc.rs` | 295 | `crates/syscall` | split | Decompose by topic; misc is a smell |
| `kernel/src/syscall_glue_timers.rs` | 279 | (new) `crates/timers` | move | POSIX timers + setitimer |
| `kernel/src/syscall_glue_xfer.rs` | 242 | `crates/vfs` | fold | sendfile/splice/copy_file_range |
| `kernel/src/syscall_glue_namei.rs` | 204 | `crates/vfs` | fold | name → inode resolution |
| `kernel/src/syscall_glue_open.rs` | 189 | `crates/vfs` | fold | F156 ext4 fallback chain |
| `kernel/src/syscall_glue_utime.rs` | 176 | `crates/vfs` | fold | |
| `kernel/src/syscall_glue_time.rs` | 166 | `crates/syscall` | fold | clock_gettime / time / etc |
| `kernel/src/syscall_glue_pvmrw.rs` | 137 | `crates/vmm` | fold | process_vm_readv/writev |
| `kernel/src/syscall_glue_prctl.rs` | 137 | `crates/sched` | fold | prctl is task-scoped |
| `kernel/src/syscall_glue_proclink.rs` | 133 | `crates/procfs` | fold | /proc/self resolves |
| `kernel/src/syscall_glue_perms.rs` | 115 | `crates/security` | fold | |
| `kernel/src/syscall_glue_select.rs` | 102 | `crates/vfs` | fold | poll/select/pselect |
| `kernel/src/syscall_glue_mount.rs` | 110 | `crates/vfs` | fold | |
| `kernel/src/syscall_glue_unix_cmsg.rs` | 84 | `crates/net` | fold | SCM_RIGHTS cmsg |
| `kernel/src/syscall_glue_anonfd.rs` | 74 | `crates/vfs` | fold | memfd_create / eventfd |
| `kernel/src/syscall_glue_falloc.rs` | 67 | `crates/vfs` | fold | fallocate |
| `kernel/src/syscall_glue_uname.rs` | 63 | (new) `crates/uts` | move | uname + UTS namespace |
| `kernel/src/syscall_glue_dmesg.rs` | 60 | `crates/klog` | fold | |
| `kernel/src/syscall_glue_rseq.rs` | 59 | `crates/sched` | fold | rseq is sched-task state |
| `kernel/src/syscall_glue_chroot.rs` | 42 | `crates/vfs` | fold | |
| `kernel/src/syscall_glue_numa.rs` | 34 | `crates/vmm` | fold | mbind / set_mempolicy stubs |

## 8 Bucket B6 — integration / smoke (stays in `kernel/`)

These are the only files whose final home is `kernel/` per `52§5`.
Total: 11 files (one new directory `kernel/src/smoke/` for the smoke
binaries).

| File | LOC | Target | Action | Notes |
|---|---:|---|---|---|
| `kernel/src/lib.rs` | 999 | `kernel/src/lib.rs` | split | Stays — boot/init order. Pressing cap, decompose into `init/{boot,smokes,wiring}.rs` |
| `kernel/src/debug_macros.rs` | 40 | `kernel/src/debug_macros.rs` | keep | Cfg-gated `debug_*!` per `04` R06 |
| `kernel/src/elf_smoke.rs` | 923 | `kernel/src/smoke/elf_x86.rs` | rename | Boot-time ELF smoke |
| `kernel/src/elf_smoke_arm.rs` | 441 | `kernel/src/smoke/elf_arm.rs` | rename | F156 init stack pre-fault lives here |
| `kernel/src/userspace_smoke.rs` | 251 | `kernel/src/smoke/userspace_x86.rs` | rename | |
| `kernel/src/userspace_smoke_arm.rs` | 173 | `kernel/src/smoke/userspace_arm.rs` | rename | |
| `kernel/src/canary.rs` | 304 | `kernel/src/smoke/canary.rs` | rename | sched canary |
| `kernel/src/preempt_smoke.rs` | 161 | `kernel/src/smoke/preempt.rs` | rename | |
| `kernel/src/mmuops_smoke.rs` | 210 | `kernel/src/smoke/mmuops.rs` | rename | |
| `kernel/src/user_map_smoke.rs` | 115 | `kernel/src/smoke/user_map.rs` | rename | |
| `kernel/src/device_map_smoke.rs` | 681 | `kernel/src/smoke/device_map.rs` | rename | |
| `kernel/src/pf_recover_smoke.rs` | 146 | `kernel/src/smoke/pf_recover.rs` | rename | |
| `kernel/src/user_as.rs` | 998 | `kernel/src/init/user_as.rs` | split | Pressing cap; fault classifier + init AS wiring stay |

## 9 Totals after Stage A

| Bucket | Files | LOC | Disposition |
|---:|---:|---:|---|
| B1 (existing or new domain crate) | 60 | ~12,500 | move/fold |
| B2 (driver) | 5 | ~3,170 | move/fold |
| B3 (arch) | 10 | ~2,400 | move |
| B5 (syscall_glue split) | 30 | ~10,200 | split per topic |
| B6 (integration/smoke) | 13 | ~5,800 | stays in `kernel/` |
| (Verification) | 119 - 1 = 118 + lib.rs | ≈34,089 | matches snapshot |

After full Stage B/C completion, `kernel/src` shrinks from 34 KLOC
to ≈5–6 KLOC across ≤15 files — all integration, init order, smokes.

## 10 New crates this migration creates

26 new crates land during Stage B (new-crate column in §4–§7):

`tmpfs`, `keyring`, `devfs`, `coredump`, `flock`, `futex`, `perf`,
`hostname`, `exec`, `pipe`, `inotify`, `epoll`, `signalfd`, `pidfd`,
`timerfd`, `dev-null-zero-random`, `console`, `tracefs`, `input`,
`userfaultfd`, `signal`, `ptrace`, `cpu`, `smp`, `pmm-setup`,
`drivers/virtio-net`, `timers`, `uts`.

Each gets:
1. `crates/<name>/Cargo.toml` + `src/lib.rs`
2. Workspace member entry in root `Cargo.toml`
3. `pub use crate::<old_module>` re-exports from `kernel/src` for one
   release window per `52§8` so call sites can migrate gradually.

## 11 Migration ordering (Stage B sub-phases)

Order matters: domain crates may depend on `pmm-setup`, `sched`, and
`signal` per `52§7`, so those move first.

1. **B-0 foundations**: extract `pmm-setup` and `sched` into their
   own crates (or fully populate the existing `sched` crate). Required
   so subsequent moves don't import back into `kernel`.
2. **B-1 vfs cluster**: `vfs` absorbs `xattr_overlay`, `inode_times`,
   plus the vfs-side syscall_glue (`open`/`namei`/`xfer`/etc).
3. **B-2 ipc cluster**: `ipc` absorbs sysv shm/sem/msg, posix mq.
4. **B-3 signal + ptrace**: new `signal`/`ptrace` crates absorb
   `sig_dispatch`, `ptrace_singlestep`, `syscall_glue_signal`.
5. **B-4 procfs/tty**: existing `procfs`/`tty` crates absorb the
   in-tree files; `dev_pty` folds into `tty`.
6. **B-5 net**: existing `net` absorbs `dev_net` and
   `syscall_glue_net`/`syscall_glue_unix_cmsg`.
7. **B-6 fs-nodes**: new `pipe`/`epoll`/`signalfd`/etc.
8. **B-7 arch sweep**: move `lapic`/`gic`/`its`/`pl011`/`arm_timer`/
   `psci` into the right hal crate.
9. **B-8 syscall finale**: split `syscall_glue.rs` itself; the
   dispatch-table assembly stays in `kernel/`.

## 12 Cross-references

- `52§3` layer model.
- `52§5` ownership rules.
- `52§7` dependency direction.
- `52§9` migration plan (this doc is Stage A's artifact).
- `08§7` file length cap (drives the `procfs.rs` / `syscall_glue.rs`
  / `lib.rs` / `user_as.rs` / `virtio_drv.rs` decomposition urgency).

## 13 OQ

1. **Devfs**: standalone `crates/devfs` or fold into `crates/vfs`?
   Linux puts devtmpfs under fs/, but our `devfs` is more like a
   sysfs-style kernel-object registry. Recommend standalone.
2. **Smoke binaries**: are `elf_smoke`/`userspace_smoke` integration
   tests (move to `tests/`) or runtime smokes that ship in the kernel
   binary (keep in `kernel/src/smoke/`)? Currently they're invoked
   from `kernel_main` and produce boot-log lines — runtime smokes.
3. **`signal` vs `sig_dispatch`**: rename crate to `signal` for
   clarity vs Linux convention (`kernel/signal.c`)?
4. **Exact split of `syscall_glue.rs:999`**: the dispatch table
   assembly + per-syscall NR table glue currently live together.
   Spec says the dispatch table assembly stays in `kernel/`. Where
   does the per-NR routing logic land — `crates/syscall` or per
   target crate's `syscalls.rs`? Recommend per-target.
