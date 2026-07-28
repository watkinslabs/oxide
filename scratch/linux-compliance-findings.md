# Linux compliance findings — consolidated subsystem audit

DRAFT 2026-07-27. Dep: `scratch/audit-mm.md`, `scratch/audit-sched.md`, `scratch/audit-vfs.md`, `scratch/audit-net-sec.md`, `scratch/syscall-compliance-matrix.md`, `scratch/partial-gap-triage.md`.

Consolidates four read-only subsystem audits run against `/home/nd/oxide/linux-master`
(v7.2.0-rc4). Each source doc carries per-row Linux file:line and oxide file:line;
this file is the index, the cross-cutting patterns, and the work order.

## 1 Totals

Counts as reported by each audit lane from its own document.

| Subsystem | Doc | BLOCKER | SECURITY | CORRECTNESS | PERF | ABSENT-OK | Findings |
|---|---|---|---|---|---|---|---|
| mm | `audit-mm.md` | 3 | 23 | 58 | 29 | 24 | 137 |
| sched/time/signals | `audit-sched.md` | 4 | 8 | 66 | 20 | 15 | ~150 |
| vfs/fs/block | `audit-vfs.md` | 11 | 25 | 112 | 31 | 1 | 180 |
| net/security/ipc/tty/drivers | `audit-net-sec.md` | 16 | 39 | 102 | 14 | 51 | 222 |
| **Total** | | **34** | **95** | **338** | **94** | **91** | **~689** |

`ABSENT-OK` = Linux itself omits this under a plausible `CONFIG`; recorded so a later
lane does not implement something upstream does not have either. Not a gap.

Separately, 46 rows record mechanisms **verified as matching Linux** (§6).

## 2 Blockers, deduplicated and ordered

Ordered by user-visible impact. Several audits reached the same defect from different
directions; those are merged here with all reporting docs cited.

| # | Blocker | Effect | Status |
|---|---|---|---|
| 1 | **Every kernel timeout has a ~100 ms floor** — `park_with_deadline` only stamps a deadline; the sole consumer is a 100 ms periodic that is itself self-throttled to 100 ms on a kthread parking 100 ms per loop. Wait deadlines never reach `next_interrupt_deadline()`. | `nanosleep(1ms)`, `epoll_wait(…,1)`, futex/select/poll timeouts all block ~100 ms (worst case ~200 ms). A global latency floor under every desktop IPC wait. **Leading explanation for the standing desktop-slowness symptom.** | `B1460` in flight |
| 2 | **timerfd has no timer object** — expiry is discovered by polling the same 100 ms scanner; nothing ever fires. | systemd and GNOME are heavy timerfd users. | with #1 |
| 3 | **Signals are only delivered at the syscall-return tail** — `take_lowest_pending()` has one call site and none on the IRQ/exception return path, either arch. | A compute-bound loop issuing no syscalls is **unkillable**: `kill -9`, `^C`, `SIGALRM` never arrive. Sibling SIGKILL from `zap_other_threads` also lands only at each sibling's next syscall return. | FIXED `B1471-signal-on-irq-return` — Linux's `exit_to_user_mode_loop` (`kernel/entry/common.c`) ported whole: ONE loop, called from the syscall tail AND from every IRQ/exception return on both arches, looping while `_TIF_WORK` remains with interrupts enabled per pass and masked for the re-check. Decision logic is ungated in `sched::exit_to_user` (11 hosted tests); the arch paths reach the body through a boot-installed hook because `arch-irq` sits below the crate owning signal delivery. Two prerequisites came with it: (a) ONE user-register frame per arch — x86_64 had three save layouts and a signal builder hardwired to `gs:[8]-0x80`, and its IRQ stub saved only the 9 scratch GPRs, so no correct `ucontext` could be built off it; (b) Linux's SYSRET-eligibility guard (`do_syscall_64`'s tail) with an IRETQ fallback, because `SYSRETQ` forces `RIP:=RCX` and cannot return an `rt_sigreturn` frame whose `rcx` is real interrupted state. Proof: `spinsig` block added to the guest differential (SIGUSR1 into a spin, the spinner's own `alarm(2)`, SIGKILL to a spinning sibling), **100/100 identical records on both arches**. |
| 4 | **No working path to a durable write** — `vfs_fsync` calls `f_op->fsync` before `mapping.writeback()` (Linux is the reverse); `O_SYNC`/`O_DSYNC`/`RWF_SYNC` parsed and never consulted; `msync(MS_SYNC)` never reaches the device; `O_DIRECT` a no-op; `VIRTIO_BLK_F_FLUSH` never negotiated while `T_FLUSH` is sent and its result discarded. | `write()` + `fsync()` returning 0 can lose data. Invisible to boot tests. | `B1462` in flight |
| 5 | **Inodes built with no `PollSubscribers`** — tty, pty, ext4 FIFOs, mqueue fds. `poll` parks with no wake source; `epoll_ctl(ADD)` registers no callback. | Readiness survives only via epoll's O(N) rescan fallback — which is why this presents as slowness, not as a hang. Found independently by three lanes in three subsystems. | `B1461` in flight |
| 6 | **`POLL_OUT` never de-asserts** — every AF_UNIX and TCP poll mask sets it unconditionally while the send paths correctly return `EAGAIN`. | A non-blocking poll-driven writer against a slow reader spins at 100% CPU. | with #5 |
| 7 | **inotify events carry no filename** — `len` hardwired to 0, the leaf name taken and discarded. | Every directory watcher learns *that* something changed, never *which* file: systemd `.path` units, udev, `GFileMonitor`, Nautilus, dconf. | `B1463` in flight |
| 8 | **User frames freed with no TLB flush** — `evict_foreign_pages_in_range` unmapped then immediately freed, no local flush, no shootdown, either arch. The in-file justification ("oxide is UP") was false; SMP bring-up runs on both arches and smoke boots `-smp 2`. | Reachable from `process_madvise`/`process_mrelease`: a frame returned to the buddy while another CPU held a writable TLB entry. Same class as the io_uring free-while-mapped UAF. | FIXED `B1467-smp-tlb-and-runqueue` — teardown now runs through `pmm::tlb_gather::TlbGather` (Linux `mm/mmu_gather.c`: unhook -> invalidate -> free, batched), targeting the TARGET mm's cpumask rather than the caller's. Two ADDITIONAL sites of the same class found and fixed: `unmap.rs` `glue_munmap` + `evict_pages_in_range` gated their local flush on `#[cfg(target_arch="x86_64")]`, so EVERY aarch64 munmap/MADV_DONTNEED freed frames with no invalidation at all (ARM has no TLB IPI — `arch-irq::tlb` is x86-only — so the no-op shootdown was the only other candidate); and `pageout.rs` `flush_reclaim_mapping` issued its ARM broadcast only when the mm was current, leaving the normal foreign-rmap reclaim path uninvalidated on ARM. 8 hosted ordering tests in `mm-pmm/src/tlb_gather/tests.rs` (ungated; `user_as` is kernel-gated and would compile tests out). |
| 9 | **`sched_setscheduler` on a remote-queued task uses the caller's runqueue** — force-cleared `on_rq`, then enqueued into a second tree. | One `Arc<Task>` in two runqueue trees; two CPUs can run one task and corrupt its saved context. | FIXED `B1467-smp-tlb-and-runqueue` — `set_class` now delegates to `live::rq_locate::set_class_with`, which locates the runqueue the task is ACTUALLY on (Linux `task_rq_lock` / `sched_change_begin`+`end`, both of which recompute `task_rq(p)`), dequeues and re-enqueues THERE. `relocate_for_affinity` shares the same helper, so there is one locating routine, not a third pattern. 11 hosted tests in `sched/src/live/rq_locate/tests.rs`; 3 of them fail against the pre-fix algorithm (verified by reverting). |
| 10 | **No global OOM killer** — `kill_memcg` has one caller and fires only under a cgroup limit. | On a normal desktop, memory exhaustion kills nothing; the allocation failure propagates and the *faulting* process takes SIGSEGV instead of a badness-selected victim taking SIGKILL. | open |
| 11 | ~~**The exec transition has no security floor**~~ — every part of the finding was CONFIRMED and is now FIXED: `S_ISUID`/`S_ISGID` honouring with all of Linux's suppression rules, `MAY_EXEC` + file-type + `path_noexec` on the live exec path, `AT_SECURE`/`AT_UID`/`AT_EUID`/`AT_GID`/`AT_EGID` from the real creds on both arches, `MNT_NOSUID` via `Mount::may_suid`, `MNT_NODEV` in `may_open`. Plus the capability half: file caps (incl. the rev-3 `rootid` namespace test and an interleaved-layout decode bug), ambient clearing, `SECBIT_NOROOT`/`SECBIT_KEEP_CAPS`, the `LSM_UNSAFE_*` downgrade, `PER_CLEAR_ON_SETID` and `would_dump` dumpability. Decision is one pure ungated fn with 38 unit tests. | DONE | `B1464-exec-privilege-transition` |
| 12 | **`/proc/<pid>/status` is fabricated** — `Uid: 0 0 0 0`, all-ones capability masks, `NoNewPrivs: 0` for every process; procfs has no `ptrace_may_access` gate and every dynamic file is 0444. | systemd, polkit, dbus-daemon and `pkexec` read this to decide who a peer is and what it may do. | `B1463` in flight |
| 13 | **arm64 `rt_sigreturn` writes raw user PSTATE into `spsr_el1`** — forging `M[3:0]=0b0101` returns user code at **EL1**. x86_64 has the same shape with EFLAGS and no `FIX_EFLAGS` whitelist (IOPL user-settable); `build_signal_frame` has no `access_ok`, giving an arbitrary kernel write. | Unprivileged local privilege escalation. | `B1459` merged; the FPU/SIMD gap the same lane found is `B1466`, merged |
| 14 | **`AT_RANDOM` is a clock reading** — 16 bytes derived from one `monotonic_ns()` sample; bytes 8..15 re-derive from the same word. | glibc builds `__stack_chk_guard` and the `PTR_MANGLE` pointer guard from it, so both mitigations are predictable. `crates/kernel/crng` exists and is not called. | `F768` in flight |

## 3 Cross-cutting patterns

These explain a large share of the 338 CORRECTNESS rows and change how the work should
be estimated.

### 3.1 Complete machinery with no callers
The dominant defect class is **correct, sometimes tested code that nothing invokes** —
not missing code. Confirmed: `age_anon`/`age_file`, `mark_lru_referenced`,
`psi::task_stall`, `vfs::DirtyPages`, the `f_ra` readahead state machine, the whole
`crates/shared/slab` allocator, `sched::oom::kill_memcg` (one caller), `update_rtt`
(so TCP's RTO is a fixed 1 s and `tcpi_rtt` always 0), `static_console::poll_subscribers`,
`encode_get_edid`, `register_family`, `virtio::queue::VirtQueue`,
`sigpend::all_pending`, `security::bpf_lsm`.

Consequence: **a symbol existing proves nothing.** Grep call sites, not definitions.
Corollary: many of these are wiring jobs, not implementations — cheaper than they look.

Worked example, FIXED `B1466`: `fpu_save`/`fpu_restore` and a full per-task XSAVE area
existed and were exercised on every context switch, while the signal frame wrote
`fpstate = 0` (x86_64) and an empty `__reserved` (arm64) — so any handler calling a
SIMD-optimised glibc routine silently destroyed the interrupted context. The fix was
mostly wiring, but NOT only wiring: the frame layout, `save_xstate_epilog`, the
`check_xstate_in_sigframe` / `validate_user_xstate_header` / MXCSR restore checks and
arm64's `parse_user_sigframe` record chain all had to be written, and arm64's
`sigcontext.__reserved` turned out to be 8 bytes off Linux (280 vs the UAPI's
`__aligned__(16)` 288) — latent exactly as long as nothing lived there.
`userspace/wait_diff/sigfpu.c` now diffs SIMD preservation across signal delivery
against the host's real Linux, with two mutants in `tools/wait-diff-selftest.sh`.

Second lesson from the same lane, for anyone touching an arm64 signal frame:
`struct sigcontext` is 4384 bytes and `rt_sigframe` 4688, so staging either in a
kernel-stack local is fatal — LLVM turned ONE by-value read of `sigcontext` into a
21 KiB stack frame on a 16 KiB guard-paged kstack. Hosted tests were all green;
only `make smoke-arm` caught it. Write and read the frame field by field straight
into user memory, which is what Linux's `__put_user_error`/`__get_user_error` do.

### 3.2 Gated files hide their own tests
`crates/kernel/syscalls/src/kernel_body.rs` and every slot file it `#[path]`-includes are
`#[cfg(target_os = "oxide-kernel")]`. A `#[cfg(test)] mod tests` there **compiles out
silently** while cargo prints "ok". The sched audit found the correlation directly: the
code that turned out **correct** overwhelmingly lives in *ungated* modules. This is the
strongest available argument for moving decision logic out of gated files, and it is now
a standing requirement in every fix brief.

### 3.3 Fabricated data presented as real
Distinct from "unimplemented", and worse, because callers cannot detect it:
`perf_event_open` returned a timestamp as whatever counter was requested;
`/proc/<pid>/status` reports uid 0 and full capabilities for every process;
`AT_RANDOM` is a clock; `/proc/sys/kernel/perf_event_paranoid` was a dead cell no code
read — a split source of truth letting userspace "loosen" a gate the syscall never
consulted. Hunt for constants in files that render kernel state.

### 3.4 aarch64 numbers falling through to the x86 table
`arm_abi.rs` passes an unmapped aarch64 number straight into the x86_64 dispatch table.
`asm-generic/unistd.h` reserves 295..402 as unassigned; every one of those ran a real x86
syscall — aarch64 `syscall(300)` executed `fanotify_mark`. Earlier instance: `nfsservctl`
ran `connect`. **Absence of a mapping is not `ENOSYS`** — it must be an explicit rule.

## 4 Work order

1. **#1/#2 timeout floor** — largest user-visible win, self-contained, one-shot programmer already exists.
2. **#13/#14 signal-frame escalation + `AT_RANDOM`** — security, both small and isolated.
   `AT_RANDOM` closed by `F768` (execve) and `F771` (PID 1 spawn); ASLR itself closed by `F771`.
3. **#4 durable write** — data loss; invisible to every test we currently run.
4. **#5/#6 readiness** — removes an O(N) fallback the desktop leans on.
5. **#3 signal delivery on IRQ/exception return** — correctness floor; `docs/54` governs both arches.
6. **#11/#12 exec floor + procfs credentials** — the privilege model; #11 must follow `F768` (same files).
7. **#8/#9 SMP hazards** — currently latent; blocking for SMP>1, which is untested.
8. **#10 OOM killer**, then the long CORRECTNESS tail by owning subsystem.

## 5 What could not be determined

Recorded rather than guessed. Each needs a targeted lane.

| Question | Why it matters | Doc |
|---|---|---|
| Does the fault handler recover from a kernel-mode fault at an unmapped user VA? | Bounds whether the mqueue user-buffer row is a trivially reachable unprivileged kernel fault. | net-sec |
| AF_VSOCK message-level conformance | Not diffed against Linux. | net-sec |
| IPv6 SLAAC / NUD correctness | Not verified. | net-sec |
| Full 281-hook LSM inventory | Only sampled. | net-sec |
| 9 further mm items | Listed in `audit-mm.md` § What I could not determine. | mm |

## 6 Verified correct — do not re-audit

Recorded to stop future lanes spending time here. Capabilities, user namespaces,
keyrings, job control, VT process-mode switching, TCP CUBIC, POSIX/OFD/flock owner
split, atime policy, xattr namespace gating, `sync_file_range`, htree insert/split,
extent trees to depth 5, `metadata_csum`, fanotify (including blocking permission
events), zram, quota (the most Linux-faithful subsystem audited), `membarrier`, the
robust-futex exit walker, `restart_block`, NTP discipline, POSIX CPU timers,
`sigaltstack`, the tty job-control decision table, and `rseq` (`rseq_cs` decode, IP
fixup, signature validation — both arches).

## 6a Fixed by `B1465` — TCP sequence prediction + randomness honesty

Post-dates the audit; neither ledger carried the ISN row before this branch.

| Finding | Why it mattered | Fix |
|---|---|---|
| **TCP initial sequence numbers were a fixed constant** — `TCP_ISN_INITIAL = 0x1000_0000` stepping `0x1000` from a global counter, identical every boot; the passive/server side opened at literal **0**; ephemeral ports scanned sequentially from a fixed base | Remotely exploitable TCP sequence prediction (RFC 6528): an off-path attacker needed to guess neither the sequence number nor the source port, so blind connection reset and blind data injection against any TCP connection were arithmetic rather than search. Structural cause: `crates/kernel/net` had no `crng` dependency | Linux `net/core/secure_seq.c` construction — `seq_scale(siphash(4-tuple, net_secret))` with a per-boot CSPRNG key. New `crates/shared/siphash` (Linux `lib/siphash.c`, pinned to upstream's own vectors); `crates/kernel/net/src/secure_seq.rs` |
| TCP TSval was one global clock shared by every connection | Published host uptime; let an observer correlate every connection from this host | `tp->tsoffset` from the high half of the same hash |
| `crng::reseed()` set `SEEDED` unconditionally, so `is_initialized()` could never report a cold pool | `getrandom(2)` could never block and `GRND_NONBLOCK` could never return `EAGAIN` — the readiness signal userspace relies on to know its keys are safe was synthetic. On a TCG boot with no RDRAND and no virtio-rng the pool was keyed from one cycle-counter read while reporting itself ready | Credit only a source that actually answered (never the TSC, matching Linux); `add_hw_entropy` vs `add_entropy` split; a real `wait_for_random_bytes()` loop in slot 318 |
| `/proc/sys/kernel/randomize_va_space` reported `2` with no ASLR implemented | Hardening detectors read it and concluded the system was protected | Reports `0`. **ASLR itself remains absent and remains on the ledger** — only the false report is fixed |
| `/proc/sys/kernel/random/uuid` (and the sysfs copy) were static inodes | Every reader for the whole boot got the identical UUID | Fresh v4 UUID per read |
| glibc `mkstemp`/`mkdtemp`/`mktemp` used a clock-seeded LCG | Predictable temp filenames — classic `/tmp` symlink-attack vector | glibc's `__gen_tempname` over `getrandom(2)` |

## 7 Corrections to earlier ledgers

- **ASLR (`audit-mm.md` §1, `audit-net-sec.md` §A2): all six components implemented in F771.**
  Two corrections to how those rows described Linux. (a) The dynamic linker's base is NOT an
  independent random draw — `load_elf_interp` passes the main image's `load_bias` as `no_base`
  and maps with hint 0 and no `MAP_FIXED`, so `get_unmapped_area` places it off the already
  randomised `mmap_base` (`fs/binfmt_elf.c:686-689`). (b) The vDSO likewise has NO dedicated
  random slot on x86_64 or arm64 in v7.2.0-rc4; `map_vdso_randomized()` no longer exists and
  `vdso_addr()` survives only on s390/sparc. Both are `get_unmapped_area(NULL, 0, ...)` +
  `_install_special_mapping`. Implementing them therefore meant routing both through the arena,
  not inventing draws Linux does not take.
- **`personality(ADDR_NO_RANDOMIZE)` is no longer a no-op.** It is read by
  `exec_transition::exec_rnd` with `per_clear` folded in first, matching Linux's ordering
  (`begin_new_exec` applies `per_clear` before `load_elf_binary` derives `PF_RANDOMIZE`), so a
  setuid exec cannot inherit a pre-armed bit. `setarch -R` now produces a genuinely fixed layout.
- **`kernel.randomize_va_space` no longer lies in either direction.** Bound to `aslr`'s live
  cell; default `2`, and all three modes behave as documented. Linux registers this leaf with
  plain `proc_dointvec` and no min/max — the previous `Some((0,2))` bounds were not Linux.
- **A second clock-derived `AT_RANDOM` survived `F768` in the PID 1 boot spawn** (`smoke/src/elf.rs`,
  `smoke/src/elf_arm.rs` both built `random16` from one `monotonic_ns()` sample). F768 fixed only
  the `execve` path. Both now call `crng::fill`, so the most privileged process on the system no
  longer gets a guessable stack canary.
- `partial-gap-triage.md` A1 lists `rseq` as missing `rseq_cs`/IP-fixup. **Stale** — only `rseq_signal_deliver` is absent.
- `fadvise64 NOREUSE` is **not** a gap; Linux's effect is reclaim-bias only.
- `RLIMIT_MEMLOCK` **is** enforced — but `mlockall(2)` and `mmap(MAP_LOCKED)` bypass it.
- hugetlbfs is **not** absent; it is mountable and hands out 4 KiB pages (a false capability probe).
- The AF_UNIX listener accept-readiness wakeup is **already fixed**.
- `bpf` is **not** an arbitrary-kernel-execution hole — programs never execute; a functional void, not a security one.
- The TCP ISN finding is **new** — it post-dates every earlier ledger and appeared in neither. Fixed on `B1465`; see §6a.
- **B1434's `pkey_alloc` correction was itself wrong for x86_64 — corrected by B1479.** B1434
  replaced an `ENOSYS` strawman with a flat `ENOSPC` on both arches, on the reasoning that "pkey 0
  is allocated implicitly when the mm is created, so the allocation map is already full". That
  holds on arm64 and NOT on x86_64: `arch/x86/include/asm/mmu_context.h` `init_new_context` sets
  `pkey_allocation_map = 0x1` *inside* `if (cpu_feature_enabled(X86_FEATURE_OSPKE))`, so without
  OSPKE the map starts EMPTY. x86's `mm_pkey_alloc` has no `arch_pkeys_enabled()` guard (arm64's
  does), so the first call hands out key 0 and fails one step later in
  `arch_set_user_pkey_access` with `EINVAL` (`arch/x86/kernel/fpu/xstate.c`); the rollback
  `mm_pkey_free` fails too, because key 0 equals the likewise-uninitialised `execute_only_pkey`
  and `mm_pkey_is_allocated` refuses it, so the bit stays set and every later call is `ENOSPC`.
  Result: **x86_64 `EINVAL` once per mm then `ENOSPC`; aarch64 `ENOSPC` from the first call.**
  Two more per-arch differences fell out of the same read: `PKEY_ACCESS_MASK` is `0x3` on x86 and
  `0xF` on arm64 (`PKEY_DISABLE_READ`/`_EXECUTE` are arm64-only, `arch/arm64/include/uapi/asm/mman.h`),
  and `pkey_free(0)`/`pkey_mprotect(...,0)` succeed on arm64 and are `EINVAL` on x86. B1479 models
  the real per-mm `mm_context_t::pkey_allocation_map` instead of a constant, so all three syscalls
  follow one map. **Method note:** the error was believing a plausible chain without tracing the
  one `#ifdef`/`if` that gates the initialisation — the same failure mode B1434 existed to fix.
- `bind()`/`mknod` stale negative dentries: **already fixed**. A blocking lease break **does** exist. Unwritten-extent writes are **not** rejected. Mandatory locking is `ABSENT-OK` (Linux removed it in 5.15). `copy_file_range`'s unconditional `EXDEV` matches current Linux.

## 8 B1472 — gdm "no session desktop files installed": three Linux-incompat kernel bugs

Reported symptom: `live-gnome` reaches `graphical.target`, gdm aborts with `GdmSession: no
session desktop files installed, aborting...` about `/usr/share/wayland-sessions`, which
demonstrably holds `gnome.desktop` + `gnome-wayland.desktop`. `gnome-shell` never starts.

**`readdir` was NOT the cause** (the reported hypothesis). Verified in a live guest on the
`systemd.debug_shell=ttyS0` console: `ls -la /usr/share/wayland-sessions` lists both files,
`md5sum` matches the host, `TryExec=/usr/bin/gnome-session` exists mode 0755. gdm never opens
that directory — it drops the Wayland session dirs before searching. `gdm`'s
`get_system_session_dirs` (disassembled from the image binary) builds the search list from
`self->supported_session_types`; with only `x11` the list is the four X11 dirs, and
`/usr/share/xsessions` is EMPTY in this image, so zero sessions is the correct output of a
wrong input.

Chain, each link observed rather than inferred:

| # | Bug | Observation | Linux |
|---|---|---|---|
| 1 | `fs_struct.root`/`pwd` only set by `chroot(2)`, so `/proc/<pid>/root` is ENOENT | `readlink /proc/1/root` → ENOENT; `stat -L` → ENOENT | `init_mount_tree()` runs `set_fs_root`/`set_fs_pwd` on `init_fs`; `proc_root_link` → `get_task_root` never fails for a live task |
| 2 | sysfs attributes reject `O_TRUNC` (`i_op->truncate` default `EROFS`) | `echo add > /sys/class/drm/card0/uevent` → "Read-only file system" | `kernfs_iop_setattr` runs `setattr_copy` and "ignores size changes" (`fs/kernfs/inode.c`) |
| 3 | `fstatfs` on a synthesized sysfs inode reports TMPFS_MAGIC (no `i_sb`) | `udevadm trigger --dry-run -v` lists 2 devices; debug log: `sd-device: the syspath "/sys/devices/…" is outside of sysfs, refusing` | `vfs_statfs(&f->f_path)` reads `f_path.dentry->d_sb`, which for a path-backed fd IS the mount's sb — `sys_statfs` on the same path already answered SYSFS_MAGIC, so the two disagreed |

Consequence chain: (1) makes systemd's `running_in_chroot()` true — `udevadm trigger` prints
"Running in chroot, ignoring request." (2) and (3) independently break coldplug even once the
chroot check passes. No udev database ⇒ no `master-of-seat` tag on the DRM card ⇒ logind
`/run/systemd/seats/seat0` `CAN_GRAPHICAL=0` ⇒ gdm's Wayland session types are dropped ⇒ empty
X11-only session dirs ⇒ `g_error` ⇒ abort.

Before/after, same image, x86_64:

```
before: readlink /proc/1/root = ENOENT   udevadm trigger = "Running in chroot, ignoring request."
        /run/udev/data absent            CAN_GRAPHICAL=0    gnome-shell never runs
after:  readlink /proc/1/root = "/"      trigger enumerates 43 devices (was 2)
        /run/udev/data = 35 entries      tags = master-of-seat,seat,systemd,uaccess
        master-of-seat = c226:0          CAN_GRAPHICAL=1    gnome-shell running (2 procs)
```

Also observed and NOT fixed here:

- gdm's `abort()` after `g_error` killed it with **SIGSEGV, not SIGABRT** — glibc's `abort()`
  falls through to `ABORT_INSTRUCTION` (`hlt`, → #GP → SIGSEGV) only when BOTH `raise(SIGABRT)`
  calls return. Signal-to-self via `tgkill` in a threaded process is not terminating the group.
  Moot for this blocker (gdm no longer aborts) but a real signal-delivery gap.
- SMP=2 `live-gnome` boot panicked at `sched/live/schedule/switch.rs:367`
  "schedule selected task already owned by another CPU". Pre-existing `on_cpu` ownership race,
  unrelated to this diff; the faster boot (working udev) makes it easier to hit.
  **Root-caused and fixed in B1473 — see §9.**
- Serial RX duplicates input bytes under load (`xsessions` → `xsessiions`), and a burst of
  typed input has twice ended in `#DF` inside `sched::diag::emit::sysrq_rx`.

## 9 B1473 — "schedule selected task already owned by another CPU": two `on_cpu` protocol breaks

Invariant the `kassert` encodes (`live/schedule/switch.rs`): a task with `on_cpu == true` is
EXECUTING on its owner CPU, so no other CPU may pick it. A failure means two CPUs are about to
run one `Arc<Task>` off one saved register context.

Distinct from B1467 (`set_class` dequeuing from the CALLER's runqueue). Two independent
deviations from Linux's `on_cpu` protocol, both required to close it. Neither is a wake-path
routing bug — the routing bugs found alongside (table below) were real but did not stop the
panic; that was established by fixing them first and still reproducing.

### 9.1 `schedule()` published `on_cpu = 1` AFTER the pick had cleared `on_rq`

`kernel/sched/core.c`, beside `try_to_wake_up`'s `smp_load_acquire(&p->on_cpu)`:

```
 * Ensure we load p->on_cpu _after_ p->on_rq, otherwise it would be
 * possible to, falsely, observe p->on_cpu == 0.
 *
 * One must be running (->on_cpu == 1) in order to remove oneself
 * from the runqueue.
 *
 * __schedule() (switch to task 'p')	try_to_wake_up()
 *   STORE p->on_cpu = 1		  LOAD p->on_rq
 * __schedule() (put 'p' to sleep)
 *   STORE p->on_rq = 0			  LOAD p->on_cpu
```

In Linux a RUNNING task keeps `on_rq == TASK_ON_RQ_QUEUED`; only `block_task()` clears it, long
after `prepare_task(next)` set `on_cpu`, so the order holds for free. Here `on_rq` means "in a
class tree", so the pick itself clears it — and the pre-fix code set `on_cpu` ~20 instructions
LATER, after `swap_current`, the AS switch and the FPU save. `Task::pending_wake` (the wake-list
drain's reader) loads `on_rq` then `on_cpu`, so it could see BOTH clear for a task the local CPU
was mid-switch onto and report it `Ready`.

Fix: `RunqueueInner::pick_next_task_claim` — Linux's `pick_next_task` + `prepare_task(next)`
fused, so `on_cpu` is published BEFORE the task leaves the tree, under the rq lock. It returns
the prior `on_cpu`, which is what `schedule()` now asserts on, so the guard is unchanged in
strength and is checked where ownership is taken rather than after the switch.

### 9.2 `sched_ttwu_pending` classified outside the rq lock, then enqueued inside it

Linux (`kernel/sched/core.c`) takes the rq lock FIRST and re-reads `p->on_cpu` at the activation
point, waiting the switch out if it is still set:

```c
rq_lock_irqsave(rq, &rf);
llist_for_each_entry_safe(p, t, llist, wake_entry.llist) {
        if (WARN_ON_ONCE(p->on_cpu))
                smp_cond_load_acquire(&p->on_cpu, !VAL);
        if (WARN_ON_ONCE(task_cpu(p) != cpu_of(rq)))
                set_task_cpu(p, cpu_of(rq));
        ttwu_do_activate(rq, p, ..., &rf);
}
```

Ours drained + classified with no lock, then acquired the rq lock and enqueued — a check-then-act
across an unbounded wait, because this rq's lock is held across whole context switches. A task
cleared as "not executing" could be executing by the time the enqueue landed. Both of Linux's
`WARN_ON_ONCE` conditions were live in our tree simultaneously, which is how it was caught: a
chokepoint probe in `RunqueueInner::enqueue` logged
`tid=4096 on_rq=0 tcpu=1 rq=0 at=live/schedule/switch.rs:281` — `p->on_cpu` set AND
`task_cpu(p) != cpu_of(rq)`, from `sched_ttwu_pending`'s call site.

Fix: classify inside the rq lock, immediately before the enqueue it authorises. Where Linux
waits with `smp_cond_load_acquire`, this defers to the owner's wake-list — an unbounded cross-CPU
spin under a held rq lock AB-BAs against a peer balancer wanting that same lock (the `-smp` hang
the wake-list exists to avoid). Deferral loses no wake.

### 9.3 Same-family deviations fixed in the same PR

| # | Site | What it did | Linux |
|---|---|---|---|
| 1 | `switch.rs` `oxide_finish_task_switch` | released the rq lock BEFORE clearing `prev->on_cpu` | `finish_task(prev)` runs before `finish_lock_switch(rq)`; core.c: `on_cpu` is set and cleared "both under rq->lock" |
| 2 | `zombies.rs` `wake_wait4_parent` | `claim_wake` then raw `inner.enqueue` on the CALLER's rq — no `on_cpu` handshake, no `select_task_rq` | `try_to_wake_up` → `smp_load_acquire(&p->on_cpu)` → `ttwu_queue_wakelist(p, task_cpu(p), …)` |
| 3 | `sigpend.rs` `unfreeze_task` / `freeze_task` | thaw raw-enqueued on the caller's rq; freeze removed from the caller's rq only, so a task queued elsewhere stayed runnable | thaw goes through ttwu placement; freeze under `task_rq_lock(p)` |
| 4 | `balance.rs` | migrated the leftmost CFS task with no running check | `can_migrate_task`: `if (task_on_cpu(env->src_rq, p) …) return 0` (`kernel/sched/fair.c`, `nr_failed_migrations_running`) |

### 9.4 Evidence

Hosted, deterministic, no boots. `tests/queues.rs`:
`a_task_being_switched_to_is_never_reported_enqueueable` asserts `pending_wake` reports `Defer`
at every point after the claiming pick; `probe_detects_the_pre_fix_pick_then_claim_window` runs
the pre-fix order and asserts the reader falsely observes `Ready` in between, so the first test
cannot be vacuous. The wake-path deviations get a two-CPU model over real `Runqueue`s with an
injected CPU→rq accessor (the `rq_locate` split from B1467, now applied to
`ttwu::place_runnable_with` / `select_task_rq_with`);
`live/zombies/tests.rs::wake_wait4_parent_defers_a_parent_that_is_still_on_cpu` fails against the
pre-fix `wake_wait4_parent` and passes after (verified by reverting).

Boot measurement used a non-fatal probe at the `RunqueueInner::enqueue` chokepoint, so a PASSING
boot still reports whether a live task was enqueued. `live-gnome` x86 SMP=2:

| build | boots | ownership panics | live-task enqueues caught |
|---|---|---|---|
| §9.1 fix only | 4 | 1 | 2 |
| §9.1 + §9.2 | 6 | 0 | 0 |

The probe going to zero is the direct signal; the panic is only its fatal tail.

## 10 Open after the desktop-blocker chain (2026-07-28)

Found while verifying the gdm/udev fix. None has a lane.

| # | Item | Evidence | Owner |
|---|---|---|---|
| 1 | `[BUG] exit_to_user_mode_loop: work never cleared` — the pass-bound bail-out in `B1471`'s return-to-user work loop | 2 of 17 `live-gnome` boots. Trips `boot-smoke`'s `[BUG]` fail marker, so it presents as an intermittent smoke failure unrelated to whatever is under test. Not A/B'd against clean `main` — too rare to settle in a few boots | sched/syscalls |
| 2 | `[CPU-STALL] cpu=0 no heartbeat for 18s (seen by cpu=1)`, `nr_running=9`, NMI backtrace at `rip=ffffffff8019407e` | Own `live-gnome` SMP=2 run, ~503s guest. Distinct from the `on_cpu` ownership race (`B1473`), which this tree already carries | sched |
| 3 | **SIGABRT does not kill a threaded process** | glibc `abort()` reaches `ABORT_INSTRUCTION` (`hlt` → #GP → SIGSEGV) only when *both* `raise(SIGABRT)` calls return. gdm died `11/SEGV`, not `6/SIGABRT` | sched signals |
| 3b | ~~`accounts-daemon` never signals READY within systemd's 90s start timeout.~~ **ROOT-CAUSED + FIXED — `B1475`.** Not accountsservice-specific and not D-Bus activation: `udisks2`, `upower`, `rtkit-daemon`, `switcheroo-control`, `polkit` and `systemd-hostnamed` all blow the same 90s timeout on the same boot. Split of the interval (`debug-execload` + a new `debug-startlat` >50ms dispatch probe): of 158s measured, **127s is BEFORE the binary is exec'd** — it is `systemd-executor` building the unit's sandbox (`ProtectSystem=strict`, `ReadWritePaths=`, `PrivateDevices=`, `PrivateNetwork=`), where every `mount(2)` is followed by a `/proc/self/mountinfo` re-parse. Renders of that file measured 267 ms for 59 rows. Root cause is one level down: kalloc's sorted hole list is O(N) on BOTH `alloc` (first fit) and `dealloc` (ordered insert), so an alloc+free pair costs **21 ns on a clean heap and 128 µs once ~20 000 holes exist — 6000×** (hosted probe on a 64 MiB heap). Every allocation-heavy kernel path paid it; a single `format!` in the mountinfo row loop cost 1.97 ms. Fixes: (a) `kmalloc` size-class front end (`kalloc/sizeclass.rs`, Linux `mm/slub.c` shape) → fragmented alloc+free back to **20 ns**; (b) mountinfo field 4 via the `d_parent` walk Linux uses (`show_path`→`dentry_path`) instead of two global `absolute_path()`s, each of which linearly scanned the system-wide mount table; (c) `/proc/*/mountinfo` renders on first read, not at open (Linux `seq_open` renders nothing) — an open+read-at-0 was doing TWO full renders | mm/kalloc, procfs |
| 4 | Serial RX duplicates bytes under load (`xsessions` → `xsessiions`); typed bursts twice ended in `#DF` inside `sched::diag::emit::sysrq_rx` | Observed from the guest debug shell | drivers/tty |
| 5 | ~~**`debug-boot` tracing is now self-defeating.**~~ **FIXED — `B1474`.** Root cause was broader than the serial volume: `debug-boot` had become the junk drawer for every campaign trace, and `make qemu-*` sets it unconditionally. `[SIGDELIV]`, `[USTACK]`, the `trace_mutter_syscall` ledger (twice per syscall), `trace_logind_dev` (an extra `read_user_path` per `openat`), `[MUTTERWAIT]` (per deadline park) and `[B288 dgram]` (a full ~14-field journald record per log line) each paid a `with_exe_path` lock + substring scan on their hot path even when nothing printed. Split into `debug-sigdeliv` / `debug-ustack` / `debug-desktop` / `debug-execload` / `debug-journal` / `debug-taskdrop` / `debug-faultdiag`; nothing removed. A/B on the same `live-gnome` x86 boot: `graphical.target` **509.5s guest / 550s wall → 265.9s / 305s**; `basic.target` 72.5 → 46.2s; serial 8900 → 4270 lines. **Trap found while verifying:** `boot-smoke`'s `Reached target basic.target` marker is delivered BY `[B288 dgram]` — systemd's own console output stops once journald starts — so that trace stays on `debug-boot`, narrowed to each record's `MESSAGE=` line | observability |
| 6 | ~~klog interleaving~~ **FIXED — `B1474`.** Not interrupt context specifically: the console owner lock serialised each `emit_bytes_at` CALL and every trace site builds one line from many calls, so the lock was dropped between fragments and ANY two emitters spliced. klog now assembles per-CPU line buffers keyed by a caller identity and publishes a completed line in one fan-out (Linux `LOG_CONT` / `prb_reserve_in_last`). Splice signature `<token>=[TAG` on the same `live-gnome` boot: **37 → 0** (`origin/main` sample: `[EXECLOAD begin tid=[EXECLOAD ready tid=41124114`, tids 4112/4114 interleaved; also `accounts-daemon[162]: started daemon version 25.05.0[TASK-DROP] tid=`) | klog |

### Measurement traps confirmed here

- `SMOKE_KEEP_LOG` retains only the **last** attempt's log, while a panic appears in the **failing** attempt's dump inside boot-smoke's own output. Reading only the kept log makes a real panic look like a plain timeout — this nearly produced a false retraction.
- Marking on a process name (`SMOKE_MARKER='gnome-shell'`) is unmeasurable when that process prints nothing to serial. The reliable check is the sysrq task dump boot-smoke injects on timeout, or `ps` from `systemd.debug_shell=ttyS0`.

## 12 B1478 — security controls that reported success while enforcing nothing

Branch `B1478-security-enforcement`. Four controls whose callers built on a
guarantee the kernel never delivered. Each is worse than an unimplemented
feature, because userspace treats the success return as enforcement.

| # | Control | What was actually unenforced | Linux rule mirrored |
|---|---|---|---|
| 1 | `openat2` `RESOLVE_*` | `O_CREAT` branch built its parent walk from `LookupFlags::default()`, dropping every scoping bit | `fs/open.c build_open_flags` folds all six into ONE `op->lookup_flags`; `fs/namei.c path_openat` uses it for both walk phases |
| 2 | `userfaultfd` | `UFFDIO_COPY`/`ZEROPAGE` installed USER\|RW at any VA with no VMA and no registration — an arbitrary-write primitive; no creation gate at all | `mm/userfaultfd.c validate_dst_vma`, `find_vma_and_prepare_anon`, `userfaultfd_syscall_allowed` |
| 3 | mount flags | `graft_mount` passed a hardcoded `0` as `mnt_flags`; `MNT_LOCK_*` did not exist; `require_sys_admin()` was a flat effective-set test | `fs/namespace.c path_mount`, `lock_mnt_tree`, `may_mount`; `fs/super.c mount_capable` |
| 4 | `seccomp` | `RET_TRACE`/`RET_LOG` failed OPEN — a filter denying by tracing was a no-op | `kernel/seccomp.c __seccomp_filter` |

### 12.1 Corrections to the source audit

The audit rows were treated as claims to disprove. Four were wrong:

- **`fs/userfaultfd.c` does not exist in v7.2.0-rc4.** userfaultfd is entirely
  in `mm/userfaultfd.c`. Any row citing the old path was not read against this tree.
- **`validate_dst_vma` tests `vm_userfaultfd_ctx.ctx` for NON-NULL, not identity**
  with the calling ctx. The identity test is MOVE-only (`validate_move_areas`).
  There is likewise no `ctx->mm != current->mm` check outside `userfaultfd_move`.
- **Mount binds are not a gap.** `path_mount` DISCARDS `mnt_flags` for `MS_BIND`
  (`return do_loopback(path, dev_name, flags & MS_REC)`) and the clone inherits
  from its source. `mount --bind -o ro` does not make a ro bind upstream either.
- **A tracerless `SECCOMP_RET_TRACE` does not act as `RET_KILL_THREAD`.**
  `kernel/seccomp.c __seccomp_filter` sets the return value to `-ENOSYS` and
  `goto skip` — the task LIVES. `RET_LOG` likewise does not "fail open": it IS
  an allow-after-audit action. And the filter chain WAS already cloned on fork;
  only `seccomp_mode` was not, which produced the same escape by a different
  route.
- **`RESOLVE_BENEATH` was not the escaping flag.** Only `RESOLVE_IN_ROOT`
  produced a live escape: it is the sole scoping bit that CLAMPS rather than
  errors, so the scoped walk returns ENOENT and hands control to the unscoped
  create path. BENEATH/NO_SYMLINKS/NO_XDEV all abort earlier with
  EXDEV/ELOOP/EXDEV — incidentally covered, never enforced.

### 12.2 Method note

Every fix carries a NEGATIVE assertion (the escape is refused, the unprivileged
call is denied, the flag is honoured), because a happy-path test passes a
control that enforces nothing — which is how all four shipped. Causality was
verified by reverting each production edit and confirming the specific tests go
red, not by asserting that new tests pass.
