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
