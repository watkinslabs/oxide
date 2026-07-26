# HANDOFF — road to a graphical GNOME boot

Written 2026-07-26. Baseline `main` @ `5458d241e`.
This file is the complete handoff. Companions: `fixplan.md` (execution ledger),
`broke.md` (evidence for every claim). If they disagree with this file, this
file is newer — reconcile, do not guess.

---

## 0. ANSWER FIRST: is GNOME booting?

**No.** The desktop does not come up. Do not let anything below read as
"nearly there" — measure before believing.

Hard evidence, last boot (`scratchpad/gnome3.log`, `live-gnome` x86_64, SMP=1, KVM):

| Fact | Evidence |
|---|---|
| `graphical.target` NEVER reached | appears exactly once, `[5.982] Queued start job for default target graphical.target` — no "Reached target" line anywhere |
| `gnome-shell` NEVER executed | 0 occurrences in the whole log |
| last processes | `gdm`, then `plymouth` |
| gdm state | started at 367 s after failing once (`restart counter is at 1`) |

**Unmeasured, and it matters:** the capture window ended at 377 s of guest time
— only ~10 s after gdm started. Whether gdm then crash-loops again is **not
known**. That is the first thing to measure, with a longer window. Do not
assume it is fine.

---

## 1. What changed — the wedge is fixed

The machine used to die at 191 s. It now survives.

| | before | after |
|---|---|---|
| survived to | **191 s, dead** | **377 s, no wedge** |
| soft lockups / no-progress dumps | 1 / 1 | **0 / 0** |
| targets reached | `basic.target` | + `network.target`, `network-online.target`, `multi-user.target` |
| gdm | never started | `Started gdm.service`, `/usr/bin/gdm` exec'd |

### Root cause (W1) — RTNL was a spinlock

`rtnl_lock()` in Linux is `mutex_lock(&rtnl_mutex)` — a **sleeping mutex**.
Ours was a `Spinlock`.

RTNL holders legitimately block: they allocate, call into drivers, wait on
devices. Under a spinlock a sleeping holder puts every other acquirer into an
unbounded spin — and because this kernel **does not preempt kernel mode**
(`oxide_irq_resched_on_exit` gates on `should_resched_to_user`), the spinner
then owns the CPU forever, so the sleeping holder can never be rescheduled to
release it. Deadlock, permanent.

Observed: `ktimers` firing `ipv6_control_tick` spun on RTNL while
NetworkManager held it across a sleep. 0 context switches for 40 s.

**How it was found — reuse this method.** A task dump can only ever name the
*kthread*, which for a timer wedge is always `ktimers`; it can never name the
callback that hung. `timer::run_state` (merged) makes `run_due` record its
phase and the executing callback's address, printed by the soft-lockup
watchdog. One boot gave `timer_phase=fire-periodic timer_fn=0xffffffff80202ff0`
→ `net::ipv6_control_timer`. Cost: two relaxed stores per fired timer.

**Trap that cost time:** resolve such an address against the ELF that was
ACTUALLY booted (`target/builds/<id>/.../oxide-x86_64`), not
`target/artifacts/...`. `make qemu-x86` builds with `--features debug-boot`, a
different binary with a different layout. The wrong ELF gave a symbol 17 KB
away and a false answer.

**Wrong turn, recorded so it is not repeated:** I first theorised a preempted
lock holder and dismissed the whole class after finding kernel mode is never
preempted. That was right about *involuntary* preemption but too broad — a
holder that *voluntarily sleeps* produces the identical deadlock. That is what
this was.

### Prerequisites that had to land first

A sleeping lock must never be reachable from softirq. All RTNL call sites were
audited: **78 process-context, 0 hardirq, 0 under-spinlock, 4 softirq-reachable**.

| # | Site | Fix |
|---|---|---|
| W1-a | `net/src/stack_igmp.rs` `handle_igmp` | RX no longer takes RTNL |
| W1-b | `net/src/stack_ipv6/mld.rs` `respond_mld_query` | RX no longer takes RTNL |
| W1-c | `net/src/mcast_filter.rs:432` via `InetSocket::Drop` | final release deferred out of softirq |
| W1-d | `net/src/sock/packet_membership.rs:84` via `InetSocket::Drop` | same |

W1-a/b were smaller than expected: both took RTNL *only* to read the interface
multicast generation, and that read never needed it —
`control_generation_in_ns` uses the guard purely as a `guard_matches`
discipline token while the data is protected by the interface table's own lock.
Linux reads device state in RX under RCU, never `rtnl_lock()`.

W1-c/d were a real race, not hypothetical: `sock/packet.rs::deliver()` runs in
the NetRx softirq holding temporary `Arc<InetSocket>` clones from
`Weak::upgrade()`; if the owner closes the fd mid-flight, `deliver()`'s locals
drop the **last** reference from softirq. Linux never destroys a socket in
softirq (`__sk_destruct` runs from an RCU callback).

**Design decisions to preserve:**
- `rtnl_lock()` stayed a SAFE wrapper rather than `unsafe`. Marking it unsafe
  would churn 117 call sites and push the obligation onto every caller where it
  would rot. The contract is carried by the audit and stated at the single
  acquisition point.
- Hosted builds keep a spinlock, at a module boundary (`mod imp`). `sched::live`
  does not exist off the kernel target — there is no scheduler to sleep on —
  and hosted tasks are real OS threads, so the exclusion contract under test is
  identical.
- `rtnl_trylock()` was added (Linux has it) for callers that should skip a round
  rather than queue behind a long control-plane operation.

---

## 2. THE NEW WALL (W2) — start here

With the machine alive, the real desktop blocker is visible for the first time.
gdm starts, then restarts, because the services it depends on **start and hang**
until their unit timeout. None of them crash.

| Unit | Symptom | Count |
|---|---|---|
| `upower.service` | start operation timed out | 3 timeouts / 5 "Failed to start" |
| `polkit.service` | Failed to start | 2 |
| `accounts-daemon.service` | start operation timed out | 2 |
| `udisks2.service` | start operation timed out | 1 |
| `switcheroo-control.service` | start operation timed out | 1 |
| `rtkit-daemon.service` | start operation timed out | 1 |

**All six are D-Bus-activated system daemons and all six fail identically.**
That is one shared stall, not six bugs. Chase the common mechanism — D-Bus
activation, af_unix accept/readiness, or a syscall that never returns — NOT the
individual services.

Prior art in `broke.md`: an earlier session measured
`StartServiceByName(org.freedesktop.hostname1)` timing out at 25 s, and the
af_unix→epoll notify PATHS were confirmed to exist (`wake_peer_subs` →
`notify_epoll_waiters`); the open question was promptness, not existence.

Suggested method, in order:
1. Longer boot window (>600 s) to learn whether gdm crash-loops indefinitely.
2. Pick ONE hung daemon, find its last syscall before the stall (`debug-dbus`,
   `debug-syscall`, `debug-wakelat` features exist).
3. Prefer a hosted harness over boots — see the rules in §5.

---

## 2b. W2 investigation log — hypotheses KILLED (do not re-run these)

Each of these cost real time. They are recorded so nobody re-derives them.

| # | Hypothesis | Verdict | Evidence |
|---|---|---|---|
| H1 | exec is slow | **DEAD** | `EXECLOAD begin→ready` median **23 ms**; ALL exec in a whole boot sums to **14.8 s** |
| H2 | CPU is busy during the gap | **DEAD** | 297 log lines in a 96 s window |
| H3 | `preempt_count` leak (idle loop's own documented failure mode) | **DEAD** | boot with `debug-preempt`: **zero** `[PREEMPT-LEAK]` reports |
| H4 | the intermittent 40 s parked wedge causes the gaps | **DEAD** | a boot with **zero** `no-progress`/`soft lockup` events still showed the identical gaps |
| H5 | gap scales with number of sandbox directives | **DEAD** | `rtkit` has 2 directives → 1 quantum; `accounts-daemon` has 1 → 3 quanta |
| H6 | `PrivateNetwork` → `CLONE_NEWNET` → RTNL sleeping-mutex block | **DEAD as sole cause** | **4 of the 6 slow units do not set `PrivateNetwork` at all** — including the two slowest (`accounts-daemon` 99 s, `systemd-logind` 97 s). Verified by reading the real unit files out of the rootfs image with `debugfs` |
| H7 | eventfd/pipe lost-wakeup race is the mechanism | **UNLIKELY** | the race is REAL (fix in `B1422`) but needs SMP>1; our boots are `SMP=1` (`Makefile: SMP ?= 1`). Also a true lost wake parks **forever**, not 33 s |

### Measurement traps hit (both cost time)

- **"Only N log lines ⇒ idle" is not sound.** It only says few *traced* things happened. Verify with a feature that traces the suspected subsystem before concluding idleness.
- **`debug-mount` traces `MUNMAP`, not filesystem mounts.** Do not use it to look for mount-tree activity. Its output is `[mnt] MUNMAP addr=...`.
- **Heavy trace features distort the thing being measured.** A `debug-mount` boot reached only **t=42 s of guest time in 300 s of wall clock**, never reaching the 33 s gap window. Pick a narrow feature or raise the wall-clock budget.

### What still stands

- The gap is between systemd forking its `sd-executor` helper and that **same tid** calling `execve` — confirmed by tid correlation (rtkit helper forks t=25.9 s, execs t=58.2 s, silent in between).
- The discriminator is **any sandboxing at all**: `udisks2.service` is `Type=dbus`+`BusName`, forks identically, carries **zero** sandbox directives, and is fast (~7 s). All six slow units carry at least one of `PrivateNetwork` / `PrivateTmp` / `ProtectSystem`.
- Therefore the common path is `CLONE_NEWNS` + mount-namespace setup, NOT the network namespace.
- Exec ORDER is monotonic (rtkit 58.2 → switcheroo 106.6 → upower 124.7 → accounts 132.9 → logind 146.5) while start order is not — consistent with a queue draining at a fixed rate, or with per-namespace cost growing as namespaces accumulate.

### Next measurement (unblocked, not yet run)

`debug-dbus`/`debug-cgroup` were BROKEN by the comm change and are now repaired (`#3972`). The decisive step is still: capture the stuck tid's actual blocking syscall between its two execs, with a NARROW trace feature and a wall-clock budget large enough to reach t>60 s.

## 3. Merged this session (all on `main`)

| PR | Branch | What | Verified by |
|---|---|---|---|
| #3958 | `F718-timer-softirq` | softirq `timer_list` + threaded IRQ handlers | 229 tests, x86 boot |
| #3959 | `F719-zstd-in-tree` | in-tree Zstandard codec (`crates/shared/zstd`) | conformance vs reference, both directions |
| #3960 | `F720-zstd-zram` | zram on it; vendored codec out of the kernel build | **0 kernel frames ≥8 KiB** (was 6) |
| #3961 | `B1407-openat-absolute-dirfd` | `openat` must ignore `dirfd` for absolute paths | 5 hosted tests, fails-before/passes-after |
| #3962 | `B1409-sock-drop-softirq-defer` | socket destruction deferred out of softirq | 988 net tests |
| #3963 | `B1408-ktimers-rtnl-mutex` | **RTNL → sleeping mutex** + timer instrumentation | boot 191 s→377 s, 0 wedges |

Notes worth keeping:
- The zstd conformance test (encode ours→decode reference, and the reverse, all
  levels, every length 0..=4096) found **three real bugs** a self-round-trip
  could never catch: the RFC match-length distribution has **seven**
  low-probability entries not five (both sum to 64, so the wrong table built
  cleanly and decoded every long match wrong); the Huffman table is laid out by
  **ascending** weight (the mirror layout is also a valid prefix code, so it
  decoded into a permuted alphabet rather than failing); and the FSE weight
  stream terminates one symbol pair earlier than written.
- The vendored `structured-zstd` remains ONLY as a dev-dependency oracle for
  that test. It is out of the kernel build entirely. Deleting
  `vendor/rust/structured-zstd-0.0.49` now costs only that test — **the user's
  call, not ours.**
- `#[inline(never)]` was tried first on the 6 oversized vendored frames and
  split **none** of them. Replacement, not a workaround, is what closed it.

---

## 4. Everything still broken — full inventory

Counts are real, taken from the trackers on 2026-07-26.

### 4a. Security holes — unprivileged process can own the box

These are real privilege escalations with file:line evidence, not theory.

| # | Defect |
|---|---|
| S1 | `ptrace` performs **zero** permission checks on every request — ATTACH, PEEK/POKE, GETREGS/SETREGS, KILL, SINGLESTEP. Any unprivileged process can read/write memory and registers of, or kill, any process including root's. The correct pattern already exists in the same crate (`ptrace_fpu.rs:113,153` check `traced_by` + `Stopped`) and was never propagated. `101_ptrace.rs` |
| S2 | `keyctl`/`add_key`/`request_key` never enforce key permission bits or possession; `perm` is stored and reported but never read for enforcement. Serials climb sequentially from `0x1000_0000` — trivially enumerable. Full keyring bypass. `fs/src/keyring.rs` |
| S3 | `rt_sigqueueinfo`/`rt_tgsigqueueinfo` skip `sig_perm_check`, which sits directly above them and IS used by `kill`. Arbitrary signal injection with spoofed sender identity. `signal_common.rs:39` |
| S4 | `prlimit64` rewrites any process's rlimits with no `CAP_SYS_RESOURCE` or uid check. `302_prlimit64.rs:19` |

### 4b. Desktop-relevant correctness

| # | Defect |
|---|---|
| D1 | `mount -t cgroup` (v1) returns **success without mounting anything** (`"devpts" \| "cgroup" => 0`). systemd mounts cgroup v1 hierarchies. `fsmount_common/mount_ops.rs:26` |
| D2 | `prctl(PR_SET_NAME)` is a no-op — the name pointer is never read, so `pthread_setname_np()` and every systemd thread rename silently do nothing. `sched/src/prctl.rs:64` |
| D3 | `PR_SET_DUMPABLE` no-op, `PR_GET_DUMPABLE` always 1 — compounds S1 |
| N6 | Ether NICs register with `IFF_UP` **hardcoded**; Linux registers carrier-only and lets userspace bring the link up. Fix exists at `archive/B1378-remove-boot-ip-seed-hack`; the boot IP-seed hack must die in the same change. **RE-TEST FIRST — see §6.** |

### 4c. Linux-shape violations

| # | Defect |
|---|---|
| S5 | `membarrier` is `{ 0 }` — argument never bound. `CMD_QUERY` reports nothing supported while barrier commands report success, on an SMP-capable kernel |
| S8/S9 | `io_uring_setup` never reads the params struct (`IORING_SETUP_SQPOLL` silently ignored); `io_uring_enter` binds `min_complete`/`flags` to `_` so `IORING_ENTER_GETEVENTS` returns instantly instead of waiting |
| N1 | `TtyStruct.fg_pgrp` has three driver-side shadow copies synced by hand, plus a second unreachable `TIOCSPGRP` path that updates only the core. Linux has one field |
| N2 | configfs `CREATED: BTreeMap<String, usize>` keyed by FULL path, duplicating the kernfs tree; `child_has_children` does a prefix-string scan. Linux has one tree |
| N3 | Root device falls back to `first_device` — an arbitrary disk — when the `oxide-root` serial is absent. Linux resolves `root=` one way and panics otherwise |
| N4 | `notify_change` silently no-ops chmod/chown on `is_public_device()` inodes |
| F1 | futex PI ops (`LOCK_PI`/`UNLOCK_PI`/`TRYLOCK_PI`/`*_REQUEUE_PI`) fall into `_ => 0` — `PTHREAD_PRIO_INHERIT` mutexes believe they locked something never arbitrated |
| F2 | `mlock` family never enforces `RLIMIT_MEMLOCK` or `CAP_IPC_LOCK` |
| F3 | `SO_SNDBUFFORCE`/`SO_RCVBUFFORCE` take the non-FORCE path with no `CAP_NET_ADMIN` check |
| F4 | `sigaltstack` rejects nothing — no unknown-flag, `MINSIGSTKSZ`, or on-stack check |
| F5 | `statmount` hardcodes `MNT_ROOT` to `"/"` — bind mounts misreport, breaking `findmnt`/libmount |
| F6 | `fcntl(F_SETLKW)` busy-spins through `schedule()` instead of parking on a wait queue |
| F7 | `SCHED_DEADLINE` returns `EOPNOTSUPP`; `SCHED_RESET_ON_FORK` is masked off and discarded |
| F8 | `file_getattr` zero-fills while `ioctl(FS_IOC_GETFLAGS)` really reads ext4 `i_flags` — two syscalls, same state, different answers |
| F9 | `clone(CLONE_CHILD_SETTID)` only writes the TID when `CLONE_VM` is set |
| F10 | `open_by_handle_at` only checks the inode cache — evicted-but-valid handles wrongly get `ESTALE` |
| F11 | `seccomp(GET_ACTION_AVAIL)` never reads the queried action; every value reports available |
| F12 | `TCP_INFO` fills ~13 fields and zeroes the rest, with a test asserting the zero tail. `ss -i` always shows no traffic |

### 4d. Our own gates are not trustworthy

| # | Problem |
|---|---|
| X1 | `cargo test -p vfs --test dcache_drop_unhash` :: `freed_dentry_is_not_resurrected_from_bucket` **fails on clean `main`** |
| X2 | `net` :: `unix_sock::tests::scm_gc::newer_observer_cannot_reblock_released_generation` fails in the full suite, passes 3/3 isolated — order/parallelism flake. `arp::ioctl::*` is similarly flaky |

Fix these before trusting any "tests pass" claim.

### 4e. Doc lies — cheap, and they cause future bugs

`258_mkdirat.rs:23` claims "Ignores dirfd" (it honours it) · `vfs/src/setattr.rs:130,201`
and `perms_common.rs:62` describe a chmod/chown overlay removed by D17 ·
`062_kill.rs:10` says `kill(-1)` unimplemented (fully implemented) ·
`101_ptrace.rs:24-32` calls four requests stubs (all real) · `271_ppoll.rs:12`
says sigmask is a follow-up (real swap-and-restore) ·
`145_sched_getscheduler.rs:8` says 144 is a no-op (it applies the policy) ·
`055_getsockopt.rs:20` claims silent zero-fill (~40 options handled correctly).

### 4f. Standing campaigns

| Tracker | Real state |
|---|---|
| `syscall-compliance-matrix.md` | 385 rows: 45 `IMPL`, 116 `PARTIAL`, 207 `NEEDS-AUDIT`, 18 correctly `ENOSYS`, 7 in-progress, **1** `DISPATCH-GAP`. Read correctly: 207 unaudited ≠ 207 broken, and exactly one row has no route at all. The work is proving/finishing semantics, not adding syscalls |
| `network-plan.md` | 128 items: 103 merged, 16 `[~]`, 9 `[ ]`, 0 blocked |
| `ext4fix.md` | 9 real items — jbd2 checksums (descriptor UUID still hardcoded `SAME_UUID`), backup SB/GDT sync, `inline_data`, `COLLAPSE`/`INSERT_RANGE`, mballoc, jbd2 batching, flex_bg parse, **POSIX ACLs stored but never enforced**, dx_tail verify |
| `tcp-edge-inventory.md` | all 10 rows open |
| `console2.md` | SOW-2/3/4 open (boot-gated) |
| mount rows | 165, 166, 428-433, 442, 457/458, 467 still `PARTIAL` |

---

## 5. Rules learned the hard way — obey these

1. **Verify left.** A hosted `cargo test` harness driving real code is the inner
   loop. A QEMU boot is the FINAL gate, never the dev loop. Boots are ~4 min.
2. **Never boot-per-hypothesis.** If you have booted twice to chase one bug, the
   loop is the problem — instrument or build a harness instead. Instrumentation
   named the RTNL wedge in ONE boot after multiple sessions of theorising.
3. **Resolve addresses against the ELF that actually booted** —
   `target/builds/<id>/...`, not `target/artifacts/...`. Different features,
   different layout, false answers.
4. **`xtask kernel` does not export.** `xtask artifacts --arch <a>` is a separate
   step. Building without it boots a STALE kernel and invalidates the result.
5. **Fresh `main` before branching; always commit → push → PR → merge.** Do not
   leave PRs open.
6. **The `metadata/index.md` counter is NOT collision-safe under fan-out.** A
   parallel agent reads the stale value until your bump is *merged* — that is
   how two lanes both took B1407 this session. Merge the bump early, or assign
   counters centrally.
7. **Fan out read-only audits aggressively** — they are cheap and they found the
   security holes, the stale trackers, and the RTNL call-site classification.
   Give each a precise output contract and tell them to omit rather than guess.
8. **Sandbox cannot kill processes.** Never launch background boot retry-loops;
   leaked `qemu-system` foul every later boot (port 2222 / KVM). Run boots
   strictly sequentially.
9. A flaky ~8-line "boot" is a GRUB hang, not a result. A real boot is >2000
   lines. Re-run once.

---

## 6. Order of work for whoever picks this up

1. **W2 — the six hanging D-Bus daemons.** One shared stall. Start with a
   >600 s boot to learn whether gdm crash-loops forever, then trace ONE daemon's
   last syscall. Everything else is behind this.
2. **Re-test N6 before "fixing" it.** `network-online.target` now completes,
   which means NetworkManager finishes. The long-standing "NM never manages
   eth0" symptom was at least partly the RTNL wedge, not solely the hardcoded
   `IFF_UP`. Measure against this baseline first or you will fix something that
   already works.
3. **X1 + X2** — make the vfs and net suites green so "tests pass" means
   something.
4. **Phase 2 security holes (S1-S4)** — independent of the boot, each a
   self-contained lane, each hosted-testable.
5. **D1/D2** — most likely to matter to systemd and the desktop.
6. Then the standing campaigns in §4f.

Do not re-litigate: string-path filesystem resolution was swept on 2026-07-26
and is clean — what remains is correct Linux behaviour (dentry children keyed
by a single NAME component IS the dcache) or debug-gated logging. The table in
`broke.md` §1b records exactly what was checked.
