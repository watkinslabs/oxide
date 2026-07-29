# What is actually broken — inventory 2026-07-26

Goal this serves: **boot the glibc GNOME image to a visible graphical session.**
Everything below is ranked by whether it blocks that, not by how large it is.

Baseline: `main` @ `cf25080f3`. Evidence for the boot rows is a live
`live-gnome` x86_64 capture from this date (`scratchpad/gnome1.log`, 2.9 GB
Fedora image, SMP=1, KVM).

## 0. The wall — the machine stops before gdm

| # | Symptom | Evidence | Status |
|---|---|---|---|
| W1 | **ktimers soft lockup → whole-machine wedge at ~191 s** | `[201.156] [WATCHDOG] soft lockup: no reschedule for 10s on tid=4096 (ktimers)`, then `[231.159] no-progress: 0 context switches for 40s`. Serial output stops entirely at 231.4 s. | **OPEN — top priority** |

What the two dumps prove, 30 s apart:

- `switches=9646` is **identical** in both. Not slow — stopped.
- `current=tid:4096` (ktimers), `ST=R`, `onrq=n`. It is on-CPU and never leaves.
- `ksoftirqd`, `netns_reaper`, `init`, `systemd-journald`, `dbus-broker`,
  `dbus-broker-launch`, `nm-dispatcher` are all `R` + `onrq=y` — runnable,
  queued, and never scheduled.
- The watchdog itself still prints, so **timer IRQs are still arriving**. The
  tick runs; the switch never happens.

Ruled out already:

- *Preempted lock holder.* `oxide_irq_resched_on_exit` gates on
  `should_resched_to_user(from_user)`, so a kernel-mode holder is **never**
  involuntarily preempted. The classic UP spin-deadlock cannot be this.
- *Slow scan.* `tick_wake_expired` is O(N_tasks) over ~200 tasks. Not 40 s.

So ktimers is inside `run_due` (or the reaper) and never reaches its
`schedule()`. Remaining candidates: a spin on a lock whose holder slept while
holding it, or a non-terminating loop in the deadline walker. **Next action: GDB
backtrace of CPU0 at the wedge** — that names it outright rather than guessing.

Related but NOT the same bug — the ktimers wedge fixed in B1348 was *circular
waker* (ktimers parked forever). This one is the opposite: ktimers is RUNNING and
will not yield. A past-due-and-parked ktimers is B1348; a running-and-stuck
ktimers is W1.

## 1. Confirmed Linux-compat defects found on the way

| # | Defect | Evidence | Cost |
|---|---|---|---|
| L1 | `openat` validates `dirfd` **before** checking whether the path is absolute. Linux ignores `dirfd` entirely for absolute paths (`path_init` returns early). An absolute path with a non-directory `dirfd` wrongly returns `ENOTDIR`. | `[ENOTDIR] op=resolve_at_path why=dirfd-base tid=4236 dirfd=0 raw=/run/ConsoleKit/database` — fd 0 is `/dev/null`. `crates/kernel/syscalls/src/pathresolve/at.rs:25` `dirfd_base()` | small fix, 1 hit this boot |
| L2 | `Spinlock::lock()` does not disable preemption. Linux `spin_lock()` is `preempt_disable()` + spin. Harmless *today* only because the kernel never preempts kernel mode — it becomes a live deadlock the moment involuntary kernel preemption is enabled. | `crates/shared/sync/src/lib.rs:287` | latent, blocks future preemption work |

`walk()` already resets to root for absolute paths and already returns `EXDEV`
for `RESOLVE_BENEATH`, so L1's early `dirfd` check is pure loss — no behaviour
depends on it.

## 1b. String-path resolution — swept 2026-07-26, essentially clean

The user flagged leftover "shitty string path filesystem resolution". Swept
`crates/kernel/` + `crates/drivers/` for full-path string matching that drives
SEMANTICS. Result: the removal really did land. What remains is benign:

| Site | Verdict |
|---|---|
| `vfs/src/dentry.rs:100` `children: BTreeMap<String, Arc<Dentry>>` | **correct** — a dentry's children keyed by ONE name component is exactly Linux's dcache. Not a full-path key. |
| `syscalls/src/{083_mkdir,090_chmod,092_chown,260_fchownat,268_fchmodat,...}.rs` `raw.starts_with("/run")` | **benign** — inside `#[cfg(feature = "debug-mount")]`/`debug-udevdb`; selects what to LOG, never what to do. |
| `sched/src/trace.rs:27` `path == "/usr/lib/systemd/systemd"` | **benign** — selects which process to TRACE under `debug-gnome-syscall`. Comment already explains it keys on executable+credential, not a fixed pid. |
| `vfs/src/namei/lookup.rs:102` `if path == "/"` | **correct** — Linux special-cases the root component too. |

No full-path-keyed map and no path sniffing that changes behaviour was found
outside debug gates. Keep this table so a future sweep does not re-litigate it.

| # | Defect | Evidence | Cost |
|---|---|---|---|
| L3 | `mkdirat` doc-comment claims "Ignores dirfd (paths resolved absolute or cwd-relative)". The CODE passes `args.a0` to `resolve_create_parent_at`, so it honours dirfd correctly. The comment is simply false and will mislead the next reader into "fixing" working code. | `crates/kernel/syscalls/src/258_mkdirat.rs:23` | doc-only, trivial |

## 1c. Non-Linux shapes — swept 2026-07-26

Audit of `crates/kernel/` + `crates/drivers/` for parallel registries, shadow
state, full-path string keys, process-name special-casing and fallback lookups.
Debug-gated tracing excluded (it selects what to PRINT, never what to DO).

| # | Defect | Where | Linux does | Sev |
|---|---|---|---|---|
| N1 | `TtyStruct.fg_pgrp` is documented as sole truth, but `VtConsoleDriver`, `SerialTtyDriver` and the static console each keep an independent `fg_pgrp` shadow so `signal_fg_pgrp` can target a pgrp without a back-pointer. Every live site updates both by hand. Worse, `tty/src/ioctl.rs:95` has a SECOND generic `TIOCSPGRP` handler that updates only the core — currently unreachable (VT/serial hand-code the dual update in `016_ioctl/tty_ioctl.rs`), so dead code today, but it silently diverges core from signal-target the moment anything calls it. | `tty/src/core/tty.rs:431`, `console/src/vt_tty.rs:43`, `serialtty/src/lib.rs:133`, `vtconsole/src/lib.rs:95` | one field, `tty_struct.pgrp` | MED (latent) |
| N2 | `CREATED: BTreeMap<String, usize>` keyed by the FULL configfs path, duplicating the canonical `kernfs::PseudoDir` tree. `rmdir` existence-checks the map instead of the tree; `child_has_children` does a linear PREFIX-STRING SCAN over its keys instead of walking children. Two independently-mutated stores of "an item exists at path X". | `modules/src/linux_configfs/dynamic.rs:18` | one tree (`configfs_dirent`), no path-string table | MED |
| N3 | Root device resolves `by_serial("oxide-root")` then falls back to `first_device` — "grab whichever disk published first". A second disk enumerating early would silently be mounted as `/`. | `kmain/src/kmain/rootfs.rs:25` | exactly one mechanism (`root=` major:minor / UUID / PARTUUID / LABEL); panics rather than substituting | LOW-MED |
| N4 | `notify_change` silently no-ops chmod/chown on `is_public_device()` inodes instead of applying or refusing them. | `syscalls/src/perms_common.rs:166` | applies the change; permission is decided by credentials, not by device class | MED |
| N6 | Ether NICs register with `IFF_UP` hardcoded, so the link is already up before userspace sees it. NetworkManager therefore never manages `eth0`. | `net/src/netdev/registration.rs` (both `register_in_ns` sites) | registers with carrier only; userspace brings the link up | **HIGH** |
| N5 | Stale doc comments still describe a chmod/chown "metadata overlay" that D17 already removed. Misleads the next reader exactly like L3. | `vfs/src/setattr.rs:130,201`, `syscalls/src/perms_common.rs:62` | — | doc-only |

Explicitly checked and RULED OUT (do not re-litigate): `cgroup/tree/types.rs:190`
`file_owner` is keyed by a single file name within one cgroup node, not a path;
`devfs`'s per-namespace `ROOTS` is a real component-walked tree and its
ns-broadcast matches devtmpfs being one shared instance in Linux; every
`gnome-shell`/`mutter`/`gdm`/`systemd` name check found is debug-gated.

## 2. Big trackers — real numbers

### `syscall-compliance-matrix.md` — 385 Linux rows

| Status | Rows | Meaning |
|---|---|---|
| `NEEDS-AUDIT` | 207 | route exists, parity **unproven** |
| `PARTIAL` | 116 | partly done, named gaps remain |
| `IMPL` | 45 | full semantics + harness evidence |
| `LINUX-ENOSYS` | 18 | correct as-is; Linux ENOSYSes these too |
| `IN-PROGRESS` | 7 | live lanes (`ioctl`, `quotactl`, `inotify_*`, `quotactl_fd`) |
| `DISPATCH-GAP` | 1 | no route at all |

Read this correctly: **207 `NEEDS-AUDIT` is not 207 broken syscalls.** It is 207
unproven ones, and exactly **one** row has no route whatsoever. The remaining
work is proving and finishing semantics, not adding syscalls.

### `network-plan.md` — 128 lane items

| State | Count |
|---|---|
| `[x]` merged | 103 |
| `[~]` claimed / in progress | 16 |
| `[ ]` unclaimed | 9 |
| `[!]` blocked | 0 |

**N22 live lead is a concrete non-Linux behaviour, not just a missing test:**
Ether NICs are registered with `IFF_UP` **hardcoded** (`net/src/netdev/registration.rs`,
both `register_in_ns` call sites). Linux registers with carrier only and lets
userspace bring the link up — which is why NetworkManager never manages `eth0`.
A fix exists at `archive/B1378-remove-boot-ip-seed-hack` (cherry-pickable); it is
gated on proving NM will actually DHCP once the link is not pre-upped, and the
boot IP-seed hack must die in the same change. Tracked as **N6** below.

Two other recoverable items: MII ioctls (`SIOCGMIIPHY`/`SIOCGMIIREG`/`SIOCSMIIREG`,
zero hits in main; working version at `archive/C116-network-mmsg-ordering-probes`)
and a contested `recvmmsg(MSG_DONTWAIT, timeout)` copy-back rule that must be
settled against the host oracle before row 299 is touched again.

Completion gate is blocked on ARM lockstep smoke (data abort `far=0x9`).

### `ext4fix.md` — the table LIES; real count is ~9, not 10, and Phase A is closed

Audited against `git log` + source 2026-07-26. Rows still marked `TODO` that are
actually **merged and ancestors of HEAD**:

| Row | Reality | Evidence |
|---|---|---|
| A5 jbd2 write-ahead durability | DONE | `B676-ext4-jbd2-wal-durability`, merge `b130c5711` |
| A6 REVOKE emission | N/A under the single-transaction model, by the doc's own text |
| B1 feature gating + csum verify | DONE | `mount/core.rs:101,106,121`; `F695` `e41ef478b`, `B674` `a3e98eb82` |
| C3 htree create + leaf split | DONE | `ext4/src/htree.rs:445`; `338eb7b5a` via `B696` `67acb0f10` |
| C2 `PUNCH_HOLE` | DONE | `sched/src/falloc.rs` supported mask; `5e62709a0` |
| C5 residual sb fields | DONE except flex_bg | `superblock.rs:92-98,202-208`, `inode.rs:150-161` |

Genuinely open: B6 jbd2 checksums (descriptor UUID still hardcoded `SAME_UUID`),
B8 backup SB/GDT sync, B10 `inline_data` read/write, C2 remainder
(`COLLAPSE_RANGE`/`INSERT_RANGE` still `EOPNOTSUPP`), C4 mballoc (single-block
allocator, no run-length/flex_bg/Orlov), C6 jbd2 batching, flex_bg parse,
**POSIX ACL enforcement (xattrs stored but never enforced)**, dx_tail htree
read-verify. All hosted; `e2fsck` is the gate. Do **not** boot for these.

### `poll.md` — 5 of 6 findings are already fixed

Items 1 (per-epitem `sub_id`, `f8f0081fd`), 2 (`EPOLL_CTL_MOD` re-subscribes),
3 (`EPOLLEXCLUSIVE` wired), 6 (AF_UNIX stream recv parks instead of
busy-yielding) are all merged. Only item 4 survives, and it is now an
architecture smell rather than a proven bug: `UnixListener.subs` is a cached
`Weak<PollSubscribers>` side pointer set by `register_subs`, not a
listener-owned waitqueue registered lazily at `poll()` time.

### `console.md` / `console2.md`

`console.md` closes itself — zero remaining kernel-console divergences. So
`console2.md` SOW-5 ("polish console.md G3-G6") is stale by extension, and SOW-1
(unblock sysinit to reach `getty.target`) is superseded — today's capture
reaches `basic.target` clean. Genuinely open and all boot-gated: SOW-2 (getty
renders `oxide login:` in the virtio-gpu window), SOW-3 (virtio-keyboard →
fg-VT ldisc → echoed login), SOW-4 (console role correctness under `quiet`).

### `mountfix.md`

Its "remaining before publication" is done (`B810`, PR #3069, `11432fee5`). What
remains is matrix rows still `PARTIAL`: 165 `mount`, 166 `umount2`, 428-433
(`open_tree`/`move_mount`/`fsopen`/`fsconfig`/`fsmount`/`fspick`), 442
`mount_setattr`, 457/458 `statmount`/`listmount`, 467 `open_tree_attr` — mount
flag semantics, `MNT_EXPIRE`/`MNT_FORCE`, propagation, errno ordering.

### `tcp-edge-inventory.md` — current, all 10 rows open

SYN/backlog/syncookies, established input ordering, output/retransmit timing,
RST/FIN/TIME_WAIT, urgent/OOB, `SO_REUSEPORT`, async errors/ICMP/PMTU,
keepalive/timeout, accept wakeups/poll, `TCP_INFO` diagnostics. Each needs a
corpus; all hosted+guest.

### Everything else

`magic.md` 189 done / 0 open. `skizm.md` steps 6b and 8b closed today.
`console*.md`, `poll.md`, `ext42.md`, `mountfix.md`, `tcp-edge-inventory.md`,
`kernel-audit2.md`, `zram-plan.md`, `arm-*.md` are historical or complete.

`desktop-boot-blockers.md` is **stale** (dated 2026-07-08). Its open blocker #4
(`systemd-journal-flush` 90 s hang) did not reproduce in today's capture:
`sysinit.target` and `basic.target` both reached with **zero** timeouts or
failures. Do not plan against that file without re-verifying.

## 3. Order of work

1. **W1.** Nothing else matters while the machine stops at 191 s. GDB backtrace
   first, fix, then re-boot to find the next wall.
2. Re-capture and re-baseline the desktop chain once W1 is fixed — the old
   blocker list is stale and the next wall is unknown until the machine survives.
3. L1 (cheap, correct, hosted-testable).
4. Then resume the plan work: network `[~]` lanes, syscall `IN-PROGRESS` rows,
   `ext4fix` — all hosted-iterable, none of them boot-gated.
5. L2 whenever kernel preemption is turned on; it is a prerequisite for that,
   not for the desktop.
