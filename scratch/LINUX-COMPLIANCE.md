# Linux compliance — consolidated state

DRAFT 2026-07-28. The single entry point. Everything else is a source document
cited from here; nothing in this file is unique to it except §1 and §7.

| Source | What it holds |
|---|---|
| `syscall-compliance-matrix.md` | 385 syscall rows, per-row status + evidence |
| `partial-surface-2026-07-28.md` | the 193 PARTIAL rows re-derived into buckets + work order |
| `linux-compliance-findings.md` | subsystem-audit index, blockers, §10-§13 running findings |
| `audit-{mm,sched,vfs,net-sec}.md` | the four raw subsystem audits, both-sides cited |
| `wait-diff-open-items.md` | guest-differential harness items W1-W9 |

## 1 State

| | Value |
|---|---|
| Syscalls audited | **385 / 385** (`NEEDS-AUDIT` 198 → 0) |
| Syscalls fully implemented (`IMPL`) | **165** |
| `PARTIAL` | **193** |
| `LINUX-ENOSYS` (Linux ENOSYSes them too) | 22 |
| `DONE` | 3 |
| Subsystem-audit findings | ~689 (34 BLOCKER, 95 SECURITY) |
| Subsystem blockers closed | **14 / 14** |
| Guest differential | **109 records, exact vs host Linux, both arches** |

**Not complete.** The audit is finished; the implementation is not. The 193
PARTIAL rows resolve to **162 real functional gaps from ~40 root causes** — see
§3. Anyone reading this as "done" is reading it wrong.

## 2 What the campaign actually established

The audit's most useful output is not the finding count, it is three structural
facts that change how the remaining work should be estimated.

**2.1 Every fix so far closed the syscall-shim half.** The re-triage expected
~30 PARTIAL rows to be stale-but-fixed; it found **3**. The ~30 merged lanes
closed sub-claims *inside* rows — errno ordering, ABI layout, permission
ladders — and left the subsystem half untouched: the RT tick, `shared_pending`,
`i_writecount`, the aio ring, uid translation. That is why the rows still read
PARTIAL, and it is the shape of everything below.

**2.2 The dominant defect class is machinery with no callers**, not missing
code. Confirmed instances: ext4's orphan list (complete, wired only to
`O_TMPFILE`), `timer_slack_ns` (present, inherited, prctl-settable, read by
nothing — most of a 100 ms latency floor), `update_rtt` (TCP RTO stuck at 1 s),
`atime_needs_update`, `graft_mount`'s flags word (hardcoded 0, so every mount
read "unrestricted" from a word nothing wrote), DRM `object_type`, a second
dead copy of `get_obj_properties`, the LRU aging functions, PSI, the readahead
state machine, the slab allocator. **Grep call sites, not definitions.** Many
"missing features" are wiring.

**2.3 Correct code correlates with ungated modules.** Code behind
`#[cfg(target_os = "oxide-kernel")]` compiles its `#[cfg(test)] mod tests` out
**silently** while cargo prints "ok" — six shipped instances, including
`stat_common.rs`, whose tests had never compiled once. The code that audited
*correct* overwhelmingly lives in ungated modules.

## 3 Remaining work, ordered

Full detail and row numbers in `partial-surface-2026-07-28.md` §4, which also
marks the five entries already closed. Highest value first:

| # | Item | Size | Why |
|---|---|---|---|
| 1 | kuid/kgid translation (16 rows) | L | Largest single root cause. Translator exists, 2 callers. Needs a `Cred` type split so mixing a namespace-relative id with a stored one is a compile error, as Linux's `kuid_t` makes it |
| 2 | RT throttling + `SCHED_DEADLINE` | L | **FIFO non-preemption and the RR quantum are DONE** (`B1490`). Requeue-at-tail needed no work: `put_prev_task` → `enqueue` → `push_back` and `pick_highest` pops the head, so rotation is inherent — verified, not assumed. What remains: `sched_rt_runtime_us` throttling (no `rt_runtime`/`rt_period`/`rt_time` anywhere — needs per-rq accounting plus a period timer, and throttling implemented wrong wedges a boot) and a real `SCHED_DEADLINE` class |
| 3 | aio family | L | `aio_context_t` is a small integer libaio dereferences → fio/PostgreSQL SIGSEGV rather than degrade |
| 4 | blocking reads that never block | M | inotify/fanotify still EAGAIN/spin; the wake source exists (`B1489`) but **parking wedged the boot** — a producer does not reach `enqueue_event`. Find it before writing the park. `timerfd` is NOT in this set: it already parks correctly with `park_interruptible_with_deadline` — the triage entry was stale |
| 5 | ptrace | L | `traced_by` never reaches `wait4`; `gdb -p`/`strace -f` non-functional |
| 6 | io_uring | L | 64-entry rings vs 32768, 15 ops, `GETEVENTS` never blocks |
| 7 | mount flags/permission model | M | `MNT_LOCKED` set by nothing; `top_mount_on` resolves by dentry alone |
| 8 | rlimit enforcement | M | CPU/CORE/NPROC/MEMLOCK/AS/SIGPENDING/MSGQUEUE/RTTIME stored, not enforced |
| 9 | dentry identity across rename | M | ` (deleted)` paths through `/proc/<pid>/fd` and `getcwd` |
| 10 | **IF=0 syscalls and faults** | campaign | x86_64 runs syscalls (`IA32_FMASK`) and faults (interrupt gates) with interrupts disabled end to end, where Linux enables them in both. Only three `IrqGate::save_enable()` sites exist. Root cause under the CPU-stall class. Not a PR |

## 4 Desktop

`basic.target` 13.6s · `graphical.target` 19.4s · `Running GNOME Shell` 54.9s ·
**greeter renders** (QMP screendump, 1280×800, top bar + clock + power button).

**User field data 2026-07-28 — the dispatch error is probably NOT gnome-shell's.**
Two lines land adjacent on their boots, repeatedly:

```
[NAMEI] openat-create path="/var/log/journal/<id>/user-1000.journal" err=5
[B288 dgram /run/systemd/journal/socket pid=4451] MESSAGE=Failed to dispatch fd source: Invalid argument
```

`err=5` is **EIO** creating the journal file, and the dispatch message is
emitted by the process writing to the journal socket — i.e. journald's own,
not the compositor's. That reframes the whole line of enquiry: the leading
theory has been a DRM fd returning EOF, and the errno was never explained by
it (EOF does not produce EINVAL). **Chase the EIO on journal creation first**,
and confirm which pid emits the dispatch error before assuming the compositor.
The adjacent `[INOTIFY-ENOENT …]` lines are expected — watches on paths that do
not exist yet — and are noise here.

This also matches a standing note that journald writes zero entries despite fs
and mmap working.

**Traced to the exact line 2026-07-28 (not fixed).** An earlier note here named
`RootfsState::create_at` (the `Option`-returning one) — **that was wrong**, it is
not the path `openat` takes. The real path is
`ext4/rootfs/inode/special.rs::create`, which propagates errors correctly:
quota via `?`, backend failures through `vfs_error_from_mount`.

It contains exactly ONE `Eio`, and it is the last line:

```rust
d.st.forget_created_ino(ino);
d.st.wrap_file(ino).ok_or(VfsError::Eio)   // <- err=5 comes from here
```

So for the journal file, **`create_file` SUCCEEDED — the inode was allocated on
disk — and `wrap_file(ino)` then returned `None`.** The EIO is not an I/O error
and not a quota rejection: it is a freshly created inode that could not be
wrapped into a VFS inode. `tmpfile` has the identical last line.

**Narrowed to two lines.** `wrap_file` (`ext4/rootfs/ops.rs:105`) returns
`None` in exactly two places:

1. `self.mount.read_inode(ino).ok()?` — the inode `create_file` just allocated
   cannot be read back. Suspect ordering: `forget_created_ino` runs immediately
   before and invalidates the page cache + `iforget`s the number, so the re-read
   goes to disk; if the inode-table write is not yet visible this fails.
2. `if !inode.is_reg() { return None; }` — **RULED OUT.** `create_file`
   (`ialloc/create.rs:34`) writes `S_IFREG | (mode_perm & 0x0FFF)`, so masking
   the type off at the call site is harmless. Checked, not assumed.

**So it is arm 1, and there is a concrete mechanism.** `create_file` runs inside
`create_op`, whose own comment says it "defers the batch commit". Then
`forget_created_ino` invalidates the page cache for that inode and `iforget`s
it. Then `wrap_file` calls `read_inode`, which must now go to disk — for an
inode-table block whose write may still be sitting in the deferred batch. That
ordering reads through a cache it just dropped, for data not yet committed.

**Do NOT "just commit before the forget".** `create_op` already ends with
`maybe_commit_batch()`, and the mount carries a shadow that reads are supposed
to consult — so forcing a commit per create would (a) paper over the real
question of why the read misses the shadow, and (b) reintroduce per-operation
synchronous journal commits, which this project already measured as a
pathological slowness source (~87 commits/s dominating boot).

**The right question is why `read_inode` does not see the just-created inode**
— whether through the batch, the shadow, or the cache that `forget_created_ino`
drops immediately beforehand. Establish that first; the fix follows from it and
is probably in the read path, not the commit policy.

Either way this leaves an allocated on-disk inode with no VFS reference on every
failure — a leak alongside the wrong errno, and if journald retries in a loop it
burns an inode per attempt.

Then it **freezes**: screendumps 150s→400s byte-identical, alongside a large
volume of `Failed to dispatch fd source: Invalid argument` from gnome-shell —
also observed independently by the user on their own boots. The DRM EOF bugs
behind the leading theory are fixed (card + render minors, blocking reads,
wake source); **whether that unfreezes the greeter is unverified**, and the
`Invalid argument` errno is still unexplained — EOF would not produce it.

## 5 Verified correct — do not re-audit

Capabilities, user namespaces, keyrings, job control, VT process-mode
switching, TCP CUBIC, POSIX/OFD/flock owner split, atime policy, xattr
namespace gating, `sync_file_range`, htree insert/split, extent trees to depth
5, `metadata_csum`, fanotify permission events, zram, quota, `membarrier`, the
robust-futex exit walker, `restart_block`, NTP discipline, POSIX CPU timers,
`sigaltstack`, the tty job-control decision table, `rseq` (`rseq_cs` decode, IP
fixup, signature validation, both arches), `semtimedop`, `swapoff`.

## 6 Corrections to earlier claims

Recorded because each was asserted before being checked, and propagated.

- `B1434` was **wrong for x86_64**: `pkey_alloc` without OSPKE returns EINVAL on the first call and ENOSPC only on the second; the two arches differ across four behaviours. Fixed in `B1479`.
- "SIGABRT does not kill a threaded process" — **does not reproduce**; the premise was inferred, never observed. `B1471` had already closed it.
- `RESOLVE_BENEATH` was **not** the `openat2` escape; only `RESOLVE_IN_ROOT` was, because it clamps rather than errors.
- Linux does **not** treat a tracerless `SECCOMP_RET_TRACE` as `KILL_THREAD`.
- `fadvise64 NOREUSE`, THP, KSM, mandatory locking and `copy_file_range`'s `EXDEV` are ABSENT-OK — Linux omits them too.
- `rseq`, blocking lease break, `RLIMIT_MEMLOCK`, hugetlbfs and `timerfd` parking were all listed as gaps and are **implemented**.
- `gnome-shell` runs, and did before this session's fixes — an earlier doubt of mine was wrong.

## 7 Traps that cost real time

1. **Hosted tests cannot see stack depth; boots cannot see host-cfg builds.** Three arm64 kernel-stack overflows were green in every hosted test and caught only by `boot-smoke` as `[BADSTACK]`; a host-target build break passed every gate we run.
2. **Adding a sleep where no wake source exists converts a spin into a hang.** Parking inotify/fanotify reads wedged the boot at 500s (normal: 52s) because a producer does not reach `enqueue_event`. Verify the wake before writing the park.
3. **`SMOKE_KEEP_LOG` keeps only the LAST attempt** while a panic lands in the *failing* one. Use `SMOKE_KEEP_LOG_DIR`.
4. **Do not mark on a process name** — unmeasurable if it writes nothing to serial. Use the sysrq task dump or `systemd.debug_shell=ttyS0` + `ps`.
5. **A weak implementation passes a naive test.** `AT_RANDOM`'s "two execs differ" passed with a clock-derived value; the load-bearing assertion was "upper half not derivable from lower half".
6. **A consistency test comparing two of our own values proves nothing** — DRM's ioctl-size test passed with both number and struct wrong. Anchor to Linux.
7. **An 8-byte-wrong ioctl size made a complete subsystem unreachable.** DRM atomic modesetting was fully implemented and never once ran.
