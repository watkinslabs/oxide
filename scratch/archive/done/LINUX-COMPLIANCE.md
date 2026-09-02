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

**RESOLVED 2026-07-28 — `B1494` / PR #4143 (merged).** The EIO was the last line
of `ext4/rootfs/inode/special.rs::create`:

```rust
d.st.forget_created_ino(ino);
d.st.wrap_file(ino).ok_or(VfsError::Eio)   // <- err=5
```

`create_file` had SUCCEEDED — the inode was on disk — and `wrap_file` then
re-read the slot to build the VFS inode, folding every backend failure into
`None` through `read_inode(..).ok()?`. So a create that worked surfaced as a
bare EIO with no diagnostic, and stranded the allocated inode on every attempt.

The earlier reading here (arm 2 `!is_reg()` "RULED OUT", so it must be a
deferred-batch visibility problem) was **wrong on both halves**: the read path
IS shadow-coherent (`read_inode` → `read_meta_byte_range` →
`read_metadata_block` consults `state.shadow`), and the ruling-out was circular
— it assumed the read sees the write.

The real defect was structural, not a race. **Linux never re-reads what it just
allocated:** creating a file hands the live in-memory inode straight to
dentry instantiation, and orphans rather than leaks on failure. `forget_created_ino` — dropping the cache
immediately before the read — existed only to service a round trip Linux does
not make. `init_inode` now returns the parsed `Inode` it wrote, and
`wrap_created_file`/`wrap_created_any` build from it with no I/O and no failure
mode. `mkdir` shared the bug (the boot's other symptom,
`mkdir /var/log/journal/<id> err=5`) and is fixed with it. `build_file_inode`
also stopped re-reading the slot for `i_blocks` alone — it had been silently
reporting `st_blocks = 0` whenever that read failed — so every instantiation,
not just creates, lost a metadata read.

Guarded by `crates/kernel/ext4/tests/create_no_readback_image.rs`: the wrap is
asserted to issue ZERO inode-table reads, with a control proving the injected
read fault actually bites.

**Whether this unfreezes the greeter is unverified** — it removes the journald
write failure, not necessarily the freeze below.

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
- The journald EIO was **not** a deferred-batch visibility problem. The read path is shadow-coherent, and the "arm 2 ruled out" argument was circular — it assumed the read sees the write. Real cause: a read-back round trip Linux does not make (`B1494`).

## 7 Traps that cost real time

1. **Hosted tests cannot see stack depth; boots cannot see host-cfg builds.** Three arm64 kernel-stack overflows were green in every hosted test and caught only by `boot-smoke` as `[BADSTACK]`; a host-target build break passed every gate we run.
2. **Adding a sleep where no wake source exists converts a spin into a hang.** Parking inotify/fanotify reads wedged the boot at 500s (normal: 52s) because a producer does not reach `enqueue_event`. Verify the wake before writing the park.
3. **`SMOKE_KEEP_LOG` keeps only the LAST attempt** while a panic lands in the *failing* one. Use `SMOKE_KEEP_LOG_DIR`.
4. **Do not mark on a process name** — unmeasurable if it writes nothing to serial. Use the sysrq task dump or `systemd.debug_shell=ttyS0` + `ps`.
5. **A weak implementation passes a naive test.** `AT_RANDOM`'s "two execs differ" passed with a clock-derived value; the load-bearing assertion was "upper half not derivable from lower half".
6. **A consistency test comparing two of our own values proves nothing** — DRM's ioctl-size test passed with both number and struct wrong. Anchor to Linux.
7. **An 8-byte-wrong ioctl size made a complete subsystem unreachable.** DRM atomic modesetting was fully implemented and never once ran.
8. **A read-back of what you just wrote is a non-Linux invention, and it manufactures a failure mode that cannot happen in Linux.** ext4's `create`/`mkdir`/`tmpfile` allocated an inode, discarded what they knew, re-read the slot, and folded every backend error into one bare `EIO` from an operation that had SUCCEEDED. Linux hands the live `struct inode` to `d_instantiate_new` and never re-reads. When an error is unattributable, ask what the Linux path does *not* do — the round trip was also costing a metadata read per create (`B1494`).
9. **`cargo test` halts on the first failing target, so one red test hides the rest.** Use `--no-fail-fast` when auditing a crate. A `-p fs` run reported only `sys_dup2_shape`; `sys_close_shape` was failing behind it (`B1495`).
10. **A hosted test that passes standalone and fails in the suite is a shared-global race, not a flake to re-run.** Test binaries run their tests on concurrent threads, so any `static CURRENT`-style global needs a `TEST_LOCK`. Three files had it; two did not (`B1495`).
