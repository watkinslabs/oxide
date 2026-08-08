# C295 — purge external-source citations

Drop file for branch `C295-purge-external-source-citations`. Folds into `scratch/known_issues.md`.

## What the sweep did

Repository text must not "name, path-link, quote, or cite external implementation source
files" (`CLAUDE.md`, Semantic verification). The tree violated that at scale. This branch is
a text-only sweep: comments, doc comments, string literals and markdown prose. Zero
executable tokens changed.

Detector (paths into an external kernel tree, line-number pins, reference-tree names,
kernel-source/mailing-list URLs), run over `crates/ docs/ scratch/ tools/ kernel/`, excluding
`scratch/syscall-compliance-matrix.md`:

| detector | before | after |
|---|---|---|
| path-shaped (external source paths, tree names, URLs, commit SHAs) | 3043 | 12 |
| widened (adds bare `<dir>/<file>.h` UAPI headers, `.tbl`/`.rst`, dirs the first pattern missed) | 458 | 10 |

Both residues are the same justified set, counted differently. Every remaining hit is one of:
- `kpi/include/linux/*.h` and `linux/<hdr>.h` in `scratch/done/kpi_{handoff,fix}.md`,
  `crates/kernel/modules/src/linux_dma.rs`, `tools/kpi-header-smoke.c` — **our own** `kpi/`
  compat-header tree, which by design carries Linux-shaped header paths;
- `userspace/wait_diff/*.c` in `scratch/done/partial-surface-2026-07-28.md` — our own sources;
- `scratch/known_issues.md` row 181, owned by another lane, left for that owner.

The path-shaped pattern alone was **not** enough. It missed bare UAPI header names
(`linux/magic.h`, `drm_mode.h`), `.tbl` and `.rst` extensions, upstream commit SHAs, and any
directory outside its hardcoded list (`fpu/`, `io_uring/`, `autofs/`, `sched/signal.h`). Those
were ~150 further citations, found only by widening twice. Any gate written for this must use
the wide form.

The narrower pattern named in the brief — a handful of external top-level source
directories, restricted to comment and table lines under `crates/kernel tools docs` —
went **537 → 0**. Its 12 apparent survivors are `/proc/sys/net/ipv4/*` sysctl paths, which
are ABI we implement, not source citations.

The sanctioned exception, `scratch/syscall-compliance-matrix.md`'s `Linux refs` column
(385 rows), was not touched.

## Categories found

| Category | Rough count | Notes |
|---|---|---|
| External path + line-number pin (a source file plus a line range) | ~1800 | Largest class. Worst kind — stale the moment the other tree moves. |
| Bare external source path, no line number | ~600 | |
| UAPI and internal header paths | ~350 | Rewritten to name the UAPI surface, not the file. |
| Dedicated `Linux ref` table column in archived audit docs | ~800 lines | 5 docs under `scratch/done/`; column deleted wholesale, every other column kept. |
| Reference-tree name / version pin (reference-tree directory name, its absolute path, and a pinned version tag) | ~25 | |
| Upstream commit SHAs | 2 | Not caught by the path pattern; found by a separate grep. |
| `Documentation/**.rst` doc-tree citations | ~6 | |
| Quoted blocks of external C source | ~10 | Paraphrased to prose. Two of these were live doctest hazards — see below. |

Function/symbol NAMES used to describe a shape (`d_move`, `mfill_atomic`) were deliberately
left in place: the rule bans citing files, and the names carry behavioural meaning that
deleting would gut. Flagging as a judgement call, not a silent decision.

## Latent doctest failures defused

The gate this class already broke once (B1949, `net::recv_result::recv_empty`). Two more of
the same shape found and fixed — a 4-space-indented block under `///` with no fence, which
rustdoc compiles as a Rust doctest:

| File | Content |
|---|---|
| `crates/kernel/syscalls/src/186_gettid.rs` | `///     return task_pid_vnr(current);` |
| `crates/kernel/syscalls/src/218_set_tid_address.rs` | two lines of bare pseudo-C under `///` |

Both rewritten as prose. Every other 4+-space-indented `///` line in the tree was audited and
is markdown list-continuation, not a code block. `cargo test --workspace --doc` green
(100 crates, exit 0) both before and after — the two above are in target-gated files, so they
were latent rather than currently-failing, and would have fired the moment those files were
ungated.

## Rows

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED C295 | INFRA | med | 3043 lines of repository text cited an external implementation tree by path, line number, commit SHA or quoted source, against the Semantic-verification hard rule. | Detector 3043 → 12 (all 12 justified); 903 files changed, comments/docs only. | C295 |
| FIXED C295 | DEFECT | med | Two doc comments held unfenced indented pseudo-C, which rustdoc compiles as a doctest — the exact shape that made `cargo test -p net --doc` fail on clean `main` (B1949). | `syscalls/src/186_gettid.rs`, `syscalls/src/218_set_tid_address.rs`; both target-gated so latent, not yet firing. | C295 |
| FIXED C295 | DEFECT | low | Bulk `Linux ref` column deletion in `scratch/done/audit-mm.md` also deleted the `CORRECTNESS` severity cell of the userfaultfd range-ioctl-bitmap row, because an unescaped `\|` inside `(1<<1) \| (1<<2)` inflated that row's column count. | `audit-mm.md:152`; caught by a per-row before/after column-count diff, repaired. Row/oxide-ref multiset counts verified unchanged across all 5 audit docs. | C295 |
| OPEN | COVERAGE | med | No gate prevents a new external-source citation from landing. This rule has now cost four lanes time (B1949, B1955, B1956, C295). | See "Recurrence" below. | unowned |

### Coverage gaps — an ordering was pinned only by a citation, no test encodes it

Each row below had a comment citing an external source to justify an ordering, mask or
layout, and nothing in this repo can fail if that behaviour breaks. The citation was the only
record. Tests are supposed to be the durable provenance; here there are none.

| Area | File | Ordering / contract with no test |
|---|---|---|
| syscalls | `syscalls/src/312_kcmp.rs` | ESRCH → EPERM → EINVAL ladder. File is `#![cfg(target_os = "oxide-kernel")]`, so a `#[cfg(test)]` block there would be a phantom test — the decision must move to an ungated module first (`docs/53`; pattern already used by `pkey.rs`, `lsm.rs`). |
| syscalls | `syscalls/src/277_sync_file_range.rs` | EBADF-first: fd lookup precedes argument validation. Target-gated, same phantom-test problem. |
| syscalls | `syscalls/src/059_execve/{x86_64,aarch64}.rs` | `arch_pick_mmap_layout`/`setup_arg_pages` must run before PT_LOAD placement. Only observable via boot. |
| vfs | `vfs/src/mount/mnt_flags.rs` | `MOUNT_ATTR_*` numeric bit layout unpinned. |
| vfs | `vfs/src/dentry/flags.rs` | `D_OP_*` bits and `D_TYPE_MASK`/`D_*_TYPE` layout (bits 20-22) unpinned. |
| vfs | `vfs/src/inode/flags.rs` | `FS_XFLAG_*` mask groupings — no membership test. |
| vfs | `vfs/src/getattr.rs:369-376` | `SB_NOATIME` clears `STATX_ATIME`; automount/DAX attribute-bit ORing. Tests only hit `generic_fillattr` directly. |
| vfs | `vfs/src/setattr.rs` | `ATTR_FORCE` short-circuits the DAC/owner gates; chmod-on-symlink → EOPNOTSUPP ordered ahead of `setattr_prepare`. |
| vfs | `vfs/src/inode/file_lock/records.rs` | `Files` vs `Ofd` owner identity at close (survives vs dies with the fd). |
| vfs | `vfs/src/dcache/lifecycle.rs` | `d_delete` sole-user vs shared branch; `d_drop` never unhashes a live mountpoint. |
| vfs | `vfs/src/superblock/registry.rs` | `sget`/`sget_reused` reuse-vs-build return value. |
| fs | `fs/src/flock.rs:45-48` | Interrupted `flock` returns `-ERESTARTSYS`, never `-EINTR`. |
| fs | `fs/src/posix_lock.rs:126-142` | Interrupted `F_SETLKW` → ERESTARTSYS; wake source on close/last-fput/F_UNLCK; EDEADLK check with the OFD-lock exemption. |
| fs | `fs/src/fallocate/vfs.rs:38-45` | Full cross-check order: EINVAL range → EOPNOTSUPP mode → EBADF writability → EPERM/ETXTBSY inode flags. Only the mode sub-ladder is tested. |
| fs | `fs/src/keyring/perm.rs:88-91` | `key_validate` order ENOKEY → EKEYREVOKED → EKEYEXPIRED. |
| fs | `fs/src/perf/glue.rs:145` | `SetOutput` ioctl EINVAL-vs-EBADF precedence. |
| fs | `fs/src/pipe.rs:340,372` | FIFO partner-wait interrupt/success ordering. Structurally untestable hosted (kernel-gated blocking path). |
| fs | `fs/tests/splice_pipe_model.rs:148` | Claims ESPIPE-vs-FMODE-gate precedence, but the test only exercises correctly-moded ends, so the two checks never compete. **The test does not test what it says.** |
| ext4 | `ext4/src/extent_rw/{append.rs:83,insert.rs:374}` | Quota charged before the block is handed out. `i_blocks_accounting_image.rs` checks resulting state, not ordering. |
| devpts | `devpts/src/fileops.rs:1-6,117-119,144` | Slave read/write job-control gate vs `O_NONBLOCK`; master-last-close wake-then-hangup ordering; `clear_hangup` on slave reopen after vhangup. |
| ipc | `ipc/src/live/posix_mq/notify.rs` | `si_pid`/`SI_MESGQ` shape; "any unblocked thread may take it". Kernel-gated file. |
| ipc | `ipc/src/live/posix_mq/sendrecv.rs` | Notify fires only on the 0→1 transition with no waiting receiver. |
| ipc | `ipc/src/live/posix_mq/open.rs` | mq descriptor is unconditionally `O_CLOEXEC` regardless of `oflag`. |
| sched | `sched/src/live/schedule/switch.rs:164-171` | `on_cpu` clear must precede `finish_lock_switch` releasing the rq lock. |
| sched | `sched/src/live/rq_locate.rs:1-18` | Dequeue/enqueue must target the task's own rq, never the caller's. |
| sched | `sched/src/live/ttwu.rs:118-133` | Wake-list drain must happen inside the rq lock, immediately before enqueue. |
| sched | `sched/src/runqueue.rs:165-191` | `on_cpu`-before-`on_rq`-clear vs `pending_wake`'s `on_rq`-then-`on_cpu` load ordering. |
| sched | `sched/src/live/sigpend.rs:78-80` | `complete_signal` picks the leader first, then falls back, for a process-directed signal. |
| sched | `sched/src/task/rlimits.rs:10-24` | `do_prlimit` four-branch ladder: EINVAL range → EINVAL cur>max / NOFILE cap → EPERM without `CAP_SYS_RESOURCE`. |
| sched | `sched/src/session.rs:110-119` | `setpgid` six-branch ladder EINVAL→ESRCH→EINVAL→EPERM→EACCES→ESRCH. |
| sched | `sched/src/timers/clockid.rs:205-230` | STATIC vs DYNAMIC `CLOCK_THREAD_CPUTIME_ID` EOPNOTSUPP-vs-EINVAL divergence — self-documented as a residual bug with no test pinning current behaviour. |
| modules | `modules/src/linux_sync/waitqueue.rs:59` | `prepare_to_wait_event` returns `-ERESTARTSYS` once a signal is pending. `linux_sync_tests.rs:81` only tests the `0` path. |

Several of these are unfixable-in-place for the reason `CLAUDE.md` already names: the decision
lives in a `#[cfg(target_os = "oxide-kernel")]` file, so any test written beside it compiles
out silently. Closing them means moving the decision into an ungated module first.

### Defects noticed while reading (not fixed here — text-only branch)

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | DEFECT | med | Load average counts only runnable tasks; the reference also counts uninterruptible-sleep tasks, so loadavg reads low under I/O-wait-heavy load. | `crates/kernel/sched/src/loadavg.rs:5-6` | unowned |
| OPEN | MISSING | med | `RLIMIT_SIGPENDING` charging is only the decision half; queues are bounded by a fixed `RT_QUEUE_CAP` in the interim. The comment frames this as deferred, which Discipline rule 3 forbids. | `crates/kernel/sched/src/rlimit/pending.rs:9-16` | unowned |

## Recurrence — a lint would pay for itself

This rule has been broken continuously and has now cost four lanes: B1949 (a quoted C block
in a doc comment silently failed `cargo test -p net --doc` on clean `main`, and the failure
was misread as belonging to the citation rather than to the gate), B1955 and B1956 (each had
to strip a citation mid-task), and this one (3043 lines).

Recommended, in order of value:

1. **A spec-lint rule + `make no-external-citations`.** One regex over tracked files —
   external-tree source paths, line-number pins into them, reference-tree names, upstream
   commit SHAs, kernel-source and mailing-list URLs. Allowlist exactly two things:
   `scratch/syscall-compliance-matrix.md`'s `Linux refs` column, and our own `kpi/` tree
   (whose header paths are `include/linux/*.h`-shaped and are the pattern's only real false
   positive). Baseline at 0 and ratchet, since the tree is now clean — this is the cheap
   moment to add it, before it drifts again.
2. **A doc-comment indented-block check.** Any `///` line indented 4+ spaces that is not
   inside a fenced block is a doctest rustdoc will try to compile. That is what broke the
   gate, and the check is independent of citations — it would also catch a stray ASCII
   diagram. Cheaper and more targeted than relying on `cargo test --doc` noticing, since
   target-gated files hide the failure until they are ungated.
3. Note for whoever writes (1): a bulk table-column edit across these audit docs is not safe
   naively — rows with an unescaped `|` inside backticked code have an inflated column count,
   and a positional delete takes the wrong cell. Verify by a per-row before/after column-count
   diff, not by eye. That is how the `audit-mm.md:152` severity-cell loss above was caught.
