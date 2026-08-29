DRAFT 2026-08-28. Dep: `docs/02`, `docs/03`, `docs/07`, `docs/08`, `docs/16`, `docs/17`, `docs/39`, `docs/42`, `docs/43`.

# ext4 program

## 1

One ext4 program owns the remaining ext4 correctness, compatibility, performance, and test work. The reference tree is the authority for Linux behavior. `scratch/known_issues.md` is the issue ledger; IDs in this plan are the canonical ext4 work items. Historical rows remain evidence, but this inventory controls status.

No item closes on a parser change alone. Each closes only when the Linux-shaped owner exists, focused tests pass, the relevant image test passes, both architecture checks pass, and the same smoke milestone passes on x86_64 and aarch64.

## 2 — master inventory

| ID | Priority | Current gap | Depends on | Exit evidence |
|---|---|---|---|---|
| E4-00 | DONE | The ext4 baseline and fixture ownership are frozen. The package suite passes in parallel, all workspace test targets build independently, and the real-root workloads use the caller-selected image without shared mutable fixtures. | baseline | 375 unit tests plus image suite; 177 isolated workspace test-target builds; serial real-root workload on both GNOME images |
| E4-01 | DONE | Owned concurrent block reads are the ordinary ext4 file-read path. The focused concurrency harness, byte-for-byte real-image reads, serial 7/7 real-root workloads on both arches, target checks, and current boot smokes are green. | E4-02 | concurrent read stress, serial 7/7 real-root workload on both arches, byte-for-byte image validation, no boot regression |
| E4-02 | DONE | Metadata/frame ownership has canonical shared reads, generation fencing, frame-identity retry, failed-owner retry, and first-completion retention. The synchronous metadata-read contract has no cancellation point: the owner waits for completion, publishes the result, then removes in-flight ownership. | baseline only | one cache/request ownership model, injected completion/error tests, no stale-frame publication; cancellation is not part of this synchronous contract |
| E4-03 | DONE | Canonical size publication and short-fill retry handling are in place. The complete ignored real-root harness passes serially on both GNOME root images, including VFS journald writes, merged-usr symlink walks, metadata churn, and remount checks; x86 full GNOME/Firefox and ARM SMP=2 graphical resolver checks pass. | E4-02 | serial 7/7 real-root workload on both arches; provenance identifies the failing boundary; live GNOME read survives |
| E4-04 | DONE | Journal replay stale-cache `EIO` is fixed and quota replay coverage is present. The complete ignored real-root harness passes serially on both GNOME root images, including batched journald persistence, writeback, and remount checks. A real dconf database overwrite and a newly allocated dconf database both survive frame-cache writeback, journal flush, and remount. | E4-02, E4-05 | serial 7/7 real-root journal workload on both arches, crash/replay matrix, real dconf allocation/write/persistence |
| E4-05 | DONE | Retained pending checkpoint images, coalescing, journal-space accounting, and clean-publication state are implemented. Journal commit records use a distinct device-write phase. The crash/replay matrix covers torn commit, descriptor, data, publish, and checkpoint boundaries; quota replay and write-amplification coverage are green. | E4-01, E4-02 | 18 journal image tests, 5 quota replay tests, 40-page writeback at 0.25 device writes/page, batched-create accounting, repeated boot/perf evidence |
| E4-06 | DONE | Async journal commit option and JBD2 ordering owner are implemented and validated. Shared crash/replay coverage is tracked under E4-05. | E4-01, E4-05 | option validation and async commit ordering complete; shared crash/replay matrix under E4-05 |
| E4-07 | DONE | Exact physical preallocation ownership, failed-claim rollback, contiguous locality-tail consumption with Linux-style size re-bucketing, Linux's `fls(len)-2` average-fragment buckets, the bounded three-order best-available scan fallback, bounded multiblock extent selection, and inode-PA release on truncate, punch-hole, range shifts, final orphan eviction, last-writer release, ENOSPC discard, and mount teardown are covered. | E4-01, E4-02, E4-05 | allocator model tests, fragmentation/failure tests, e2fsck-clean images, full ext4 matrix |
| E4-08 | medium | Indexed-directory lookup and inode construction reuse the type-probe image and resident VFS inode identity; special inode construction and directory mutation now reuse parsed inode fields instead of rereading the inode table. Ordinary pathname walks start in Linux RCU mode and fall back at blocking boundaries. The Linux-shaped rwsem reader fast path removes the wait-lock round trip for uncontended shared readers, delayed-allocation buffered writes no longer reread the inode table before returning, and linear-directory byte matching now avoids per-entry object and closure work while borrowing the shared metadata block. Linear scans now retain Linux's per-directory last-successful-block hint. Create/mkdir/symlink/mknod and ordinary VFS unlink/rmdir/link/rename/writeback transactions now durably publish journal records before returning and defer home-block checkpointing to the background owner, matching the reference journal-handle boundary and shortening the VFS inode-lock hold. Ext4 inode xattrs now load lazily behind a sleepable per-inode owner on the first xattr, ACL, or list operation, matching Linux's on-demand path. The checkpoint owner skips a busy mutation gate and retries asynchronously. Batched handles now release the mount transaction gate while unrelated operation bodies run; locality preallocation selection retires its claimed prefix atomically, preserving Linux's reservation ownership under concurrent handles. The latest valid aggregate measurements remain within harness variance, so whole-boot closure is not credited. Aggregate closure is still open at ~12–15x host; the remaining owners are the blocking ext4 lookup path, residual mutation work, and repeatable controlled performance evidence. | E4-01, E4-02 | named phase owner; repeated controlled comparison closes the ratio |
| E4-09 | DONE | `inode_readahead_blks` warms a Linux-bounded inode-table window through the canonical metadata cache and excludes each group's `bg_itable_unused` tail. The ext4 address-space readahead worker is exercised against both real GNOME root images and publishes multiple resident file pages. | E4-01, E4-02 | cold-lookup/image coverage, async ownership integration, both-arch target checks, boot-smoke and perf comparison |
| E4-10 | DONE | `dioread_nolock`, `nodioread_nolock`, and `dioread_lock` are explicitly refused because this tree has no O_DIRECT consumer whose unwritten-extent protocol they could control. | E4-01, E4-02 | Add a complete O_DIRECT owner before reconsidering support |
| E4-11 | DONE | Bitmap prefetch is wired and covered; `nombcache` is explicitly refused because its mbcache owner is absent. | E4-02, E4-07 | Add mbcache before changing the refusal |
| E4-12 | DONE | Legacy options without consumers are refused explicitly; generic VFS tokens remain pass-through. | baseline only | known unowned ext4 options refuse |
| E4-13 | DONE | All ext4 e2fsck image fixtures use PID/sequence-unique temporary paths and clean up after each run; the large allocator harness uses a per-process directory, and serial/parallel runs agree. | baseline only | isolated fixture ownership; parallel and serial suites agree |
| E4-14 | DONE | The previously reported ARM sysinit EIO/SIGBUS event did not reproduce in the controlled ARM boot-smoke run; userspace answered the systemd probe and the serial RX probe passed in 22 seconds. | E4-02, E4-03 | controlled ARM boot-smoke evidence; retain broader ARM desktop validation under E4-03 |
| E4-15 | DONE | Controlled GNOME/SMP=1 comparison, phase attribution, and repeatability evidence are recorded. The result remains within harness variance and is not credited as a whole-boot gain; the dominant remaining resolution cost is parent-lock contention. | E4-01 through E4-05 | saved baseline, phase metrics, repeated runs, comparison report |
| E4-16 | DONE | Historical ext4 rows are explicitly historical, mapped to the E4 inventory, and no longer carry stale pending SHAs or old current-suite counts. | baseline only | corrected rows map to an E4 item or retain explicit evidence |

## 3 — supported mode contract

The target is every useful ext4 mode that this kernel can support honestly. A mode is not “supported” because mount-option admission accepts its name.

| Mode family | Target disposition |
|---|---|
| `data=journal`, `data=ordered`, `data=writeback` | fully live, with Linux ordering and recovery rules |
| journal barriers and `nobarrier` | fully live through the block durability owner |
| journal checksums and `journal_async_commit` | live JBD2 feature transitions, ordering, and replay |
| delayed allocation and immediate allocation | live allocation/writeback policy |
| multiblock allocation, locality PAs, stream goals, stripe alignment | Linux-shaped lifecycle and heuristics |
| inode-table readahead | asynchronous cache-backed behavior |
| discard | capability-gated post-free discard |
| ACLs, user xattrs, quotas, project quotas | live policy and persistence |
| journal recovery, `noload`, `norecovery`, error policies | Linux ordering and error result |
| direct I/O options | implement when the direct-I/O owner is present; otherwise refuse rather than silently ignore |
| DAX, inline data, encryption, bigalloc, verity, and other absent device/layout owners | explicit refusal is correct until the required owner exists |
| obsolete compatibility spellings | preserve Linux-compatible no-op behavior only where that is the reference behavior; document each one |

## 4 — dependency-ordered execution

### 4.1 E4-00: freeze the baseline and fixture ownership

1. Record the current ext4 package/image test counts, both architecture checks, dual smoke, and controlled GNOME/perf measurements.
2. Give every image test an isolated copy or an exclusive generated fixture; remove shared mutable image paths.
3. Add a failure-injection matrix for metadata reads, data reads, owned completions, extent reads, allocation, journal writes, flushes, and remounts.
4. Close or update stale ledger evidence only after the current commands reproduce it.

Evidence: `TMPDIR=/home/nd/oxide/ext4-test-tmp cargo test -p ext4 --all-targets
--no-fail-fast -- --test-threads=4` passed 375 unit tests plus the image suite;
`tools/test-build-check.sh` passed all 177 workspace test-target builds in
isolation; the complete ignored real-root workload passed serially on both
GNOME images. The former 62-failure result is historical only.

Exit: COMPLETE. The controlled baseline is committed, every mutable fixture
has one owner, E4-13 and E4-16 are resolved, and later measurements identify
the commit, image, architecture, SMP setting, and harness mode.

### 4.2 E4-02: establish the ext4 I/O and cache ownership model

1. Read the complete reference read, buffer-cache, page-cache, and completion paths.
2. Make one owner responsible for an outstanding request, its buffer, completion, error, and cache publication.
3. Define the mount lifetime needed by deferred work; cancellation/drop must prevent callbacks from touching a dead mount.
4. Preserve journal shadow precedence over clean metadata cache bytes.
5. Add tests for completion-before-wait, completion-after-wait, error completion, short completion, duplicate completion, invalid frame, and unmount cancellation.

Exit: E4-02 passes independently on x86_64 and aarch64 hosted/build paths, with no second cache or side-channel source of truth.

### 4.3 E4-01: repair and adopt owned concurrent block reads

1. Implement the reference-shaped owned-request path at the block boundary.
2. Convert ext4 reads only after E4-02 proves buffer and mount ownership.
3. Test out-of-order completions, queue depth, partial-range reads, metadata reads, extent-node reads, and concurrent callers.
4. Re-run boot images after every ownership change; do not mask failures with retries, timeouts, or disabled concurrency.

Exit: ext4 no longer depends on the serialized compatibility path for ordinary reads, all bytes match the device image, and both architectures reach the normal smoke milestone.

### 4.4 E4-03 and E4-04: close the ext4 read/write correctness failures

1. Instrument one provenance boundary at a time: inode read, extent resolution, device completion, frame allocation, frame publication, and page fill.
2. Reproduce the dconf read failure and classify the first failing owner.
3. Reproduce `/home` dconf write EIO with a small focused image, then follow allocation → extent update → data writeback → journal checkpoint.
4. Fix the owner named by evidence; preserve normal error returns and rollback semantics.
5. Verify remount, crash/replay, and live GNOME behavior on both architectures.

Exit: no unexplained EIO/SIGBUS remains in the controlled matrix; E4-14 is either fixed through the same owner or closed with controlled evidence.

### 4.5 E4-05 and E4-06: finish JBD2 transaction ownership and modes

1. Read the complete reference transaction, commit-record, barrier, checkpoint, and recovery ordering.
2. Replace the one-entry pending handoff with a retained checkpoint list and exact journal-space accounting.
3. Keep data ordering, journal ordering, target writeback, and clean-superblock publication in separate owned phases.
4. Add `journal_async_commit` as a real policy: validate incompatible data modes, set/read the on-disk feature, submit the commit record with the correct durability contract, and wait at the checkpoint boundary.
5. Add crash points before/after descriptor, data, commit, journal-superblock, home-write, and clean-publication operations. The harness now covers torn commit-record publication as well as partial descriptor/data bodies; broader crash/replay and write-amplification evidence remains.

Exit: all three data modes, barriers, checksums, recovery, and async commit have positive and negative tests; no mode is admitted while its ordering owner is absent.

### 4.6 E4-07: finish mballoc from the reference model

1. Compare every allocation-context field and state transition with the reference.
2. Complete group scan criteria and best-group selection after the order indexes are consulted. The bounded Linux best-available goal trim and bounded extent scoring are wired.
3. Complete locality PA candidate distance selection, use, trim, discard, and release lifecycle.
4. Validate stream/locality goals under fragmentation, CPU migration, ENOSPC, rollback, truncate, unlink, and remount.
5. Keep bitmap, buddy summaries, PA reservations, quota, journal, and on-disk counters under their canonical owners.

Exit: allocator model tests, fragmented image tests, failure injection, and e2fsck validation pass on both architectures; measured allocation work improves without changing placement correctness.

### 4.7 E4-09, E4-10, E4-11, E4-12: complete useful mount modes

1. Add each option to the one `Ext4Behaviour` owner only once.
2. Wire inode-table readahead through the lifetime-safe asynchronous I/O/cache owner from E4-02/E4-01.
3. Implement direct-I/O policy only through a real direct-I/O owner; refuse unsupported combinations with the reference errno.
4. Wire mbcache and bitmap-prefetch policy into the actual allocator cache lifecycle.
5. Audit every remaining admitted spelling and record implemented/refused/intentional-no-op disposition.
6. Test mount, remount, sysfs exposure, recovery, and option-order behavior.

Exit: no useful mode is accept-and-drop; no absent owner is represented as supported.

### 4.8 E4-08 and E4-15: optimize and prove the result

1. Re-run the syscall/function-time harness only after correctness work is green.
2. Attribute `newfstatat`, metadata reads, journal commits, allocations, and page fills to named phases.
3. Complete the transaction ownership dependency chain:
   - [DONE] add per-metadata-block ownership for read-modify-write and shadow publication;
   - [DONE] add per-operation running-transaction handles and rollback frames keyed by the handle;
   - [DONE] protect allocation-group bitmap/GDT decisions with group ownership while unrelated handles run;
   - make handle stop release credits without holding the parent inode lock across unrelated journal work;
   - retain checkpoint ordering, ordered-data rules, replay visibility, and failure rollback.
4. Fix htree downstream cost at its actual owner; do not optimize the already-fast index selection based on the aggregate ratio.
5. Compare against the frozen local-Linux baseline with the same userspace, image, SMP, workload, and measurement window.
6. Record distributions and regressions, not a single favorable run.

Current E4-08 transaction status: per-metadata-block writer ownership, per-handle
rollback frames, allocation-group ownership, and gate release during unrelated
handle bodies are implemented. Locality preallocation selection and retirement
are one atomic ownership transition, preventing concurrent handles from claiming
the same reserved block. The ext4 suite is 378/378; the allocator/e2fsck harness
is 7/7; hosted/test-build/feature checks pass on x86_64 and AArch64. The valid
real-root harness passes on current main. The whole-boot aggregate remains
uncredited because a fresh perf boot failed before the GNOME marker with
userspace resource/EIO failures and therefore is not comparable. A single-extent-cursor planner
experiment (PR #6496) passed hosted/image fixtures but produced early GNOME
boot EIOs and orphan/bitmap damage on a freshly repaired disposable image; it
was reverted in PR #6497. The planner remains unchanged until a harness covers
that real-root allocation shape.

Exit: each claimed gain has a reproducible before/after measurement; no correctness regression is traded for speed.

### 4.9 preserved performance history

The rows below are intentionally kept as a comparison series. They are not
interchangeable workloads: each is a real GNOME boot with `SMP=1`, and normal
desktop and socket variance is expected.

| revision | syscalls | CPU ms | average ns | `newfstatat` | block reads / ms | block writes / ms | result |
|---|---:|---:|---:|---:|---:|---:|---|
| `5d15845be` | 1,367,309 | 6,938 | 5,074 | 20,150 | 526 / 368 | 8,027 / 2,807 | GNOME Shell marker reached |
| `baf0ad839` | 1,367,913 | 7,043 | 5,148 | 20,921 | 526 / 333 | 8,300 / 2,878 | GNOME Shell marker reached |

The second row includes the merged inode-image and inode-cache lookup changes.
It does not demonstrate a whole-boot gain: the aggregate and `newfstatat`
values are within the harness's documented run-to-run variance. The lookup
phase remains the next measurement target.

## 5 — phase gate

Every execution item must pass:

- reference behavior read and mechanism recorded;
- focused hosted tests and relevant image tests;
- `git diff --check`;
- x86_64 kernel check;
- aarch64 kernel check;
- x86_64 smoke milestone;
- aarch64 smoke milestone;
- current `scratch/known_issues.md` evidence;
- clean merged `main` before the next dependency phase.

No ext4 item is complete while its dependency is only partially implemented, its mode is parser-only, or its performance claim lacks a controlled baseline.
