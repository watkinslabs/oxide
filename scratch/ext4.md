DRAFT 2026-08-28. Dep: `docs/02`, `docs/03`, `docs/07`, `docs/08`, `docs/16`, `docs/17`, `docs/39`, `docs/42`, `docs/43`.

# ext4 program

## 1

One ext4 program owns the remaining ext4 correctness, compatibility, performance, and test work. The reference tree is the authority for Linux behavior. `scratch/known_issues.md` is the issue ledger; IDs in this plan are the canonical ext4 work items. Historical rows remain evidence, but this inventory controls status.

No item closes on a parser change alone. Each closes only when the Linux-shaped owner exists, focused tests pass, the relevant image test passes, both architecture checks pass, and the same smoke milestone passes on x86_64 and aarch64.

## 2 — master inventory

| ID | Priority | Current gap | Depends on | Exit evidence |
|---|---|---|---|---|
| E4-01 | high | Owned concurrent block reads are now the ordinary ext4 file-read path; the lane still needs its complete exit matrix. | E4-02 | concurrent read stress, byte-for-byte image validation, no boot regression, both arches |
| E4-02 | high | Metadata/frame ownership now has canonical shared reads, generation fencing, and frame-identity retry; the lane still needs the full architecture and cancellation evidence. | baseline only | one cache/request ownership model, injected completion/error tests, no stale-frame publication |
| E4-03 | high | Canonical size publication and short-fill retry handling are in place. Focused live-root dconf/framecache reads and VFS-path journal workloads pass; repeated full GNOME/SMP boot evidence remains. | E4-02 | provenance identifies the failing boundary; focused reproducer passes repeatedly; live GNOME read survives |
| E4-04 | high | Journal replay stale-cache `EIO` is fixed and quota replay coverage is present. Focused live-root journaled mkdir, rotation, writeback, and remount workloads pass; GNOME dconf write/persistence evidence remains. | E4-02, E4-05 | focused write/persistence test, remount persistence, live GNOME dconf write |
| E4-05 | high | Retained pending checkpoint images, coalescing, journal-space accounting, and clean-publication state are implemented. Journal commit records now use a distinct device-write phase, and the harness covers power loss before/after commit, before/after publish, after home checkpoint, and during a partial home checkpoint; descriptor/data-specific crash points and broader write-amplification evidence remain. | E4-01, E4-02 | crash/replay matrix, checkpoint-list tests, repeated boot/perf evidence |
| E4-06 | medium | Async journal commit option and JBD2 ordering owner are implemented; crash/replay coverage remains part of E4-05. | E4-01, E4-05 | option validation and async commit ordering complete; finish shared crash/replay matrix |
| E4-07 | medium | Exact physical preallocation ownership, failed-claim rollback, contiguous locality-tail consumption, Linux's `fls(len)-2` average-fragment buckets, and the bounded three-order best-available scan fallback are covered. Multiblock allocation still differs in detailed extent scoring and complete locality preallocation lifecycle. | E4-01, E4-02, E4-05 | allocator model tests, fragmentation/failure tests, e2fsck-clean images, measured workload |
| E4-08 | medium | Indexed-directory lookup and inode construction now reuse the type-probe image and resident VFS inode identity, but `newfstatat` remains far slower than host Linux. | E4-01, E4-02 | phase profile names remaining owner; repeated controlled comparison closes the ratio |
| E4-09 | medium | `inode_readahead_blks` warms a bounded inode-table window through the canonical metadata cache; architecture and performance comparison remain with E4-01/E4-02/E4-15. | E4-01, E4-02 | cold-lookup/image coverage, async ownership integration, boot/perf comparison |
| E4-10 | medium | `dioread_nolock`, `nodioread_nolock`, and `dioread_lock` need a direct-I/O data path. | E4-01, E4-02 | Complete O_DIRECT semantics later, or keep the explicit capability refusal |
| E4-11 | low | Bitmap prefetch is wired; `nombcache` is explicitly refused because its mbcache owner is absent. | E4-02, E4-07 | bitmap-prefetch coverage complete; add mbcache before changing refusal |
| E4-12 | low | Legacy options without consumers must not be silently accepted. | baseline only | complete: known unowned ext4 options refuse; generic VFS tokens remain pass-through |
| E4-13 | medium | The large e2fsck allocator harness now uses a per-process temporary directory and its serial/parallel runs agree; remaining image fixtures still need a workspace-wide ownership audit. | baseline only | isolated fixture ownership; parallel and serial suites agree |
| E4-14 | medium | One ARM sysinit boot produced ext4-shaped EIO/SIGBUS symptoms without a controlled reproduction. | E4-02, E4-03 | repeated controlled ARM reproduction or evidence-backed closure as host contention |
| E4-15 | medium | Repeated GNOME/SMP=1 reports are preserved, including the post-lookup-cache run; the result remains within harness variance and is not credited as a whole-boot gain. | E4-01 through E4-05 | saved baseline, phase metrics, repeated runs, comparison report |
| E4-16 | documentation | Historical ext4 rows contain stale claims, including old image-test failure counts. | baseline only | every historical row is corrected, linked to an E4 item, or closed with evidence |

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

Initial evidence: `cargo test -p ext4 --tests --no-fail-fast --quiet --
--test-threads=4` passed all 353 ext4 tests on 2026-08-28. This supersedes the
old 62-failure count as a current result, but does not close fixture isolation:
the command exercises the package in parallel only, not a workspace-wide run
with every consumer of the shared generated images.

Exit: the controlled baseline is committed, every mutable fixture has one
owner, E4-13 and E4-16 are resolved, and all later measurements identify the
commit, image, architecture, SMP setting, and harness mode.

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
5. Add crash points before/after descriptor, data, commit, journal-superblock, home-write, and clean-publication operations. Commit-boundary coverage is now present; descriptor/data request classification remains.

Exit: all three data modes, barriers, checksums, recovery, and async commit have positive and negative tests; no mode is admitted while its ordering owner is absent.

### 4.6 E4-07: finish mballoc from the reference model

1. Compare every allocation-context field and state transition with the reference.
2. Complete group scan criteria and best-group selection after the order indexes are consulted. The bounded Linux best-available goal trim is now wired; detailed extent scoring remains.
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
3. Fix htree downstream cost at its actual owner; do not optimize the already-fast index selection based on the aggregate ratio.
4. Compare against the frozen local-Linux baseline with the same userspace, image, SMP, workload, and measurement window.
5. Record distributions and regressions, not a single favorable run.

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
