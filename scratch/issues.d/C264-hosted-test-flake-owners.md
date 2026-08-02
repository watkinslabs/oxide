# C264 — hosted test flake owners

## Flake 1 — `ipc` sysv::sem undo tests

Curated row (`scratch/known_issues.md`, quoted opening text):

> `ipc`'s `sysv::sem::tests::undo::{setval_and_setall_clear_pending_adjustments,
> ipc_rmid_invalidates_the_undo_so_a_later_exit_is_a_no_op}` are flaky on
> `origin/main` itself, independently of this branch: TWO claims over ONE
> resource, the process-global current-task slot. `F794`'s
> `sysv_shm/creator/tests.rs` installs a current task (`become_current` sets
> `CUR` and `sched::set_current_hook`) under the shm claim, while the sem undo
> tests file their undo records under `current_tgid()` and assume it reports 0
> because no task is installed...

Verified before touching code that only `sysv_shm/creator/tests.rs` installs
`sched::set_current_hook` anywhere in the `ipc` crate (grepped every
`set_current_hook`/`become_current`/`current_tgid` call site). `current_tgid()`
is read on the `sysv::sem::op` SEM_UNDO recording path (`op.rs:184`), and
`sched::current()` is a single process-global `AtomicU64` fn-pointer
(`crates/kernel/sched/src/lib.rs:133-169`), not thread-local — so a shm
creator test holding the hook installed for its whole body is visible to
every concurrently-running sem test thread, regardless of which mutex either
side takes. Confirmed no other `ipc` test file installs a current task.

### Fix

`crates/kernel/ipc/src/sysv_shm/test_claim.rs`: made the private `SHM: Mutex<()>`
`pub(crate)`.

`crates/kernel/ipc/src/sysv/sem/tests/common.rs`: `TEST_LOCK` is now
`pub static TEST_LOCK: &std::sync::Mutex<()> = &crate::sysv_shm::test_claim::SHM;`
— an alias of the same mutex, not a second one. All ~38 `TEST_LOCK.lock()...`
call sites across `sysv/sem/tests/{get,ctl,op,undo,ns}.rs` are untouched
(auto-deref makes `.lock()` work identically on `&Mutex<()>`).

One crate-wide IPC claim now serializes every sem test against every shm
creator test, closing the current-task race by construction.

### Evidence

`cargo test -p ipc <filter>` filters exclude the interfering module, so it
cannot reproduce the race (only 8 `sysv::sem::tests::undo` tests ran, 0
`sysv_shm` tests). Reproduced instead by running the built test binary
directly with process-level oversubscription (`--test-threads=300-400`,
tens of concurrent OS processes) to widen the scheduling window between
sem-thread `current_tgid()` reads and shm-thread `become_current` bodies.

- BEFORE (pre-fix `ipc` binary, same stress harness): **1 red / 260 runs**
  (`setval_and_setall_clear_pending_adjustments` FAILED, matches the
  diagnosed test exactly — log preserved this session, not committed).
- AFTER (post-fix `ipc` binary, identical harness, same run count): **0 red / 260 runs**.
- `cargo test -q -p ipc --lib` (normal invocation): 230 passed, 0 failed, both
  before and after (this flake needs the stress harness to manifest at all
  under default thread counts on this box).

Files changed:
- `crates/kernel/ipc/src/sysv_shm/test_claim.rs`
- `crates/kernel/ipc/src/sysv/sem/tests/common.rs`

## Flake 2 — `cargo test -p drv` driver-model hooks

Curated row (`scratch/known_issues.md`, quoted opening text):

> `cargo test -p drv` is flaky under parallel test threads: the driver-model
> publish/bind hooks are process-global `fn` pointers that concurrent tests
> overwrite, so up to 20 of 40 tests fail depending on interleaving.
> Reproduces on `main` (1 of 3 runs red) and disappears with
> `--test-threads=1`. Pre-existing, not this lane's change.

**Already fixed on this branch, by a prior merge, before this lane started.**
Commit `1b56032d367fb3462d4e9f80a42e5afc311cdfac` ("fix(netlink): stop
RTM_GETLINK panicking on a device removed mid-dump", merged 2026-08-01, an
ancestor of this branch's HEAD `2e7c87113`) introduced exactly the claim this
task specifies: `crates/drivers/drv/src/model/test_claim.rs` — a single
crate-wide `MODEL: Mutex<()>` / `claim_model()` that resets `DEVICES`,
`MODEL_DRIVERS`, both counters, and all six publish/bind hook slots
(`SYSFS_HOOK`, `SYSFS_REMOVE_HOOK`, `BIND_HOOK`, `DRIVER_HOOK`,
`DEVTMPFS_HOOK`, `DEVTMPFS_DEL_HOOK`). All 39 of the crate's 40 tests that
touch the model call `claim_model()`; the 40th
(`model::lifecycle_state::tests::removal_claim_has_one_owner_and_lifecycle_is_one_way`)
is self-contained (owns its own `Arc<Lifecycle>` and threads, touches no
global) and needs no claim. Same commit also fixed
`drv-zram::tests::control_reuses_removed_index` and its two siblings
(`crates/drivers/drv-zram/src/tests.rs`: `CONTROL: Mutex<()>` /
`claim_control()`, same one-claim shape) — closing the "zram and block index
spaces" resource named in that commit's message.

No code change made for this flake in this lane — it was already closed.

### Evidence

- Checked out the commit immediately BEFORE the fix
  (`1b80f8855`, parent of `1b56032d3`) into a throwaway `git worktree add
  --detach` under `/tmp` (never touched `/home/nd/oxide/kernel` or another
  agent's worktree; removed after measuring). `drv` test binary, default
  thread count, plain repeat loop: **3 red / 30 runs**.
- Current `wt-C264` HEAD (post-fix, unmodified by this lane): **0 red / 40 runs**,
  `drv` test binary, default thread count.
- `drv-zram` on current HEAD: **0 red / 20 runs**.
- `cargo test -q -p drv --lib`: 40 passed, 0 failed.
- `cargo test -q -p drv-zram --lib`: 104 passed, 0 failed.

### Not fixed / out of scope, left as-is

- `drv-virtio-input` devfs lifetime races (`devfs::tests::lifetime::*`,
  curated row starting "`drv-virtio-input` devfs lifetime tests are a
  parallel global-state race") — this is `crates/drivers/fbdev/src/devfs.rs`
  (fbdev's devfs registry), a different crate and a different global than
  `drv`'s model claim or `drv-zram`'s control claim. It shares no owner with
  either fix in this lane, so per the task's instruction it is left alone.
  Still OPEN in `scratch/known_issues.md`.
- No other `drv`/`drv-zram` rows found still open at time of this check.
