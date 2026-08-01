# B1694 — the workspace suite's long tail: one owner per shared resource

Continues B1680 (baseline), B1681 (`softirq`), B1682 (`fbcon`), B1683
(`drv-virtio-input`). Method unchanged: N sequential
`cargo test --workspace --no-fail-fast` runs with a private `TMPDIR` off the
shared tmpfs, recording the exact failing set each time.

Base for both distributions: `origin/main` at `7c458d89a`. Rebased onto
`1b80f8855` after `F794-exit-shm-creator-list-rmid-forced` landed in the same
files; the `ipc` rows below are stated against the rebased tree.

The headline is not a test defect. `netlink::rtnetlink::iface::ifaces_snapshot_in`
panicked the kernel on an `RTM_GETLINK` dump racing a device removal — a
production path reachable from userspace. It surfaced only because the suite was
finally run to completion, repeatedly.

## Before — 10 runs, 0 clean

| Package | Red runs | Failing tests |
|---|---|---|
| `fs` | 10/10 | `sys_pipe2_shape::pollout_tracks_current_pipe_capacity` every run; plus `inotify::limits_tests::a_new_watch_past_the_per_user_ceiling_is_enospc` and `keyring_procfs::a_new_key_appears_in_the_proc_keys_body_procfs_renders` in one run each |
| `drv` | 3/10 | 20 tests at once in the worst run (`model::tests::lifecycle::*`, `path::tests::*`); `model::tests::hooks::device_add_initial_probe_precedes_add_uevent_without_bind_change` twice |
| `fbdev` | 1/10 | `tests::register_count_roundtrip`, `tests::register_unwinds_record_when_model_publication_conflicts` |
| `drv-virtio-blk` | 1/10 | `tests::lifecycle::remove_blk_selects_only_matching_device_record` |
| `timer` | 1/10 | `tests::oneshot_fires_once_and_unregisters` |

The B1680 baseline's remaining names (`modules`, `procfs`, `klog`, `sound`,
`netlink`, `sysfs`, `nscg`, `drv-zram`, `drv-virtio-gpu`) did not surface in 10
workspace runs on this box, so each was measured separately at N=30 by looping
the binary a `cargo test --workspace --no-run` had already built — same feature
unification as the workspace run, ~100x the samples per minute:

| Package | Red runs (N=30, before) |
|---|---|
| `modules` | 3/30 |
| `drv-zram` | 2/30 |
| `procfs` | 1/30 |
| `klog`, `netlink`, `sysfs`, `nscg`, `sound`, `drv-virtio-gpu` | 0/30 |
| `drv-virtio-input`, `fbcon`, `softirq` (B1681-83) | 0/30 — the earlier fixes hold |

## Intermediate — 10 runs after the first eight fixes

8 of 10 clean. Removing the loud offenders exposed two rarer ones that ten runs
had never reached before, both fixed here as well:

| Package | Red runs | Failing test |
|---|---|---|
| `crng` | 1/10 | `pool::tests::short_and_unaligned_lengths_are_filled_completely` |
| `sched` | 1/10 | `tests::signals::realtime_queue_is_bounded_by_rlimit_sigpending_not_a_constant` |

A further 12 runs then left `netlink` alone: 2/12, two different
`rtnetlink_lookup` tests. That one had three separate causes, all fixed below.

A third 12 runs was 10/12 clean and surfaced two more, each once: `ipc`
(`sysv_shm::shmctl::tests::syscall_entry_copies_stat_info_and_set_buffers`) and
`sync` (`spin_relax::tests::relax_is_inert_until_a_hook_is_installed_and_then_runs_it`).
Both fixed below. The tail is ordered by rarity, so each fix exposes the next
one: nothing short of running the suite to completion, repeatedly, finds them.

## After — 12 runs

| Package | Red runs |
|---|---|
| every package | 0/12 — `cargo test --workspace --no-fail-fast` completes green |

Per-package re-measurement after the fixes: `fs --lib` 0/40 (was 2/30 and
2/40), `modules` 0/40 (was 3/30), `netlink` 0/250 (was 6/200), `crng` 0/60,
`sched` 0/30, `procfs` 0/30, `drv-zram` 0/30, `net` 0/20.

## After the rebase onto `1b80f8855` — 12 runs, 11 clean

The single red run is the load-sensitive `ipc` futex deadline recorded OPEN
below, not a shared-state race and not touched by this branch. `ipc` reports 230
tests on both sides of the conflict resolution, and its own 60-run series is
1/60 — the pre-existing `sem` undo row below, which `origin/main` shows at
2/60.

## What was wrong

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| FIXED B1694 | high | `fs::sys_pipe2_shape::pollout_tracks_current_pipe_capacity` was UNSOUND, not racy, and failed every run: it asserted `set_pipe_size(inode, 2) == Ok(2)`. `F_SETPIPE_SZ` never yields a pipe smaller than one allocation unit and never one whose capacity is not a whole number of units, so the answer is a page, and the resolved size is what is reported back. The test then drove POLLOUT with a 2-byte write against a 4096-byte ring. Rewritten to pin the rounding contract and to fill the RESOLVED capacity. This one test is why `make test` stopped before reaching most of the suite. | `left: Ok(4096), right: Ok(2)`, 10/10 runs. Closes the `B1690` row that recorded it. | — |
| FIXED B1694 | high | `drv`'s 38 hosted tests took NO serialization while all of them mutate one driver model — `DEVICES`, `MODEL_DRIVERS`, their counters and six publication hooks, all process-global because a kernel has one device tree. Worst run: 20 simultaneous failures across `model::tests::lifecycle` and `path::tests`. `model::test_claim::claim_model()` is now the model's single owner: taking it excludes every sibling AND resets the model, so each test starts from an empty tree with no hooks installed. One claim for the crate, not one per file — `model::tests` and `path::tests` publish into the same registries. | 3/10 workspace runs before, 0/10 after; `cargo test -p drv` 40/40. Closes the unowned `cargo test -p drv is flaky under parallel test threads` row. | — |
| FIXED B1694 | high | `fs`'s inotify/fanotify tests raced through `dispatch::INSTANCES` even though each already used its own inodes and its own uid — the reason two earlier lanes could not pin them. Dispatch UPGRADES every weak ref in the registry before deciding whether a group is interested, so ANY test firing an event holds a live `Arc` to EVERY other test's group for that walk, and `register_instance`'s `retain` does the same. A sibling's `drop(group)` therefore does not run `InotifyData::Drop` while a walk is in flight: inode pins and ucount charges are released later, on the other test's thread, after the sibling asserted they were gone. `inotify::test_claim::claim_notify()` now owns the registry for the body of each of the ~130 tests in the ten inotify test files. | Two distinct symptoms, one cause: `i_count()` 2 vs 1 in `fan_tests::re_adding_a_mark_restates_whether_it_pins_its_object`, and `ucount(InotifyWatches)` 2 vs 0 in `limits_tests::a_new_watch_past_the_per_user_ceiling_is_enospc`. `fs --lib` 2/30 before, 0/40 after. | — |
| FIXED B1694 | high | `modules` cleared the ONE kernel symbol table from seventeen files. Each `export_symbols_registers_*_surface` test called `symtab::_reset()` — whose doc-comment claimed it "lets each test start from a known empty state without coordinating with siblings", the exact inverse of what emptying a process-global table does — then asserted its own names were present. `tests.rs` held a `SERIAL` for its own nine tests only, so the other seventeen wiped it from outside the lock: two locks over one table exclude nothing. A test that merely RESOLVED a name (`linux_netdev::core::tests::export_symbols_registers_netdev_surface`) lost it mid-body, so readers need the claim too. `_reset` is now `reset_for_test`, `pub(crate)`, `cfg(test)`, reachable only through `test_serial::claim()`, which every `#[test]` in the crate takes. The same claim covers the firmware cache + reader hook and the IRQ table, which produced the other two observed failures. | 3/30 before, 0/40 after. Failures seen: `linux_{string,time,runtime,netdev}` surface tests, `linux_firmware::tests::firmware_cache_survives_reader_clear`, `linux_irq::tests::request_dispatch_disable_and_free_irq`. | — |
| FIXED B1694 | med | `fbdev`'s `reset_fbdev()` cleared `FBS` and the `/dev/fbN` node table with no serialization, from three test files. Content was right — the reset goes through `unregister_node` so each node's model device is torn down by `device_del` — but running it unserialized meant one test's reset removed another's just-registered `fb0`, and a registry cleared mid-flight leaves a `graphics`/`fbN` identity that makes the NEXT `register` fail as a duplicate. Replaced by `test_claim::claim_fbdev()`, which owns the reset. | 1/10 workspace runs before (`register_count_roundtrip` saw `count()` 0 vs 1), 0/10 after. | — |
| FIXED B1694 | med | `timer`'s tests called `reset()` — clearing `TIMERS`, `ONESHOTS`, `CANCELLED_ONESHOTS`, `NEXT_ID` and the fire counters — with no lock, on the one wheel a kernel has. `claim_wheel()` now owns the reset. | `oneshot_fires_once_and_unregisters` read `A == 40` where 3 was due: another test's `tick_a` fired into the shared counter. 1/10 before, 0/10 after. | — |
| FIXED B1694 | med | `drv-virtio-blk::tests::lifecycle` and `drv-zram::tests::control_reuses_removed_index` both assert on a RECYCLED global id. `TEST_DISK_SEQ` and `BACKING_TEST_ID` keep each test's disk NAME unique but not its index: `block::registry::register` and zram's `hot_add` both hand out the LOWEST free slot, so a sibling registering between this test's remove and its `is_none()`/`== index` check takes the number just freed. Both crates now claim their id space for the tests that drive it. | `by_dev(second_dev_t).is_none()` failed 1/10 workspace runs; `control_reuses_removed_index` 2/30. Both 0 after. Closes the `drv-zram control_reuses_removed_index` half of the `B1690` row. | — |
| FIXED B1694 | med | `procfs`'s four `proc_handler_netns_tests` share one file-level `CURRENT` namespace slot, and the bound leaves resolve their namespace by CALLING `current()`. A sibling storing its own namespace between this test's `bind()` and its `store()` redirects this test's write into the sibling's namespace. Claimed for the body of each test. (`proc_handler_tests.rs` declares its `CURRENT` INSIDE each test fn and is not affected.) | `opened_net_sysctls_retain_owner_after_task_namespace_switch` 1/30 before, 0/30 after. | — |
| FIXED B1694 | med | `fs`'s `keyring_procfs` tests all mint a session keyring through `KEYCTL_JOIN_SESSION_KEYRING`, which REPLACES the calling task's session keyring, and two of them move the global `/proc/sys/kernel/keys/*` ceilings. Two tests joining concurrently leave one rendering a `/proc/keys` body whose key the other displaced. Claimed. | `a_new_key_appears_in_the_proc_keys_body_procfs_renders` rendered a body holding only the sibling's `_ses` keyring. | — |
| FIXED B1694 | high | `netlink`'s route tests and `net`'s hosted fixture were TWO LOCKS OVER ONE TABLE, across a crate boundary. Namespace 0's route rows belong to `net::hosted_fixture::init_net_domain()`, which snapshots them on acquire and RESTORES them on drop; `netlink::test_serial::FIB` was a private mutex beside it that excluded only netlink's own route tests. A netlink test holding `FIB` inserted ns-0 routes that a concurrent `net`-fixture holder then restored away underneath it, so the test's own `route_remove` reported 0 rows removed. `FIB` is deleted: every route test now takes the domain guard, which is the table's real owner. Ten tests that took BOTH lost the redundant one. | `dump_groups_equal_cost_routes_as_multipath` and `lookup_prefers_longest_prefix`, `route_remove` returning 0 vs 1. `netlink` 2/12 workspace runs before, 0/250 binary runs after. | — |
| FIXED B1694 | high | `netlink::rtnetlink::iface::ifaces_snapshot_in` panicked on a device unregistered between its snapshot and its per-device lookup — `lookup_in_ns(id, ns).unwrap()` with nothing held across the two. This is a production path, not test scaffolding: an `RTM_GETLINK` dump racing a device removal takes the kernel down. Now skipped rather than unwrapped, which is what a dump reports anyway — the removal is announced on its own `RTM_DELLINK`. | `getlink_dump_ends_with_nlmsg_done`, `called Option::unwrap() on a None value` at `iface.rs:19`. | — |
| FIXED B1694 | med | Two genetlink quota-group defects, both invisible in 30 runs and both found at N=200. (1) `a_warning_with_no_listener_is_not_an_error_for_the_filesystem` broadcasts on the `VFS_DQUOT` events group while explicitly NOT taking the group's claim — its comment reasons that it creates no subscriber, which is true of itself and false of the sibling holding the claim, whose queue received a record it never sent. (2) `quota_listener()` returned `(socket, guard)`, and bindings drop in reverse declaration order, so `let (listener, _serial)` released the claim while the socket was still registered in the process-global `GENL_LISTENERS` list — the exclusion has to outlive the resource it protects. Guard now comes first in the tuple. | The intruder decoded as `ParsedWarning { qtype: 0, excess_id: 1, caused_id: 0 }` — byte for byte the warning the unclaimed test sends. 6/200 before, 0/250 after. | — |
| FIXED B1694 | med | `sched::tests::signals` tasks all shared ONE `RLIMIT_SIGPENDING` account. The limit is charged to a (user namespace, uid) account, not to the task, so every test task left at the default uid 0 queued into one process-global account and the test that sets a tight limit found a sibling's records already filling it. Each task now takes its tid as its account uid — which is what Linux gives a test its own account: a distinct user, not a lock. | `push()` refused the 1st of 3 records under a limit of 3. 1/10 workspace runs before, 0/30 after. | — |
| FIXED B1694 | med | `crng::pool::tests::short_and_unaligned_lengths_are_filled_completely` was UNSOUND, not racy: it asserted a 1-byte fill contains a non-zero byte, which a correct CSPRNG fails once in 256. The intent — catching a fill that silently writes nothing — is kept by resampling: 32 independent all-zero results is 256^-32, while a pool writing nothing never escapes the loop. | 1/10 workspace runs, `fill(1) produced all zeroes`. 0/60 after. | — |
| OPEN | med | `ipc`'s `sysv::sem::tests::undo::{setval_and_setall_clear_pending_adjustments, ipc_rmid_invalidates_the_undo_so_a_later_exit_is_a_no_op}` are flaky on `origin/main` itself, independently of this branch: TWO claims over ONE resource, the process-global current-task slot. `F794`'s `sysv_shm/creator/tests.rs` installs a current task (`become_current` sets `CUR` and `sched::set_current_hook`) under the shm claim, while the sem undo tests file their undo records under `current_tgid()` and assume it reports 0 because no task is installed — an assumption they hold under the SEM lock, which does not exclude the shm one. While a creator test holds `CUR`, a sem `semop_in` files its undo record under the creator's tgid and `semadj_snapshot(0, ..)` reads `None`. NOT fixed here: proven pre-existing by A/B, and folding sem's `TEST_LOCK` into the shm claim (one crate-wide IPC claim, ~38 call sites) is scope this PR should not grow after review started. The fix is small and mechanical for whoever takes it — make `sem::tests::common::TEST_LOCK` an alias of the shm claim's mutex, which leaves every call site untouched. | A/B on the same 60-run loop, same binary shape: `origin/main` (`1b80f8855`) **2/60 red**, this branch **1/60 red**, same tests. Both sides report **230 tests**, so the conflict resolution dropped no coverage. | — |
| FIXED B1694 | high | `ipc` had FOUR copies of `reset()` over the ONE System V shared-memory subsystem — `sysv_shm/tests.rs`, `sysv_shm/shmctl.rs`, `sysv_shm/creator/tests.rs`, and a raw `REG.segs.lock().clear()` in `sysv_shm/shmdt/tests.rs` — and they did not agree on what a reset IS: only two returned `next_id` to 1, only `creator`'s cleared `shm_rmid_forced`. A test's starting state depended on which file it lived in, and a flag one file cleared stayed set for the others. The lock had also been three separate statics when this lane measured the failure; `F794` consolidated the lock while this branch was in review, so what lands here is the reset half: `sysv_shm::test_claim` owns the claim AND the single reset body. The same shape as `fbcon` in B1682, in a different subsystem. | `sys_shmctl(IPC_SET)` returned -22 where 0 was due, 1/12 workspace runs. After the rebase onto `F794`: `ipc` 230 tests, 1/60 red and the only failures are the pre-existing sem row above, which `origin/main` shows at 2/60. | — |
| FIXED B1694 | med | `sync::spin_relax`'s test counted hook invocations in a PROCESS-wide `AtomicU32` while `relax()` is what every contended `Spinlock` in the crate calls. Its comment claimed it was "serialised by being the only test that touches HOOK" — true of the hook slot, false of the counter: while the hook is installed, every sibling test's spinning thread runs it too, and the count overshoots. The counter is now thread-local, which attributes each call to the test that made it — the test's own resource, not the process's. | 1/12 workspace runs before, 0/60 after. | — |
| OPEN | med | `cargo test -p procfs` alone does NOT COMPILE: `error[E0433]: cannot find 'live' in 'sched'`. It only builds under a workspace invocation, where another package's dev-dependency turns the enabling feature on — the feature-unification hazard, in the direction that HIDES a broken package rather than breaking a working one. Same class as the `drv-virtio-input`/`net` note in the B1676 row. Not this lane's to fix: the per-package check gate owns it. | Reproduced on this branch and on a clean `origin/main`; `cargo test --workspace` builds `procfs` fine. | `B1674-hosted-check-gate` lane |
| OPEN | low | Nothing stops the next regression. A test added to any of these crates that does not take its crate's claim reintroduces exactly the defect fixed here, and no gate notices: `cargo test --workspace` is still not run to completion by CI or by the routine gate. Now that the suite is green, wiring it in is a live option rather than a permanently-red gate — the follow-up the B1680 row already anticipated. | The suite went green in this PR; nothing keeps it there. | — |
| OPEN | low | The `--test-threads=1` workaround recorded against three of these packages in the curated ledger is now unnecessary and should not be reached for again: every failure here was a missing owner for a shared resource, and all nine were fixable without serializing the whole binary. Recorded so a future lane reading those rows does not adopt the workaround. | Nine independent resources, nine claims, no global thread cap. | — |
| FIXED B1694 | med | `vfs::tests::quota_limits` asserts "one denial, one warning" against `take_logged_warnings()`, which DRAINS a process-global log. A sibling charging quota into the same log makes the count 2. Every test in the file now claims the log. | `left: 2, right: 1`, 1/12 workspace runs. | — |
| OPEN | med | `ipc`'s `futex_core_hosted::wait_timeout_returns_etimedout_not_a_fake_success` is LOAD-sensitive, not racy on shared state: it bounds a cross-thread handoff with `rx.recv_timeout(Duration::from_secs(5))` and reports `must not hang: Timeout` when the box is saturated by a 48-way workspace run. Seen twice, both times only inside a full workspace run, never in 40 runs of the crate alone. Deliberately NOT fixed here: raising the bound hides load sensitivity rather than removing it, and picking a new number is a judgement the futex lane should make. Same shape to look for in any other hosted test that bounds a handoff with a wall-clock deadline. | 1/12 workspace runs; `finished in 5.00s` where the passing run is 0.00s. | — |
| OPEN | high | The ext4 e2fsck tests still write ~1.8 GB images to FIXED `$TMPDIR` names, unchanged from the B1680 row. Both distributions here were taken with a private `TMPDIR` on `/home` specifically to dodge it. Two concurrent workspace runs, or two lanes on this box, still collide. | Carried forward from B1680; `crates/kernel/ext4/tests/balloc_uninit_e2fsck.rs:136,208`. | — |
