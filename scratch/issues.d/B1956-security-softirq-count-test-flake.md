# B1956 — hosted preempt count was shared by every libtest worker thread

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED B1956 | DEFECT | high | `sched::preempt` selected its thread-local hosted count on `any(test, feature = "hosted")`, so hosted-ness depended on whether a DOWNSTREAM crate remembered to enable `sched/hosted`. A crate that did not (`security`, and every other host test crate that omits the feature) compiled the per-CPU ARRAY path with `this_cpu()` pinned to 0 — one `AtomicU32` shared by every libtest worker thread. One test's `spin_lock_bh` was then visible in every other test's `softirq_count()`. | `security::network::tests::network_registry_lock_excludes_bottom_halves_for_the_guard_lifetime` failed `1/40` runs at the default thread count (`left: 512` = exactly one `SOFTIRQ_DISABLE_OFFSET`, i.e. another worker inside `HOOKS.lock()`), `1/20` at `--test-threads=32`, and `0/40` at `--test-threads=1`. After the fix: `0/40` default, `0/20` at `--test-threads=32`. | Chris Watkins |
| FIXED B1956 | COVERAGE | high | Nothing could fail when a downstream hosted build picked the shared count. The `sched` crate's own tests carry `cfg(test)`, so they always took the thread-local path and pass either way — a textbook phantom check: the defect is only observable from a crate that depends on `sched`. | New `security::network::tests::bottom_half_state_is_private_to_the_observing_thread` holds `spin_lock_bh` on a second OS thread and asserts the observer sees 0. Positive control: reinstating the old `cfg` makes it fail deterministically (`left: 512, right: 0`, `1/1` runs) instead of the old `1/40`. | Chris Watkins |
| OPEN | COVERAGE | high | `crates/kernel/socket` tests flake ~20 %: `security_hooks::fixture()` serialises only the tests that ASK for its private `LOCK`, but the policy it installs lands in the process-global `security::network::HOOKS` for the ONE hosted network namespace. Tests elsewhere in the crate (`tests::batch_imports_and_publishes_one_message_at_a_time`, `tests::netlink_prepares_oob_length_control_and_address_in_linux_order`, `tests::oversized_socket_batch_is_limited_to_linux_uio_maxiov`) drive sends through that same namespace without the guard, so they see a concurrent test's `deny` hook (`Err(Eacces)`) and bump its counters (`Some((0, 2))` vs `Some((0, 1))`). Identical mechanism to the net-fixture row in `B1949`: the lock protects the fixture, not the state the fixture installs into. | `cargo test -p socket`, 40 runs: **8/40 FAILED on the unmodified base**, 6/40 with this branch's `sched` change — pre-existing and unrelated to it. Green at `--test-threads=1`. | unassigned (outside B1956's file ownership) |

## Mechanism — how to diagnose a bottom-half / preempt count anomaly next time

The count has exactly two owners, chosen by TARGET, never by feature:

| build | owner | scope |
|---|---|---|
| `target_os = "oxide-kernel"` | `PREEMPT_COUNT[this_cpu()]` | per CPU |
| anything else (hosted) | `HOSTED_PREEMPT_COUNT` thread-local | per OS thread |

A hosted `softirq_count()` that is non-zero where the code path cannot explain it
is one of two things, and the thread-count sweep separates them in one step:

- fails at `--test-threads=1` as well ⇒ a real LEAK — an unpaired
  `local_bh_disable`, a `BhGuard`/`LockBhGuard` that was forgotten or moved
  somewhere it is never dropped, or an error return that skips the enable.
- green at `--test-threads=1`, fails only in parallel ⇒ cross-thread
  INTERFERENCE, i.e. the count is not private to the observer. That is the shape
  this row fixed, and the new test is what keeps it fixed.

The leaked value names the operation: `0x200` (`SOFTIRQ_DISABLE_OFFSET`) is one
`local_bh_disable` / `spin_lock_bh`; `0x100` (`SOFTIRQ_OFFSET`) is a drain in
progress; `0x10000` is a hard-IRQ level; a low-byte value is plain
`preempt_disable` nesting.

## Fix

`preempt.rs` now selects on `target_os = "oxide-kernel"` alone, and the per-CPU
array is compiled ONLY into the kernel build, so a hosted build has no second
place the count could live. `sched`'s `extern crate std` follows the same
predicate — a non-kernel target IS hosted, which is not a fact a downstream
`Cargo.toml` gets a vote on. The `hosted` feature keeps its other job (gating the
task/live modules); it no longer decides where the count lives.

Rejected: pinning `--test-threads`, retries, `#[ignore]`, reordering, or relaxing
the absolute-zero assertion — that assertion is the only thing in the tree that
can observe a bottom-half count leak.
