# B1955 — nscg hosted suite had no owner for its process-global namespace state

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED B1955 | COVERAGE | high | Enumerating the canonical active namespace registry materialises a strong pin for EVERY live namespace in the process. While such a page is alive, another test's last owner drop is not the final drop, so the finalizers that erase per-namespace state (`uts_ns::remove`, `cgroup_ns::remove`) have not run when its `close()` returns. `nsfd_only_owner_retains_uts_state_until_close` therefore raced every test that listed namespaces. | Probe on `b44d2a8fc`: 200 000 allocate/drop cycles beside one thread calling the global snapshot in a loop — **16 280 cycles observed the UTS state still present after the final owner ref dropped** (`weak.upgrade()` was `None` in all 200 000, so the failing assertion is the state-removal one, not the liveness one). After the fix: 300/300 runs at `--test-threads=16`, 50/50 at each of 4/8/32/48/64. | Chris Watkins |
| FIXED B1955 | COVERAGE | high | `network-namespace` publishes ONE immutable final-drop callback per process and refuses `allocate` until it is published. Only 4 nscg tests published it, so `ipc_net_cgroup_setns_all_require_sys_admin` (and any future net test) passed only when an earlier test had already published — a cross-test ordering dependency that changes with the thread count. | `b44d2a8fc`, unmodified: **2/200 runs** of the test binary at `--test-threads=16` failed with `called Result::unwrap() on an Err value: FinalDropCallbackMissing`, and 2/30 via `cargo test`. This, not the UTS test, was the failure the baseline loop actually produced here. After the fix: 0/300. | Chris Watkins |
| FIXED B1955 | COVERAGE | med | `structural_no_successor_differs_from_filtered_empty_page` derived a cursor from the largest UTS global id observed a moment earlier, then asserted that listing from it yields `NoSuccessor`. Any concurrent allocation publishes a higher id, turning the structural no-successor into a page. Pre-existing: the suite's private `TEST_LOCK` serialised listns tests against each other but never against the tests in other modules that allocate UTS namespaces. | 1 of the first 2 full-workspace runs at `--test-threads=16` (`left: None, right: Some(NoSuccessor)`). Too rare for the isolated loop: 240 runs under 4-way parallel load did not reproduce it. Made deterministic by injecting the allocation between the snapshot and the listing — fails 1/1. The rewritten test passes 1/1 with the same allocation injected. | Chris Watkins |
| FIXED B1955 | INFRA | low | `cgroup_ns.rs` header path-linked an external implementation file, which repository text may not do. | Header comment; the surrounding symbol names are kept, the path is gone. | Chris Watkins |

## Mechanism

One process-global registry, three operations that interact, and no owner for
any of them:

- **allocate** publishes an identity into the active indexes;
- **enumerate** upgrades every weak index entry into a strong pin — including
  pins to namespaces private to other tests;
- **final drop** runs the registered finalizers that erase per-namespace state.

Enumeration defers an unrelated test's final drop for exactly as long as the
page lives, so "the finalizer ran by the time `close()` returned" is true only
when nothing is enumerating. This is correct production behaviour — a concurrent
holder of a reference legitimately extends a namespace's lifetime, and the
kernel's own listing path is a reference holder. No production ordering bug was
involved; the defect was that the hosted suite asserted quiescence it never
established.

The network-namespace callback is the same shape one level up: a global slot
whose contents depended on which test ran first.

## Fix

- **Publication before `main`.** The hosted final-drop notifier is installed from
  a single `.init_array` constructor in `nscg::test_support`, so no test body can
  observe the empty slot and ordering cannot matter. `install_test_final_drop_callback`
  and its four scattered call sites are gone; `test_support::net_ns()` is the one
  way nscg tests allocate a network namespace.
- **Membership decides who may enumerate.** One `RwLock` in `test_support`:
  `registry_scan()` (exclusive) is required to enumerate, `drop_isolation()`
  (shared, so those tests still run in parallel) is required to observe a
  finalizer running. Enumeration is reachable only as a method on the guard.
- **The requirement is checked at the choke points, not left to convention.**
  `listns::candidates` — the single function all three enumeration entry points
  pass through — asserts a live scan under `#[cfg(test)]`; `uts_ns::contains` and
  `cgroup_ns::contains` assert isolation. A test that forgets fails on its first
  single-threaded run instead of flaking later. The listns suite's private
  `TEST_LOCK` is deleted rather than left beside the new guard.
- **Where quiescence was incidental, the dependency is removed instead of
  guarded.** The no-successor test now uses a cursor above every allocatable id;
  the guard does not exclude allocation, and it should not have to.

Rejected: pinning `--test-threads`, retries, `#[ignore]`, reordering, weakening
an assertion, and a second lock beside the existing one.

## Positive controls

| Removed | Result |
|---|---|
| `registry_scan()` from `listns::tests::nsfd_only_dynamic_uts_is_listed_and_retained` | panics at the `candidates` choke point, `--test-threads=1`, 1/1 |
| `drop_isolation()` from `nsfd_only_owner_retains_uts_state_until_close` (calling `uts_ns::contains` directly, as a forgetful future test would) | panics at the `contains` choke point, `--test-threads=1`, 1/1 |
| the deterministic cursor, restoring the observed-maximum one, with an allocation injected into the window | `left: None, right: Some(NoSuccessor)`, 1/1 — the exact workspace-run signature |

All restored; 57 tests before and after (no test compiled out).

## Same class, not in this lane

`time-namespace` and `user-namespace` each carry the identical
`contains()`-after-final-drop helper against a finalizer-erased map. Their own
test binaries are separate processes and neither suite enumerates the registry,
so neither can flake today — but a listing test added to either crate would
reproduce this exactly.
