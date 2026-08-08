# B1957 — socket hosted suite had no owner for its process-global send state

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED B1957 | COVERAGE | high | `tests/security_hooks.rs::fixture()` serialised only the five tests that ASKED for its private `LOCK`, but the policy it installs lands in the process-global network-security registry for the ONE hosted network namespace every socket send target is built in. Eighteen other tests in the crate drove sends through that same namespace with no claim at all, so they were judged by a concurrent test's `deny` hook (`Err(Eacces)` where the family answer was expected) and bumped its evaluation counters (`Some((0, 2))` where the owner asserted `Some((0, 1))`). Third occurrence of the pattern fixed in `B1949` and `B1955`: the lock protects the fixture, not the state the fixture installs into. | `cargo test -p socket` at the default thread count on `5eeb9d411`, unmodified: **10/40 runs FAILED**, across **16 distinct tests** — the three named in the `B1956` row were 11 of the 36 individual failures; the other 25 fell on 13 tests nobody had connected to the fixture (`vsock_*`, `unix_scm_*`, `sendmmsg_*`, `sendto_*`, `udp_sendmsg_*`, `phased_batch_*`, and the fixture's own `an_internet_send_reaches_the_message_hook` / `one_send_asks_the_hook_exactly_once`). Green at `--test-threads=1`. After: **0/40** default, and 0/20 at each of `--test-threads` 1, 8, 16, 32, 64. | Chris Watkins |
| FIXED B1957 | COVERAGE | med | `receive_tests.rs`'s `SCM_SERIAL` was the same shape one resource over: a private lock over the process-global AF_UNIX in-flight/GC graph, taken by every test in that file by convention only. It had already been widened once (2/12 failures) after being taken by one test out of six — the next test added to the file would have had nothing to stop it forgetting again. | Converted to the crate's one claim, checked at `receive::install_received_fds`. Positive control: dropping the claim from `zero_capacity_discards_complete_batch` panics at the choke point, `--test-threads=1`, 1/1. | Chris Watkins |
| OPEN | COVERAGE | low | `packet_tests.rs::packet_tx_ring_file()` registers an interface into the process-global interface table for namespace 0 and brings it up, with no claim on that table. `net`'s own `assert_initial_domain_held` choke point (`B1949`) is `#[cfg(test)]` **within `net`**, so it compiles out of `socket`'s test binary and cannot see this. The two packet tests each get their own ifindex, so they do not collide today, and the claim added here does not cover the interface table. | Not observed to fail: 0 occurrences across the 40 baseline and 140 post-fix `socket` runs. Structural, not measured — a future socket test that asserts on namespace-0 interface or MIB state would race these two. | unassigned |
| FIXED B1957 | INFRA | low | `src/tests.rs` was 541 lines, over the `docs/08§7` 500-line cutoff, so the conversion could not be written into it. | Split into `tests/{common,batch,phases,vsock,unix_scm}.rs` (105/170/107/133 lines) behind a manifest `tests.rs`. Verified by test-name MULTISET, not name set: 49 leaf names before, 49 after, `diff` clean — none dropped, none duplicated. | Chris Watkins |

## Mechanism

Every socket send entry point (`send`, `send_io`, `send_batch`, `write`,
`writev`) funnels through `send::prepare` into `security::admit`, which asks the
namespace-keyed security registry exactly one question. The namespace comes from
the socket, and every hosted target — UDP, netlink, vsock, AF_UNIX, AF_PACKET —
is built in `network_namespace::initial()`. So the registry entry one test
installs is the registry entry every other test's send is judged by, and its
allowed/denied counters are incremented by their traffic.

`std::sync::Mutex` gives mutual exclusion between HOLDERS. It cannot exclude a
non-holder, and nothing about reaching the registry requires holding it. The
fixture lock was therefore load-bearing for correctness and enforced by nothing.

No production ordering bug was involved: the hook is asked once, in the right
place, ahead of the family validation. **The fix is entirely test-side** — the
only non-test lines are two `#[cfg(test)]` assertion calls at the choke points.

## Fix

- **One owner per global resource, in one module.** `socket::test_support`
  (`#[cfg(test)]`) owns both: the initial namespace's security policy and the
  AF_UNIX in-flight graph. `security_hooks.rs`'s private `LOCK` and
  `receive_tests.rs`'s `SCM_SERIAL` are DELETED, not left beside the new claim.
- **Shared where sharing is safe.** Policy is an `RwLock`: `policy_control()`
  (exclusive) is required to install, remove, or count policy; `unpoliced()`
  (shared) is required to drive a send through the namespace and asserts nothing
  about the registry beyond its being empty, so the 18 sending tests still run in
  parallel with each other. Only the 5 fixture tests serialise.
- **Checked at the choke point, not by convention.** `security::admit` — the one
  function every send passes through to reach the registry — asserts the calling
  thread holds a claim when the target namespace is the initial one, tracked by a
  per-thread depth counter raised in the constructor and lowered in `Drop`.
  `receive::install_received_fds` does the same for the rights graph. A new test
  that forgets fails deterministically on its FIRST single-threaded run.
- The assertion is placed after the target is classified, so the three tests that
  send to a regular file (`Enotsock` before any namespace exists) need no claim
  and are untouched.

Rejected: pinning `--test-threads`, retries, `#[ignore]`, reordering, weakening
an assertion, and a second lock beside an existing one.

## Positive controls

| Removed | Result |
|---|---|
| `unpoliced()` from `tests::vsock::vsock_oob_imports_envelope_only` | panics at the `admit` choke point, `--test-threads=1`, 1/1 |
| `scm_graph()` from `receive_tests::zero_capacity_discards_complete_batch` | panics at the `install_received_fds` choke point, `--test-threads=1`, 1/1 |

Both restored; 49 tests before and after.

## What generalises — this is the third instance, and the fourth is already written

`B1949` (net), `B1955` (nscg) and this one are the same defect with three
different nouns. The recurring shape:

1. A crate has a hosted fixture that installs into a **process-global** static.
2. The fixture takes a private lock, so its own tests do not race each other.
3. Nothing requires a non-holder to take it, and the global is reachable by any
   test that merely constructs the ordinary object (a `NetStack`, a namespace,
   a socket) — so the lock's protection is a convention, invisible at every site
   that needs it.
4. The visible failures are a small fraction of the exposed surface: 2 of 72 in
   `B1949`; here the row that opened this lane named 3, the flake loop exposed 16,
   and the check found 23. The count of tests that TRIP the new check on its first
   run is the real number; the flake rate only samples it.

The fix has been the same three parts every time, and is worth copying verbatim:
**(a)** one owner module per crate holding one claim type per global resource,
exclusive and shared where the distinction buys parallelism; **(b)** a per-thread
depth counter raised on acquire and lowered in `Drop`; **(c)** a `#[cfg(test)]`
assertion at the single function every entry path passes through — never at the
test, which is exactly the place that forgets.

Diagnosis is mechanical and needs no theory: **green at `--test-threads=1` and
red in parallel means shared state, not a leak**; a failure at both means a leak.
That one sweep separates the two classes in a single step.

### Making the class impossible rather than fixing it a fourth time

Two levers, in order of value:

- **Stop pinning the singleton.** All three globals are already keyed (by
  namespace id); the hosted fixture just pins one key — `initial()` / id 0 — for
  every test. A hosted suite that allocated a PRIVATE key per test would need no
  claim, no assertion and no serialisation, and the check would have nothing to
  catch. This is the only fix that removes the class rather than guarding it.
  It is a per-test semantic rewrite (some tests assert on initial-namespace
  behaviour specifically, and those genuinely cannot move), so it proceeds
  incrementally UNDERNEATH the checks, which is the order `B1949` chose.
- **Detect the candidates before they flake.** The precondition is grep-able:
  a `static` `Mutex`/`RwLock`/`Spinlock`/`Atomic*` reachable from a crate with
  hosted tests, whose accessor carries no `cfg(test)` ownership assertion. A
  sweep of `static <NAME>: std::sync::{Mutex,RwLock}` in test modules returns
  **25 further private serialisation locks** across `drv-virtio-blk`, `crng`,
  `devfs`, `fs/timerfd`, `input`, `ipc`, `modules` (×3), `net` (×3), `pidfd`,
  `sched` (×6), `syscalls`, `sysfs` (×4) and `sync/rcu`. Each is a fixture lock
  that may or may not have a non-holder path to the same global; each is a
  candidate for occurrence four. A tool that lists them with "does the accessor
  assert ownership?" would turn this from a discovery per incident into one
  audit. Worth building before the next flake finds one of them for us.

A shared `hosted-claim` helper crate (claim type + per-thread depth + assert
macro) would remove the copied boilerplate, but NOT the class: it still depends
on someone remembering to call the assertion at the choke point. Prefer the two
levers above.
