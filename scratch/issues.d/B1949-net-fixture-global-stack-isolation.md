# B1949 — net hosted fixture: namespace-0 isolation was partial

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED B1949 | COVERAGE | high | `hosted_fixture::init_net_domain()` serialised only the tests that ASKED for it, so the net hosted suite flaked at high thread counts. Namespace 0 is process-global (netfilter hook, MIB counters, `iface_addr` rows, route records) but a test could build its own `NetStack`, register a namespace-0 interface and drive traffic through it without taking the guard — bumping an owning test's `LOCAL_OUT_CALLS` hook counter and its `mib::get(0, ..)` samples. Found independently by three lanes (B1939, B1943, B1949) before being fixed. | `cargo test -p net --lib -- --test-threads=24`, 24 runs on `376d175e5`: **9/24 runs FAILED** (`raw4::tx_control_tests::ip_nodefrag_keeps_raw_hdrincl_fragments_out_of_local_out_defrag`, `stack_tests::forwarding::ipv4_ingress_mib_names_unforwardable_and_unknown_packets`). Green at `--test-threads=1`. After the fix: 30/30 runs clean. Positive control: dropping the guard from one converted test reproduced the flake. | Chris Watkins |
| FIXED B1949 | COVERAGE | med | `mib::tests` ran three tests (`a_counted_event_moves_only_its_own_column`, `a_forgotten_namespace_starts_over`, `a_snapshot_reports_every_counter_in_order`) against ONE shared namespace id `0x5150`, each calling `forget()` on it, and `initial_namespace_updates_bypass_the_dynamic_table` bumped namespace 0 unguarded. A second, independent flake of the same class, exposed once the first fix changed the schedule. | 1/30 runs at `--test-threads=24`. Fixed by one namespace id per test plus the guard on the namespace-0 test; 40/30 clean after. | Chris Watkins |
| FIXED B1949 | INFRA | med | `cargo test -p net` was RED on main: the `recv_result::recv_empty` doc comment carried an indented external C excerpt, which rustdoc compiled as a Rust doctest (`error: expected item, found keyword 'if'`). The same comment named an external implementation file, which repository text may not do. | `cargo test -p net --doc` on `376d175e5`: `test crates/kernel/net/src/recv_result.rs - recv_result::recv_empty (line 88) ... FAILED`. Rewritten to state the ABI contract only; `cargo test -p net` now green. | Chris Watkins |
| FIXED B1949 | COVERAGE | med | 70 net tests drove namespace-0 traffic without the ownership guard — the audit surface was far larger than the two tests that visibly flaked. Any of them could have become the next flake as tests were added. | The count is the number of `#[test]` bodies that tripped the new `assert_initial_domain_held` choke point on its first single-threaded run. | Chris Watkins |

## Mechanism

`INITIAL_NET_DOMAIN: Mutex<()>` gives mutual exclusion between guard HOLDERS. It
cannot exclude a non-holder, and a non-holder reaches the same process-global
state through any `NetStack`, because namespace membership — not `NetStack`
identity — selects the netfilter hook, the MIB counters and the address/route
rows. The lock therefore protected the fixture, not the state the fixture
installs into.

## Fix

The ownership requirement is now **checked at the choke point** rather than left
to convention: registering or publishing a namespace-0 interface asserts that the
calling thread holds a live `InitNetDomain` (`hosted_fixture::assert_initial_domain_held`,
tracked by a per-thread depth counter incremented in `init_net_domain()` and
decremented in `InitNetDomain::drop`). A test cannot drive namespace-0 traffic
without an interface, so a new test that forgets the guard fails deterministically
on its first run instead of corrupting a concurrent test's counters. The 70
offending tests take the guard; namespace-private tests (`ForwardingFixture` and
peers) are untouched and still run in parallel.

Rejected: pinning `--test-threads`, retries, `#[ignore]`, or a second lock beside
the existing one. Also rejected for now: migrating the 70 tests to private
namespaces — better parallelism, but 70 semantic rewrites of tests that assert on
namespace-0 behaviour, with no structural guarantee against the next forgotten
guard. The check is what makes the guarantee hold; migrating tests off namespace 0
can proceed incrementally underneath it.
