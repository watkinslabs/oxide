# F779-rusage-times-child-rollup

Filed by the F779 lane; restored by F781 after the rows were lost resolving the
#4338 merge conflict (the code landed, the ledger content did not).

The `net::sock_opts` gate break this lane also hit is NOT repeated here — it is
already filed by `B1662-ip-sockopt-consumers-b` (the owning lane) and
`B1667-show-unhandled-signals`. Corroborating evidence only: it reproduces on
clean detached worktrees at `origin/main` 80e6adf05, 10b0a909a and eaa2e33cb, so
it is not branch-local, and `cargo test -p fs` is blocked by it as well as
`cargo test -p procfs`.

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | low | `ru_utime`/`ru_stime` and `times(2)`'s `tms_utime`/`tms_stime` are tick-sampled per-task counters, not the scaled pair upstream derives so that user+system exactly equals the task's total run time. The two can therefore differ from `sum_exec_runtime` by up to a tick per thread. Deliberate: the sampled values are the more direct measurement and no known consumer depends on the identity. Revisit if a benchmark or a `getrusage`-based profiler reports the discrepancy. | F779, negative result — no test asserts the identity because it does not hold. | — |
| OPEN | low | `fs/tests/keyring_procfs.rs::a_new_key_appears_in_the_proc_keys_body_procfs_renders` failed ONCE (assertion at line 37) in a combined `-p ... -p net -p fs` run on base `4a110da60`, and did not reproduce on later bases in a 6257-test full run. NOT attributed: it may be the known net global-state test race, or base-dependent. Recorded so the next observer has a prior rather than treating it as new. | F779, one observation, not reproduced. An observation, not a diagnosis. | — |
