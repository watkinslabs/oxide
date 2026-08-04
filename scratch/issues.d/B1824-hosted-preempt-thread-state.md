# B1824 — hosted preemption thread state

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | INFRA | med | Hosted preemption state aliases OS test threads after `cpu::MAX_CPUS`, so one test can observe another's SOFTIRQ context and take an interrupt-only teardown path. | 100 default-parallel `cargo test -p net --lib` repetitions failed on run 47: `sock_rtnl_defer::tests::process_context_final_drop_still_releases_inline` deferred its process-context release. `sched::preempt::hosted_cpu_slot` wraps its thread allocation at 64. | B1824-hosted-preempt-thread-state |
