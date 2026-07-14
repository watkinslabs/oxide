// Module manifest:
// - common: shared hosted-test fixtures and serialisation helpers.
// - net_namespace: task-owned network namespace lifetime and exit ordering.
// - queues: RT/CFS/runqueue scheduling invariants and pick/remove behavior.
// - task: Task construction, state, identity, and proc-facing task helpers.
// - procfs: argv/cmdline, tid registry, process-group, and pid-visibility helpers.
// - timing: rlimit, clock, preempt, and RCU helper behavior.

mod common;
mod net_namespace;
mod procfs;
mod queues;
mod task;
mod timing;
