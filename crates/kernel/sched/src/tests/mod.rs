// Module manifest:
// - common: shared hosted-test fixtures and serialisation helpers.
// - net_namespace: task-owned network namespace lifetime and exit ordering.
// - namespaces: concrete non-network owner lifetime and exit ordering.
// - pidfd: exact identity acquisition, reap ordering, reuse, and readiness.
// - prctl: PR_SET_NAME/PR_GET_NAME comm rename + PR_SET_DUMPABLE/GET_DUMPABLE.
// - queues: RT/CFS/runqueue scheduling invariants and pick/remove behavior.
// - task: Task construction, state, identity, and proc-facing task helpers.
// - procfs: argv/cmdline, tid registry, process-group, and pid-visibility helpers.
// - registry: tid/vpid BTreeMap index correctness, scale, and concurrency (B1429).
// - session: setpgid/setsid/getpgid/getsid/getppid error ladder + personality query.
// - timing: rlimit, clock, preempt, and RCU helper behavior.
// - wake_list: lock-free per-CPU wake list ownership + double-push coalescing.

mod common;
mod net_namespace;
mod namespaces;
mod pidfd;
mod prctl;
mod procfs;
mod queues;
mod registry;
mod session;
mod task;
mod timing;
mod wake_list;
