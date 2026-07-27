// Module manifest:
// - affinity: cpus_allowed fork inheritance + cpuset/user-mask composition.
// - common: shared hosted-test fixtures and serialisation helpers.
// - cpu_nanosleep: CPU-clock clock_nanosleep arm/resolve + accounting-tick service.
// - exit_notify: exit_notify/forget_original_parent adoption order + autoreap.
// - net_namespace: task-owned network namespace lifetime and exit ordering.
// - namespaces: concrete non-network owner lifetime and exit ordering.
// - pidfd: exact identity acquisition, reap ordering, reuse, and readiness.
// - prctl: PR_SET_NAME/PR_GET_NAME comm rename + PR_SET_DUMPABLE/GET_DUMPABLE.
// - queues: RT/CFS/runqueue scheduling invariants and pick/remove behavior.
// - task: Task construction, state, identity, and proc-facing task helpers.
// - procfs: argv/cmdline, tid registry, process-group, and pid-visibility helpers.
// - registry: tid/vpid BTreeMap index correctness, scale, and concurrency (B1429).
// - rlimit_prio: getpriority(2) return bias, RLIMIT_NICE units, process-wide rlimits.
// - session: setpgid/setsid/getpgid/getsid/getppid error ladder + personality query.
// - signals: per-signal queue depth, shared-vs-private pending, saved sigmask.
// - timing: rlimit, clock, preempt, and RCU helper behavior.
// - umask: fs_struct-owned umask(2) sharing across CLONE_FS / fork / unshare.
// - wake_list: lock-free per-CPU wake list ownership + double-push coalescing.

mod affinity;
mod common;
mod cpu_nanosleep;
mod exit_notify;
mod net_namespace;
mod namespaces;
mod pidfd;
mod prctl;
mod procfs;
mod queues;
mod registry;
mod rlimit_prio;
mod session;
mod signals;
mod task;
mod timing;
mod umask;
mod wake_list;
