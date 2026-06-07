// CPU-affinity syscalls (`sched_setaffinity`/`getaffinity`, slots
// 203/204) backed by `Task::cpus_allowed`. Split from proc.rs for the
// 1000-line cap (`08§7`). With real SMP (both arches `-smp 2`) the mask
// is honored by the load balancer (`balance_once` won't migrate a task
// to a CPU outside its mask); cgroup `cpuset.cpus` rewrites it too.
// Handlers moved to per-file modules (docs/53 §0): 203_sched_setaffinity.rs,
// 204_sched_getaffinity.rs; shared helpers in affinity_common.rs.

#![cfg(target_os = "oxide-kernel")]
