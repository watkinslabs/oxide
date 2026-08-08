// `/proc/sys/fs/mqueue/*`.
//
// Every leaf is per-IPC-namespace: `set_lookup` resolves
// `current->nsproxy->ipc_ns->mq_set`, so a namespace that raised its
// `msg_max` does not raise anybody else's. The values live with the queues
// they gate (`model::MqDir::sysctls`) rather than in a procfs-owned copy, so
// `mq_open`'s EINVAL ceiling and the file can never disagree.

use crate::mqueue_policy::attr::MqSysctls;

use super::model;
use super::user::ipc_ns;

fn read(pick: fn(&MqSysctls) -> i64) -> i64 {
    match ipc_ns() { Ok(ns) => pick(&model::sysctls(ns)), Err(_) => 0 }
}

fn write(apply: fn(&mut MqSysctls, i64)) -> impl FnOnce(i64) {
    move |v| { if let Ok(ns) = ipc_ns() { model::update_sysctls(ns, |s| apply(s, v)); } }
}

/// # C: O(N_ns)
pub fn queues_max() -> i64 { read(|s| s.queues_max as i64) }
/// # C: O(N_ns)
pub fn set_queues_max(v: i64) { write(|s, v| s.queues_max = v.max(0) as u32)(v) }
/// # C: O(N_ns)
pub fn msg_max() -> i64 { read(|s| s.msg_max) }
/// # C: O(N_ns)
pub fn set_msg_max(v: i64) { write(|s, v| s.msg_max = v)(v) }
/// # C: O(N_ns)
pub fn msgsize_max() -> i64 { read(|s| s.msgsize_max) }
/// # C: O(N_ns)
pub fn set_msgsize_max(v: i64) { write(|s, v| s.msgsize_max = v)(v) }
/// # C: O(N_ns)
pub fn msg_default() -> i64 { read(|s| s.msg_default) }
/// # C: O(N_ns)
pub fn set_msg_default(v: i64) { write(|s, v| s.msg_default = v)(v) }
/// # C: O(N_ns)
pub fn msgsize_default() -> i64 { read(|s| s.msgsize_default) }
/// # C: O(N_ns)
pub fn set_msgsize_default(v: i64) { write(|s, v| s.msgsize_default = v)(v) }
