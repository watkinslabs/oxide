// Built-in providers for task priority and scheduler-policy hooks.

use core::sync::atomic::Ordering;

fn cap_safe_nice(caller: &sched::Task, target: &sched::Task) -> Result<(), i64> {
    let caller_permitted = caller.security.creds.cap_permitted.load(Ordering::Acquire);
    let target_permitted = target.security.creds.cap_permitted.load(Ordering::Acquire);
    if target_permitted & !caller_permitted == 0
        || nscg::proc_ns::has_cap_for_task(caller, target, sched::cap::SYS_NICE) {
        return Ok(());
    }
    Err(-(syscall::errno::Errno::Eperm.as_i32() as i64))
}

fn capability_setnice(caller: &sched::Task, target: &sched::Task, _nice: i32)
    -> Result<(), i64>
{
    cap_safe_nice(caller, target)
}

fn capability_setscheduler(caller: &sched::Task, target: &sched::Task) -> Result<(), i64> {
    cap_safe_nice(caller, target)
}

fn selinux_setscheduler(caller: &sched::Task, target: &sched::Task) -> Result<(), i64> {
    let ssid = caller.security.selinux_label.lock().sid;
    let tsid = target.security.selinux_label.lock().sid;
    selinux_runtime::check::class_permissions(ssid, tsid, "process", &["setsched"])
}

fn selinux_setnice(caller: &sched::Task, target: &sched::Task, _nice: i32) -> Result<(), i64> {
    selinux_setscheduler(caller, target)
}

/// Install capability first and SELinux at its resolved framework position.
/// # C: O(providers)
pub(crate) fn register() {
    crate::lsm::register_task_setnice_for(crate::lsm::LSM_ID_CAPABILITY, capability_setnice);
    crate::lsm::register_task_setscheduler_for(
        crate::lsm::LSM_ID_CAPABILITY, capability_setscheduler);
    crate::lsm::register_task_setnice_for(
        crate::lsm::LSM_ID_BPF, crate::bpf_lsm::task_setnice_hook);
    crate::lsm::register_task_setscheduler_for(
        crate::lsm::LSM_ID_BPF, crate::bpf_lsm::task_setscheduler_hook);
    crate::lsm::register_task_setnice_for(crate::lsm::LSM_ID_SELINUX, selinux_setnice);
    crate::lsm::register_task_setscheduler_for(crate::lsm::LSM_ID_SELINUX, selinux_setscheduler);
}
