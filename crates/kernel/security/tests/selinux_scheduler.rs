use core::sync::atomic::Ordering;

use sched::{SchedClass, Task};
use selinux::{BootConfig, Enforcing};
use syscall::errno::Errno;

const SID_USER: u32 = 1;
const CALLER_TID: u32 = 0x7fff_fe01;
const TARGET_TID: u32 = 0x7fff_fe02;
const EACCES: i64 = -(Errno::Eacces as i32 as i64);
const EPERM: i64 = -(Errno::Eperm as i32 as i64);

fn task(tid: u32) -> Task {
    let task = Task::new(tid, "selinux-scheduler-test", SchedClass::Normal { weight: 1024 });
    task.security.creds.cap_effective.store(0, Ordering::Release);
    task.security.creds.cap_permitted.store(0, Ordering::Release);
    task.security.selinux_label.lock().sid = SID_USER;
    task
}

fn load(allow_setsched: bool) {
    let image = selinux::test_policy::scheduler(allow_setsched);
    selinux_runtime::with(|server| server.load_policy(&image))
        .expect("the live SELinux server is installed")
        .expect("the scheduler policy image loads");
}

#[test]
fn real_selinux_provider_decides_process_setsched_after_capability() {
    // SAFETY: this integration-test process has one initialization thread and
    // invokes the boot-time registration routine exactly once.
    unsafe { security::init().expect("initialize the real LSM providers"); }
    assert!(selinux_runtime::install(BootConfig {
        enabled: true,
        enforcing: Some(Enforcing::Enforcing),
    }));
    assert_eq!(security::active_lsm_ids(), [
        security::lsm::LSM_ID_CAPABILITY,
        security::lsm::LSM_ID_LANDLOCK,
        security::lsm::LSM_ID_SELINUX,
        security::lsm::LSM_ID_BPF,
    ]);

    let caller = task(CALLER_TID);
    let target = task(TARGET_TID);
    load(false);

    target.security.creds.cap_permitted.store(1, Ordering::Release);
    assert_eq!(security::lsm::task_setscheduler(&caller, &target), Err(EPERM),
        "capability is the first decisive scheduler provider");

    target.security.creds.cap_permitted.store(0, Ordering::Release);
    assert_eq!(security::lsm::task_setscheduler(&caller, &target), Err(EACCES),
        "the enforcing SELinux policy refuses process:setsched");

    load(true);
    assert_eq!(security::lsm::task_setscheduler(&caller, &target), Ok(()),
        "the same real provider permits the policy's allow rule");
}
