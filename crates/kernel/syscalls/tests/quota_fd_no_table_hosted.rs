use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

#[path = "../src/179_quotactl/cmd.rs"]
mod cmd;

mod s443_quotactl_fd {
    pub fn quotactl_fd_file(_file: &vfs::File, _cmd: u64, _id: u64, _addr: u64) -> i64 {
        panic!("missing fd table must return before fd dispatch")
    }
}

#[path = "../src/443_quotactl_fd/sys.rs"]
mod qfd_sys;

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: tests publish leaked Task pointers and clear only between serialized cases.
    Some(unsafe { &*(ptr as *const sched::Task) })
}

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CURRENT_TASK_PTR.store(0, Ordering::Release);
    sched::set_current_hook(hosted_current_task);
    guard
}

fn install_current_without_fd_table() {
    let task = Box::leak(Box::new(sched::Task::new(0x4d20, "quotactl-fd-no-table-hosted", sched::SchedClass::Normal { weight: 1024 })));
    // SAFETY: hosted test owns this leaked task and intentionally removes its descriptor table before publishing it.
    unsafe { task.replace_fd_table(None); }
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
}

#[test]
fn sys_quotactl_fd_no_fd_table_returns_ebadf_before_cmd_validation_hosted() {
    let _guard = begin_test();
    install_current_without_fd_table();
    let args = SyscallArgs {
        a0: 7,
        a1: cmd::qcmd(cmd::Q_SYNC, cmd::MAXQUOTAS),
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Ebadf));
}
