use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const SPECIAL_ADDR: u64 = 0x5155_5E10;
const BAD_SPECIAL_ADDR: u64 = 0x5155_5E11;
const QUOTAON_ADDR: u64 = 0x5155_5E12;

static RESOLVE_SPECIAL: AtomicBool = AtomicBool::new(false);
static READ_USER_PATH_CALLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(addr: u64) -> Result<String, i64> {
        crate::READ_USER_PATH_CALLS.lock().unwrap().push(addr);
        if addr == crate::BAD_SPECIAL_ADDR {
            return Err(-(syscall::errno::Errno::Efault.as_i32() as i64));
        }
        Ok("/dev/quota-block-path-errors-hosted".into())
    }
}

mod pathresolve {
    pub fn resolve_path_raw(_raw: &str, _follow: bool) -> vfs::KResult<vfs::VfsPath> {
        if !crate::RESOLVE_SPECIAL.load(core::sync::atomic::Ordering::Acquire) {
            return Err(vfs::VfsError::Enoent);
        }
        Err(vfs::VfsError::Einval)
    }
}

#[path = "../src/179_quotactl/abi.rs"]
mod abi;
#[path = "../src/179_quotactl/cmd.rs"]
mod cmd;
#[path = "../src/179_quotactl/dispatch.rs"]
mod dispatch;
#[path = "../src/179_quotactl/sys.rs"]
mod sys;
#[path = "../src/179_quotactl_xfs.rs"]
mod xfs;

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    RESOLVE_SPECIAL.store(false, Ordering::Release);
    sched::set_current_hook(|| None);
    guard
}

fn args(special: u64) -> SyscallArgs {
    SyscallArgs {
        a0: cmd::qcmd(cmd::Q_GETFMT, cmd::USRQUOTA),
        a1: special,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    }
}

fn quotaon_args(special: u64, addr: u64) -> SyscallArgs {
    SyscallArgs {
        a0: cmd::qcmd(cmd::Q_QUOTAON, cmd::USRQUOTA),
        a1: special,
        a2: vfs::QFMT_VFS_V1 as u64,
        a3: addr,
        a4: 0,
        a5: 0,
    }
}

#[test]
fn sys_quotactl_special_usercopy_error_precedes_current_task_hosted() {
    let _guard = begin_test();

    assert_eq!(sys::sys_quotactl(&args(BAD_SPECIAL_ADDR)), eno(Errno::Efault));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[BAD_SPECIAL_ADDR]);
}

#[test]
fn sys_quotactl_special_lookup_error_precedes_current_task_hosted() {
    let _guard = begin_test();

    assert_eq!(sys::sys_quotactl(&args(SPECIAL_ADDR)), eno(Errno::Enoent));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
}

#[test]
fn sys_quotactl_quotaon_defers_quota_path_error_but_bad_special_usercopy_wins_hosted() {
    let _guard = begin_test();

    assert_eq!(sys::sys_quotactl(&quotaon_args(BAD_SPECIAL_ADDR, QUOTAON_ADDR)), eno(Errno::Efault));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[QUOTAON_ADDR, BAD_SPECIAL_ADDR]);
}
