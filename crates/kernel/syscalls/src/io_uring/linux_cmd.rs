// External-driver io_uring command lifetime.  The ABI export facade is in
// modules; this owner retains the request until a driver completes it.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use modules::linux_io_uring::LinuxIoUringCmd;

use super::req::IoReq;

#[repr(C)]
pub struct IoTwReq { pub req: *mut c_void }
#[repr(C)]
pub struct IoTwState { pub cancel: bool }
type TaskFn = unsafe extern "C" fn(IoTwReq, IoTwState);

/// One command whose address is also its target `struct io_kiocb` address.
#[repr(C)]
pub struct ExternalCmd {
    pub cmd: LinuxIoUringCmd,
    req: Arc<IoReq>,
    file: Arc<vfs::File>,
    abi_file: *mut c_void,
    task: AtomicUsize,
}

impl ExternalCmd {
    /// Allocate a command whose first byte is the ABI `io_uring_cmd`.
    /// # C: O(1)
    pub fn new(req: Arc<IoReq>, file: Arc<vfs::File>, abi_file: *mut c_void) -> Box<Self> {
        Box::new(Self {
            cmd: LinuxIoUringCmd { file: abi_file, sqe: req.sqe.raw.as_ptr(), cmd_op: 0,
                flags: 0, pdu: [0; 32], unused: [0; 8] },
            req, file, abi_file, task: AtomicUsize::new(0),
        })
    }
}

/// Recover the complete command lifetime from its ABI first member.
/// # C: O(1)
unsafe fn state(cmd: *mut LinuxIoUringCmd) -> Option<&'static ExternalCmd> {
    if cmd.is_null() { return None; }
    // SAFETY: ExternalCmd is repr(C) and cmd is its first field for every command dispatched here.
    Some(unsafe { &*cmd.cast::<ExternalCmd>() })
}

/// Complete exactly once, post the selected CQE width, and release ABI storage.
/// # C: O(N_chain)
pub unsafe extern "C" fn done(cmd: *mut LinuxIoUringCmd, ret: i32, res2: u64, _flags: u32, cqe32: bool) {
    let Some(s) = (unsafe { state(cmd) }) else { return; };
    let req = Arc::clone(&s.req);
    if !req.claim() { return; }
    let file = Arc::clone(&s.file);
    let abi_file = s.abi_file;
    let out = if cqe32 { super::dispatch::OpOutcome::wide(ret as i64, [res2, 0]) }
        else { super::dispatch::OpOutcome::res(ret as i64) };
    super::iowq::run::complete_out(&req, out);
    // SAFETY: this successful claim is the one terminal completion and owns the allocation.
    unsafe { drop(Box::from_raw(cmd.cast::<ExternalCmd>())); }
    // SAFETY: the command allocation retained the matching open file and ABI object until terminal completion.
    unsafe { vfs::opened_chrdev_uring_file_drop(&file, abi_file); }
}

/// Queue a driver task-work callback against the retained command.
/// # C: O(1)
pub unsafe extern "C" fn do_in_task(cmd: *mut LinuxIoUringCmd, callback: usize, _flags: u32) {
    let Some(s) = (unsafe { state(cmd) }) else { return; };
    if callback == 0 { return; }
    if s.task.compare_exchange(0, callback, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    if !sched::live::workqueue::queue_work(run_task, cmd as usize) { run_task(cmd as usize); }
}

fn run_task(arg: usize) {
    let cmd = arg as *mut LinuxIoUringCmd;
    let Some(s) = (unsafe { state(cmd) }) else { return; };
    let task = s.task.swap(0, Ordering::AcqRel);
    if task == 0 { return; }
    // SAFETY: do_in_task stored the module callback's exact io_tw_req/io_tw_state ABI address.
    let callback: TaskFn = unsafe { core::mem::transmute(task) };
    // SAFETY: cmd is the io_kiocb-addressed first field required by io_uring_cmd_from_tw.
    unsafe { callback(IoTwReq { req: cmd.cast() }, IoTwState { cancel: false }); }
}
