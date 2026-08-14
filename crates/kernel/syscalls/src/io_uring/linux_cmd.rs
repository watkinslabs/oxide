// External-driver io_uring command lifetime.  The ABI export facade is in
// modules; this owner retains the request until a driver completes it.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use modules::linux_io_uring::{LinuxIoUringCmd, LinuxUserIovec};
use pmm::native_bvec::{ITER_DEST, ITER_SOURCE, NativeBioVec, NativeIovIter};
use sync::{Spinlock, TaskList as CmdLockClass};
use syscall::errno::Errno;

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
    done: AtomicBool,
    bvecs: Spinlock<Vec<NativeBioVec>, CmdLockClass>,
}

impl ExternalCmd {
    /// Allocate a command whose first byte is the ABI `io_uring_cmd`.
    /// # C: O(1)
    pub fn new(req: Arc<IoReq>, file: Arc<vfs::File>, abi_file: *mut c_void) -> Box<Self> {
        Box::new(Self {
            cmd: LinuxIoUringCmd { file: abi_file, sqe: req.sqe.raw.as_ptr(), cmd_op: req.sqe.off as u32,
                flags: req.sqe.op_flags, pdu: [0; 32], unused: [0; 8] },
            req, file, abi_file, task: AtomicUsize::new(0), done: AtomicBool::new(false),
            bvecs: Spinlock::new(Vec::new()),
        })
    }
}

const EIOCBQUEUED: i32 = 529;

/// Issue the retained external command; `None` means the driver owns its completion.
/// # C: driver-dependent
pub fn issue(req: &Arc<IoReq>) -> Option<super::dispatch::OpOutcome> {
    static INSTALLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    if !INSTALLED.swap(true, Ordering::AcqRel) {
        modules::linux_io_uring::install_cmd_hooks(do_in_task, done, import_fixed, import_fixed_vec);
    }
    let file = if req.sqe.flags & crate::io_uring_abi::ops::IOSQE_FIXED_FILE != 0 {
        match super::dispatch::fdres::fixed_file(&req.ring, req.sqe.fd as u32) { Ok(f) => f, Err(e) => return Some(super::dispatch::OpOutcome::res(e)) }
    } else {
        let Some(cur) = sched::live::current() else { return Some(super::dispatch::OpOutcome::res(-(Errno::Ebadf.as_i32() as i64))); };
        // SAFETY: the worker borrowed this request's owner, so this is the submitter's live descriptor table.
        let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Some(super::dispatch::OpOutcome::res(-(Errno::Ebadf.as_i32() as i64))); };
        match fdt.get(req.sqe.fd) { Ok(f) => f, Err(_) => return Some(super::dispatch::OpOutcome::res(-(Errno::Ebadf.as_i32() as i64))) }
    };
    let Some(abi_file) = vfs::opened_chrdev_uring_file_new(&file) else { return Some(super::dispatch::OpOutcome::res(-(Errno::Eopnotsupp.as_i32() as i64))); };
    let state = ExternalCmd::new(Arc::clone(req), Arc::clone(&file), abi_file);
    let raw = Box::into_raw(state);
    // SAFETY: raw names the retained ExternalCmd whose first member is the driver ABI command.
    let ret = unsafe { vfs::opened_chrdev_uring_cmd(&file, (&mut (*raw).cmd as *mut LinuxIoUringCmd).cast(), 0) };
    match ret {
        Some(Ok(r)) if r == -EIOCBQUEUED => None,
        Some(Ok(r)) => {
            // SAFETY: a synchronously returned command never transferred completion ownership to its driver.
            unsafe { drop(Box::from_raw(raw)); vfs::opened_chrdev_uring_file_drop(&file, abi_file); }
            Some(super::dispatch::OpOutcome::res(r as i64))
        }
        Some(Err(_)) | None => {
            // SAFETY: the driver declined the command without retaining its ABI object.
            unsafe { drop(Box::from_raw(raw)); vfs::opened_chrdev_uring_file_drop(&file, abi_file); }
            Some(super::dispatch::OpOutcome::res(-(Errno::Eopnotsupp.as_i32() as i64)))
        }
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
    if s.done.swap(true, Ordering::AcqRel) { return; }
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

const IORING_URING_CMD_FIXED: u32 = 1;

fn direction(rw: i32) -> Result<u8, Errno> {
    match rw { 0 => Ok(ITER_DEST), 1 => Ok(ITER_SOURCE), _ => Err(Errno::Einval) }
}

fn import_range(s: &ExternalCmd, addr: u64, len: usize, rw: i32, iter: *mut NativeIovIter) -> Result<(), Errno> {
    if s.cmd.flags & IORING_URING_CMD_FIXED == 0 { return Err(Errno::Einval); }
    if iter.is_null() { return Err(Errno::Efault); }
    let buf = super::dispatch::fdres::reg_buf(&s.req.ring, s.req.sqe.buf_index as u32).map_err(|_| Errno::Efault)?;
    let off = addr.checked_sub(buf.base).ok_or(Errno::Efault)?;
    let mut bvecs = buf.native_bvecs(off, len as u64)?;
    let mut abi = NativeIovIter::empty(direction(rw)?);
    if !bvecs.is_empty() { abi.bvec = bvecs.as_ptr(); abi.count = len; abi.nr_segs = bvecs.len(); }
    let mut retained = s.bvecs.lock();
    *retained = core::mem::take(&mut bvecs);
    // SAFETY: caller supplied the ABI output iterator and the command retains its backing bvec vector until completion.
    unsafe { iter.write(abi); }
    Ok(())
}

/// Import a byte range from the SQE-selected registered buffer.
/// # C: O(len / PAGE)
pub unsafe extern "C" fn import_fixed(addr: u64, len: usize, rw: i32, iter: *mut NativeIovIter, cmd: *mut LinuxIoUringCmd, _flags: u32) -> i32 {
    let Some(s) = (unsafe { state(cmd) }) else { return -Errno::Einval.as_i32(); };
    import_range(s, addr, len, rw, iter).map_or_else(|e| -e.as_i32(), |_| 0)
}

/// Import each user vector through the SQE-selected registered buffer.
/// # C: O(N_vec + bytes / PAGE)
pub unsafe extern "C" fn import_fixed_vec(cmd: *mut LinuxIoUringCmd, vec: *const LinuxUserIovec, nr: usize, rw: i32, iter: *mut NativeIovIter, _flags: u32) -> i32 {
    let Some(s) = (unsafe { state(cmd) }) else { return -Errno::Einval.as_i32(); };
    if iter.is_null() || (nr != 0 && vec.is_null()) { return -Errno::Efault.as_i32(); }
    if s.cmd.flags & IORING_URING_CMD_FIXED == 0 { return -Errno::Einval.as_i32(); }
    let Ok(dir) = direction(rw) else { return -Errno::Einval.as_i32(); };
    let Ok(buf) = super::dispatch::fdres::reg_buf(&s.req.ring, s.req.sqe.buf_index as u32) else { return -Errno::Efault.as_i32(); };
    let mut bvecs = Vec::new();
    let mut total = 0usize;
    for i in 0..nr {
        let Some(at) = (vec as u64).checked_add((i * core::mem::size_of::<LinuxUserIovec>()) as u64) else { return -Errno::Efault.as_i32(); };
        let mut raw = [0u8; core::mem::size_of::<LinuxUserIovec>()];
        if uaccess::copy_from_user(&mut raw, at).is_err() { return -Errno::Efault.as_i32(); }
        let addr = u64::from_ne_bytes(raw[..8].try_into().unwrap());
        let len = usize::from_ne_bytes(raw[8..].try_into().unwrap());
        let Some(off) = addr.checked_sub(buf.base) else { return -Errno::Efault.as_i32(); };
        let Ok(mut one) = buf.native_bvecs(off, len as u64) else { return -Errno::Efault.as_i32(); };
        let Some(sum) = total.checked_add(len) else { return -Errno::Efault.as_i32(); };
        if bvecs.try_reserve(one.len()).is_err() { return -Errno::Enomem.as_i32(); }
        bvecs.append(&mut one);
        total = sum;
    }
    let mut abi = NativeIovIter::empty(dir);
    if !bvecs.is_empty() { abi.bvec = bvecs.as_ptr(); abi.count = total; abi.nr_segs = bvecs.len(); }
    let mut retained = s.bvecs.lock();
    *retained = bvecs;
    // SAFETY: the command owns the bvec allocation until its sole terminal completion.
    unsafe { iter.write(abi); }
    0
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
