// External-driver io_uring command lifetime.  The ABI export facade is in
// modules; this owner retains the request until a driver completes it.
// Every reference rule this file relies on is stated and tested in
// `crate::io_uring_cmd_life`, which is ungated because this file is not.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::Ordering;

use modules::linux_io_uring::{LinuxIoUringCmd, LinuxUserIovec};
use pmm::native_bvec::{ITER_DEST, ITER_SOURCE, NativeBioVec, NativeIovIter};
use sync::{Spinlock, TaskList as CmdLockClass};
use syscall::errno::Errno;

use crate::io_uring_cmd_life::{CmdClaims, CmdLifetime, arm_handoff, claim_terminal, take_handoff};

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
    claims: CmdClaims,
    bvecs: Spinlock<Vec<NativeBioVec>, CmdLockClass>,
}

impl CmdLifetime for ExternalCmd { fn claims(&self) -> &CmdClaims { &self.claims } }

impl Drop for ExternalCmd {
    /// The ABI file object dies with the command's storage, not with the
    /// completion: a queued task callback may still be holding the command.
    fn drop(&mut self) {
        // SAFETY: abi_file is the object opened_chrdev_uring_file_new returned
        // for exactly this file, released once, here, when the last reference
        // to the command that retained both is gone.
        unsafe { vfs::opened_chrdev_uring_file_drop(&self.file, self.abi_file); }
    }
}

impl ExternalCmd {
    /// Allocate a command whose first byte is the ABI `io_uring_cmd`.
    /// # C: O(1)
    pub fn new(req: Arc<IoReq>, file: Arc<vfs::File>, abi_file: *mut c_void) -> Arc<Self> {
        Arc::new(Self {
            cmd: LinuxIoUringCmd { file: abi_file, sqe: req.sqe.raw.as_ptr(), cmd_op: req.sqe.off as u32,
                flags: req.sqe.op_flags, pdu: [0; 32], unused: [0; 8] },
            req, file, abi_file, claims: CmdClaims::new(),
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
    // The driver's reference: taken here, released by the terminal completion.
    let raw = Arc::into_raw(state);
    // SAFETY: raw names the retained ExternalCmd whose first member is the
    // driver ABI command, and this call holds the reference just taken.
    let ret = unsafe { vfs::opened_chrdev_uring_cmd(&file, core::ptr::addr_of!((*raw).cmd).cast_mut().cast(), 0) };
    match ret {
        Some(Ok(r)) if r == -EIOCBQUEUED => None,
        Some(Ok(r)) => {
            // SAFETY: a synchronously returned command never transferred completion
            // ownership to its driver, so the reference taken above is released here.
            unsafe { drop(Arc::from_raw(raw)); }
            Some(super::dispatch::OpOutcome::res(r as i64))
        }
        Some(Err(_)) | None => {
            // SAFETY: the driver declined the command without retaining its ABI
            // object, so the reference taken above is released here.
            unsafe { drop(Arc::from_raw(raw)); }
            Some(super::dispatch::OpOutcome::res(-(Errno::Eopnotsupp.as_i32() as i64)))
        }
    }
}

/// Recover the complete command lifetime from its ABI first member.
/// # C: O(1)
unsafe fn state(cmd: *mut LinuxIoUringCmd) -> Option<&'static ExternalCmd> {
    if cmd.is_null() { return None; }
    // SAFETY: ExternalCmd is repr(C) and cmd is its first field for every
    // command dispatched here; the caller holds the driver reference that
    // keeps the allocation live for the borrow (`io_uring_cmd_life`).
    Some(unsafe { &*cmd.cast::<ExternalCmd>() })
}

/// Complete exactly once, post the selected CQE width, and release ABI storage.
/// # C: O(N_chain)
pub unsafe extern "C" fn done(cmd: *mut LinuxIoUringCmd, ret: i32, res2: u64, _flags: u32, cqe32: bool) {
    // SAFETY: `claim_terminal` requires a live command reference the caller
    // holds across the call. A driver reaches this hook only through the ABI
    // export, with the command this dispatch handed it after answering
    // -EIOCBQUEUED, and owes exactly one completion which it has not yet made
    // -- the same precondition the reference places on its own consumers, and
    // the only one expressible from a bare pointer. Nothing is read through
    // `cmd` before the claim, and the claim takes the driver's reference, so
    // the storage is released once and no losing caller frees it.
    let Some(s) = (unsafe { claim_terminal::<ExternalCmd>(cmd.cast()) }) else { return; };
    let out = if cqe32 { super::dispatch::OpOutcome::wide(ret as i64, [res2, 0]) }
        else { super::dispatch::OpOutcome::res(ret as i64) };
    super::iowq::run::complete_out(&s.req, out);
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
    // SAFETY: `state` requires a pointer whose allocation begins with ExternalCmd;
    // the import hook receives the exact `cmd` this dispatch handed the driver,
    // and the command is still live because its completion has not been posted.
    let Some(s) = (unsafe { state(cmd) }) else { return -Errno::Einval.as_i32(); };
    import_range(s, addr, len, rw, iter).map_or_else(|e| -e.as_i32(), |_| 0)
}

/// Import each user vector through the SQE-selected registered buffer.
/// # C: O(N_vec + bytes / PAGE)
pub unsafe extern "C" fn import_fixed_vec(cmd: *mut LinuxIoUringCmd, vec: *const LinuxUserIovec, nr: usize, rw: i32, iter: *mut NativeIovIter, _flags: u32) -> i32 {
    // SAFETY: as `import_fixed` — the module passes back the `cmd` pointer this
    // dispatch gave it, whose allocation starts with the ExternalCmd header and
    // lives until the terminal completion that has not yet run.
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
    // SAFETY: `arm_handoff` requires a live command reference the caller holds
    // across the call; a driver reaches this hook only with the command this
    // dispatch handed it, before completing it. Unlike the reference, which
    // runs the callback and the completion off one per-request task-work node
    // on one task, this kernel runs the callback on a workqueue that can
    // overlap a completion on another CPU -- so the reference the worker runs
    // under is taken here, before the work is queued.
    let Some(handed) = (unsafe { arm_handoff::<ExternalCmd>(cmd.cast(), callback) }) else { return; };
    if !sched::live::workqueue::queue_work(run_task, handed as usize) { run_task(handed as usize); }
}

fn run_task(arg: usize) {
    // SAFETY: `arg` is the hand-off pointer `arm_handoff` returned for this one
    // queued work item, consumed exactly once here (`queue_work` delivers each
    // item once, and the inline fallback runs only when it queued nothing).
    // The reference it carries keeps the command alive for this whole
    // function, including across a driver completion landing on another CPU.
    let Some((s, task)) = (unsafe { take_handoff::<ExternalCmd>(arg as *const ExternalCmd) }) else { return; };
    // SAFETY: do_in_task stored the module callback's exact io_tw_req/io_tw_state ABI address.
    let callback: TaskFn = unsafe { core::mem::transmute(task) };
    let cmd = Arc::as_ptr(&s) as *mut ExternalCmd;
    // SAFETY: cmd is the io_kiocb-addressed first field required by
    // io_uring_cmd_from_tw, and `s` holds it live for the call -- including
    // the usual case where the callback completes the command.
    unsafe { callback(IoTwReq { req: cmd.cast() }, IoTwState { cancel: false }); }
}
