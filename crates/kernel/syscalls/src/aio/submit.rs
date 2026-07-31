// `io_submit(2)`: the per-iocb validation ladder and the per-opcode dispatch.
//
// Read/write/fsync submissions run to completion inside the submitting call
// and land in the ring before `io_submit` returns; `IOCB_CMD_POLL` is the one
// opcode that stays outstanding, so it is the only thing `io_cancel` can find
// and the only thing `io_destroy` has to resolve.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use syscall::errno::Errno;
use syscall::SyscallArgs;
use vfs::File;

use crate::aio_abi::iocb::{classify, decode, validate_common, validate_fsync, validate_poll,
    wants_ioprio, wants_resfd, AioOp, Iocb};
use crate::aio_abi::uapi::{IOCB_OFF_KEY, IOCB_SIZE, KIOCB_KEY};
use crate::aio::ctx::{ActiveReq, AioContext, IoEvent};
use crate::userbuf::{validate_user_buf, validate_user_buf_readable, validate_user_buf_writable};

/// Size of one entry in the `iocbpp` array of user `struct iocb *`.
const PTR_SIZE: u64 = 8;
/// Bytes of one `struct iovec`.
const IOVEC_SIZE: u64 = 16;
/// Poll conditions always reported regardless of the requested mask.
const POLL_ALWAYS: u32 = vfs::POLL_ERR | vfs::POLL_HUP;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Current task's fd table. # C: O(1)
pub(crate) fn cur_fdt() -> Option<Arc<vfs::FdTable>> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; preempt-off through the syscall; sole reader of the fd_table slot per `13§5`.
    unsafe { cur.fd_table_ref() }.cloned()
}

/// Signal an `aio_resfd` eventfd by one, the wake an epoll/read waiter on that
/// fd is expecting. # C: O(1)
pub(crate) fn signal_resfd(f: &Arc<File>) {
    let one = 1u64.to_ne_bytes();
    let _ = f.inode().write(0, &one);
}

/// `sys_io_submit(ctx_id, nr, iocbpp)` — slot 209.
///
/// The count check precedes the context lookup, so a negative `nr` is `EINVAL`
/// even for a bogus context. A request larger than the ring is silently
/// clamped rather than refused. A failure part-way through reports the number
/// already submitted; only a failure on the FIRST iocb surfaces its errno.
/// # C: O(nr x per-op cost)
pub fn sys_io_submit(ctx_id: u64, nr: i64, iocbpp: u64) -> i64 {
    if nr < 0 { return err(Errno::Einval); }
    let c = match crate::aio::ctx::lookup(ctx_id) { Some(c) => c, None => return err(Errno::Einval) };
    let nr = core::cmp::min(nr, c.nr_events as i64);
    let mut i: i64 = 0;
    let mut rv: i64 = 0;
    while i < nr {
        let slot = iocbpp + i as u64 * PTR_SIZE;
        if validate_user_buf_readable(slot, PTR_SIZE, PTR_SIZE).is_err() { rv = err(Errno::Efault); break; }
        // SAFETY: slot validated readable and 8-byte aligned below USER_VA_END; CPL=0 reads one user iocb pointer out of the caller's array.
        let uiocb = unsafe { core::ptr::read_volatile(slot as *const u64) };
        rv = submit_one(&c, uiocb);
        if rv != 0 { break; }
        i += 1;
    }
    if i != 0 { i } else { rv }
}

/// Validate and run one submission. Returns 0 once the request is owned by the
/// context (completed or outstanding), else `-errno`.
/// # C: O(per-op cost)
fn submit_one(c: &Arc<AioContext>, uiocb: u64) -> i64 {
    // `copy_from_user(&iocb, user_iocb, sizeof(iocb))` — no alignment
    // requirement, so a misaligned but mapped iocb is legal.
    if validate_user_buf_readable(uiocb, IOCB_SIZE, 1).is_err() { return err(Errno::Efault); }
    let mut raw = [0u8; IOCB_SIZE as usize];
    for (n, b) in raw.iter_mut().enumerate() {
        // SAFETY: the whole 64-byte iocb was validated readable below USER_VA_END; CPL=0 copies it byte-wise through the caller's address space.
        *b = unsafe { core::ptr::read_volatile((uiocb + n as u64) as *const u8) };
    }
    let io = decode(&raw);
    if let Err(e) = validate_common(&io) { return err(e); }
    // A ring slot is reserved before any work runs, so a completion always has
    // somewhere to go.
    if let Err(e) = c.get_req() { return err(e); }
    match prepare_and_run(c, uiocb, &io) {
        Ok(()) => 0,
        Err(rv) => { c.put_reqs(1); rv }
    }
}

/// The fd/eventfd/key ladder, then the opcode switch. # C: O(per-op cost)
fn prepare_and_run(c: &Arc<AioContext>, uiocb: u64, io: &Iocb) -> Result<(), i64> {
    let fdt = cur_fdt().ok_or(err(Errno::Ebadf))?;
    // The fd is resolved BEFORE the eventfd and before any per-opcode field
    // check, so a bad fd is EBADF even for an opcode that would be EINVAL.
    let file = fdt.get(io.fildes as i32).map_err(|_| err(Errno::Ebadf))?;
    let resfd = if wants_resfd(io) {
        let f = fdt.get(io.resfd as i32).map_err(|_| err(Errno::Ebadf))?;
        // A live fd that is not an eventfd is EINVAL, not EBADF.
        if !::fs::pipe::is_eventfd(f.inode()) { return Err(err(Errno::Einval)); }
        Some(f)
    } else { None };
    // The kernel stamps its request tag into the caller's iocb; `io_cancel`
    // refuses any iocb that does not carry it.
    if validate_user_buf_writable(uiocb + IOCB_OFF_KEY, 4, 1).is_err() { return Err(err(Errno::Efault)); }
    // SAFETY: the aio_key word was validated writable below USER_VA_END; CPL=0 stamps the request tag into the caller's iocb.
    unsafe { core::ptr::write_unaligned((uiocb + IOCB_OFF_KEY) as *mut u32, KIOCB_KEY); }

    let op = classify(io.opcode).map_err(err)?;
    match op {
        AioOp::Poll => start_poll(c, uiocb, io, file, resfd),
        AioOp::Fsync | AioOp::Fdsync => {
            validate_fsync(io).map_err(err)?;
            let datasync = op == AioOp::Fdsync;
            let a = SyscallArgs { a0: io.fildes as u64, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 };
            let res = if datasync { crate::misc::s074_fsync::sys_fdatasync(&a) } else { crate::misc::s074_fsync::sys_fsync(&a) };
            finish(c, uiocb, io, res, resfd.as_ref());
            Ok(())
        }
        _ => {
            let res = run_rw(op, io, &file)?;
            finish(c, uiocb, io, res, resfd.as_ref());
            Ok(())
        }
    }
}

/// Read/write preparation and execution. The three preparation failures —
/// ioprio capability, `RWF_*` admission, and the direction gate — are submit
/// errors; anything the transfer itself reports becomes the completion result.
/// # C: O(bytes)
fn run_rw(op: AioOp, io: &Iocb, file: &Arc<File>) -> Result<i64, i64> {
    use crate::rwf::{kiocb_set_rw_flags, RwCaps, RwDir};
    // `aio_reqprio` is only interpreted when the caller opted in; without the
    // flag an arbitrary value there is ignored rather than rejected.
    if wants_ioprio(io) {
        match crate::ioprio::check_cap(io.reqprio as i32) {
            Err(rv) => return Err(rv),
            Ok(crate::ioprio::CapNeed::SysAdminOrSysNice) => {
                let cur = sched::live::current().ok_or(err(Errno::Eperm))?;
                if !cur.has_cap(sched::cap::SYS_ADMIN) && !cur.has_cap(sched::cap::SYS_NICE) {
                    return Err(err(Errno::Eperm));
                }
            }
            Ok(crate::ioprio::CapNeed::None) => {}
        }
    }
    let dir = if op.is_write() { RwDir::Write } else { RwDir::Read };
    let caps = RwCaps {
        nowait: file.f_mode().contains(vfs::Fmode::NOWAIT),
        o_append: file.flags().contains(vfs::OpenFlags::O_APPEND),
        inode_append_only: vfs::inode::is_append(file.inode()),
        ..RwCaps::default()
    };
    let eff = kiocb_set_rw_flags(io.rw_flags as u64, dir, &caps)
        .map_err(|e| err(e))?;
    let want = if op.is_write() { vfs::Fmode::WRITE } else { vfs::Fmode::READ };
    if !file.f_mode().contains(want) { return Err(err(Errno::Ebadf)); }
    if op.is_vectored() {
        // The iovec ARRAY is copied in at submit time, so an unreadable array
        // is a submit error rather than a completion carrying -EFAULT.
        let bytes = io.nbytes.checked_mul(IOVEC_SIZE).ok_or(err(Errno::Efault))?;
        if io.nbytes != 0 && validate_user_buf(io.buf, bytes, 8).is_err() {
            return Err(err(Errno::Efault));
        }
    }
    let _ = eff;
    Ok(dispatch_rw(op, io))
}

/// Hand the request to the syscall work fn that owns this transfer shape.
/// Offsets follow each work fn's own argument convention: the vectored pair
/// splits the offset across two words on x86_64 and takes it whole on aarch64,
/// so packing it wrongly truncates any aio transfer past 4 GiB.
/// # C: O(bytes)
fn dispatch_rw(op: AioOp, io: &Iocb) -> i64 {
    let off = io.offset as u64;
    match op {
        AioOp::Pread => crate::s017_pread64::sys_pread64(
            &SyscallArgs { a0: io.fildes as u64, a1: io.buf, a2: io.nbytes, a3: off, a4: 0, a5: 0 }),
        AioOp::Pwrite => crate::s018_pwrite64::sys_pwrite64(
            &SyscallArgs { a0: io.fildes as u64, a1: io.buf, a2: io.nbytes, a3: off, a4: 0, a5: 0 }),
        AioOp::Preadv | AioOp::Pwritev => {
            #[cfg(target_arch = "x86_64")]
            let (a3, a4) = (off & 0xffff_ffff, off >> 32);
            #[cfg(target_arch = "aarch64")]
            let (a3, a4) = (off, 0u64);
            let a = SyscallArgs { a0: io.fildes as u64, a1: io.buf, a2: io.nbytes, a3, a4,
                                  a5: io.rw_flags as u64 };
            if op.is_write() { crate::s296_pwritev::sys_pwritev2(&a) }
            else { crate::s295_preadv::sys_preadv2(&a) }
        }
        _ => err(Errno::Einval),
    }
}

/// `IOCB_CMD_POLL`: complete straight away when the condition already holds,
/// otherwise keep the request outstanding so a reaper (or `io_cancel`) can
/// resolve it. # C: O(1)
fn start_poll(c: &Arc<AioContext>, uiocb: u64, io: &Iocb, file: Arc<File>,
              resfd: Option<Arc<File>>) -> Result<(), i64>
{
    let mask = validate_poll(io).map_err(err)? as u32;
    // A file with no wait queue cannot support a pollable request.
    if file.poll_subscribers().is_none() { return Err(err(Errno::Einval)); }
    let events = mask | POLL_ALWAYS;
    let ready = file.poll() as u32 & events;
    if ready != 0 {
        finish(c, uiocb, io, ready as i64, resfd.as_ref());
        return Ok(());
    }
    c.active.lock().push(ActiveReq { obj: uiocb, data: io.data, file, events, resfd });
    Ok(())
}

/// Publish a completion and signal its eventfd. # C: O(1)
pub(crate) fn finish(c: &AioContext, uiocb: u64, io: &Iocb, res: i64, resfd: Option<&Arc<File>>) {
    c.complete(IoEvent { data: io.data, obj: uiocb, res, res2: 0 });
    if let Some(f) = resfd { signal_resfd(f); }
}

/// Complete an outstanding poll request. # C: O(1)
pub(crate) fn finish_active(c: &AioContext, req: &ActiveReq, res: i64) {
    c.complete(IoEvent { data: req.data, obj: req.obj, res, res2: 0 });
    if let Some(f) = req.resfd.as_ref() { signal_resfd(f); }
}
