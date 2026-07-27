// 78 getdents / 217 getdents64 — one syscall pair, one file (docs/53 §0). Thin
// shim: fd + directory admission, user-range validation, then the record ABI
// and the return rule from the hosted-tested `getdents_abi`.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::getdents_abi::{self, DirentFill, DirentLayout, Fill};
use crate::userbuf::validate_user_buf_writable;

#[cfg(feature = "debug-getdents-detail")]
const GETDENTS_STAGE_VALIDATED: &[u8] = b"validated";
#[cfg(feature = "debug-getdents-detail")]
const GETDENTS_STAGE_READDIR_ENTER: &[u8] = b"readdir-enter";
#[cfg(feature = "debug-getdents-detail")]
const GETDENTS_STAGE_READDIR_EXIT: &[u8] = b"readdir-exit";
#[cfg(feature = "debug-getdents-detail")]
const GETDENTS_STAGE_COPYOUT_DONE: &[u8] = b"copyout-done";
#[cfg(feature = "debug-getdents-detail")]
const GETDENTS_STAGE_COPYOUT_OVERFLOW: &[u8] = b"copyout-overflow";

/// Retained, feature-gated getdents boundary trace. It runs only after the
/// output range has been admitted, so a trace never dereferences or renders
/// state for a rejected userspace range. # C: O(path length)
#[cfg(feature = "debug-getdents-detail")]
fn trace_getdents(stage: &[u8], fd: i32, file: &vfs::File, fpos: u64, count: usize, result: Option<i64>) {
    let Some(task) = sched::current() else { return; };
    let path = file.dentry().absolute_path();
    klog::write_raw(b"[GETDENTS] stage=");
    klog::write_raw(stage);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(task.tid as u64);
    klog::write_raw(b" fd=");
    klog::write_dec_u64(fd as u32 as u64);
    klog::write_raw(b" mnt=");
    klog::write_dec_u64(file.mnt_id());
    klog::write_raw(b" ino=");
    klog::write_dec_u64(file.inode().ino());
    klog::write_raw(b" path=");
    klog::write_raw(&path);
    klog::write_raw(b" fpos=");
    klog::write_dec_u64(fpos);
    klog::write_raw(b" count=");
    klog::write_dec_u64(count as u64);
    if let Some(rv) = result {
        klog::write_raw(b" result=");
        klog::write_hex_u64(rv as u64);
    }
    klog::write_raw(b"\n");
}

/// `sys_getdents64(fd, dirp, count)` — slot 217. Packs `linux_dirent64`
/// records (`d_type` is a real field at offset 18).
/// # C: O(N_dirents)
pub fn sys_getdents64(args: &SyscallArgs) -> i64 {
    getdents_common(args, DirentLayout::Modern)
}

/// `sys_getdents(fd, dirp, count)` — legacy slot 78. Packs the older
/// `linux_dirent` layout, whose `d_type` lives in the record's LAST byte and
/// whose name starts one byte earlier. Routing this through the dirent64
/// packer corrupts every record.
/// # C: O(N_dirents)
pub fn sys_getdents(args: &SyscallArgs) -> i64 {
    getdents_common(args, DirentLayout::Legacy)
}

/// `dir_context` actor (Linux `filldir`/`filldir64`): packs each emitted entry
/// into the validated user range `[dirp, dirp + count)`.
struct GetdentsActor {
    dirp: u64,
    fill: DirentFill,
    #[cfg(feature = "debug-getdents")]
    task: &'static sched::Task,
}

impl GetdentsActor {
    /// Offer one entry on the raw `DT_*` channel. `d_type` is written through
    /// untouched, so a backend's honest `DT_UNKNOWN` survives to userspace.
    /// # C: O(reclen)
    fn offer(&mut self, name: &str, ino: u64, dt: u8, next_pos: u64) -> bool {
        // Linux abandons the walk once a signal is pending and at least one
        // record is packed, so a huge directory cannot delay delivery.
        if getdents_abi::interrupt_stops_fill(self.fill.written(), signal_pending()) { return false; }
        let cap = self.fill.capacity();
        // SAFETY: getdents_common admitted [dirp, dirp+count) through
        // validate_user_buf_writable (WRITE-mapped user VA below USER_VA_END)
        // before building this actor; CPL=0 with the caller's AS active, and
        // DirentFill bounds every write to `cap`.
        let out: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(self.dirp as *mut u8, cap) };
        matches!(self.fill.offer(out, ino, next_pos, dt, name.as_bytes()), Fill::Wrote(_))
    }
}

impl vfs::DirEmit for GetdentsActor {
    fn emit(&mut self, name: &str, ino: u64, d_type: vfs::FileType, next_pos: u64) -> bool {
        self.offer(name, ino, vfs::dirent::dtype_from_file_type(d_type), next_pos)
    }

    fn emit_dt(&mut self, name: &str, ino: u64, d_type: vfs::DType, next_pos: u64) -> bool {
        self.offer(name, ino, d_type.raw(), next_pos)
    }

    #[cfg(feature = "debug-getdents")]
    fn debug_getdents_progress(&mut self, backend: vfs::DirDebugBackend, block: u32,
                               entries: u64, pos: u64) {
        sched::diag::getdents_progress(self.task, backend, block, entries, pos);
    }
}

/// Linux `signal_pending(current)`. # C: O(1)
fn signal_pending() -> bool { sched::live::sigpend::deliverable_signals_self() != 0 }

/// Shared getdents core. Linux `SYSCALL_DEFINE3(getdents{,64})`:
///
/// ```text
/// CLASS(fd_pos, f)(fd); if (fd_empty(f)) return -EBADF;
/// error = iterate_dir(fd_file(f), &buf.ctx);            // ENOTDIR here
/// if (error >= 0) error = buf.error;                    // EINVAL / EIO / EFAULT
/// if (buf.prev_reclen) error = count - buf.ctx.count;   // bytes always win
/// ```
///
/// `iterate_dir` stores `file->f_pos = ctx->pos` whether or not the backend
/// errored, so a partial listing is never replayed.
/// # C: O(N_dirents)
fn getdents_common(args: &SyscallArgs, layout: DirentLayout) -> i64 {
    use vfs::FileType;
    let fd = args.a0 as i32;
    let dirp = args.a1;
    let count = getdents_abi::count_arg(args.a2);
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = file.inode().clone();
    // ENOTDIR comes out of `iterate_dir`, BEFORE any user access: `getdents` on
    // a regular fd with a garbage pointer is ENOTDIR in Linux, not EFAULT.
    if !matches!(inode.file_type(), FileType::Directory) {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    // `count == 0` never touches the buffer in Linux (the first capacity test
    // fails first), so a NULL/unmapped pointer with count 0 is EINVAL — or 0 on
    // an empty directory — not EFAULT.
    if count > 0 {
        if let Err(rv) = validate_user_buf_writable(dirp, count as u64, 1) { return rv; }
    }
    #[cfg(feature = "debug-getdents")]
    sched::diag::getdents_begin(cur, fd, file.mnt_id(), inode.ino(), file.pos(), count);
    #[cfg(feature = "debug-getdents-detail")]
    trace_getdents(GETDENTS_STAGE_VALIDATED, fd, &file, file.pos(), count, None);

    // readdir cursor validity (file D32): a fresh cursor (pos==0) stamps
    // `f_version` from the inode's change-cookie; a non-zero cursor whose
    // directory has changed since this open last read it is stale → drop it
    // (restart from 0) and re-stamp (Linux `file->f_version` invalidation).
    let mut start = file.pos();
    if start == 0 || file.dir_version_changed() {
        if start != 0 { start = 0; }
        file.set_f_version(vfs::inode::inode_query_iversion(&inode));
    }

    let mut actor = GetdentsActor { dirp, fill: DirentFill::new(layout, count),
                                    #[cfg(feature = "debug-getdents")] task: cur };
    #[cfg(feature = "debug-getdents")]
    sched::diag::getdents_stage(cur, sched::diag::getdents::GETDENTS_STAGE_READDIR_ENTER, start, 0);
    #[cfg(feature = "debug-getdents-detail")]
    trace_getdents(GETDENTS_STAGE_READDIR_ENTER, fd, &file, start, count, None);

    // `.`/`..` come from the VFS for every backend that does not carry them
    // itself (`vfs::readdir_dots`); the parent ino is the dentry's parent, or
    // this directory itself at a filesystem root — Linux `d_parent_ino`.
    let self_ino = inode.ino();
    let parent_ino = file.dentry().parent()
        .and_then(|p| p.inode()).map(|i| i.ino()).unwrap_or(self_ino);
    let (r, new_off) = vfs::readdir_dots(&inode, self_ino, parent_ino, start, &mut actor);
    let iter_err = r.as_ref().err().map(|e| *e as i32);

    #[cfg(feature = "debug-getdents")]
    sched::diag::getdents_stage(cur, sched::diag::getdents::GETDENTS_STAGE_READDIR_EXIT, start,
                                iter_err.map_or(new_off as i64, |e| -(e as i64)));
    #[cfg(feature = "debug-getdents-detail")]
    trace_getdents(GETDENTS_STAGE_READDIR_EXIT, fd, &file, start, count,
                   Some(iter_err.map_or(new_off as i64, |e| -(e as i64))));

    // Linux `iterate_dir` stores the cursor unconditionally, error or not.
    file.set_pos(new_off);
    if actor.fill.written() > 0 {
        let cap = actor.fill.capacity();
        // SAFETY: same admitted [dirp, dirp+count) range as the packing path;
        // CPL=0 with the caller's AS active, and the rewrite stays inside a
        // record this call already wrote.
        let out: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(dirp as *mut u8, cap) };
        actor.fill.seal_last_d_off(out, new_off);
    }
    let rv = actor.fill.ret(iter_err);
    #[cfg(feature = "debug-getdents")]
    {
        let stage = if rv < 0 { sched::diag::getdents::GETDENTS_STAGE_COPYOUT_OVERFLOW }
                    else      { sched::diag::getdents::GETDENTS_STAGE_COPYOUT_DONE };
        sched::diag::getdents_stage(cur, stage, new_off, rv);
        sched::diag::getdents_clear(cur);
    }
    #[cfg(feature = "debug-getdents-detail")]
    trace_getdents(if rv < 0 { GETDENTS_STAGE_COPYOUT_OVERFLOW } else { GETDENTS_STAGE_COPYOUT_DONE },
                   fd, &file, new_off, count, Some(rv));
    rv
}
