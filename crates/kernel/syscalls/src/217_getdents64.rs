// 217 getdents64 — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;

#[cfg(feature = "debug-getdents")]
const GETDENTS_STAGE_VALIDATED: &[u8] = b"validated";
#[cfg(feature = "debug-getdents")]
const GETDENTS_STAGE_READDIR_ENTER: &[u8] = b"readdir-enter";
#[cfg(feature = "debug-getdents")]
const GETDENTS_STAGE_READDIR_EXIT: &[u8] = b"readdir-exit";
#[cfg(feature = "debug-getdents")]
const GETDENTS_STAGE_COPYOUT_DONE: &[u8] = b"copyout-done";
#[cfg(feature = "debug-getdents")]
const GETDENTS_STAGE_COPYOUT_OVERFLOW: &[u8] = b"copyout-overflow";

/// Retained, feature-gated getdents boundary trace. It runs only after the
/// output range has been admitted, so a trace never dereferences or renders
/// state for a rejected userspace range. # C: O(path length)
#[cfg(feature = "debug-getdents")]
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
/// records (fixed `d_type` field at offset 18).
/// # C: O(N_dirents)
pub fn sys_getdents64(args: &SyscallArgs) -> i64 {
    getdents_common(args, false)
}

/// `sys_getdents(fd, dirp, count)` — legacy slot 78. Packs the older
/// `linux_dirent` layout (`d_type` smuggled into the record's LAST byte).
/// Routing this through the dirent64 packer corrupts records, so it has
/// its own packer.
/// # C: O(N_dirents)
pub fn sys_getdents(args: &SyscallArgs) -> i64 {
    getdents_common(args, true)
}

/// `dir_context` actor (Linux `filldir`/`filldir64`) for getdents: packs each
/// emitted entry as a `linux_dirent`(`legacy`)/`linux_dirent64` record into the
/// user buffer `[dirp, dirp+count)`, stopping (returns `false`) once the next
/// record would overflow. `overflow_first` records a too-small buffer so the
/// caller can distinguish it (EINVAL) from a genuinely empty dir (return 0).
struct GetdentsActor {
    dirp: u64,
    count: usize,
    legacy: bool,
    written: usize,
    overflow_first: bool,
}

impl vfs::DirEmit for GetdentsActor {
    fn emit(&mut self, name: &str, ino: u64, d_type: vfs::FileType, next_pos: u64) -> bool {
        let reclen = if self.legacy { vfs::dirent_reclen(name.len()) }
                     else          { vfs::dirent64_reclen(name.len()) };
        if self.written + reclen > self.count {
            if self.written == 0 { self.overflow_first = true; }
            return false;
        }
        let dt: u8 = vfs::dirent::dtype_from_file_type(d_type);
        let mut tmp = [0u8; 320];
        let n = if self.legacy {
            vfs::dirent_pack(&mut tmp[..reclen], ino, next_pos, dt, name.as_bytes())
        } else {
            vfs::dirent64_pack(&mut tmp[..reclen], ino, next_pos, dt, name.as_bytes())
        }.expect("dirent pack: tmp buf sized to reclen");
        // SAFETY: validate_user_buf bounded [dirp, dirp+count) < USER_VA_END; CPL=0; caller's AS active.
        unsafe {
            for i in 0..n {
                core::ptr::write_volatile((self.dirp + (self.written + i) as u64) as *mut u8, tmp[i]);
            }
        }
        self.written += n;
        true
    }
}

/// Shared getdents core. `legacy` selects the `linux_dirent` (true) vs
/// `linux_dirent64` (false) record layout. Drives `f_op->iterate` through a
/// [`vfs::DirContext`] whose actor ([`GetdentsActor`]) packs the user buffer;
/// `ctx.pos` is the resume cookie persisted into `file->f_pos`. Returns bytes
/// written; **EINVAL** if the buffer cannot hold even the first entry (Linux
/// `filldir` contract — returning 0 there would be read as end-of-dir, silently
/// truncating the listing). ENOTDIR for non-dirs.
/// # C: O(N_dirents)
fn getdents_common(args: &SyscallArgs, legacy: bool) -> i64 {
    use vfs::FileType;
    let fd = args.a0 as i32;
    let dirp = args.a1;
    let count = args.a2 as usize;
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
    if let Err(rv) = validate_user_buf_writable(dirp, args.a2, 1) { return rv; }
    #[cfg(feature = "debug-getdents")]
    trace_getdents(GETDENTS_STAGE_VALIDATED, fd, &file, file.pos(), count, None);
    let inode = file.inode().clone();
    if !matches!(inode.file_type(), FileType::Directory) {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    // readdir cursor validity (file D32): a fresh cursor (pos==0) stamps
    // `f_version` from the inode's change-cookie; a non-zero cursor whose
    // directory has changed since this open last read it is stale → drop it
    // (restart from 0) and re-stamp (Linux `file->f_version` invalidation).
    let mut start = file.pos();
    if start == 0 || file.dir_version_changed() {
        if start != 0 { start = 0; }
        file.set_f_version(vfs::inode::inode_query_iversion(&inode));
    }
    let mut actor = GetdentsActor { dirp, count, legacy, written: 0, overflow_first: false };
    #[cfg(feature = "debug-getdents")]
    trace_getdents(GETDENTS_STAGE_READDIR_ENTER, fd, &file, start, count, None);
    let r = {
        let mut ctx = vfs::DirContext::new(start, &mut actor);
        inode.readdir(&mut ctx).map(|()| ctx.pos)
    };
    #[cfg(feature = "debug-getdents")]
    trace_getdents(GETDENTS_STAGE_READDIR_EXIT, fd, &file, start, count,
                   Some(r.as_ref().map_or_else(|e| -(*e as i64), |pos| *pos as i64)));
    match r {
        Ok(new_off) => {
            if actor.written == 0 && actor.overflow_first {
                let rv = -(Errno::Einval.as_i32() as i64);
                #[cfg(feature = "debug-getdents")]
                trace_getdents(GETDENTS_STAGE_COPYOUT_OVERFLOW, fd, &file, new_off, count, Some(rv));
                return rv;
            }
            file.set_pos(new_off);
            let rv = actor.written as i64;
            #[cfg(feature = "debug-getdents")]
            trace_getdents(GETDENTS_STAGE_COPYOUT_DONE, fd, &file, new_off, count, Some(rv));
            rv
        }
        Err(e) => -(e as i64),
    }
}
