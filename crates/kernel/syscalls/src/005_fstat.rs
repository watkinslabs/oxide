// 005 fstat — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::stat_common::{STAT_BYTES, new_stat_from_kstat, write_new_stat_user};
use crate::userbuf::validate_user_buf_writable;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// `sys_fstat(fd, statbuf)` — slot 5. 144-byte Linux x86_64 struct stat.
/// # C: O(1)
pub fn sys_fstat(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    // x86_64 struct stat = 144 B; aarch64 asm-generic struct stat = 128 B.
    // Per-arch layout differs (mode@24/+rdev@40 vs mode@16/+rdev@32) — using
    // the x86 layout on aarch64 returned mismatched st_ino vs newfstatat
    // because the field offsets don't line up; broke musl's ttyname.
    let cur = match current_task() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot per single-mutator-per-active-CPU invariant in `13§5`.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f)  => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = file.inode();
    // vfs_getattr → i_op->getattr (default generic_fillattr): S_IF* mapping +
    // native inode metadata + idmap-out owner ids, identical to the other
    // stat-family handlers. The fd carries the owning mount for the idmap.
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let st = vfs::vfs_getattr(inode, &idmap);
    let dev = crate::namei_common::fsid_to_dev(st.fsid);
    // DIAG (debug-atexit): ld.so dedups DSOs by fstat (st_dev, st_ino) — log
    // every ext4-file fstat so unstable dev or colliding ino shows in the boot log.
    #[cfg(feature = "debug-atexit")]
    let ino = st.ino;
    #[cfg(feature = "debug-atexit")]
    if (ino >> 48) == 0x6e54 {
        klog::write_raw(b"[SOSTAT] tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" fd=");
        klog::write_dec_u64(fd as u64);
        klog::write_raw(b" ino=");
        klog::write_hex_u64(ino);
        klog::write_raw(b" dev=");
        klog::write_hex_u64(dev);
        klog::write_raw(b"\n");
    }
    let out = match new_stat_from_kstat(&st, dev) {
        Ok(o) => o,
        Err(rv) => return rv,
    };
    // Linux vfs_fstat and cp_new_stat conversion run before the output buffer fault.
    if let Err(rv) = validate_user_buf_writable(buf, STAT_BYTES, 1) { return rv; }
    // SAFETY: buf validated STAT_BYTES writable below USER_VA_END.
    unsafe { write_new_stat_user(buf, &out); }
    0
}
