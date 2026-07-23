#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

/// Effective byte offset for a cursor-advancing write. `O_APPEND` writes start
/// from live `i_size`, matching Linux `IOCB_APPEND`. # C: O(1)
pub(crate) fn write_pos(file: &vfs::File) -> u64 {
    if file.flags().contains(vfs::OpenFlags::O_APPEND) {
        file.inode().size()
    } else {
        file.pos()
    }
}

/// Effective byte offset for a positional write. Linux still honors the
/// `O_APPEND` quirk for pwrite/pwritev, so append-mode descriptions use live
/// `i_size`; otherwise the caller's explicit offset is used. # C: O(1)
pub(crate) fn positional_write_pos(file: &vfs::File, off: u64) -> u64 {
    if file.flags().contains(vfs::OpenFlags::O_APPEND) {
        file.inode().size()
    } else {
        off
    }
}

/// Linux `generic_write_check_limits` RLIMIT_FSIZE half. The superblock
/// `s_maxbytes` half lives in VFS; this half needs current-task rlimits and
/// posts `SIGXFSZ` when a write starts beyond the soft file-size limit.
/// # C: O(1)
pub(crate) fn rlimit_fsize_cap(cur: &sched::Task, file: &vfs::File, pos: u64, len: usize,
                               signal_on_efbig: bool) -> Result<usize, i64> {
    if len == 0 || file.inode().file_type() != vfs::FileType::Regular {
        return Ok(len);
    }
    let limit = cur.rlimit(sched::rlimit::rlim::FSIZE).0;
    if limit == sched::rlimit::INFINITY {
        return Ok(len);
    }
    if pos >= limit {
        if signal_on_efbig {
            sched::live::sigpend::send_signal_self(sched::live::sigpend::Signum::Sigxfsz);
        }
        return Err(-(Errno::Efbig.as_i32() as i64));
    }
    Ok(core::cmp::min(len as u64, limit - pos) as usize)
}
