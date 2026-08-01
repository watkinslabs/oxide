use alloc::sync::Arc;

use vfs::{FdTable, File, OpenFlags};

/// Reserve, copy out, construct, then atomically publish an fd pair. # C: O(1)
pub(crate) fn install_fd_pair<P, C>(
    fdt: &FdTable,
    limit: usize,
    reserve_flags: OpenFlags,
    mut put: P,
    create: C,
) -> i64
where
    P: FnMut(usize, i32) -> Result<(), i64>,
    C: FnOnce() -> Result<(Arc<File>, Arc<File>), i64>,
{
    let first = match fdt.get_unused_fd_flags(reserve_flags, limit) {
        Ok(fd) => fd,
        Err(e) => return -(e as i64),
    };
    let second = match fdt.get_unused_fd_flags(reserve_flags, limit) {
        Ok(fd) => fd,
        Err(e) => { fdt.put_unused_fd(first); return -(e as i64); }
    };
    if let Err(rv) = put(0, first).and_then(|()| put(1, second)) {
        fdt.put_unused_fd(first);
        fdt.put_unused_fd(second);
        return rv;
    }
    let (first_file, second_file) = match create() {
        Ok(files) => files,
        Err(rv) => {
            fdt.put_unused_fd(first);
            fdt.put_unused_fd(second);
            return rv;
        }
    };
    fdt.fd_install(first, first_file);
    fdt.fd_install(second, second_file);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use syscall::errno::Errno;
    use vfs::{default_file_ops, default_inode_ops, mk_mode};
    use vfs::{Dentry, FileType, InodeBuilder, InodeRef, VfsError};

    fn file(ino: u64) -> Arc<File> {
        let inode: InodeRef = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build();
        let dentry = Dentry::new(None, "pair".into(), Arc::clone(&inode));
        File::new(inode, dentry, OpenFlags::O_RDWR)
    }

    #[test]
    fn success_publishes_both_only_after_copy_and_create() {
        let fdt = FdTable::new();
        let hidden = AtomicBool::new(false);
        let mut out = Vec::new();
        let rv = install_fd_pair(&fdt, 8, OpenFlags::O_CLOEXEC,
            |_, fd| { out.push(fd); Ok(()) },
            || {
                hidden.store(matches!(fdt.get(0), Err(VfsError::Ebadf)) && matches!(fdt.get(1), Err(VfsError::Ebadf)), Ordering::Release);
                Ok((file(1), file(2)))
            });
        assert_eq!(rv, 0);
        assert_eq!(out, [0, 1]);
        assert!(hidden.load(Ordering::Acquire));
        assert!(fdt.get(0).is_ok() && fdt.get(1).is_ok());
        assert!(fdt.cloexec(0).unwrap() && fdt.cloexec(1).unwrap());
    }

    #[test]
    fn second_reservation_failure_rolls_back_first_before_copy() {
        let fdt = FdTable::new();
        let mut puts = 0;
        let rv = install_fd_pair(&fdt, 1, OpenFlags::O_CLOEXEC,
            |_, _| { puts += 1; Ok(()) }, || Ok((file(1), file(2))));
        assert_eq!(rv, -(VfsError::Emfile as i64));
        assert_eq!(puts, 0);
        assert_eq!(fdt.get_unused_fd_flags(OpenFlags::empty(), 1), Ok(0));
    }

    #[test]
    fn second_copy_fault_preserves_first_value_but_releases_both() {
        let fdt = FdTable::new();
        let mut out = [-1, -1];
        let rv = install_fd_pair(&fdt, 8, OpenFlags::empty(),
            |index, fd| {
                if index == 1 { return Err(-(Errno::Efault.as_i32() as i64)); }
                out[index] = fd;
                Ok(())
            }, || Ok((file(1), file(2))));
        assert_eq!(rv, -(Errno::Efault.as_i32() as i64));
        assert_eq!(out, [0, -1]);
        assert!(fdt.live_fds().is_empty());
        assert_eq!(fdt.get_unused_fd_flags(OpenFlags::empty(), 8), Ok(0));
    }

    /// `socketpair(2)` reserves and PUBLISHES both descriptor numbers before it
    /// asks the family to build anything, so a rejected family/type/protocol
    /// still leaves the caller's array written — the values just name no open
    /// file. A constructor that ran first would leave the array untouched.
    #[test]
    fn rejected_socket_arguments_still_perturb_the_callers_array() {
        let fdt = FdTable::new();
        let out = core::cell::Cell::new([-1i32, -1]);
        let copied_before_create = AtomicBool::new(false);
        let rv = install_fd_pair(&fdt, 8, OpenFlags::empty(),
            |index, fd| { let mut v = out.get(); v[index] = fd; out.set(v); Ok(()) },
            || {
                copied_before_create.store(out.get() == [0, 1], Ordering::Release);
                Err(-(Errno::Eafnosupport.as_i32() as i64))
            });
        assert_eq!(rv, -(Errno::Eafnosupport.as_i32() as i64));
        assert!(copied_before_create.load(Ordering::Acquire),
            "construction must follow the copyout");
        assert_eq!(out.get(), [0, 1]);
        assert!(fdt.live_fds().is_empty());
    }

    #[test]
    fn constructor_error_after_copy_releases_both_without_publication() {
        let fdt = FdTable::new();
        let mut out = [-1, -1];
        let rv = install_fd_pair(&fdt, 8, OpenFlags::empty(),
            |index, fd| { out[index] = fd; Ok(()) },
            || Err(-(Errno::Eprotonosupport.as_i32() as i64)));
        assert_eq!(rv, -(Errno::Eprotonosupport.as_i32() as i64));
        assert_eq!(out, [0, 1]);
        assert!(fdt.live_fds().is_empty());
        assert_eq!(fdt.get_unused_fd_flags(OpenFlags::empty(), 8), Ok(0));
    }
}
