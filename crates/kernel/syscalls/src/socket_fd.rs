use alloc::sync::Arc;

/// Publish one socket file with descriptor flags in the same fd-table critical section. # C: O(fd words)
pub(crate) fn install(fdt: &vfs::FdTable, file: Arc<vfs::File>, nofile: usize,
                      cloexec: bool) -> vfs::KResult<i32> {
    let flags = if cloexec { vfs::OpenFlags::O_CLOEXEC } else { vfs::OpenFlags::empty() };
    fdt.install_limit(file, flags, nofile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    fn file(ino: u64) -> Arc<vfs::File> {
        let inode = vfs::InodeBuilder::new(
            ino, vfs::mk_mode(vfs::FileType::Socket, 0o600),
            vfs::default_inode_ops(), vfs::default_file_ops(),
        ).build();
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
        vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
    }

    #[test]
    fn cloexec_socket_is_flagged_at_first_publication_and_closed_by_exec() {
        let fdt = vfs::FdTable::new();
        let fd = install(&fdt, file(1), 8, true).unwrap();
        assert!(fdt.get(fd).is_ok());
        assert_eq!(fdt.cloexec(fd), Ok(true));
        fdt.close_on_exec();
        assert_eq!(fdt.get(fd).err(), Some(vfs::VfsError::Ebadf));
    }

    #[test]
    fn plain_socket_survives_exec_without_descriptor_flag() {
        let fdt = vfs::FdTable::new();
        let fd = install(&fdt, file(2), 8, false).unwrap();
        assert_eq!(fdt.cloexec(fd), Ok(false));
        fdt.close_on_exec();
        assert!(fdt.get(fd).is_ok());
    }

    #[test]
    fn limit_failure_publishes_nothing_and_leaves_slot_reusable() {
        let fdt = vfs::FdTable::new();
        assert_eq!(install(&fdt, file(3), 0, true), Err(vfs::VfsError::Emfile));
        assert!(fdt.live_fds().is_empty());
        assert_eq!(install(&fdt, file(4), 1, true), Ok(0));
        assert_eq!(fdt.cloexec(0), Ok(true));
    }

    #[test]
    fn close_and_reuse_linearizations_never_inherit_stale_descriptor_flags() {
        let close_first = vfs::FdTable::new();
        close_first.close_range(0, 0, false);
        assert_eq!(install(&close_first, file(5), 1, true), Ok(0));
        assert_eq!(close_first.cloexec(0), Ok(true));

        let install_first = vfs::FdTable::new();
        assert_eq!(install(&install_first, file(6), 1, true), Ok(0));
        install_first.close_range(0, 0, false);
        assert_eq!(install(&install_first, file(7), 1, false), Ok(0));
        assert_eq!(install_first.cloexec(0), Ok(false));
    }

    #[test]
    fn exec_racing_atomic_publication_has_only_valid_final_states() {
        for ino in 8..72 {
            let fdt = Arc::new(vfs::FdTable::new());
            let gate = Arc::new(Barrier::new(2));
            let exec_fdt = fdt.clone();
            let exec_gate = gate.clone();
            let exec = thread::spawn(move || {
                exec_gate.wait();
                exec_fdt.close_on_exec();
            });
            gate.wait();
            let fd = install(&fdt, file(ino), 1, true).unwrap();
            exec.join().unwrap();
            match fdt.get(fd) {
                Ok(_) => assert_eq!(fdt.cloexec(fd), Ok(true)),
                Err(e) => assert_eq!(e, vfs::VfsError::Ebadf),
            }
        }
    }

    #[test]
    fn every_socket_descriptor_route_uses_atomic_publication() {
        let socket = include_str!("041_socket.rs");
        let accept = include_str!("043_accept.rs");
        // IORING_OP_* dispatch is split by operation family; the socket ops
        // live in their own child module, and the SQE wire decode in the
        // shared entry decoder.
        let uring = include_str!("io_uring/dispatch/net_ops.rs");
        let sqe = include_str!("io_uring_sqe.rs");

        assert_eq!(socket.matches("socket_fd::install").count(), 1);
        assert_eq!(accept.matches("socket_fd::install").count(), 2);
        assert!(!socket.contains("alloc_limit"));
        assert!(!accept.contains("alloc_limit"));
        assert!(!socket.contains("set_cloexec"));
        assert!(!accept.contains("set_cloexec"));
        assert!(uring.contains("sys_accept4(&op.sqe.accept_args(op.fd))"));
        // The accept flags come from the SQE's own flags word, not from `len`.
        assert!(sqe.contains("op_flags: g32(28)"));
    }
}
