//! Synthetic IPC inode identities owned by live IPC pseudo-filesystems.
//! Queue inodes themselves take real `get_next_ino()` numbers, as mqueuefs
//! does (`ipc/mqueue.c:300`); only the per-namespace root is fixed.

/// `i_ino` of every per-IPC-namespace mqueuefs ROOT directory.
pub(crate) const POSIX_MQ_ROOT_INO: u64 = 0xFEED_0011;
