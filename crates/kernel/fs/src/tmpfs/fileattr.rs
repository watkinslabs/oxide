// `i_op->fileattr_{get,set}` for tmpfs.
// Reached by `FS_IOC_{GET,SET}FLAGS`, `FS_IOC_FS{GET,SET}XATTR` (slot 16) and
// by `file_getattr(2)` / `file_setattr(2)` (slots 468/469). Without it every
// tmpfs mount — `/tmp`, `/run`, `/dev/shm` — answered `EOPNOTSUPP` where the
// real ABI answers `0`, and `chattr +i` on a tmpfs file was impossible.
//
// The BODY lives in `vfs::inode::shmem_fileattr_{get,set}`: the device
// filesystem's directory tree is a shmem instance too and exposes the exact
// same surface, so one implementation serves both. tmpfs re-exports it under
// its own name for its `i_op` vectors.

pub(super) use vfs::inode::shmem_fileattr_get as tmpfs_fileattr_get;
pub(super) use vfs::inode::shmem_fileattr_set as tmpfs_fileattr_set;
