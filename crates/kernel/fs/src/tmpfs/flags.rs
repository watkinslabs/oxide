/// memfd file-seal bits (`include/uapi/linux/fcntl.h`).
pub use vfs::{
    F_SEAL_EXEC, F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK,
    F_SEAL_WRITE,
};

pub(super) const S_IFMT:  u16 = 0xF000;
pub(super) const S_IFCHR: u16 = 0x2000;
pub(super) const S_IFBLK: u16 = 0x6000;
pub(super) const S_IFIFO: u16 = 0x1000;
pub(super) const S_IFSOCK: u16 = 0xC000;
