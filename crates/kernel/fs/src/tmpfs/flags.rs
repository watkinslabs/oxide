/// memfd file-seal bits (`fcntl.h`).
pub const F_SEAL_SEAL:   u32 = 0x0001;
pub const F_SEAL_SHRINK: u32 = 0x0002;
pub const F_SEAL_GROW:   u32 = 0x0004;
pub const F_SEAL_WRITE:  u32 = 0x0008;
pub const F_SEAL_FUTURE_WRITE: u32 = 0x0010;

pub(super) const S_IFMT:  u16 = 0xF000;
pub(super) const S_IFCHR: u16 = 0x2000;
pub(super) const S_IFBLK: u16 = 0x6000;
pub(super) const S_IFIFO: u16 = 0x1000;
pub(super) const S_IFSOCK: u16 = 0xC000;
