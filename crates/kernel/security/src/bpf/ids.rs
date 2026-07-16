use vfs::Ino;

pub(crate) const INO_BASE: Ino = 0x7300_0000;
pub(crate) const INO_PROG: Ino = INO_BASE | 0x01;
pub(crate) const INO_MAP: Ino = INO_BASE | 0x02;
pub(crate) const INO_LINK: Ino = INO_BASE | 0x03;
