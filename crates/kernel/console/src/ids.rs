//! Synthetic console inode identities owned by the console filesystem layer.

use vfs::Ino;

pub(crate) const VCS_INO: Ino = 0x7600;
pub(crate) const VCSA_INO: Ino = 0x7700;
pub(crate) const TTY_INO_MASK: Ino = 0xFF;
