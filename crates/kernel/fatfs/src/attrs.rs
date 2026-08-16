//! The attribute byte, and the mode it presents as.
//!
//! FAT stores no owner and no permission bits. It stores ONE bit that means
//! anything to a mode — read-only — and the rest of what a caller sees is the
//! mount's `uid=`/`gid=`/`fmask=`/`dmask=` answer. So a mode is derived, and
//! the derivation is here rather than in the mount code because that code
//! reaches the block layer and cannot be tested; this can.
//!
//! Two rules in it are not obvious and both come straight from the reference.
//! A read-only DIRECTORY keeps its write bits unless the mount asked for
//! `rodir`, because the attribute means something else on a directory and
//! honouring it makes tools refuse to descend. And `showexec` gives the
//! execute bits to three extensions and takes them from everything else,
//! which is the only sense in which this filesystem has an executable file.

use crate::dirent::{ATTR_ARCH, ATTR_DIR, ATTR_RO};
use crate::opts::Options;

/// Every permission bit, before a mask is applied.
pub const ALL_PERMS: u16 = 0o777;
/// The write bits a read-only entry loses.
pub const WRITE_BITS: u16 = 0o222;
/// The execute bits `showexec` grants or withholds.
pub const EXEC_BITS: u16 = 0o111;

/// Where the extension starts within a short entry's eleven bytes, and how
/// long it is.
const EXT_AT: usize = 8;
const EXT_LEN: usize = 3;

/// The three extensions `showexec` treats as executable, concatenated in the
/// order the reference walks them.
const EXEC_EXTENSIONS: &[u8; 9] = b"EXECOMBAT";

/// Whether the three extension bytes name an executable. # C: O(1)
pub fn is_exec(ext: &[u8]) -> bool {
    if ext.len() < EXT_LEN { return false; }
    EXEC_EXTENSIONS.chunks_exact(EXT_LEN).any(|known| known == &ext[..EXT_LEN])
}

/// The permission bits an entry presents with.
///
/// `raw_name` is the entry's eleven bytes, needed only for `showexec`; a
/// directory never loses its execute bits to it, since a directory with none
/// cannot be entered.
/// # C: O(1)
pub fn make_mode(attr: u8, raw_name: &[u8], o: &Options) -> u16 {
    let is_dir = attr & ATTR_DIR != 0;
    let mut mode = ALL_PERMS;
    // The read-only attribute means "do not change this file". On a directory
    // it means something closer to "custom icon", so it is honoured there only
    // when the mount asked for it.
    if attr & ATTR_RO != 0 && !(is_dir && !o.rodir) { mode &= !WRITE_BITS; }
    if is_dir { return mode & !o.dmask; }
    if o.showexec && raw_name.len() >= EXT_AT + EXT_LEN && !is_exec(&raw_name[EXT_AT..]) {
        mode &= !EXEC_BITS;
    }
    mode & !o.fmask
}

/// The attribute byte a mode change writes back.
///
/// Only the read-only bit can be expressed. A mode with no owner write bit is
/// read-only; anything else is not, and the archive bit is set on every file
/// because that is what a file that has been written carries.
/// # C: O(1)
pub fn make_attrs(is_dir: bool, mode: u16, previous: u8) -> u8 {
    const OWNER_WRITE: u16 = 0o200;
    let mut attr = previous & !ATTR_RO;
    if mode & OWNER_WRITE == 0 { attr |= ATTR_RO; }
    if is_dir { attr | ATTR_DIR } else { (attr & !ATTR_DIR) | ATTR_ARCH }
}

#[cfg(test)]
#[path = "attrs/tests.rs"]
mod tests;
