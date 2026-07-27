// readdir driver: `.`/`..` synthesis + child-cursor offsetting.
//
// Linux has every filesystem call `dir_emit_dots` (`include/linux/fs.h`) at the
// head of its own `iterate_shared`, and reserves readdir cursors 0 and 1 for the
// two dots. Backends whose entries physically carry the dots (ext4, and FUSE
// where the daemon supplies them) opt out via
// [`crate::FileOps::iterate_emits_dots`]; every synthetic backend gets them
// here, in ONE place, instead of ~50 `iterate` bodies each having to shift its
// own cookie space by two.
//
// Without the dots `ls -a` shows no `.`/`..` on /proc, /sys, /dev, /run and
// every other synthetic mount, `find` cannot walk upward, and `getcwd(3)`
// fallbacks that compare `..` inode numbers fail.

use crate::dirent::{DType, DOTS_RESERVED, emit_dots};
use crate::file_ops::{DirContext, DirEmit};
use crate::inode::InodeRef;
use crate::types::{FileType, KResult};

/// Forwarding actor that shifts a backend's child cookies past the two reserved
/// dot cursors, so cursor `0`/`1` always mean `.`/`..` and child `i` sits at
/// `DOTS_RESERVED + i`.
struct DotShift<'a> { inner: &'a mut dyn DirEmit }

impl DirEmit for DotShift<'_> {
    fn emit(&mut self, name: &str, ino: u64, d_type: FileType, next_pos: u64) -> bool {
        self.inner.emit(name, ino, d_type, next_pos + DOTS_RESERVED)
    }
    fn emit_dt(&mut self, name: &str, ino: u64, d_type: DType, next_pos: u64) -> bool {
        self.inner.emit_dt(name, ino, d_type, next_pos + DOTS_RESERVED)
    }
    #[cfg(feature = "debug-getdents")]
    fn debug_getdents_progress(&mut self, backend: crate::file_ops::DirDebugBackend, block: u32,
                               entries: u64, pos: u64) {
        self.inner.debug_getdents_progress(backend, block, entries, pos);
    }
}

/// Drive one `getdents` pass over `inode` starting at readdir cursor `start`,
/// synthesising `.` (ino `self_ino`) and `..` (ino `parent_ino`) unless the
/// backend supplies its own. Returns the backend's result and the resume cursor
/// to store in `file->f_pos`.
///
/// For a filesystem root Linux makes `..` resolve back to the root, so the
/// caller passes `parent_ino == self_ino` there.
/// # C: O(N_dirents)
pub fn readdir_dots(inode: &InodeRef, self_ino: u64, parent_ino: u64, start: u64,
                    actor: &mut dyn DirEmit) -> (KResult<()>, u64) {
    if inode.dir_emits_dots() {
        let mut ctx = DirContext::new(start, actor);
        let r = inode.readdir(&mut ctx);
        return (r, ctx.pos);
    }
    let mut pos = start;
    if start < DOTS_RESERVED {
        let mut sink = |ino: u64, next: u64, name: &str, ft: FileType| {
            if actor.emit(name, ino, ft, next) { pos = next; true } else { false }
        };
        if !emit_dots(start, self_ino, parent_ino, &mut sink) {
            // Buffer filled inside the dots: stop without touching the backend,
            // so the unemitted dot is retried on the next call.
            return (Ok(()), pos);
        }
    }
    let mut shift = DotShift { inner: actor };
    let mut ctx = DirContext::new(pos - DOTS_RESERVED, &mut shift);
    let r = inode.readdir(&mut ctx);
    (r, ctx.pos + DOTS_RESERVED)
}
