//! The merged directory stream, deduplicated and filtered.
//!
//! Reading a merged directory means reading every layer's copy of it and
//! presenting one list. Three things have to be true of that list or ordinary
//! tools break: a name present in two layers appears ONCE, a whiteout hides
//! the name it covers in every layer below AND does not itself appear, and the
//! position of a name does not move between two reads of the same directory —
//! `getdents` resumes from an offset, so a list that reorders makes a caller
//! see an entry twice or miss one entirely.
//!
//! The ordering rule that buys the last property is worth stating: entries
//! that exist in the BOTTOM layer come first, in that layer's own order, and
//! entries added by layers above follow. A copy-up adds a name to the writable
//! layer without moving anything already in the bottom one, so the offsets of
//! everything below stay where they were.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::dirent::DType;
use vfs::file_ops::{DirContext, DirEmit};
use vfs::types::FileType;
use vfs::InodeRef;

use crate::err::to_errno;
use crate::layers::{LayerStack, OvlEntry};
use crate::whiteout;
use crate::xino;

/// One name in the merged stream.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    pub name: String,
    pub ino: u64,
    pub dtype: DType,
    /// Hides the same name in every layer below, and is not itself shown.
    pub whiteout: bool,
    /// Came from the writable layer.
    pub upper: bool,
}

/// Names of one real directory, as its own layer reports them. # C: O(entries)
fn one_layer(dir: &InodeRef) -> Result<Vec<(String, u64, DType)>, Errno> {
    struct Sink(Vec<(String, u64, DType)>);
    impl DirEmit for Sink {
        fn emit(&mut self, name: &str, ino: u64, t: FileType, _next: u64) -> bool {
            self.emit_dt(name, ino, DType::from_file_type(t), _next)
        }
        fn emit_dt(&mut self, name: &str, ino: u64, t: DType, _next: u64) -> bool {
            self.0.push((name.to_string(), ino, t));
            true
        }
    }
    let mut sink = Sink(Vec::new());
    let mut ctx = DirContext::new(0, &mut sink);
    dir.readdir(&mut ctx).map_err(to_errno)?;
    Ok(sink.0)
}

/// Build the merged list for `entry`.
///
/// The bottom layer is read last but placed FIRST, so that a name it holds
/// keeps its position no matter what the layers above it gain.
/// # C: O(total entries · log names)
pub fn merged(stack: &Arc<LayerStack>, entry: &OvlEntry) -> Result<Vec<Entry>, Errno> {
    let mut dirs: Vec<(InodeRef, bool, bool)> = Vec::new();
    if let Some(u) = &entry.upper { dirs.push((u.clone(), true, false)); }
    for p in &entry.lower {
        if p.layer.data_only { continue; }
        dirs.push((p.inode.clone(), false, p.layer.xwhiteouts() && entry.xwhiteouts));
    }
    if dirs.is_empty() { return Ok(Vec::new()); }

    let last = dirs.len() - 1;
    let mut above: Vec<Entry> = Vec::new();
    let mut bottom: Vec<Entry> = Vec::new();
    for (i, (dir, upper, marked)) in dirs.iter().enumerate() {
        for (name, ino, dtype) in one_layer(dir)? {
            if name == "." || name == ".." { continue; }
            let w = is_whiteout(stack, dir, &name, dtype, *marked);
            let e = Entry { name, ino: report_ino(stack, entry, i, ino), dtype, whiteout: w,
                            upper: *upper };
            if i == last {
                // A name the bottom layer also holds moves down here, keeping
                // that layer's order and therefore its offsets.
                if let Some(pos) = above.iter().position(|x| x.name == e.name) {
                    bottom.push(above.remove(pos));
                } else {
                    bottom.push(e);
                }
            } else if !above.iter().any(|x| x.name == e.name) {
                above.push(e);
            }
        }
    }
    bottom.extend(above);
    Ok(bottom)
}

/// Is this entry a whiteout? Only a character device or, in a directory that
/// declares them, an empty marked file can be, so the extra lookup is made
/// for nothing else. # C: O(1) or one lookup
fn is_whiteout(stack: &Arc<LayerStack>, dir: &InodeRef, name: &str, dtype: DType, marked: bool)
    -> bool {
    let chr = DType::from_file_type(FileType::CharDev);
    let reg = DType::from_file_type(FileType::Regular);
    if dtype != chr && !(marked && dtype == reg) { return false; }
    match dir.lookup(name) {
        Ok(i) => whiteout::is_whiteout(&stack.config, &i, marked),
        Err(_) => false,
    }
}

/// The inode number to report for an entry from layer `idx`.
///
/// A lower layer's numbers are tagged so two layers holding the same number
/// stop looking like one file to `find -samefile` and `du`.
/// # C: O(1)
fn report_ino(stack: &Arc<LayerStack>, entry: &OvlEntry, idx: usize, ino: u64) -> u64 {
    let bits = stack.xino.bits();
    if bits == 0 || idx == 0 && entry.upper.is_some() { return ino; }
    let li = if entry.upper.is_some() { idx - 1 } else { idx };
    match entry.lower.get(li) {
        Some(p) => xino::remap(ino, bits, p.layer.fsid),
        None => ino,
    }
}

/// The names a caller actually sees. # C: O(entries)
pub fn visible(list: &[Entry]) -> impl Iterator<Item = &Entry> {
    list.iter().filter(|e| !e.whiteout)
}

/// Is the merged directory empty enough to remove?
///
/// A directory holding only whiteouts is empty as far as any caller can tell,
/// and removing it is what makes `rm -r` of a directory whose contents were
/// all deleted work at all. The whiteouts themselves are cleaned up with it.
/// # C: O(entries)
pub fn is_empty(stack: &Arc<LayerStack>, entry: &OvlEntry) -> Result<bool, Errno> {
    Ok(visible(&merged(stack, entry)?).next().is_none())
}

/// The whiteouts inside a directory that is about to be removed, which have to
/// go with it. # C: O(entries)
pub fn whiteouts(list: &[Entry]) -> impl Iterator<Item = &Entry> {
    list.iter().filter(|e| e.whiteout)
}

#[cfg(test)]
#[path = "readdir/tests.rs"]
mod tests;
