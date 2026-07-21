// Hosted tests for the `dir_context` readdir model (file_ops D38/file D32):
// `DirContext::emit` cursor advance, the resume cookie, and buffer-full stop.

extern crate alloc;
use crate::file_ops::{DirContext, DirEmit};
use crate::types::FileType;
use alloc::string::String;
use alloc::vec::Vec;

// Index-cursor backend stand-in (tmpfs/procfs shape): resume at `ctx.pos`,
// emit each entry with a 1-based `next_pos` cookie, stop when `emit` rejects.
fn fake_iterate(entries: &[(&str, u64, FileType)], ctx: &mut DirContext) {
    let mut idx = ctx.pos as usize;
    while idx < entries.len() {
        let (name, ino, ft) = entries[idx];
        let next = idx as u64 + 1;
        if !ctx.emit(name, ino, ft, next) { return; }
        idx += 1;
    }
}

// `filldir` stand-in accepting at most `cap` entries, then signalling full.
struct CapActor { cap: usize, got: Vec<(String, u64, u64)> }
impl DirEmit for CapActor {
    fn emit(&mut self, name: &str, ino: u64, _d: FileType, next_pos: u64) -> bool {
        if self.got.len() >= self.cap { return false; }
        self.got.push((String::from(name), ino, next_pos));
        true
    }
}

const DIR: [(&str, u64, FileType); 4] = [
    ("a", 10, FileType::Regular),
    ("b", 11, FileType::Regular),
    ("c", 12, FileType::Directory),
    ("d", 13, FileType::Symlink),
];

#[test]
fn dir_context_emit_and_resume_cookie() {
    // Pass 1: buffer holds 2 → stop after "b"; cursor parks at b's cookie.
    let mut a1 = CapActor { cap: 2, got: Vec::new() };
    let pos_after = {
        let mut ctx = DirContext::new(0, &mut a1);
        fake_iterate(&DIR, &mut ctx);
        ctx.pos
    };
    assert_eq!(a1.got.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(pos_after, 2); // resume cookie = the accepted "b" entry's next_pos

    // Pass 2 resuming at the cookie: continues with c, d — no dup, no skip.
    let mut a2 = CapActor { cap: 10, got: Vec::new() };
    let pos_end = {
        let mut ctx = DirContext::new(pos_after, &mut a2);
        fake_iterate(&DIR, &mut ctx);
        ctx.pos
    };
    assert_eq!(a2.got.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["c", "d"]);
    assert_eq!(pos_end, 4);
    // d_ino + cookie threading preserved end-to-end.
    assert_eq!(a2.got[0], (String::from("c"), 12, 3));
}

#[test]
fn dir_context_buffer_full_does_not_advance_pos() {
    // cap 0 → first emit rejected; pos stays at start so the cursor is not lost
    // (Linux `filldir` full-buffer: the entry is retried on the next getdents).
    let mut a = CapActor { cap: 0, got: Vec::new() };
    let pos = {
        let mut ctx = DirContext::new(0, &mut a);
        fake_iterate(&DIR, &mut ctx);
        ctx.pos
    };
    assert!(a.got.is_empty());
    assert_eq!(pos, 0);
}

#[cfg(feature = "debug-getdents")]
#[test]
fn debug_getdents_progress_uses_the_named_entry_interval() {
    use crate::file_ops::{DEBUG_GETDENTS_PROGRESS_ENTRY_INTERVAL, debug_getdents_progress_due};
    assert!(!debug_getdents_progress_due(0));
    assert!(!debug_getdents_progress_due(DEBUG_GETDENTS_PROGRESS_ENTRY_INTERVAL - 1));
    assert!(debug_getdents_progress_due(DEBUG_GETDENTS_PROGRESS_ENTRY_INTERVAL));
    assert!(debug_getdents_progress_due(DEBUG_GETDENTS_PROGRESS_ENTRY_INTERVAL * 2));
}
