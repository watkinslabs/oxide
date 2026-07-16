use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use vfs::InodeRef;

use super::self_files::{push, push_u64};

const IO_BODY: &[u8] = b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n";

/// Linux `/proc/<pid>/io` task I/O accounting. # C: O(1)
pub fn io_body_for_task(t: &sched::Task) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    push(&mut out, b"rchar: "); push_u64(&mut out, t.io_rchar.load(Ordering::Relaxed)); out.push(b'\n');
    push(&mut out, b"wchar: "); push_u64(&mut out, t.io_wchar.load(Ordering::Relaxed)); out.push(b'\n');
    push(&mut out, b"syscr: "); push_u64(&mut out, t.io_syscr.load(Ordering::Relaxed)); out.push(b'\n');
    push(&mut out, b"syscw: "); push_u64(&mut out, t.io_syscw.load(Ordering::Relaxed)); out.push(b'\n');
    push(&mut out, b"read_bytes: "); push_u64(&mut out, t.io_read_bytes.load(Ordering::Relaxed)); out.push(b'\n');
    push(&mut out, b"write_bytes: "); push_u64(&mut out, t.io_write_bytes.load(Ordering::Relaxed)); out.push(b'\n');
    push(&mut out, b"cancelled_write_bytes: "); push_u64(&mut out, t.io_cancelled_write_bytes.load(Ordering::Relaxed)); out.push(b'\n');
    out
}

fn self_io_body() -> Vec<u8> {
    match sched::live::current() {
        Some(t) => io_body_for_task(t),
        None    => IO_BODY.to_vec(),
    }
}

/// `/proc/self/io` inode. # C: O(1)
pub fn make_proc_self_io() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::SELF_IO, self_io_body) }
