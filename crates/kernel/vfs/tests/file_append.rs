//! `File::write` + `O_APPEND` (Linux `FMODE_WRITE` + `O_APPEND`, `man 2 open`:
//! "the file offset is positioned at the end of the file ... before each
//! write(2)"). `File::write` must force the write offset to `inode.size()`
//! under `f_pos_lock` whenever `O_APPEND` is set, so an append lands at EOF
//! and never overwrites existing data — regardless of where the file-position
//! cursor currently points.
//!
//! Pre-fix shape: `write` used `pos` as the offset unconditionally; a cursor
//! left at (or rewound to) 0 by a prior `lseek`/`read`/`set_pos` would clobber
//! the head of the file. The implementation now reads `inode.size()` for the
//! offset on the `O_APPEND` branch, inside the same `f_pos_lock` region as the
//! cursor update, so concurrent appenders on one shared description serialize
//! at distinct end-of-file offsets.

use std::sync::{Arc, Mutex};
use std::thread;

use vfs::inode::Inode;
use vfs::{Dentry, File, FileType, Ino, InodeRef, KResult, OpenFlags, VfsError};

/// Growable in-memory regular file. `write(off, buf)` places `buf` at `off`,
/// zero-extending the backing store when `off` is past the current end;
/// `size()` reports the high-water length (so `O_APPEND` sees real growth).
struct MemFile { data: Mutex<Vec<u8>> }

impl MemFile {
    fn new(initial: &[u8]) -> Arc<Self> { Arc::new(Self { data: Mutex::new(initial.to_vec()) }) }
    fn bytes(&self) -> Vec<u8> { self.data.lock().unwrap().clone() }
}

impl Inode for MemFile {
    fn ino(&self) -> Ino { 0xA9 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { self.data.lock().unwrap().len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = self.data.lock().unwrap();
        let off = off as usize;
        if off >= d.len() { return Ok(0); }
        let n = buf.len().min(d.len() - off);
        buf[..n].copy_from_slice(&d[off..off + n]);
        Ok(n)
    }
    fn write(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        let mut d = self.data.lock().unwrap();
        let off = off as usize;
        if off + buf.len() > d.len() { d.resize(off + buf.len(), 0); }
        d[off..off + buf.len()].copy_from_slice(buf);
        Ok(buf.len())
    }
}

fn append_file(ino: &Arc<MemFile>, mode: OpenFlags) -> Arc<File> {
    let i: InodeRef = Arc::clone(ino) as InodeRef;
    let d = Dentry::new(None, "f".into(), Arc::clone(&i));
    File::new(i, d, mode | OpenFlags::O_APPEND)
}

/// An append with the cursor rewound to 0 must still land at EOF, leaving the
/// existing head intact, and must advance `pos` to the new end-of-file.
/// Pre-fix this clobbers "HEAD" (write at pos=0) → final bytes "TAIL".
#[test]
fn append_writes_at_eof_not_at_cursor() {
    let ino = MemFile::new(b"HEAD");                 // size = 4
    let f = append_file(&ino, OpenFlags::O_WRONLY);
    f.set_pos(0);                                     // rewind the cursor under the write's nose
    assert_eq!(f.write(b"TAIL").unwrap(), 4);
    assert_eq!(ino.bytes(), b"HEADTAIL", "append must not overwrite the file head");
    assert_eq!(f.pos(), 8, "pos advances to the new end-of-file after an append");
}

/// Repeated appends keep extending from the live size, never from a stale
/// cursor, even after an intervening rewind between writes.
#[test]
fn repeated_appends_keep_extending() {
    let ino = MemFile::new(b"");
    let f = append_file(&ino, OpenFlags::O_WRONLY);
    f.write(b"aa").unwrap();
    f.set_pos(0);                                     // try to make the next write clobber
    f.write(b"bb").unwrap();
    f.set_pos(1);                                     // again, mid-file cursor
    f.write(b"cc").unwrap();
    assert_eq!(ino.bytes(), b"aabbcc", "each append starts at the current size");
    assert_eq!(f.pos(), 6);
}

/// `O_RDWR | O_APPEND`: writes append at EOF while reads honour the cursor.
#[test]
fn rdwr_append_writes_at_eof_reads_at_cursor() {
    let ino = MemFile::new(b"0123");
    let f = append_file(&ino, OpenFlags::O_RDWR);
    f.set_pos(0);
    let mut head = [0u8; 4];
    assert_eq!(f.read(&mut head).unwrap(), 4);
    assert_eq!(&head, b"0123", "read uses the cursor, not EOF");
    // Cursor is now 4 (== size); append still pins to size regardless.
    f.set_pos(1);
    f.write(b"XY").unwrap();
    assert_eq!(ino.bytes(), b"0123XY", "append ignores the rewound cursor");
}

/// Concurrent appenders sharing one `Arc<File>` must each land at a distinct
/// end-of-file offset (the `O_APPEND` size-read sits inside `f_pos_lock`), so
/// the file grows by exactly the total bytes with no lost writes.
#[test]
fn concurrent_appends_do_not_overwrite() {
    const N: usize = 8;
    const L: usize = 4;
    let ino = MemFile::new(b"");
    let f = append_file(&ino, OpenFlags::O_WRONLY);
    let mut hs = Vec::new();
    for _ in 0..N {
        let f = Arc::clone(&f);
        hs.push(thread::spawn(move || { f.write(&[0xAB; L]).unwrap(); }));
    }
    for h in hs { h.join().unwrap(); }
    let bytes = ino.bytes();
    assert_eq!(bytes.len(), N * L, "every append extends the file; none overwrite another");
    assert!(bytes.iter().all(|&b| b == 0xAB), "no byte was left unwritten/clobbered");
    assert_eq!(f.pos() as usize, N * L, "final pos == total appended bytes");
}
