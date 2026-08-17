//! A `/proc/fs` seq file: bytes produced by the owning filesystem's renderer.
//!
//! The existing dynamic-file constructors in this crate take a bare `fn`
//! pointer, which cannot carry the mount a per-mount file reports on. A
//! filesystem's `/proc/fs/<name>/<mount>/...` files all need that, so the
//! renderer here is a callable that can hold it.
//!
//! Read semantics follow `seq_file`: the body is rendered once when the file
//! is opened and every partial read is served from that one result. A
//! `getdents`-sized read of a segment table would otherwise see the table
//! change between pages and splice two different snapshots together. A read
//! made without an open — an internal caller holding the inode directly —
//! renders fresh, because there is no open to have cached anything.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{default_inode_ops, mk_mode, File, FileOps, FileType, Ino, Inode, InodeBuilder,
          InodeRef, KResult, VfsError};

/// Renders a `/proc/fs` file's current bytes (upstream `seq_show`).
pub type ShowFn = Arc<dyn Fn() -> KResult<Vec<u8>> + Send + Sync>;

/// Consumes a write to a `/proc/fs` file (upstream `proc_ops->proc_write`),
/// returning the count accepted — what the caller's `write(2)` reports.
///
/// Most files here are reports and have none. A few are controls: a
/// filesystem's label is set by writing the new one to the file that reads it
/// back, and there is nowhere else that operation lives.
pub type StoreFn = Arc<dyn Fn(&[u8]) -> KResult<usize> + Send + Sync>;

/// `i_private` of a `/proc/fs` file: the callables the filesystem supplied.
struct SeqData { show: ShowFn, store: Option<StoreFn> }

struct SeqFileOps;

impl FileOps for SeqFileOps {
    /// procfs files always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &File) -> bool { true }

    /// # C: cost of the filesystem's own renderer
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<SeqData>().ok_or(VfsError::Einval)?;
        let body = (d.show)()?;
        Ok(window(&body, off, buf))
    }

    /// # C: O(n)
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let raw = file.private_data();
        if raw == 0 { return Err(VfsError::Einval); }
        // SAFETY: `on_open_file` allocates exactly one Vec for this open file
        // and stores its non-null pointer here; `on_release_file` drops it only
        // after the last reference to this open description is gone, so the
        // pointer is live and uniquely owned for the whole of this read.
        let body = unsafe { &*(raw as *const Vec<u8>) };
        Ok(window(body, off, buf))
    }

    /// A file with no `store` is a report, and refuses writes rather than
    /// accepting and discarding them. # C: cost of the filesystem's own store
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<SeqData>().ok_or(VfsError::Einval)?;
        match &d.store {
            Some(store) => store(buf),
            None => Err(VfsError::Erofs),
        }
    }

    /// # C: cost of the filesystem's own renderer
    fn on_open_file(&self, file: &File) -> KResult<()> {
        if !file.f_mode().contains(vfs::Fmode::READ) { return Ok(()); }
        let d = file.inode().private::<SeqData>().ok_or(VfsError::Einval)?;
        let body = Box::new((d.show)()?);
        file.set_private_data(Box::into_raw(body) as u64);
        Ok(())
    }

    /// # C: O(1)
    fn on_release_file(&self, file: &File) {
        let raw = file.private_data();
        if raw == 0 { return; }
        // SAFETY: `on_open_file` allocated this Vec for this File alone, and
        // `File::drop` invokes release exactly once, at the last close.
        unsafe { drop(Box::from_raw(raw as *mut Vec<u8>)); }
        file.set_private_data(0);
    }
}

/// Copy `body[off..]` into `buf`, the shared windowed read. # C: O(n)
fn window(body: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let off = off as usize;
    if off >= body.len() { return 0; }
    let avail = &body[off..];
    let n = avail.len().min(buf.len());
    buf[..n].copy_from_slice(&avail[..n]);
    n
}

/// Build one `/proc/fs` seq-file inode. # C: O(1)
pub(crate) fn make(mode: u16, show: ShowFn, store: Option<StoreFn>, ino: Ino) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, mode), default_inode_ops(),
                      Arc::new(SeqFileOps))
        .private(Arc::new(SeqData { show, store }))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    /// The renderer supplies the bytes, and a windowed read returns the
    /// requested slice of them.
    #[test]
    fn a_read_windows_the_rendered_body() {
        let show: ShowFn = Arc::new(|| Ok(b"segment 0|3\n".to_vec()));
        let inode = make(0o444, show, None, 0x3800_1000);
        let mut buf = [0u8; 4];
        let n = inode.read(8, &mut buf).expect("read");
        assert_eq!(&buf[..n], b"0|3\n");
    }

    /// An error from the filesystem's renderer reaches the reader rather than
    /// being reported as an empty file.
    #[test]
    fn a_renderer_error_reaches_the_reader() {
        let show: ShowFn = Arc::new(|| Err(VfsError::Eio));
        let inode = make(0o444, show, None, 0x3800_1001);
        let mut buf = [0u8; 4];
        assert_eq!(inode.read(0, &mut buf), Err(VfsError::Eio));
    }

    /// A file with no store reports, and does not accept commands.
    #[test]
    fn a_write_to_a_report_is_refused() {
        let show: ShowFn = Arc::new(|| Ok(Vec::new()));
        let inode = make(0o444, show, None, 0x3800_1002);
        assert_eq!(inode.write(0, b"x"), Err(VfsError::Erofs));
    }

    /// A control's write reaches the filesystem, and the count it accepted is
    /// what the writer is told. A write that never arrived would leave the
    /// name a volume answers to unchanged with nothing to show for it.
    #[test]
    fn a_write_to_a_control_reaches_the_filesystem() {
        use sync::{Spinlock, TaskList};
        static SEEN: Spinlock<Vec<u8>, TaskList> = Spinlock::new(Vec::new());
        let show: ShowFn = Arc::new(|| Ok(SEEN.lock().clone()));
        let store: StoreFn = Arc::new(|b: &[u8]| {
            *SEEN.lock() = b.to_vec();
            Ok(b.len())
        });
        let inode = make(0o644, show, Some(store), 0x3800_1004);
        assert_eq!(inode.write(0, b"NEW-LABEL"), Ok(9));
        let mut buf = [0u8; 16];
        let n = inode.read(0, &mut buf).expect("read");
        assert_eq!(&buf[..n], b"NEW-LABEL");
    }

    /// Every page of ONE open read must come from ONE render: a paginated
    /// read that re-rendered per page would splice two snapshots together.
    #[test]
    fn one_open_serves_every_page_from_one_render() {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let show: ShowFn = Arc::new(|| {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            Ok(alloc::format!("{n}{n}{n}{n}{n}{n}").into_bytes())
        });
        let inode = make(0o444, show, None, 0x3800_1003);
        let dentry = vfs::Dentry::new_root(Arc::clone(&inode));
        let fdt = vfs::FdTable::new();
        let fd = vfs::file::install_open_at(&fdt, inode, dentry, vfs::OpenFlags::O_RDONLY, 0,
            vfs::FileCred::root(), usize::MAX, None).expect("open");
        let f = fdt.get(fd).expect("file");
        let mut page = [0u8; 3];
        let n = f.read(&mut page).expect("first page");
        let first = page[..n].to_vec();
        let n = f.read(&mut page).expect("second page");
        let second = page[..n].to_vec();
        assert_eq!(first, second, "the two pages came from different renders");
    }
}
