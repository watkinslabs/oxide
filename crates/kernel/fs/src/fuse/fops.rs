// Forwarding `i_op` (`FuseInodeOps`) and `i_fop` (`FuseFileOps`) for a mounted
// fuse inode — the VFS→channel bridge. Each op encodes the matching FUSE request
// body, issues it on the inode's channel via [`FuseConn::call`] (which blocks
// the caller until the daemon replies), and decodes the reply.
//
// REAL read-path ops: LOOKUP, GETATTR, OPEN/OPENDIR, READ, READDIR, RELEASE/
// RELEASEDIR, FLUSH. The write/create/namespace-mutation family is out of scope
// and takes the trait's `Erofs` default — no faked success.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use sync::{Spinlock, Tty as FuseClass};
use vfs::{DirContext, File, FileOps, FileType, Idmap, Inode, InodeOps, InodeRef, KResult, VfsError};
use vfs::{Kstat, generic_fillattr};

use super::fs::{build_inode, fuse_data, name_body};
use super::proto::{self, Attr};

/// Per-open file handle state (Linux `struct fuse_file`). Keyed by the reader's
/// open `File` identity so READ carries the `fh` the daemon returned from OPEN.
/// # C: O(1)
struct FuseFile {
    /// `fuse_open_out.fh` the daemon assigned. # consumers: read/release.
    fh: u64,
    /// The nodeid this handle was opened on. # consumers: release.
    nodeid: u64,
}

/// `File` identity → its opened FUSE handle. An entry exists from the first
/// read's lazy OPEN until `on_release_file`. # C: O(1)
static FUSE_FILES: Spinlock<BTreeMap<usize, FuseFile>, FuseClass> = Spinlock::new(BTreeMap::new());

/// `struct fuse_attr` → the volatile inode fields we cache locally, then defer
/// the stat assembly to `generic_fillattr`. # C: O(1)
fn apply_attr(inode: &Inode, attr: &Attr) {
    inode.set_size(attr.size);
    if attr.nlink != 0 { inode.set_nlink(attr.nlink); }
}

/// `i_op` for a fuse inode — the namespace/metadata ops forwarded to the daemon.
pub struct FuseInodeOps;
impl InodeOps for FuseInodeOps {
    /// `FUSE_LOOKUP` — resolve `name` in this directory nodeid → a child inode.
    /// A daemon `entry.nodeid == 0` is a NEGATIVE lookup (`Enoent`). # C: O(1) + rtt
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = fuse_data(inode)?;
        let reply = d.conn.call(proto::FUSE_LOOKUP, d.nodeid, &name_body(name))?;
        let entry = proto::EntryOut::decode(&reply).ok_or(VfsError::Eio)?;
        if entry.nodeid == 0 { return Err(VfsError::Enoent); }
        Ok(build_inode(&d.conn, entry.nodeid, &entry.attr))
    }

    /// `FUSE_GETATTR` — refresh + report this inode's attributes. On a daemon
    /// error, report the locally cached fields because this VFS signature cannot
    /// return an errno. # C: O(1) + rtt
    fn getattr(&self, inode: &Inode, idmap: &Idmap) -> Kstat {
        if let Ok(d) = fuse_data(inode) {
            let mut body = Vec::with_capacity(proto::FUSE_GETATTR_IN_SIZE);
            proto::GetattrIn { getattr_flags: 0, fh: 0 }.encode(&mut body);
            if let Ok(reply) = d.conn.call(proto::FUSE_GETATTR, d.nodeid, &body) {
                if let Some(ao) = proto::AttrOut::decode(&reply) { apply_attr(inode, &ao.attr); }
            }
        }
        generic_fillattr(inode, idmap)
    }
}

/// Recover the per-open handle key for a fuse `File`. # C: O(1)
fn file_key(file: &File) -> usize { file as *const File as usize }

/// Ensure the reader's `File` has an OPEN handle, doing the lazy `FUSE_OPEN` on
/// first read (Linux opens at `open(2)`; this VFS has no per-open op that can
/// stash the `fh`, so the open is folded into first read). Returns the `fh`.
/// # C: O(1) + rtt on first call
fn ensure_open(file: &File) -> KResult<u64> {
    let key = file_key(file);
    if let Some(f) = FUSE_FILES.lock().get(&key) { return Ok(f.fh); }
    let d = fuse_data(file.inode())?;
    let is_dir = file.inode().file_type() == FileType::Directory;
    let op = if is_dir { proto::FUSE_OPENDIR } else { proto::FUSE_OPEN };
    let mut body = Vec::with_capacity(proto::FUSE_OPEN_IN_SIZE);
    proto::OpenIn { flags: file.flags().bits() & 0o3, open_flags: 0 }.encode(&mut body);
    let reply = d.conn.call(op, d.nodeid, &body)?;
    let oo = proto::OpenOut::decode(&reply).ok_or(VfsError::Eio)?;
    FUSE_FILES.lock().insert(key, FuseFile { fh: oo.fh, nodeid: d.nodeid });
    Ok(oo.fh)
}

/// `i_fop` for a fuse inode — the data-path ops forwarded to the daemon.
pub struct FuseFileOps;
impl FileOps for FuseFileOps {
    /// `FUSE_READ` — read `buf.len()` bytes at `off` through this open's `fh`
    /// (lazily opened on first read). The reply body IS the raw file data
    /// (Linux `fuse_read_fill`). # C: O(bytes) + rtt
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = fuse_data(file.inode())?;
        let fh = ensure_open(file)?;
        let mut body = Vec::with_capacity(proto::FUSE_READ_IN_SIZE);
        proto::ReadIn { fh, offset: off, size: buf.len() as u32, read_flags: 0, lock_owner: 0, flags: 0 }
            .encode(&mut body);
        let reply = d.conn.call(proto::FUSE_READ, d.nodeid, &body)?;
        let n = reply.len().min(buf.len());
        buf[..n].copy_from_slice(&reply[..n]);
        Ok(n)
    }

    /// `FUSE_READDIR` — stream the directory nodeid's entries into `ctx`,
    /// resuming at the cursor `ctx.pos` (the daemon `off` cookie). OPENDIR (lazy
    /// per-iterate) + READDIR + RELEASEDIR; the daemon returns a packed
    /// `fuse_dirent` stream which is decoded and emitted. # C: O(entries) + rtt
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = fuse_data(inode)?;
        // OPENDIR to obtain a directory fh (released at the end of this call).
        let mut ob = Vec::with_capacity(proto::FUSE_OPEN_IN_SIZE);
        proto::OpenIn { flags: 0, open_flags: 0 }.encode(&mut ob);
        let oreply = d.conn.call(proto::FUSE_OPENDIR, d.nodeid, &ob)?;
        let fh = proto::OpenOut::decode(&oreply).ok_or(VfsError::Eio)?.fh;
        let res = readdir_stream(d.conn.as_ref(), d.nodeid, fh, ctx);
        // RELEASEDIR regardless of the readdir outcome.
        let mut rb = Vec::with_capacity(proto::FUSE_RELEASE_IN_SIZE);
        encode_release(&mut rb, fh, 0);
        let _ = d.conn.call(proto::FUSE_RELEASEDIR, d.nodeid, &rb);
        res
    }

    /// The daemon's `FUSE_READDIR` stream carries its own `.`/`..` (libfuse
    /// convention), and its cookies are daemon-defined, so the VFS must not
    /// prepend synthetic dots or shift the cookie space. # C: O(1)
    fn iterate_emits_dots(&self) -> bool { true }

    /// `FUSE_FLUSH` on `close(2)` (every fd close). Best-effort. # C: O(1) + rtt
    fn on_flush(&self, inode: &Inode) -> KResult<()> {
        if let Ok(d) = fuse_data(inode) {
            let mut b = Vec::with_capacity(proto::FUSE_FLUSH_IN_SIZE);
            encode_flush(&mut b, 0);
            let _ = d.conn.call(proto::FUSE_FLUSH, d.nodeid, &b);
        }
        Ok(())
    }

    /// `FUSE_RELEASE`/`FUSE_RELEASEDIR` at last close — drop the daemon's `fh`
    /// and forget the per-open handle. Runs from `File::Drop`. # C: O(1) + rtt
    fn on_release_file(&self, file: &File) {
        let Some(f) = FUSE_FILES.lock().remove(&file_key(file)) else { return };
        let Ok(d) = fuse_data(file.inode()) else { return };
        let is_dir = file.inode().file_type() == FileType::Directory;
        let op = if is_dir { proto::FUSE_RELEASEDIR } else { proto::FUSE_RELEASE };
        let mut b = Vec::with_capacity(proto::FUSE_RELEASE_IN_SIZE);
        encode_release(&mut b, f.fh, file.flags().bits() & 0o3);
        let _ = d.conn.call(op, f.nodeid, &b);
    }
}

/// Drive one `FUSE_READDIR` at `ctx.pos` and emit every parsed entry through the
/// dir context (advancing its resume cookie to each entry's `off`). Stops when
/// the context buffer fills or the daemon returns an empty stream (EOF). One RTT
/// per call (the caller re-enters `iterate` with the advanced `pos` for more).
/// # C: O(entries)
fn readdir_stream(conn: &super::conn::FuseConn, nodeid: u64, fh: u64, ctx: &mut DirContext) -> KResult<()> {
    const READDIR_BUF: u32 = 4096;
    let mut body = Vec::with_capacity(proto::FUSE_READ_IN_SIZE);
    proto::ReadIn { fh, offset: ctx.pos, size: READDIR_BUF, read_flags: 0, lock_owner: 0, flags: 0 }
        .encode(&mut body);
    let reply = conn.call(proto::FUSE_READDIR, nodeid, &body)?;
    let ents = proto::decode_dirent_stream(&reply).ok_or(VfsError::Eio)?;
    for e in ents {
        let name = fuse_dirent_name(&e.name);
        // Pass the daemon's DT_* through untouched: `DT_UNKNOWN` is a legal,
        // meaningful answer that `readdir(3)` resolves with `stat`. Round-tripping
        // it through `FileType` rewrites it to `DT_REG` — a fabricated type.
        let dt = vfs::DType::from_raw(e.d_type as u8);
        // The daemon's `off` is the resume cookie for the NEXT entry (Linux).
        if !ctx.emit_dt(&name, e.ino, dt, e.off) { break; }
    }
    Ok(())
}

fn fuse_dirent_name(name: &[u8]) -> alloc::string::String {
    vfs::path_from_bytes(name)
}

/// Encode a `struct fuse_release_in` (`fh,flags,release_flags,lock_owner`).
/// # C: O(1)
fn encode_release(out: &mut Vec<u8>, fh: u64, flags: u32) {
    proto::put_u64(out, fh);
    proto::put_u32(out, flags);
    proto::put_u32(out, 0); // release_flags
    proto::put_u64(out, 0); // lock_owner
}

/// Encode a `struct fuse_flush_in` (`fh,unused,padding,lock_owner`). # C: O(1)
fn encode_flush(out: &mut Vec<u8>, fh: u64) {
    proto::put_u64(out, fh);
    proto::put_u32(out, 0); // unused
    proto::put_u32(out, 0); // padding
    proto::put_u64(out, 0); // lock_owner
}

#[cfg(test)]
mod tests {
    use super::fuse_dirent_name;

    #[test]
    fn fuse_dirent_name_preserves_non_utf8_bytes() {
        let raw = b"raw-\xff-entry";
        let name = fuse_dirent_name(raw);
        assert_eq!(vfs::path_into_bytes(&name), raw);
    }
}
