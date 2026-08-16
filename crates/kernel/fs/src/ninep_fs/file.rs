// `i_fop` for a 9P inode — the data path, forwarded as `.L` messages.
//
// Every open file description holds its OWN server handle. A shared one would
// mean two descriptions with different open modes addressing one server handle,
// and a read-only description could then write.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use ninep::client::FidRef;
use ninep::uapi::dotl;
use sync::{Spinlock, Tty as NpClass};
use vfs::{DirContext, File, FileOps, FileType, Inode, KResult, VfsError};
use vfs::dirent::DType;

use super::attr::open_flags_to_dotl;
use super::fs::data;

/// Bytes one directory read asks the server for. Large enough that an ordinary
/// directory finishes in one message and small enough to stay well inside any
/// negotiated frame.
pub const READDIR_CHUNK: usize = 8192;

/// The per-open handle plus the directory cursor that belongs to it.
struct OpenFile {
    fid: FidRef,
    /// Server cookie for the next directory entry. Kept per DESCRIPTION rather
    /// than per inode: two processes reading one directory each have their own
    /// position, and sharing it makes each of them skip the other's entries.
    dir_cookie: u64,
    /// Position the cursor was left at, so a `seek` back to the start is
    /// detected and the cookie reset instead of resuming mid-directory.
    dir_pos: u64,
}

/// Open `File` identity → its server handle. An entry exists from the open
/// until the last close. # C: O(1)
static OPEN_FILES: Spinlock<BTreeMap<usize, OpenFile>, NpClass> = Spinlock::new(BTreeMap::new());

fn key(file: &File) -> usize { file as *const File as usize }

/// Ensure this description holds an open server handle, performing the open if
/// nothing did it yet, and return the handle.
///
/// The handle is a CLONE of the inode's: the open transforms the handle it is
/// given, and transforming the inode's would leave every later lookup through
/// that inode addressing an open file rather than a directory entry.
/// # C: O(1), plus two RPCs on first use
fn ensure_open(file: &File) -> KResult<FidRef> {
    if let Some(f) = OPEN_FILES.lock().get(&key(file)) { return Ok(f.fid.clone()); }
    let inode = file.inode();
    let d = data(inode)?;
    let handle = d.mount.client.clone_fid(&d.fid).map_err(VfsError::from)?;
    let mut flags = open_flags_to_dotl(file.flags().bits());
    // The class comes from the inode, not from what the caller asked for: a
    // directory opened without the directory flag makes some servers refuse.
    if inode.file_type() == FileType::Directory { flags |= dotl::DIRECTORY; }
    // Creation and truncation already happened during path resolution;
    // repeating them here would truncate a file the caller only opened.
    flags &= !(dotl::CREATE | dotl::EXCL | dotl::TRUNC);
    d.mount.client.lopen(&handle, flags).map_err(VfsError::from)?;
    let mut g = OPEN_FILES.lock();
    let entry = g.entry(key(file)).or_insert(OpenFile { fid: handle, dir_cookie: 0, dir_pos: 0 });
    Ok(entry.fid.clone())
}

/// `i_fop` for every 9P inode.
pub struct NinepFileOps;

impl FileOps for NinepFileOps {
    /// `Tread`, split across as many messages as the frame size needs.
    /// # C: RPC per frame
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = data(file.inode())?;
        let fid = ensure_open(file)?;
        d.mount.client.read(&fid, off, buf).map_err(VfsError::from)
    }

    /// `Twrite`, split the same way. # C: RPC per frame
    fn write_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        let d = data(file.inode())?;
        let fid = ensure_open(file)?;
        let n = d.mount.client.write(&fid, off, buf).map_err(VfsError::from)?;
        // The server now holds more than the cached size says; a stat that did
        // not go to the server would otherwise report the file as too short.
        let end = off.saturating_add(n as u64);
        if end > file.inode().size() { file.inode().set_size(end); }
        Ok(n)
    }

    /// A 9P server has no non-blocking mode; a read that would block on the
    /// far side blocks here too, which is what a network filesystem does.
    /// # C: RPC
    fn read_nonblock_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_file(file, off, buf)
    }

    /// # C: RPC
    fn write_nonblock_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write_file(file, off, buf)
    }

    /// `Treaddir`, walking the packed entries the server returned.
    ///
    /// The cursor is the server's OPAQUE cookie, not a byte offset and not an
    /// entry index: it is carried per description and reset only when the
    /// caller seeks back to the start. Deriving it from `ctx.pos` arithmetic
    /// would work against one server and skip or repeat entries on another.
    /// # C: RPC per chunk
    fn iterate_file(&self, file: &File, ctx: &mut DirContext) -> KResult<()> {
        let d = data(file.inode())?;
        let fid = ensure_open(file)?;
        let mut cookie = {
            let mut g = OPEN_FILES.lock();
            let e = g.get_mut(&key(file)).ok_or(VfsError::Ebadf)?;
            // A rewind is the one position change that can be honoured: any
            // other seek names a byte offset the server's cookies do not
            // correspond to.
            if ctx.pos == 0 { e.dir_cookie = 0; }
            e.dir_pos = ctx.pos;
            e.dir_cookie
        };
        loop {
            let bytes = d.mount.client.readdir(&fid, cookie, READDIR_CHUNK)
                .map_err(VfsError::from)?;
            if bytes.is_empty() { break; }
            let mut advanced = false;
            for ent in ninep::codec::DirEntries::new(&bytes) {
                let ent = ent.map_err(|_| VfsError::Eproto)?;
                let Ok(name) = core::str::from_utf8(ent.name) else { continue };
                let next = ctx.pos.saturating_add(1);
                if !ctx.emit_dt(name, ent.qid.path, DType::from_raw(ent.dtype), next) {
                    // The caller's buffer is full: remember where the SERVER is
                    // so the next call resumes there. The entry just refused is
                    // re-emitted, which is correct — it was never delivered.
                    let mut g = OPEN_FILES.lock();
                    if let Some(e) = g.get_mut(&key(file)) { e.dir_cookie = cookie; }
                    return Ok(());
                }
                cookie = ent.offset;
                advanced = true;
            }
            let mut g = OPEN_FILES.lock();
            if let Some(e) = g.get_mut(&key(file)) { e.dir_cookie = cookie; }
            drop(g);
            // A batch that emitted nothing and moved no cookie would loop
            // forever against a server that keeps answering with empty chunks.
            if !advanced { break; }
        }
        Ok(())
    }

    /// The server supplies `.` and `..` itself when it has them; this backend
    /// does not synthesise them. # C: O(1)
    fn iterate_emits_dots(&self) -> bool { false }

    /// # C: O(1)
    fn can_poll(&self, _file: &File) -> bool { false }
}

/// Release this description's server handle. The handle is clunked when the
/// last reference to it goes; the entry must be removed on close or every
/// opened file leaks a server handle for the life of the mount. # C: O(log N)
pub fn release(file: &File) { OPEN_FILES.lock().remove(&key(file)); }

/// `Tfsync` on this description's handle. `datasync` asks the server to skip
/// the metadata flush. # C: RPC
pub fn fsync(file: &File, datasync: bool) -> KResult<()> {
    let d = data(file.inode())?;
    let fid = ensure_open(file)?;
    d.mount.client.fsync(&fid, datasync).map_err(VfsError::from)
}

/// Open handles this mount is holding, for tests and diagnostics. # C: O(1)
pub fn open_handle_count() -> usize { OPEN_FILES.lock().len() }

/// An inode's own handle, for a caller that needs to act without a description.
/// # C: O(1)
pub fn inode_fid(inode: &Inode) -> KResult<FidRef> { Ok(data(inode)?.fid.clone()) }

/// Directory entries decoded from one readdir payload, for tests. # C: O(bytes)
pub fn decode_entries(bytes: &[u8]) -> KResult<Vec<(alloc::string::String, u64, u8)>> {
    let mut out = Vec::new();
    for ent in ninep::codec::DirEntries::new(bytes) {
        let ent = ent.map_err(|_| VfsError::Eproto)?;
        let name = core::str::from_utf8(ent.name).map_err(|_| VfsError::Eproto)?;
        out.push((alloc::string::String::from(name), ent.offset, ent.dtype));
    }
    Ok(out)
}
