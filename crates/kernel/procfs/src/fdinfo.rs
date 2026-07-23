// /proc/<pid>/fdinfo/<n> — per-fd open file description metadata.
// Linux Documentation/filesystems/proc.rst format:
//   pos:    <bytes>
//   flags:  <octal>
//   mnt_id: <mount id>
//   ino:    <inode>
//
// systemd / ss / lsof read these to discover seek positions and the
// underlying inode without walking /proc/<pid>/fd/<n> symlinks. v1
// emits the four common lines from sched::proclink::proc_fd_file +
// File::{pos,flags,inode}().

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{default_inode_ops, mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

const FDINFO_DIR_MODE: u16 = 0o555;
const FDINFO_FILE_MODE: u16 = 0o444;

/// `i_private` for the `/proc/{self|<pid>}/fdinfo` directory. Same readdir
/// set as `/proc/<pid>/fd` (one entry per live fd); `lookup(<n>)` returns a
/// per-fd `fdinfo` body inode. `None` ⇒ resolve `self` at every call.
pub struct ProcFdInfoDirInode {
    pub tid_opt: Option<u32>,
}

/// `i_op` for the fdinfo directory — `lookup(<n>)` validates the fd then
/// synthesises a body inode keyed on `(tid_opt, fd)`.
struct FdInfoDirOps;
impl InodeOps for FdInfoDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ProcFdInfoDirInode>().ok_or(VfsError::Einval)?;
        let fd: i32 = name.parse().map_err(|_| VfsError::Enoent)?;
        // Validate the fd exists for the resolved task now (ENOENT like
        // Linux on a stale fd), but DON'T capture the `Arc<File>`: the
        // resulting inode may be dcache-cached under the literal path
        // `/proc/self/fdinfo/<n>` and reused by a *different* process, so
        // a frozen File would serve the first opener's open-file (and its
        // pidfd `Pid:`) to everyone. Store `(tid_opt, fd)` and re-resolve
        // live in the body — matches Linux seq_file fdinfo.
        sched::proclink::proc_fd_file(d.tid_opt, fd).ok_or(VfsError::Enoent)?;
        Ok(make_fdinfo_file(d.tid_opt, fd))
    }
}

/// `i_fop` for the fdinfo directory — readdir enumerates the live fds.
struct FdInfoDirFileOps;
impl FileOps for FdInfoDirFileOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<ProcFdInfoDirInode>().ok_or(VfsError::Einval)?;
        let task = match d.tid_opt {
            None    => sched::live::current().and_then(|c|
                            sched::live::registry::lookup(c.tid)),
            Some(t) => sched::live::registry::lookup(t),
        };
        let task = match task { Some(t) => t, None => return Ok(()) };
        // `task` may be a foreign task (arbitrary tid): clone_fd_table pins
        // against a concurrent exit-time replace_fd_table(None) on another CPU.
        let fdt = match task.clone_fd_table() {
            Some(t) => t, None => return Ok(()),
        };
        let fds = fdt.live_fds();
        let mut idx = ctx.pos as usize;
        while idx < fds.len() {
            let next = idx as u64 + 1;
            let fd = fds[idx];
            let mut buf = [0u8; 11]; let mut n = 0; let mut t = fd as u32;
            if t == 0 { buf[0] = b'0'; n = 1; }
            else { while t > 0 { buf[n] = b'0' + (t % 10) as u8; t /= 10; n += 1; } }
            buf[..n].reverse();
            let s = crate::util::decimal_str(&buf, n);
            let ino = inode.lookup(s).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(s, ino, FileType::Regular, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}

/// `/proc/{self|<pid>}/fdinfo` directory inode. # C: O(1)
pub fn make_fdinfo_dir(tid_opt: Option<u32>) -> InodeRef {
    InodeBuilder::new(crate::ids::FDINFO_ROOT, mk_mode(FileType::Directory, FDINFO_DIR_MODE), Arc::new(FdInfoDirOps), Arc::new(FdInfoDirFileOps))
        .private(Arc::new(ProcFdInfoDirInode { tid_opt }))
        .build()
}

/// `i_private` for a `/proc/<pid>/fdinfo/<n>` body inode.
///
/// Holds `(tid_opt, fd)`, NOT a captured `Arc<File>`: the File is re-resolved
/// against the live task on every read (Linux seq_file fdinfo reads the live
/// `files_struct` at read time). Capturing the File froze the first opener's
/// open-file into a dcache-cached `/proc/self/fdinfo/<n>` inode, which a later
/// process then read back — yielding a stale pidfd `Pid:` and a synthetic
/// systemd ESRCH.
pub struct ProcFdInfoInode {
    pub tid_opt: Option<u32>,
    pub fd: i32,
}

fn fdinfo_body(d: &ProcFdInfoInode) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(64);
    // Re-resolve live: a cached `self` inode reflects the reading task, not
    // the first opener. Closed fd / gone task ⇒ empty body (Linux revalidates
    // the dentry away; an empty read is benign).
    let file = match sched::proclink::proc_fd_file(d.tid_opt, d.fd) {
        Some(f) => f,
        None    => return out,
    };
    let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut out), format_args!(
        "pos:\t{}\n\
         flags:\t0{:o}\n\
         mnt_id:\t{}\n\
         ino:\t{}\n",
        file.pos(),
        file.flags().bits(),
        file.mnt_id(),
        file.inode().ino(),
    ));
    // Linux appends each fd type's own `show_fdinfo` lines after the generic
    // header — pidfd emits `Pid:`/`NSpid:` here (systemd reads it).
    file.inode().fdinfo_extra(&mut out);
    out
}

/// `i_fop` for a `/proc/<pid>/fdinfo/<n>` body — renders the four common lines
/// (plus fd-type extras) at read time off the live open-file.
struct FdInfoFileOps;
impl FileOps for FdInfoFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<ProcFdInfoInode>().ok_or(VfsError::Einval)?;
        Ok(crate::dyn_file::read_at(&fdinfo_body(d), off, buf))
    }
    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// `/proc/<pid>/fdinfo/<n>` body inode. # C: O(1)
pub fn make_fdinfo_file(tid_opt: Option<u32>, fd: i32) -> InodeRef {
    InodeBuilder::new(crate::ids::FDINFO_FILE, mk_mode(FileType::Regular, FDINFO_FILE_MODE), default_inode_ops(), Arc::new(FdInfoFileOps))
        .private(Arc::new(ProcFdInfoInode { tid_opt, fd }))
        .build()
}

/// Path-keyed lookup for `/proc/{self|<pid>}/fdinfo[/<n>]`. Mirrors
/// `proc_links::lookup_fd_path` for /proc/<pid>/fd.
/// # C: O(path_len)
pub fn lookup_fdinfo_path(path: &str) -> Option<InodeRef> {
    let rest = path.strip_prefix("/proc/")?;
    let mut it = rest.splitn(3, '/');
    let who = it.next()?;
    if it.next()? != "fdinfo" { return None; }
    let tid_opt: Option<u32> = if who == "self" { None }
        else { Some(who.parse::<u32>().ok()?) };
    match it.next() {
        None => Some(make_fdinfo_dir(tid_opt)),
        Some(n_str) => {
            let fd: i32 = n_str.parse().ok()?;
            // Validate existence only; re-resolve the File live in the body
            // (see ProcFdInfoInode — never capture across processes).
            sched::proclink::proc_fd_file(tid_opt, fd)?;
            Some(make_fdinfo_file(tid_opt, fd))
        }
    }
}

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}
