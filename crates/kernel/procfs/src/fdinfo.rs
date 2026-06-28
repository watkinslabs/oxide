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

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// `/proc/{self|<pid>}/fdinfo` directory. Same readdir set as
/// `ProcSelfFdInode` (one entry per live fd); `lookup(<n>)` returns
/// a `ProcFdInfoInode` body inode for that fd.
pub struct ProcFdInfoDirInode {
    /// `None` ⇒ resolve `self` at every call against the running task.
    pub tid_opt: Option<u32>,
}

impl Inode for ProcFdInfoDirInode {
    fn ino(&self) -> Ino { 0x3000_1800 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let fd: i32 = name.parse().map_err(|_| VfsError::Enoent)?;
        // Validate the fd exists for the resolved task now (ENOENT like
        // Linux on a stale fd), but DON'T capture the `Arc<File>`: the
        // resulting inode may be dcache-cached under the literal path
        // `/proc/self/fdinfo/<n>` and reused by a *different* process, so
        // a frozen File would serve the first opener's open-file (and its
        // pidfd `Pid:`) to everyone. Store `(tid_opt, fd)` and re-resolve
        // live in `body()` — matches Linux seq_file fdinfo (reads the live
        // `files_struct` at read() time).
        sched::proclink::proc_fd_file(self.tid_opt, fd).ok_or(VfsError::Enoent)?;
        Ok(Arc::new(ProcFdInfoInode { tid_opt: self.tid_opt, fd }) as InodeRef)
    }
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        let task = match self.tid_opt {
            None    => sched::live::current().and_then(|c|
                            sched::live::registry::lookup(c.tid)),
            Some(t) => sched::live::registry::lookup(t),
        };
        let task = match task { Some(t) => t, None => return Ok(off) };
        // SAFETY: sole reader; single-mutator per `13§5`.
        let fdt = match unsafe { task.fd_table_ref() } {
            Some(t) => t.clone(), None => return Ok(off),
        };
        let fds = fdt.live_fds();
        let mut idx = off as usize;
        while idx < fds.len() {
            let next = idx as u64 + 1;
            let fd = fds[idx];
            let mut buf = [0u8; 11]; let mut n = 0; let mut t = fd as u32;
            if t == 0 { buf[0] = b'0'; n = 1; }
            else { while t > 0 { buf[n] = b'0' + (t % 10) as u8; t /= 10; n += 1; } }
            buf[..n].reverse();
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("0");
            let ino = self.lookup(s).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, s, FileType::Regular) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// Body inode for /proc/<pid>/fdinfo/<n>.
///
/// Holds `(tid_opt, fd)`, NOT a captured `Arc<File>`: the File is
/// re-resolved against the live task on every `read()` (Linux seq_file
/// fdinfo reads the live `files_struct` at read time). Capturing the
/// File froze the first opener's open-file into a dcache-cached
/// `/proc/self/fdinfo/<n>` inode, which a later process then read back
/// — yielding a stale pidfd `Pid:` and a synthetic systemd ESRCH.
pub struct ProcFdInfoInode {
    /// `None` ⇒ resolve `self` (live `current()`) at every read.
    pub tid_opt: Option<u32>,
    pub fd: i32,
}

impl ProcFdInfoInode {
    fn body(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(64);
        // Re-resolve live: a cached `self` inode reflects the reading
        // task, not the first opener. Closed fd / gone task ⇒ empty body
        // (Linux revalidates the dentry away; an empty read is benign).
        let file = match sched::proclink::proc_fd_file(self.tid_opt, self.fd) {
            Some(f) => f,
            None    => return out,
        };
        let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut out), format_args!(
            "pos:\t{}\n\
             flags:\t0{:o}\n\
             mnt_id:\t0\n\
             ino:\t{}\n",
            file.pos(),
            file.flags().bits(),
            file.inode().ino(),
        ));
        // Linux appends each fd type's own `show_fdinfo` lines after the
        // generic header — pidfd emits `Pid:`/`NSpid:` here (systemd reads it).
        file.inode().fdinfo_extra(&mut out);
        out
    }
}

impl Inode for ProcFdInfoInode {
    fn ino(&self) -> Ino { 0x3000_1820 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
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
        None => Some(Arc::new(ProcFdInfoDirInode { tid_opt }) as InodeRef),
        Some(n_str) => {
            let fd: i32 = n_str.parse().ok()?;
            // Validate existence only; re-resolve the File live in body()
            // (see ProcFdInfoInode — never capture across processes).
            sched::proclink::proc_fd_file(tid_opt, fd)?;
            Some(Arc::new(ProcFdInfoInode { tid_opt, fd }) as InodeRef)
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
