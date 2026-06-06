// procfs symlink inodes: /proc/self/{exe,cwd,root} + per-fd
// symlinks. Each delegates to `sched::proclink::resolve_proc_link`
// at readlink time so the target reflects live task state.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Per-fd symlink under `/proc/self/fd/<n>` (and per-pid analogue).
/// `target` is the path bytes returned by readlink(2); `ino` is a
/// stable distinguisher so getdents reflects the fd.
pub struct ProcFdLinkInode {
    pub target: Vec<u8>,
    pub ino:    Ino,
}

impl Inode for ProcFdLinkInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.target.len() as u64 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> { Ok(self.target.clone()) }
}

/// `/proc/self/exe` symlink — resolves to the current task's
/// `mm.exe_path` (the path the kernel saw at execve).
pub struct ProcSelfExeInode;

impl Inode for ProcSelfExeInode {
    fn ino(&self) -> Ino { 0x3000_1700 }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> {
        Ok(sched::proclink::resolve_proc_link("/proc/self/exe")
            .unwrap_or_else(|| b"/init".to_vec()))
    }
}

/// `/proc/self/cwd` symlink.
pub struct ProcSelfCwdInode;

impl Inode for ProcSelfCwdInode {
    fn ino(&self) -> Ino { 0x3000_1701 }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> {
        Ok(sched::proclink::resolve_proc_link("/proc/self/cwd")
            .unwrap_or_else(|| b"/".to_vec()))
    }
}

/// `/proc/self/root` symlink.
pub struct ProcSelfRootInode;

impl Inode for ProcSelfRootInode {
    fn ino(&self) -> Ino { 0x3000_1702 }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> {
        Ok(sched::proclink::resolve_proc_link("/proc/self/root")
            .unwrap_or_else(|| b"/".to_vec()))
    }
}

/// Per-pid `/proc/<tid>/{exe,cwd,root}` magic symlink. Distinct from
/// the `/proc/self/*` inodes above (which hardcode "self"): resolves
/// for an explicit kernel tid so `/proc/1/root` etc. follow to the
/// real target inode. MUST be a Symlink, not a regular file —
/// systemd's `running_in_chroot()` does `inode_same("/proc/1/root",
/// "/")`, which `openat(O_PATH)`-follows the link and compares the
/// target inode against `/`. A regular-file placeholder resolves to a
/// procfs inode (never matching `/`), so systemd wrongly concludes it
/// is chrooted and freezes PID1.
pub struct ProcPidLinkInode { pub tid: u32, pub leaf: &'static str }

impl Inode for ProcPidLinkInode {
    fn ino(&self) -> Ino {
        let base: Ino = match self.leaf {
            "exe" => 0x3000_1800, "cwd" => 0x3000_1900, _ => 0x3000_1A00,
        };
        base | self.tid as Ino
    }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> {
        use core::fmt::Write as _;
        let mut p = alloc::string::String::new();
        // `# C: O(N_leaf)` — build "/proc/<tid>/<leaf>" then resolve.
        let _ = write!(p, "/proc/{}/{}", self.tid, self.leaf);
        // root is always "/" even for a dead tid; exe/cwd fall back to
        // "/" (resolve_proc_link returns None only when the tid is gone).
        Ok(sched::proclink::resolve_proc_link(&p).unwrap_or_else(|| b"/".to_vec()))
    }
}

/// Build a per-fd symlink inode targeting the open File's path.
/// Used by `ProcSelfFdInode::lookup`.
/// # C: O(target_len)
pub fn fd_link_for_path(path: &[u8], fd: i32) -> InodeRef {
    Arc::new(ProcFdLinkInode {
        target: path.to_vec(),
        ino:    0x3000_1600 | (fd as Ino),
    })
}

/// Path-keyed lookup for `/proc/{self|<pid>}/fd` and its `<N>` children.
/// `/proc/self/fd` itself is statically registered as a `ProcSelfFdInode`
/// in `static_files::init`; per-pid `/proc/<pid>/fd` and the individual
/// fd-link inodes aren't path-keyed in devfs, so synthesise them here so
/// stat()/readlink() resolve uniformly with open(2) which routes through
/// `dup_fd_target`.
/// # C: O(path_len)
pub fn lookup_fd_path(path: &str) -> Option<InodeRef> {
    let rest = path.strip_prefix("/proc/")?;
    let mut it = rest.splitn(3, '/');
    let who = it.next()?;
    if it.next()? != "fd" { return None; }
    let tid_opt: Option<u32> = if who == "self" { None }
        else { Some(who.parse::<u32>().ok()?) };
    match it.next() {
        None => Some(Arc::new(crate::ProcSelfFdInode) as InodeRef),
        Some(n_str) => {
            let fd: i32 = n_str.parse().ok()?;
            let file = sched::proclink::proc_fd_file(tid_opt, fd)?;
            Some(fd_link_for_path(&file.dentry().absolute_path(), fd))
        }
    }
}
