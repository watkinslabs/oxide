// procfs symlink inodes: /proc/self/{exe,cwd,root} + per-fd
// symlinks. Each delegates to `sched::proclink::resolve_proc_link`
// at readlink time so the target reflects live task state.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{default_file_ops, mk_mode, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

/// `i_private` for a procfs magic symlink (KEYSTONE struct-`Inode`). Either a
/// fixed `target` (per-fd link), or a `/proc` path re-resolved live at
/// `readlink` time (`exe`/`cwd`/`root`) with a `fallback` when the tid is gone.
pub struct ProcLinkData {
    /// `Some(path)` ⇒ resolve `sched::proclink::resolve_proc_link(path)` live;
    /// `None` ⇒ the link is the fixed `target`.
    pub resolve: Option<String>,
    pub target: Vec<u8>,
    pub fallback: Vec<u8>,
}

/// `i_op` for a procfs symlink — `readlink` reads `ProcLinkData`.
struct ProcLinkOps;
impl InodeOps for ProcLinkOps {
    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        let d = inode.private::<ProcLinkData>().ok_or(VfsError::Einval)?;
        match &d.resolve {
            None => Ok(d.target.clone()),
            Some(p) => Ok(sched::proclink::resolve_proc_link(p).unwrap_or_else(|| d.fallback.clone())),
        }
    }
}

/// Build a procfs symlink inode with the given ino, reported `size`, and
/// `ProcLinkData`. `S_IFLNK | 0o777` (Linux magic-link mode). # C: O(1)
fn make_proc_link(ino: Ino, size: u64, data: ProcLinkData) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777), Arc::new(ProcLinkOps), default_file_ops())
        .size(size)
        .private(Arc::new(data))
        .build()
}

/// `/proc/self/exe` symlink — resolves to the current task's `mm.exe_path`
/// (the path the kernel saw at execve). # C: O(1)
pub fn make_proc_self_exe() -> InodeRef {
    make_proc_link(0x3000_1700, 0, ProcLinkData {
        resolve: Some(String::from("/proc/self/exe")), target: Vec::new(), fallback: b"/init".to_vec(),
    })
}

/// `/proc/self/cwd` symlink. # C: O(1)
pub fn make_proc_self_cwd() -> InodeRef {
    make_proc_link(0x3000_1701, 0, ProcLinkData {
        resolve: Some(String::from("/proc/self/cwd")), target: Vec::new(), fallback: b"/".to_vec(),
    })
}

/// `/proc/self/root` symlink. # C: O(1)
pub fn make_proc_self_root() -> InodeRef {
    make_proc_link(0x3000_1702, 0, ProcLinkData {
        resolve: Some(String::from("/proc/self/root")), target: Vec::new(), fallback: b"/".to_vec(),
    })
}

/// Per-pid `/proc/<tid>/{exe,cwd,root}` magic symlink. Distinct from the
/// `/proc/self/*` constructors above (which hardcode "self"): resolves for an
/// explicit kernel tid so `/proc/1/root` etc. follow to the real target inode.
/// MUST be a Symlink, not a regular file — systemd's `running_in_chroot()`
/// does `inode_same("/proc/1/root", "/")`, which `openat(O_PATH)`-follows the
/// link and compares the target inode against `/`. A regular-file placeholder
/// resolves to a procfs inode (never matching `/`), so systemd wrongly
/// concludes it is chrooted and freezes PID1. # C: O(1)
pub fn make_proc_pid_link(tid: u32, leaf: &'static str) -> InodeRef {
    use core::fmt::Write as _;
    let base: Ino = match leaf { "exe" => 0x3000_1800, "cwd" => 0x3000_1900, _ => 0x3000_1A00 };
    let mut p = String::new();
    let _ = write!(p, "/proc/{}/{}", tid, leaf);
    // root is always "/" even for a dead tid; exe/cwd fall back to "/"
    // (resolve_proc_link returns None only when the tid is gone).
    make_proc_link(base | tid as Ino, 0, ProcLinkData {
        resolve: Some(p), target: Vec::new(), fallback: b"/".to_vec(),
    })
}

/// Build a per-fd symlink inode targeting the open File's path.
/// Used by `ProcSelfFdInode::lookup`. `ino` is a stable distinguisher so
/// getdents reflects the fd. # C: O(target_len)
pub fn fd_link_for_path(path: &[u8], fd: i32) -> InodeRef {
    make_proc_link(0x3000_1600 | (fd as Ino), path.len() as u64, ProcLinkData {
        resolve: None, target: path.to_vec(), fallback: Vec::new(),
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
        None => Some(crate::live::make_proc_self_fd()),
        Some(n_str) => {
            let fd: i32 = n_str.parse().ok()?;
            let file = sched::proclink::proc_fd_file(tid_opt, fd)?;
            Some(fd_link_for_path(&file.dentry().absolute_path(), fd))
        }
    }
}
