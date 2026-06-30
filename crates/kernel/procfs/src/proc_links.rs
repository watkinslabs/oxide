// procfs symlink inodes: /proc/self/{exe,cwd,root} + per-fd
// symlinks. Each delegates to `sched::proclink::resolve_proc_link`
// at readlink time so the target reflects live task state.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{default_file_ops, mk_mode, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, LinkTarget, VfsError, VfsPath};

/// `i_private` for a procfs magic symlink (KEYSTONE struct-`Inode`). Either a
/// fixed `target` (per-fd link), or a `/proc` path re-resolved live at
/// `readlink` time (`exe`/`cwd`/`root`) with a `fallback` when the tid is gone.
pub struct ProcLinkData {
    /// `Some(path)` ⇒ resolve `sched::proclink::resolve_proc_link(path)` live;
    /// `None` ⇒ the link is the fixed `target`.
    pub resolve: Option<String>,
    pub target: Vec<u8>,
    pub fallback: Vec<u8>,
    /// `Some((tid_opt, fd))` ⇒ this is a `/proc/<pid>/fd/<n>` MAGIC link: a walk
    /// THROUGH it does `nd_jump_link` to the open file's `(mnt,dentry,inode)`,
    /// re-resolved live at follow time (Linux `proc_fd_link` `get_link`).
    /// `readlink(2)` still returns the `target` TEXT. `None` for `exe`/`cwd`/
    /// `root` (resolved as ordinary path symlinks).
    pub jump_fd: Option<(Option<u32>, i32)>,
}

/// `i_op` for a procfs symlink — `readlink` reads the link TEXT from
/// `ProcLinkData`; `get_link` returns a `Jump` for fd magic links (resolved in
/// the walk via `nd_jump_link`) or falls through to the `Path` text otherwise.
struct ProcLinkOps;
impl InodeOps for ProcLinkOps {
    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        let d = inode.private::<ProcLinkData>().ok_or(VfsError::Einval)?;
        match &d.resolve {
            None => Ok(d.target.clone()),
            Some(p) => Ok(sched::proclink::resolve_proc_link(p).unwrap_or_else(|| d.fallback.clone())),
        }
    }

    /// `/proc/<pid>/fd/<n>`: a walk through it JUMPS to the open file's resolved
    /// `(mnt,dentry,inode)` (Linux `nd_jump_link`), re-fetched live so the jump
    /// tracks the current fd table. If the fd is gone, fall through to the
    /// `Path` text (`readlink`) — a stale but safe string. All non-fd links
    /// (`exe`/`cwd`/`root`) take the default `Path` body. # C: O(1)
    fn get_link(&self, inode: &Inode) -> KResult<LinkTarget> {
        if let Some(d) = inode.private::<ProcLinkData>() {
            if let Some((tid_opt, fd)) = d.jump_fd {
                if let Some(f) = sched::proclink::proc_fd_file(tid_opt, fd) {
                    return Ok(LinkTarget::Jump(VfsPath {
                        mnt_id: f.mnt_id(),
                        dentry: f.dentry().clone(),
                        inode:  f.inode().clone(),
                        last_component: None,
                    }));
                }
            }
        }
        Ok(LinkTarget::Path(self.readlink(inode)?))
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
        jump_fd: None,
    })
}

/// `/proc/self/cwd` symlink. # C: O(1)
pub fn make_proc_self_cwd() -> InodeRef {
    make_proc_link(0x3000_1701, 0, ProcLinkData {
        resolve: Some(String::from("/proc/self/cwd")), target: Vec::new(), fallback: b"/".to_vec(),
        jump_fd: None,
    })
}

/// `/proc/self/root` symlink. # C: O(1)
pub fn make_proc_self_root() -> InodeRef {
    make_proc_link(0x3000_1702, 0, ProcLinkData {
        resolve: Some(String::from("/proc/self/root")), target: Vec::new(), fallback: b"/".to_vec(),
        jump_fd: None,
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
    let tag: u64 = match leaf { "exe" => 0x18, "cwd" => 0x19, _ => 0x1A };
    let mut p = String::new();
    let _ = write!(p, "/proc/{}/{}", tid, leaf);
    // root is always "/" even for a dead tid; exe/cwd fall back to "/"
    // (resolve_proc_link returns None only when the tid is gone).
    make_proc_link(crate::live::pid_ino(tag, tid), 0, ProcLinkData {
        resolve: Some(p), target: Vec::new(), fallback: b"/".to_vec(),
        jump_fd: None,
    })
}

/// Build a per-fd MAGIC symlink inode for `/proc/<tid_opt>/fd/<fd>`. `readlink`
/// returns the open File's `path` TEXT (captured here for the text view); a
/// walk THROUGH it does `nd_jump_link` to the file's live `(mnt,dentry,inode)`
/// via `jump_fd` (re-resolved at follow time — see `ProcLinkOps::get_link`).
/// `tid_opt` is `None` for `/proc/self/fd` (the caller's own table). `ino` is a
/// stable distinguisher so getdents reflects the fd. # C: O(target_len)
pub fn fd_link_for_path(path: &[u8], tid_opt: Option<u32>, fd: i32) -> InodeRef {
    make_proc_link(crate::live::pid_ino(0x16, fd as u32), path.len() as u64, ProcLinkData {
        resolve: None, target: path.to_vec(), fallback: Vec::new(),
        jump_fd: Some((tid_opt, fd)),
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
            Some(fd_link_for_path(&file.dentry().absolute_path(), tid_opt, fd))
        }
    }
}
