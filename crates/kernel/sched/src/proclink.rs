// `/proc/<pid>/{exe,cwd,root,fd/<n>,ns/<type>}` symlink resolver.
// Split out of `syscall_glue_fs.rs` to keep that file under the
// 1000-line cap. Used by `sys_readlink` for proc-link paths.


extern crate alloc;
use alloc::vec::Vec;
use vfs::{KResult, VfsError};

/// Resolve a `/proc/<pid>/<leaf>` symlink to its readlink target bytes.
/// # C: O(N_path)
pub fn resolve_proc_link(path: &str) -> KResult<Vec<u8>> {
    let rest = path.strip_prefix("/proc/").ok_or(VfsError::Enoent)?;
    let mut parts = rest.splitn(2, '/');
    let head = parts.next().ok_or(VfsError::Enoent)?;
    let leaf = parts.next().ok_or(VfsError::Enoent)?;
    let tid_opt: Option<u32> = if head == "self" { None } else { head.parse().ok() };
    if head != "self" && tid_opt.is_none() { return Err(VfsError::Enoent); }
    if let Some(tid) = tid_opt {
        if crate::live::registry::lookup(tid).is_none() { return Err(VfsError::Enoent); }
    }
    match leaf {
        "exe"  => task_exe_path(tid_opt),
        "cwd"  => task_cwd_path(tid_opt),
        "root" => task_root_path(tid_opt),
        l if l.starts_with("fd/") => task_fd_path(tid_opt, &l[3..]),
        l if l.starts_with("ns/") => task_ns_link(tid_opt, &l[3..]),
        _      => Err(VfsError::Enoent),
    }
}

fn task_for_proc_link(tid_opt: Option<u32>) -> KResult<alloc::sync::Arc<crate::Task>> {
    match tid_opt {
        Some(tid) => crate::live::registry::lookup(tid).ok_or(VfsError::Enoent),
        None      => crate::live::current()
            .and_then(|c| crate::live::registry::lookup(c.tid))
            .ok_or(VfsError::Enoent),
    }
}

fn task_exe_path(tid_opt: Option<u32>) -> KResult<Vec<u8>> {
    let task = match tid_opt {
        Some(tid) => crate::live::registry::lookup(tid),
        None      => crate::live::current().and_then(|c| crate::live::registry::lookup(c.tid)),
    };
    if let Some(t) = task {
        // Linux: /proc/<pid>/exe is rooted on mm_struct::exe_file
        // — the dentry the user named at execve, shared across all
        // CLONE_VM threads. Prefer the mm slot over the per-task
        // mirror so hardlinks resolve to the invoked path.
        // SAFETY: mm slot single-mutator per `13§5`; we hold a
        // current-task snapshot.
        if let Some(mm) = unsafe { t.mm_ref() } {
            if let Some(s) = mm.exe_path() {
                if !s.is_empty() { return Ok(s.into_bytes()); }
            }
        }
        // SAFETY: exe_path single-mutator per `13§5`; snapshot.
        if let Some(s) = unsafe { (*t.exe_path.get()).clone() } {
            if !s.is_empty() { return Ok(s.into_bytes()); }
        }
    }
    Err(VfsError::Enoent)
}

fn task_cwd_path(tid_opt: Option<u32>) -> KResult<Vec<u8>> {
    let task = task_for_proc_link(tid_opt)?;
    // SAFETY: cwd slot single-mutator per `13§5`.
    let s = unsafe { (*task.cwd.get()).clone() };
    if !s.is_empty() { Ok(s.into_bytes()) } else { Err(VfsError::Enoent) }
}

fn task_root_path(tid_opt: Option<u32>) -> KResult<Vec<u8>> {
    let task = task_for_proc_link(tid_opt)?;
    // SAFETY: task.root single-mutator per `13§5`.
    let s = unsafe { (*task.root.get()).clone() };
    if !s.is_empty() { Ok(s.into_bytes()) } else { Err(VfsError::Enoent) }
}

fn task_ns_link(tid_opt: Option<u32>, leaf: &str) -> KResult<Vec<u8>> {
    use core::sync::atomic::Ordering;
    let task = task_for_proc_link(tid_opt)?;
    let id = match leaf {
        "ipc"    => task.ipc_ns.load(Ordering::Acquire),
        "uts"    => task.uts_ns.load(Ordering::Acquire),
        "pid" | "pid_for_children" => task.pid_ns.load(Ordering::Acquire),
        "net"    => task.net_ns.load(Ordering::Acquire),
        "user"   => task.user_ns.load(Ordering::Acquire),
        "cgroup" => task.cgroup_ns.load(Ordering::Acquire),
        "mnt"    => task.mount_ns.load(Ordering::Acquire),
        _ => return Err(VfsError::Enoent),
    };
    let kind = if leaf == "pid_for_children" { "pid" } else { leaf };
    let mut out = Vec::with_capacity(kind.len() + 8);
    out.extend_from_slice(kind.as_bytes());
    out.extend_from_slice(b":[");
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    let mut n = id;
    if n == 0 { i -= 1; buf[i] = b'0'; }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out.extend_from_slice(&buf[i..]);
    out.push(b']');
    Ok(out)
}

fn task_fd_path(tid_opt: Option<u32>, fd_str: &str) -> KResult<Vec<u8>> {
    let fd: i32 = fd_str.parse().map_err(|_| VfsError::Enoent)?;
    let task = task_for_proc_link(tid_opt)?;
    // SAFETY: fd_table slot single-mutator per `13§5`.
    let fdt = unsafe { (*task.fd_table.get()).as_ref().ok_or(VfsError::Enoent)?.clone() };
    let file = fdt.get(fd).map_err(|_| VfsError::Enoent)?;
    Ok(vfs::mount::render_path_for_mount(file.mnt_id(), file.dentry()).into_bytes())
}

/// Return the open `File` behind `/proc/<pid|self>/fd/<n>` so open(2)
/// can dup the existing open file description (Linux magic fd-link
/// reopen) instead of reopening the underlying path. None if no such
/// task or fd.
/// # C: O(1)
pub fn proc_fd_file(tid_opt: Option<u32>, fd: i32) -> Option<alloc::sync::Arc<vfs::File>> {
    let task = match tid_opt {
        Some(tid) => crate::live::registry::lookup(tid)?,
        None      => crate::live::registry::lookup(crate::live::current()?.tid)?,
    };
    // SAFETY: fd_table slot single-mutator per `13§5`; Arc-clone snapshot.
    let fdt = unsafe { (*task.fd_table.get()).as_ref()?.clone() };
    fdt.get(fd).ok()
}

/// Live fd numbers for `/proc/<tid_opt>/fd` readdir. `None` ⇒ the caller's own
/// table; `Some(tid)` ⇒ the TARGET task's — so `/proc/<pid>/fd` lists that
/// pid's descriptors, not the reader's (the `readdir` bug that made every
/// `/proc/<pid>/fd` show the caller's fds). # C: O(N_fds)
pub fn proc_fd_list(tid_opt: Option<u32>) -> alloc::vec::Vec<i32> {
    let task = match tid_opt {
        Some(tid) => crate::live::registry::lookup(tid),
        None      => crate::live::current().and_then(|c| crate::live::registry::lookup(c.tid)),
    };
    match task {
        // SAFETY: fd_table slot single-mutator per `13§5`; Arc-clone snapshot.
        Some(t) => match unsafe { (*t.fd_table.get()).as_ref() } {
            Some(fdt) => fdt.clone().live_fds(),
            None => alloc::vec::Vec::new(),
        },
        None => alloc::vec::Vec::new(),
    }
}
