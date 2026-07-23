// `/proc/<pid>/{exe,cwd,root,fd/<n>,ns/<type>}` symlink resolver.
// Split out of `syscall_glue_fs.rs` to keep that file under the
// 1000-line cap. Used by `sys_readlink` for proc-link paths.


extern crate alloc;
use alloc::vec::Vec;
use vfs::{KResult, VfsError, VfsPath};

fn task_for_proc_link(tid_opt: Option<u32>) -> KResult<alloc::sync::Arc<crate::Task>> {
    match tid_opt {
        Some(tid) => crate::live::registry::lookup(tid).ok_or(VfsError::Enoent),
        None      => crate::live::current()
            .and_then(|c| crate::live::registry::lookup(c.tid))
            .ok_or(VfsError::Enoent),
    }
}

/// Return `/proc/<pid>/exe` readlink bytes from the task's exec image state.
/// # C: O(1)
pub fn task_exe_path(tid_opt: Option<u32>) -> KResult<Vec<u8>> {
    let task = match tid_opt {
        Some(tid) => crate::live::registry::lookup(tid),
        None      => crate::live::current().and_then(|c| crate::live::registry::lookup(c.tid)),
    };
    if let Some(t) = task {
        // Linux: /proc/<pid>/exe is rooted on mm_struct::exe_file
        // — the dentry the user named at execve, shared across all
        // CLONE_VM threads. Prefer the mm slot over the per-task
        // mirror so hardlinks resolve to the invoked path.
        // `t` may be a foreign task (arbitrary tid): clone_mm pins
        // against a concurrent exit/execve mm replacement on another CPU.
        if let Some(mm) = t.clone_mm() {
            if let Some(s) = mm.exe_path() {
                if !s.is_empty() { return Ok(s.into_bytes()); }
            }
        }
        if let Some(s) = t.exe_path() {
            if !s.is_empty() { return Ok(s.into_bytes()); }
        }
    }
    Err(VfsError::Enoent)
}

/// Return `/proc/<pid>/cwd` readlink bytes from the target task's live path.
/// # C: O(1)
pub fn task_cwd_path(tid_opt: Option<u32>) -> KResult<Vec<u8>> {
    let p = task_cwd_vfs(tid_opt)?;
    Ok(vfs::mount::render_path_for_mount(p.mnt_id, &p.dentry).into_bytes())
}

/// Return `/proc/<pid>/root` readlink bytes from the target task's live path.
/// # C: O(1)
pub fn task_root_path(tid_opt: Option<u32>) -> KResult<Vec<u8>> {
    let p = task_root_vfs(tid_opt)?;
    Ok(vfs::mount::render_path_for_mount(p.mnt_id, &p.dentry).into_bytes())
}

/// Return `/proc/<pid>/cwd` as the target task's live `struct path`.
/// # C: O(1)
pub fn task_cwd_vfs(tid_opt: Option<u32>) -> KResult<VfsPath> {
    let task = task_for_proc_link(tid_opt)?;
    task.fs_context_snapshot().cwd_vfs().ok_or(VfsError::Enoent)
}

/// Return `/proc/<pid>/root` as the target task's live `struct path`.
/// # C: O(1)
pub fn task_root_vfs(tid_opt: Option<u32>) -> KResult<VfsPath> {
    let task = task_for_proc_link(tid_opt)?;
    task.fs_context_snapshot().root_vfs().ok_or(VfsError::Enoent)
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
    // `task` may be a foreign task (arbitrary tid): clone_fd_table pins
    // against a concurrent exit-time replace_fd_table(None) on another CPU.
    let fdt = task.clone_fd_table()?;
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
        // `t` may be a foreign task (arbitrary tid): clone_fd_table pins
        // against a concurrent exit-time replace_fd_table(None) on another CPU.
        Some(t) => match t.clone_fd_table() {
            Some(fdt) => fdt.live_fds(),
            None => alloc::vec::Vec::new(),
        },
        None => alloc::vec::Vec::new(),
    }
}
