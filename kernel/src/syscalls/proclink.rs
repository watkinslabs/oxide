// `/proc/<pid>/{exe,cwd,root,fd/<n>,ns/<type>}` symlink resolver.
// Split out of `syscall_glue_fs.rs` to keep that file under the
// 1000-line cap. Used by `kernel_sys_readlink` for proc-link paths.

#![cfg(target_os = "oxide-kernel")]

extern crate alloc;
use alloc::vec::Vec;

/// Resolve a `/proc/<pid>/<leaf>` symlink to its readlink target bytes.
/// # C: O(N_path)
pub fn resolve_proc_link(path: &str) -> Option<Vec<u8>> {
    let rest = path.strip_prefix("/proc/")?;
    let mut parts = rest.splitn(2, '/');
    let head = parts.next()?;
    let leaf = parts.next()?;
    let tid_opt: Option<u32> = if head == "self" { None } else { head.parse().ok() };
    if head != "self" && tid_opt.is_none() { return None; }
    if let Some(tid) = tid_opt {
        if sched::live::registry::lookup(tid).is_none() { return None; }
    }
    match leaf {
        "exe"  => Some(task_exe_path(tid_opt)),
        "cwd"  => Some(task_cwd_path(tid_opt)),
        "root" => Some(task_root_path(tid_opt)),
        l if l.starts_with("fd/") => task_fd_path(tid_opt, &l[3..]),
        l if l.starts_with("ns/") => task_ns_link(tid_opt, &l[3..]),
        _      => None,
    }
}

fn task_exe_path(tid_opt: Option<u32>) -> Vec<u8> {
    let task = match tid_opt {
        Some(tid) => sched::live::registry::lookup(tid),
        None      => sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid)),
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
                if !s.is_empty() { return s.into_bytes(); }
            }
        }
        // SAFETY: exe_path single-mutator per `13§5`; snapshot.
        if let Some(s) = unsafe { (*t.exe_path.get()).clone() } {
            if !s.is_empty() { return s.into_bytes(); }
        }
        // SAFETY: cmdline single-mutator per `13§5`.
        if let Some(s) = unsafe { (*t.cmdline.get()).clone() } {
            let bytes = s.as_bytes();
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            if end > 0 { return bytes[..end].to_vec(); }
        }
    }
    b"/init".to_vec()
}

fn task_cwd_path(tid_opt: Option<u32>) -> Vec<u8> {
    let task = match tid_opt {
        Some(tid) => sched::live::registry::lookup(tid),
        None      => sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid)),
    };
    if let Some(t) = task {
        // SAFETY: cwd slot single-mutator per `13§5`.
        let s = unsafe { (*t.cwd.get()).clone() };
        if !s.is_empty() { return s.into_bytes(); }
    }
    b"/".to_vec()
}

fn task_root_path(tid_opt: Option<u32>) -> Vec<u8> {
    let task = match tid_opt {
        Some(tid) => sched::live::registry::lookup(tid),
        None      => sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid)),
    };
    if let Some(t) = task {
        // SAFETY: task.root single-mutator per `13§5`.
        let s = unsafe { (*t.root.get()).clone() };
        if !s.is_empty() { return s.into_bytes(); }
    }
    b"/".to_vec()
}

fn task_ns_link(tid_opt: Option<u32>, leaf: &str) -> Option<Vec<u8>> {
    use core::sync::atomic::Ordering;
    let task = match tid_opt {
        Some(tid) => sched::live::registry::lookup(tid)?,
        None      => sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))?,
    };
    let id = match leaf {
        "ipc"    => task.ipc_ns.load(Ordering::Acquire),
        "uts"    => (task.ns_membership.load(Ordering::Acquire) >> 1) & 0xff_ffff_ffff,
        "pid" | "pid_for_children" => task.pid_ns.load(Ordering::Acquire),
        "net"    => task.net_ns.load(Ordering::Acquire),
        "user"   => task.user_ns.load(Ordering::Acquire),
        "cgroup" => task.cgroup_ns.load(Ordering::Acquire),
        "mnt"    => task.mount_ns.load(Ordering::Acquire),
        _ => return None,
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
    Some(out)
}

fn task_fd_path(tid_opt: Option<u32>, fd_str: &str) -> Option<Vec<u8>> {
    let fd: i32 = fd_str.parse().ok()?;
    let task = match tid_opt {
        Some(tid) => sched::live::registry::lookup(tid)?,
        None      => sched::live::registry::lookup(sched::live::current()?.tid)?,
    };
    // SAFETY: fd_table slot single-mutator per `13§5`.
    let fdt = unsafe { (*task.fd_table.get()).as_ref()?.clone() };
    let file = fdt.get(fd).ok()?;
    Some(file.dentry().name().as_bytes().to_vec())
}
