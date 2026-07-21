#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;

use super::cred::current_cred;
use super::root::resolution_root_vfs;

fn trim_mount_raw(raw: &str) -> Result<&str, vfs::VfsError> {
    if raw.is_empty() { return Err(vfs::VfsError::Enoent); }
    let trimmed = if raw.len() > 1 { raw.trim_end_matches('/') } else { raw };
    if trimmed.is_empty() { Ok("/") } else { Ok(trimmed) }
}

fn rest_after<'a>(s: &'a str, p: &str) -> Option<&'a str> {
    let (sb, pb) = (s.as_bytes(), p.as_bytes());
    if sb.len() >= pb.len() && &sb[..pb.len()] == pb { Some(&s[pb.len()..]) } else { None }
}

pub fn dup_fd_target(raw: &str) -> Option<(Option<u32>, i32)> {
    match raw {
        "/dev/stdin"  => return Some((None, 0)),
        "/dev/stdout" => return Some((None, 1)),
        "/dev/stderr" => return Some((None, 2)),
        _ => {}
    }
    if let Some(rest) = rest_after(raw, "/dev/fd/") {
        return rest.parse::<i32>().ok().map(|n| (None, n));
    }
    let rest = rest_after(raw, "/proc/")?;
    let mut it = rest.splitn(3, '/');
    let who = it.next()?;
    if it.next()? != "fd" { return None; }
    let fd: i32 = it.next()?.parse().ok()?;
    let tid = if who == "self" { None } else { Some(who.parse::<u32>().ok()?) };
    Some((tid, fd))
}

pub fn procfd_path(raw: &str) -> Option<vfs::VfsPath> {
    let (tid_opt, fd) = dup_fd_target(raw)?;
    let file = sched::proclink::proc_fd_file(tid_opt, fd)?;
    Some(vfs::VfsPath {
        mnt_id: file.mnt_id(),
        dentry: file.dentry().clone(),
        inode: file.inode().clone(),
        last_component: None,
    })
}

fn raw_lookup_base() -> Result<(vfs::VfsPath, vfs::VfsPath, bool), vfs::VfsError> {
    if let Some(context) = sched::live::current_vfs_lookup_context() {
        return Ok((context.start, context.root, context.beneath));
    }
    let (root, beneath) = resolution_root_vfs().ok_or(vfs::VfsError::Enoent)?;
    let start = match sched::live::current() {
        Some(cur) => {
            cur.fs_context_snapshot().cwd_vfs()
                .filter(|p| p.mnt_id != vfs::mount::MNT_ID_NONE)
                .unwrap_or_else(|| root.clone())
        }
        None => root.clone(),
    };
    Ok((start, root, beneath))
}

/// Resolve raw user path text directly from the live cwd/root `struct path`,
/// without first rendering cwd into a string. # C: O(components × dir-lookup)
pub fn resolve_path_raw(raw: &str, no_follow_final: bool) -> Result<vfs::VfsPath, vfs::VfsError> {
    let raw = trim_mount_raw(raw)?;
    if let Some(p) = procfd_path(raw) { return Ok(p); }
    let (start, root, beneath) = raw_lookup_base()?;
    let start_mnt = start.mnt_id;
    let root_mnt = root.mnt_id;
    let mut flags = vfs::LookupFlags { no_follow_final, ..Default::default() };
    flags.beneath = flags.beneath || beneath;
    vfs::path_lookup_at_root_cred(
        start.dentry, start_mnt, root.dentry, root_mnt, raw, flags, current_cred())
        .map_err(|e| {
            if e == vfs::VfsError::Enotdir { trace_lookup_enotdir(raw, start_mnt, root_mnt); }
            e
        })
}

/// Resolve raw user path text as a mount attach target and return the display
/// path derived from that walked identity. # C: O(components × dir-lookup)
pub fn resolve_mount_target_raw(raw: &str) -> Result<(vfs::MountTarget, String), vfs::VfsError> {
    let raw = trim_mount_raw(raw)?;
    if let Some(p) = procfd_path(raw) {
        let display = vfs::mount::render_path_for_mount(p.mnt_id, &p.dentry);
        let target = vfs::mount_target_from_resolved_path(p);
        return Ok((target, display));
    }
    let (start, root, _) = raw_lookup_base()?;
    let start_mnt = start.mnt_id;
    let root_mnt = root.mnt_id;
    let res = vfs::mountpoint_lookup_at_root_cred(
        start.dentry, start_mnt, root.dentry, root_mnt, raw, current_cred());
    match res {
        Ok(t) => {
            let display = vfs::mount::render_path_for_mount(t.parent.mnt_id, &t.mountpoint);
            Ok((t, display))
        }
        Err(vfs::VfsError::Enotdir) => {
            trace_lookup_enotdir(raw, start_mnt, root_mnt);
            Err(vfs::VfsError::Enotdir)
        }
        Err(e) => Err(e),
    }
}

#[cfg(feature = "debug-boot")]
fn trace_lookup_enotdir(abs: &str, start_mnt: u64, root_mnt: u64) {
    klog::write_raw(b"[ENOTDIR] op=resolve_path_flags why=walk tid=");
    klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
    klog::write_raw(b" start_mnt=");
    klog::write_dec_u64(start_mnt);
    klog::write_raw(b" root_mnt=");
    klog::write_dec_u64(root_mnt);
    klog::write_raw(b" path=");
    klog::write_raw(abs.as_bytes());
    if let Some(c) = sched::live::current() {
        let cwd = c.fs_context_snapshot().cwd();
        klog::write_raw(b" cwd=");
        klog::write_raw(cwd.as_bytes());
    }
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-boot"))]
fn trace_lookup_enotdir(_abs: &str, _start_mnt: u64, _root_mnt: u64) {}
