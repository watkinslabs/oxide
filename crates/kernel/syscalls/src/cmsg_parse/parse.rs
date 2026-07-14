use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::File;

pub(super) const SOL_SOCKET: i32 = 1;
pub(super) const SCM_RIGHTS: i32 = 1;
pub(super) const SCM_CREDENTIALS: i32 = 2;
const SCM_MAX_FD: usize = 253;

pub struct ParsedScm {
    pub fds: Vec<Arc<File>>,
    pub creds: Option<net::sock::SenderCreds>,
}

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }
fn i32_at(bytes: &[u8], at: usize) -> i32 { i32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap()) }
fn u64_at(bytes: &[u8], at: usize) -> u64 { u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap()) }

/// Parse a snapshotted control buffer and pin every SCM_RIGHTS file. Any bad
/// descriptor rejects the complete message, matching Linux `scm_fp_copy`.
/// # C: O(controllen + nfds)
pub fn parse_scm(control: &[u8], allow_rights: bool) -> Result<ParsedScm, i64> {
    let cur = sched::live::current().ok_or_else(|| err(Errno::Esrch))?;
    // SAFETY: current task owns this fd-table view for the syscall duration.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or_else(|| err(Errno::Ebadf))?.clone();
    let mut out = Vec::new();
    let mut creds = None;
    let mut off = 0usize;
    while control.len().saturating_sub(off) >= 16 {
        let cmsg_len = usize::try_from(u64_at(control, off)).map_err(|_| err(Errno::Einval))?;
        if cmsg_len < 16 || cmsg_len > control.len() - off { return Err(err(Errno::Einval)); }
        let level = i32_at(control, off + 8);
        let kind = i32_at(control, off + 12);
        if level == SOL_SOCKET && kind == SCM_RIGHTS {
            if !allow_rights { return Err(err(Errno::Einval)); }
            let data = cmsg_len - 16;
            if data % 4 != 0 { return Err(err(Errno::Einval)); }
            if out.len().saturating_add(data / 4) > SCM_MAX_FD { return Err(err(Errno::Einval)); }
            for at in (off + 16..off + cmsg_len).step_by(4) {
                let file = fdt.get(i32_at(control, at)).map_err(|_| err(Errno::Ebadf))?;
                if file.inode().private::<crate::io_uring::IoUringInode>().is_some() {
                    return Err(err(Errno::Einval));
                }
                out.push(file);
            }
        } else if level == SOL_SOCKET && kind == SCM_CREDENTIALS {
            creds = Some(validate_credentials(&control[off + 16..off + cmsg_len], &cur)?);
        } else if level == SOL_SOCKET {
            return Err(err(Errno::Einval));
        }
        let aligned = cmsg_len.checked_add(7).ok_or_else(|| err(Errno::Einval))? & !7;
        let next = off.checked_add(aligned).ok_or_else(|| err(Errno::Einval))?;
        if next > control.len() { break; }
        off = next;
    }
    Ok(ParsedScm { fds: out, creds })
}

fn validate_credentials(data: &[u8], cur: &sched::Task) -> Result<net::sock::SenderCreds, i64> {
    if data.len() != 12 { return Err(err(Errno::Einval)); }
    use core::sync::atomic::Ordering;
    let pid = i32_at(data, 0);
    let uid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
    let gid = u32::from_ne_bytes(data[8..12].try_into().unwrap());
    if pid <= 0 { return Err(err(Errno::Esrch)); }
    let pid_ok = pid == cur.visible_pid() as i32 || cur.has_cap(sched::cap::SYS_ADMIN);
    let uid_ok = uid == cur.creds.ruid.load(Ordering::Acquire)
        || uid == cur.creds.euid.load(Ordering::Acquire)
        || uid == cur.creds.suid.load(Ordering::Acquire)
        || cur.has_cap(sched::cap::SETUID);
    let gid_ok = gid == cur.creds.rgid.load(Ordering::Acquire)
        || gid == cur.creds.egid.load(Ordering::Acquire)
        || gid == cur.creds.sgid.load(Ordering::Acquire)
        || cur.has_cap(sched::cap::SETGID);
    if !pid_ok || !uid_ok || !gid_ok
    { return Err(err(Errno::Eperm)); }
    if pid != cur.visible_pid() as i32 && sched::registry::resolve_user_pid(pid as u32).is_none() {
        return Err(err(Errno::Esrch));
    }
    Ok(net::sock::SenderCreds { pid: pid as u32, uid, gid })
}
