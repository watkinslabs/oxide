use alloc::sync::Arc;
use alloc::vec::Vec;

use net::uapi::{MSG_CMSG_CLOEXEC, MSG_CTRUNC};
use vfs::File;

use crate::recv_user::RecvUser;

const CMSG_HDR: usize = 16;
const CMSG_ALIGN: usize = 8;
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;

fn errno(e: syscall::errno::Errno) -> i64 { -(e.as_i32() as i64) }
pub(crate) struct DeliveredControl {
    pub len: usize,
    pub flags: u32,
}

pub(crate) struct Control {
    pub flags: u32,
    cap: usize,
    entries: Vec<(i32, i32, Vec<u8>)>,
}

fn aligned(n: usize) -> usize { (n + CMSG_ALIGN - 1) & !(CMSG_ALIGN - 1) }

impl Control {
    /// Create one receive-control cursor with the imported user capacity. # C: O(1)
    pub fn new(cap: usize) -> Self { Self { flags: 0, cap, entries: Vec::new() } }

    /// Queue one protocol control message for ordered copyout. # C: O(data)
    pub fn push(&mut self, level: i32, ty: i32, data: &[u8]) {
        self.entries.push((level, ty, data.to_vec()));
    }

    /// Emit queued cmsgs through one Linux-style advancing cursor. # C: O(entries + data + faults)
    pub fn copy_to(&mut self, user: &RecvUser) -> Result<usize, i64> {
        let mut copied = 0usize;
        for (level, ty, data) in &self.entries {
            let full_len = CMSG_HDR + data.len();
            let remaining = self.cap.saturating_sub(copied);
            if remaining < CMSG_HDR { self.flags |= MSG_CTRUNC as u32; continue; }
            let advance = core::cmp::min(aligned(full_len), remaining);
            let data_len = core::cmp::min(data.len(), remaining - CMSG_HDR);
            if remaining < full_len { self.flags |= MSG_CTRUNC as u32; }
            let cmsg_len = CMSG_HDR + data_len;
            let mut entry = alloc::vec![0u8; cmsg_len];
            entry[..8].copy_from_slice(&(cmsg_len as u64).to_ne_bytes());
            entry[8..12].copy_from_slice(&level.to_ne_bytes());
            entry[12..16].copy_from_slice(&ty.to_ne_bytes());
            entry[CMSG_HDR..CMSG_HDR + data_len].copy_from_slice(&data[..data_len]);
            let Some(dst) = user.control.checked_add(copied as u64) else { continue; };
            uaccess::copy_to_user(dst, &entry).map_err(errno)?;
            copied += advance;
        }
        Ok(copied)
    }
}

/// Preserve receive-only input flags that Linux returns in `msg_flags`. # C: O(1)
pub(crate) fn output_flags(recv_flags: u64) -> u32 {
    (recv_flags & MSG_CMSG_CLOEXEC) as u32
}

fn cred_bytes(cred: (u32, u32, u32)) -> [u8; 12] {
    let mut raw = [0u8; 12];
    raw[..4].copy_from_slice(&cred.0.to_ne_bytes());
    raw[4..8].copy_from_slice(&cred.1.to_ne_bytes());
    raw[8..].copy_from_slice(&cred.2.to_ne_bytes());
    raw
}

/// Emit credentials, then reserve, copy, and publish each received fd. # C: O(files + faults)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn deliver(user: &RecvUser, files: Vec<Arc<File>>, cred: Option<(u32, u32, u32)>, recv_flags: u64) -> Result<DeliveredControl, i64> {
    let mut flags = output_flags(recv_flags);
    let cap = if user.control == 0 { 0 } else { user.controllen };
    let mut control = Control::new(cap);
    if let Some(cred) = cred { control.push(SOL_SOCKET, SCM_CREDENTIALS, &cred_bytes(cred)); }
    let off = control.copy_to(user)?;
    flags |= control.flags;
    let remaining = cap.saturating_sub(off);
    let rights_cap = remaining.saturating_sub(CMSG_HDR) / 4;
    if rights_cap < files.len() { flags |= MSG_CTRUNC as u32; }
    let cur = sched::live::current();
    // SAFETY: current task owns its fd-table reference throughout this syscall.
    let fdt = cur.as_ref().and_then(|task| unsafe { task.fd_table_ref() }).cloned();
    let nofile = cur.as_ref().map(|task| task.nofile_soft()).unwrap_or(0);
    let cloexec = recv_flags & MSG_CMSG_CLOEXEC != 0;
    let Some(fdt) = fdt else {
        if !files.is_empty() { flags |= MSG_CTRUNC as u32; }
        return Ok(DeliveredControl { len: off, flags });
    };
    let result = socket::install_received_fds(&fdt, nofile, cloexec, files, rights_cap, |index, fd| {
            let dst = user.control.checked_add((off + CMSG_HDR + index * 4) as u64);
            let dst = dst.ok_or(vfs::VfsError::Efault)?;
            // SAFETY: fd bytes are kernel-owned; raw usercopy reports a fault without losing prefix state.
            let left = unsafe { uaccess::raw_copy_to_user(dst, fd.to_ne_bytes().as_ptr(), 4) };
            if left == 0 { Ok(()) } else { Err(vfs::VfsError::Efault) }
        });
    if result.truncated { flags |= MSG_CTRUNC as u32; }
    let installed = result.installed;
    if installed == 0 { return Ok(DeliveredControl { len: off, flags }); }
    let rights_len = CMSG_HDR + installed * 4;
    let rights_space = core::cmp::min(aligned(rights_len), cap - off);
    let base = user.control.checked_add(off as u64);
    let header_ok = base.is_some_and(|base| base.checked_add(8).is_some_and(|p| uaccess::copy_to_user(p, &SOL_SOCKET.to_ne_bytes()).is_ok())
        && base.checked_add(12).is_some_and(|p| uaccess::copy_to_user(p, &SCM_RIGHTS.to_ne_bytes()).is_ok())
        && uaccess::copy_to_user(base, &(rights_len as u64).to_ne_bytes()).is_ok());
    Ok(DeliveredControl { len: if header_ok { off + rights_space } else { off }, flags })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_cmsg_len_describes_only_emitted_data() {
        let data = [0x5au8; 12];
        for cap in 0..=32 {
            let mut bytes = [0u8; 32];
            let user = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0, control: bytes.as_mut_ptr() as u64,
                controllen: cap, iov: Vec::new(), capacity: 0 };
            let mut control = Control::new(cap);
            control.push(SOL_SOCKET, SCM_CREDENTIALS, &data);
            let copied = control.copy_to(&user).unwrap();
            if cap < CMSG_HDR {
                assert_eq!(copied, 0);
            } else {
                let emitted = core::cmp::min(data.len(), cap - CMSG_HDR);
                let len = u64::from_ne_bytes(bytes[..8].try_into().unwrap()) as usize;
                assert_eq!(len, CMSG_HDR + emitted);
                assert_eq!(&bytes[CMSG_HDR..CMSG_HDR + emitted], &data[..emitted]);
            }
            assert_eq!(control.flags & MSG_CTRUNC as u32 != 0, cap < CMSG_HDR + data.len());
        }
    }

    #[test]
    fn complete_cmsg_does_not_write_alignment_padding() {
        let mut bytes = [0xa5u8; 32];
        let user = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0, control: bytes.as_mut_ptr() as u64,
            controllen: bytes.len(), iov: Vec::new(), capacity: 0 };
        let mut control = Control::new(bytes.len());
        control.push(SOL_SOCKET, SCM_CREDENTIALS, &[0x5a; 12]);

        assert_eq!(control.copy_to(&user).unwrap(), 32, "cursor advances through CMSG_SPACE");
        assert_eq!(&bytes[28..], &[0xa5; 4], "put_cmsg never touches alignment padding");
    }

    #[test]
    fn recv_output_preserves_cmsg_cloexec_only() {
        assert_eq!(output_flags(MSG_CMSG_CLOEXEC | net::uapi::MSG_PEEK), MSG_CMSG_CLOEXEC as u32);
        assert_eq!(output_flags(net::uapi::MSG_PEEK), 0);
    }
}
