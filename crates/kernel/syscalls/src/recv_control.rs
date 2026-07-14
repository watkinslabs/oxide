use alloc::sync::Arc;
use alloc::vec::Vec;

use net::uapi::MSG_CTRUNC;
use vfs::{File, OpenFlags};

use crate::recv_user::RecvUser;

const CMSG_HDR: usize = 16;
const CMSG_ALIGN: usize = 8;
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;

pub(crate) struct DeliveredControl {
    pub len: usize,
    pub flags: u32,
}

fn aligned(n: usize) -> usize { (n + CMSG_ALIGN - 1) & !(CMSG_ALIGN - 1) }

fn put_header(out: &mut [u8], at: usize, len: usize, ty: i32) {
    out[at..at + 8].copy_from_slice(&(len as u64).to_ne_bytes());
    out[at + 8..at + 12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
    out[at + 12..at + 16].copy_from_slice(&ty.to_ne_bytes());
}

fn append_cred(out: &mut Vec<u8>, cap: usize, cred: (u32, u32, u32), flags: &mut u32) {
    const LEN: usize = CMSG_HDR + 12;
    let remaining = cap.saturating_sub(out.len());
    if remaining < CMSG_HDR { *flags |= MSG_CTRUNC as u32; return; }
    let at = out.len();
    let write = core::cmp::min(aligned(LEN), remaining);
    if write < aligned(LEN) { *flags |= MSG_CTRUNC as u32; }
    out.resize(at + write, 0);
    put_header(out, at, LEN, SCM_CREDENTIALS);
    let mut raw = [0u8; 12];
    raw[..4].copy_from_slice(&cred.0.to_ne_bytes());
    raw[4..8].copy_from_slice(&cred.1.to_ne_bytes());
    raw[8..].copy_from_slice(&cred.2.to_ne_bytes());
    let data_len = core::cmp::min(raw.len(), write - CMSG_HDR);
    out[at + CMSG_HDR..at + CMSG_HDR + data_len].copy_from_slice(&raw[..data_len]);
}

/// Stage ancillary bytes and descriptor reservations, copy once, then publish fds. # C: O(files + faults)
pub(crate) fn deliver(user: &RecvUser, files: Vec<Arc<File>>, cred: Option<(u32, u32, u32)>, recv_flags: u64) -> DeliveredControl {
    let mut flags = 0u32;
    let cap = if user.control == 0 { 0 } else { user.controllen };
    let mut out = Vec::new();
    if let Some(cred) = cred { append_cred(&mut out, cap, cred, &mut flags); }
    let remaining = cap.saturating_sub(out.len());
    let rights_cap = remaining.saturating_sub(CMSG_HDR) / 4;
    let want_rights = core::cmp::min(files.len(), rights_cap);
    if want_rights < files.len() { flags |= MSG_CTRUNC as u32; }
    let cur = sched::live::current();
    // SAFETY: current task owns its fd-table reference throughout this syscall.
    let fdt = cur.as_ref().and_then(|task| unsafe { task.fd_table_ref() }).cloned();
    let nofile = cur.as_ref().map(|task| task.nofile_soft()).unwrap_or(0);
    let reserve_flags = if recv_flags & MSG_CMSG_CLOEXEC != 0 { OpenFlags::O_CLOEXEC } else { OpenFlags::empty() };
    let mut reserved: Vec<(i32, Arc<File>)> = Vec::with_capacity(want_rights);
    if let Some(fdt) = &fdt {
        for file in files.iter().take(want_rights) {
            match fdt.get_unused_fd_flags(reserve_flags, nofile) {
                Ok(fd) => reserved.push((fd, file.clone())),
                Err(_) => { flags |= MSG_CTRUNC as u32; break; }
            }
        }
    } else if want_rights != 0 {
        flags |= MSG_CTRUNC as u32;
    }
    if !reserved.is_empty() {
        let rights_len = CMSG_HDR + reserved.len() * 4;
        let off = out.len();
        let write = core::cmp::min(aligned(rights_len), cap.saturating_sub(off));
        out.resize(off + write, 0);
        put_header(&mut out, off, rights_len, SCM_RIGHTS);
        for (i, (fd, _)) in reserved.iter().enumerate() {
            let at = off + CMSG_HDR + i * 4;
            out[at..at + 4].copy_from_slice(&fd.to_ne_bytes());
        }
    }
    if out.is_empty() { return DeliveredControl { len: 0, flags }; }
    if uaccess::copy_to_user(user.control, &out).is_err() {
        if let Some(fdt) = &fdt { for (fd, _) in &reserved { fdt.put_unused_fd(*fd); } }
        return DeliveredControl { len: 0, flags: flags | MSG_CTRUNC as u32 };
    }
    if let Some(fdt) = &fdt {
        for (fd, file) in reserved {
            vfs::fire_clone_hook(&file);
            fdt.fd_install(fd, file);
        }
    }
    DeliveredControl { len: out.len(), flags }
}
