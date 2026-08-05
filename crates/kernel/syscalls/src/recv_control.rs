use alloc::vec::Vec;

use net::uapi::{MSG_CMSG_CLOEXEC, MSG_CTRUNC};
// `deliver` (the only fd-passing consumer) is kernel-gated.
#[cfg(target_os = "oxide-kernel")]
use alloc::sync::Arc;
#[cfg(target_os = "oxide-kernel")]
use vfs::File;

use crate::recv_user::RecvUser;

const CMSG_HDR: usize = 16;
const CMSG_ALIGN: usize = 8;
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
const SCM_SECURITY: i32 = 3;
const SCM_PIDFD: i32 = 4;
use net::sock_opts::inq::InqCmsg;

fn errno(e: syscall::errno::Errno) -> i64 { -(e.as_i32() as i64) }
pub(crate) struct DeliveredControl {
    pub len: usize,
    pub flags: u32,
}

/// Per-record SOL_SOCKET data handed to the sole receive copyout owner.
/// Transports retain this alongside their queued payload; deciding which
/// receiver options consume it belongs here, not in AF_UNIX or NETLINK.
#[cfg(target_os = "oxide-kernel")]
pub(crate) struct ScmReceive {
    pub credentials: Option<(u32, u32, u32)>,
    pub security: Option<Vec<u8>>,
    pub pid: Option<Arc<sched::pid::PidIdentity>>,
    pub want_pidfd: bool,
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

    /// Queue the unread-bytes report a receive owes its caller. Every option
    /// that enables one — the socket-level and the transport-level number
    /// alike — publishes through this one path. # C: O(1)
    pub fn push_inq(&mut self, inq: Option<InqCmsg>) {
        if let Some(inq) = inq { self.push(inq.level, inq.ty, &inq.data()); }
    }

    /// Emit queued cmsgs through one Linux-style advancing cursor. # C: O(entries + data + faults)
    pub fn copy_to(&mut self, user: &RecvUser) -> Result<usize, i64> {
        self.copy_to_at(user, 0)
    }

    /// Emit the control stream at the option ABI's raw user pointer. # C: O(entries + data + faults)
    pub fn copy_to_raw(&mut self, control: u64) -> Result<usize, i64> {
        self.copy_to(&RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0,
            control, controllen: self.cap, iov: Vec::new(), capacity: 0 })
    }

    fn copy_to_at(&mut self, user: &RecvUser, at: usize) -> Result<usize, i64> {
        let mut copied = 0usize;
        for (level, ty, data) in &self.entries {
            let Some((entry, advance, truncated)) =
                encode_entry(*level, *ty, data, self.cap.saturating_sub(copied))
            else { self.flags |= MSG_CTRUNC as u32; continue; };
            if truncated { self.flags |= MSG_CTRUNC as u32; }
            let Some(dst) = user.control.checked_add(at.saturating_add(copied) as u64) else { continue; };
            uaccess::copy_to_user(dst, &entry).map_err(errno)?;
            copied += advance;
        }
        Ok(copied)
    }

    /// The same stream as one buffer, for the option read that publishes a
    /// control stream instead of a value. # C: O(entries + data)
    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for (level, ty, data) in &self.entries {
            let Some((entry, advance, truncated)) =
                encode_entry(*level, *ty, data, self.cap.saturating_sub(out.len()))
            else { self.flags |= MSG_CTRUNC as u32; continue; };
            if truncated { self.flags |= MSG_CTRUNC as u32; }
            let at = out.len();
            out.resize(at + advance, 0);
            out[at..at + entry.len()].copy_from_slice(&entry);
        }
        out
    }
}

/// One control message's bytes, how far the cursor advances past it, and
/// whether the payload was cut short. `None` when not even the header fits.
/// # C: O(data)
fn encode_entry(level: i32, ty: i32, data: &[u8], remaining: usize)
    -> Option<(Vec<u8>, usize, bool)>
{
    if remaining < CMSG_HDR { return None; }
    let full_len = CMSG_HDR + data.len();
    let advance = core::cmp::min(aligned(full_len), remaining);
    let data_len = core::cmp::min(data.len(), remaining - CMSG_HDR);
    let cmsg_len = CMSG_HDR + data_len;
    let mut entry = alloc::vec![0u8; cmsg_len];
    entry[..8].copy_from_slice(&(cmsg_len as u64).to_ne_bytes());
    entry[8..12].copy_from_slice(&level.to_ne_bytes());
    entry[12..16].copy_from_slice(&ty.to_ne_bytes());
    entry[CMSG_HDR..CMSG_HDR + data_len].copy_from_slice(&data[..data_len]);
    Some((entry, advance, remaining < full_len))
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
pub(crate) fn deliver(user: &RecvUser, files: Vec<Arc<File>>, scm: ScmReceive,
    inq: Option<InqCmsg>, protocol: Option<(i32, i32, &[u8])>, recv_flags: u64)
    -> Result<DeliveredControl, i64>
{
    let mut flags = output_flags(recv_flags);
    let cap = if user.control == 0 { 0 } else { user.controllen };
    let mut control = Control::new(cap);
    if let Some((level, ty, data)) = protocol { control.push(level, ty, data); }
    if let Some(cred) = scm.credentials { control.push(SOL_SOCKET, SCM_CREDENTIALS, &cred_bytes(cred)); }
    if let Some(label) = scm.security.as_deref() { control.push(SOL_SOCKET, SCM_SECURITY, label); }
    control.push_inq(inq);
    let mut off = control.copy_to(user)?;
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
    if installed != 0 {
        let rights_len = CMSG_HDR + installed * 4;
        let rights_space = core::cmp::min(aligned(rights_len), cap - off);
        let base = user.control.checked_add(off as u64);
        let header_ok = base.is_some_and(|base| base.checked_add(8).is_some_and(|p| uaccess::copy_to_user(p, &SOL_SOCKET.to_ne_bytes()).is_ok())
            && base.checked_add(12).is_some_and(|p| uaccess::copy_to_user(p, &SCM_RIGHTS.to_ne_bytes()).is_ok())
            && uaccess::copy_to_user(base, &(rights_len as u64).to_ne_bytes()).is_ok());
        if header_ok { off += rights_space; }
    }
    if scm.want_pidfd {
        if cap.saturating_sub(off) < CMSG_HDR + core::mem::size_of::<i32>() {
            flags |= MSG_CTRUNC as u32;
        } else if let Some(identity) = scm.pid {
            let current = sched::live::current();
            let prepared = current.as_ref().and_then(|task|
                pidfd::prepare(task, identity, pidfd::OpenOptions::default()).ok());
            let fd = prepared.as_ref().map_or(-1, pidfd::Prepared::fd);
            let mut pidfd = Control::new(cap - off);
            pidfd.push(SOL_SOCKET, SCM_PIDFD, &fd.to_ne_bytes());
            let copied = pidfd.copy_to_at(user, off)?;
            if copied != 0 {
                if let Some(prepared) = prepared { prepared.commit(); }
                off += copied;
            }
        }
    }
    Ok(DeliveredControl { len: off, flags })
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
    fn socket_security_follows_credentials_in_the_one_control_cursor() {
        let mut bytes = [0u8; 64];
        let user = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0,
            control: bytes.as_mut_ptr() as u64, controllen: bytes.len(), iov: Vec::new(), capacity: 0 };
        let mut control = Control::new(bytes.len());
        control.push(SOL_SOCKET, SCM_CREDENTIALS, &[0; 12]);
        control.push(SOL_SOCKET, SCM_SECURITY, b"sender_t");
        assert_eq!(control.copy_to(&user).unwrap(), 56);
        assert_eq!(i32::from_ne_bytes(bytes[8..12].try_into().unwrap()), SOL_SOCKET);
        assert_eq!(i32::from_ne_bytes(bytes[12..16].try_into().unwrap()), SCM_CREDENTIALS);
        assert_eq!(i32::from_ne_bytes(bytes[40..44].try_into().unwrap()), SOL_SOCKET);
        assert_eq!(i32::from_ne_bytes(bytes[44..48].try_into().unwrap()), SCM_SECURITY);
        assert_eq!(&bytes[48..56], b"sender_t");
    }

    #[test]
    fn the_unread_bytes_report_is_emitted_at_its_own_level_and_number() {
        // Both options publish through the one push path, so the level and
        // number in the emitted header are the only thing that differs.
        for (inq, level, ty) in [
            (InqCmsg::socket(7), 1, net::sock_opts::sol_socket::SCM_INQ),
            (InqCmsg::tcp(7), 6, net::sock_opts::sol_tcp::TCP_CM_INQ as i32),
        ] {
            let mut bytes = [0u8; 32];
            let user = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0,
                control: bytes.as_mut_ptr() as u64, controllen: bytes.len(),
                iov: Vec::new(), capacity: 0 };
            let mut control = Control::new(bytes.len());
            control.push_inq(Some(inq));
            let copied = control.copy_to(&user).unwrap();
            assert_eq!(copied, aligned(CMSG_HDR + 4));
            assert_eq!(u64::from_ne_bytes(bytes[..8].try_into().unwrap()) as usize, CMSG_HDR + 4);
            assert_eq!(i32::from_ne_bytes(bytes[8..12].try_into().unwrap()), level);
            assert_eq!(i32::from_ne_bytes(bytes[12..16].try_into().unwrap()), ty);
            assert_eq!(i32::from_ne_bytes(bytes[16..20].try_into().unwrap()), 7);
        }
    }

    #[test]
    fn a_socket_that_did_not_ask_gets_no_unread_bytes_report() {
        let mut bytes = [0u8; 32];
        let user = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0,
            control: bytes.as_mut_ptr() as u64, controllen: bytes.len(),
            iov: Vec::new(), capacity: 0 };
        let mut control = Control::new(bytes.len());
        control.push_inq(None);
        assert_eq!(control.copy_to(&user).unwrap(), 0);
    }

    #[test]
    fn recv_output_preserves_cmsg_cloexec_only() {
        assert_eq!(output_flags(MSG_CMSG_CLOEXEC | net::uapi::MSG_PEEK), MSG_CMSG_CLOEXEC as u32);
        assert_eq!(output_flags(net::uapi::MSG_PEEK), 0);
    }
}
