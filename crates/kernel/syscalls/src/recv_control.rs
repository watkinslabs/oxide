use alloc::vec::Vec;

use net::uapi::{MSG_CMSG_CLOEXEC, MSG_CTRUNC};
// `deliver` (the only fd-passing consumer) is kernel-gated.
#[cfg(target_os = "oxide-kernel")]
use alloc::sync::Arc;
#[cfg(target_os = "oxide-kernel")]
use vfs::File;

use crate::msg_layout::{MsgLayout, cmsg};
use crate::recv_user::RecvUser;

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


/// One control-stream copyout: how far the cursor advanced, and whether an
/// entry faulted. The two are independent — the entries that landed before a
/// faulting one keep their space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControlCopy {
    pub copied: usize,
    pub faulted: bool,
}

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

    /// Emit queued cmsgs through one Linux-style advancing cursor. The option
    /// ABI wants a fault to be the answer; the receive ABI does not, and asks
    /// [`copy_to_recv`](Self::copy_to_recv) instead.
    /// # C: O(entries + data + faults)
    pub fn copy_to(&mut self, user: &RecvUser) -> Result<usize, i64> {
        let copy = self.copy_to_at(user, 0);
        if copy.faulted { return Err(errno(syscall::errno::Errno::Efault)); }
        Ok(copy.copied)
    }

    /// Emit receive ancillary data, applying the receive fault rule owned by
    /// [`crate::recv_txn`]. # C: O(entries + data + faults)
    pub fn copy_to_recv(&mut self, user: &RecvUser) -> usize {
        let copy = self.copy_to_at(user, 0);
        crate::recv_txn::control_len(copy)
    }

    /// Emit the control stream at the option ABI's raw user pointer. # C: O(entries + data + faults)
    pub fn copy_to_raw(&mut self, control: u64) -> Result<usize, i64> {
        self.copy_to(&RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0,
            control, controllen: self.cap, iov: Vec::new(), capacity: 0, layout: MsgLayout::Native })
    }

    /// One entry at a time, exactly as Linux's `put_cmsg` cursor runs: an
    /// entry that faults advances nothing and ends the stream, and every entry
    /// that already landed keeps the space it took. # C: O(entries + data + faults)
    fn copy_to_at(&mut self, user: &RecvUser, at: usize) -> ControlCopy {
        self.copy_stream(user.layout, user.control, at,
            |dst, bytes| uaccess::copy_to_user(dst, bytes).is_ok())
    }

    /// The cursor itself, with the byte move left to the caller so the
    /// composition is checkable against a scripted fault. # C: O(entries + data)
    fn copy_stream<W>(&mut self, layout: MsgLayout, base: u64, at: usize, mut write: W)
        -> ControlCopy
    where W: FnMut(u64, &[u8]) -> bool
    {
        let mut copied = 0usize;
        for (level, ty, data) in &self.entries {
            let Some((entry, advance, truncated)) =
                encode_entry(layout, *level, *ty, data, self.cap.saturating_sub(copied))
            else { self.flags |= MSG_CTRUNC as u32; continue; };
            if truncated { self.flags |= MSG_CTRUNC as u32; }
            let Some(dst) = base.checked_add(at.saturating_add(copied) as u64) else { continue; };
            if !write(dst, &entry) { return ControlCopy { copied, faulted: true }; }
            copied += advance;
        }
        ControlCopy { copied, faulted: false }
    }

    /// The same stream as one buffer, for the option read that publishes a
    /// control stream instead of a value. # C: O(entries + data)
    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for (level, ty, data) in &self.entries {
            let Some((entry, advance, truncated)) =
                encode_entry(MsgLayout::Native, *level, *ty, data,
                    self.cap.saturating_sub(out.len()))
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
/// A 32-bit receiver is handed a 12-byte header on a 4-byte grid; the
/// truncation arithmetic is otherwise identical. # C: O(data)
fn encode_entry(layout: MsgLayout, level: i32, ty: i32, data: &[u8], remaining: usize)
    -> Option<(Vec<u8>, usize, bool)>
{
    let hdr = layout.cmsghdr_size();
    if remaining < hdr { return None; }
    let full_len = hdr + data.len();
    let advance = core::cmp::min(layout.cmsg_aligned(full_len), remaining);
    let data_len = core::cmp::min(data.len(), remaining - hdr);
    let cmsg_len = hdr + data_len;
    let mut entry = cmsg::header_bytes(layout, cmsg_len, level, ty);
    entry.extend_from_slice(&data[..data_len]);
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
    inq: Option<InqCmsg>, protocol: &[(i32, i32, &[u8])], recv_flags: u64)
    -> Result<DeliveredControl, i64>
{
    let mut flags = output_flags(recv_flags);
    let cap = if user.control == 0 { 0 } else { user.controllen };
    let mut control = Control::new(cap);
    for (level, ty, data) in protocol { control.push(*level, *ty, data); }
    if let Some(cred) = scm.credentials { control.push(SOL_SOCKET, SCM_CREDENTIALS, &cred_bytes(cred)); }
    if let Some(label) = scm.security.as_deref() { control.push(SOL_SOCKET, SCM_SECURITY, label); }
    control.push_inq(inq);
    let mut off = control.copy_to_recv(user);
    flags |= control.flags;
    let hdr = user.layout.cmsghdr_size();
    let remaining = cap.saturating_sub(off);
    let rights_cap = remaining.saturating_sub(hdr) / 4;
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
            let dst = user.control.checked_add((off + hdr + index * 4) as u64);
            let dst = dst.ok_or(vfs::VfsError::Efault)?;
            // SAFETY: fd bytes are kernel-owned; raw usercopy reports a fault without losing prefix state.
            let left = unsafe { uaccess::raw_copy_to_user(dst, fd.to_ne_bytes().as_ptr(), 4) };
            if left == 0 { Ok(()) } else { Err(vfs::VfsError::Efault) }
        });
    if result.truncated { flags |= MSG_CTRUNC as u32; }
    let installed = result.installed;
    if installed != 0 {
        let rights_len = hdr + installed * 4;
        let rights_space = core::cmp::min(user.layout.cmsg_aligned(rights_len), cap - off);
        let header = cmsg::header_bytes(user.layout, rights_len, SOL_SOCKET, SCM_RIGHTS);
        let header_ok = user.control.checked_add(off as u64)
            .is_some_and(|base| uaccess::copy_to_user(base, &header).is_ok());
        if header_ok { off += rights_space; }
    }
    if scm.want_pidfd {
        if cap.saturating_sub(off) < hdr + core::mem::size_of::<i32>() {
            flags |= MSG_CTRUNC as u32;
        } else if let Some(identity) = scm.pid {
            let current = sched::live::current();
            let prepared = current.as_ref().and_then(|task|
                pidfd::prepare(task, identity, pidfd::OpenOptions::default()).ok());
            let fd = prepared.as_ref().map_or(-1, pidfd::Prepared::fd);
            let mut pidfd = Control::new(cap - off);
            pidfd.push(SOL_SOCKET, SCM_PIDFD, &fd.to_ne_bytes());
            let copied = crate::recv_txn::control_len(pidfd.copy_to_at(user, off));
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

    /// The native `sizeof(struct cmsghdr)`, which these tests assert against.
    const CMSG_HDR: usize = 16;

    fn aligned(n: usize) -> usize { MsgLayout::Native.cmsg_aligned(n) }

    #[test]
    fn truncated_cmsg_len_describes_only_emitted_data() {
        let data = [0x5au8; 12];
        for cap in 0..=32 {
            let mut bytes = [0u8; 32];
            let user = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0, control: bytes.as_mut_ptr() as u64,
                controllen: cap, iov: Vec::new(), capacity: 0, layout: MsgLayout::Native };
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
            controllen: bytes.len(), iov: Vec::new(), capacity: 0, layout: MsgLayout::Native };
        let mut control = Control::new(bytes.len());
        control.push(SOL_SOCKET, SCM_CREDENTIALS, &[0x5a; 12]);

        assert_eq!(control.copy_to(&user).unwrap(), 32, "cursor advances through CMSG_SPACE");
        assert_eq!(&bytes[28..], &[0xa5; 4], "put_cmsg never touches alignment padding");
    }

    #[test]
    fn socket_security_follows_credentials_in_the_one_control_cursor() {
        let mut bytes = [0u8; 64];
        let user = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0,
            control: bytes.as_mut_ptr() as u64, controllen: bytes.len(), iov: Vec::new(), capacity: 0, layout: MsgLayout::Native };
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
                iov: Vec::new(), capacity: 0, layout: MsgLayout::Native };
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
            iov: Vec::new(), capacity: 0, layout: MsgLayout::Native };
        let mut control = Control::new(bytes.len());
        control.push_inq(None);
        assert_eq!(control.copy_to(&user).unwrap(), 0);
    }

    #[test]
    fn recv_output_preserves_cmsg_cloexec_only() {
        assert_eq!(output_flags(MSG_CMSG_CLOEXEC | net::uapi::MSG_PEEK), MSG_CMSG_CLOEXEC as u32);
        assert_eq!(output_flags(net::uapi::MSG_PEEK), 0);
    }

    // A 32-bit receiver is handed 12-byte headers on a 4-byte grid. Emitting
    // the native shape into its buffer would put the level and type where its
    // `CMSG_DATA` starts, and advance the cursor past entries it never sees.
    #[test]
    fn a_compat_receiver_gets_twelve_byte_headers_on_the_four_byte_grid() {
        let mut bytes = [0xa5u8; 64];
        let user = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0,
            control: bytes.as_mut_ptr() as u64, controllen: bytes.len(), iov: Vec::new(),
            capacity: 0, layout: MsgLayout::Compat };
        let mut control = Control::new(bytes.len());
        control.push(SOL_SOCKET, SCM_CREDENTIALS, &[1u8; 12]);
        control.push(SOL_SOCKET, SCM_SECURITY, b"t");
        // CMSG_SPACE(12) = 24 and CMSG_SPACE(1) = 16 in the 32-bit ABI;
        // natively the same two entries would take 32 and 24.
        assert_eq!(control.copy_to(&user).unwrap(), 40);
        assert_eq!(u32::from_ne_bytes(bytes[..4].try_into().unwrap()), 24);
        assert_eq!(i32::from_ne_bytes(bytes[4..8].try_into().unwrap()), SOL_SOCKET);
        assert_eq!(i32::from_ne_bytes(bytes[8..12].try_into().unwrap()), SCM_CREDENTIALS);
        assert_eq!(&bytes[12..24], &[1u8; 12]);
        assert_eq!(u32::from_ne_bytes(bytes[24..28].try_into().unwrap()), 13);
        assert_eq!(i32::from_ne_bytes(bytes[28..32].try_into().unwrap()), SOL_SOCKET);
        assert_eq!(i32::from_ne_bytes(bytes[32..36].try_into().unwrap()), SCM_SECURITY);
        assert_eq!(&bytes[36..37], b"t");
        assert_eq!(control.flags & MSG_CTRUNC as u32, 0);
    }

    // The truncation arithmetic follows the receiver's own header size: a
    // buffer that holds a native header but not a native entry still holds a
    // complete compat one.
    #[test]
    fn compat_truncation_is_measured_against_the_compat_header() {
        let mut bytes = [0u8; 32];
        for cap in 0..=16usize {
            let user = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0,
                control: bytes.as_mut_ptr() as u64, controllen: cap, iov: Vec::new(),
                capacity: 0, layout: MsgLayout::Compat };
            let mut control = Control::new(cap);
            control.push(SOL_SOCKET, SCM_CREDENTIALS, &[0u8; 4]);
            let copied = control.copy_to(&user).unwrap();
            assert_eq!(copied, if cap < 12 { 0 } else { core::cmp::min(16, cap) }, "cap={cap}");
            assert_eq!(control.flags & MSG_CTRUNC as u32 != 0, cap < 16, "cap={cap}");
        }
    }

    /// Three entries, with the byte move scripted to fail on the `fail_at`th.
    /// Returns the cursor answer and which entries the cursor tried to write.
    fn scripted(fail_at: usize, cap: usize) -> (Control, ControlCopy, Vec<usize>) {
        let mut control = Control::new(cap);
        control.push(SOL_SOCKET, SCM_CREDENTIALS, &[1u8; 4]);
        control.push(SOL_SOCKET, SCM_SECURITY, &[2u8; 4]);
        control.push(SOL_SOCKET, SCM_PIDFD, &[3u8; 4]);
        let mut attempts = Vec::new();
        let copy = control.copy_stream(MsgLayout::Native, 0x1000, 0, |_, _| {
            attempts.push(attempts.len());
            attempts.len() - 1 != fail_at
        });
        (control, copy, attempts)
    }

    // A control entry that faults ends the stream and advances nothing, and
    // every entry that already landed keeps the space it took. Losing that
    // prefix would report a `msg_controllen` of zero for a buffer that holds
    // one complete control message.
    #[test]
    fn a_faulting_control_entry_keeps_the_prefix_that_landed() {
        let one = aligned(CMSG_HDR + 4);
        for (fail_at, expect) in [(0usize, 0usize), (1, one), (2, one * 2)] {
            let (_, copy, attempts) = scripted(fail_at, one * 3);
            assert_eq!(copy, ControlCopy { copied: expect, faulted: true }, "fail_at={fail_at}");
            assert_eq!(attempts.len(), fail_at + 1, "the stream stops at the fault");
        }
    }

    // The receive ABI never fails for a control fault; the option ABI, which
    // publishes a control stream as its whole answer, always does.
    #[test]
    fn the_two_control_abis_answer_a_fault_differently() {
        let user = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0, control: 0,
            controllen: 64, iov: Vec::new(), capacity: 0, layout: MsgLayout::Native };
        let mut control = Control::new(64);
        control.push(SOL_SOCKET, SCM_CREDENTIALS, &[0u8; 4]);
        assert_eq!(control.copy_to(&user), Err(errno(syscall::errno::Errno::Efault)));
        let mut control = Control::new(64);
        control.push(SOL_SOCKET, SCM_CREDENTIALS, &[0u8; 4]);
        assert_eq!(control.copy_to_recv(&user), 0);
    }

    // A truncated entry raises `MSG_CTRUNC` before its bytes are attempted, so
    // an entry that is both cut short and unwritable still reports the flag —
    // the receive survives the fault and publishes `msg_flags`.
    #[test]
    fn truncation_is_reported_even_when_the_same_entry_faults() {
        let mut control = Control::new(CMSG_HDR + 2);
        control.push(SOL_SOCKET, SCM_CREDENTIALS, &[0u8; 8]);
        let copy = control.copy_stream(MsgLayout::Native, 0x1000, 0, |_, _| false);
        assert!(copy.faulted);
        assert_eq!(copy.copied, 0);
        assert_ne!(control.flags & MSG_CTRUNC as u32, 0);
    }
}
