// AF_UNIX SOCK_DGRAM cmsg writeback helper (F122). Split out of
// `syscall_glue_net.rs` to keep that file under the 1000-line cap.
//
// recvmsg on a UnixDgram socket pops one message from the per-socket
// queue, copies its payload across the supplied iovecs, and (when
// msg_control is provided) writes a single SCM_CREDENTIALS cmsg with
// the sender's (pid, uid, gid). SCM_RIGHTS rides v2 (Arc<File> capture).
//
// Linux msghdr layout (x86_64):
//   +0  msg_name        u64
//   +8  msg_namelen     u32 + pad
//   +16 msg_iov         u64
//   +24 msg_iovlen      u64
//   +32 msg_control     u64
//   +40 msg_controllen  u64
//   +48 msg_flags       i32 + pad

#![no_std]

extern crate alloc;

use syscall::errno::Errno;
use hal::USER_VA_END;
use dev_net::{InetSocket, SockKind};

/// # C: O(iov)
pub fn recvmsg_unix_dgram(sock: &alloc::sync::Arc<InetSocket>, msgp: u64) -> i64 {
    let q = match &*sock.kind.lock() {
        SockKind::UnixDgram(q) => q.clone(),
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    let msg = match q.pop() {
        Some(m) => m, None => return -(Errno::Eagain.as_i32() as i64),
    };
    // SAFETY: msgp validated < USER_VA_END at caller; reads four 8-byte fields from msghdr at offsets 16/24/32/40 through caller's AS.
    let (iov, iovlen, control, controllen) = unsafe {
        (core::ptr::read_volatile((msgp + 16) as *const u64),
         core::ptr::read_volatile((msgp + 24) as *const u64),
         core::ptr::read_volatile((msgp + 32) as *const u64),
         core::ptr::read_volatile((msgp + 40) as *const u64))
    };
    let mut written = 0usize;
    for i in 0..iovlen {
        if written >= msg.payload.len() { break; }
        let iov_i = iov + i * 16;
        if iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i+16 lies in the validated iov array per Linux ABI; reads are 8-byte-aligned u64 fields of struct iovec.
        let (base, len) = unsafe {
            (core::ptr::read_volatile(iov_i as *const u64),
             core::ptr::read_volatile((iov_i + 8) as *const u64))
        };
        if len == 0 { continue; }
        let take = core::cmp::min(len as usize, msg.payload.len() - written);
        // SAFETY: base+take falls within the user iov entry (validated by ABI); CPL=0 copy through caller AS.
        unsafe {
            core::ptr::copy_nonoverlapping(
                msg.payload.as_ptr().add(written),
                base as *mut u8,
                take,
            );
        }
        written += take;
    }
    // SCM_CREDENTIALS cmsg writeback (CMSG_LEN(ucred) = 16 + 12 = 28).
    if control != 0 && controllen >= 28 && control < USER_VA_END {
        const SOL_SOCKET: i32 = 1;
        const SCM_CREDENTIALS: i32 = 2;
        let (pid, uid, gid) = msg.creds;
        // SAFETY: control validated < USER_VA_END; caller's msghdr contract gives the writeback buffer permission.
        unsafe {
            core::ptr::write_volatile( control        as *mut u64, 28u64);
            core::ptr::write_volatile((control +  8)  as *mut i32, SOL_SOCKET);
            core::ptr::write_volatile((control + 12)  as *mut i32, SCM_CREDENTIALS);
            core::ptr::write_volatile((control + 16)  as *mut u32, pid);
            core::ptr::write_volatile((control + 20)  as *mut u32, uid);
            core::ptr::write_volatile((control + 24)  as *mut u32, gid);
            core::ptr::write_volatile((msgp + 40) as *mut u64, 28);
        }
    } else if control == 0 || controllen == 0 {
        if msgp + 40 < USER_VA_END {
            // SAFETY: msgp validated < USER_VA_END at entry; the +40 slot is the msg_controllen field.
            unsafe { core::ptr::write_volatile((msgp + 40) as *mut u64, 0); }
        }
    }
    written as i64
}
