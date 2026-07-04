use alloc::sync::Arc;
use alloc::vec::Vec;

use hal::USER_VA_END;
use vfs::File;

pub(super) const SOL_SOCKET: i32 = 1;
pub(super) const SCM_RIGHTS: i32 = 1;

/// Parse a control buffer of length `len` for SCM_RIGHTS cmsgs;
/// returns Arc<File> refs for every fd in caller's fd_table. Bogus
/// fds → silently skipped (Linux returns -EBADF if ANY is bad, but
/// v1 simplifies; tighten later).
/// # C: O(controllen)
pub fn parse_scm_rights(control: u64, controllen: u64) -> Vec<Arc<File>> {
    let mut out: Vec<Arc<File>> = Vec::new();
    let cur = sched::live::current();
    // SAFETY: caller is the currently running task — sole reader of fd_table.
    let fdt = match cur.as_ref().and_then(|c| unsafe { c.fd_table_ref() }) {
        Some(t) => t.clone(),
        None => return out,
    };
    let mut off: u64 = 0;
    while off + 16 <= controllen {
        let base = control + off;
        if base + 16 > USER_VA_END { break; }
        // SAFETY: base validated < USER_VA_END − 16; cmsghdr is 8-byte aligned per ABI.
        let (cmsg_len, cmsg_level, cmsg_type) = unsafe {
            (
                core::ptr::read_volatile(base as *const u64),
                core::ptr::read_volatile((base + 8) as *const i32),
                core::ptr::read_volatile((base + 12) as *const i32),
            )
        };
        if cmsg_len < 16 || cmsg_len > controllen - off { break; }
        if cmsg_level == SOL_SOCKET && cmsg_type == SCM_RIGHTS {
            let nfds = ((cmsg_len - 16) / 4) as u64;
            for i in 0..nfds {
                // SAFETY: data area inside cmsg bounded by cmsg_len.
                let fd = unsafe { core::ptr::read_volatile((base + 16 + i * 4) as *const i32) };
                if let Ok(f) = fdt.get(fd) { out.push(f); }
            }
        }
        off += (cmsg_len + 7) & !7;
    }
    out
}
