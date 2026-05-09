// `sys_syslog` (slot 103, Linux klogctl) real impl — exposes the klog
// ring as a dmesg backend. Split out of `syscall_glue_proc.rs` to keep
// that file under the 1000-line cap (08§7).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_syslog(type, bufp, len)` — slot 103.
///
/// Supported types per `linux/kernel.h SYSLOG_ACTION_*`:
///   0 (CLOSE)        — accept; we have no per-task open state.
///   1 (OPEN)         — accept.
///   2 (READ)         — non-blocking read of newest log bytes.
///                      Blocking semantics ride a follow-up.
///   3 (READ_ALL)     — read tail (newest min(len, available) bytes).
///   4 (READ_CLEAR)   — same as READ_ALL; clear is a no-op (we don't
///                      truncate the cumulative `total` counter).
///   5 (CLEAR)        — accept; clearing the ring would lose forensic
///                      data we want during early-bring-up smokes.
///   6/7 (CONSOLE_OFF/ON), 8 (CONSOLE_LEVEL) — accept (no-op).
///   9 (SIZE_UNREAD)  — total bytes ever written, capped at ring size.
///   10 (SIZE_BUFFER) — ring-buffer capacity in bytes.
/// # C: O(len)
pub fn kernel_sys_syslog(args: &SyscallArgs) -> i64 {
    let kind = args.a0 as u32;
    let bufp = args.a1;
    let len  = args.a2 as usize;
    match kind {
        0 | 1 | 5 | 6 | 7 | 8 => 0,
        9 => {
            let total = klog::ring_total();
            let cap   = klog::ring_size();
            (if total < cap { total } else { cap }) as i64
        }
        10 => klog::ring_size() as i64,
        2 | 3 | 4 => {
            if bufp == 0 || bufp >= hal::USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            if len == 0 { return 0; }
            if bufp.checked_add(len as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
                return -(Errno::Efault.as_i32() as i64);
            }
            let total = klog::ring_total();
            let cursor = if total > len { total - len } else { 0 };
            let mut tmp = alloc::vec![0u8; len];
            let (n, _next) = klog::ring_read(cursor, &mut tmp);
            // SAFETY: bufp+len validated < USER_VA_END (range checked above); CPL=0 writes per-byte through caller AS into kernel-owned tmp data; n is bounded by tmp.len() == len.
            unsafe {
                for i in 0..n {
                    core::ptr::write_volatile((bufp + i as u64) as *mut u8, tmp[i]);
                }
            }
            n as i64
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}
