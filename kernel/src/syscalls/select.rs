// select / pselect6 extracted from syscall_glue_fs.rs to keep
// that file under the 1000-line cap (`08§7`). Both walk the fd_set
// bitmap and reuse the readability state the existing poll path
// consults; pselect6 simply forwards to select for v1 (sigmask +
// timespec extras are ignored on the non-blocking check).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// `sys_select(nfds, readfds, writefds, exceptfds, timeout)` — slot 23.
/// # C: O(nfds)
pub fn kernel_sys_select(args: &SyscallArgs) -> i64 {
    const NFDS_MAX: u64 = 4096;
    let nfds        = args.a0;
    let readfds_p   = args.a1;
    let writefds_p  = args.a2;
    let exceptfds_p = args.a3;
    let _timeout    = args.a4;
    if nfds > NFDS_MAX { return -(Errno::Einval.as_i32() as i64); }
    let bit_at = |p: u64, i: u64| -> bool {
        if p == 0 || p >= USER_VA_END { return false; }
        let byte_off = (i / 8) as u64;
        if byte_off >= 128 { return false; }
        // SAFETY: byte within the 128-byte fd_set; CPL=0 reads through caller's AS.
        let b = unsafe { core::ptr::read_volatile((p + byte_off) as *const u8) };
        (b & (1u8 << (i & 7))) != 0
    };
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    for &p in &[readfds_p, writefds_p, exceptfds_p] {
        if p != 0 && p < USER_VA_END {
            // SAFETY: 128-byte fd_set fits in user range; CPL=0 writes through caller's AS.
            unsafe {
                for i in 0..128usize {
                    core::ptr::write_volatile((p + i as u64) as *mut u8, 0);
                }
            }
        }
    }
    let mut ready: i64 = 0;
    for fd in 0..nfds {
        let want_read   = bit_at(readfds_p, fd);
        let want_write  = bit_at(writefds_p, fd);
        let want_except = bit_at(exceptfds_p, fd);
        if !(want_read || want_write || want_except) { continue; }
        let file = match fdt.get(fd as i32) { Ok(f) => f, Err(_) => continue };
        let mut got_read = false;
        let mut got_write = false;
        if file.inode().file_type() == vfs::FileType::CharDev {
            let ino = file.inode().ino();
            if (ino & 0xFFFF_0000) == 0x6000_0000 {
                let is_master = (ino & 0x8000) == 0;
                if let Some(pair) = crate::dev::pty::pair_for((ino & 0x7FFF) as u32) {
                    let r = pair.with_pair(|p| if is_master { p.master_readable() } else { p.slave_readable() });
                    got_read  = r;
                    got_write = true;
                }
            } else {
                got_read = true;
                got_write = true;
            }
        } else {
            got_read = true; got_write = true;
        }
        let mut hit = false;
        if want_read && got_read {
            set_bit(readfds_p, fd); hit = true;
        }
        if want_write && got_write {
            set_bit(writefds_p, fd); hit = true;
        }
        let _ = want_except;
        if hit { ready += 1; }
    }
    ready
}

#[inline]
fn set_bit(p: u64, i: u64) {
    if p == 0 || p >= USER_VA_END { return; }
    let byte_off = (i / 8) as u64;
    if byte_off >= 128 { return; }
    // SAFETY: byte within the 128-byte fd_set; CPL=0 read+write through caller's AS.
    unsafe {
        let b = core::ptr::read_volatile((p + byte_off) as *const u8);
        core::ptr::write_volatile((p + byte_off) as *mut u8, b | (1u8 << (i & 7)));
    }
}

/// `sys_pselect6(nfds, r, w, e, timeout, sigmask_pair)` — slot 270.
/// # C: O(nfds)
pub fn kernel_sys_pselect6(args: &SyscallArgs) -> i64 {
    kernel_sys_select(args)
}
