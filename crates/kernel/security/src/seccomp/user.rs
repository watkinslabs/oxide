// User-memory access for the seccomp install path. The `security` crate
// carries no `uaccess` dependency, so range validation against `USER_VA_END`
// plus volatile access is the crate-local idiom (same shape as `bpf/user.rs`).
// Nothing here decides an errno beyond EFAULT; the ladder lives in
// `install.rs`.

use alloc::vec::Vec;
use hal::USER_VA_END;
use syscall::errno::Errno;

use super::insn::SockFilter;
use super::uapi::*;

/// `-EFAULT` unless `[ptr, ptr+len)` lies entirely in user VA.
/// # C: O(1)
fn range_ok(ptr: u64, len: u64) -> Result<(), Errno> {
    if ptr == 0 { return Err(Errno::Efault); }
    match ptr.checked_add(len) {
        Some(end) if end <= USER_VA_END => Ok(()),
        _ => Err(Errno::Efault),
    }
}

/// `copy_from_user(&fprog, user_filter, sizeof(fprog))` — `struct sock_fprog
/// { unsigned short len; struct sock_filter *filter; }`, 16 bytes on 64-bit
/// with the pointer at offset 8.
/// # C: O(1)
pub fn read_fprog(uptr: u64) -> Result<(u16, u64), Errno> {
    range_ok(uptr, SOCK_FPROG_BYTES)?;
    // SAFETY: range_ok proved uptr..uptr+16 is user VA under the caller's live address space; volatile reads of the two sock_fprog members on the syscall path.
    let (len, filter) = unsafe {
        (core::ptr::read_volatile(uptr as *const u16),
         core::ptr::read_volatile((uptr + SOCK_FPROG_FILTER_OFF) as *const u64))
    };
    Ok((len, filter))
}

/// Copy `len` `struct sock_filter` entries into the packed-u64 form the
/// interpreter runs. Caller has already bounded `len` by `BPF_MAXINSNS`.
/// # C: O(len)
pub fn read_prog(filter_p: u64, len: usize) -> Result<Vec<u64>, Errno> {
    let bytes = (len as u64).checked_mul(SOCK_FILTER_BYTES).ok_or(Errno::Efault)?;
    range_ok(filter_p, bytes)?;
    let mut prog: Vec<u64> = Vec::with_capacity(len);
    for i in 0..len {
        let p = filter_p + (i as u64) * SOCK_FILTER_BYTES;
        // SAFETY: range_ok proved filter_p..filter_p+len*8 is user VA under the caller's live address space; each read stays inside that proven range on the syscall path.
        let f = unsafe {
            SockFilter::new(
                core::ptr::read_volatile(p as *const u16),
                core::ptr::read_volatile((p + 2) as *const u8),
                core::ptr::read_volatile((p + 3) as *const u8),
                core::ptr::read_volatile((p + 4) as *const u32))
        };
        prog.push(f.encode());
    }
    Ok(prog)
}

/// `copy_from_user(&action, uaction, sizeof(action))` for
/// `SECCOMP_GET_ACTION_AVAIL`.
/// # C: O(1)
pub fn read_u32(uptr: u64) -> Result<u32, Errno> {
    range_ok(uptr, 4)?;
    // SAFETY: range_ok proved uptr..uptr+4 is user VA under the caller's live address space; single volatile u32 read on the syscall path.
    Ok(unsafe { core::ptr::read_volatile(uptr as *const u32) })
}

/// `copy_to_user(usizes, &sizes, sizeof(sizes))` for
/// `SECCOMP_GET_NOTIF_SIZES`: `struct seccomp_notif_sizes { __u16
/// seccomp_notif, seccomp_notif_resp, seccomp_data; }`.
/// # C: O(1)
pub fn write_notif_sizes(uptr: u64, sizes: [u16; 3]) -> Result<(), Errno> {
    range_ok(uptr, 6)?;
    for (i, v) in sizes.iter().copied().enumerate() {
        // SAFETY: range_ok proved uptr..uptr+6 is user VA under the caller's live address space; each u16 store stays inside that proven range on the syscall path.
        unsafe { core::ptr::write_volatile((uptr + (i as u64) * 2) as *mut u16, v); }
    }
    Ok(())
}
