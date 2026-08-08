// 275 splice / 276 tee / 278 vmsplice — one file (docs/53 §0). ABI shim only:
// fd resolution, the `loff_t __user *` copy-in/copy-out, and the iovec import.
// Every transfer rule is `fs::splice`.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::rwf::UIO_MAXIOV;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Resolve one fd to its open file description. # C: O(1)
fn fd_file(fd: i32) -> Result<alloc::sync::Arc<vfs::File>, i64> {
    let cur = sched::live::current().ok_or(errno(Errno::Ebadf))?;
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; Arc clone.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(errno(Errno::Ebadf))?.clone();
    fdt.get(fd).map_err(|_| errno(Errno::Ebadf))
}

/// Read a `loff_t __user *`. `NULL` stays `None` — the distinction drives the
/// whole offset contract. # C: O(1)
fn get_loff(ptr: u64) -> Result<Option<u64>, i64> {
    if ptr == 0 { return Ok(None); }
    validate_user_buf(ptr, 8, 8)?;
    // SAFETY: `validate_user_buf` proved 8 readable, 8-aligned bytes at `ptr`
    // below USER_VA_END in the caller's active address space.
    Ok(Some(unsafe { core::ptr::read_volatile(ptr as *const u64) }))
}

/// Write a `loff_t __user *` back. # C: O(1)
fn put_loff(ptr: u64, v: u64) -> Result<(), i64> {
    validate_user_buf_writable(ptr, 8, 8)?;
    // SAFETY: `validate_user_buf_writable` proved 8 writable, 8-aligned bytes
    // at `ptr` below USER_VA_END in the caller's active address space.
    unsafe { core::ptr::write_volatile(ptr as *mut u64, v); }
    Ok(())
}

/// `sys_splice(fd_in, off_in, fd_out, off_out, len, flags)` — slot 275.
///
/// Order is Linux's: `len == 0` returns 0 BEFORE any
/// fd or flag validation, then the flag word, then the two fd lookups.
/// # C: O(len)
pub fn sys_splice(args: &SyscallArgs) -> i64 {
    let len = args.a4 as usize;
    if len == 0 { return 0; }
    if args.a5 & !::fs::splice::SPLICE_F_ALL != 0 { return errno(Errno::Einval); }
    let in_file  = match fd_file(args.a0 as i32) { Ok(f) => f, Err(e) => return e };
    let out_file = match fd_file(args.a2 as i32) { Ok(f) => f, Err(e) => return e };
    // `__do_splice` copies the offsets in AFTER the ESPIPE tests, which the
    // work-fn owns; passing `Some(_)` merely records "a pointer was supplied",
    // so an ESPIPE for a pipe end still precedes any EFAULT on that pointer.
    let (in_off_ptr, out_off_ptr) = (args.a1, args.a3);
    let mut in_off = match get_loff(in_off_ptr) { Ok(v) => v, Err(e) => return e };
    let mut out_off = match get_loff(out_off_ptr) { Ok(v) => v, Err(e) => return e };
    let ret = ::fs::splice::do_splice(&in_file, in_off.as_mut(),
                                      &out_file, out_off.as_mut(), len, args.a5);
    if ret < 0 { return ret; }
    // Copy-out only on success.
    if let Some(v) = in_off { if let Err(e) = put_loff(in_off_ptr, v) { return e; } }
    if let Some(v) = out_off { if let Err(e) = put_loff(out_off_ptr, v) { return e; } }
    ret
}

/// `sys_tee(fd_in, fd_out, len, flags)` — slot 276. Flags are validated BEFORE
/// the `len == 0` short-circuit here, the reverse of `splice`.
/// # C: O(len)
pub fn sys_tee(args: &SyscallArgs) -> i64 {
    if args.a3 & !::fs::splice::SPLICE_F_ALL != 0 { return errno(Errno::Einval); }
    let len = args.a2 as usize;
    if len == 0 { return 0; }
    let in_file  = match fd_file(args.a0 as i32) { Ok(f) => f, Err(e) => return e };
    let out_file = match fd_file(args.a1 as i32) { Ok(f) => f, Err(e) => return e };
    ::fs::splice::do_tee(&in_file, &out_file, len, args.a3)
}

/// `sys_vmsplice(fd, iov, nr_segs, flags)` — slot 278. The direction comes from
/// `f_mode`, so the iovec is imported as a SOURCE or
/// a DESTINATION accordingly — reading the caller's pages for `ToPipe`,
/// writing them for `ToUser`. # C: O(sum of iov lens)
pub fn sys_vmsplice(args: &SyscallArgs) -> i64 {
    let iov = args.a1;
    let nr  = args.a2;
    let flags = args.a3;
    if flags & !::fs::splice::SPLICE_F_ALL != 0 { return errno(Errno::Einval); }
    let file = match fd_file(args.a0 as i32) { Ok(f) => f, Err(e) => return e };
    let dir = match ::fs::splice::vmsplice_dir(
        file.f_mode().contains(vfs::Fmode::WRITE),
        file.f_mode().contains(vfs::Fmode::READ),
    ) { Ok(d) => d, Err(e) => return errno(e) };
    if nr > UIO_MAXIOV { return errno(Errno::Einval); }
    let ranges = match import_iov(iov, nr, dir == ::fs::splice::VmspliceDir::ToUser) {
        Ok(r) => r, Err(e) => return e,
    };
    match dir {
        ::fs::splice::VmspliceDir::ToPipe => {
            let bufs: Vec<&[u8]> = ranges.iter().map(|&(b, l)| {
                // SAFETY: `import_iov` proved [b, b+l) readable in the caller's
                // address space below USER_VA_END.
                unsafe { core::slice::from_raw_parts(b as *const u8, l) }
            }).collect();
            ::fs::splice::do_vmsplice_to_pipe(&file, &bufs, flags)
        }
        ::fs::splice::VmspliceDir::ToUser => {
            let mut bufs: Vec<&mut [u8]> = ranges.iter().map(|&(b, l)| {
                // SAFETY: `import_iov` proved [b, b+l) writable in the caller's
                // address space below USER_VA_END; the ranges are distinct
                // iovec segments so the mutable borrows do not alias.
                unsafe { core::slice::from_raw_parts_mut(b as *mut u8, l) }
            }).collect();
            ::fs::splice::do_vmsplice_to_user(&file, &mut bufs, flags)
        }
    }
}

/// `import_iovec` for `vmsplice`: validates the array then each segment, in the
/// direction the transfer needs, applying the same negative-length EINVAL and
/// `MAX_RW_COUNT` truncation as the read/write vector path. # C: O(nr)
fn import_iov(iov: u64, nr: u64, writable: bool) -> Result<Vec<(u64, usize)>, i64> {
    let mut out: Vec<(u64, usize)> = Vec::new();
    if nr == 0 { return Ok(out); }
    let array_bytes = nr.checked_mul(16).ok_or(errno(Errno::Efault))?;
    validate_user_buf(iov, array_bytes, 8)?;
    let mut total: u64 = 0;
    for i in 0..nr {
        let e = iov + i * 16;
        // SAFETY: the whole iovec array was validated readable above; `e` is
        // inside it and 8-byte aligned per the Linux `struct iovec` ABI.
        let base = unsafe { core::ptr::read_volatile(e as *const u64) };
        // SAFETY: same validated array; `iov_len` sits at +8 within the entry.
        let len  = unsafe { core::ptr::read_volatile((e + 8) as *const u64) };
        if (len as i64) < 0 { return Err(errno(Errno::Einval)); }
        if len == 0 { continue; }
        if writable { validate_user_buf_writable(base, len, 1)?; } else { validate_user_buf(base, len, 1)?; }
        let room = crate::rwf::MAX_RW_COUNT.saturating_sub(total);
        if room == 0 { break; }
        let capped = len.min(room);
        total += capped;
        out.push((base, capped as usize));
    }
    Ok(out)
}
