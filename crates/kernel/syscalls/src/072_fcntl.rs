// 072 fcntl — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;

/// `sys_fcntl(fd, cmd, arg)` — slot 72. F_DUPFD / F_DUPFD_CLOEXEC /
/// F_GETFD / F_SETFD / F_GETFL / F_SETFL / F_GETPIPE_SZ /
/// F_SETPIPE_SZ / F_GETOWN / F_SETOWN; F_SETLK / F_SETLKW / F_GETLK
/// + F_OFD_* via `handle_record_lock`.
/// # C: O(1) per cmd; O(N_fds) for F_DUPFD.
pub fn sys_fcntl(args: &SyscallArgs) -> i64 {
    const F_DUPFD: u64 = 0; const F_GETFD: u64 = 1; const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3; const F_SETFL: u64 = 4;
    const F_GETLK: u64 = 5; const F_SETLK: u64 = 6; const F_SETLKW: u64 = 7;
    const F_OFD_GETLK: u64 = 36; const F_OFD_SETLK: u64 = 37; const F_OFD_SETLKW: u64 = 38;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const F_GETPIPE_SZ: u64 = 1032; const F_SETPIPE_SZ: u64 = 1031;
    const F_ADD_SEALS: u64 = 1033; const F_GET_SEALS: u64 = 1034;
    const F_SEAL_SEAL: u32 = 0x0001;
    const F_GETOWN: u64 = 9; const F_SETOWN: u64 = 8;
    const SETTABLE_FL: u32 = 0o4_004_000 | 0o0_004_000; // O_APPEND | O_NONBLOCK
    let fd = args.a0 as i32; let cmd = args.a1; let arg = args.a2;
    let ebadf = -(Errno::Ebadf.as_i32() as i64);
    let cur = match sched::live::current() { Some(c) => c, None => return ebadf };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return ebadf };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return ebadf };
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => match fdt.dup_min(fd, arg as i32) {
            Ok(n) => { if cmd == F_DUPFD_CLOEXEC { let _ = fdt.set_cloexec(n, true); } n as i64 }
            Err(e) => -(e as i64),
        },
        F_GETFD => match fdt.cloexec(fd) { Ok(true) => 1, Ok(false) => 0, Err(_) => 0 },
        F_SETFD => { let _ = fdt.set_cloexec(fd, (arg & 1) != 0); 0 }
        F_GETFL => file.flags().bits() as i64,
        F_SETFL => {
            let nb = (file.flags().bits() & !SETTABLE_FL) | ((arg as u32) & SETTABLE_FL);
            file.set_flags(vfs::OpenFlags::from_bits_retain(nb));
            0
        }
        F_GETPIPE_SZ | F_SETPIPE_SZ => 4096,
        // memfd seals (`fcntl.h`, docs/19). Only a sealable memfd exposes
        // seals; everything else → EINVAL.
        F_GET_SEALS => match file.inode().fcntl_seals() {
            Some(s) => s.load(core::sync::atomic::Ordering::Acquire) as i64,
            None    => -(Errno::Einval.as_i32() as i64),
        },
        F_ADD_SEALS => match file.inode().fcntl_seals() {
            Some(s) => {
                use core::sync::atomic::Ordering;
                let cur_seals = s.load(Ordering::Acquire);
                // F_SEAL_SEAL already set ⇒ no further sealing (EPERM).
                if cur_seals & F_SEAL_SEAL != 0 { return -(Errno::Eperm.as_i32() as i64); }
                s.fetch_or(arg as u32, Ordering::AcqRel);
                0
            }
            None => -(Errno::Einval.as_i32() as i64),
        },
        F_GETOWN => file.owner.load(core::sync::atomic::Ordering::Acquire) as i64,
        F_SETOWN => { file.owner.store(arg as i32, core::sync::atomic::Ordering::Release); 0 }
        F_SETLK | F_SETLKW | F_GETLK |
        F_OFD_SETLK | F_OFD_SETLKW | F_OFD_GETLK => {
            handle_record_lock(&cur, &fdt, &file, cmd, arg)
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

/// F_SETLK / F_SETLKW / F_GETLK + F_OFD_* dispatch via
/// `fs::posix_lock`. SETLKW spins on EAGAIN until success;
/// GETLK probes and writes back.
/// # C: O(1) per probe; SETLKW O(spins) until peer releases.
fn handle_record_lock(
    cur: &sched::Task,
    _fdt: &alloc::sync::Arc<vfs::FdTable>,
    file: &alloc::sync::Arc<vfs::File>,
    cmd: u64,
    arg: u64,
) -> i64 {
    use fs::posix_lock::{decode_flock, encode_flock, probe, try_set_lock, Owner, FLOCK_BYTES};
    const F_GETLK: u64 = 5; const F_SETLK: u64 = 6; const F_SETLKW: u64 = 7;
    const F_OFD_GETLK: u64 = 36; const F_OFD_SETLK: u64 = 37; const F_OFD_SETLKW: u64 = 38;
    if let Err(rv) = validate_user_buf(arg, FLOCK_BYTES as u64, 8) { return rv; }
    let mut bytes = [0u8; FLOCK_BYTES];
    // SAFETY: arg validated FLOCK_BYTES below USER_VA_END; CPL=0 reads through caller's AS.
    unsafe {
        for i in 0..FLOCK_BYTES {
            bytes[i] = core::ptr::read_volatile((arg + i as u64) as *const u8);
        }
    }
    let cur_pos  = file.pos();
    let file_sz  = file.inode().size();
    let mut req  = match decode_flock(&bytes, cur_pos, file_sz) {
        Ok(r) => r, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let is_ofd = matches!(cmd, F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW);
    let owner = if is_ofd {
        Owner::Ofd(alloc::sync::Arc::as_ptr(file) as *const u8 as usize)
    } else {
        Owner::Pid(cur.tid)
    };
    let inode = file.inode();
    match cmd {
        F_GETLK | F_OFD_GETLK => {
            req.pid = match owner { Owner::Pid(p) => p, _ => 0 };
            match probe(inode, &req, owner) {
                Some(blk) => {
                    let mut out = [0u8; FLOCK_BYTES];
                    encode_flock(&mut out, &blk);
                    // SAFETY: arg validated above; CPL=0 writes through caller's AS.
                    unsafe {
                        for i in 0..FLOCK_BYTES {
                            core::ptr::write_volatile((arg + i as u64) as *mut u8, out[i]);
                        }
                    }
                }
                None => {
                    // No conflict — return F_UNLCK in l_type.
                    let mut out = bytes;
                    out[0..2].copy_from_slice(&(fs::posix_lock::F_UNLCK).to_le_bytes());
                    // SAFETY: arg validated above; CPL=0 writes through caller's AS.
                    unsafe {
                        for i in 0..FLOCK_BYTES {
                            core::ptr::write_volatile((arg + i as u64) as *mut u8, out[i]);
                        }
                    }
                }
            }
            0
        }
        F_SETLK | F_OFD_SETLK => {
            match try_set_lock(inode, &req, owner) {
                Ok(()) => 0,
                Err(e) => -(e as i64),
            }
        }
        F_SETLKW | F_OFD_SETLKW => {
            // Spin-yield until peer releases (real wait list rides
            // a follow-up).
            loop {
                match try_set_lock(inode, &req, owner) {
                    Ok(()) => return 0,
                    Err(vfs::VfsError::Eagain) => {
                        // SAFETY: process ctx; preempt-off; runqueue installed; voluntary schedule() yields the CPU; we stay Runnable so the scheduler picks us back up shortly.
                        unsafe { sched::live::schedule::schedule(); }
                    }
                    Err(e) => return -(e as i64),
                }
            }
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}
