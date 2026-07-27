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
    const F_SEAL_SHRINK: u32 = 0x0002;
    const F_SEAL_GROW: u32 = 0x0004;
    const F_SEAL_WRITE: u32 = 0x0008;
    const F_SEAL_FUTURE_WRITE: u32 = 0x0010;
    const F_GETOWN: u64 = 9; const F_SETOWN: u64 = 8;
    const F_SETSIG: u64 = 10; const F_GETSIG: u64 = 11;
    const F_SETOWN_EX: u64 = 15; const F_GETOWN_EX: u64 = 16;
    // f_owner_ex.type (Linux fcntl.h): TID / PID / PGRP.
    const F_OWNER_TID: i32 = 0; const F_OWNER_PID: i32 = 1; const F_OWNER_PGRP: i32 = 2;
    // F_*LEASE / F_NOTIFY (Linux fcntl.h, asm-generic).
    const F_SETLEASE: u64 = 1024; const F_GETLEASE: u64 = 1025; const F_NOTIFY: u64 = 1026;
    // F_{GET,SET}_RW_HINT + the per-file variants (Linux fcntl.h). arg is a
    // pointer to a u64 RWH_WRITE_LIFE_* value (NOT_SET=0 … EXTREME=5).
    const F_GET_RW_HINT: u64 = 1035; const F_SET_RW_HINT: u64 = 1036;
    const F_GET_FILE_RW_HINT: u64 = 1037; const F_SET_FILE_RW_HINT: u64 = 1038;
    const RWH_WRITE_LIFE_EXTREME: u64 = 5;
    const O_ASYNC: u64 = 0o20000;
    // Lease types (== the l_type record-lock values): read / write / unlock.
    const F_RDLCK: i32 = 0; const F_WRLCK: i32 = 1; const F_UNLCK: i32 = 2;
    // dnotify F_NOTIFY DN_* event bits + DN_MULTISHOT (Linux fcntl.h).
    const DN_VALID: u32 = 0x0000_003f; // ACCESS|MODIFY|CREATE|DELETE|RENAME|ATTRIB
    const DN_MULTISHOT: u32 = 0x8000_0000;
    const NSIG: u64 = 64;
    let fd = args.a0 as i32; let cmd = args.a1; let arg = args.a2;
    let ebadf = -(Errno::Ebadf.as_i32() as i64);
    let cur = match sched::live::current() { Some(c) => c, None => return ebadf };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return ebadf };
    if matches!(cmd, F_DUPFD | F_DUPFD_CLOEXEC) {
        return match crate::fcntl_dup::duplicate_fd(
            &fdt, fd, arg as i32, cmd == F_DUPFD_CLOEXEC, cur.nofile_soft(),
        ) {
            Ok(n) => n as i64,
            Err(e) => -(e as i64),
        };
    }
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return ebadf };
    match cmd {
        F_GETFD => match fdt.cloexec(fd) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(e) => -(e as i64),
        },
        F_SETFD => match fdt.set_cloexec(fd, (arg & 1) != 0) {
            Ok(()) => 0,
            Err(e) => -(e as i64),
        },
        // F_GETFL: on 64-bit Linux every open implicitly carries O_LARGEFILE
        // (`include/linux/fcntl.h` force_o_largefile; the open path ORs it into
        // `f_flags`), so F_GETFL always reports it. OR it in here — O_LARGEFILE
        // is NOT in `SETFL_MASK`, so F_SETFL cannot clear it (Linux parity).
        F_GETFL => (file.flags() | vfs::OpenFlags::O_LARGEFILE).bits() as i64,
        F_SETFL => {
            // SETFL masking (preserve access mode + creation flags, update only
            // O_APPEND/O_NONBLOCK/O_DIRECT/O_NOATIME/O_ASYNC) lives in the VFS
            // work fn `File::set_fl` per `53§3`; the shim forwards the raw `arg`.
            // Toggling O_ASYNC calls the backend `f_op->fasync` when present;
            // absent fasync support is ignored here, unlike `ioctl(FIOASYNC)`.
            let was_async = file.is_async();
            let want_async = (arg & O_ASYNC) != 0;
            if want_async != was_async {
                match file.fasync(fd, want_async) {
                    Ok(()) => {
                        if want_async { sched::live::sigpend::install_sigio_hook(); }
                    }
                    Err(vfs::VfsError::Enotty) => {}
                    Err(e) => return -(e as i64),
                }
            }
            file.set_fl(vfs::OpenFlags::from_bits_retain(arg as u32));
            0
        }
        F_GETPIPE_SZ => match fs::pipe::pipe_size(file.inode()) {
            Some(size) => size as i64,
            None => -(Errno::Einval.as_i32() as i64),
        },
        F_SETPIPE_SZ => match fs::pipe::set_pipe_size(file.inode(), arg as usize) {
            Ok(size) => size as i64,
            Err(e) => -(e as i64),
        },
        // memfd seals (`fcntl.h`, docs/19). Only a sealable memfd exposes
        // seals; everything else → EINVAL.
        F_GET_SEALS => match file.inode().fcntl_seals() {
            Some(s) => s.load(core::sync::atomic::Ordering::Acquire) as i64,
            None    => -(Errno::Einval.as_i32() as i64),
        },
        F_ADD_SEALS => match file.inode().fcntl_seals() {
            Some(s) => {
                use core::sync::atomic::Ordering;
                let requested = arg as u32;
                let valid = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;
                if requested & !valid != 0 { return -(Errno::Einval.as_i32() as i64); }
                let cur_seals = s.load(Ordering::Acquire);
                // F_SEAL_SEAL already set ⇒ no further sealing (EPERM).
                if cur_seals & F_SEAL_SEAL != 0 { return -(Errno::Eperm.as_i32() as i64); }
                s.fetch_or(requested, Ordering::AcqRel);
                0
            }
            None => -(Errno::Einval.as_i32() as i64),
        },
        F_GETOWN => file.owner.load(core::sync::atomic::Ordering::Acquire) as i64,
        // F_SETOWN: record the SIGIO target AND snapshot the requesting creds
        // (Linux `f_setown` -> `__f_setown` capturing `current_cred()->uid/euid`)
        // so a later async signal is permission-checked against the credentials
        // that asked for ownership, not those current when it fires. Ensure the
        // sched SIGIO delivery hook is installed.
        F_SETOWN => {
            sched::live::sigpend::install_sigio_hook();
            file.f_setown(arg as i32, &crate::pathresolve::current_cred());
            0
        }
        // F_GETSIG/F_SETSIG (Linux f_owner.signum): the signal delivered on
        // async-I/O readiness; 0 = default SIGIO/SIGURG (D36).
        F_GETSIG => file.sig() as i64,
        F_SETSIG => {
            let sig = arg as i32;
            if sig < 0 || arg > NSIG { return -(Errno::Einval.as_i32() as i64); }
            file.set_sig(sig);
            0
        }
        // F_GETOWN_EX: write f_owner_ex { i32 type; i32 pid } (8 B). A negative
        // stored owner is a process group (Linux convention) (D36).
        F_GETOWN_EX => {
            if let Err(rv) = validate_user_buf(arg, 8, 4) { return rv; }
            let raw = file.owner.load(core::sync::atomic::Ordering::Acquire);
            let (ty, pid) = if raw < 0 { (F_OWNER_PGRP, -raw) } else { (F_OWNER_PID, raw) };
            // SAFETY: arg validated for 8 B below USER_VA_END; CPL=0 writes through caller's AS.
            unsafe {
                core::ptr::write_unaligned(arg as *mut i32, ty);
                core::ptr::write_unaligned((arg + 4) as *mut i32, pid);
            }
            0
        }
        // F_SETOWN_EX: read f_owner_ex; store pid (PGRP → negative). TID is
        // treated as PID (no per-thread fasync routing yet) (D36).
        F_SETOWN_EX => {
            if let Err(rv) = validate_user_buf(arg, 8, 4) { return rv; }
            // SAFETY: arg validated for 8 B below USER_VA_END; CPL=0 reads through caller's AS.
            let (ty, pid) = unsafe {
                (core::ptr::read_unaligned(arg as *const i32),
                 core::ptr::read_unaligned((arg + 4) as *const i32))
            };
            let stored = match ty {
                F_OWNER_TID | F_OWNER_PID => pid,
                F_OWNER_PGRP              => -pid,
                _ => return -(Errno::Einval.as_i32() as i64),
            };
            sched::live::sigpend::install_sigio_hook();
            // Capture the requesting creds too (same as F_SETOWN); TID is routed
            // as PID (no per-thread fasync queue yet).
            file.f_setown(stored, &crate::pathresolve::current_cred());
            0
        }
        // F_GETLEASE (Linux `fcntl_getlease`): the lease type held on the open
        // file description — F_RDLCK / F_WRLCK, or F_UNLCK when none.
        F_GETLEASE => file.lease() as i64,
        // F_SETLEASE (Linux `do_fcntl_add_lease`): take/drop a read/write lease.
        // Only regular files may hold a lease (EINVAL otherwise). Records the
        // type AND indexes the holder in the lease registry so a later
        // conflicting open can find + signal it (`break_lease`). EBADF-class
        // checks already passed (fd resolved). Returns 0 on success.
        F_SETLEASE => {
            let ty = arg as i32;
            if !matches!(ty, F_RDLCK | F_WRLCK | F_UNLCK) {
                return -(Errno::Einval.as_i32() as i64);
            }
            if !matches!(file.inode().file_type(), vfs::FileType::Regular) {
                return -(Errno::Einval.as_i32() as i64);
            }
            file.set_lease(ty);
            // F_UNLCK drops the registry entry; otherwise index it. Ensure a SIGIO
            // target + delivery hook exist so the lease-break signal lands even
            // without a prior F_SETOWN — default `f_owner` to the holder process
            // (Linux delivers via the file's fown, defaulting to the opener).
            if ty == F_UNLCK {
                vfs::file::lease_unregister(&file);
            } else {
                if file.owner.load(core::sync::atomic::Ordering::Acquire) == 0 {
                    let tgid = cur.tgid.load(core::sync::atomic::Ordering::Acquire) as i32;
                    file.f_setown(tgid, &crate::pathresolve::current_cred());
                }
                sched::live::sigpend::install_sigio_hook();
                vfs::file::lease_register(&file);
            }
            0
        }
        // F_NOTIFY (Linux `fcntl_dirnotify`, dnotify): arm a directory-change
        // watch. Only a directory fd is valid (ENOTDIR otherwise). `arg == 0`
        // clears the watch; otherwise the DN_* mask is validated and stored,
        // and the fd is indexed in the dnotify registry so a dir mutation
        // (create/unlink/rename/attrib) can find + signal it. Linux F_NOTIFY is
        // additive (OR-in) unless arg==0 clears; DN_MULTISHOT makes it sticky.
        F_NOTIFY => {
            if !matches!(file.inode().file_type(), vfs::FileType::Directory) {
                return -(Errno::Enotdir.as_i32() as i64);
            }
            let mask = arg as u32;
            if mask != 0 && (mask & !(DN_VALID | DN_MULTISHOT)) != 0 {
                return -(Errno::Einval.as_i32() as i64);
            }
            if mask == 0 {
                file.set_dnotify(0);
                vfs::file::dnotify_unregister(&file);
            } else {
                // Additive: OR the new events onto any existing watch (Linux
                // `fcntl_dirnotify` merges into the existing `dnotify_struct`).
                file.set_dnotify(file.dnotify() | mask);
                if file.owner.load(core::sync::atomic::Ordering::Acquire) == 0 {
                    let tgid = cur.tgid.load(core::sync::atomic::Ordering::Acquire) as i32;
                    file.f_setown(tgid, &crate::pathresolve::current_cred());
                }
                sched::live::sigpend::install_sigio_hook();
                vfs::file::dnotify_register(&file);
            }
            0
        }
        // F_GET_RW_HINT / F_GET_FILE_RW_HINT (Linux `fcntl_rw_hint`): write the
        // stored RWH_WRITE_LIFE_* hint to the u64 the caller points `arg` at.
        F_GET_RW_HINT | F_GET_FILE_RW_HINT => {
            if let Err(rv) = validate_user_buf(arg, 8, 8) { return rv; }
            // SAFETY: arg validated for 8 B below USER_VA_END; CPL=0 writes through caller's AS.
            unsafe { core::ptr::write_unaligned(arg as *mut u64, file.rw_hint()); }
            0
        }
        // F_SET_RW_HINT / F_SET_FILE_RW_HINT: read the u64 hint, reject any value
        // above RWH_WRITE_LIFE_EXTREME (Linux `rw_hint_valid`), then store it.
        F_SET_RW_HINT | F_SET_FILE_RW_HINT => {
            if let Err(rv) = validate_user_buf(arg, 8, 8) { return rv; }
            // SAFETY: arg validated for 8 B below USER_VA_END; CPL=0 reads through caller's AS.
            let hint = unsafe { core::ptr::read_unaligned(arg as *const u64) };
            if hint > RWH_WRITE_LIFE_EXTREME { return -(Errno::Einval.as_i32() as i64); }
            file.set_rw_hint(hint);
            0
        }
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
            // a follow-up). Interruptible: a deliverable signal aborts with
            // -ERESTARTSYS, matching Linux `fcntl_setlk` -> `do_lock_file_wait`
            // (`fs/locks.c:2536`) / `posix_lock_inode_wait` (`:1480`), both bare
            // `wait_event_interruptible` whose interrupted value is
            // -ERESTARTSYS (`kernel/sched/wait.c:309`) propagated unchanged.
            loop {
                match try_set_lock(inode, &req, owner) {
                    Ok(()) => return 0,
                    Err(vfs::VfsError::Eagain) => {
                        if sched::live::sigpend::deliverable_signals(cur) != 0 {
                            return syscall::restart::restart_sys();
                        }
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
