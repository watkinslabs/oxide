// 072 fcntl — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::fcntl_deleg;
use crate::fcntl_lease::{fowner_euid, fowner_uid, read_delegation, set_lease, write_delegation};
use crate::userbuf::validate_user_buf;

/// `sys_fcntl(fd, cmd, arg)` — slot 72. F_DUPFD / F_DUPFD_CLOEXEC /
/// F_GETFD / F_SETFD / F_GETFL / F_SETFL / F_GETPIPE_SZ /
/// F_SETPIPE_SZ / F_GETOWN / F_SETOWN; F_SETLK / F_SETLKW / F_GETLK
/// + F_OFD_* via `handle_record_lock`.
/// # C: O(1) per cmd; O(N_fds) for F_DUPFD.
pub fn sys_fcntl(args: &SyscallArgs) -> i64 {
    use crate::fcntl_cmds::{
        allowed_on_o_path, F_ADD_SEALS, F_CREATED_QUERY, F_DUPFD, F_DUPFD_CLOEXEC,
        F_DUPFD_QUERY, F_GETFD, F_GETFL, F_GETLEASE, F_GETLK, F_GETOWN, F_GETOWNER_UIDS,
        F_GETOWN_EX, F_GETPIPE_SZ, F_GETSIG, F_GET_RW_HINT, F_GET_SEALS, F_NOTIFY,
        F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW, F_SETFD, F_SETFL, F_SETLEASE, F_SETLK,
        F_SETLKW, F_SETOWN, F_SETOWN_EX, F_SETPIPE_SZ, F_SETSIG, F_SET_RW_HINT,
    };
    use vfs::file::owner_type::{F_OWNER_PGRP, F_OWNER_PID, F_OWNER_TID};
    const RWH_WRITE_LIFE_EXTREME: u64 = 5;
    const O_ASYNC: u64 = 0o20000;
    // dnotify F_NOTIFY DN_* event bits + DN_MULTISHOT (Linux fcntl UAPI).
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
    // An `O_PATH` descriptor names a location, not an open file: only the
    // commands that operate on the descriptor itself are admitted, and every
    // other one answers EBADF. Ahead of the whole dispatch, so no command can
    // reach a file that has no backend behind it.
    if file.f_mode().contains(vfs::Fmode::PATH) && !allowed_on_o_path(cmd) { return ebadf; }
    if cmd == F_CREATED_QUERY {
        // `!!(filp->f_mode & FMODE_CREATED)`.
        return file.f_mode().contains(vfs::Fmode::CREATED) as i64;
    }
    if cmd == F_DUPFD_QUERY {
        // `f_dupfd_query`: EBADF for an empty `arg` slot, else the pointer
        // comparison `fd_file(f) == filp` — 1 when both descriptors name the
        // SAME open file description (a dup, not a re-open), 0 otherwise.
        // Identity is the `Arc<File>` here, which is exactly one open file
        // description, so `Arc::ptr_eq` IS Linux's `struct file *` compare.
        let other = match fdt.get(arg as i32) { Ok(f) => f, Err(_) => return ebadf };
        return alloc::sync::Arc::ptr_eq(&file, &other) as i64;
    }
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
        // (`force_o_largefile`; the open path ORs it into
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
            if file.set_fl(vfs::OpenFlags::from_bits_retain(arg as u32)).is_err() {
                return -(Errno::Einval.as_i32() as i64);
            }
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
        // memfd seals (fcntl UAPI, docs/19). Only a sealable memfd exposes
        // seals; everything else → EINVAL.
        F_GET_SEALS => match file.inode().fcntl_seals() {
            Some(s) => s.load(core::sync::atomic::Ordering::Acquire) as i64,
            None    => -(Errno::Einval.as_i32() as i64),
        },
        F_ADD_SEALS => {
            use core::sync::atomic::Ordering;
            let writable = file.f_mode().contains(vfs::Fmode::WRITE);
            let requested = arg as u32;
            let inode = file.inode();
            let seals = inode.fcntl_seals();
            let mut current = seals.map(|s| s.load(Ordering::Acquire));
            loop {
                let add = match crate::fcntl_seal::plan_add_seals(
                    writable,
                    requested,
                    current,
                    inode.i_mode() as u16,
                ) {
                    Ok(add) => add,
                    Err(e) => return -(e.as_i32() as i64),
                };
                let Some(seals) = seals else {
                    return -(Errno::Einval.as_i32() as i64);
                };
                let observed = current.expect("sealable inode has a seal word");
                let publish = || seals.compare_exchange(
                    observed, observed | add, Ordering::AcqRel, Ordering::Acquire,
                ).is_ok();
                let needs_mapping_deny =
                    add & vfs::F_SEAL_WRITE != 0 && observed & vfs::F_SEAL_WRITE == 0;
                let published = if needs_mapping_deny {
                    match inode.file_rmap().commit_write_seal(publish) {
                        Ok(done) => done,
                        Err(vmm::WriteSealError::Busy) => {
                            return -(Errno::Ebusy.as_i32() as i64);
                        }
                    }
                } else {
                    publish()
                };
                if published {
                    return 0;
                }
                current = Some(seals.load(Ordering::Acquire));
            }
        }
        // `f_getown`: a process-group owner is reported as a NEGATIVE pgid,
        // the legacy encoding `F_GETOWN_EX` exists to replace.
        F_GETOWN => file.f_getown() as i64,
        // F_SETOWN: record the SIGIO target AND snapshot the requesting creds
        // (Linux `f_setown` -> `__f_setown` capturing `current_cred()->uid/euid`)
        // so a later async signal is permission-checked against the credentials
        // that asked for ownership, not those current when it fires. Ensure the
        // sched SIGIO delivery hook is installed.
        F_SETOWN => {
            let who = arg as i32;
            // `if (who == INT_MIN) return -EINVAL;` — negating it overflows.
            if who == i32::MIN { return -(Errno::Einval.as_i32() as i64); }
            let (id, ty) = if who < 0 { (-who, F_OWNER_PGRP) } else { (who, F_OWNER_PID) };
            // `find_vpid(who)` returning NULL is `ESRCH`: naming a target that
            // does not exist is an error, not a silently stored id.
            if id != 0 && !owner_exists(id, ty) { return -(Errno::Esrch.as_i32() as i64); }
            sched::live::sigpend::install_sigio_hook();
            file.f_setown(id, ty, fowner_uid(), fowner_euid());
            0
        }
        // `F_GETOWNER_UIDS`: copy out the `f_owner` credential snapshot as two
        // consecutive `uid_t`. `f_setown` captured them; this reads them back.
        F_GETOWNER_UIDS => {
            if let Err(rv) = validate_user_buf(arg, 8, 4) { return rv; }
            let (uid, euid) = file.f_owner_creds();
            // SAFETY: arg validated for 8 B below USER_VA_END; CPL=0 writes through caller's AS.
            unsafe {
                core::ptr::write_unaligned(arg as *mut u32, uid);
                core::ptr::write_unaligned((arg + 4) as *mut u32, euid);
            }
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
        // F_GETOWN_EX: write f_owner_ex { i32 type; i32 pid } (8 B). The stored
        // `pid_type` is reported verbatim, so an `F_OWNER_TID` owner does not
        // come back as `F_OWNER_PID` (D36).
        F_GETOWN_EX => {
            if let Err(rv) = validate_user_buf(arg, 8, 4) { return rv; }
            let ty = file.f_owner_type();
            let pid = file.owner.load(core::sync::atomic::Ordering::Acquire);
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
            if !matches!(ty, F_OWNER_TID | F_OWNER_PID | F_OWNER_PGRP) {
                return -(Errno::Einval.as_i32() as i64);
            }
            // `find_vpid(owner.pid)` NULL for a non-zero pid is `ESRCH`.
            if pid != 0 && !owner_exists(pid, ty) { return -(Errno::Esrch.as_i32() as i64); }
            sched::live::sigpend::install_sigio_hook();
            // Capture the requesting creds too (same as F_SETOWN). The type is
            // STORED, so delivery reaches one thread / one process / a group as
            // asked and `F_GETOWN_EX` reports back what was set.
            file.f_setown(pid, ty, fowner_uid(), fowner_euid());
            0
        }
        // F_GETLEASE: the PLAIN lease type held on this open file description —
        // F_RDLCK / F_WRLCK, or F_UNLCK when none. A delegation held on the
        // same description is invisible here; F_GETDELEG is its query.
        F_GETLEASE => file.lease_of(vfs::file::FL_LEASE) as i64,
        // F_SETLEASE: take/drop a read/write lease. Records the type AND
        // indexes the holder in the lease registry so a later conflicting open
        // can find + signal it. EBADF-class checks already passed (fd
        // resolved). Returns 0 on success.
        F_SETLEASE => set_lease(&cur, &file, vfs::file::LeaseKind::Lease, arg as i32),
        // F_GETDELEG: the DELEGATION held on this description, written back
        // into the caller's `struct delegation`. A plain lease is invisible
        // here, exactly as a delegation is to F_GETLEASE — one break path, two
        // separate queries.
        fcntl_deleg::F_GETDELEG => {
            // The request is READ and validated before the answer is produced:
            // a caller passing a reserved field it invented is told EINVAL, not
            // handed a delegation type it never asked for.
            if let Err(rv) = read_delegation(arg) { return rv; }
            write_delegation(arg, file.lease_of(vfs::file::FL_DELEG));
            0
        }
        // F_SETDELEG: take/drop a delegation. Same storage, same registry and
        // the same break path as a lease; it differs in that a DIRECTORY may
        // be delegated (read-only) where it may never be leased, and in which
        // breaker disturbs it.
        fcntl_deleg::F_SETDELEG => match read_delegation(arg) {
            Ok(d)   => set_lease(&cur, &file, vfs::file::LeaseKind::Deleg, d.d_type),
            Err(rv) => rv,
        },
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
                    file.f_setown(tgid, F_OWNER_PID, fowner_uid(), fowner_euid());
                }
                sched::live::sigpend::install_sigio_hook();
                vfs::file::dnotify_register(&file);
            }
            0
        }
        // F_GET_RW_HINT / F_GET_FILE_RW_HINT (Linux `fcntl_rw_hint`): write the
        // stored RWH_WRITE_LIFE_* hint to the u64 the caller points `arg` at.
        F_GET_RW_HINT => {
            if let Err(rv) = validate_user_buf(arg, 8, 8) { return rv; }
            // SAFETY: arg validated for 8 B below USER_VA_END; CPL=0 writes through caller's AS.
            unsafe { core::ptr::write_unaligned(arg as *mut u64, file.rw_hint()); }
            0
        }
        // F_SET_RW_HINT / F_SET_FILE_RW_HINT: read the u64 hint, reject any value
        // above RWH_WRITE_LIFE_EXTREME (Linux `rw_hint_valid`), then store it.
        F_SET_RW_HINT => {
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

/// Whether the id an `F_SETOWN`/`F_SETOWN_EX` names resolves to something
/// live — Linux `find_vpid(who)`, which yields `ESRCH` when it does not. The
/// vpid is read in the caller's pid namespace, which is the namespace
/// `F_SETOWN` records in.
/// # C: O(log N) for a task; O(N_tasks) for a process group
fn owner_exists(id: i32, ty: i32) -> bool {
    use vfs::file::owner_type::F_OWNER_PGRP;
    if id <= 0 { return false; }
    if ty == F_OWNER_PGRP { return !sched::registry::tasks_in_pgrp(id as u32).is_empty(); }
    sched::registry::lookup_by_vpid(id as u32).is_some()
}

/// F_SETLK / F_SETLKW / F_GETLK + F_OFD_* ABI shim (`docs/53`): validate the
/// user `struct flock`, hand ONE work fn the decoded request, encode the
/// answer back. Wait policy and lock state live in `fs::posix_lock` /
/// `vfs::FileLockContext`.
/// # C: O(1) plus the work fn
fn handle_record_lock(
    cur: &sched::Task,
    fdt: &alloc::sync::Arc<vfs::FdTable>,
    file: &alloc::sync::Arc<vfs::File>,
    cmd: u64,
    arg: u64,
) -> i64 {
    use core::sync::atomic::Ordering;
    use fs::posix_lock::{decode_flock, encode_flock, fmode_ok_for_setlk, getlk, owner_for,
                         resolve, setlk, setlkw, FLOCK_BYTES, F_UNLCK};
    use crate::fcntl_cmds::{F_GETLK, F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW, F_SETLK, F_SETLKW};
    if let Err(rv) = validate_user_buf(arg, FLOCK_BYTES as u64, 8) { return rv; }
    let mut bytes = [0u8; FLOCK_BYTES];
    // SAFETY: arg validated FLOCK_BYTES below USER_VA_END; CPL=0 reads through caller's AS.
    unsafe {
        for i in 0..FLOCK_BYTES {
            bytes[i] = core::ptr::read_volatile((arg + i as u64) as *const u8);
        }
    }
    let req = match decode_flock(&bytes, file.pos(), file.inode().size()) {
        Ok(r) => r, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let is_ofd = matches!(cmd, F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW);
    // Linux `fcntl_setlk`: `flc_owner = current->files` for POSIX locks — the
    // descriptor table, so all threads of a process are ONE owner — and `filp`
    // for OFD locks. `flc_pid = current->tgid` is reporting only.
    let owner = owner_for(is_ofd, file, alloc::sync::Arc::as_ptr(fdt) as *const u8 as usize);
    let rec = match resolve(&req, owner, cur.tgid.load(Ordering::Relaxed)) {
        Ok(r) => r, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    match cmd {
        F_GETLK | F_OFD_GETLK => {
            // Linux `fcntl_getlk`: only a read/write probe is meaningful.
            if rec.l_type == F_UNLCK { return -(Errno::Einval.as_i32() as i64); }
            let mut out = bytes;
            match getlk(file, &rec) {
                Some(blk) => encode_flock(&mut out, &blk),
                // No conflict — Linux reports F_UNLCK and leaves the rest of
                // the caller's struct as it was.
                None => out[0..2].copy_from_slice(&F_UNLCK.to_le_bytes()),
            }
            // SAFETY: arg validated FLOCK_BYTES below USER_VA_END; CPL=0 writes through caller's AS.
            unsafe {
                for i in 0..FLOCK_BYTES {
                    core::ptr::write_volatile((arg + i as u64) as *mut u8, out[i]);
                }
            }
            0
        }
        F_SETLK | F_OFD_SETLK | F_SETLKW | F_OFD_SETLKW => {
            if !fmode_ok_for_setlk(file, rec.l_type) { return -(Errno::Ebadf.as_i32() as i64); }
            if matches!(cmd, F_SETLK | F_OFD_SETLK) { setlk(file, &rec) } else { setlkw(file, &rec) }
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}
