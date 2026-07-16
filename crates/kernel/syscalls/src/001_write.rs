// 001 write — one syscall, one file (docs/53 §0).
use syscall::{errno::Errno, SyscallArgs};
#[cfg(test)]
use crate::socket;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

// DIAG (debug-stderr): echo fd==2 (stderr) writes to the console tagged with the
// writing tid+name. GLib/GTK/mutter log fatal errors via write(2,...) to stderr;
// gdm routes the session's stderr to a pipe/journal, so those death messages
// never reach the serial console. Mirrors `trace_stderr_writev` (020_writev) for
// the plain-write path, giving visibility into why gnome-shell exits code=1.
// Kept lightweight (syscalls-only) so a live-gnome boot reaches the desktop at
// normal speed — unlike debug-atexit which also arms the ld.so DR0 machinery.
#[cfg(feature = "debug-stderr")]
fn trace_stderr_write(fd: i32, bytes: &[u8]) {
    if fd != 2 { return; }
    let n = core::cmp::min(bytes.len(), 512);
    klog::write_raw(b"[STDERR t=");
    if let Some(c) = sched::live::current() {
        klog::write_dec_u64(c.tid as u64);
        klog::write_raw(b" ");
        klog::write_raw(c.name.as_bytes());
    }
    klog::write_raw(b"] ");
    klog::write_raw(&bytes[..n]);
    if n < bytes.len() { klog::write_raw(b"...<truncated>"); }
    if n == 0 || bytes[n - 1] != b'\n' { klog::write_raw(b"\n"); }
}

// DIAG (debug-session): echo writes whose target path is a logind session-state
// file (/run/systemd/{sessions,users,seats,machines}/*, incl. the atomic-write
// temp `.#…` siblings in those dirs) to the console. logind classifies a session
// (Type/Class/Seat/VTNr) and records the user's primary graphical session
// (DISPLAY=) in these files — mutter's `sd_uid_get_display()` reads them. Seeing
// the exact bytes logind writes tells us why "Failed to find any matching session".
#[cfg(feature = "debug-session")]
fn trace_session_write(file: &vfs::File, bytes: &[u8]) {
    let path = file.dentry().absolute_path();
    let p = &path[..];
    let hit = p.windows(21).any(|w| w == b"/run/systemd/sessions")
        || p.windows(18).any(|w| w == b"/run/systemd/users")
        || p.windows(18).any(|w| w == b"/run/systemd/seats");
    if !hit { return; }
    let n = core::cmp::min(bytes.len(), 512);
    klog::write_raw(b"[SESSFILE ");
    klog::write_raw(&path);
    klog::write_raw(b"] ");
    klog::write_raw(&bytes[..n]);
    if n < bytes.len() { klog::write_raw(b"...<truncated>"); }
    if n == 0 || bytes[n - 1] != b'\n' { klog::write_raw(b"\n"); }
}

/// `sys_write(fd, buf, cnt)` — slot 1. Work fn: `vfs::File::write`.
/// # C: O(cnt) on the underlying inode write.
pub fn sys_write(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let mut cnt = args.a2 as usize;
    let cur = match current_task() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; no concurrent fd_table writer.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    if !file.f_mode().contains(vfs::Fmode::WRITE) { return -(Errno::Ebadf.as_i32() as i64); }
    // DIAG (debug-wakelat): symbolize systemd-hwdb (tid 4135)'s write() CALLER
    // stack during its serialize-spin. The USERIP sampler only catches the libc
    // syscall wrapper (0x7ffff71af75e); the real infinite loop is hwdb's own .text
    // (~0x10xxxxxx) calling write. Walk the user stack, print (ino, file-offset) for
    // each return address in a File-backed EXEC VMA → objdump the hwdb binary /
    // libc at foff to name the loop. Modeled on 024_sched_yield's YIELD-SPIN probe.
    // Rate-limited (1/2048) so the spin doesn't flood.
    #[cfg(all(feature = "debug-wakelat", target_arch = "x86_64"))]
    if cur.tid == 4135 {
        use core::sync::atomic::{AtomicU64, Ordering};
        static WSYM: AtomicU64 = AtomicU64::new(0);
        let k = WSYM.fetch_add(1, Ordering::Relaxed);
        if k >= 40 && k % 256 == 0 && k < 40000 {
            // SAFETY: current_user_frame()[2] is the saved user rsp on this task's syscall kstack.
            let ursp = unsafe { (*hal_x86_64::current_user_frame())[2] };
            klog::write_raw(b"[HWSTK ursp="); klog::write_hex_u64(ursp); klog::write_raw(b"]\n");
            // SAFETY: running task on this CPU; single-mutator mm slot per 13§5.
            if let Some(mm) = unsafe { cur.mm_ref() } {
                let mut i = 0u64;
                let mut found = 0u32;
                while i < 220 && found < 20 {
                    // SAFETY: reading this task's own user stack; range validated as a live user VA below.
                    let a = unsafe { core::ptr::read_volatile((ursp + i * 8) as *const u64) };
                    if let Some(uva) = hal::UserVirtAddr::new(a) {
                        if let Some(vma) = mm.find_vma(uva) {
                            if vma.prot.contains(vmm::VmaProt::EXEC) {
                                if let vmm::VmaBacking::File { backing, off } = &vma.backing {
                                    let foff = off.wrapping_add(a - vma.start.as_u64());
                                    klog::write_raw(b"[HWCALL a="); klog::write_hex_u64(a);
                                    klog::write_raw(b" ino="); klog::write_hex_u64(backing.ino());
                                    klog::write_raw(b" foff="); klog::write_hex_u64(foff);
                                    klog::write_raw(b"]\n");
                                    found += 1;
                                }
                            }
                        }
                    }
                    i += 1;
                }
            }
        }
    }
    let empty: [u8; 0] = [];
    let slice: &[u8] = if cnt == 0 {
        &empty
    } else {
        if let Err(rv) = crate::userbuf::validate_user_buf_readable(buf, cnt as u64, 1) { return rv; }
        cnt = crate::userbuf::clamp_rw_count(cnt);
        let pos = crate::write_common::write_pos(&file);
        cnt = match crate::write_common::rlimit_fsize_cap(&cur, &file, pos, cnt, true) {
            Ok(n)  => n,
            Err(e) => return e,
        };
        // SAFETY: range [buf, buf+cnt) validated readable in the caller's AS before CPL=0 dereference.
        unsafe { core::slice::from_raw_parts(buf as *const u8, cnt) }
    };
    #[cfg(feature = "debug-session")]
    trace_session_write(&file, slice);
    #[cfg(feature = "debug-stderr")]
    trace_stderr_write(fd, slice);
    let context = socket::SendContext::new(cur);
    let wr = socket::write(&context, file.clone(), slice);
    #[cfg(feature = "debug-udevdb")]
    {
        let rv = match &wr { Ok(n) => *n as i64, Err(e) => -(*e as i64) };
        crate::namei_common::trace_udevdb_file(b"write", &file, rv);
    }
    let ret = match wr {
        Ok(n)  => {
            // DIAG (debug-wakelat): a write() returning 0 for a NON-zero request is
            // a Linux violation (must write >0, block, or error) and spins glibc's
            // write-all loop forever (the systemd-hwdb sysinit busy-spin). Log the
            // offending fd/type/path once. Rate-limited so the spin doesn't flood.
            #[cfg(feature = "debug-wakelat")]
            if n == 0 && cnt > 0 {
                use core::sync::atomic::{AtomicU64, Ordering};
                static W0: AtomicU64 = AtomicU64::new(0);
                if W0.fetch_add(1, Ordering::Relaxed) < 12 {
                    klog::write_raw(b"[WRITE0] pid=");
                    klog::write_dec_u64(cur.tid as u64);
                    klog::write_raw(b" name=");
                    klog::write_raw(cur.name.as_bytes());
                    klog::write_raw(b" fd=");
                    klog::write_dec_u64(fd as u64);
                    klog::write_raw(b" type=");
                    klog::write_dec_u64(file.inode().file_type() as u64);
                    klog::write_raw(b" cnt=");
                    klog::write_dec_u64(cnt as u64);
                    klog::write_raw(b" path=\"");
                    klog::write_raw(&file.dentry().absolute_path());
                    klog::write_raw(b"\"\n");
                }
            }
            n as i64
        }
        Err(e) => {
            // DIAG (debug-wakelat): any write() Err — the systemd-hwdb sysinit spin
            // is a glibc cancellable-write retry loop on some non-EROFS error
            // (EAGAIN on a blocking fd, spurious EINTR, …). Name the errno+fd+type.
            #[cfg(feature = "debug-wakelat")]
            {
                use core::sync::atomic::{AtomicU64, Ordering};
                static WE: AtomicU64 = AtomicU64::new(0);
                if WE.fetch_add(1, Ordering::Relaxed) < 16 {
                    klog::write_raw(b"[WRITEERR] pid=");
                    klog::write_dec_u64(cur.tid as u64);
                    klog::write_raw(b" name=");
                    klog::write_raw(cur.name.as_bytes());
                    klog::write_raw(b" fd=");
                    klog::write_dec_u64(fd as u64);
                    klog::write_raw(b" type=");
                    klog::write_dec_u64(file.inode().file_type() as u64);
                    klog::write_raw(b" cnt=");
                    klog::write_dec_u64(cnt as u64);
                    klog::write_raw(b" errno=");
                    klog::write_dec_u64(e as u64);
                    klog::write_raw(b" path=\"");
                    klog::write_raw(&file.dentry().absolute_path());
                    klog::write_raw(b"\"\n");
                }
            }
            if e == socket::Error::Erofs {
                klog::write_raw(b"[WRITE-EROFS] pid=");
                klog::write_dec_u64(cur.tid as u64);
                klog::write_raw(b" name=");
                klog::write_raw(cur.name.as_bytes());
                klog::write_raw(b" fd=");
                klog::write_dec_u64(fd as u64);
                klog::write_raw(b" path=\"");
                let path = file.dentry().absolute_path();
                klog::write_raw(&path);
                klog::write_raw(b"\" mnt_id=");
                klog::write_dec_u64(file.mnt_id());
                if let Some(m) = file.vfsmount() {
                    klog::write_raw(b" mnt_ns=");
                    klog::write_dec_u64(m.namespace_id());
                    klog::write_raw(b" mnt_flags=0x");
                    klog::write_hex_u64(m.flags());
                    klog::write_raw(b" sb_ro=");
                    klog::write_dec_u64(if m.sb().is_readonly() { 1 } else { 0 });
                    klog::write_raw(b" mp=\"");
                    let mp = m.mount_point_str();
                    klog::write_raw(mp.as_bytes());
                } else {
                    klog::write_raw(b" mnt_ns=0 mnt_flags=0x0 sb_ro=0 mp=\"<none>");
                }
                klog::write_raw(b"\" ino=");
                klog::write_dec_u64(file.inode().ino());
                klog::write_raw(b" type=");
                klog::write_dec_u64(file.inode().file_type() as u64);
                klog::write_raw(b" cnt=");
                klog::write_dec_u64(cnt as u64);
                klog::write_raw(b"\n");
            }
            -(e as i64)
        },
    };
    cur.account_write_result(ret);
    ret
}
