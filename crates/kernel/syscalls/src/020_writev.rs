// 020 writev — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

use alloc::vec::Vec;
use syscall::SyscallArgs;
use syscall::errno::Errno;
#[cfg(test)]
use crate::socket;

use crate::userbuf::validate_user_buf;
use crate::userbuf::validate_user_buf_readable;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

// DIAG (debug-stderr): lightweight fd==2 echo for the writev path (no ld.so
// verassert VMA dump), mirroring 001_write's trace_stderr_write.
#[cfg(all(feature = "debug-stderr", not(feature = "debug-atexit")))]
fn trace_stderr_echo(fd: i32, bytes: &[u8]) {
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

#[cfg(feature = "debug-atexit")]
fn trace_stderr_writev(fd: i32, bytes: &[u8]) {
    if fd != 2 {
        return;
    }

    let mut n = bytes.len();
    if n > 512 {
        n = 512;
    }

    // Tag each fragment with the writing tid: glibc splits one LD_DEBUG line
    // across several writes and multiple processes interleave, so an untagged
    // stream is unreconstructable. `[DYNERR t=<tid>]` lets a post-pass demux
    // per-process and read the exact `vn_file` of the last "checking for
    // version" line before each assert.
    klog::write_raw(b"[DYNERR t=");
    if let Some(c) = sched::live::current() { klog::write_dec_u64(c.tid as u64); }
    klog::write_raw(b"] ");
    klog::write_raw(&bytes[..n]);
    if n < bytes.len() {
        klog::write_raw(b"...<truncated>");
    }
    if n == 0 || bytes[n - 1] != b'\n' {
        klog::write_raw(b"\n");
    }

    // On the ld.so `_dl_check_map_versions` assertion (needed != NULL), dump the
    // failing process's full VMA layout so library placement (overlap / wrong
    // load bias / missing map) can be inspected directly — the loader scope is
    // built from exactly these mappings. `off`/ino per File VMA identifies the
    // library and confirms the file->va offset. # C: O(N_vmas)
    let is_verassert = bytes.windows(9).any(|w| w == b"needed !=")
        || bytes.windows(12).any(|w| w == b"Inconsistenc");
    if is_verassert {
        if let Some(c) = sched::live::current() {
            // SAFETY: running task on this CPU; sole mm reader here.
            if let Some(mm) = unsafe { c.mm_ref() } {
                klog::write_raw(b"[VMADUMP] tid=");
                klog::write_dec_u64(c.tid as u64);
                klog::write_raw(b" root="); klog::write_hex_u64(mm.root_pa());
                klog::write_raw(b"\n");
                let mut prev_end = 0u64;
                for v in mm.snapshot_vmas() {
                    klog::write_raw(b"  [");
                    klog::write_hex_u64(v.start.as_u64());
                    klog::write_raw(b",");
                    klog::write_hex_u64(v.end.as_u64());
                    klog::write_raw(b") prot=");
                    klog::write_hex_u64(v.prot.bits() as u64);
                    // Overlap with the previous (ascending) VMA = the smoking gun.
                    if v.start.as_u64() < prev_end {
                        klog::write_raw(b" **OVERLAP prev_end=");
                        klog::write_hex_u64(prev_end);
                        klog::write_raw(b"**");
                    }
                    prev_end = v.end.as_u64();
                    match &v.backing {
                        vmm::VmaBacking::File { backing, off } => {
                            klog::write_raw(b" File ino="); klog::write_hex_u64(backing.ino());
                            klog::write_raw(b" off="); klog::write_hex_u64(*off);
                        }
                        vmm::VmaBacking::Anonymous => klog::write_raw(b" Anon"),
                        _ => klog::write_raw(b" Other"),
                    }
                    klog::write_raw(b"\n");
                }

                // Walk ld.so's link_map chain (the list find_needed loop-1 walks
                // via l_next) so we see WHERE it breaks / whether libgcc_s is
                // reachable. Uses the STABLE public ABI: ld.so@INTERP_LOAD_BIAS
                // 0x40000000; `_r_debug` at file offset 0x37e58 (readelf of this
                // ld-linux); r_debug.r_map at +8; per link_map l_name at +8,
                // l_next at +24. Reads are through the running task's active AS
                // (user pages readable at CPL=0); each node VA is translate-gated
                // so a bad pointer logs and stops instead of faulting the kernel.
                #[cfg(target_arch = "x86_64")]
                {
                    use hal::{MmuOps, Va};
                    let rd = |va: u64| -> Option<u64> {
                        if va < 0x1000 || va >= hal::USER_VA_END { return None; }
                        // SAFETY: translate is a privileged PT read of the running task's root.
                        <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::translate(Va(va & !0xfff))?;
                        // SAFETY: page mapped (translate ok); CPL=0 read of user VA.
                        Some(unsafe { core::ptr::read_volatile(va as *const u64) })
                    };
                    // `_r_debug_extended` @ 0x37e58: base r_debug (r_map @ +8) then
                    // r_next @ +40 chains per-NAMESPACE r_debug structs. Walk every
                    // namespace to see if libgcc_s was added to a DIFFERENT one
                    // (wrong l_ns) rather than genuinely dropped.
                    const R_DEBUG_VA: u64 = 0x4000_0000 + 0x0003_7e58;
                    let read_name = |np: u64, want: &[u8]| -> bool {
                        if np == 0 { return false; }
                        let mut i = 0u64; let mut buf = [0u8; 96]; let mut m = 0usize;
                        while i < 96 {
                            if (np + i) & 0xfff == 0 || i == 0 { if rd(np + i).is_none() { break; } }
                            // SAFETY: page validated per 4K boundary; CPL=0 read.
                            let b = unsafe { core::ptr::read_volatile((np + i) as *const u8) };
                            if b == 0 { break; }
                            buf[m] = b; m += 1; i += 1;
                        }
                        klog::write_raw(&buf[..m]);
                        m >= want.len() && buf[..m].windows(want.len()).any(|w| w == want)
                    };
                    let mut ns_va = R_DEBUG_VA;
                    let mut nsidx = 0u32;
                    let mut gcc_in_ns: i64 = -1;
                    while ns_va != 0 && nsidx < 8 {
                        klog::write_raw(b"[LINKMAP] ns="); klog::write_dec_u64(nsidx as u64);
                        klog::write_raw(b" chain:\n");
                        let mut node = rd(ns_va + 8).unwrap_or(0);
                        let mut n = 0u32;
                        while node != 0 && n < 64 {
                            klog::write_raw(b"  #"); klog::write_dec_u64(n as u64);
                            klog::write_raw(b" map="); klog::write_hex_u64(node);
                            klog::write_raw(b" name=");
                            let name_ptr = rd(node + 8).unwrap_or(0);
                            if read_name(name_ptr, b"libgcc_s.") { gcc_in_ns = nsidx as i64; }
                            let lnext = rd(node + 24).unwrap_or(0);
                            klog::write_raw(b" l_next="); klog::write_hex_u64(lnext);
                            klog::write_raw(b"\n");
                            node = lnext;
                            n += 1;
                        }
                        klog::write_raw(b"[LINKMAP] ns="); klog::write_dec_u64(nsidx as u64);
                        klog::write_raw(b" nodes="); klog::write_dec_u64(n as u64); klog::write_raw(b"\n");
                        ns_va = rd(ns_va + 40).unwrap_or(0);   // r_next → next namespace
                        nsidx += 1;
                    }
                    klog::write_raw(b"[LINKMAP] libgcc_s ");
                    if gcc_in_ns < 0 { klog::write_raw(b"MISSING-FROM-ALL-NAMESPACES\n"); }
                    else { klog::write_raw(b"in ns="); klog::write_dec_u64(gcc_in_ns as u64); klog::write_raw(b"\n"); }
                }
            }
        }
    }
}

/// `sys_writev(fd, iov, iovcnt)` — slot 20. Imports the Linux `iovec` array,
/// applies `UIO_MAXIOV`/`MAX_RW_COUNT`, then dispatches one vectored VFS write
/// so the open-file cursor advances atomically across the whole request.
/// # C: O(iovcnt + sum(iov[i].len))
pub fn sys_writev(args: &SyscallArgs) -> i64 {
    const IOV_MAX: u64 = 1024;
    let fd     = args.a0 as i32;
    let iov    = args.a1;
    let iovcnt = args.a2;
    let cur = match current_task() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => {
            let ret = -(Errno::Ebadf.as_i32() as i64);
            cur.account_write_result(ret);
            return ret;
        }
    };
    let file = match fdt.get(fd) {
        Ok(f)  => f,
        Err(_) => {
            let ret = -(Errno::Ebadf.as_i32() as i64);
            cur.account_write_result(ret);
            return ret;
        }
    };
    if !file.f_mode().contains(vfs::Fmode::WRITE) {
        let ret = -(Errno::Ebadf.as_i32() as i64);
        cur.account_write_result(ret);
        return ret;
    }
    if iovcnt > IOV_MAX {
        let ret = -(Errno::Einval.as_i32() as i64);
        cur.account_write_result(ret);
        return ret;
    }
    let array_bytes = match iovcnt.checked_mul(16) {
        Some(v) => v,
        None    => {
            let ret = -(Errno::Efault.as_i32() as i64);
            cur.account_write_result(ret);
            return ret;
        }
    };
    if iovcnt != 0 {
        if let Err(rv) = validate_user_buf(iov, array_bytes, 8) {
            cur.account_write_result(rv);
            return rv;
        }
    }
    let mut ranges: Vec<(u64, usize)> = Vec::new();
    let mut imported_total = 0usize;
    for i in 0..iovcnt {
        let iov_i = iov + i * 16;
        // SAFETY: iov array validated above; iov_i lies inside; 8-byte aligned per Linux ABI.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: same range as the read above; iov_len at +8 is 8-byte aligned.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if len == 0 { continue; }
        if let Err(rv) = validate_user_buf_readable(base, len, 1) {
            cur.account_write_result(rv);
            return rv;
        }
        let remaining = crate::userbuf::MAX_RW_COUNT.saturating_sub(imported_total);
        if remaining == 0 { break; }
        let capped = core::cmp::min(len as usize, remaining);
        imported_total = imported_total.saturating_add(capped);
        if capped != 0 {
            ranges.push((base, capped));
        }
    }
    let mut bufs: Vec<&[u8]> = Vec::new();
    for (base, len) in ranges {
        // SAFETY: range validated readable in the caller's AS before CPL=0 dereference.
        let bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(base as *const u8, len)
        };
        #[cfg(feature = "debug-atexit")]
        trace_stderr_writev(fd, bytes);
        #[cfg(all(feature = "debug-stderr", not(feature = "debug-atexit")))]
        trace_stderr_echo(fd, bytes);
        bufs.push(bytes);
    }
    // One VFS iterator call owns the complete imported iovec. Record-oriented
    // socket file-ops preserve one-message semantics; streams and regular files
    // use the shared partial-progress iterator.
    let context = socket::SendContext::new(cur);
    let wr = socket::writev(&context, file.clone(), &bufs);
    #[cfg(feature = "debug-udevdb")]
    {
        let rv = match &wr { Ok(n) => *n as i64, Err(e) => -(*e as i64) };
        crate::namei_common::trace_udevdb_file(b"writev", &file, rv);
    }
    let ret = match wr {
        Ok(n)  => n as i64,
        Err(e) => -(e as i64),
    };
    cur.account_write_result(ret);
    ret
}
