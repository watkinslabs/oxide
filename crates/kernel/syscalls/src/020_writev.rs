// 020 writev — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;

#[cfg(feature = "debug-atexit")]
fn trace_stderr_writev(fd: i32, bytes: &[u8]) {
    if fd != 2 {
        return;
    }

    let mut n = bytes.len();
    if n > 512 {
        n = 512;
    }

    klog::write_raw(b"[DYNERR] ");
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
                    const R_DEBUG_VA: u64 = 0x4000_0000 + 0x0003_7e58;
                    klog::write_raw(b"[LINKMAP] chain (l_name via r_debug.r_map):\n");
                    if let Some(mut node) = rd(R_DEBUG_VA + 8) {
                        let mut n = 0u32;
                        let mut saw_gcc = false;
                        let mut prev_node = 0u64;
                        while node != 0 && n < 48 {
                            let name_ptr = rd(node + 8).unwrap_or(0);
                            klog::write_raw(b"  #"); klog::write_dec_u64(n as u64);
                            klog::write_raw(b" map="); klog::write_hex_u64(node);
                            klog::write_raw(b" name=");
                            if name_ptr != 0 {
                                // Read up to 96 bytes of the null-terminated l_name.
                                let mut i = 0u64;
                                let mut buf = [0u8; 96];
                                let mut m = 0usize;
                                while i < 96 {
                                    // one byte at a time, translate-gated per page boundary
                                    if (name_ptr + i) & 0xfff == 0 || i == 0 {
                                        if rd(name_ptr + i).is_none() { break; }
                                    }
                                    // SAFETY: page validated at each 4K boundary above; CPL=0 read.
                                    let b = unsafe { core::ptr::read_volatile((name_ptr + i) as *const u8) };
                                    if b == 0 { break; }
                                    buf[m] = b; m += 1; i += 1;
                                }
                                klog::write_raw(&buf[..m]);
                                if buf[..m].windows(9).any(|w| w == b"libgcc_s.") { saw_gcc = true; }
                            } else { klog::write_raw(b"<null>"); }
                            let lnext = rd(node + 24).unwrap_or(0);   // l_next
                            let lprev = rd(node + 32).unwrap_or(0);   // l_prev (public ABI)
                            klog::write_raw(b" l_next="); klog::write_hex_u64(lnext);
                            klog::write_raw(b" l_prev="); klog::write_hex_u64(lprev);
                            // Back-link mismatch: this node's l_prev should equal
                            // the previous forward node. If not, l_prev names the
                            // ORPHAN link_map whose predecessor's l_next append was
                            // lost — dump its name to identify the dropped lib.
                            if n > 0 && lprev != prev_node && lprev != 0 {
                                klog::write_raw(b" **ORPHAN-BACKLINK->");
                                let onp = rd(lprev + 8).unwrap_or(0);
                                if onp != 0 {
                                    let mut j = 0u64; let mut ob = [0u8; 64]; let mut om = 0usize;
                                    while j < 64 {
                                        if (onp + j) & 0xfff == 0 || j == 0 { if rd(onp + j).is_none() { break; } }
                                        // SAFETY: page validated per 4K boundary; CPL=0 read.
                                        let b = unsafe { core::ptr::read_volatile((onp + j) as *const u8) };
                                        if b == 0 { break; }
                                        ob[om] = b; om += 1; j += 1;
                                    }
                                    klog::write_raw(&ob[..om]);
                                }
                                klog::write_raw(b"**");
                            }
                            klog::write_raw(b"\n");
                            prev_node = node;
                            node = lnext;
                            n += 1;
                        }
                        klog::write_raw(b"[LINKMAP] nodes="); klog::write_dec_u64(n as u64);
                        klog::write_raw(if saw_gcc { b" libgcc_s=IN-CHAIN\n" } else { b" libgcc_s=MISSING-FROM-CHAIN\n" });
                    } else {
                        klog::write_raw(b"[LINKMAP] r_debug.r_map unreadable\n");
                    }
                }
            }
        }
    }
}

/// `sys_writev(fd, iov, iovcnt)` — slot 20. fd_table-routed
/// version: looks up the open `File`, walks the iovec array,
/// calls `File::write` for each non-empty buffer. Returns total
/// bytes written or the first negative errno encountered.
/// # C: O(iovcnt × iov[i].len)
pub fn sys_writev(args: &SyscallArgs) -> i64 {
    dtrace!(b"WV_IN", args.a2);
    const IOV_MAX: u64 = 1024;
    let fd     = args.a0 as i32;
    let iov    = args.a1;
    let iovcnt = args.a2;
    if iovcnt == 0 { return 0; }
    if iovcnt > IOV_MAX { return -(Errno::Einval.as_i32() as i64); }
    let array_bytes = match iovcnt.checked_mul(16) {
        Some(v) => v,
        None    => return -(Errno::Efault.as_i32() as i64),
    };
    if let Err(rv) = validate_user_buf(iov, array_bytes, 8) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f)  => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let mut total: u64 = 0;
    for i in 0..iovcnt {
        let iov_i = iov + i * 16;
        // SAFETY: iov array validated above; iov_i lies inside; 8-byte aligned per Linux ABI.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: same range as the read above; iov_len at +8 is 8-byte aligned.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        dtrace!(b"WV_IOV", len);
        if len == 0 { continue; }
        if let Err(rv) = validate_user_buf(base, len, 1) { return rv; }
        // SAFETY: range validated < USER_VA_END; CPL=0 reads through caller's user pages.
        let bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(base as *const u8, len as usize)
        };
        #[cfg(feature = "debug-atexit")]
        trace_stderr_writev(fd, bytes);
        dtrace!(b"WV_PRE_W");
        match file.write(bytes) {
            Ok(n)  => { dtrace!(b"WV_OK", n as u64); total = total.saturating_add(n as u64); }
            Err(e) => { dtrace!(b"WV_ERR", e as u64); return -(e as i64); }
        }
    }
    dtrace!(b"WV_OUT", total);
    total as i64
}
