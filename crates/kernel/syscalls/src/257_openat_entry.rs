use super::*;

/// `sys_openat(dirfd, path, flags, mode)` — slot 257. No openat2 RESOLVE_*
/// modifiers (default `LookupFlags`). # C: O(N_path)
pub fn sys_openat(args: &SyscallArgs) -> i64 {
    let rv = open_core(args, vfs::LookupFlags::default(), false);
    #[cfg(feature = "debug-udevdb")]
    if let Ok(p) = crate::namei_common::read_user_path(args.a1) {
        crate::namei_common::trace_udevdb_path(b"openat", p.as_str(), rv);
    }
    // `debug-desktop`, not `debug-boot`: this re-copies the pathname out of
    // user memory on EVERY openat(2) just to run six substring scans, which is
    // real per-open cost even when nothing is printed.
    #[cfg(feature = "debug-desktop")]
    if let Ok(p) = crate::namei_common::read_user_path(args.a1) {
        crate::namei_common::trace_logind_dev(b"open", p.as_str(), rv);
    }
    rv
}

/// `sys_openat2(dirfd, path, how, size)`. Copies `struct open_how` with Linux
/// size/tail rules, validates `resolve`, and maps it onto `LookupFlags`
/// consumed by the resolver. The `RESOLVE_*` decisions live in the ungated
/// `openat2_resolve` module so they are unit-tested. # C: O(N_path + how_size)
pub fn sys_openat2(args: &SyscallArgs) -> i64 {
    let how = match copy_open_how(args.a2, args.a3) {
        Ok(h) => h, Err(rv) => return rv,
    };
    if let Err(e) = crate::openat2_resolve::validate_resolve(how.resolve) {
        return -(e.as_i32() as i64);
    }
    let mut sa = *args;
    sa.a2 = how.flags;
    sa.a3 = how.mode;
    let extra = crate::openat2_resolve::lookup_flags_from_resolve(how.resolve);
    let rv = open_core(&sa, extra, true);
    #[cfg(feature = "debug-udevdb")]
    if let Ok(p) = crate::namei_common::read_user_path(args.a1) {
        crate::namei_common::trace_udevdb_path(b"openat2", p.as_str(), rv);
    }
    rv
}

struct OpenHow {
    flags:   u64,
    mode:    u64,
    resolve: u64,
}

fn copy_open_how(ptr: u64, size: u64) -> Result<OpenHow, i64> {
    if size < OPEN_HOW_SIZE_VER0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    if size > PAGE_SIZE { return Err(-(Errno::E2big.as_i32() as i64)); }
    validate_user_readable(ptr, size)?;
    let flags = um::get_u64(ptr).map_err(|_| um::EFAULT)?;
    let mode = um::get_u64(ptr + 8).map_err(|_| um::EFAULT)?;
    let resolve = um::get_u64(ptr + 16).map_err(|_| um::EFAULT)?;
    if size > OPEN_HOW_SIZE_VER0 {
        let mut p = ptr + OPEN_HOW_SIZE_VER0;
        while p < ptr + size {
            if um::get_u8(p).map_err(|_| um::EFAULT)? != 0 {
                return Err(-(Errno::E2big.as_i32() as i64));
            }
            p += 1;
        }
    }
    Ok(OpenHow { flags, mode, resolve })
}

fn validate_user_readable(ptr: u64, len: u64) -> Result<(), i64> {
    use hal::{UserVirtAddr, PAGE_SIZE_BYTES, USER_VA_END};
    use vmm::VmaProt;
    if ptr == 0 { return Err(-(Errno::Efault.as_i32() as i64)); }
    let end = ptr.checked_add(len).ok_or(-(Errno::Efault.as_i32() as i64))?;
    if end > USER_VA_END { return Err(-(Errno::Efault.as_i32() as i64)); }
    if len == 0 { return Ok(()); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return Err(-(Errno::Efault.as_i32() as i64)),
    };
    // SAFETY: current task owns its mm slot during syscall argument copying.
    let mm = match unsafe { cur.mm_ref() } {
        Some(m) => m.clone(), None => return Err(-(Errno::Efault.as_i32() as i64)),
    };
    let mut va = ptr & !(PAGE_SIZE_BYTES - 1);
    let last = (end - 1) & !(PAGE_SIZE_BYTES - 1);
    loop {
        let uva = UserVirtAddr::new(va).ok_or(-(Errno::Efault.as_i32() as i64))?;
        match mm.find_vma(uva) {
            Some(v) if v.prot.contains(VmaProt::READ) => {}
            _ => return Err(-(Errno::Efault.as_i32() as i64)),
        }
        if va == last { return Ok(()); }
        va = va.checked_add(PAGE_SIZE_BYTES).ok_or(-(Errno::Efault.as_i32() as i64))?;
    }
}

pub(super) fn is_chr_rdev(inode: &vfs::InodeRef, rdev: u32) -> bool {
    inode.file_type() == vfs::FileType::CharDev && inode.rdev() == rdev
}

/// openat / openat2 shared core. `extra` carries the openat2 RESOLVE_* bits
/// (empty for plain openat). # C: O(N_path)
fn open_core(args: &SyscallArgs, extra: vfs::LookupFlags, openat2: bool) -> i64 {
    let rv = open_core_impl(args, extra, openat2);
    // Y3 cgroup-EACCES capture (gated): systemd --user (uid 979) EXIT_CGROUP
    // (code=219). Log the EXACT cgroup path + euid + inode owner that a denied
    // openat hit, to confirm/refute the delegation-chown hypothesis.
    #[cfg(feature = "debug-syscall")]
    if rv == -(Errno::Eacces.as_i32() as i64) {
        if let Ok(p) = crate::namei_common::read_user_path(args.a1) {
            let s: &str = p.as_str();
            if s.contains("cgroup") {
                use core::sync::atomic::Ordering;
                let cur = sched::live::current();
                let (vpid, euid) = match &cur {
                    Some(c) => {
                        let v = c.security.vtgid.load(Ordering::Acquire);
                        let vpid = if v != 0 { v } else { c.tgid.load(Ordering::Acquire) };
                        (vpid as u64, c.security.creds.euid.load(Ordering::Acquire) as u64)
                    }
                    None => (0, 0),
                };
                klog::write_raw(b"[CGACC] vpid=");
                klog::write_dec_u64(vpid);
                klog::write_raw(b" euid=");
                klog::write_dec_u64(euid);
                klog::write_raw(b" path=");
                klog::write_raw(s.as_bytes());
                // Inode ownership (delegation-chown probe): resolve the target
                // (it exists, this is a perm denial not ENOENT) and dump its
                // uid/gid/mode. root:root => chown not applied; 979 => applied.
                if let Ok(vp) = crate::pathresolve::resolve_path_raw(s, false) {
                    klog::write_raw(b" ino.uid=");
                    klog::write_dec_u64(vp.inode.uid().unwrap_or(0xFFFF_FFFF) as u64);
                    klog::write_raw(b" ino.gid=");
                    klog::write_dec_u64(vp.inode.gid().unwrap_or(0xFFFF_FFFF) as u64);
                    klog::write_raw(b" ino.mode=");
                    klog::write_hex_u64(vp.inode.i_mode() as u64);
                }
                klog::write_raw(b" rv=-13\n");
            }
        }
    }
    rv
}
