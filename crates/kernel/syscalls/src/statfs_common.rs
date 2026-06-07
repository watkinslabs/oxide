// statfs shared helpers — used by ≥2 statfs handlers (docs/53 §0).
// Moved verbatim from statfs.rs.

#![cfg(target_os = "oxide-kernel")]

// struct statfs `f_type` magics (linux/magic.h).
pub(crate) const M_PROC:    u64 = 0x9fa0;
pub(crate) const M_SYSFS:   u64 = 0x6265_6572;
pub(crate) const M_TMPFS:   u64 = 0x0102_1994;
pub(crate) const M_CGROUP2: u64 = 0x6367_7270;
pub(crate) const M_DEVPTS:  u64 = 0x1cd1;
pub(crate) const M_EXT4:    u64 = 0xEF53;

/// True when `m` equals `path` or is a path-prefix of it (`m` + `/…`).
/// # C: O(len(path))
fn under(path: &str, m: &str) -> bool {
    path == m || (path.starts_with(m) && path.as_bytes().get(m.len()) == Some(&b'/'))
}

/// Resolve an absolute path to its backing filesystem's `s_magic`.
/// Consults the live mount table first (so user `mount -t tmpfs|cgroup2`
/// and bind mounts report correctly — the Linux way), then a prefix
/// table for the fixed synthetic trees not registered as mounts
/// (sysfs `/sys`, devpts `/dev/pts`, tmpfs `/run` + `/dev/shm`), then
/// falls back to the ext4 rootfs.
/// # C: O(N_mounts)
pub(crate) fn magic_for_path(path: &str) -> u64 {
    // A registered mount that isn't the root wins (longest-prefix).
    if let Some((mnt, _)) = vfs::mount::resolve_mount(path) {
        if mnt.mount_point != "/" {
            let m = mnt.fs.magic();
            if m != 0 { return m; }
        }
    }
    // Fixed synthetic mounts not in the table. cgroup before sysfs.
    if under(path, "/sys/fs/cgroup")             { return M_CGROUP2; }
    if under(path, "/proc")                      { return M_PROC; }
    if under(path, "/sys")                       { return M_SYSFS; }
    if under(path, "/dev/pts")                   { return M_DEVPTS; }
    if under(path, "/dev/shm") || under(path, "/run") || under(path, "/tmp") { return M_TMPFS; }
    if under(path, "/dev")                       { return M_TMPFS; }
    M_EXT4
}

/// Fill a 120-byte `struct statfs` (identical LP64 layout on x86_64
/// and aarch64). `magic` is `f_type`; `blocks`/`bfree`/`bavail`/`files`
/// fill the usage fields so `df` keeps the entry (df drops
/// rows with f_blocks==0).
/// # C: O(1)
pub(crate) fn write_statfs(buf: u64, magic: u64, blocks: u64, bfree: u64, files: u64) {
    // SAFETY: caller validated 120-byte user buf < USER_VA_END, 8-aligned; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..120u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        core::ptr::write_volatile( buf        as *mut u64, magic);  // f_type   @0
        core::ptr::write_volatile((buf +  8)  as *mut u64, 4096);   // f_bsize  @8
        core::ptr::write_volatile((buf + 16)  as *mut u64, blocks); // f_blocks @16
        core::ptr::write_volatile((buf + 24)  as *mut u64, bfree);  // f_bfree  @24
        core::ptr::write_volatile((buf + 32)  as *mut u64, bfree);  // f_bavail @32
        core::ptr::write_volatile((buf + 40)  as *mut u64, files);  // f_files  @40
        core::ptr::write_volatile((buf + 48)  as *mut u64, files);  // f_ffree  @48
        core::ptr::write_volatile((buf + 64)  as *mut u64, 255);    // f_namelen@64 (NAME_MAX)
        core::ptr::write_volatile((buf + 72)  as *mut u64, 4096);   // f_frsize @72
    }
}

/// Plausible (blocks, bfree, files) by magic. Real ext4 usage comes
/// from the rootfs blob size; synthetic fses report a token nonzero
/// so `df` doesn't drop them. v1: not real per-fs accounting.
/// # C: O(1)
pub(crate) fn usage_for(magic: u64) -> (u64, u64, u64) {
    match magic {
        M_EXT4 => {
            // Image is 32 MiB today (xtask rootfs builder); inode count
            // matches mkfs.ext4 default. Reporting half-free is plausible
            // until real per-fs accounting lands.
            let blocks: u64 = 8192;
            (blocks, blocks / 2, 8192)
        }
        _ => (1, 0, 1),
    }
}
