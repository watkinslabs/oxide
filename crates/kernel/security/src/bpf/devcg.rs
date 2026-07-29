// `BPF_CGROUP_DEVICE` enforcement — Linux
// `__cgroup_bpf_check_dev_permission()` (kernel/bpf/cgroup.c), reached
// from `devcgroup_check_permission()` via the `inode_permission` and
// `vfs_mknod` hooks in include/linux/device_cgroup.h.
//
// This is the run site systemd's `DeviceAllow=`/`DevicePolicy=` depend
// on. Accepting the attach without running the programs would publish a
// MAC guarantee the kernel does not keep, so load, attach and run are
// one feature, not three.

use syscall::errno::Errno;

use super::cgstore;
use super::uapi::devcg;

/// `bpf_cgroup_dev_ctx` as the interpreter sees it: three native-endian
/// `u32`s, read-only. Both supported targets are little-endian, which is
/// also how `bpf_interp`'s `LDX` decodes memory.
fn ctx_bytes(dev_type: u16, major: u32, minor: u32, access: u16) -> [u8; devcg::CTX_SIZE] {
    let mut c = [0u8; devcg::CTX_SIZE];
    let access_type = ((access as u32) << 16) | dev_type as u32;
    c[devcg::CTX_ACCESS_TYPE..devcg::CTX_ACCESS_TYPE + 4].copy_from_slice(&access_type.to_ne_bytes());
    c[devcg::CTX_MAJOR..devcg::CTX_MAJOR + 4].copy_from_slice(&major.to_ne_bytes());
    c[devcg::CTX_MINOR..devcg::CTX_MINOR + 4].copy_from_slice(&minor.to_ne_bytes());
    c
}

/// `devcgroup_check_permission()`. Every effective program runs; a
/// program returning 0 denies (`bpf_prog_run_array_cg()` turns the first
/// zero into `-EPERM` and keeps running the rest).
///
/// A program the interpreter cannot finish — an out-of-bounds context
/// read or an exhausted step budget, both of which Linux's verifier
/// rejects at load time and this one cannot yet prove — denies as well.
/// Failing open there would silently drop the policy.
/// # C: O(depth · progs · insns)
pub fn check_permission(dev_type: u16, major: u32, minor: u32, access: u16) -> Result<(), Errno> {
    if !cgstore::device_enabled() { return Ok(()); }
    let Some(cur) = sched::current() else { return Ok(()); };
    let progs = cgstore::device_effective(cgroup::cgroup_of(cur.tid as u64));
    if progs.is_empty() { return Ok(()); }
    let ctx = ctx_bytes(dev_type, major, minor, access);
    let mut verdict = Ok(());
    for p in &progs {
        let Some(bp) = p.prog() else { continue; };
        match crate::bpf_interp::run(&bp.insns, &ctx) {
            Some(r) if r as u32 != 0 => {}
            _ => verdict = Err(Errno::Eperm),
        }
    }
    verdict
}

/// VFS-facing shape of [`check_permission`]: the hook the `vfs`
/// `devcgroup_*` helpers call once they have classified the inode.
/// # C: O(depth · progs · insns)
pub fn vfs_hook(dev_type: u16, major: u32, minor: u32, access: u16) -> Result<(), vfs::VfsError> {
    check_permission(dev_type, major, minor, access).map_err(|_| vfs::VfsError::Eperm)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `access_type` word systemd's device programs decode with
    /// `AND 0xffff` (device type) and `RSH 16` (access mask).
    #[test]
    fn ctx_packs_access_over_device_type() {
        let c = ctx_bytes(devcg::DEV_CHAR, 1, 3, devcg::ACC_READ | devcg::ACC_WRITE);
        let at = u32::from_ne_bytes([c[0], c[1], c[2], c[3]]);
        assert_eq!(at & 0xffff, devcg::DEV_CHAR as u32);
        assert_eq!(at >> 16, (devcg::ACC_READ | devcg::ACC_WRITE) as u32);
        assert_eq!(u32::from_ne_bytes([c[4], c[5], c[6], c[7]]), 1);
        assert_eq!(u32::from_ne_bytes([c[8], c[9], c[10], c[11]]), 3);
    }

    #[test]
    fn context_is_exactly_the_uapi_struct_size() {
        assert_eq!(ctx_bytes(devcg::DEV_BLOCK, 0, 0, 0).len(), 12);
    }

    /// A device program shaped like the one systemd emits: read the
    /// device type, the access mask, major and minor from the context,
    /// and accept exactly `c 1:3 rw`.
    #[test]
    fn a_systemd_shaped_device_program_evaluates_against_the_context() {
        fn insn(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
            let o = off.to_le_bytes();
            let m = imm.to_le_bytes();
            [opc, (src << 4) | (dst & 0x0f), o[0], o[1], m[0], m[1], m[2], m[3]]
        }
        let prog: alloc::vec::Vec<u8> = [
            insn(0x61, 2, 1, 0, 0),      // LDX_W r2 = ctx->access_type
            insn(0x54, 2, 0, 0, 0xffff), // AND32 r2, 0xffff        (device type)
            insn(0x61, 3, 1, 0, 0),      // LDX_W r3 = ctx->access_type
            insn(0x74, 3, 0, 0, 16),     // RSH32 r3, 16            (access mask)
            insn(0x61, 4, 1, 4, 0),      // LDX_W r4 = ctx->major
            insn(0x61, 5, 1, 8, 0),      // LDX_W r5 = ctx->minor
            insn(0xbc, 1, 3, 0, 0),      // MOV32 r1 = r3
            insn(0x54, 1, 0, 0, 6),      // AND32 r1, (READ|WRITE)
            insn(0x5d, 1, 3, 5, 0),      // JNE r1, r3 -> deny
            insn(0x55, 2, 0, 4, 2),      // JNE r2, DEV_CHAR -> deny
            insn(0x55, 4, 0, 3, 1),      // JNE r4, 1 -> deny
            insn(0x55, 5, 0, 2, 3),      // JNE r5, 3 -> deny
            insn(0xb7, 0, 0, 0, 1),      // MOV64 r0 = 1 (allow)
            insn(0x95, 0, 0, 0, 0),      // EXIT
            insn(0xb7, 0, 0, 0, 0),      // MOV64 r0 = 0 (deny)
            insn(0x95, 0, 0, 0, 0),      // EXIT
        ].concat();
        assert_eq!(crate::bpf_verify::verify_cgroup_device(&prog), Ok(()));
        let allow = ctx_bytes(devcg::DEV_CHAR, 1, 3, devcg::ACC_READ);
        assert_eq!(crate::bpf_interp::run(&prog, &allow), Some(1));
        let wrong_minor = ctx_bytes(devcg::DEV_CHAR, 1, 5, devcg::ACC_READ);
        assert_eq!(crate::bpf_interp::run(&prog, &wrong_minor), Some(0));
        let wrong_type = ctx_bytes(devcg::DEV_BLOCK, 1, 3, devcg::ACC_READ);
        assert_eq!(crate::bpf_interp::run(&prog, &wrong_type), Some(0));
        let mknod = ctx_bytes(devcg::DEV_CHAR, 1, 3, devcg::ACC_MKNOD);
        assert_eq!(crate::bpf_interp::run(&prog, &mknod), Some(0));
    }
}
