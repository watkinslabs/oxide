// memfd_create(2) flag policy — Linux `mm/memfd.c` `sanitize_flags` (l.407),
// `check_sysctl_memfd_noexec` (l.344), `memfd_alloc_file` (l.454) and
// `alloc_name` (l.428) as of linux-master v7.2.0-rc4.
//
// NOT target-gated: `319_memfd_create.rs` carries `#![cfg(target_os =
// "oxide-kernel")]`, so a `#[cfg(test)]` block inside it never compiles. The
// EINVAL/EACCES ladder and the derived seal-word / inode-mode state live here
// where hosted `cargo test` reaches them.

use syscall::errno::Errno;

/// `include/uapi/linux/memfd.h`.
pub const MFD_CLOEXEC:       u32 = 0x0001;
pub const MFD_ALLOW_SEALING: u32 = 0x0002;
pub const MFD_HUGETLB:       u32 = 0x0004;
pub const MFD_NOEXEC_SEAL:   u32 = 0x0008;
pub const MFD_EXEC:          u32 = 0x0010;
/// `MFD_ALL_FLAGS` (`mm/memfd.c:342`).
pub const MFD_ALL_FLAGS: u32 =
    MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_NOEXEC_SEAL | MFD_EXEC;
/// Huge-page size encoding admitted alongside `MFD_HUGETLB` only
/// (`include/uapi/asm-generic/hugetlb_encode.h:20`).
pub const MFD_HUGE_SHIFT: u32 = 26;
pub const MFD_HUGE_MASK:  u32 = 0x3f;

/// `F_SEAL_*` (`include/uapi/linux/fcntl.h:47`). The seal word a fresh memfd
/// carries; `F_ADD_SEALS`/`F_GET_SEALS` in `072_fcntl.rs` read the same word.
pub use vfs::{F_SEAL_EXEC, F_SEAL_SEAL};

/// `pidns_memfd_noexec_scope` levels (`include/linux/pid_namespace.h:21`).
pub const MEMFD_NOEXEC_SCOPE_EXEC: u32 =
    namespace_identity::PID_MEMFD_NOEXEC_SCOPE_EXEC as u32;
pub const MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL: u32 =
    namespace_identity::PID_MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL as u32;
pub const MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED: u32 =
    namespace_identity::PID_MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED as u32;

/// `shmem_get_inode(..., S_IFREG | S_IRWXUGO, ...)` (`mm/shmem.c:5793`) — a
/// memfd inode is born 0777, NOT 0644.
pub const MEMFD_PERM: u16 = 0o777;
/// `MFD_NOEXEC_SEAL`: `inode->i_mode &= ~0111` (`mm/memfd.c:489`).
pub const MEMFD_PERM_NOEXEC: u16 = MEMFD_PERM & !0o111;

/// `MFD_NAME_PREFIX` / `MFD_NAME_MAX_LEN` (`mm/memfd.c:338`).
pub const MFD_NAME_PREFIX: &[u8] = b"memfd:";
pub const MFD_NAME_MAX_LEN: usize = vfs::path::NAME_MAX - MFD_NAME_PREFIX.len();

/// Per-file state `memfd_alloc_file` installs once the flags are sanitized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemfdSetup {
    /// Initial seal word.
    pub seals: u32,
    /// Initial `i_mode` permission bits.
    pub perm: u16,
    /// `FD_CLOEXEC` on the returned descriptor.
    pub cloexec: bool,
    /// Backing store must be hugetlbfs.
    pub hugetlb: bool,
}

/// `sanitize_flags` + `check_sysctl_memfd_noexec`: reject undefined bits and
/// the `MFD_EXEC | MFD_NOEXEC_SEAL` contradiction, then fold the
/// `vm.memfd_noexec` scope default into the returned EFFECTIVE flags. Runs
/// before the name is read, so its errors outrank the name's `EFAULT`/`EINVAL`.
/// # C: O(1)
pub fn sanitize_flags(flags: u32, scope: u32) -> Result<u32, Errno> {
    if flags & MFD_HUGETLB == 0 {
        if flags & !MFD_ALL_FLAGS != 0 { return Err(Errno::Einval); }
    } else if flags & !(MFD_ALL_FLAGS | (MFD_HUGE_MASK << MFD_HUGE_SHIFT)) != 0 {
        return Err(Errno::Einval);
    }
    if flags & MFD_EXEC != 0 && flags & MFD_NOEXEC_SEAL != 0 { return Err(Errno::Einval); }
    let mut eff = flags;
    if eff & (MFD_EXEC | MFD_NOEXEC_SEAL) == 0 {
        if scope >= MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL { eff |= MFD_NOEXEC_SEAL; }
        else { eff |= MFD_EXEC; }
    }
    if eff & MFD_NOEXEC_SEAL == 0 && scope >= MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED {
        return Err(Errno::Eacces);
    }
    Ok(eff)
}

/// Apply the effective policy owned by one active PID namespace.
/// # C: O(PID namespace depth)
pub fn sanitize_flags_for_pidns(flags: u32,
    namespace: &namespace_identity::NamespaceRef) -> Result<u32, Errno>
{
    let scope = namespace.pid_memfd_noexec_scope().map_err(|_| Errno::Einval)?;
    sanitize_flags(flags, u32::from(scope))
}

/// Seal word / inode mode / fd flags `memfd_alloc_file` derives from the
/// sanitized flags. A shmem inode is born with `F_SEAL_SEAL` set
/// (`mm/shmem.c:3030`); `MFD_ALLOW_SEALING` and `MFD_NOEXEC_SEAL` are the only
/// two flags that clear it, and `MFD_NOEXEC_SEAL` additionally sets
/// `F_SEAL_EXEC` and strips the inode's exec bits.
/// # C: O(1)
pub fn setup(eff: u32) -> MemfdSetup {
    let sealing = eff & (MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL) != 0;
    let mut seals = if sealing { 0 } else { F_SEAL_SEAL };
    let mut perm = MEMFD_PERM;
    if eff & MFD_NOEXEC_SEAL != 0 {
        seals |= F_SEAL_EXEC;
        perm = MEMFD_PERM_NOEXEC;
    }
    MemfdSetup {
        seals,
        perm,
        cloexec: eff & MFD_CLOEXEC != 0,
        hugetlb: eff & MFD_HUGETLB != 0,
    }
}

/// `alloc_name`'s length verdict: `strncpy_from_user(dst, uname,
/// MFD_NAME_MAX_LEN + 1)` returns the copied length, and `len >
/// MFD_NAME_MAX_LEN` is `EINVAL` — so a name of exactly `MFD_NAME_MAX_LEN`
/// bytes is accepted and one byte more is rejected. `scan_user_cstr` reports
/// the same window as `Enametoolong`, which this maps.
/// # C: O(1)
pub fn name_scan_err(e: Errno) -> Errno {
    if e == Errno::Enametoolong { Errno::Einval } else { e }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: u32 = MEMFD_NOEXEC_SCOPE_EXEC;

    #[test]
    fn undefined_bits_are_einval_without_hugetlb() {
        assert_eq!(sanitize_flags(0x20, DEFAULT), Err(Errno::Einval));
        assert_eq!(sanitize_flags(MFD_CLOEXEC | 0x8000_0000, DEFAULT), Err(Errno::Einval));
    }

    #[test]
    fn hugetlb_admits_the_huge_page_size_encoding() {
        // MFD_HUGE_2MB = 21 << 26 — EINVAL without MFD_HUGETLB, accepted with it.
        let huge_2mb = 21u32 << MFD_HUGE_SHIFT;
        assert_eq!(sanitize_flags(huge_2mb, DEFAULT), Err(Errno::Einval));
        assert_eq!(sanitize_flags(MFD_HUGETLB | huge_2mb, DEFAULT), Ok(MFD_HUGETLB | huge_2mb | MFD_EXEC));
    }

    #[test]
    fn hugetlb_still_rejects_bits_above_the_size_encoding() {
        let above = 1u32 << 5;
        assert_eq!(sanitize_flags(MFD_HUGETLB | above, DEFAULT), Err(Errno::Einval));
    }

    #[test]
    fn hugetlb_and_allow_sealing_is_not_rejected() {
        // No current check pairs them (`mm/memfd.c:407..426` only rejects
        // undefined bits and EXEC|NOEXEC_SEAL); hugetlbfs grew seal support.
        assert!(sanitize_flags(MFD_HUGETLB | MFD_ALLOW_SEALING, DEFAULT).is_ok());
    }

    #[test]
    fn exec_and_noexec_seal_together_are_einval() {
        assert_eq!(sanitize_flags(MFD_EXEC | MFD_NOEXEC_SEAL, DEFAULT), Err(Errno::Einval));
    }

    #[test]
    fn neither_exec_flag_takes_the_sysctl_default() {
        assert_eq!(sanitize_flags(0, MEMFD_NOEXEC_SCOPE_EXEC), Ok(MFD_EXEC));
        assert_eq!(sanitize_flags(0, MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL), Ok(MFD_NOEXEC_SEAL));
        assert_eq!(sanitize_flags(0, MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED), Ok(MFD_NOEXEC_SEAL));
    }

    #[test]
    fn enforced_scope_rejects_an_explicit_exec_request() {
        assert_eq!(sanitize_flags(MFD_EXEC, MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED), Err(Errno::Eacces));
        assert_eq!(sanitize_flags(MFD_EXEC, MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL), Ok(MFD_EXEC));
    }

    #[test]
    fn pid_namespace_policy_drives_effective_flags() {
        let user = namespace_identity::initial(namespace_identity::NamespaceKind::User);
        let namespace = namespace_identity::allocate(
            namespace_identity::NamespaceKind::Pid, user, None).unwrap();
        namespace.set_pid_memfd_noexec_scope(
            namespace_identity::PID_MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL).unwrap();
        assert_eq!(sanitize_flags_for_pidns(0, &namespace), Ok(MFD_NOEXEC_SEAL));
        namespace.set_pid_memfd_noexec_scope(
            namespace_identity::PID_MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED).unwrap();
        assert_eq!(sanitize_flags_for_pidns(MFD_EXEC, &namespace), Err(Errno::Eacces));
    }

    #[test]
    fn a_plain_memfd_is_born_sealed_against_further_seals() {
        let s = setup(sanitize_flags(0, DEFAULT).expect("plain memfd"));
        assert_eq!(s.seals, F_SEAL_SEAL, "F_GET_SEALS on a no-ALLOW_SEALING memfd reads F_SEAL_SEAL");
        assert_eq!(s.perm, MEMFD_PERM);
        assert!(!s.cloexec);
    }

    #[test]
    fn allow_sealing_clears_the_seal_seal_bit() {
        let s = setup(sanitize_flags(MFD_ALLOW_SEALING, DEFAULT).expect("sealable memfd"));
        assert_eq!(s.seals, 0);
        assert_eq!(s.perm, MEMFD_PERM);
    }

    #[test]
    fn noexec_seal_sets_seal_exec_and_strips_the_exec_bits() {
        let s = setup(sanitize_flags(MFD_NOEXEC_SEAL, DEFAULT).expect("noexec memfd"));
        assert_eq!(s.seals, F_SEAL_EXEC, "sealing is enabled AND F_SEAL_EXEC applied immediately");
        assert_eq!(s.perm, MEMFD_PERM_NOEXEC);
        assert_eq!(s.perm & 0o111, 0);
    }

    #[test]
    fn noexec_seal_with_allow_sealing_is_the_same_state() {
        let a = setup(sanitize_flags(MFD_NOEXEC_SEAL, DEFAULT).expect("a"));
        let b = setup(sanitize_flags(MFD_NOEXEC_SEAL | MFD_ALLOW_SEALING, DEFAULT).expect("b"));
        assert_eq!(a.seals, b.seals);
        assert_eq!(a.perm, b.perm);
    }

    #[test]
    fn cloexec_and_hugetlb_are_reported_separately() {
        let s = setup(sanitize_flags(MFD_CLOEXEC | MFD_HUGETLB, DEFAULT).expect("cloexec hugetlb"));
        assert!(s.cloexec);
        assert!(s.hugetlb);
    }

    #[test]
    fn the_name_budget_leaves_room_for_the_prefix() {
        assert_eq!(MFD_NAME_PREFIX, b"memfd:");
        assert_eq!(MFD_NAME_MAX_LEN, 255 - 6);
    }

    #[test]
    fn an_over_long_name_is_einval_not_enametoolong() {
        assert_eq!(name_scan_err(Errno::Enametoolong), Errno::Einval);
        assert_eq!(name_scan_err(Errno::Efault), Errno::Efault);
    }
}
