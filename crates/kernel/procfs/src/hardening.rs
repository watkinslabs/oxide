// Honest defaults for the `/proc/sys/kernel` leaves that REPORT a hardening
// capability rather than tune one. `checksec`, `lynis`, `systemd-analyze
// security` and CIS scanners read these files and act on the number; a value
// describing a mitigation the kernel does not have is a false security report,
// not a harmless placeholder.
//
// UNGATED on purpose — `ctl.rs` is `#[cfg(target_os = "oxide-kernel")]`, so a
// test living beside the table would compile out silently.

/// `kernel.randomize_va_space` default. Linux owns this in `mm/memory.c`
/// (`int randomize_va_space` + the `mmu_sysctl_table` `proc_dointvec` leaf);
/// `Documentation/admin-guide/sysctl/kernel.rst` defines the ladder as
/// 0 = off, 1 = mmap base + stack + vDSO randomized, 2 = 1 plus heap (brk).
///
/// 0 here because this kernel implements NO address-space randomization —
/// `docs/31§6` ("ships without ASLR for now"), and the code agrees on every
/// address Linux would randomize: PIE load bias is the constant
/// `exec::PIE_LOAD_BIAS`, ld.so base `exec::INTERP_LOAD_BIAS`, stack top
/// `hal::USER_VA_END - 0x10000`, mmap base `stack - vmm::MMAP_BASE_GAP` over a
/// deterministic top-down first fit (`mm-vmm` `hole::find_hole`), brk the
/// page-aligned end of the last `PT_LOAD`. 0 is exactly what Linux reports for
/// "architectures that do not support this feature anyways", so a detector
/// reading this file is told the truth. When ASLR lands, this leaf repoints at
/// the mm-owned variable per the `ctl.rs` backing-variable policy rather than
/// having its constant raised.
pub const RANDOMIZE_VA_SPACE_DEFAULT: i64 = 0;

/// Writable window Linux gives the leaf (`proc_dointvec` over the full 0..=2
/// ladder). Writes are accepted regardless of what is implemented, matching
/// Linux — `norandmaps` and `sysctl -w` both move the value.
pub const RANDOMIZE_VA_SPACE_BOUNDS: (i64, i64) = (0, 2);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randomize_va_space_reports_no_aslr() {
        assert_eq!(RANDOMIZE_VA_SPACE_DEFAULT, 0,
            "no ASLR is implemented (docs/31§6); reporting nonzero is a false hardening report");
        let (min, max) = RANDOMIZE_VA_SPACE_BOUNDS;
        assert_eq!((min, max), (0, 2), "Linux accepts writes of 0/1/2 regardless");
        assert!(RANDOMIZE_VA_SPACE_DEFAULT >= min && RANDOMIZE_VA_SPACE_DEFAULT <= max);
    }
}
