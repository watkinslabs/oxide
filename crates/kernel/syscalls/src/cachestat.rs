// `cachestat(2)` admission policy (`can_do_cachestat`).
//
// Ungated: the slot file is `#![cfg(target_os = "oxide-kernel")]`, so the
// permission ladder would otherwise never be exercised by a hosted test.

/// `can_do_cachestat` — page-cache residency is a side channel onto file
/// contents, so the caller must be someone who could have written the file
/// anyway. Three accepting legs, in Linux's short-circuit order: the
/// description is already open for writing; the caller owns the inode (or
/// holds the override capability); or a write-permission check on the file
/// passes. `EPERM` when all three fail.
/// # C: O(1)
pub fn can_do_cachestat(fmode_write: bool, owner_or_capable: bool, may_write_ok: bool) -> bool {
    fmode_write || owner_or_capable || may_write_ok
}

#[cfg(test)]
mod tests {
    use super::can_do_cachestat;

    // A description open for writing is admitted without consulting ownership
    // or the inode's mode bits at all.
    #[test]
    fn write_open_description_is_admitted_alone() {
        assert!(can_do_cachestat(true, false, false));
    }

    // Ownership (or the override capability) admits a read-only description
    // even when the mode bits deny writing — the "could open for writing" leg.
    #[test]
    fn owner_is_admitted_without_write_mode() {
        assert!(can_do_cachestat(false, true, false));
    }

    // A non-owner with write permission through the mode/ACL is admitted.
    #[test]
    fn write_permission_admits_a_non_owner() {
        assert!(can_do_cachestat(false, false, true));
    }

    // All three legs failing is the only EPERM case.
    #[test]
    fn read_only_non_owner_without_write_permission_is_refused() {
        assert!(!can_do_cachestat(false, false, false));
    }
}
