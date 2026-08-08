// `faccessat`'s credential override — Linux `access_override_creds`
//. Ungated so the rule is testable: the caller in
// `pathresolve/cred.rs` is `#![cfg(target_os = "oxide-kernel")]`, where a
// `#[cfg(test)] mod tests` compiles out silently.

/// Effective capability set for a non-`AT_EACCESS` `faccessat` probe.
///
/// Linux switches fsuid/fsgid to the REAL ids, then applies the setuid fixup
/// **only when `SECURE_NO_SETUID_FIXUP` is clear**: non-root loses its effective
/// set, root gets its permitted set. With the securebit SET, the caller's
/// existing effective set is carried through untouched — a process that
/// deliberately keeps capabilities across a uid switch keeps them here, and
/// recomputing from uid would silently strip them, which is precisely what the
/// securebit exists to prevent.
/// # C: O(1)
pub fn access_override_effective(
    real_uid: u32, permitted: u64, current_effective: u64, no_setuid_fixup: bool,
) -> u64 {
    if no_setuid_fixup { return current_effective; }
    if real_uid == 0 { permitted } else { 0 }
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod tests {
    use super::access_override_effective;

    #[test]
    fn non_root_loses_its_effective_set_when_the_fixup_applies() {
        assert_eq!(access_override_effective(1000, 0xffff, 0x00ff, false), 0);
    }

    #[test]
    fn root_gets_its_permitted_set_when_the_fixup_applies() {
        assert_eq!(access_override_effective(0, 0xffff, 0x00ff, false), 0xffff);
    }

    #[test]
    fn the_securebit_carries_the_existing_effective_set_through() {
        // The case that was missing: with SECURE_NO_SETUID_FIXUP set, neither
        // branch above may run. A non-root caller keeps what it had — the old
        // code returned 0 here and silently stripped it.
        assert_eq!(access_override_effective(1000, 0xffff, 0x00ff, true), 0x00ff);
        // And root is NOT promoted to its permitted set either.
        assert_eq!(access_override_effective(0, 0xffff, 0x00ff, true), 0x00ff);
    }
}
