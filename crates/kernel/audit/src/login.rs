// Per-task audit login identity policy and session-id allocation.

use syscall::errno::Errno;

use crate::uapi::{feature_to_mask, AUDIT_FEATURE_LOGINUID_IMMUTABLE,
    AUDIT_FEATURE_ONLY_UNSET_LOGINUID};

/// The value both audit identity fields use until a login is established.
pub const UNSET: u32 = u32::MAX;

/// Monotonic login-session allocator. The one forbidden value is skipped.
pub struct SessionIds { last: u32 }

impl SessionIds {
    /// # C: O(1)
    pub const fn new() -> Self { Self { last: 0 } }

    #[cfg(test)]
    const fn from_last(last: u32) -> Self { Self { last } }

    /// # C: O(1)
    fn alloc(&mut self) -> u32 {
        self.last = self.last.wrapping_add(1);
        if self.last == UNSET { self.last = self.last.wrapping_add(1); }
        self.last
    }
}

/// Apply the loginuid permission ladder and return the corresponding session.
/// An unset current identity is the unprivileged first-write case. Once set,
/// immutability wins, then capability, then the only-unset feature. # C: O(1)
pub fn decide<C>(ids: &mut SessionIds, features: u32, old: u32, new: u32,
                 cap_audit_control: C) -> Result<u32, Errno>
where C: FnOnce() -> bool
{
    if old != UNSET {
        if features & feature_to_mask(AUDIT_FEATURE_LOGINUID_IMMUTABLE) != 0 {
            return Err(Errno::Eperm);
        }
        if !cap_audit_control() { return Err(Errno::Eperm); }
        if features & feature_to_mask(AUDIT_FEATURE_ONLY_UNSET_LOGINUID) != 0
            && new != UNSET
        {
            return Err(Errno::Eperm);
        }
    }
    if new == UNSET { Ok(UNSET) } else { Ok(ids.alloc()) }
}

/// Apply the live audit configuration and allocate one session id. # C: O(1)
pub fn set<C>(old: u32, new: u32, cap_audit_control: C) -> Result<u32, Errno>
where C: FnOnce() -> bool
{
    crate::state::with(|s| decide(&mut s.sessions, s.cfg.features, old, new,
        cap_audit_control))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use syscall::errno::Errno;

    #[test]
    fn an_unset_identity_can_be_established_without_a_capability() {
        let mut ids = SessionIds::new();
        assert_eq!(decide(&mut ids, 0, UNSET, 1000, || false), Ok(1));
    }

    #[test]
    fn immutable_and_only_unset_rules_keep_linux_error_order() {
        let mut ids = SessionIds::new();
        let cap_asked = Cell::new(false);
        let immutable = crate::uapi::feature_to_mask(
            crate::uapi::AUDIT_FEATURE_LOGINUID_IMMUTABLE);
        assert_eq!(decide(&mut ids, immutable, 1000, 1001, || {
            cap_asked.set(true); true
        }), Err(Errno::Eperm));
        assert!(!cap_asked.get(), "immutable refusal precedes capability");
        assert_eq!(decide(&mut ids, 0, 1000, 1001, || false), Err(Errno::Eperm));
        let only_unset = crate::uapi::feature_to_mask(
            crate::uapi::AUDIT_FEATURE_ONLY_UNSET_LOGINUID);
        assert_eq!(decide(&mut ids, only_unset, 1000, 1001, || true), Err(Errno::Eperm));
        assert_eq!(decide(&mut ids, only_unset, 1000, UNSET, || true), Ok(UNSET));
    }

    #[test]
    fn the_session_allocator_never_publishes_the_unset_sentinel() {
        let mut ids = SessionIds::from_last(u32::MAX - 1);
        assert_eq!(decide(&mut ids, 0, UNSET, 1000, || false), Ok(0));
    }
}
