//! Scalar ranges for helper arguments and program return values.

use crate::bpf::uapi;
use crate::bpf_lsm::{Ret, spec};
use super::Profile;

/// Largest magnitude a program may return as a negative errno.
pub(super) const MAX_ERRNO: i64 = 4095;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct Scalar {
    pub(super) min: i64,
    pub(super) max: i64,
}

impl Scalar {
    /// # C: O(1)
    pub(super) const fn exact(value: i64) -> Self { Self { min: value, max: value } }
    /// # C: O(1)
    pub(super) const fn range(min: i64, max: i64) -> Self { Self { min, max } }
    /// # C: O(1)
    pub(super) const fn unknown() -> Self { Self::range(i64::MIN, i64::MAX) }
    /// # C: O(1)
    pub(super) const fn value(self) -> Option<i64> {
        if self.min == self.max { Some(self.min) } else { None }
    }
    /// # C: O(1)
    pub(super) fn i32_within(self, min: i32, max: i32) -> bool {
        if let Some(value) = self.value() {
            let value = value as i32;
            return value >= min && value <= max;
        }
        self.min >= min as i64 && self.max <= max as i64
    }
}

/// Range the exit value must lie in, or `None` for a program type whose
/// return carries no kernel-side bound. `None` still requires R0 to be an
/// initialized non-pointer scalar; it removes only the range. Socket
/// filters are the `None` case — their return is a byte count the receive
/// path clamps, so every value is meaningful.
/// # C: O(1)
pub(super) fn return_range(profile: &Profile) -> Option<Scalar> {
    use uapi::prog_type as p;
    let expected_attach_type = profile.expected_attach_type;
    match profile.prog_type {
        p::SOCKET_FILTER => None,
        // An iterator program answers one of two things per step: the
        // object was shown, or show it again.
        p::TRACING => Some(Scalar::range(0, 1)),
        // An LSM hook's return contract is the hook's, not the program
        // type's: an int-returning hook admits success or a negative
        // errno, a bool hook admits only the two truth values, and a
        // void hook constrains nothing beyond R0 being a live scalar.
        p::LSM => match profile.hook.map(|hook| spec(hook).ret) {
            Some(Ret::Errno) => Some(Scalar::range(-MAX_ERRNO, 0)),
            Some(Ret::Bool) => Some(Scalar::range(0, 1)),
            Some(Ret::Void) => None,
            None => Some(Scalar::exact(0)),
        },
        p::CGROUP_SKB if expected_attach_type == uapi::attach_type::CGROUP_INET_EGRESS =>
            Some(Scalar::range(0, 3)),
        p::CGROUP_SOCK_ADDR if matches!(expected_attach_type,
            uapi::attach_type::CGROUP_INET4_BIND | uapi::attach_type::CGROUP_INET6_BIND) =>
            Some(Scalar::range(0, 3)),
        _ => Some(Scalar::range(0, 1)),
    }
}
