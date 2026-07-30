//! Scalar ranges for helper arguments and program return values.

use crate::bpf::uapi;

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

/// # C: O(1)
pub(super) fn return_range(prog_type: u32, expected_attach_type: u32) -> Scalar {
    if prog_type == uapi::prog_type::CGROUP_SKB
        && expected_attach_type == uapi::attach_type::CGROUP_INET_EGRESS
        || prog_type == uapi::prog_type::CGROUP_SOCK_ADDR
            && matches!(expected_attach_type,
                uapi::attach_type::CGROUP_INET4_BIND | uapi::attach_type::CGROUP_INET6_BIND) {
        Scalar::range(0, 3)
    } else {
        Scalar::range(0, 1)
    }
}
