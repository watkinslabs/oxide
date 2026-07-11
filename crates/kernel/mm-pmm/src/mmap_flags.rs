use syscall::errno::Errno;

pub(crate) const MAP_SHARED:  u64 = 0x01;
pub(crate) const MAP_PRIVATE: u64 = 0x02;
pub(crate) const MAP_FIXED:   u64 = 0x10;
pub(crate) const MAP_ANON:    u64 = 0x20;
pub(crate) const MAP_GROWSDOWN: u64       = 0x100;
pub(crate) const MAP_DENYWRITE: u64       = 0x800;
pub(crate) const MAP_EXECUTABLE: u64      = 0x1000;
pub(crate) const MAP_LOCKED:    u64       = 0x2000;
pub(crate) const MAP_NORESERVE: u64       = 0x4000;
pub(crate) const MAP_POPULATE:  u64       = 0x8000;
pub(crate) const MAP_NONBLOCK:  u64       = 0x10000;
pub(crate) const MAP_STACK:     u64       = 0x20000;
pub(crate) const MAP_HUGETLB:   u64       = 0x40000;
pub(crate) const MAP_SYNC:      u64       = 0x80000;
pub(crate) const MAP_FIXED_NOREPLACE: u64 = 0x100000;
pub(crate) const MAP_UNINITIALIZED: u64   = 0x4000000;

const MAP_KNOWN: u64 = MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANON
    | MAP_GROWSDOWN | MAP_DENYWRITE | MAP_EXECUTABLE | MAP_LOCKED
    | MAP_NORESERVE | MAP_POPULATE | MAP_NONBLOCK | MAP_STACK
    | MAP_HUGETLB | MAP_SYNC | MAP_FIXED_NOREPLACE | MAP_UNINITIALIZED;

/// # C: O(1)
pub(crate) fn validate(flags: u64) -> Result<(), i64> {
    if (flags & !MAP_KNOWN) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    if (flags & MAP_HUGETLB) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hugetlb_uses_linux_einval_not_enosys() {
        let r = validate(MAP_PRIVATE | MAP_ANON | MAP_HUGETLB);
        assert_eq!(r, Err(-(Errno::Einval.as_i32() as i64)));
    }

    #[test]
    fn unknown_future_bits_are_einval() {
        let r = validate(MAP_PRIVATE | MAP_ANON | 0x8000_0000);
        assert_eq!(r, Err(-(Errno::Einval.as_i32() as i64)));
    }
}
