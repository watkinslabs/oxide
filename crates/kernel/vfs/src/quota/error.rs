/// Quota accounting failure. `Edquot` maps to Linux EDQUOT at syscall edges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaError {
    Edquot,
    Einval,
}

/// Quota subsystem result. # C: O(1)
pub type QuotaResult<T> = core::result::Result<T, QuotaError>;
