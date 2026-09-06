//! `NtUserCallMsgFilter`: WH_SYSMSGFILTER then WH_MSGFILTER hook chains decide
//! whether a dialog/menu message is consumed. Without an installed hook the
//! reference consumes nothing.
pub(crate) const ORDINAL: u64 = 0x133a;

/// # C: O(1)
pub(crate) fn route(ordinal: u64, hooks_installed: impl FnOnce() -> bool) -> Option<u64> {
    if ordinal != ORDINAL { return None; }
    Some(u64::from(hooks_installed()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn without_a_hook_no_message_is_filtered() {
        assert_eq!(route(ORDINAL, || false), Some(0));
        assert_eq!(route(ORDINAL, || true), Some(1));
        assert_eq!(route(0x1332, || panic!("wrong ordinal consulted hooks")), None);
    }
}
