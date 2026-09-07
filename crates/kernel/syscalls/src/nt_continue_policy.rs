//! Which extended continue must test for a pending alert first.
//!
//! The second argument of the extended continue is overloaded: a small value
//! is the alertable boolean itself, and a larger one is the address of a
//! record whose flags word carries the request. Both forms are live, so the
//! decision is made once, here, rather than at each caller.

/// Continue flag naming a pending-alert test before the context is restored.
pub const KCONTINUE_FLAG_TEST_ALERT: u32 = 0x01;
/// Argument values at or below this are the flag itself rather than a pointer
/// to a continue-argument record.
pub const KCONTINUE_ARGUMENT_MIN_POINTER: u64 = 0xff;
/// Byte offset of the continue flags within a continue-argument record.
pub const KCONTINUE_FLAGS_OFFSET: u64 = 4;

/// Whether an extended continue must test for a pending alert first. The
/// second argument is overloaded: a small value is a boolean in its own
/// right, and a larger one is the address of a record whose flags word
/// carries the request.
/// # C: O(1)
pub fn continue_ex_alertable(argument: u64, flags: impl FnOnce(u64) -> Option<u32>) -> Option<bool> {
    if argument <= KCONTINUE_ARGUMENT_MIN_POINTER { return Some(argument != 0); }
    let flags = flags(argument.checked_add(KCONTINUE_FLAGS_OFFSET)?)?;
    Some(flags & KCONTINUE_FLAG_TEST_ALERT != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_small_argument_is_the_alertable_boolean_itself() {
        assert_eq!(continue_ex_alertable(0, |_| unreachable!("no record is read")), Some(false));
        assert_eq!(continue_ex_alertable(1, |_| unreachable!("no record is read")), Some(true));
        assert_eq!(continue_ex_alertable(0xff, |_| unreachable!()), Some(true));
        assert_eq!(KCONTINUE_ARGUMENT_MIN_POINTER, 0xff);
        assert_eq!(KCONTINUE_FLAG_TEST_ALERT, 0x01);
    }

    #[test]
    fn a_record_address_is_read_for_its_flags_word() {
        let base = 0x7fff_0000_1000u64;
        assert_eq!(continue_ex_alertable(base, |address| {
            // The record's first word is the continue type; the flags word is
            // the second, four bytes in. Naming the constant here would make
            // the check agree with any offset the constant happened to hold.
            assert_eq!(address, base + 4, "the flags word follows the type word");
            Some(KCONTINUE_FLAG_TEST_ALERT)
        }), Some(true));
    }

    #[test]
    fn a_record_without_the_alert_flag_does_not_test_for_one() {
        let base = 0x7fff_0000_1000u64;
        assert_eq!(continue_ex_alertable(base, |_| Some(0)), Some(false));
        // An unrelated flag must not be read as the alert request.
        assert_eq!(continue_ex_alertable(base, |_| Some(0x02)), Some(false));
    }

    #[test]
    fn an_unreadable_record_yields_no_decision() {
        assert_eq!(continue_ex_alertable(0x7fff_0000_1000, |_| None), None);
    }
}
