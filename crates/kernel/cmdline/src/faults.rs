// Boot parameters that decide what a fatal kernel event does: keep limping,
// stop dead, or restart the machine. A wedge that leaves no record is the
// failure these exist to convert into evidence.

use crate::token::{bare_flag, int_value, value};

/// `panic=<n>`: seconds to wait after a panic before restarting the machine.
/// `0` means "wait forever" (the default — a stopped machine keeps its
/// console text on screen). A negative value restarts immediately.
/// # C: O(line length)
pub fn panic_timeout_secs(line: &[u8]) -> Option<i64> { int_value(line, b"panic") }

/// `panic_on_warn`: stop the machine at the FIRST broken invariant, so the
/// state that produced it is what gets reported rather than whatever it
/// corrupts later. Accepts the bare flag and the `=1`/`=0` spellings.
/// # C: O(line length)
pub fn panic_on_warn(line: &[u8]) -> bool {
    match value(line, b"panic_on_warn") {
        Some(b"0") | Some(b"n") | Some(b"N") | Some(b"off") | Some(b"false") => false,
        Some(_) => true,
        None => bare_flag(line, b"panic_on_warn"),
    }
}

/// `oops=panic`: promote an unhandled kernel fault from "halt this CPU" to a
/// full panic, so the panic path's reporting and `panic=` restart apply.
/// # C: O(line length)
pub fn oops_panic(line: &[u8]) -> bool { value(line, b"oops") == Some(b"panic") }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_timeout_reads_seconds() {
        assert_eq!(panic_timeout_secs(b"root=/dev/oxide0 panic=30 quiet"), Some(30));
        assert_eq!(panic_timeout_secs(b"panic=0"), Some(0));
        assert_eq!(panic_timeout_secs(b"panic=-1"), Some(-1));
    }

    #[test]
    fn absent_or_malformed_panic_keeps_default() {
        assert_eq!(panic_timeout_secs(b"root=/dev/oxide0"), None);
        assert_eq!(panic_timeout_secs(b"panic=soon"), None, "a typo must not install a timeout");
    }

    #[test]
    fn panic_name_is_not_matched_by_a_prefix() {
        assert_eq!(panic_timeout_secs(b"panic_on_warn=1"), None);
        assert_eq!(panic_timeout_secs(b"kernel.panic=5"), None);
    }

    #[test]
    fn panic_on_warn_takes_the_flag_and_boolean_spellings() {
        assert!(panic_on_warn(b"quiet panic_on_warn"));
        assert!(panic_on_warn(b"panic_on_warn=1"));
        assert!(!panic_on_warn(b"panic_on_warn=0"));
        assert!(!panic_on_warn(b"quiet"));
        assert!(!panic_on_warn(b"panic_on_warn_extra=1"), "a prefix is a different parameter");
    }

    #[test]
    fn panic_on_warn_is_not_matched_by_panic() {
        assert_eq!(panic_timeout_secs(b"panic_on_warn=1"), None);
        assert!(!panic_on_warn(b"panic=30"));
    }

    #[test]
    fn oops_panic_requires_the_panic_value() {
        assert!(oops_panic(b"quiet oops=panic"));
        assert!(!oops_panic(b"quiet oops=warn"));
        assert!(!oops_panic(b"quiet oops"));
        assert!(!oops_panic(b"quiet"));
    }
}
