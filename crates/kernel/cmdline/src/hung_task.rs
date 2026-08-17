// Hung-task detector boot parameters. Pure decisions over the command line;
// the scheduler's detector applies them once at boot.

use crate::token::{bare_flag, full_uint, value};

/// `hung_task_timeout_secs=<n>`: seconds a task may sleep uninterruptibly
/// before it is reported. `0` disables the detector. `None` keeps the build
/// default. A malformed value is `None` rather than `0`, because a typo must
/// not silently switch the detector off.
/// # C: O(line length)
pub fn timeout_secs(line: &[u8]) -> Option<u64> {
    value(line, b"hung_task_timeout_secs").and_then(full_uint)
}

/// `hung_task_panic[=<bool>]`: panic once a task is reported hung, rather
/// than logging and continuing.
/// # C: O(line length)
pub fn panic_on_hung(line: &[u8]) -> bool {
    match value(line, b"hung_task_panic") {
        Some(v) => matches!(v, b"1" | b"y" | b"Y" | b"on" | b"true" | b""),
        None => bare_flag(line, b"hung_task_panic"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_without_the_parameters_asks_for_nothing() {
        assert_eq!(timeout_secs(b"root=/dev/vda rw"), None);
        assert!(!panic_on_hung(b"root=/dev/vda rw"));
    }

    #[test]
    fn the_timeout_is_read_in_seconds() {
        assert_eq!(timeout_secs(b"quiet hung_task_timeout_secs=30 rw"), Some(30));
        assert_eq!(timeout_secs(b"hung_task_timeout_secs=0"), Some(0), "0 disables");
    }

    /// A typo must keep the default, never install `0` — that would turn a
    /// mistyped knob into a silently disabled detector.
    #[test]
    fn a_malformed_timeout_keeps_the_default() {
        assert_eq!(timeout_secs(b"hung_task_timeout_secs=abc"), None);
        assert_eq!(timeout_secs(b"hung_task_timeout_secs=30s"), None);
    }

    #[test]
    fn the_panic_flag_takes_both_spellings() {
        assert!(panic_on_hung(b"hung_task_panic"));
        assert!(panic_on_hung(b"hung_task_panic=1"));
        assert!(!panic_on_hung(b"hung_task_panic=0"));
        assert!(!panic_on_hung(b"hung_task_panicky=1"), "a longer name is a different name");
    }
}
