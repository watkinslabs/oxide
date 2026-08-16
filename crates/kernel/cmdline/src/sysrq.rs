// `sysrq_always_enabled`: take the magic-SysRq keys out of the sysctl's hands.
//
// `kernel.sysrq` is userspace policy, and on a composed distribution image the
// distribution's own `sysctl.d` drop-ins set it — after any value the boot line
// asked for. The keys are then refused on exactly the machine that needs them:
// one whose userspace has stopped answering, where the serial line is the only
// remaining channel and a task dump is the only remaining evidence. Measured on
// this image: `[sysrq] this operation is disabled by kernel.sysrq` in answer to
// the timeout handler's task-dump request, on a wedge with no other diagnostic.
//
// The reference carries the same escape hatch as a boot parameter, because a
// boot parameter is the one setting userspace cannot overwrite.

use crate::token::{bare_flag, value};

/// `sysrq_always_enabled`: every SysRq command runs whatever `kernel.sysrq`
/// later says. Accepts the bare flag and the `=1`/`=0` spellings, as the other
/// boolean parameters on this line do.
/// # C: O(line length)
pub fn sysrq_always_enabled_in(line: &[u8]) -> bool {
    match value(line, b"sysrq_always_enabled") {
        Some(b"0") | Some(b"n") | Some(b"N") | Some(b"off") | Some(b"false") => false,
        Some(_) => true,
        None => bare_flag(line, b"sysrq_always_enabled"),
    }
}

/// The installed boot line's answer. # C: O(line length)
pub fn sysrq_always_enabled() -> bool { sysrq_always_enabled_in(crate::get()) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bare_flag_asks_for_it() {
        assert!(sysrq_always_enabled_in(b"root=/dev/vda rw sysrq_always_enabled quiet"));
    }

    #[test]
    fn an_absent_parameter_leaves_the_sysctl_in_charge() {
        assert!(!sysrq_always_enabled_in(b"root=/dev/vda rw sysctl.kernel.sysrq=1"));
    }

    /// The `sysctl.kernel.sysrq=` spelling on the same line is a DIFFERENT
    /// parameter — userspace policy, which is the thing this one overrides.
    /// A substring match would read one as the other.
    #[test]
    fn the_sysctl_spelling_is_not_this_parameter() {
        assert!(!sysrq_always_enabled_in(b"sysctl.kernel.sysrq_always_enabled=1"));
    }

    #[test]
    fn the_off_spellings_are_honoured() {
        for line in [&b"sysrq_always_enabled=0"[..], b"sysrq_always_enabled=off",
                     b"sysrq_always_enabled=false", b"sysrq_always_enabled=n"] {
            assert!(!sysrq_always_enabled_in(line), "{:?} asked for it off", core::str::from_utf8(line));
        }
        assert!(sysrq_always_enabled_in(b"sysrq_always_enabled=1"));
    }
}
