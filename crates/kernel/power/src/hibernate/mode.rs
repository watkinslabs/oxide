//! Hibernation-mode policy and `/sys/power/disk` rendering (`32b§10`).

use alloc::string::String;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::decide::{Error, KResult};

/// How a durable image transitions the current machine out of service.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Mode { Platform, Shutdown, Reboot, Suspend, TestResume }

/// Machine-specific admission for every terminal policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Available {
    pub platform: bool, pub shutdown: bool, pub reboot: bool,
    pub suspend: bool, pub test_resume: bool,
}

static SELECTED: AtomicU8 = AtomicU8::new(Mode::Shutdown as u8);

impl Mode {
    /// Stable sysfs spelling for this terminal policy. # C: O(1)
    pub const fn label(self) -> &'static str {
        match self {
            Self::Platform => "platform", Self::Shutdown => "shutdown",
            Self::Reboot => "reboot", Self::Suspend => "suspend",
            Self::TestResume => "test_resume",
        }
    }

    /// Whether the machine supplies every callback this policy needs. # C: O(1)
    pub const fn admitted(self, available: Available) -> bool {
        match self {
            Self::Platform => available.platform,
            Self::Shutdown => available.shutdown,
            Self::Reboot => available.reboot,
            Self::Suspend => available.suspend,
            Self::TestResume => available.test_resume,
        }
    }
}

/// The selected mode. # C: O(1)
pub fn selected() -> Mode {
    match SELECTED.load(Ordering::Acquire) {
        x if x == Mode::Platform as u8 => Mode::Platform,
        x if x == Mode::Reboot as u8 => Mode::Reboot,
        x if x == Mode::Suspend as u8 => Mode::Suspend,
        x if x == Mode::TestResume as u8 => Mode::TestResume,
        _ => Mode::Shutdown,
    }
}

/// Select the post-suspend fallback after a retained-image sleep fails.
/// # C: O(1)
pub fn fallback_after_suspend_failure(platform: bool) -> Mode {
    let mode = if platform { Mode::Platform } else { Mode::Shutdown };
    SELECTED.store(mode as u8, Ordering::Release);
    mode
}

/// Select an admitted mode from one sysfs write. # C: O(bytes)
pub fn select(buf: &[u8], available: Available) -> KResult<()> {
    let line = strip_newline(buf);
    let mode = [Mode::Platform, Mode::Shutdown, Mode::Reboot, Mode::Suspend,
                Mode::TestResume]
        .into_iter()
        .find(|mode| line == mode.label().as_bytes())
        .ok_or(Error::Inval)?;
    if !mode.admitted(available) { return Err(Error::Inval); }
    SELECTED.store(mode as u8, Ordering::Release);
    Ok(())
}

/// Render available modes with the selection bracketed. # C: O(1)
pub fn render(available: Available) -> String {
    let selected = selected();
    let mut out = String::new();
    for mode in [Mode::Platform, Mode::Shutdown, Mode::Reboot, Mode::Suspend,
                 Mode::TestResume]
    {
        if !mode.admitted(available) { continue; }
        if !out.is_empty() { out.push(' '); }
        if mode == selected { out.push('['); }
        out.push_str(mode.label());
        if mode == selected { out.push(']'); }
    }
    out.push('\n');
    out
}

fn strip_newline(buf: &[u8]) -> &[u8] {
    match buf.strip_suffix(b"\n") { Some(line) => line, None => buf }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() { SELECTED.store(Mode::Shutdown as u8, Ordering::Release); }

    #[test]
    fn only_modes_with_real_owners_are_listed() {
        reset();
        assert_eq!(render(Available { platform: false, shutdown: true, reboot: true,
                       suspend: false, test_resume: true }),
                   "[shutdown] reboot test_resume\n");
        assert_eq!(render(Available { platform: true, shutdown: true, reboot: true,
                       suspend: true, test_resume: true }),
                   "platform [shutdown] reboot suspend test_resume\n");
    }

    #[test]
    fn an_unavailable_or_unknown_mode_does_not_move_the_selection() {
        reset();
        let none = Available { platform: false, shutdown: true, reboot: true,
            suspend: false, test_resume: true };
        assert_eq!(select(b"platform\n", none), Err(Error::Inval));
        assert_eq!(select(b"other", none), Err(Error::Inval));
        assert_eq!(selected(), Mode::Shutdown);
    }

    #[test]
    fn one_optional_newline_is_accepted() {
        reset();
        let all = Available { platform: true, shutdown: true, reboot: true,
            suspend: true, test_resume: true };
        select(b"test_resume\n", all).unwrap();
        assert_eq!(selected(), Mode::TestResume);
        assert_eq!(select(b"shutdown\n\n", all), Err(Error::Inval));
    }
}
