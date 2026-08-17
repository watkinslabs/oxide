//! The halt path, without a machine to stop.

use super::*;

/// One recorded demand, so a test can see what a filesystem asked for.
static SEEN: sync::Spinlock<Option<(&'static str, &'static str)>, FsHaltHookLock> =
    sync::Spinlock::new(None);

fn record(fs: &'static str, reason: &'static str) { *SEEN.lock() = Some((fs, reason)); }

/// With nothing installed the request is REFUSED and says so, which is what
/// keeps a caller going down its remaining arms instead of assuming it is gone.
#[test]
fn an_uninstalled_halt_is_refused_and_says_so() {
    clear_fs_halt_hook();
    assert!(!fs_halt_installed());
    assert!(!fs_halt("testfs", "a reason"), "a halt was claimed with no path to take it");
}

/// Installed, the demand reaches the layer that owns the machine, with both
/// facts a diagnosis needs.
#[test]
fn an_installed_halt_takes_the_demand() {
    set_fs_halt_hook(record);
    *SEEN.lock() = None;
    assert!(fs_halt("testfs", "a reason"));
    assert_eq!(*SEEN.lock(), Some(("testfs", "a reason")));
    clear_fs_halt_hook();
    assert!(!fs_halt_installed());
}
