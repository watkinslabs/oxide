// Environments the in-kernel helper callers hand their programs.
//
// A helper has no shell and no login session, so the kernel supplies the whole
// environment. The two shapes below are the ones the callers use; a caller with
// extra variables appends to a copy rather than inventing a third base.

/// Root directory a helper starts in and reports as `$HOME`.
pub const HELPER_HOME: &[u8] = b"HOME=/";
/// Search path a helper resolves unqualified program names against.
pub const HELPER_PATH: &[u8] = b"PATH=/sbin:/bin:/usr/sbin:/usr/bin";
/// Search path the module loader's helper uses; the module tools live in the
/// sbin directories, which is why they come first.
pub const MODPROBE_PATH: &[u8] = b"PATH=/sbin:/usr/sbin:/bin:/usr/bin";
/// Terminal type a helper that may write diagnostics assumes.
pub const HELPER_TERM: &[u8] = b"TERM=linux";

/// The two-variable environment an upcall helper (`/sbin/request-key`, a
/// hotplug helper) is given.
pub const UPCALL_ENV: [&[u8]; 2] = [HELPER_HOME, HELPER_PATH];

/// The three-variable environment the module loader's helper is given.
pub const MODPROBE_ENV: [&[u8]; 3] = [HELPER_HOME, HELPER_TERM, MODPROBE_PATH];
