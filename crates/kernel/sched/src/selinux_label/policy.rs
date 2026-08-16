// Class and permission names this subsystem asks the policy about, and the
// lookups that turn them into the numbers a check takes.
//
// The names are the policy's own vocabulary, so they are constants at this
// boundary rather than string literals at each call site: a typo in one of
// them resolves to no permission bit at all, which reads as "granted" and
// leaves no trace.

use selinux::sidtab::Sid;
use selinux::uapi::classmap::{class_by_name, perm_bit};
use selinux_runtime::check::has_perm_noaudit;
use syscall::errno::Errno;

/// Class of a process acting as a subject.
pub const CLASS_PROCESS: &str = "process";
/// Class carrying the process permissions added after the first thirty-two.
pub const CLASS_PROCESS2: &str = "process2";
/// Class of a regular file, which is what an executable image is.
pub const CLASS_FILE: &str = "file";

/// Entering a new domain across `execve`.
pub const PERM_TRANSITION: &str = "transition";
/// Being a valid entry point into the domain being entered.
pub const PERM_ENTRYPOINT: &str = "entrypoint";
/// Executing an image without changing domain.
pub const PERM_EXECUTE_NO_TRANS: &str = "execute_no_trans";
/// Exemption from the secure-execution treatment of a domain change.
pub const PERM_NOATSECURE: &str = "noatsecure";
/// Transitioning while no-new-privileges is set.
pub const PERM_NNP_TRANSITION: &str = "nnp_transition";
/// Transitioning off a `nosuid` mount.
pub const PERM_NOSUID_TRANSITION: &str = "nosuid_transition";
/// Reading another task's attributes.
pub const PERM_GETATTR: &str = "getattr";
/// Rewriting one's own current domain.
pub const PERM_SETCURRENT: &str = "setcurrent";
/// The domain change a `current` write performs.
pub const PERM_DYNTRANSITION: &str = "dyntransition";
/// Staging the domain of the next `execve`.
pub const PERM_SETEXEC: &str = "setexec";
/// Staging the label of the next file created.
pub const PERM_SETFSCREATE: &str = "setfscreate";
/// Staging the label of the next key created.
pub const PERM_SETKEYCREATE: &str = "setkeycreate";
/// Staging the label of the next socket created.
pub const PERM_SETSOCKCREATE: &str = "setsockcreate";

/// Whether one permission of a class is granted, without reporting. # C: O(1) cached
///
/// A class or permission the loaded policy does not define yields no bit, and
/// a request of no bits is granted — which is what a kernel newer than its
/// policy must do, since the alternative refuses operations the policy never
/// had an opinion about.
pub fn granted(ssid: Sid, tsid: Sid, class: &str, permission: &str) -> bool {
    let Some(class) = class_by_name(class) else { return true };
    let Some(bit) = perm_bit(class, permission) else { return true };
    has_perm_noaudit(ssid, tsid, class, bit).allowed
}

/// Demand one permission of a class, reporting a denial. # C: O(1) cached
///
/// Same unknown-class reading as [`granted`], for the same reason.
pub fn check(ssid: Sid, tsid: Sid, class: &str, permission: &str) -> Result<(), Errno> {
    let Some(class) = class_by_name(class) else { return Ok(()) };
    let Some(bit) = perm_bit(class, permission) else { return Ok(()) };
    selinux_runtime::check::has_perm(ssid, tsid, class, bit).map_err(|_| Errno::Eacces)
}

/// Whether the loaded policy enables one capability bit. # C: O(log chunks)
pub fn policycap(bit: u32) -> bool {
    selinux_runtime::with(|s| s.policy().is_some_and(|p| p.policycap(bit))).unwrap_or(false)
}
