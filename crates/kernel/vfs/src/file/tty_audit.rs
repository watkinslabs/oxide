// The terminal-input audit hook on the read path.
//
// Auditing terminal input has to happen where the bytes are handed to the
// reader, not where the device delivered them: only the reader is the task the
// input is attributed to, and only bytes a task actually read were "typed at"
// that task. Every `read`/`readv` on any description therefore passes through
// one hook site here, and each terminal backend answers what it is.
//
// The cost when nothing is audited is one relaxed load. The flag is armed only
// while some thread group is actually marked for tty auditing, so the ordinary
// system pays that and nothing else — no virtual call, no lock.

use core::sync::atomic::{AtomicBool, Ordering};

use sync::Spinlock;

use super::File;

/// What a terminal backend answers about itself.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TtyAuditFacts {
    /// The terminal's device number, already split: the packed encoding is
    /// this layer's business, and a decoder in the audit layer could disagree.
    pub major: u32,
    pub minor: u32,
    /// Canonical (line-at-a-time) input.
    pub icanon: bool,
    /// Input is echoed back to the terminal.
    pub echo: bool,
    /// The controlling half of a pseudo-terminal pair, whose readable stream
    /// is the other half's OUTPUT rather than typed input.
    pub pty_master: bool,
}

/// Fired after a read returned bytes from a description that named itself a
/// terminal.
pub type TtyAuditHook = fn(TtyAuditFacts, &[u8]);

/// Lock class for the one-entry hook slot. Taken only while armed, and the
/// pointer is copied out before the hook runs, so it never nests.
struct TtyAuditReg;
impl sync::LockClass for TtyAuditReg { fn rank() -> u16 { 34 } fn name() -> &'static str { "TtyAuditReg" } }

/// Installed once at boot; `None` when the kernel has no audit subsystem wired
/// (host tests, early boot).
static HOOK: Spinlock<Option<TtyAuditHook>, TtyAuditReg> = Spinlock::new(None);

/// Whether any thread group is marked for tty auditing right now. Read on
/// every `read(2)`, written only when an audit daemon changes a mask.
static ARMED: AtomicBool = AtomicBool::new(false);

/// Install the terminal-input audit hook. # C: O(1)
pub fn set_tty_audit_hook(f: TtyAuditHook) { *HOOK.lock() = Some(f); }

/// Arm or disarm the read-path check. # C: O(1)
pub fn arm_tty_audit(on: bool) { ARMED.store(on, Ordering::Release); }

/// Whether the read path must ask a backend what it is. # C: O(1)
pub fn tty_audit_armed() -> bool { ARMED.load(Ordering::Relaxed) }

/// Report bytes a task just read from a terminal. Caller has already
/// established that the read succeeded and that the check is armed.
/// # C: O(len) + hook
pub(crate) fn fire_tty_audit(file: &File, data: &[u8]) {
    let Some(f) = *HOOK.lock() else { return };
    let Some(facts) = file.f_op.tty_audit_facts(file) else { return };
    f(facts, data);
}
