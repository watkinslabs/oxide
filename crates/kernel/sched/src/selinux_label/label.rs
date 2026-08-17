// The per-task label struct and the rule that carries it across fork.

use selinux::sidtab::Sid;

use super::attr::AttrSlot;

/// Security label carried by one task.
///
/// `sid` is the domain the task runs in. The four staging slots hold labels
/// userspace has asked the kernel to apply to the NEXT operation of a given
/// kind; each is consumed by that operation. `prev` records the domain held
/// before the last transition and exists only to be read back.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaskLabel {
    /// Domain this task runs in.
    pub sid: Sid,
    /// Domain the next `execve` enters, overriding the policy's transition.
    pub exec: Option<Sid>,
    /// Label the next file this task creates takes.
    pub fscreate: Option<Sid>,
    /// Label the next key this task creates takes.
    pub keycreate: Option<Sid>,
    /// Label the next socket this task creates takes.
    pub sockcreate: Option<Sid>,
    /// Domain held before the last transition.
    pub prev: Option<Sid>,
}

impl TaskLabel {
    /// A label in `sid` with nothing staged and no history. # C: O(1)
    pub const fn with_sid(sid: Sid) -> Self {
        Self { sid, exec: None, fscreate: None, keycreate: None, sockcreate: None, prev: None }
    }

    /// Label of a kernel thread. # C: O(1)
    pub fn kernel() -> Self { Self::with_sid(selinux_runtime::label::kernel_sid()) }

    /// Label a task starts with before any policy is loaded. # C: O(1)
    ///
    /// Every task begins in the initial-SID domain the policy names `init`.
    /// Until a policy is loaded no check consults it, so the value matters
    /// only from the first load onwards — at which point the policy's own
    /// `init` context is what a distribution's early userspace expects to read
    /// back out of `/proc/1/attr/current`.
    pub fn init() -> Self { Self::with_sid(selinux_runtime::label::init_sid()) }

    /// Label a forked child takes from its parent. # C: O(1)
    ///
    /// EVERY field carries, the staged `exec` label included. That looks
    /// surprising — a label staged for one `execve` reaching a whole subtree —
    /// but it is what the reference does, and the fork-then-exec pair is
    /// precisely how a shell applies one: the process that stages the label is
    /// usually not the process that execs. Dropping it here would make
    /// `setexec` silently do nothing for the ordinary caller.
    ///
    /// What bounds it is the CONSUMER, not this rule: the staged label is
    /// taken and cleared by the first `execve` that uses it, so it applies
    /// once per branch of the tree rather than persisting.
    pub fn inherit(parent: &TaskLabel) -> Self { *parent }

    /// Value of one attribute slot. # C: O(1)
    pub fn slot(&self, slot: AttrSlot) -> Option<Sid> {
        match slot {
            AttrSlot::Current => Some(self.sid),
            AttrSlot::Exec => self.exec,
            AttrSlot::FsCreate => self.fscreate,
            AttrSlot::KeyCreate => self.keycreate,
            AttrSlot::SockCreate => self.sockcreate,
            AttrSlot::Prev => self.prev,
        }
    }

    /// Store one staging slot. # C: O(1)
    ///
    /// `Current` and `Prev` are not staging slots and are not written here:
    /// the current domain changes only through a transition, which also moves
    /// the old value into `prev`, and letting a slot write set either directly
    /// would leave the two disagreeing about the same event.
    pub fn set_staged(&mut self, slot: AttrSlot, value: Option<Sid>) {
        match slot {
            AttrSlot::Exec => self.exec = value,
            AttrSlot::FsCreate => self.fscreate = value,
            AttrSlot::KeyCreate => self.keycreate = value,
            AttrSlot::SockCreate => self.sockcreate = value,
            AttrSlot::Current | AttrSlot::Prev => {}
        }
    }

    /// Move this label into `new`, recording where it came from. # C: O(1)
    ///
    /// A move to the domain already held is not a transition and leaves `prev`
    /// alone: overwriting it would erase the last real transition and make the
    /// history read back as "came from itself".
    pub fn enter(&mut self, new: Sid) {
        if new == self.sid { return; }
        self.prev = Some(self.sid);
        self.sid = new;
    }
}

impl Default for TaskLabel {
    fn default() -> Self { Self::init() }
}

/// Label of the running thread, for the object owners' checks. # C: O(1)
///
/// A check made from no task at all — the boot path, an interrupt — is the
/// kernel acting on its own behalf and carries the kernel's label.
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn current_sid() -> Sid {
    match crate::live::current() {
        Some(t) => t.selinux_label.lock().sid,
        None => selinux_runtime::label::kernel_sid(),
    }
}

/// Label the running thread staged for the next object it creates. # C: O(1)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn current_fscreate_sid() -> Option<Sid> {
    crate::live::current().and_then(|t| t.selinux_label.lock().fscreate)
}

/// Label the running thread staged for the next SOCKET it creates. # C: O(1)
///
/// Separate from the file-creation staging: a thread may stage a label for the
/// sockets it opens without staging one for the files it writes, and the two
/// slots are written through different attributes.
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn current_sockcreate_sid() -> Option<Sid> {
    crate::live::current().and_then(|t| t.selinux_label.lock().sockcreate)
}
