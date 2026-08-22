// `/proc/<pid>/attr/*`: the interface early userspace uses to read its own
// domain and to stage the labels the kernel applies to its next operations
// (`62§9`).
//
// Every decision here — which slot a name is, whether it may be written, what
// a written buffer means, which permission governs it — is a function over
// values, because the file that plumbs them into procfs is compiled only for
// the kernel target and nothing in it could be tested.

use alloc::vec::Vec;

use selinux::sidtab::Sid;
use syscall::errno::Errno;

use super::policy::{PERM_SETEXEC, PERM_SETFSCREATE, PERM_SETKEYCREATE, PERM_SETSOCKCREATE};
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
use super::policy::{self, CLASS_PROCESS, PERM_DYNTRANSITION, PERM_GETATTR, PERM_SETCURRENT};

/// Largest attribute write accepted, matching the one-page bound userspace
/// writes against.
const ATTR_WRITE_MAX: usize = 4096;

/// Mode of a slot userspace may both read and write.
const MODE_RW: u16 = 0o666;
/// Mode of a slot userspace may only read.
const MODE_RO: u16 = 0o444;

/// One attribute exposed under `/proc/<pid>/attr/`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttrSlot {
    /// Domain the task runs in.
    Current,
    /// Domain staged for the next `execve`.
    Exec,
    /// Label staged for the next file created.
    FsCreate,
    /// Label staged for the next key created.
    KeyCreate,
    /// Label staged for the next socket created.
    SockCreate,
    /// Domain held before the last transition.
    Prev,
}

/// Every slot, in the order the directory lists them.
pub const ATTR_SLOTS: [(&str, AttrSlot); 6] = [
    ("current", AttrSlot::Current),
    ("exec", AttrSlot::Exec),
    ("fscreate", AttrSlot::FsCreate),
    ("keycreate", AttrSlot::KeyCreate),
    ("prev", AttrSlot::Prev),
    ("sockcreate", AttrSlot::SockCreate),
];

impl AttrSlot {
    /// Slot one file name selects. # C: O(slots)
    pub fn from_name(name: &str) -> Option<Self> {
        ATTR_SLOTS.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
    }
}

/// Permission mode of one slot's file. # C: O(1)
pub fn attr_mode(slot: AttrSlot) -> u16 {
    match slot { AttrSlot::Prev => MODE_RO, _ => MODE_RW }
}

/// How a write to one slot is governed. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttrWritePerm {
    /// The slot is not writable at all.
    Refused,
    /// A domain change, governed by the dynamic-transition rules.
    Dynamic,
    /// A staging slot, governed by this one permission of `process`.
    Staged(&'static str),
}

/// Permission that governs writing one slot. # C: O(1)
///
/// `prev` records what already happened. Letting userspace write it would let
/// a process claim a transition history it never had, and every consumer of
/// that history reads it precisely to learn what the kernel decided.
pub fn write_permission(slot: AttrSlot) -> AttrWritePerm {
    match slot {
        AttrSlot::Prev => AttrWritePerm::Refused,
        AttrSlot::Current => AttrWritePerm::Dynamic,
        AttrSlot::Exec => AttrWritePerm::Staged(PERM_SETEXEC),
        AttrSlot::FsCreate => AttrWritePerm::Staged(PERM_SETFSCREATE),
        AttrSlot::KeyCreate => AttrWritePerm::Staged(PERM_SETKEYCREATE),
        AttrSlot::SockCreate => AttrWritePerm::Staged(PERM_SETSOCKCREATE),
    }
}

/// What one write to an attribute file asks for.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttrRequest<'a> {
    /// Unset the slot.
    Clear,
    /// Set the slot to this written context.
    Set(&'a str),
}

/// Whether a write may reach this task's attributes. # C: O(1)
///
/// Only the calling thread's own. Staging a label on another thread would put
/// it in a domain at a moment that thread cannot observe, between its own
/// checks and the operation the label applies to.
pub fn attr_write_target(caller_tid: u32, target_tid: u32) -> Result<(), Errno> {
    if caller_tid == target_tid { Ok(()) } else { Err(Errno::Eacces) }
}

/// Read one write buffer as a request. # C: O(len)
///
/// An empty buffer, a leading NUL, or a leading newline clears the slot. That
/// is how userspace un-stages a label it decided not to use; treating it as an
/// invalid context would leave the slot armed with no way to disarm it.
/// Clearing `current` is different — a task always has a domain — so it is
/// rejected rather than obeyed.
pub fn parse_attr_write(slot: AttrSlot, src: &[u8]) -> Result<AttrRequest<'_>, Errno> {
    if matches!(write_permission(slot), AttrWritePerm::Refused) { return Err(Errno::Eacces); }
    if src.len() > ATTR_WRITE_MAX { return Err(Errno::Einval); }
    let clears = !matches!(src.first(), Some(b) if *b != 0 && *b != b'\n');
    if clears {
        if matches!(slot, AttrSlot::Current) { return Err(Errno::Einval); }
        return Ok(AttrRequest::Clear);
    }
    let mut text = src;
    if let Some(rest) = text.strip_suffix(b"\n") { text = rest; }
    // A written context is a C string: userspace commonly includes the
    // terminator in the count, and the bytes past it are not part of the
    // context.
    if let Some(nul) = text.iter().position(|b| *b == 0) { text = &text[..nul]; }
    if text.is_empty() { return Err(Errno::Einval); }
    core::str::from_utf8(text).map(AttrRequest::Set).map_err(|_| Errno::Einval)
}

/// Render one slot's value for a read. # C: O(categories)
///
/// An unset slot, and every slot on a kernel with no module installed, read as
/// zero bytes rather than an error: userspace tests these files for emptiness to
/// decide whether the module is doing anything, and an error there reads as a
/// broken kernel rather than as an unset label.
///
/// A slot that IS set and whose label cannot be rendered is an ERROR, not zero
/// bytes. Those two are not the same answer and must not collapse onto one:
/// userspace that reads an empty buffer carries the empty string onward as a
/// label and only fails much later, somewhere that names neither the SID nor the
/// read. An empty context is not a context, so the read that could not produce
/// one has to say so.
pub fn render_slot(value: Option<Sid>) -> Result<Vec<u8>, Errno> {
    let Some(sid) = value else { return Ok(Vec::new()) };
    slot_answer(selinux_runtime::with(|s|
        s.sid_to_context(sid).ok().map(alloc::string::String::into_bytes)))
}

/// The read's answer, given what the module could render. # C: O(1)
///
/// `None` is no module installed; `Some(None)` is a module that could not render
/// the label; `Some(Some(text))` is the rendered context. The middle case is the
/// one that must not become zero bytes, and it is separated from the outer one
/// here so a test can reach it without a loaded policy.
pub fn slot_answer(rendered: Option<Option<Vec<u8>>>) -> Result<Vec<u8>, Errno> {
    match rendered {
        Some(Some(text)) => Ok(text),
        // The label is set and no table can render it.
        Some(None) => Err(Errno::Einval),
        // No module at all: nothing labels anything, so there is no label to
        // report and no failure to report either.
        None => Ok(Vec::new()),
    }
}

/// Read one attribute of a task. # C: O(categories)
///
/// Gated with `live`: naming the calling task is what needs a scheduler.
///
/// A thread always reads its own; reading another's is an access to that
/// task's state and is governed by the policy.
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn read_attr(target: &crate::Task, slot: AttrSlot) -> Result<Vec<u8>, Errno> {
    let value = target.selinux_label.lock().slot(slot);
    let caller = crate::live::current();
    if let Some(caller) = caller {
        if caller.tid != target.tid {
            let ssid = caller.selinux_label.lock().sid;
            let tsid = target.selinux_label.lock().sid;
            policy::check(ssid, tsid, CLASS_PROCESS, PERM_GETATTR)?;
        }
    }
    render_slot(value)
}

/// Write one attribute of the calling thread. # C: O(categories)
///
/// Returns the number of bytes consumed, which is the whole buffer: a partial
/// write of a context is not a thing userspace can act on.
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn write_attr(target: &crate::Task, slot: AttrSlot, src: &[u8]) -> Result<usize, Errno> {
    let caller = crate::live::current().ok_or(Errno::Eacces)?;
    attr_write_target(caller.tid, target.tid)?;
    let old = target.selinux_label.lock().sid;
    match write_permission(slot) {
        AttrWritePerm::Refused => return Err(Errno::Eacces),
        AttrWritePerm::Dynamic => policy::check(old, old, CLASS_PROCESS, PERM_SETCURRENT)?,
        AttrWritePerm::Staged(perm) => policy::check(old, old, CLASS_PROCESS, perm)?,
    }
    let request = parse_attr_write(slot, src)?;
    let value = match request {
        AttrRequest::Clear => None,
        AttrRequest::Set(text) => Some(
            selinux_runtime::with(|s| s.context_to_sid(text))
                .and_then(|r| r.ok())
                .ok_or(Errno::Einval)?,
        ),
    };
    match slot {
        AttrSlot::Current => {
            let new = value.ok_or(Errno::Einval)?;
            // A domain change applies to the whole process. Linux permits a
            // multithreaded caller only when the new domain is type-bounded by
            // the old one, then still demands the ordinary dyntransition.
            if !target.thread_group.is_single_member() {
                match selinux_runtime::with(|s| s.bounded_transition(old, new)) {
                    None | Some(Ok(true)) => {}
                    Some(Ok(false)) => return Err(Errno::Eperm),
                    Some(Err(_)) => return Err(Errno::Einval),
                }
            }
            policy::check(old, new, CLASS_PROCESS, PERM_DYNTRANSITION)?;
            target.selinux_label.lock().enter(new);
        }
        _ => target.selinux_label.lock().set_staged(slot, value),
    }
    Ok(src.len())
}
