//! The link-kind registry and the create/change/delete dispatch over it.
//! One registry, keyed by the kind string userspace sends; a kind that is not
//! registered is `EOPNOTSUPP`, never a silently-created plain device.

extern crate alloc;
use alloc::vec::Vec;

use sync::{Socket as SocketLockClass, Spinlock};
use syscall::errno::Errno;

use crate::msg::LinkMsg;

/// What one link kind must provide. The registry owns no policy: every
/// decision — which attributes are required, which values are legal, what the
/// device becomes — belongs to the kind.
pub trait LinkKindOps: Sync {
    /// Kind string as it appears in the message.
    /// # C: O(1)
    fn kind(&self) -> &'static str;

    /// Whether this kind is built on top of a lower device, which makes
    /// `IFLA_LINK` mandatory at creation.
    /// # C: O(1)
    fn needs_lower(&self) -> bool { false }

    /// Reject a creation request that cannot work, before anything is built.
    /// # C: O(len(data))
    fn validate(&self, msg: &LinkMsg<'_>) -> Result<(), Errno>;

    /// Build the device. Returns the interface index it was registered under.
    /// # C: kind-defined
    fn newlink(&self, msg: &LinkMsg<'_>) -> Result<u32, Errno>;

    /// Apply a change to an existing device of this kind.
    /// # C: kind-defined
    fn changelink(&self, ifindex: u32, msg: &LinkMsg<'_>) -> Result<(), Errno>;

    /// Tear one down.
    /// # C: kind-defined
    fn dellink(&self, ifindex: u32) -> Result<(), Errno>;

    /// Encode this device's kind-private attributes for a dump.
    /// # C: kind-defined
    fn fill_info(&self, _ifindex: u32) -> Option<Vec<u8>> { None }

    /// Whether this kind owns a live interface index. # C: O(N_kind-state)
    fn owns(&self, _ifindex: u32) -> bool { false }
}

static KINDS: Spinlock<Vec<&'static dyn LinkKindOps>, SocketLockClass> =
    Spinlock::new(Vec::new());

/// Why a registration was refused.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RegisterError {
    /// A kind of that name is already registered.
    Exists,
    /// The kind string is empty or longer than the message field.
    BadName,
}

/// Publish a link kind. # C: O(N_kinds)
pub fn register(ops: &'static dyn LinkKindOps) -> Result<(), RegisterError> {
    let name = ops.kind();
    if name.is_empty() || name.len() >= crate::uapi::MODULE_NAME_LEN {
        return Err(RegisterError::BadName);
    }
    let mut g = KINDS.lock();
    if g.iter().any(|k| k.kind() == name) { return Err(RegisterError::Exists); }
    g.push(ops);
    Ok(())
}

/// Withdraw a link kind. # C: O(N_kinds)
pub fn unregister(name: &str) -> bool {
    let mut g = KINDS.lock();
    match g.iter().position(|k| k.kind() == name) {
        Some(i) => { g.remove(i); true }
        None => false,
    }
}

/// Resolve a kind string. # C: O(N_kinds)
pub fn lookup(name: &str) -> Option<&'static dyn LinkKindOps> {
    KINDS.lock().iter().find(|k| k.kind() == name).copied()
}

/// Every registered kind's name. # C: O(N_kinds)
pub fn kinds() -> Vec<&'static str> {
    KINDS.lock().iter().map(|k| k.kind()).collect()
}

/// Handle a link-creation or link-change request.
///
/// The distinction is the message's interface index, not the message type: a
/// request naming an existing device is a change even when it carries a kind,
/// and a request naming none is a creation. Treating a change as a creation
/// would build a second device with the same name.
/// # C: O(N_kinds + kind-defined)
pub fn newlink(msg: &LinkMsg<'_>, exists: impl Fn(u32) -> bool)
    -> Result<u32, Errno>
{
    if msg.info.index != 0 {
        let ifindex = u32::try_from(msg.info.index).map_err(|_| Errno::Einval)?;
        if !exists(ifindex) { return Err(Errno::Enodev); }
        let Some(kind) = msg.kind else { return Err(Errno::Eopnotsupp) };
        let ops = lookup(kind).ok_or(Errno::Eopnotsupp)?;
        ops.changelink(ifindex, msg)?;
        return Ok(ifindex);
    }
    // A creation with no kind is a request for a plain device, which rtnetlink
    // does not create; only a registered kind can build one.
    let Some(kind) = msg.kind else { return Err(Errno::Eopnotsupp) };
    let ops = lookup(kind).ok_or(Errno::Eopnotsupp)?;
    if msg.name.is_none() { return Err(Errno::Einval); }
    if ops.needs_lower() && msg.link.is_none() { return Err(Errno::Einval); }
    ops.validate(msg)?;
    ops.newlink(msg)
}

/// Handle a link-deletion request. The kind is looked up from the device, not
/// from the message: userspace need not repeat it to delete.
/// # C: O(N_kinds + kind-defined)
pub fn dellink(msg: &LinkMsg<'_>, kind_of: impl Fn(u32) -> Option<&'static str>)
    -> Result<(), Errno>
{
    let ifindex = u32::try_from(msg.info.index).map_err(|_| Errno::Einval)?;
    if ifindex == 0 { return Err(Errno::Einval); }
    let Some(kind) = kind_of(ifindex) else { return Err(Errno::Eopnotsupp) };
    let ops = lookup(kind).ok_or(Errno::Eopnotsupp)?;
    ops.dellink(ifindex)
}

/// Resolve a live interface index to its registered kind. # C: O(N_kinds · kind-state)
pub fn kind_of(ifindex: u32) -> Option<&'static str> {
    KINDS.lock().iter().find(|k| k.owns(ifindex)).map(|k| k.kind())
}

/// Clear the registry. Hosted tests build and tear down kinds repeatedly, and
/// a leaked registration from one test changes another's answer.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn reset() { KINDS.lock().clear(); }
