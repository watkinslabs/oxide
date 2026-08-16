// The one live framework.
//
// Everything above this line is a value a test can build. This is the single
// instance the running kernel uses. A second copy of the module order or the
// slot allocation could disagree with this one, and a disagreement is a
// module reading a slot that belongs to another module.

use alloc::vec::Vec;

use sync::{LsmFramework, Spinlock};

use crate::blob::BlobKind;
use crate::framework::Framework;
use crate::module::{LsmId, LsmInfo};
use crate::order::Selection;

static FRAMEWORK: Spinlock<Option<Framework>, LsmFramework> = Spinlock::new(None);

/// Resolve and install the framework for this boot. # C: O(modules * list)
///
/// Refused if called twice. A second call would re-run the slot allocation,
/// and every module holding a slot index from the first run would then be
/// reading somebody else's state.
pub fn start(modules: Vec<LsmInfo>, selection: Selection<'_>) -> bool {
    let mut slot = FRAMEWORK.lock();
    if slot.is_some() { return false; }
    *slot = Some(Framework::start(modules, selection));
    true
}

/// Whether the framework has been installed. # C: O(1)
pub fn started() -> bool { FRAMEWORK.lock().is_some() }

/// Run a closure against the framework, if installed. # C: O(1) plus closure
///
/// The lock is never held across a call into a module: a module reached here
/// takes its own policy lock, and holding both would order them the wrong way
/// round. Callers read what they need out and drop the guard.
pub fn with<R>(f: impl FnOnce(&Framework) -> R) -> Option<R> {
    FRAMEWORK.lock().as_ref().map(f)
}

/// Whether one module runs. # C: O(modules)
pub fn is_active(id: u64) -> bool { with(|fw| fw.is_active(id)).unwrap_or(false) }

/// A module's place in the order, for hook registration. # C: O(modules)
pub fn position(id: u64) -> Option<u16> { with(|fw| fw.position(id)).flatten() }

/// A module's slot on one object kind. # C: O(modules)
pub fn blob_slot(id: u64, kind: BlobKind) -> Option<u16> {
    with(|fw| fw.blob_slot(id, kind)).flatten()
}

/// Slots a shared object of this kind carries. # C: O(1)
pub fn slots(kind: BlobKind) -> usize { with(|fw| fw.slots(kind)).unwrap_or(0) }

/// Identities of the running modules, in order. # C: O(active)
pub fn id_list() -> Vec<LsmId> { with(|fw| fw.id_list()).unwrap_or_default() }
