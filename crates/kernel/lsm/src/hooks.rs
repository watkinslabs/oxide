// One hook, every module.
//
// A hook list holds one entry per module that answers at that point, kept in
// the framework's module order. The subsystem owning the object type owns the
// list; the framework owns what "asking every module" means, so a new check
// point cannot accidentally consult one module and not another.

use crate::limits::MAX_LSM_COUNT;
use crate::module::LsmId;

/// Why a registration was refused.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HookError {
    /// The list already holds `MAX_LSM_COUNT` modules.
    Full,
    /// This module already answers at this point.
    ///
    /// Refused rather than replaced. A module registering twice has a bug,
    /// and silently keeping the second answer would make which one runs
    /// depend on initialisation order.
    Duplicate,
}

/// One module's answer at one hook.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Entry<F: Copy> {
    lsm: LsmId,
    /// Position of the module in the framework's order.
    position: u16,
    hook: F,
}

/// Every module answering at one hook, in module order.
#[derive(Copy, Clone, Debug)]
pub struct HookList<F: Copy> {
    entries: [Option<Entry<F>>; MAX_LSM_COUNT],
    len: usize,
}

impl<F: Copy> HookList<F> {
    /// An empty list. # C: O(1)
    pub const fn new() -> Self { Self { entries: [None; MAX_LSM_COUNT], len: 0 } }

    /// How many modules answer here. # C: O(1)
    pub const fn len(&self) -> usize { self.len }

    /// Whether no module answers here. # C: O(1)
    pub const fn is_empty(&self) -> bool { self.len == 0 }

    /// Add one module's answer, keeping the list in module order. # C: O(modules)
    ///
    /// The position comes from the framework's resolved order rather than
    /// from when this call happens, so a module that initialises late still
    /// answers in the place the boot line put it.
    pub fn register(&mut self, lsm: LsmId, position: u16, hook: F) -> Result<(), HookError> {
        for slot in self.entries.iter().take(self.len) {
            if slot.is_some_and(|e| e.lsm == lsm) { return Err(HookError::Duplicate); }
        }
        if self.len == MAX_LSM_COUNT { return Err(HookError::Full); }
        let entry = Entry { lsm, position, hook };
        let mut at = self.len;
        while at > 0 {
            let prev = self.entries[at - 1].expect("entries below len are filled");
            if prev.position <= position { break; }
            self.entries[at] = Some(prev);
            at -= 1;
        }
        self.entries[at] = Some(entry);
        self.len += 1;
        Ok(())
    }

    /// The modules answering here, in order. # C: O(modules)
    pub fn iter(&self) -> impl Iterator<Item = (LsmId, F)> + '_ {
        self.entries.iter().take(self.len).filter_map(|e| e.map(|e| (e.lsm, e.hook)))
    }

    /// Identities answering here, in order. # C: O(modules)
    pub fn modules(&self) -> impl Iterator<Item = LsmId> + '_ { self.iter().map(|(id, _)| id) }
}

impl<F: Copy> Default for HookList<F> {
    fn default() -> Self { Self::new() }
}

/// Ask every module until one of them decides. # C: O(modules)
///
/// A module returning the default has not decided anything, so the walk
/// continues; the first answer that differs from the default is the answer,
/// and no later module can overturn it. With a permit-shaped default this is
/// what makes a refusal by any one module stand: stopping at the first
/// module that permits would let the first module in the order grant an
/// access every other module refuses.
pub fn call_first_decisive<F: Copy, R: PartialEq>(
    list: &HookList<F>, default: R, mut call: impl FnMut(F) -> R,
) -> R {
    for (_, hook) in list.iter() {
        let answer = call(hook);
        if answer != default { return answer; }
    }
    default
}

/// Ask every module and report which one decided. # C: O(modules)
pub fn call_first_decisive_by<F: Copy, R: PartialEq>(
    list: &HookList<F>, default: R, mut call: impl FnMut(F) -> R,
) -> (R, Option<LsmId>) {
    for (lsm, hook) in list.iter() {
        let answer = call(hook);
        if answer != default { return (answer, Some(lsm)); }
    }
    (default, None)
}

/// Tell every module, expecting no answer. # C: O(modules)
///
/// Every module runs. A notification hook that stopped early would leave
/// later modules with stale state about an object they are still mediating.
pub fn call_all<F: Copy>(list: &HookList<F>, mut call: impl FnMut(F)) {
    for (_, hook) in list.iter() { call(hook); }
}

#[cfg(test)]
#[path = "tests/hooks.rs"]
mod tests;
