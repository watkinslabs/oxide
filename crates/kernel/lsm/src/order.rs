// Which modules run, and in what order.
//
// Pure over the module list and the boot line, so the decision can be checked
// without a running kernel. Ordering is a security decision in its own right:
// a module dropped from the order is a policy that silently stops being
// consulted, and nothing else in the system would notice.

use alloc::vec;
use alloc::vec::Vec;

use crate::limits::MAX_LSM_COUNT;
use crate::module::{LsmInfo, Order};

/// What the boot line and the build say about module selection.
#[derive(Copy, Clone, Debug, Default)]
pub struct Selection<'a> {
    /// Order compiled into this kernel.
    pub builtin: &'a str,
    /// Modern ordered list from the boot line, if given.
    pub cmdline: Option<&'a str>,
    /// Legacy single-module selector from the boot line, if given.
    pub legacy: Option<&'a str>,
}

/// Why one module did not make the order.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Skipped {
    /// Something had already turned the module off.
    Disabled,
    /// Another module holding the exclusive flag was selected first.
    ExclusiveConflict,
    /// The order was already full.
    Full,
    /// The selection never named it.
    NotSelected,
    /// A different legacy module was selected.
    LegacyConflict,
}

/// The resolved order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ordered {
    /// Indices into the module list, in initialisation order.
    pub active: Vec<usize>,
    /// Final enable state of every module, parallel to the module list.
    pub enabled: Vec<bool>,
    /// Reason each module was left out, parallel to the module list.
    pub skipped: Vec<Option<Skipped>>,
}

impl Ordered {
    /// Whether a module ended up running. # C: O(1)
    pub fn is_active(&self, index: usize) -> bool {
        self.enabled.get(index).copied().unwrap_or(false)
    }

    /// Position of a module in the order. # C: O(active)
    pub fn position(&self, index: usize) -> Option<usize> {
        self.active.iter().position(|i| *i == index)
    }
}

/// Resolve the order the modules initialise in. # C: O(modules * list)
///
/// The modern list and the legacy selector do not combine: naming the modern
/// list on the boot line discards the legacy one entirely, because the two
/// express incompatible intentions and honouring both would run a module the
/// operator asked to replace.
pub fn resolve(modules: &[LsmInfo], selection: Selection<'_>) -> Ordered {
    let mut state = State::new(modules);
    let (list, legacy) = match selection.cmdline {
        Some(list) => (list, None),
        None => (selection.builtin, selection.legacy),
    };

    // A legacy selection names one module and excludes its peers. It does
    // NOT fall back to another peer when the named one is separately
    // disabled: the operator asked for that module or none.
    if let Some(want) = legacy {
        for (at, m) in modules.iter().enumerate() {
            if m.is_legacy_major() && m.id.name != want {
                state.disable(at, Skipped::LegacyConflict);
            }
        }
    }

    for (at, m) in modules.iter().enumerate() {
        if m.order == Order::First { state.append(at); }
    }

    for name in list.split(',') {
        let name = name.trim();
        if name.is_empty() { continue; }
        for (at, m) in modules.iter().enumerate() {
            if m.id.name == name && m.order == Order::Mutable { state.append(at); }
        }
    }

    if let Some(want) = legacy {
        for (at, m) in modules.iter().enumerate() {
            if m.id.name == want { state.append(at); }
        }
    }

    for (at, m) in modules.iter().enumerate() {
        if m.order == Order::Last { state.append(at); }
    }

    for at in 0..modules.len() {
        if state.ordered.active.contains(&at) { continue; }
        if state.ordered.skipped[at].is_none() { state.ordered.skipped[at] = Some(Skipped::NotSelected); }
        state.ordered.enabled[at] = false;
    }

    state.ordered
}

struct State<'m> {
    modules: &'m [LsmInfo],
    ordered: Ordered,
    exclusive_taken: bool,
}

impl<'m> State<'m> {
    fn new(modules: &'m [LsmInfo]) -> Self {
        let n = modules.len();
        Self {
            modules,
            ordered: Ordered {
                active: Vec::new(),
                enabled: modules.iter().map(|m| !m.explicitly_disabled()).collect(),
                skipped: vec![None; n],
            },
            exclusive_taken: false,
        }
    }

    fn disable(&mut self, at: usize, why: Skipped) {
        self.ordered.enabled[at] = false;
        if self.ordered.skipped[at].is_none() { self.ordered.skipped[at] = Some(why); }
    }

    fn append(&mut self, at: usize) {
        if self.ordered.active.contains(&at) { return; }
        if !self.ordered.enabled[at] {
            if self.ordered.skipped[at].is_none() {
                self.ordered.skipped[at] = Some(Skipped::Disabled);
            }
            return;
        }
        if self.ordered.active.len() == MAX_LSM_COUNT {
            self.disable(at, Skipped::Full);
            return;
        }
        if self.modules[at].is_exclusive() {
            if self.exclusive_taken { self.disable(at, Skipped::ExclusiveConflict); return; }
            self.exclusive_taken = true;
        }
        self.ordered.enabled[at] = true;
        self.ordered.active.push(at);
    }
}

#[cfg(test)]
#[path = "tests/order.rs"]
mod tests;
