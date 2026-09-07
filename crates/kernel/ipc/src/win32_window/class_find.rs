//! Which registered class one (name, instance) pair names.
//!
//! A registration is keyed by its name and the module that registered it. A
//! class registered with `CS_GLOBALCLASS`, or by a builtin registration, is
//! global: any module finds it. A local class answers only its own module,
//! plus the fallback that accepts a module sharing the high bits of the
//! registering one. A lookup that names no module at all accepts the first
//! class of that name.
use super::{WindowClass, WindowManager, same_name};

/// WNDCLASSEX style bit: the class is visible to every module of the process.
pub const CS_GLOBALCLASS: u32 = 0x4000;
/// Largest class-extra or window-extra allocation one registration may ask for.
pub const MAX_CLASS_EXTRA: i32 = 4096;
/// The module-handle bits the fallback match ignores.
const MODULE_LOW: u64 = 0xffff;

/// Whether one registered class answers a lookup made by `instance`.
/// A module handle whose high bits are all zero is a 16-bit instance and is
/// excluded from the high-bit fallback. # C: O(1)
pub const fn instance_matches(module: u64, local: bool, instance: u64) -> bool {
    if instance == 0 || !local || module == instance { return true; }
    let is_win16 = module >> 16 == 0;
    !is_win16 && (module & !MODULE_LOW) == (instance & !MODULE_LOW)
}

/// Whether one registration is local to the module that registers it. # C: O(1)
pub const fn registration_is_local(style: u32, builtin: bool) -> bool {
    !builtin && style & CS_GLOBALCLASS == 0
}

/// Whether an extra-byte request is one a registration may make. # C: O(1)
pub const fn extra_size_admitted(size: i32) -> bool { size >= 0 && size <= MAX_CLASS_EXTRA }

impl WindowManager {
    /// Position of the class one name and module name, in registration order.
    /// # C: O(N_classes + name)
    pub(super) fn find_class_index(&self, name: &[u16], instance: u64) -> Option<usize> {
        self.classes.iter().position(|class| same_name(&class.name, name) && instance_matches(class.module, class.local, instance))
    }
    /// Position of the class one atom and module name. # C: O(N_classes)
    pub(super) fn find_class_index_by_atom(&self, atom: u16, instance: u64) -> Option<usize> {
        self.classes.iter().position(|class| class.atom == atom && instance_matches(class.module, class.local, instance))
    }
    /// The whole record one name and module name. # C: O(N_classes + name)
    pub fn find_class(&self, name: &[u16], instance: u64) -> Option<&WindowClass> {
        self.classes.get(self.find_class_index(name, instance)?)
    }
    /// The whole record one atom and module name. # C: O(N_classes)
    pub fn find_class_by_atom(&self, atom: u16, instance: u64) -> Option<&WindowClass> {
        self.classes.get(self.find_class_index_by_atom(atom, instance)?)
    }
}

#[cfg(test)]
#[path = "tests/class_find.rs"]
mod tests;
