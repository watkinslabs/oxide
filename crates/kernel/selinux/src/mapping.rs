// Kernel-to-policy translation of class and permission numbering.
//
// The kernel names a class and a permission by its own fixed enumeration; a
// loaded policy names the same things by its own symbol-table values, and the
// two agree only by accident. The translation is built ONCE per policy load
// and consulted on every query, so a query never searches symbol tables by
// name and never depends on the two numberings coinciding.
//
// A permission is looked up BY NAME, and its policy bit is `1 << (value - 1)`
// because policy permission values are 1-based. An off-by-one here does not
// fail loudly: it shifts every permission of the class by one position, so a
// query asking to search a directory is answered with the verdict for writing
// it.

use alloc::vec::Vec;

use crate::error::Result;
use crate::policydb::Policydb;
use crate::policydb::symbols::{Class, Perm};
use crate::uapi::classmap::{ClassDef, SECCLASS_MAP, class_def, perm_names};

/// Highest number of permissions an access vector can carry.
pub const AV_BITS: usize = u32::BITS as usize;

/// Highest 1-based policy permission value an access vector can express.
pub const MAX_PERM_VALUE: u32 = u32::BITS;

/// Policy bit reserved for a permission the policy does not define; no rule
/// can ever set it, so such a permission is never granted.
pub const UNKNOWN_PERM_BITS: u32 = 0;

/// One kernel class translated into the loaded policy's numbering.
pub struct MappedClass {
    /// Policy class value.
    pub policy_value: u32,
    /// Policy access-vector bits, indexed by kernel permission bit position.
    pub perm_bits: Vec<u32>,
}

/// Kernel-to-policy numbering for every class the kernel knows.
pub struct Mapping {
    /// Translation per kernel class, indexed by kernel class value minus one.
    classes: Vec<Option<MappedClass>>,
    /// Kernel classes the policy does not define.
    unknown: Vec<u16>,
}

impl Mapping {
    /// Build the kernel-to-policy translation for a loaded policy. # C: O(classes * perms)
    pub fn build(db: &Policydb) -> Result<Self> {
        let mut classes: Vec<Option<MappedClass>> = Vec::new();
        classes.try_reserve(SECCLASS_MAP.len()).map_err(|_| crate::error::Error::NoMemory)?;
        let mut unknown: Vec<u16> = Vec::new();

        for (index, def) in SECCLASS_MAP.iter().enumerate() {
            let kernel_class = index as u16 + 1;
            match db.symbols.class_by_name(def.name) {
                None => {
                    unknown.push(kernel_class);
                    classes.push(None);
                }
                Some(policy_value) => {
                    let class = db.symbols.class(policy_value);
                    let perm_bits = map_perms(db, class, def);
                    classes.push(Some(MappedClass { policy_value, perm_bits }));
                }
            }
        }
        Ok(Self { classes, unknown })
    }

    /// Policy class value for a kernel class value. # C: O(1)
    pub fn policy_class(&self, kernel_class: u16) -> Option<u32> {
        self.mapped(kernel_class).map(|m| m.policy_value)
    }

    /// Kernel class value for a policy class value. # C: O(classes)
    pub fn kernel_class(&self, policy_class: u32) -> Option<u16> {
        self.classes.iter().position(|c| {
            c.as_ref().is_some_and(|m| m.policy_value == policy_class)
        }).map(|i| i as u16 + 1)
    }

    /// Translate a kernel access vector into policy bit positions. # C: O(perms)
    pub fn to_policy_av(&self, kernel_class: u16, av: u32) -> u32 {
        let Some(m) = self.mapped(kernel_class) else { return 0 };
        let mut out = 0u32;
        for (i, bits) in m.perm_bits.iter().enumerate() {
            if av & (1u32 << i) != 0 { out |= *bits; }
        }
        out
    }

    /// Translate a policy access vector back into kernel bit positions. # C: O(perms)
    pub fn to_kernel_av(&self, kernel_class: u16, av: u32) -> u32 {
        let Some(m) = self.mapped(kernel_class) else { return 0 };
        let mut out = 0u32;
        for (i, bits) in m.perm_bits.iter().enumerate() {
            if *bits != UNKNOWN_PERM_BITS && av & *bits != 0 { out |= 1u32 << i; }
        }
        out
    }

    /// Kernel classes the policy does not define. # C: O(1)
    pub fn unknown_classes(&self) -> &[u16] { &self.unknown }

    /// Policy bits of one kernel permission bit, for tests and diagnostics. # C: O(1)
    pub fn perm_bits(&self, kernel_class: u16, kernel_bit: u32) -> u32 {
        self.mapped(kernel_class)
            .and_then(|m| m.perm_bits.get(kernel_bit as usize).copied())
            .unwrap_or(UNKNOWN_PERM_BITS)
    }

    fn mapped(&self, kernel_class: u16) -> Option<&MappedClass> {
        self.classes.get(kernel_class.checked_sub(1)? as usize)?.as_ref()
    }
}

/// Policy bit per kernel permission bit of one class.
///
/// Permissions of a class live in two places: the class's own list and the
/// list of the common it inherits. Consulting only one of them leaves every
/// inherited permission unmapped and therefore permanently denied.
fn map_perms(db: &Policydb, class: Option<&Class>, def: &'static ClassDef) -> Vec<u32> {
    let mut bits: Vec<u32> = Vec::new();
    for (i, name) in perm_names(def).enumerate() {
        if i >= AV_BITS { break; }
        bits.push(class.and_then(|c| policy_perm_bit(db, c, name)).unwrap_or(UNKNOWN_PERM_BITS));
    }
    bits
}

/// Policy access-vector bit of one named permission of a class.
fn policy_perm_bit(db: &Policydb, class: &Class, name: &str) -> Option<u32> {
    let own = find_perm(&class.perms, name);
    let perm = match own {
        Some(p) => Some(p),
        None => class.common
            .and_then(|v| db.symbols.commons.iter().find(|c| c.value == v))
            .and_then(|c| find_perm(&c.perms, name)),
    }?;
    if perm.value == 0 || perm.value > MAX_PERM_VALUE { return None; }
    Some(1u32 << (perm.value - 1))
}

fn find_perm<'a>(perms: &'a [Perm], name: &str) -> Option<&'a Perm> {
    perms.iter().find(|p| p.name == name)
}

/// Kernel class value of a class the kernel knows by name. # C: O(classes)
pub fn kernel_class_by_name(name: &str) -> Option<u16> {
    crate::uapi::classmap::class_by_name(name)
}

/// Kernel access-vector bit of a named permission of a kernel class. # C: O(perms)
pub fn kernel_perm_bit(kernel_class: u16, name: &str) -> Option<u32> {
    let def = class_def(kernel_class)?;
    let index = crate::uapi::classmap::perm_index(def, name)?;
    if index as usize >= AV_BITS { return None; }
    Some(1u32 << index)
}

#[cfg(test)]
#[path = "tests/mapping.rs"]
mod tests;
