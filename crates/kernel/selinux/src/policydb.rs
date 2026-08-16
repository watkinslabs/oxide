// The loaded policy database.
//
// Module manifest:
//   symbols     — the named entities a policy declares and their values
//   constraints — postfix expressions that remove granted permissions
//   cond        — conditional rules and the booleans that gate them
//   sections    — object contexts, genfs, filename/role/range transitions
//   read        — the image reader that builds a `Policydb`
//
// Everything here is immutable once built, except boolean state and the
// conditional-enabled bits that boolean state drives.

pub mod symbols;
pub mod constraints;
pub mod cond;
pub mod sections;
pub mod read;

use alloc::vec::Vec;

use crate::avtab::Avtab;
use crate::context::ValidContext;
use crate::ebitmap::Ebitmap;
use crate::mls::Range;

pub use read::load;
pub use sections::{FsUse, Genfs, GenfsPath, Ocontexts, PortCon, RangeTrans, RoleTrans};
pub use symbols::{Symbols, OBJECT_R_VAL, SYM_NUM};

/// A fully-read policy, ready to answer decisions.
pub struct Policydb {
    /// Version of the image this policy was read from.
    pub version: u32,
    /// Whether the policy carries MLS levels and categories.
    pub mls: bool,
    /// Refuse to load if the image names a class or permission we do not know.
    pub reject_unknown: bool,
    /// Grant, rather than deny, permissions on classes we do not know.
    pub allow_unknown: bool,
    /// Every symbol table.
    pub symbols: Symbols,
    /// Unconditional type-enforcement rules.
    pub te_avtab: Avtab,
    /// Conditional type-enforcement rules, gated by `cond_list`.
    pub te_cond_avtab: Avtab,
    /// Conditional expressions and the rule lists they gate.
    pub cond_list: Vec<cond::CondNode>,
    /// Role transitions.
    pub role_tr: Vec<RoleTrans>,
    /// Permitted role changes, as `(from, to)` pairs.
    pub role_allow: Vec<(u32, u32)>,
    /// Filename transitions, keyed by target type, class and name.
    pub filename_trans: Vec<sections::FilenameTrans>,
    /// Target types that appear in at least one filename transition.
    pub filename_trans_ttypes: Ebitmap,
    /// Object contexts: initial SIDs, ports, interfaces, nodes, fs_use.
    pub ocontexts: Ocontexts,
    /// Per-filesystem path-prefix contexts.
    pub genfs: Vec<Genfs>,
    /// MLS range transitions.
    pub range_tr: Vec<RangeTrans>,
    /// For each type value, the attributes it belongs to plus its own bit.
    pub type_attr_map: Vec<Ebitmap>,
    /// Types whose domains run permissive even when enforcing is on.
    pub permissive_map: Ebitmap,
    /// Types whose denials are never audited.
    pub neveraudit_map: Ebitmap,
    /// Policy capability bits.
    pub policycaps: Ebitmap,
    /// Class value of `process`, resolved at load and required to exist.
    pub process_class: u32,
    /// Access-vector bits of `process` transition and dyntransition.
    pub process_trans_perms: u32,
}

impl Policydb {
    /// Whether one policy capability is enabled. # C: O(log chunks)
    pub fn policycap(&self, bit: u32) -> bool { self.policycaps.get(bit) }

    /// Whether a type's domain runs permissive. # C: O(log chunks)
    ///
    /// Permissive is per-DOMAIN, keyed on the SOURCE context's type. A check
    /// that keyed it on the target would make every object in a permissive
    /// domain's reach permissive too.
    pub fn type_is_permissive(&self, ty: u32) -> bool {
        self.permissive_map.get(ty)
    }

    /// Whether a type's denials are never audited. # C: O(log chunks)
    pub fn type_is_neveraudit(&self, ty: u32) -> bool { self.neveraudit_map.get(ty) }

    /// Attribute set of one type, including the type's own value. # C: O(1)
    ///
    /// Rules are stored against attributes and types interchangeably, so this
    /// set is exactly what an access-vector lookup must iterate. An empty
    /// answer here makes every attribute rule invisible.
    pub fn type_attrs(&self, ty: u32) -> Option<&Ebitmap> {
        self.type_attr_map.get(ty.checked_sub(1)? as usize)
    }

    /// Whether a context satisfies this policy. # C: O(categories)
    ///
    /// Every component must resolve, the role must be permitted for the user,
    /// the type must be permitted for the role, and the MLS range must be
    /// ordered and within the user's clearance. Skipping any one of these
    /// admits a context the policy never authorised.
    pub fn context_is_valid(&self, c: &ValidContext) -> bool {
        let Some(user) = self.symbols.user(c.user) else { return false };
        if self.symbols.role(c.role).is_none() { return false; }
        let Some(ty) = self.symbols.ty(c.ty) else { return false };
        if ty.attribute { return false; }
        if c.role != OBJECT_R_VAL {
            if !user.roles.get(c.role - 1) { return false; }
            let Some(role) = self.symbols.role(c.role) else { return false };
            if !role.types.get(c.ty - 1) { return false; }
        }
        self.mls_range_is_valid(&c.range, c.role, user)
    }

    fn mls_range_is_valid(&self, range: &Range, role: u32, user: &symbols::User) -> bool {
        if !self.mls { return true; }
        for level in [&range.low, &range.high] {
            if self.symbols.sens_name(level.sens).is_none() { return false; }
            for cat in level.cat.iter() {
                if cat >= self.symbols.nprim[symbols::SYM_CATS] { return false; }
            }
        }
        if !range.is_ordered() { return false; }
        if role == OBJECT_R_VAL { return true; }
        user.range.contains(range)
    }
}
