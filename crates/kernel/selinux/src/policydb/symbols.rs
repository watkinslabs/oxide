// Policy symbol tables: the named entities a policy declares, each with a
// 1-based value that every other section refers to it by.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ebitmap::Ebitmap;
use crate::mls::{Level, Range};

/// Symbol table indices, in the order the image stores them.
pub const SYM_COMMONS: usize = 0;
/// Security classes.
pub const SYM_CLASSES: usize = 1;
/// Roles.
pub const SYM_ROLES: usize = 2;
/// Types and attributes.
pub const SYM_TYPES: usize = 3;
/// Users.
pub const SYM_USERS: usize = 4;
/// Conditional booleans.
pub const SYM_BOOLS: usize = 5;
/// Sensitivity levels.
pub const SYM_LEVELS: usize = 6;
/// Categories.
pub const SYM_CATS: usize = 7;
/// Number of symbol tables in a current-version policy.
pub const SYM_NUM: usize = 8;

/// Value of the synthetic object role every object context carries.
pub const OBJECT_R_VAL: u32 = 1;

/// Name of the synthetic object role.
pub const OBJECT_R: &str = "object_r";

/// One named permission within a class or common.
#[derive(Clone, Debug)]
pub struct Perm {
    /// Permission name.
    pub name: String,
    /// 1-based bit position within the class's access vector.
    pub value: u32,
}

/// A set of permissions shared by several classes.
#[derive(Clone, Debug, Default)]
pub struct Common {
    /// Common name.
    pub name: String,
    /// 1-based value.
    pub value: u32,
    /// Highest permission value declared.
    pub nprim: u32,
    /// Permissions this common declares.
    pub perms: Vec<Perm>,
}

/// Where a created object's component comes from when policy states a default.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum Default1 {
    /// Policy states no default; the caller's fallback applies.
    #[default]
    Unset,
    /// Take the component from the source context.
    Source,
    /// Take the component from the target context.
    Target,
}

/// Where a created object's MLS range comes from when policy states a default.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum DefaultRange {
    /// Policy states no default; the caller's fallback applies.
    #[default]
    Unset,
    /// Source's low level, as a single-level range.
    SourceLow,
    /// Source's high level, as a single-level range.
    SourceHigh,
    /// Source's whole range.
    SourceLowHigh,
    /// Target's low level, as a single-level range.
    TargetLow,
    /// Target's high level, as a single-level range.
    TargetHigh,
    /// Target's whole range.
    TargetLowHigh,
    /// Greatest lower bound of the source and target ranges.
    Glblub,
}

impl Default1 {
    /// Decode a wire value. # C: O(1)
    pub const fn from_wire(v: u32) -> Option<Self> {
        match v { 0 => Some(Self::Unset), 1 => Some(Self::Source), 2 => Some(Self::Target),
                  _ => None }
    }
}

impl DefaultRange {
    /// Decode a wire value. # C: O(1)
    pub const fn from_wire(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Unset),
            1 => Some(Self::SourceLow),
            2 => Some(Self::SourceHigh),
            3 => Some(Self::SourceLowHigh),
            4 => Some(Self::TargetLow),
            5 => Some(Self::TargetHigh),
            6 => Some(Self::TargetLowHigh),
            7 => Some(Self::Glblub),
            _ => None,
        }
    }
}

/// One security class.
#[derive(Clone, Debug, Default)]
pub struct Class {
    /// Class name.
    pub name: String,
    /// 1-based class value.
    pub value: u32,
    /// Name of the common whose permissions this class inherits, if any.
    pub common_name: Option<String>,
    /// Value of that common, resolved at load.
    pub common: Option<u32>,
    /// Highest permission value declared directly on this class.
    pub nprim: u32,
    /// Permissions declared directly on this class.
    pub perms: Vec<Perm>,
    /// Constraints restricting when permissions are granted.
    pub constraints: Vec<super::constraints::Constraint>,
    /// Constraints restricting relabel transitions.
    pub validatetrans: Vec<super::constraints::Constraint>,
    /// Default user for objects created in this class.
    pub default_user: Default1,
    /// Default role for objects created in this class.
    pub default_role: Default1,
    /// Default type for objects created in this class.
    pub default_type: Default1,
    /// Default MLS range for objects created in this class.
    pub default_range: DefaultRange,
}

/// One role.
#[derive(Clone, Debug, Default)]
pub struct Role {
    /// Role name.
    pub name: String,
    /// 1-based role value.
    pub value: u32,
    /// Bounding role, or zero.
    pub bounds: u32,
    /// Roles this role dominates.
    pub dominates: Ebitmap,
    /// Types this role may be paired with.
    pub types: Ebitmap,
}

/// One type or attribute.
#[derive(Clone, Debug, Default)]
pub struct Type {
    /// Type name.
    pub name: String,
    /// 1-based type value.
    pub value: u32,
    /// Whether this is the primary name for its value rather than an alias.
    pub primary: bool,
    /// Whether this value names an attribute rather than a concrete type.
    pub attribute: bool,
    /// Bounding type, or zero.
    pub bounds: u32,
}

/// One user.
#[derive(Clone, Debug, Default)]
pub struct User {
    /// User name.
    pub name: String,
    /// 1-based user value.
    pub value: u32,
    /// Bounding user, or zero.
    pub bounds: u32,
    /// Roles this user may assume.
    pub roles: Ebitmap,
    /// MLS clearance range.
    pub range: Range,
    /// Default MLS level for this user's sessions.
    pub dfltlevel: Level,
}

/// One conditional boolean.
#[derive(Clone, Debug, Default)]
pub struct Bool {
    /// Boolean name.
    pub name: String,
    /// 1-based boolean value.
    pub value: u32,
    /// Committed state.
    pub state: bool,
}

/// One sensitivity level declaration.
#[derive(Clone, Debug, Default)]
pub struct Sens {
    /// Sensitivity name.
    pub name: String,
    /// Whether this name is an alias for an already-declared sensitivity.
    pub isalias: bool,
    /// The level this name denotes.
    pub level: Level,
}

/// One category declaration.
#[derive(Clone, Debug, Default)]
pub struct Cat {
    /// Category name.
    pub name: String,
    /// 1-based category value.
    pub value: u32,
    /// Whether this name is an alias for an already-declared category.
    pub isalias: bool,
}

/// Every symbol table of a loaded policy.
#[derive(Clone, Debug, Default)]
pub struct Symbols {
    /// Commons, in declaration order.
    pub commons: Vec<Common>,
    /// Classes indexed by value minus one.
    pub classes: Vec<Class>,
    /// Roles indexed by value minus one.
    pub roles: Vec<Role>,
    /// Types indexed by value minus one; aliases are held separately.
    pub types: Vec<Type>,
    /// Users indexed by value minus one.
    pub users: Vec<User>,
    /// Booleans indexed by value minus one.
    pub bools: Vec<Bool>,
    /// Sensitivities in declaration order.
    pub sens: Vec<Sens>,
    /// Categories indexed by value minus one.
    pub cats: Vec<Cat>,
    /// Highest declared value per symbol table.
    pub nprim: [u32; SYM_NUM],
}

impl Symbols {
    /// Class by 1-based value. # C: O(1)
    pub fn class(&self, value: u32) -> Option<&Class> {
        self.classes.get(value.checked_sub(1)? as usize)
    }

    /// Type by 1-based value. # C: O(1)
    pub fn ty(&self, value: u32) -> Option<&Type> {
        self.types.get(value.checked_sub(1)? as usize)
    }

    /// Role by 1-based value. # C: O(1)
    pub fn role(&self, value: u32) -> Option<&Role> {
        self.roles.get(value.checked_sub(1)? as usize)
    }

    /// User by 1-based value. # C: O(1)
    pub fn user(&self, value: u32) -> Option<&User> {
        self.users.get(value.checked_sub(1)? as usize)
    }

    /// Class value for a class name. # C: O(classes)
    pub fn class_by_name(&self, name: &str) -> Option<u32> {
        self.classes.iter().find(|c| c.name == name).map(|c| c.value)
    }

    /// Type value for a type name. # C: O(types)
    pub fn type_by_name(&self, name: &str) -> Option<u32> {
        self.types.iter().find(|t| t.name == name).map(|t| t.value)
    }

    /// Role value for a role name. # C: O(roles)
    pub fn role_by_name(&self, name: &str) -> Option<u32> {
        self.roles.iter().find(|r| r.name == name).map(|r| r.value)
    }

    /// User value for a user name. # C: O(users)
    pub fn user_by_name(&self, name: &str) -> Option<u32> {
        self.users.iter().find(|u| u.name == name).map(|u| u.value)
    }

    /// Sensitivity value for a level name. # C: O(levels)
    pub fn sens_by_name(&self, name: &str) -> Option<u32> {
        self.sens.iter().find(|s| s.name == name).map(|s| s.level.sens)
    }

    /// Category value for a category name. # C: O(categories)
    pub fn cat_by_name(&self, name: &str) -> Option<u32> {
        self.cats.iter().find(|c| c.name == name).map(|c| c.value)
    }

    /// Name of a sensitivity value. # C: O(levels)
    pub fn sens_name(&self, sens: u32) -> Option<&str> {
        self.sens.iter().find(|s| s.level.sens == sens && !s.isalias).map(|s| s.name.as_str())
    }

    /// Name of a category value. # C: O(1)
    pub fn cat_name(&self, cat: u32) -> Option<&str> {
        self.cats.get(cat as usize).map(|c| c.name.as_str())
    }
}
