// The eight symbol tables.
//
// Each table is a count pair followed by its records; the record layout is
// per-table and grew field by field with the version, so every conditional
// here is a wire-format fact and not a policy choice.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ebitmap::Ebitmap;
use crate::error::{Error, Result};
use crate::mls::{Level, Range};
use crate::policydb::constraints;
use crate::policydb::symbols::{Bool, Cat, Class, Common, Default1, DefaultRange, Perm, Role,
                               Sens, Symbols, Type, User, OBJECT_R, OBJECT_R_VAL,
                               SYM_BOOLS, SYM_CATS, SYM_CLASSES, SYM_COMMONS, SYM_LEVELS,
                               SYM_NUM, SYM_ROLES, SYM_TYPES, SYM_USERS};
use crate::reader::Reader;
use crate::uapi::version::{POLICYDB_VERSION_BOUNDARY, POLICYDB_VERSION_DEFAULT_TYPE,
                          POLICYDB_VERSION_MLS, POLICYDB_VERSION_NEW_OBJECT_DEFAULTS,
                          POLICYDB_VERSION_VALIDATETRANS};

use super::slots::Slots;

/// Permission values are bit positions in a 32-bit access vector.
const PERM_MAX: u32 = 32;

/// Type record property bit: this name is the value's primary name.
const TYPE_PROP_PRIMARY: u32 = 0x1;
/// Type record property bit: the value names an attribute, not a type.
const TYPE_PROP_ATTRIBUTE: u32 = 0x2;

/// Permission granting the right to transition into a new domain.
const PERM_TRANSITION: &str = "transition";
/// Permission granting the right to transition the current domain in place.
const PERM_DYNTRANSITION: &str = "dyntransition";

/// Read every symbol table the header declared. # C: O(records)
pub fn read_all(r: &mut Reader<'_>, version: u32, sym_num: u32) -> Result<Symbols> {
    let mut s = Symbols::default();
    for index in 0..sym_num as usize {
        let nprim = r.u32()?;
        let nel = r.u32()?;
        if index < SYM_NUM { s.nprim[index] = nprim; }
        match index {
            SYM_COMMONS => s.commons = read_commons(r, nel)?,
            SYM_CLASSES => s.classes = read_classes(r, version, nprim, nel, &s.commons)?,
            SYM_ROLES => s.roles = read_roles(r, version, nprim, nel)?,
            SYM_TYPES => s.types = read_types(r, version, nprim, nel)?,
            SYM_USERS => s.users = read_users(r, version, nprim, nel)?,
            SYM_BOOLS => s.bools = read_bools(r, nprim, nel)?,
            SYM_LEVELS => s.sens = read_sens(r, nel)?,
            SYM_CATS => s.cats = read_cats(r, nprim, nel)?,
            _ => return Err(Error::Malformed),
        }
    }
    Ok(s)
}

/// Access-vector bits of the `process` class's two transition permissions. # C: O(permissions)
///
/// Both must exist: a domain transition is checked against their union, and a
/// missing bit here would silently drop half the check.
pub fn process_trans_perms(s: &Symbols, process_class: u32) -> Result<u32> {
    Ok(perm_bit(s, process_class, PERM_TRANSITION)?
       | perm_bit(s, process_class, PERM_DYNTRANSITION)?)
}

/// Access-vector bit of one named permission of a class. # C: O(permissions)
fn perm_bit(s: &Symbols, class_value: u32, name: &str) -> Result<u32> {
    let class = s.class(class_value).ok_or(Error::UnknownSymbol)?;
    let direct = class.perms.iter().find(|p| p.name == name);
    let inherited = || {
        let common = class.common?;
        s.commons.iter().find(|c| c.value == common)?.perms.iter().find(|p| p.name == name)
    };
    let perm = direct.or_else(inherited).ok_or(Error::UnknownSymbol)?;
    bit_of(perm.value)
}

/// Access-vector bit for a 1-based permission value. # C: O(1)
fn bit_of(value: u32) -> Result<u32> {
    if value == 0 || value > PERM_MAX { return Err(Error::Malformed); }
    Ok(1u32 << (value - 1))
}

fn read_perms(r: &mut Reader<'_>, nel: u32) -> Result<Vec<Perm>> {
    let mut out = Vec::new();
    out.try_reserve(nel as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..nel {
        let [len, value] = r.u32_array::<2>()?;
        if value == 0 || value > PERM_MAX { return Err(Error::Malformed); }
        let name = String::from(r.string_of(len)?);
        out.push(Perm { name, value });
    }
    Ok(out)
}

fn read_commons(r: &mut Reader<'_>, nel: u32) -> Result<Vec<Common>> {
    let mut out = Vec::new();
    out.try_reserve(nel as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..nel {
        let [len, value, nprim, perms_nel] = r.u32_array::<4>()?;
        let name = String::from(r.string_of(len)?);
        let perms = read_perms(r, perms_nel)?;
        out.push(Common { name, value, nprim, perms });
    }
    Ok(out)
}

fn read_classes(r: &mut Reader<'_>, version: u32, nprim: u32, nel: u32, commons: &[Common])
    -> Result<Vec<Class>>
{
    let mut slots = Slots::new(nprim)?;
    for _ in 0..nel {
        let [len, len2, value, perms_nprim, perms_nel, ncons] = r.u32_array::<6>()?;
        if value > u32::from(u16::MAX) { return Err(Error::Malformed); }
        let name = String::from(r.string_of(len)?);
        let (common_name, common) = if len2 != 0 {
            let cname = r.string_of(len2)?;
            let value = commons.iter().find(|c| c.name == cname).ok_or(Error::UnknownSymbol)?.value;
            (Some(String::from(cname)), Some(value))
        } else { (None, None) };
        let perms = read_perms(r, perms_nel)?;
        let constraints = constraints::read_list(r, version, ncons, false)?;
        let validatetrans = if version >= POLICYDB_VERSION_VALIDATETRANS {
            let ncons2 = r.u32()?;
            constraints::read_list(r, version, ncons2, true)?
        } else { Vec::new() };
        let (mut default_user, mut default_role) = (Default1::Unset, Default1::Unset);
        let mut default_range = DefaultRange::Unset;
        if version >= POLICYDB_VERSION_NEW_OBJECT_DEFAULTS {
            let [du, dr, drange] = r.u32_array::<3>()?;
            default_user = Default1::from_wire(du).ok_or(Error::Malformed)?;
            default_role = Default1::from_wire(dr).ok_or(Error::Malformed)?;
            default_range = DefaultRange::from_wire(drange).ok_or(Error::Malformed)?;
        }
        let default_type = if version >= POLICYDB_VERSION_DEFAULT_TYPE {
            Default1::from_wire(r.u32()?).ok_or(Error::Malformed)?
        } else { Default1::Unset };
        slots.place(value, true, Class {
            name, value, common_name, common, nprim: perms_nprim, perms,
            constraints, validatetrans, default_user, default_role, default_type, default_range,
        })?;
    }
    slots.finish()
}

fn read_roles(r: &mut Reader<'_>, version: u32, nprim: u32, nel: u32) -> Result<Vec<Role>> {
    let mut slots = Slots::new(nprim)?;
    // The object role is synthetic: it is created before the table is read so
    // that its value is fixed, and the stream's own copy is discarded.
    if nprim >= OBJECT_R_VAL {
        let mut dominates = Ebitmap::new();
        dominates.set(OBJECT_R_VAL - 1, true);
        slots.place(OBJECT_R_VAL, true, Role {
            name: String::from(OBJECT_R), value: OBJECT_R_VAL, bounds: 0,
            dominates, types: Ebitmap::new(),
        })?;
    }
    for _ in 0..nel {
        let (len, value, bounds) = if version >= POLICYDB_VERSION_BOUNDARY {
            let [len, value, bounds] = r.u32_array::<3>()?;
            (len, value, bounds)
        } else {
            let [len, value] = r.u32_array::<2>()?;
            (len, value, 0)
        };
        let name = String::from(r.string_of(len)?);
        let dominates = Ebitmap::read(r)?;
        let types = Ebitmap::read(r)?;
        if name == OBJECT_R {
            if value != OBJECT_R_VAL { return Err(Error::Malformed); }
            continue;
        }
        slots.place(value, true, Role { name, value, bounds, dominates, types })?;
    }
    slots.finish()
}

fn read_types(r: &mut Reader<'_>, version: u32, nprim: u32, nel: u32) -> Result<Vec<Type>> {
    let mut slots = Slots::new(nprim)?;
    for _ in 0..nel {
        let (len, value, primary, attribute, bounds) = if version >= POLICYDB_VERSION_BOUNDARY {
            let [len, value, prop, bounds] = r.u32_array::<4>()?;
            (len, value, prop & TYPE_PROP_PRIMARY != 0, prop & TYPE_PROP_ATTRIBUTE != 0, bounds)
        } else {
            let [len, value, primary] = r.u32_array::<3>()?;
            (len, value, primary != 0, false, 0)
        };
        let name = String::from(r.string_of(len)?);
        slots.place(value, primary, Type { name, value, primary, attribute, bounds })?;
    }
    slots.finish()
}

fn read_users(r: &mut Reader<'_>, version: u32, nprim: u32, nel: u32) -> Result<Vec<User>>
{
    let mut slots = Slots::new(nprim)?;
    for _ in 0..nel {
        let (len, value, bounds) = if version >= POLICYDB_VERSION_BOUNDARY {
            let [len, value, bounds] = r.u32_array::<3>()?;
            (len, value, bounds)
        } else {
            let [len, value] = r.u32_array::<2>()?;
            (len, value, 0)
        };
        let name = String::from(r.string_of(len)?);
        let roles = Ebitmap::read(r)?;
        let (range, dfltlevel) = if version >= POLICYDB_VERSION_MLS {
            (Range::read(r)?, Level::read(r)?)
        } else { (Range::default(), Level::default()) };
        slots.place(value, true, User { name, value, bounds, roles, range, dfltlevel })?;
    }
    slots.finish()
}

fn read_bools(r: &mut Reader<'_>, nprim: u32, nel: u32) -> Result<Vec<Bool>> {
    let mut slots = Slots::new(nprim)?;
    for _ in 0..nel {
        // Unlike every other record, the boolean's value and state precede its
        // name length; reading them in the usual order silently swaps a
        // boolean's state with its name length.
        let [value, state, len] = r.u32_array::<3>()?;
        if state > 1 { return Err(Error::Malformed); }
        let name = String::from(r.string_of(len)?);
        slots.place(value, true, Bool { name, value, state: state != 0 })?;
    }
    slots.finish()
}

fn read_sens(r: &mut Reader<'_>, nel: u32) -> Result<Vec<Sens>> {
    let mut out = Vec::new();
    out.try_reserve(nel as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..nel {
        let [len, isalias] = r.u32_array::<2>()?;
        let name = String::from(r.string_of(len)?);
        let level = Level::read(r)?;
        out.push(Sens { name, isalias: isalias != 0, level });
    }
    Ok(out)
}

fn read_cats(r: &mut Reader<'_>, nprim: u32, nel: u32) -> Result<Vec<Cat>> {
    let mut slots = Slots::new(nprim)?;
    for _ in 0..nel {
        let [len, value, isalias] = r.u32_array::<3>()?;
        let name = String::from(r.string_of(len)?);
        slots.place(value, isalias == 0, Cat { name, value, isalias: isalias != 0 })?;
    }
    slots.finish()
}
