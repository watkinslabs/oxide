//! Namespace access for the ACPI device drivers built on this crate.
//!
//! The AML namespace has exactly one owner (`aml_routes`); this module is the
//! read side of it, handing callers plain Rust values so that everything they
//! then decide is testable without a namespace. Device drivers never hold the
//! parser handle themselves.

use alloc::string::String;
use alloc::vec::Vec;
use aml::{value::{AmlValue, Args}, AmlContext, AmlName};

use super::aml_routes;

/// One element of an evaluated package, reduced to the two shapes ACPI
/// device methods actually return.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AmlField {
    Int(u64),
    Text(String),
}

impl AmlField {
    /// Integer payload, or `None` when the field is text. # C: O(1)
    pub fn int(&self) -> Option<u64> {
        match self { AmlField::Int(v) => Some(*v), AmlField::Text(_) => None }
    }

    /// Text payload; an integer field renders as its decimal form the way a
    /// firmware that packs a number into an identity field intends.
    /// # C: O(1)
    pub fn text(&self) -> String {
        match self {
            AmlField::Text(text) => text.clone(),
            AmlField::Int(value) => {
                let mut out = String::new();
                let _ = core::fmt::Write::write_fmt(&mut out, format_args!("{value}"));
                out
            }
        }
    }
}

/// Number of characters in the vendor part of a compressed EISA identifier.
const EISA_VENDOR_CHARS: u32 = 3;
/// Bit width of one packed vendor character.
const EISA_CHAR_BITS: u32 = 5;
/// Bit position of the first (most significant) vendor character.
const EISA_FIRST_CHAR_SHIFT: u32 = 26;
/// Character that packed value zero maps to; vendor letters count up from it.
const EISA_CHAR_BASE: u8 = b'@';
/// Bit position of the most significant product hex digit.
const EISA_FIRST_HEX_SHIFT: u32 = 12;
const EISA_HEX_BITS: u32 = 4;
const EISA_HEX_DIGITS: u32 = 4;

/// Decode a compressed EISA identifier into its `AAAnnnn` text form. Firmware
/// stores `_HID` either as this packed integer or as the string directly, and
/// a driver that only matched the string form would miss most machines.
/// # C: O(1)
pub fn eisa_id_to_string(id: u32) -> String {
    let packed = id.swap_bytes();
    let mut out = String::with_capacity((EISA_VENDOR_CHARS + EISA_HEX_DIGITS) as usize);
    for index in 0..EISA_VENDOR_CHARS {
        let shift = EISA_FIRST_CHAR_SHIFT - index * EISA_CHAR_BITS;
        let value = ((packed >> shift) & ((1 << EISA_CHAR_BITS) - 1)) as u8;
        out.push((EISA_CHAR_BASE + value) as char);
    }
    for index in 0..EISA_HEX_DIGITS {
        let shift = EISA_FIRST_HEX_SHIFT - index * EISA_HEX_BITS;
        let nibble = ((packed >> shift) & ((1 << EISA_HEX_BITS) - 1)) as u8;
        out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0').to_ascii_uppercase());
    }
    out
}

/// Reduce one evaluated value to a field. # C: O(n)
fn field(context: &AmlContext, value: &AmlValue) -> Option<AmlField> {
    match value {
        AmlValue::Integer(v) => Some(AmlField::Int(*v)),
        AmlValue::String(text) => Some(AmlField::Text(text.clone())),
        AmlValue::Buffer(bytes) => {
            let bytes = bytes.lock();
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            Some(AmlField::Text(String::from_utf8_lossy(&bytes[..end]).into_owned()))
        }
        other => other.as_integer(context).ok().map(AmlField::Int),
    }
}

/// Resolve `name` inside `scope` and evaluate it. # C: O(AML)
fn eval(context: &mut AmlContext, scope: &str, name: &str) -> Option<AmlValue> {
    let scope = AmlName::from_str(scope).ok()?;
    let path = AmlName::from_str(name).ok()?.resolve(&scope).ok()?;
    context.namespace.get_handle(&path).ok()?;
    context.invoke_method(&path, Args::EMPTY).ok()
}

/// Absolute namespace paths of every device whose `_HID` (or one of its
/// `_CID` entries) matches `hid`. # C: O(namespace)
pub fn devices_with_hid(hid: &str) -> Vec<String> {
    aml_routes::with_namespace(|context| {
        let mut scopes = Vec::new();
        let _ = context.namespace.traverse(|path, level| {
            if level.typ == aml::LevelType::Device { scopes.push(path.clone()); }
            Ok(true)
        });
        let mut matched = Vec::new();
        for scope in scopes {
            let path = scope.as_string();
            if identifiers(context, &path).iter().any(|id| id == hid) { matched.push(path); }
        }
        Some(matched)
    })
    .unwrap_or_default()
}

/// The `_HID` plus every `_CID` a device publishes, in text form.
/// # C: O(AML)
fn identifiers(context: &mut AmlContext, scope: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut push = |value: Option<AmlValue>, context: &AmlContext| {
        let Some(value) = value else { return; };
        match value {
            AmlValue::Package(entries) => {
                for entry in entries.iter() {
                    if let Some(field) = field(context, entry) { ids.push(identifier_text(&field)); }
                }
            }
            other => {
                if let Some(field) = field(context, &other) { ids.push(identifier_text(&field)); }
            }
        }
    };
    let hid = eval(context, scope, "_HID");
    push(hid, context);
    let cid = eval(context, scope, "_CID");
    push(cid, context);
    ids
}

/// Identity fields arrive either as the packed integer or the text form.
/// # C: O(1)
fn identifier_text(field: &AmlField) -> String {
    match field {
        AmlField::Int(value) => eisa_id_to_string(*value as u32),
        AmlField::Text(text) => text.clone(),
    }
}

/// Device paths nested exactly `depth` levels below `scope`. Firmware hangs
/// display outputs off the graphics device this way, and the outputs carry no
/// stable identifier of their own. # C: O(namespace)
pub fn children_of(scope: &str, depth: usize) -> Vec<String> {
    aml_routes::with_namespace(|context| {
        let prefix = alloc::format!("{scope}.");
        let mut out = Vec::new();
        let _ = context.namespace.traverse(|path, level| {
            if level.typ != aml::LevelType::Device { return Ok(true); }
            let text = path.as_string();
            if let Some(rest) = text.strip_prefix(prefix.as_str()) {
                if rest.matches('.').count() + 1 == depth { out.push(text); }
            }
            Ok(true)
        });
        Some(out)
    })
    .unwrap_or_default()
}

/// Absolute namespace paths of every thermal zone the firmware declares. A
/// zone is its own namespace level rather than a device with an identifier, so
/// the device scan cannot find one. # C: O(namespace)
pub fn thermal_zones() -> Vec<String> {
    aml_routes::with_namespace(|context| {
        let mut zones = Vec::new();
        let _ = context.namespace.traverse(|path, level| {
            if level.typ == aml::LevelType::ThermalZone { zones.push(path.as_string()); }
            Ok(true)
        });
        Some(zones)
    })
    .unwrap_or_default()
}

/// Absolute namespace paths of the devices a package of references names.
///
/// Firmware associates a cooling device with a trip point by listing it in a
/// package of references; the elements arrive as names to be resolved against
/// the declaring scope. An element the parser has already reduced to a value
/// carries no path and is skipped, because binding by position instead would
/// attach a fan to whichever trip happened to be listed alongside it.
/// # C: O(AML)
pub fn eval_reference_paths(scope: &str, name: &str) -> Vec<String> {
    aml_routes::with_namespace(|context| {
        let AmlValue::Package(entries) = eval(context, scope, name)? else { return None; };
        let base = AmlName::from_str(scope).ok()?;
        let mut paths = Vec::new();
        for entry in entries.iter() {
            let AmlValue::String(text) = entry else { continue; };
            let Ok(relative) = AmlName::from_str(text) else { continue; };
            if let Ok(resolved) = context.namespace.search_for_level(&relative, &base) {
                paths.push(resolved.as_string());
            }
        }
        Some(paths)
    })
    .unwrap_or_default()
}

/// Whether `scope` declares `name`. # C: O(AML)
pub fn has_method(scope: &str, name: &str) -> bool {
    aml_routes::with_namespace(|context| {
        let scope = AmlName::from_str(scope).ok()?;
        let path = AmlName::from_str(name).ok()?.resolve(&scope).ok()?;
        context.namespace.get_handle(&path).ok().map(|_| ())
    })
    .is_some()
}

/// Evaluate a method that returns an integer. # C: O(AML)
pub fn eval_integer(scope: &str, name: &str) -> Option<u64> {
    aml_routes::with_namespace(|context| {
        let value = eval(context, scope, name)?;
        value.as_integer(context).ok()
    })
}

/// Evaluate a method that returns a package, flattened to fields. # C: O(AML)
pub fn eval_package(scope: &str, name: &str) -> Option<Vec<AmlField>> {
    aml_routes::with_namespace(|context| {
        let AmlValue::Package(entries) = eval(context, scope, name)? else { return None; };
        Some(entries.iter().map(|entry| field(context, entry).unwrap_or(AmlField::Int(0))).collect())
    })
}

/// Evaluate a method with one integer argument, discarding its result.
/// # C: O(AML)
pub fn eval_with_integer(scope: &str, name: &str, arg: u64) -> bool {
    aml_routes::with_namespace(|context| {
        let scope = AmlName::from_str(scope).ok()?;
        let path = AmlName::from_str(name).ok()?.resolve(&scope).ok()?;
        context.namespace.get_handle(&path).ok()?;
        let args = Args::from_list(alloc::vec![AmlValue::Integer(arg)]).ok()?;
        context.invoke_method(&path, args).ok().map(|_| ())
    })
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packed_identifier_decodes_to_its_text_form() {
        assert_eq!(eisa_id_to_string(0x0A0C_D041), "PNP0C0A");
        assert_eq!(eisa_id_to_string(0x0000_D041), "PNP0000");
        assert_eq!(eisa_id_to_string(0x0303_D041), "PNP0303");
    }

    #[test]
    fn an_integer_field_still_yields_a_text_identity() {
        assert_eq!(AmlField::Int(42).text(), "42");
        assert_eq!(AmlField::Text(String::from("OXP-1")).text(), "OXP-1");
        assert_eq!(AmlField::Int(42).int(), Some(42));
        assert_eq!(AmlField::Text(String::from("x")).int(), None);
    }
}
