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

/// One `_CST` package field kept in its firmware shape. The C-state register
/// is binary data, not text: treating it as a string loses zero bytes in the
/// address and silently changes the entry mechanism.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CstField {
    Int(u64),
    Buffer(Vec<u8>),
}

/// Evaluated `_CST` package before architecture-specific validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CstPackage {
    pub count: u64,
    pub rows: Vec<Vec<CstField>>,
}

/// One firmware CPU scope and the ACPI UID that identifies its logical CPU.
/// Legacy `Processor` objects carry that UID in their object header; modern
/// ACPI CPU devices publish it through `_UID`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessorScope { pub path: String, pub uid: u32 }

/// One ACPI device's `_PRW` wake declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrwDevice {
    pub path: String,
    /// `None` selects the fixed FADT GPE blocks. A named device selects a GPE
    /// block installed by that device's driver.
    pub gpe_device: Option<String>,
    pub gpe_number: u8,
    /// Deepest system sleep state from which this source can wake.
    pub sleep_state: u8,
    pub default_enabled: bool,
    pub power_resources: Vec<String>,
}

/// One canonical AML `PowerResource` namespace object. Device `_PRx` and
/// `_PRW` packages refer to this object by path; they do not own its state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PowerResourceDecl {
    pub path: String,
    pub system_level: u8,
    pub order: u16,
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
    match context.namespace.get_by_path(&path).ok()?.clone() {
        AmlValue::Method { .. } => context.invoke_method(&path, Args::EMPTY).ok(),
        value => Some(value),
    }
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
            let relative = match entry {
                AmlValue::Reference(path) => path.clone(),
                // Keep accepting the old representation for namespace values
                // created by native AML methods and already-published tables.
                AmlValue::String(text) => match AmlName::from_str(text) { Ok(path) => path, Err(_) => continue },
                _ => continue,
            };
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

/// Evaluate a package whose elements are themselves packages, preserving the
/// inner rows. Firmware performance states use one row per state, while
/// control/status descriptors use one row per register. # C: O(AML + fields)
pub fn eval_package_rows(scope: &str, name: &str) -> Option<Vec<Vec<AmlField>>> {
    aml_routes::with_namespace(|context| {
        let value = eval(context, scope, name)?;
        package_rows(context, &value)
    })
}

/// Evaluate a package whose elements are AML buffers, preserving their raw
/// bytes. Resource-template methods use this form for register descriptors.
/// # C: O(AML + bytes)
pub fn eval_package_buffers(scope: &str, name: &str) -> Option<Vec<Vec<u8>>> {
    aml_routes::with_namespace(|context| {
        let AmlValue::Package(entries) = eval(context, scope, name)? else { return None; };
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries.iter() {
            let AmlValue::Buffer(bytes) = entry else { return None; };
            out.push(bytes.lock().clone());
        }
        Some(out)
    })
}

/// Evaluate a processor's C-state package without flattening register
/// buffers. # C: O(AML + fields)
pub fn eval_cst(scope: &str) -> Option<CstPackage> {
    aml_routes::with_namespace(|context| {
        let AmlValue::Package(entries) = eval(context, scope, "_CST")? else { return None; };
        let AmlValue::Integer(count) = entries.first()? else { return None; };
        let mut rows = Vec::with_capacity(entries.len().saturating_sub(1));
        for row in entries.iter().skip(1) {
            let AmlValue::Package(fields) = row else { rows.push(Vec::new()); continue; };
            let mut values = Vec::with_capacity(fields.len());
            for value in fields.iter() {
                let field = match value {
                    AmlValue::Buffer(bytes) => CstField::Buffer(bytes.lock().clone()),
                    AmlValue::Integer(value) => CstField::Int(*value),
                    _ => { values.clear(); break; }
                };
                values.push(field);
            }
            rows.push(values);
        }
        Some(CstPackage { count: *count, rows })
    })
}

/// Decode one package-of-packages already read from the AML namespace.
/// # C: O(fields)
fn package_rows(context: &AmlContext, value: &AmlValue) -> Option<Vec<Vec<AmlField>>> {
    let AmlValue::Package(rows) = value else { return None; };
    let mut out = Vec::with_capacity(rows.len());
    for row in rows.iter() {
        let AmlValue::Package(fields) = row else { return None; };
        let mut values = Vec::with_capacity(fields.len());
        for value in fields.iter() { values.push(field(context, value)?); }
        out.push(values);
    }
    Some(out)
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

/// Evaluate a no-argument control method, discarding its result. # C: O(AML)
pub(crate) fn eval_no_args(scope: &str, name: &str) -> bool {
    aml_routes::with_namespace(|context| {
        let scope = AmlName::from_str(scope).ok()?;
        let path = AmlName::from_str(name).ok()?.resolve(&scope).ok()?;
        context.namespace.get_handle(&path).ok()?;
        context.invoke_method(&path, Args::EMPTY).ok().map(|_| ())
    }).is_some()
}

/// Evaluate a method with integer arguments, discarding its result. # C: O(AML)
pub(crate) fn eval_with_integers(scope: &str, name: &str, args: &[u64]) -> bool {
    aml_routes::with_namespace(|context| {
        let scope = AmlName::from_str(scope).ok()?;
        let path = AmlName::from_str(name).ok()?.resolve(&scope).ok()?;
        context.namespace.get_handle(&path).ok()?;
        let values = args.iter().copied().map(AmlValue::Integer).collect();
        let args = Args::from_list(values).ok()?;
        context.invoke_method(&path, args).ok().map(|_| ())
    }).is_some()
}

#[cfg(test)]
#[path = "aml_eval/tests.rs"]
mod tests;
mod discovery;
pub use discovery::{children_of, devices_with_hid, processor_scopes, processors, thermal_zones};
pub(crate) use discovery::{power_resources, wake_devices};
#[cfg(test)]
pub(crate) use discovery::decode_prw;
