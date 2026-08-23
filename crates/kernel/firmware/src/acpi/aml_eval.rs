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

/// Decode every device `_PRW` package in the namespace. Malformed packages
/// are not wake sources; they cannot safely select a GPE. # C: O(namespace + AML)
pub(crate) fn wake_devices() -> Vec<PrwDevice> {
    aml_routes::with_namespace(|context| {
        let mut scopes = Vec::new();
        let _ = context.namespace.traverse(|path, level| {
            if level.typ == aml::LevelType::Device { scopes.push(path.clone()); }
            Ok(true)
        });
        let mut out = Vec::new();
        for scope in scopes {
            let text = scope.as_string();
            let Some(value) = eval(context, &text, "_PRW") else { continue; };
            let ids = identifiers(context, &text);
            let button = ids.iter().any(|id| matches!(id.as_str(), "PNP0C0D" | "PNP0C0E"));
            if let Some(device) = decode_prw(context, &scope, value, button) { out.push(device); }
        }
        Some(out)
    }).unwrap_or_default()
}

/// Decode every namespace `PowerResource` object once. # C: O(namespace)
pub(crate) fn power_resources() -> Vec<PowerResourceDecl> {
    aml_routes::with_namespace(|context| {
        let mut paths = Vec::new();
        let _ = context.namespace.traverse(|path, level| {
            if level.typ == aml::LevelType::PowerResource { paths.push(path.clone()); }
            Ok(true)
        });
        let mut out = Vec::new();
        for path in paths {
            if let Ok(AmlValue::PowerResource { system_level, resource_order }) =
                context.namespace.get_by_path(&path) {
                out.push(PowerResourceDecl { path: path.as_string(),
                    system_level: *system_level, order: *resource_order });
            }
        }
        Some(out)
    }).unwrap_or_default()
}

fn decode_prw(context: &AmlContext, scope: &AmlName, value: AmlValue,
              button: bool) -> Option<PrwDevice> {
    const S4: u8 = 4;
    const S5: u8 = 5;
    let AmlValue::Package(entries) = value else { return None; };
    if entries.len() < 2 { return None; }
    let (gpe_device, gpe_number) = match entries.first()? {
        AmlValue::Integer(number) => (None, u8::try_from(*number).ok()?),
        AmlValue::Package(gpe) if gpe.len() >= 2 => {
            let AmlValue::Integer(number) = gpe.get(1)? else { return None; };
            let relative = match gpe.first()? {
                AmlValue::Reference(path) => path.clone(),
                AmlValue::String(name) => AmlName::from_str(name).ok()?,
                _ => return None,
            };
            let resolved = context.namespace.search_for_level(&relative, scope).ok()?;
            (Some(resolved.as_string()), u8::try_from(*number).ok()?)
        }
        _ => return None,
    };
    let AmlValue::Integer(state) = entries.get(1)? else { return None; };
    let mut sleep_state = u8::try_from(*state).ok()?;
    if sleep_state > S5 { return None; }
    if button && sleep_state == S5 { sleep_state = S4; }
    let mut power_resources = Vec::new();
    for value in entries.iter().skip(2) {
        let relative = match value {
            AmlValue::Reference(path) => path.clone(),
            AmlValue::String(name) => AmlName::from_str(name).ok()?,
            _ => return None,
        };
        let resolved = context.namespace.search_for_level(&relative, scope).ok()?;
        power_resources.push(resolved.as_string());
    }
    Some(PrwDevice { path: scope.as_string(), gpe_device, gpe_number,
        sleep_state, default_enabled: button, power_resources })
}

/// Absolute namespace paths of every legacy ACPI `Processor` object. Modern
/// firmware may use Device objects for CPUs, but firmware performance objects
/// still commonly live beneath Processor scopes. # C: O(namespace)
pub fn processors() -> Vec<String> {
    aml_routes::with_namespace(|context| {
        let mut processors = Vec::new();
        let _ = context.namespace.traverse(|path, level| {
            if level.typ == aml::LevelType::Processor { processors.push(path.as_string()); }
            Ok(true)
        });
        Some(processors)
    })
    .unwrap_or_default()
}

/// Firmware CPU scopes paired with the ACPI UID MADT uses to identify the
/// same logical processor. A device with a non-numeric `_UID` cannot match a
/// MADT UID and is therefore not a usable CPU policy owner. # C: O(namespace)
pub fn processor_scopes() -> Vec<ProcessorScope> {
    aml_routes::with_namespace(|context| {
        let mut candidates = Vec::new();
        let _ = context.namespace.traverse(|path, level| {
            if matches!(level.typ, aml::LevelType::Processor | aml::LevelType::Device) {
                candidates.push((path.clone(), level.typ));
            }
            Ok(true)
        });
        let mut out = Vec::new();
        for (path, level) in candidates {
            let text = path.as_string();
            let uid = match level {
                aml::LevelType::Processor => match context.namespace.get_by_path(&path).ok()? {
                    AmlValue::Processor { id, .. } => Some(u32::from(*id)),
                    _ => continue,
                },
                aml::LevelType::Device => {
                    if !identifiers(context, &text).iter().any(|id| id == "ACPI0007") { continue; }
                    eval(context, &text, "_UID").and_then(|value| field(context, &value))
                        .and_then(|field| match field {
                            AmlField::Int(uid) => u32::try_from(uid).ok(),
                            AmlField::Text(uid) => uid.parse().ok(),
                        })
                }
                _ => continue,
            };
            if let Some(uid) = uid { out.push(ProcessorScope { path: text, uid }); }
        }
        Some(out)
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
