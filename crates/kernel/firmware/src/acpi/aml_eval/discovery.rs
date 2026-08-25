use super::*;

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

pub(crate) fn decode_prw(context: &AmlContext, scope: &AmlName, value: AmlValue,
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
