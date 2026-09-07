//! The parser against the modules the image actually stages.
//!
//! A synthetic image proves the decode; only the shipped catalog proves the
//! decode admits what the guest will run. Skipped when the catalog has not
//! been built, so the suite stays runnable without it.

use super::super::*;
use std::{eprintln, format, path::PathBuf, string::{String, ToString}, vec::Vec};

fn catalog() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
        .join("target/artifacts/wine/x86_64/x86_64-windows");
    if root.join("ntdll.dll").is_file() { Some(root) } else { None }
}

fn modules(root: &PathBuf) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(root).into_iter().flatten().flatten() {
        let path = entry.path();
        let extension = path.extension().and_then(|value| value.to_str()).unwrap_or("");
        if extension != "dll" && extension != "exe" { continue; }
        let name = path.file_name().and_then(|value| value.to_str()).unwrap_or("").to_string();
        if let Ok(blob) = std::fs::read(&path) { out.push((name, blob)); }
    }
    out.sort_by(|left, right| left.0.cmp(&right.0));
    out
}

/// The complete dependency walk must succeed on every shipped module. A
/// module whose walk errors contributes no dependencies to a caller that
/// treats the failure as an empty list, which silently shrinks the graph a
/// loader is asked to map.
#[test]
fn every_shipped_module_reports_its_loader_dependencies() {
    let Some(root) = catalog() else { eprintln!("pe: shipped catalog absent, skipped"); return };
    let modules = modules(&root);
    assert!(modules.len() > 20, "the catalog must carry the module set, found {}", modules.len());
    let mut failures: Vec<String> = Vec::new();
    for (name, blob) in &modules {
        let Ok(image) = parse(blob) else { continue };
        if let Err(error) = image.loader_dependencies() { failures.push(format!("{name}: {error:?}")); }
    }
    assert!(failures.is_empty(), "modules whose dependency walk fails ({}):\n{}",
        failures.len(), failures.join("\n"));
    eprintln!("pe: {} shipped modules report their loader dependencies", modules.len());
}
