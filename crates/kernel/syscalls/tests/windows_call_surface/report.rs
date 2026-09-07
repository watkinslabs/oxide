//! Audit findings and the markdown surface report the campaign fans out from.

use std::collections::BTreeSet;
use std::fmt::Write as _;

pub struct Win32uCall {
    pub name: Vec<u8>,
    pub ordinal: Option<u64>,
    pub importers: BTreeSet<String>,
    pub admitted: bool,
}
pub struct NtdllCall { pub name: Vec<u8>, pub present: bool }
pub struct UnboundImport { pub importer: String, pub dll: String, pub symbol: String }

pub struct Findings {
    pub root: String,
    pub modules: Vec<String>,
    pub missing: Vec<(String, BTreeSet<String>)>,
    pub win32u: Vec<Win32uCall>,
    pub ntdll: Vec<NtdllCall>,
    pub unbound: Vec<UnboundImport>,
}

/// # C: O(1)
pub fn text(name: &[u8]) -> String { String::from_utf8_lossy(name).into_owned() }

fn joined(importers: &BTreeSet<String>) -> String { importers.iter().cloned().collect::<Vec<_>>().join(", ") }

impl Findings {
    /// # C: O(unclaimed ordinals)
    pub fn unclaimed_win32u(&self) -> Vec<String> {
        self.win32u.iter().filter(|call| !call.admitted).map(|call| match call.ordinal {
            Some(ordinal) => format!("ordinal=0x{ordinal:04x} {} imported by {}", text(&call.name), joined(&call.importers)),
            None => format!("ordinal=UNDECODABLE {} imported by {}", text(&call.name), joined(&call.importers)),
        }).collect()
    }
    /// # C: O(ntdll imports)
    pub fn absent_ntdll(&self) -> Vec<String> {
        self.ntdll.iter().filter(|call| !call.present).map(|call| text(&call.name)).collect()
    }
    /// # C: O(unbound imports)
    pub fn unbound_lines(&self) -> Vec<String> {
        self.unbound.iter().map(|item| format!("{} imports {}!{}", item.importer, item.dll, item.symbol)).collect()
    }

    /// # C: O(closure surface)
    pub fn markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# Windows call surface audit\n");
        let _ = writeln!(out, "Catalog: `{}`\n", self.root);
        let _ = writeln!(out, "| Metric | Count |\n|---|---|");
        let _ = writeln!(out, "| closure modules | {} |", self.modules.len());
        let _ = writeln!(out, "| catalog names not found | {} |", self.missing.len());
        let _ = writeln!(out, "| distinct win32u imports | {} |", self.win32u.len());
        let _ = writeln!(out, "| win32u ordinals unadmitted | {} |", self.win32u.iter().filter(|c| !c.admitted).count());
        let _ = writeln!(out, "| distinct ntdll imports | {} |", self.ntdll.len());
        let _ = writeln!(out, "| ntdll exports absent | {} |", self.ntdll.iter().filter(|c| !c.present).count());
        let _ = writeln!(out, "| imports that do not bind | {} |\n", self.unbound.len());
        let _ = writeln!(out, "## Closure\n\n{}\n", self.modules.join(", "));
        section(&mut out, "Catalog names not found", &self.missing.iter()
            .map(|(name, by)| format!("{name} requested by {}", joined(by))).collect::<Vec<_>>());
        section(&mut out, "Unadmitted win32u ordinals", &self.unclaimed_win32u());
        section(&mut out, "Absent ntdll runtime exports", &self.absent_ntdll());
        section(&mut out, "Imports that do not bind", &self.unbound_lines());
        let _ = writeln!(out, "## Admitted win32u ordinals\n");
        let _ = writeln!(out, "| ordinal | export | importers |\n|---|---|---|");
        for call in self.win32u.iter().filter(|call| call.admitted) {
            let _ = writeln!(out, "| 0x{:04x} | {} | {} |", call.ordinal.unwrap_or_default(), text(&call.name), joined(&call.importers));
        }
        out
    }
}

fn section(out: &mut String, title: &str, lines: &[String]) {
    let _ = writeln!(out, "## {title} ({})\n", lines.len());
    if lines.is_empty() { let _ = writeln!(out, "none\n"); return; }
    for line in lines { let _ = writeln!(out, "- {line}"); }
    let _ = writeln!(out);
}

/// Write the report beside the build artifacts and return its path. # C: O(report bytes)
pub fn emit(findings: &Findings) -> String {
    let dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let _ = std::fs::create_dir_all(&dir);
    let path = format!("{dir}/windows-surface-audit.md");
    let _ = std::fs::write(&path, findings.markdown());
    path
}

impl Findings {
    /// Stable ratchet keys for every open gap in the surface. # C: O(gaps)
    pub fn keys(&self) -> BTreeSet<String> {
        self.win32u_keys().into_iter().chain(self.ntdll_keys()).chain(self.bind_keys()).chain(self.missing_keys()).collect()
    }
    /// # C: O(win32u imports)
    pub fn win32u_keys(&self) -> Vec<String> {
        self.win32u.iter().filter(|call| !call.admitted).map(|call| match call.ordinal {
            Some(ordinal) => format!("win32u 0x{ordinal:04x} {}", text(&call.name)),
            None => format!("win32u undecodable {}", text(&call.name)),
        }).collect()
    }
    /// # C: O(ntdll imports)
    pub fn ntdll_keys(&self) -> Vec<String> {
        self.ntdll.iter().filter(|call| !call.present).map(|call| format!("ntdll {}", text(&call.name))).collect()
    }
    /// # C: O(unbound imports)
    pub fn bind_keys(&self) -> Vec<String> {
        self.unbound.iter().map(|item| format!("bind {} {} {}", item.importer, item.dll, item.symbol)).collect()
    }
    /// # C: O(missing modules)
    pub fn missing_keys(&self) -> Vec<String> { self.missing.iter().map(|(name, _)| format!("missing {name}")).collect() }
}
