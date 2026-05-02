// MANIFEST.md ↔ filesystem ↔ per-file Status: line.

use std::collections::BTreeMap;
use std::path::Path;

use crate::{read, walk, Findings};

pub fn run(root: &Path, f: &mut Findings) {
    let docs = root.join("docs");
    let manifest_path = docs.join("MANIFEST.md");
    if !manifest_path.is_file() {
        f.push(&manifest_path, 0, "manifest/missing", "docs/MANIFEST.md not found");
        return;
    }
    let manifest = read(&manifest_path);
    let entries = parse_manifest(&manifest);

    // 1. Every doc file present in MANIFEST.
    let on_disk = walk::files_with_ext(&docs, "md", &["v2", "v1"]);
    for p in &on_disk {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "MANIFEST.md" { continue; }
        if !entries.contains_key(name) {
            f.push(p, 0, "manifest/missing-row", format!("file `{name}` not listed in MANIFEST.md"));
        }
    }

    // 2. Every MANIFEST entry exists on disk + Status matches.
    for (name, row) in &entries {
        let p = docs.join(name);
        if !p.is_file() {
            f.push(&manifest_path, row.line, "manifest/dangling",
                format!("MANIFEST entry `{name}` has no file"));
            continue;
        }
        let body = read(&p);
        // doc_lint owns "missing/malformed status line"; manifest_lint only checks
        // mismatch when both sides are well-formed.
        if let Some(file_status) = extract_status(&body) {
            if file_status != row.status {
                f.push(&p, 1, "manifest/status-mismatch",
                    format!("file says `{}`, MANIFEST says `{}`", file_status, row.status));
            }
        }
    }
}

pub struct Row {
    pub status: String,
    pub line: usize,
}

fn parse_manifest(text: &str) -> BTreeMap<String, Row> {
    let mut out = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        // table rows: `| `name.md` | DRAFT | ... |`
        let t = line.trim();
        if !t.starts_with('|') { continue; }
        let cells: Vec<&str> = t.split('|').map(|s| s.trim()).collect();
        if cells.len() < 4 { continue; }
        let file_cell = cells[1];
        let status_cell = cells[2];
        // file_cell form: `name.md` (backticked) — strip backticks
        let name = file_cell.trim_matches('`');
        if !name.ends_with(".md") { continue; }
        // skip header row
        if status_cell == "Status" { continue; }
        // must be DRAFT or FROZEN
        let status_word = status_cell.split_whitespace().next().unwrap_or("");
        if status_word != "DRAFT" && status_word != "FROZEN" { continue; }
        out.insert(name.to_string(), Row { status: status_word.to_string(), line: i + 1 });
    }
    out
}

fn extract_status(body: &str) -> Option<String> {
    let mut saw_h1 = false;
    for line in body.lines() {
        let t = line.trim();
        if t.is_empty() { continue; }
        if !saw_h1 {
            if t.starts_with("# ") { saw_h1 = true; }
            continue;
        }
        if t.starts_with("DRAFT ") { return Some("DRAFT".into()); }
        if t.starts_with("FROZEN ") { return Some("FROZEN".into()); }
        return None;
    }
    None
}
