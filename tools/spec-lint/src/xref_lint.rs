// Cross-reference resolver: every `<doc>§<sec>` must resolve to a section in the cited doc.
// Pattern: doc id is `\d{2}[a-z]?`, section id is `\d+(\.\d+)*[a-z]?(\.\d+)*` or single uppercase letter (charters).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::{read, walk, Findings};

pub fn run(root: &Path, f: &mut Findings) {
    let docs = root.join("docs");
    if !docs.is_dir() { return; }
    let files = walk::files_with_ext(&docs, "md", &["v2", "v1"]);

    let doc_map = build_doc_map(&files);
    let section_map = build_section_map(&files);

    for p in &files {
        check_refs(p, &doc_map, &section_map, f);
    }
}

fn doc_id_of(stem: &str) -> Option<String> {
    // `07-toolchain-and-targets` -> `07`; `29a-userspace-platform` -> `29a`
    let bytes = stem.as_bytes();
    if bytes.len() < 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() { return None; }
    let mut id = String::with_capacity(3);
    id.push(bytes[0] as char);
    id.push(bytes[1] as char);
    if bytes.len() >= 3 && bytes[2].is_ascii_lowercase() { id.push(bytes[2] as char); }
    Some(id)
}

fn build_doc_map(files: &[PathBuf]) -> BTreeMap<String, PathBuf> {
    let mut m = BTreeMap::new();
    for p in files {
        let stem = match p.file_stem().and_then(|s| s.to_str()) { Some(s) => s, None => continue };
        if let Some(id) = doc_id_of(stem) { m.insert(id, p.clone()); }
    }
    m
}

fn build_section_map(files: &[PathBuf]) -> BTreeMap<String, BTreeSet<String>> {
    let mut m: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for p in files {
        let stem = match p.file_stem().and_then(|s| s.to_str()) { Some(s) => s, None => continue };
        let id = match doc_id_of(stem) { Some(i) => i, None => continue };
        let text = read(p);
        let mut set = BTreeSet::new();
        let mut in_code = false;
        for line in text.lines() {
            let t = line.trim_start();
            if t.starts_with("```") { in_code = !in_code; continue; }
            if in_code { continue; }
            // ## <id> ... or ### <id> ... etc.
            let body = if let Some(rest) = t.strip_prefix("## ") { rest }
                else if let Some(rest) = t.strip_prefix("### ") { rest }
                else if let Some(rest) = t.strip_prefix("#### ") { rest }
                else { continue };
            let first = body.split_whitespace().next().unwrap_or("");
            if first.is_empty() { continue; }
            let trimmed = first.trim_end_matches('.');
            if trimmed.is_empty() { continue; }
            set.insert(trimmed.to_string());
            // For dotted IDs like `1.2.3`, also register every prefix so `02§1` resolves
            // when only `## 1.2` exists. Only register the prefix if the dotted form is numeric.
            if trimmed.contains('.') {
                let mut parts = trimmed.split('.');
                let mut acc = String::new();
                for part in &mut parts {
                    if !acc.is_empty() { acc.push('.'); }
                    acc.push_str(part);
                    set.insert(acc.clone());
                }
            }
        }
        m.insert(id, set);
    }
    m
}

fn check_refs(
    path: &Path,
    doc_map: &BTreeMap<String, PathBuf>,
    section_map: &BTreeMap<String, BTreeSet<String>>,
    f: &mut Findings,
) {
    let text = read(path);
    let mut in_code = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("```") { in_code = !in_code; continue; }
        if in_code { continue; }
        // Strip double-quoted spans so literal placeholders like "violates `06§X`" don't trip xref.
        // Backticks are normal carriers of refs (e.g., `02§1`); keep them.
        let scan_line = strip_double_quotes(line);
        for (doc, sec) in scan_refs(&scan_line) {
            if !doc_map.contains_key(&doc) {
                f.push(path, i + 1, "xref/doc",
                    format!("`{doc}§{sec}` -> doc `{doc}` not found"));
                continue;
            }
            let sections = match section_map.get(&doc) { Some(s) => s, None => continue };
            // Try the literal section ID and its prefixes.
            let mut hit = sections.contains(&sec);
            if !hit {
                // Permit `<doc>§<N>` when only `## N <Title>` form exists (we already store first token).
                // Also permit case-insensitive match for charter letter sections.
                let upper = sec.to_uppercase();
                hit = sections.contains(&upper);
            }
            if !hit {
                f.push(path, i + 1, "xref/sec",
                    format!("`{doc}§{sec}` -> section `{sec}` not found in `{doc}`"));
            }
        }
    }
}

fn strip_double_quotes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_dq = false;
    for c in s.chars() {
        match c {
            '"' => { in_dq = !in_dq; out.push(' '); }
            _ if in_dq => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

fn scan_refs(line: &str) -> Vec<(String, String)> {
    // Match: 2-digit or 2-digit+lowercase letter, then `§`, then [0-9A-Za-z.]+
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 < bytes.len() {
        if bytes[i].is_ascii_digit() && bytes[i + 1].is_ascii_digit() {
            let mut j = i + 2;
            if j < bytes.len() && (bytes[j] as char).is_ascii_lowercase() { j += 1; }
            // expect `§` (UTF-8: 0xC2 0xA7)
            if j + 1 < bytes.len() && bytes[j] == 0xC2 && bytes[j + 1] == 0xA7 {
                let doc = std::str::from_utf8(&bytes[i..j]).unwrap().to_string();
                let mut k = j + 2;
                while k < bytes.len() {
                    let c = bytes[k];
                    if c.is_ascii_alphanumeric() || c == b'.' { k += 1; } else { break; }
                }
                if k > j + 2 {
                    let sec = std::str::from_utf8(&bytes[j + 2..k]).unwrap()
                        .trim_end_matches('.')
                        .to_string();
                    if !sec.is_empty() {
                        // Boundary check on left: previous byte must not be alnum (avoid e.g. matching 1234§5 partial)
                        let lhs_ok = i == 0 || !(bytes[i - 1] as char).is_ascii_alphanumeric();
                        if lhs_ok { out.push((doc, sec)); }
                    }
                    i = k;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}
