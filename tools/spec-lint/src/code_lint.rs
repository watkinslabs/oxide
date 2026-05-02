// Kernel-crate code rules per docs/07§5 + docs/08§2 + CLAUDE.md§"Code style hard rules".
// Scope: crates/** and kernel/** (kernel crates only). Host crates (tools/, xtask) excluded.

use std::path::{Path, PathBuf};

use crate::{read, walk, Findings};

pub fn run(root: &Path, f: &mut Findings) {
    for sub in &["crates", "kernel"] {
        let d = root.join(sub);
        if !d.is_dir() { continue; }
        let files = walk::files_with_ext(&d, "rs", &["target"]);
        for p in files { lint_file(&p, f); }
    }
}

fn lint_file(path: &PathBuf, f: &mut Findings) {
    let text = read(path);
    let lines: Vec<&str> = text.lines().collect();
    let is_test = is_test_file(path);
    let is_root = is_crate_root(path);

    if is_root { check_no_std(path, &lines, f); }
    check_extern_std(path, &lines, f);
    if !is_test { check_static_mut(path, &text, &lines, f); }
    check_panic_fmt(path, &lines, f);
    if !is_test { check_unsafe_safety(path, &lines, f); }
    if !is_test { check_pub_fn_complexity(path, &lines, f); }
}

fn is_test_file(path: &Path) -> bool {
    if path.components().any(|c| matches!(c.as_os_str().to_str(), Some("tests"))) {
        return true;
    }
    matches!(path.file_name().and_then(|n| n.to_str()), Some("tests.rs"))
}

fn is_crate_root(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some("lib.rs") | Some("main.rs")
    )
}

fn check_no_std(path: &Path, lines: &[&str], f: &mut Findings) {
    if !lines.iter().any(|l| l.trim().starts_with("#![no_std]")) {
        f.push(path, 1, "code/no-std", "kernel crate file missing `#![no_std]`");
    }
}

fn check_extern_std(path: &Path, lines: &[&str], f: &mut Findings) {
    for (i, l) in lines.iter().enumerate() {
        if !l.trim_start().starts_with("extern crate std") { continue; }
        // Permitted only when guarded by `#[cfg(test)]` on the immediately
        // preceding non-blank line. Anywhere else = build fail.
        let mut back = 1;
        let mut guarded = false;
        while i >= back {
            let prev = lines[i - back].trim_start();
            if prev.is_empty() { back += 1; continue; }
            guarded = prev.starts_with("#[cfg(test)]") || prev.starts_with("#[cfg(any(test");
            break;
        }
        if !guarded {
            f.push(path, i + 1, "code/extern-std", "`extern crate std` forbidden in kernel crate");
        }
    }
}

fn check_static_mut(path: &Path, text: &str, lines: &[&str], f: &mut Findings) {
    // crude: skip lines inside `#[cfg(test)]` mod blocks (single-pass tracker).
    let mut depth_test = 0i32;
    let mut brace = 0i32;
    let mut at_test_brace: Vec<i32> = Vec::new();
    let mut prev_attr_test = false;

    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        let attr = t.starts_with("#[cfg(test)]") || t.starts_with("#[cfg(any(test");
        if attr { prev_attr_test = true; continue; }
        // count braces
        for c in l.chars() {
            if c == '{' {
                brace += 1;
                if prev_attr_test { at_test_brace.push(brace); depth_test += 1; prev_attr_test = false; }
            } else if c == '}' {
                if let Some(&b) = at_test_brace.last() {
                    if b == brace { at_test_brace.pop(); depth_test -= 1; }
                }
                brace -= 1;
            }
        }
        if !t.starts_with("//") && !t.starts_with("#") {
            if depth_test == 0 && contains_token(t, "static mut ") {
                f.push(path, i + 1, "code/static-mut",
                    "`static mut` forbidden outside `#[cfg(test)]`");
            }
        }
        if !attr { prev_attr_test = false; }
    }
    let _ = text;
}

fn contains_token(s: &str, needle: &str) -> bool {
    // ignore comments
    if let Some(idx) = s.find("//") { return s[..idx].contains(needle); }
    s.contains(needle)
}

fn check_panic_fmt(path: &Path, lines: &[&str], f: &mut Findings) {
    for (i, l) in lines.iter().enumerate() {
        let t = strip_line_comment(l);
        // crude: panic!(...{...) — format-string call.
        if let Some(idx) = t.find("panic!(") {
            let rest = &t[idx + "panic!(".len()..];
            if rest.contains('{') && rest.contains('}') {
                f.push(path, i + 1, "code/panic-fmt",
                    "use `kassert!(cond, \"literal\")`; no `panic!(fmt)`");
            }
        }
    }
}

fn strip_line_comment(s: &str) -> &str {
    if let Some(idx) = s.find("//") { &s[..idx] } else { s }
}

fn check_unsafe_safety(path: &Path, lines: &[&str], f: &mut Findings) {
    // For each `unsafe {` opening, require a `// SAFETY:` comment within the
    // 3 lines immediately preceding (skipping blanks/attrs), with body ≥30 chars
    // after the marker.
    for (i, l) in lines.iter().enumerate() {
        let t = strip_line_comment(l).trim_start();
        if !t.contains("unsafe ") || !contains_unsafe_block(t) { continue; }
        // Skip `unsafe fn` / `unsafe impl` / `unsafe trait` declarations.
        if t.starts_with("unsafe fn ") || t.starts_with("pub unsafe fn ")
            || t.starts_with("unsafe impl ") || t.starts_with("unsafe trait ")
        { continue; }
        let mut found = false;
        for back in 1..=4 {
            if i < back { break; }
            let prev = lines[i - back].trim_start();
            if prev.is_empty() { continue; }
            if let Some(idx) = prev.find("// SAFETY:") {
                let body = prev[idx + "// SAFETY:".len()..].trim();
                if body.len() >= 30 { found = true; break; }
                else {
                    f.push(path, i - back + 1, "code/safety-short",
                        format!("`// SAFETY:` body too short ({} chars, need ≥30)", body.len()));
                    found = true;
                    break;
                }
            }
            if prev.starts_with("//") || prev.starts_with("#[") { continue; }
            break;
        }
        if !found {
            f.push(path, i + 1, "code/safety-missing",
                "`unsafe { }` without preceding `// SAFETY: <≥30 chars>`");
        }
    }
}

fn contains_unsafe_block(t: &str) -> bool {
    // matches `unsafe {` or `= unsafe {` etc, but not `unsafe fn` etc.
    let mut rest = t;
    while let Some(idx) = rest.find("unsafe") {
        let after = &rest[idx + "unsafe".len()..];
        let next = after.chars().next();
        match next {
            Some(' ') | Some('\t') => {
                let trimmed = after.trim_start();
                if trimmed.starts_with('{') { return true; }
                rest = after;
            }
            _ => { rest = after; }
        }
        if rest.is_empty() { break; }
    }
    false
}

fn check_pub_fn_complexity(path: &Path, lines: &[&str], f: &mut Findings) {
    // Every `pub fn` (in kernel crate) needs a `# C:` doc-comment within the
    // preceding doc-comment block (`///` lines).
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim_start();
        if !is_pub_fn(t) { continue; }
        let mut found = false;
        let mut back = 1;
        while i >= back {
            let prev = lines[i - back].trim_start();
            if prev.is_empty() { back += 1; continue; }
            if prev.starts_with("#[") { back += 1; continue; }
            if !prev.starts_with("///") { break; }
            if prev.contains("# C:") { found = true; break; }
            back += 1;
        }
        if !found {
            f.push(path, i + 1, "code/pub-fn-complexity",
                "`pub fn` missing `# C: <expr>` doc-comment marker");
        }
    }
}

fn is_pub_fn(t: &str) -> bool {
    t.starts_with("pub fn ")
        || t.starts_with("pub(crate) fn ")
        || t.starts_with("pub async fn ")
        || t.starts_with("pub unsafe fn ")
        || t.starts_with("pub const fn ")
}
