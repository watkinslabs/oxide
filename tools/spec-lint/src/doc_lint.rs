// Doc rules per docs/08§6 + docs/02 + CLAUDE.md§"Doc style hard rules".

use std::path::{Path, PathBuf};

use crate::{is_charter, read, walk, Findings};

const FORBIDDEN: &[&str] = &[
    "This document defines",
    "Note that",
    "In this section we will",
    "It should be noted",
    " simply ",
    " really ",
    " actually ",
    " very ",
    " extremely ",
    " quite ",
    " rather ",
    " fairly ",
    " somewhat ",
    " essentially ",
    " basically ",
    " fundamentally ",
];

pub fn run(root: &Path, f: &mut Findings) {
    let docs = root.join("docs");
    if !docs.is_dir() { return; }
    let files = walk::files_with_ext(&docs, "md", &["v2", "v1"]);
    for p in files {
        lint_file(&p, f);
    }
}

fn lint_file(path: &PathBuf, f: &mut Findings) {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let stem = path.file_stem().and_then(|n| n.to_str()).unwrap_or("");
    let text = read(path);

    // MANIFEST + non-spec docs skip status/section checks.
    let is_spec = name != "MANIFEST.md";
    let charter = is_charter(stem);

    if is_spec {
        check_status_line(path, &text, f);
        check_headers(path, &text, charter, f);
    }
    check_forbidden(path, &text, f);
}

fn check_status_line(path: &Path, text: &str, f: &mut Findings) {
    // First non-blank line after H1 must start with `DRAFT ` or `FROZEN ` and contain a date + `Dep:`.
    let mut lines = text.lines().enumerate();
    let mut saw_h1 = false;
    for (i, line) in &mut lines {
        let t = line.trim();
        if t.is_empty() { continue; }
        if !saw_h1 {
            if !t.starts_with("# ") {
                f.push(path, i + 1, "doc/h1", "first non-blank line must be `# <title>`");
                return;
            }
            saw_h1 = true;
            continue;
        }
        let starts = t.starts_with("DRAFT ") || t.starts_with("FROZEN ");
        let dated = has_iso_date(t);
        let living = t.starts_with("DRAFT (living)") || t.starts_with("FROZEN (living)");
        let has_dep = t.contains("Dep:");
        if !(starts && has_dep && (dated || living)) {
            f.push(path, i + 1, "doc/status",
                "expected `DRAFT|FROZEN <YYYY-MM-DD>. Dep:...` or `DRAFT (living). Dep:...`");
        }
        return;
    }
    f.push(path, 1, "doc/status", "missing status line");
}

fn has_iso_date(s: &str) -> bool {
    // Look for YYYY-MM-DD anywhere.
    let b = s.as_bytes();
    if b.len() < 10 { return false; }
    for i in 0..=b.len() - 10 {
        let w = &b[i..i + 10];
        if w[0].is_ascii_digit() && w[1].is_ascii_digit() && w[2].is_ascii_digit() && w[3].is_ascii_digit()
            && w[4] == b'-'
            && w[5].is_ascii_digit() && w[6].is_ascii_digit()
            && w[7] == b'-'
            && w[8].is_ascii_digit() && w[9].is_ascii_digit()
        { return true; }
    }
    false
}

fn check_headers(path: &Path, text: &str, charter: bool, f: &mut Findings) {
    // `## N` (number, optional title only on charters).
    // Skip code blocks.
    let mut in_code = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("```") { in_code = !in_code; continue; }
        if in_code { continue; }
        if !t.starts_with("## ") { continue; }
        let body = &t[3..];
        let first = body.split_whitespace().next().unwrap_or("");
        if first.is_empty() {
            f.push(path, i + 1, "doc/header-num", "`## N` required");
            continue;
        }
        // Ban dotted-trailing form `## N. Title` per 08§1.3 negative example.
        if first.ends_with('.') {
            f.push(path, i + 1, "doc/header-dot",
                format!("dotted header form forbidden: `## {body}` (drop trailing `.`)"));
            continue;
        }
        // Charters permit any section ID (numeric, alpha, dotted-num). Subsystem docs require numeric.
        if !charter && !is_dotted_num(first) {
            f.push(path, i + 1, "doc/header-num",
                format!("non-charter section ID must be numeric: `## {first}`"));
        }
    }
}

fn is_dotted_num(s: &str) -> bool {
    // `1`, `1.2`, `1.2.3`, `14a`, `14a.1` — digits with `.` separators and
    // optional single-lowercase-letter suffix on a numeric component.
    if s.is_empty() { return false; }
    let mut last_was_digit = false;
    let mut prev_dot = true;
    let mut had_alpha = false;
    for c in s.chars() {
        if c == '.' {
            if prev_dot || !last_was_digit && !had_alpha { return false; }
            prev_dot = true; last_was_digit = false; had_alpha = false;
        } else if c.is_ascii_digit() {
            if had_alpha { return false; }
            prev_dot = false; last_was_digit = true;
        } else if c.is_ascii_lowercase() {
            if !last_was_digit || had_alpha { return false; }
            had_alpha = true;
        } else { return false; }
    }
    !prev_dot
}

fn check_forbidden(path: &Path, text: &str, f: &mut Findings) {
    let mut in_code = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("```") { in_code = !in_code; continue; }
        if in_code { continue; }
        // Strip quoted spans (`"..."` and backtick code) so docs that QUOTE forbidden phrases
        // as examples don't trip the lint.
        let stripped = strip_quoted(line);
        let padded = format!(" {stripped} ");
        let lower = padded.to_lowercase();
        for pat in FORBIDDEN {
            let needle = pat.to_lowercase();
            if lower.contains(&needle) {
                f.push(path, i + 1, "doc/forbidden",
                    format!("forbidden phrase `{}`", pat.trim()));
            }
        }
    }
}

fn strip_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut in_dq = false;
    let mut in_bt = false;
    while let Some(c) = chars.next() {
        match c {
            '"' if !in_bt => { in_dq = !in_dq; out.push(' '); }
            '`' if !in_dq => { in_bt = !in_bt; out.push(' '); }
            _ if in_dq || in_bt => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}
