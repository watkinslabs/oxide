use std::path::Path;

use crate::Findings;

pub(super) fn check_klog_ungated(path: &Path, lines: &[&str], f: &mut Findings) {
    let mut gated_stack: Vec<bool> = Vec::new();
    let mut pending_attr_gated = false;

    for (i, raw) in lines.iter().enumerate() {
        // Strip line comments + string literals so klog tokens inside text
        // (doc-comments, format strings) don't trigger.
        let line = strip_for_lint(raw);

        // Pending-gate detection BEFORE brace processing so an attribute
        // line that also opens nothing (#[cfg(...)] alone) carries forward.
        // Check the RAW line — the feature literal `"debug-..."` is wiped
        // from the stripped form by quote-stripping.
        if line_has_cfg_debug_attr(raw) {
            pending_attr_gated = true;
        }

        // Single-pass walk: track braces + `;`, and check klog tokens
        // against the gated state AT THE COLUMN where the klog token
        // appears. Required because `debug_<sub>! { klog::...; }` opens
        // and closes the gated scope on a single line — checking gated
        // state only at end-of-line would miss it.
        // `char_indices()` yields (byte_offset, char) so `col` is always a
        // valid char boundary — slicing `&line[col..]` / `&line[..col]` is
        // safe even when the line contains multi-byte UTF-8 (em-dash etc.).
        // (A previous byte-index walk with `bytes[col] as char` panicked
        // mid-`—`.) `prev_char` carries the preceding char for the
        // ident-boundary test.
        let mut prev_char: Option<char> = None;
        for (col, c) in line.char_indices() {
            // klog call detection: try at every ident start.
            if prev_char.map_or(true, |p| !is_ident_char(p)) {
                if let Some(name) = klog_call_at(&line, col) {
                    let gated = gated_stack.last().copied().unwrap_or(false);
                    if !gated {
                        f.push(path, i + 1, "code/klog-ungated",
                            format!("`{}` not under `#[cfg(feature=\"debug-<sub>\")]` or `debug_<sub>!` (`04§4.0`)", name));
                    }
                }
            }
            match c {
                '{' => {
                    let prefix = &line[..col];
                    let macro_gated = ends_with_debug_sub_macro(prefix);
                    let inherit = gated_stack.last().copied().unwrap_or(false);
                    gated_stack.push(macro_gated || pending_attr_gated || inherit);
                    pending_attr_gated = false;
                }
                '}' => { let _ = gated_stack.pop(); }
                ';' => {
                    if gated_stack.is_empty() {
                        pending_attr_gated = false;
                    }
                }
                _ => {}
            }
            prev_char = Some(c);
        }
    }
}

/// If `line[col..]` starts with one of the gated klog::* names, return it.
fn klog_call_at(line: &str, col: usize) -> Option<&'static str> {
    let rest = &line[col..];
    const FN_NAMES: &[(&str, &str)] = &[
        ("klog::write_raw(",     "klog::write_raw"),
        ("klog::write_hex_u64(", "klog::write_hex_u64"),
        ("klog::write_dec_u64(", "klog::write_dec_u64"),
    ];
    const MAC_NAMES: &[(&str, &str)] = &[
        ("klog::kinfo!",  "klog::kinfo!"),
        ("klog::kdebug!", "klog::kdebug!"),
        ("klog::kerror!", "klog::kerror!"),
        ("klog::kfatal!", "klog::kfatal!"),
        ("klog::klog!",   "klog::klog!"),
    ];
    for (pat, name) in FN_NAMES { if rest.starts_with(pat) { return Some(name); } }
    for (pat, name) in MAC_NAMES { if rest.starts_with(pat) { return Some(name); } }
    None
}
fn line_has_cfg_debug_attr(raw_line: &str) -> bool {
    // Attribute forms that gate a debug-* feature:
    //   #[cfg(feature = "debug-<sub>")]
    //   #[cfg(all(..., feature = "debug-<sub>", ...))]
    //   #[cfg(any(feature = "debug-<sub>", ...))]
    //   #[cfg_attr(feature = "debug-<sub>", ...)]
    // Detection: the line carries `#[cfg` (any form) AND the literal
    // `feature = "debug-` substring.
    let t = raw_line.trim_start();
    if !t.starts_with("#[cfg") { return false; }
    raw_line.contains("\"debug-")
}

/// True if `prefix` ends with `debug_<word>!` followed only by whitespace.
fn ends_with_debug_sub_macro(prefix: &str) -> bool {
    let p = prefix.trim_end();
    if !p.ends_with('!') { return false; }
    let p = &p[..p.len() - 1];
    let last_token: &str = p.rsplit(|c: char| !is_ident_char(c)).next().unwrap_or("");
    last_token.starts_with("debug_") && last_token.len() > "debug_".len()
}

fn strip_for_lint(s: &str) -> String {
    let no_cmt = if let Some(idx) = s.find("//") { &s[..idx] } else { s };
    let mut out = String::with_capacity(no_cmt.len());
    let mut in_dq = false;
    let mut esc = false;
    for c in no_cmt.chars() {
        if in_dq {
            out.push(' ');
            if esc { esc = false; }
            else if c == '\\' { esc = true; }
            else if c == '"' { in_dq = false; }
        } else if c == '"' {
            in_dq = true;
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

fn is_ident_char(c: char) -> bool { c.is_ascii_alphanumeric() || c == '_' }
