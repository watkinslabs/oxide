// code/magic-errno per `docs/07§5`: errno / signal / syscall-slot values reach
// code through their typed enum, never a bare integer literal.
//
// The detector keys on the NAME of the thing being assigned, initialised or
// compared — `*_eno`, `*_errno`, `*_signo`, `*_slot`. That name must be the
// operand itself, not merely a substring somewhere on the line; see
// `marker_is_the_operand`.

use std::path::Path;

use crate::Findings;

const MARKERS: &[&str] = &["_eno", "_errno", "_signo", "_slot"];
const TYPED: &[&str] = &["Errno::", "syscall::errno::", "Signum::", "NR_"];

/// # C: O(lines)
pub(super) fn check_magic_errno(path: &Path, lines: &[&str], off_kernel: &[bool], f: &mut Findings) {
    // The Errno enum itself defines the numeric values — exempt.
    if path.to_string_lossy().contains("syscall/src/errno.rs") { return; }
    for (i, l) in lines.iter().enumerate() {
        // Same scope as `code/panic-fmt`: an ABI constant that no kernel binary
        // contains cannot be a wrong ABI constant. Test fixtures build signal
        // and errno values on purpose.
        if off_kernel.get(i).copied().unwrap_or(false) { continue; }
        let t = strip_line_comment(l).trim();
        check_assignment(path, t, i, f);
        check_init_and_compare(path, t, i, f);
    }
}

fn check_assignment(path: &Path, t: &str, i: usize, f: &mut Findings) {
    for suffix in MARKERS {
        let Some(eq) = t.find(suffix) else { continue };
        let after = t[eq + suffix.len()..].trim_start();
        let Some(rhs) = after.strip_prefix('=') else { continue };
        let v = trim_operand(rhs);
        if v == "0" { continue; } // cleared / not-an-error sentinel
        if is_typed(v) { continue; }
        // Identifier rhs (call, field load, named const) is fine.
        if v.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_') { continue; }
        if is_int_literal(v) {
            f.push(path, i + 1, "code/magic-errno",
                format!("`{suffix}` assigned bare integer `{v}` — use Errno::* / Signum::* / NR_* (07§5)"));
        }
    }
}

fn check_init_and_compare(path: &Path, t: &str, i: usize, f: &mut Findings) {
    for marker in ["errno", "signo", "_slot"] {
        if !t.contains(marker) { continue; }
        // `SigInfo { signo: 9 }` carries the same ABI meaning as an assignment.
        if marker != "_slot" {
            if let Some(pos) = t.find(':') {
                if marker_is_the_operand(t, pos, marker) {
                    let v = trim_operand(&t[pos + 1..]);
                    if !is_sentinel_zero(v) && !is_typed(v) && is_int_literal(v) {
                        f.push(path, i + 1, "code/magic-errno",
                            format!("`{marker}` initialized with bare integer `{v}` — use the typed ABI constant (07§5)"));
                    }
                }
            }
        }
        for op in ["==", "!=", ">=", "<=", ">", "<"] {
            let Some(pos) = t.find(op) else { continue };
            if !marker_is_the_operand(t, pos, marker) { continue; }
            let v = trim_operand(&t[pos + op.len()..]);
            if is_sentinel_zero(v) || is_typed(v) { continue; }
            if is_int_literal(v) {
                f.push(path, i + 1, "code/magic-errno",
                    format!("`{marker}` compared against bare integer `{v}` — use the typed ABI constant (07§5)"));
            }
        }
    }
}

/// True when the identifier immediately LEFT of the operator at `pos` ends with
/// `marker`.
///
/// Without this the rule fires on any line that merely mentions the marker
/// anywhere — `fn names_slot(&self, slot: usize) -> bool { self.qname_spec &
/// (1 << slot) != 0 }` matched `_slot` (in the method name) against the `!= 0`
/// of an unrelated bitmask test, and was the rule's only finding in the tree.
fn marker_is_the_operand(t: &str, pos: usize, marker: &str) -> bool {
    let lhs = t[..pos].trim_end();
    let ident: String = lhs.chars().rev()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<Vec<_>>().into_iter().rev().collect();
    if ident.is_empty() { return false; }
    // A call or index left of the operator is an expression, not the field.
    if lhs.ends_with(')') || lhs.ends_with(']') { return false; }
    ident.ends_with(marker)
}

fn is_typed(v: &str) -> bool { TYPED.iter().any(|p| v.starts_with(p)) }

/// `12`, `0x0b`, `1_000` — but not an identifier that happens to be spelled
/// from hex digits. The old form accepted any run of `[0-9a-fx_]`, so the
/// binding name `cx` read as an integer literal.
fn is_int_literal(v: &str) -> bool {
    let Some(first) = v.chars().next() else { return false };
    if !first.is_ascii_digit() { return false; }
    if let Some(hex) = v.strip_prefix("0x") {
        return !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit() || c == '_');
    }
    v.chars().all(|c| c.is_ascii_digit() || c == '_')
}

/// `0` is the not-an-error / no-signal sentinel, not an ABI value. The
/// assignment branch has always allowed it; comparisons carry the same meaning
/// (`errno == 0` is "no error pending"), and 26 of the 28 sites the widened
/// operand scan reached were exactly that test.
fn is_sentinel_zero(v: &str) -> bool { v == "0" }

/// First token after an operator, e.g. `17` in `== 17 { reap(); }`.
///
/// The previous form trimmed trailing punctuation off the WHOLE remainder, so
/// any line with a trailing block or a second struct field kept enough text to
/// stop looking like an integer and the rule silently passed it.
fn trim_operand(s: &str) -> &str {
    let s = s.trim_start();
    let end = s.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(s.len());
    &s[..end]
}

fn strip_line_comment(s: &str) -> &str {
    if let Some(idx) = s.find("//") { &s[..idx] } else { s }
}

#[cfg(test)]
mod tests;
