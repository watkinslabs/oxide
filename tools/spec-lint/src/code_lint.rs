// Kernel-crate code rules per docs/07§5 + docs/08§2 + CLAUDE.md§"Code style hard rules".
// Scope: crates/** and kernel/** (kernel crates only). Host crates (tools/, xtask) excluded.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::{read, walk, Findings};

mod klog;
mod magic_errno;
mod scope;
use klog::check_klog_ungated;
use magic_errno::check_magic_errno;

pub fn run(root: &Path, f: &mut Findings) {
    let ext_gated = build_externally_gated_map(root);
    let dev_only = scope::dev_only_crate_dirs(root);
    let test_roots = scope::test_gated_roots(root);
    for sub in &["crates", "kernel"] {
        let d = root.join(sub);
        if !d.is_dir() { continue; }
        let files = walk::files_with_ext(&d, "rs", &["target"]);
        for p in files {
            // A crate no kernel binary links cannot break a kernel-binary rule.
            if dev_only.iter().any(|c| p.starts_with(c)) { continue; }
            let gated = test_roots.iter().any(|s| scope::under_module_root(&p, s));
            lint_file(&p, gated, &ext_gated, f);
        }
    }
}

/// For each kernel-crate root file (lib.rs/main.rs), collect submodule
/// files that are gated externally by a parent `#[cfg(feature = "debug-...")]`
/// attribute on the `mod foo;` declaration. Per `kernel/src/lib.rs`:
///   #[cfg(all(target_os="oxide-kernel", feature = "debug-sched"))]
///   pub mod ksched;
/// → `kernel/src/ksched.rs` is implicitly under `debug-sched`; klog calls
/// inside it are gated and should not flag `code/klog-ungated`.
fn build_externally_gated_map(root: &Path) -> HashSet<PathBuf> {
    let mut out = HashSet::new();
    for sub in &["crates", "kernel"] {
        let d = root.join(sub);
        if !d.is_dir() { continue; }
        let roots = walk::files_with_ext(&d, "rs", &["target"]);
        for p in roots {
            let n = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if n != "lib.rs" && n != "main.rs" && n != "mod.rs" { continue; }
            let parent = match p.parent() { Some(d) => d, None => continue };
            let text = read(&p);
            scan_mod_decls(&text, parent, &mut out);
        }
    }
    out
}

fn scan_mod_decls(text: &str, dir: &Path, out: &mut HashSet<PathBuf>) {
    let lines: Vec<&str> = text.lines().collect();
    let mut pending = false;
    for l in lines.iter() {
        let t = l.trim_start();
        if t.starts_with("#[cfg") && l.contains("\"debug-") {
            pending = true;
            continue;
        }
        if t.is_empty() || t.starts_with("//") || t.starts_with("#[") {
            continue;
        }
        if pending {
            // Look for `pub mod foo;` or `mod foo;` (semicolon = file-backed).
            if let Some(name) = parse_file_mod(t) {
                let f1 = dir.join(format!("{name}.rs"));
                let f2 = dir.join(&name).join("mod.rs");
                if f1.exists() { out.insert(f1); }
                if f2.exists() { out.insert(f2); }
            }
        }
        pending = false;
    }
}

fn parse_file_mod(t: &str) -> Option<String> {
    let rest = if let Some(r) = t.strip_prefix("pub mod ") { r }
        else if let Some(r) = t.strip_prefix("pub(crate) mod ") { r }
        else if let Some(r) = t.strip_prefix("mod ") { r }
        else { return None; };
    let name: String = rest.chars().take_while(|c| is_ident_char(*c)).collect();
    if name.is_empty() { return None; }
    // file-backed module ends with `;`; inline `mod foo { ... }` does not.
    if !rest[name.len()..].trim_start().starts_with(';') { return None; }
    Some(name)
}

fn lint_file(path: &PathBuf, test_gated: bool, ext_gated: &HashSet<PathBuf>, f: &mut Findings) {
    let text = read(path);
    let lines: Vec<&str> = text.lines().collect();
    let is_test = test_gated || is_test_file(path);
    let is_root = scope::is_crate_root(path);
    // Lines no kernel build compiles: `#[cfg(test)]` items and
    // `#[cfg(not(target_os = "oxide-kernel"))]` items. `docs/07§5` scopes these
    // rules to the kernel BINARY, and the whole-file `tests/` skip below is the
    // same judgement already applied at path granularity.
    let off_kernel: Vec<bool> = if is_test { vec![true; lines.len()] } else { scope::non_kernel_mask(&lines) };

    if is_root { check_no_std(path, &lines, f); }
    check_extern_std(path, &lines, &off_kernel, f);
    check_driver_user_deref(path, &lines, f);
    if !is_test { check_static_mut(path, &text, &lines, f); }
    check_panic_fmt(path, &lines, &off_kernel, f);
    if !is_test { check_unsafe_safety(path, &lines, f); }
    if !is_test { check_pub_fn_complexity(path, &lines, f); }
    if !is_test && !is_klog_crate(path) && !ext_gated.contains(path) {
        check_klog_ungated(path, &lines, f);
    }
    if !is_test { check_no_dyn_hal(path, &lines, f); }
    if !is_test { check_magic_errno(path, &lines, &off_kernel, f); }
}

fn is_klog_crate(path: &Path) -> bool {
    // The klog crate IS the logger; its internals own write_raw / set_byte_sink
    // / kinfo! definitions and call them in their own implementation. Gating
    // those would be circular.
    path.components().any(|c| c.as_os_str() == "klog")
}

fn is_test_file(path: &Path) -> bool {
    if path.components().any(|c| matches!(c.as_os_str().to_str(), Some("tests"))) {
        return true;
    }
    matches!(path.file_name().and_then(|n| n.to_str()), Some("tests.rs"))
}

fn check_no_std(path: &Path, lines: &[&str], f: &mut Findings) {
    let ok = lines.iter().any(|l| {
        let t = l.trim();
        t.starts_with("#![no_std]")
            || (t.starts_with("#![cfg_attr(") && t.contains("no_std"))
    });
    if !ok {
        f.push(path, 1, "code/no-std", "kernel crate file missing `#![no_std]`");
    }
}

/// `docs/07§5`: "`extern crate std` in any kernel binary → fail". `off_kernel`
/// carries the cfg scope, so an `extern crate std` INSIDE a `#[cfg(test)] mod
/// tests { … }` block or under `#[cfg(not(target_os = "oxide-kernel"))]` passes
/// — no kernel binary contains it. The old check only looked at the single
/// preceding line, so the common form (the declaration a few lines into a test
/// module) read as unguarded: 16 of its 18 findings were that false positive.
fn check_extern_std(path: &Path, lines: &[&str], off_kernel: &[bool], f: &mut Findings) {
    for (i, l) in lines.iter().enumerate() {
        if !l.trim_start().starts_with("extern crate std") { continue; }
        if off_kernel.get(i).copied().unwrap_or(false) { continue; }
        f.push(path, i + 1, "code/extern-std", "`extern crate std` forbidden in kernel crate");
    }
}

/// Driver user-ABI modules transfer through `uaccess`; raw volatile operations
/// belong to MMIO/DMA modules. Keeping those domains in separate source files
/// makes a raw ioctl-pointer dereference mechanically distinguishable from a
/// legitimate device access without a path allowlist that can drift.
fn check_driver_user_deref(path: &Path, lines: &[&str], f: &mut Findings) {
    let p = path.to_string_lossy().replace('\\', "/");
    if !p.contains("crates/drivers/") { return; }
    let user_abi = lines.iter().any(|l| strip_for_lint(l).contains("arg: u64"));
    if !user_abi { return; }
    for (i, l) in lines.iter().enumerate() {
        let code = strip_for_lint(l);
        if code.contains("read_volatile") || code.contains("write_volatile") {
            f.push(path, i + 1, "code/driver-user-deref",
                "raw volatile operation in a driver user-ABI module — transfer user memory through `uaccess` and keep MMIO/DMA in its owning module");
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
            if depth_test == 0 && is_static_mut_item(t) {
                f.push(path, i + 1, "code/static-mut",
                    "`static mut` forbidden outside `#[cfg(test)]`");
            }
        }
        if !attr { prev_attr_test = false; }
    }
    let _ = text;
}

// True only for a `static mut` ITEM declaration, not a `&'static mut T`
// reference type (the lifetime form is preceded by `'`).
fn is_static_mut_item(s: &str) -> bool {
    let code = match s.find("//") { Some(idx) => &s[..idx], None => s };
    let mut from = 0;
    while let Some(rel) = code[from..].find("static mut ") {
        let at = from + rel;
        // `&'static mut` → the byte before `static` is `'`.
        if at == 0 || code.as_bytes()[at - 1] != b'\'' { return true; }
        from = at + 1;
    }
    false
}

/// `docs/07§5`: `kassert!(cond, "literal")` only, no `panic!(fmt)` — the rule
/// exists because kernel profiles are `panic="abort"` with statically interned
/// panic strings. Host test code has neither property, and every `assert_eq!`
/// in the tree already expands to exactly the formatted panic this forbids, so
/// enforcing it there flagged 110 of 113 sites for a rule the surrounding
/// `assert!` macros break on the adjacent line.
fn check_panic_fmt(path: &Path, lines: &[&str], off_kernel: &[bool], f: &mut Findings) {
    for (i, l) in lines.iter().enumerate() {
        if off_kernel.get(i).copied().unwrap_or(false) { continue; }
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
    // For each `unsafe {` opening, require a `// SAFETY:` comment in its
    // immediately preceding comment/attribute block, with body ≥30 chars.
    for (i, l) in lines.iter().enumerate() {
        let t = strip_line_comment(l).trim_start();
        if !t.contains("unsafe ") || !contains_unsafe_block(t) { continue; }
        // Skip `unsafe fn` / `unsafe impl` / `unsafe trait` declarations.
        if t.starts_with("unsafe fn ") || t.starts_with("pub unsafe fn ")
            || t.starts_with("unsafe impl ") || t.starts_with("unsafe trait ")
        { continue; }
        let mut found = false;
        let mut back = 1usize;
        while i >= back {
            let prev = lines[i - back].trim_start();
            if prev.is_empty() { back += 1; continue; }
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
            if prev.starts_with("//") || prev.starts_with("#[") {
                back += 1;
                continue;
            }
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

// ---------------------------------------------------------------------------
// code/no-dyn-hal: forbid `dyn` on HAL traits per `07§5`. Spec lists
// the HAL traits whose dispatch must be monomorphized: MmuOps,
// CpuOps, Context, IrqOps, TimerOps. Any source-level
// `dyn (MmuOps|CpuOps|Context|IrqOps|TimerOps)` token is flagged
// before the post-build vtable grep can catch it.
//
// Detection is a literal substring match on the stripped line
// (string + line-comment text removed) so `dyn` inside docs or
// quoted examples doesn't trigger.
// ---------------------------------------------------------------------------

fn check_no_dyn_hal(path: &Path, lines: &[&str], f: &mut Findings) {
    const HAL_TRAITS: &[&str] = &["MmuOps", "CpuOps", "Context", "IrqOps", "TimerOps"];
    for (i, raw) in lines.iter().enumerate() {
        let line = strip_for_lint(raw);
        if !line.contains("dyn ") { continue; }
        for t in HAL_TRAITS {
            // Match `dyn <Trait>` with a trailing non-ident character
            // (or end-of-line) so `dyn IrqOps2` (a different name)
            // doesn't false-fire. `dyn IrqOps + Send` etc. is still
            // forbidden — `+` follows the trait name.
            let needle = format!("dyn {}", t);
            if let Some(pos) = line.find(&needle) {
                let after_idx = pos + needle.len();
                let after_byte = line.as_bytes().get(after_idx).copied().unwrap_or(b' ');
                let after_c = after_byte as char;
                if after_c == '_' || after_c.is_ascii_alphanumeric() {
                    continue; // `dyn FooOps2` etc. — different trait
                }
                f.push(path, i + 1, "code/no-dyn-hal",
                    format!("`dyn {}` forbidden — HAL traits must be monomorphized (07§5)", t));
            }
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

/// Strip `// ...` comments + double-quoted/backtick spans (replace with ' ').
/// Block comments `/* */` are not stripped (rare in this codebase; future
/// extension if needed). r-string forms `r"..."` / `r#"..."#` are handled
/// crudely as plain `"..."` which is fine for lint purposes.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn unsafe_findings(lines: &[&str]) -> Findings {
        let mut f = Findings::default();
        check_unsafe_safety(Path::new("fixture.rs"), lines, &mut f);
        f
    }

    fn driver_deref_findings(path: &str, lines: &[&str]) -> Findings {
        let mut f = Findings::default();
        check_driver_user_deref(Path::new(path), lines, &mut f);
        f
    }

    #[test]
    fn driver_ioctl_raw_volatile_is_rejected_even_through_a_local_pointer() {
        let f = driver_deref_findings("crates/drivers/example/src/ioctl.rs", &[
            "pub fn handle_ioctl(arg: u64) -> i64 {",
            "    let ptr = arg as *const u32;",
            "    unsafe { core::ptr::read_volatile(ptr) as i64 }",
            "}",
        ]);
        assert_eq!(f.items().len(), 1);
        assert_eq!(f.items()[0].rule, "code/driver-user-deref");
    }

    #[test]
    fn driver_mmio_without_a_user_argument_remains_legal() {
        let f = driver_deref_findings("crates/drivers/example/src/mmio.rs", &[
            "fn read_reg(base: u64) -> u32 {",
            "    unsafe { core::ptr::read_volatile(base as *const u32) }",
            "}",
        ]);
        assert!(f.items().is_empty());
    }

    #[test]
    fn driver_usercopy_and_pattern_names_in_text_remain_legal() {
        let f = driver_deref_findings("crates/drivers/example/src/ioctl.rs", &[
            "// read_volatile is forbidden here.",
            "pub fn handle_ioctl(arg: u64) -> Result<(), Errno> {",
            "    uaccess::copy_to_user(arg, &[0])",
            "}",
            "assert!(!source.contains(\"write_volatile\"));",
        ]);
        assert!(f.items().is_empty());
    }

    #[test]
    fn safety_comment_can_head_a_longer_comment_block() {
        let f = unsafe_findings(&[
            "// SAFETY: this comment establishes the pointer provenance and exclusive access.",
            "// Rationale remains before the operation so reviewers see it in source order.",
            "// The operation cannot race because the caller retains the unique owner.",
            "#[allow(clippy::needless_borrow)]",
            "unsafe { core::ptr::read(ptr); }",
        ]);
        assert!(f.items().is_empty());
    }

    #[test]
    fn safety_comment_does_not_cross_a_code_boundary() {
        let f = unsafe_findings(&[
            "// SAFETY: this comment establishes the pointer provenance and exclusive access.",
            "let ptr = raw;",
            "unsafe { core::ptr::read(ptr); }",
        ]);
        assert_eq!(f.items().len(), 1);
        assert_eq!(f.items()[0].rule, "code/safety-missing");
    }

    #[test]
    fn short_safety_comment_remains_a_distinct_finding() {
        let f = unsafe_findings(&[
            "// SAFETY: trusted pointer",
            "// The detailed rationale intentionally follows the claim.",
            "unsafe { core::ptr::read(ptr); }",
        ]);
        assert_eq!(f.items().len(), 1);
        assert_eq!(f.items()[0].rule, "code/safety-short");
    }
}
