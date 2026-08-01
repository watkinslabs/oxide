// Scope: which lines and which crates the kernel-binary code rules apply to.
//
// `docs/07§5` states the rules in terms of the kernel BINARY ("`extern crate
// std` in any kernel binary → fail", `panic="abort"` every kernel profile, "no
// `static mut` outside `#[cfg(test)]`"). Code that no kernel binary contains is
// therefore out of scope, and `code_lint` already acted on half of that: it
// skips `tests/` directories and `tests.rs` for static-mut, unsafe-safety,
// pub-fn-complexity, klog and magic-errno. This module supplies the other half —
// inline `#[cfg(test)]` blocks, and crates reachable only through
// `[dev-dependencies]` — so every rule uses one definition of scope instead of
// each rule carrying its own.
//
// Not a waiver list: nothing here is keyed on a crate name or a path exception.
// Membership is derived from the source (`cfg` attributes) and the manifests
// (dependency kind), so a crate that later becomes a real kernel dependency is
// linted again with no edit here.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::{read, walk};

/// Per-line mask: true where the line sits inside a `#[cfg(test)]` item, or
/// anywhere in a file carrying an inner `#![cfg(test)]`.
///
/// Brace-tracked rather than regex'd: a `#[cfg(test)] mod tests { … }` can be
/// hundreds of lines and can nest.
pub fn cfg_test_mask(lines: &[&str]) -> Vec<bool> {
    if lines.iter().any(|l| is_inner_test_cfg(l.trim())) { return vec![true; lines.len()]; }
    let mut mask = vec![false; lines.len()];
    let mut brace = 0i32;
    let mut open_at: Vec<i32> = Vec::new();
    let mut pending = false;
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if is_test_cfg_attr(t) { pending = true; mask[i] = true; continue; }
        if !open_at.is_empty() { mask[i] = true; }
        for c in l.chars() {
            if c == '{' {
                brace += 1;
                if pending { open_at.push(brace); pending = false; mask[i] = true; }
            } else if c == '}' {
                if open_at.last() == Some(&brace) { open_at.pop(); mask[i] = true; }
                brace -= 1;
            }
        }
        // `#[cfg(test)] use std::foo;` — an item with no block at all.
        if pending && t.ends_with(';') { pending = false; mask[i] = true; }
    }
    mask
}

fn is_test_cfg_attr(t: &str) -> bool {
    t.starts_with("#[cfg(test)]") || t.starts_with("#[cfg(any(test") || t.starts_with("#[cfg(all(test")
}

fn is_inner_test_cfg(t: &str) -> bool {
    t.starts_with("#![cfg(test)]") || t.starts_with("#![cfg(any(test") || t.starts_with("#![cfg(all(test")
}

/// True where the line is excluded from every kernel build by a `cfg`,
/// whether that is `test` or `not(target_os = "oxide-kernel")`.
pub fn non_kernel_mask(lines: &[&str]) -> Vec<bool> {
    let mut mask = cfg_test_mask(lines);
    for (i, l) in lines.iter().enumerate() {
        if !excludes_kernel_target(l.trim()) { continue; }
        mask[i] = true;
        // The attribute governs the next item; mark the following non-blank line.
        for j in i + 1..lines.len() {
            if lines[j].trim().is_empty() { continue; }
            mask[j] = true;
            break;
        }
    }
    mask
}

fn excludes_kernel_target(t: &str) -> bool {
    (t.starts_with("#[cfg(") || t.starts_with("#![cfg("))
        && t.contains("not(target_os")
        && t.contains("oxide-kernel")
}

/// True for `<crate>/src/lib.rs` or `<crate>/src/main.rs` where `<crate>`
/// actually holds a `Cargo.toml`.
///
/// The filename alone is not enough: `crates/kernel/syscalls/src/054_setsockopt/`
/// holds a syscall SLOT module named `main.rs`, which a filename test reads as a
/// crate root and then demands `#![no_std]` from.
pub fn is_crate_root(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name != "lib.rs" && name != "main.rs" { return false; }
    let Some(src) = path.parent() else { return false };
    if src.file_name().and_then(|n| n.to_str()) != Some("src") { return false; }
    src.parent().map(|d| d.join("Cargo.toml").is_file()).unwrap_or(false)
}

/// Roots of module subtrees declared `#[cfg(test)] mod x;` by a parent.
///
/// A test module large enough to need its own directory (`mm-vmm`'s COW-invariant
/// harness, `sysfs`'s bus test harness) carries no `cfg` attribute in its own
/// files — the gate is on the `mod` line in the parent, and it covers every
/// descendant. Without this, such a file reads as ordinary kernel source.
pub fn test_gated_roots(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for sub in &["crates", "kernel"] {
        let d = root.join(sub);
        if !d.is_dir() { continue; }
        for p in walk::files_with_ext(&d, "rs", &["target"]) {
            let Some(dir) = child_mod_dir(&p) else { continue };
            let text = read(&p);
            let mut pending = false;
            for l in text.lines() {
                let t = l.trim();
                if t.is_empty() || t.starts_with("//") { continue; }
                if t.starts_with("#[") { pending = is_test_cfg_attr(t); continue; }
                if pending {
                    if let Some(name) = file_mod_name(t) {
                        // The stem covers `x.rs` and everything under `x/`.
                        out.push(dir.join(name));
                    }
                }
                pending = false;
            }
        }
    }
    out
}

/// Directory holding the child modules `p` declares. `lib.rs`/`main.rs`/`mod.rs`
/// keep their own directory; any other `foo.rs` owns `foo/`.
fn child_mod_dir(p: &Path) -> Option<PathBuf> {
    let name = p.file_name()?.to_str()?;
    let parent = p.parent()?;
    if matches!(name, "lib.rs" | "main.rs" | "mod.rs") { return Some(parent.to_path_buf()); }
    Some(parent.join(p.file_stem()?))
}

/// `mod x;` / `pub mod x;` — semicolon form, i.e. backed by a file or directory.
fn file_mod_name(t: &str) -> Option<String> {
    let rest = t.strip_prefix("pub mod ")
        .or_else(|| t.strip_prefix("pub(crate) mod "))
        .or_else(|| t.strip_prefix("mod "))?;
    let name: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    if name.is_empty() { return None; }
    if !rest[name.len()..].trim_start().starts_with(';') { return None; }
    Some(name)
}

/// True when `path` is `<stem>.rs` or lives under `<stem>/`.
pub fn under_module_root(path: &Path, stem: &Path) -> bool {
    path.starts_with(stem) || path == stem.with_extension("rs")
}

/// Crate directories reachable ONLY through `[dev-dependencies]`.
///
/// Such a crate is linked into test binaries and never into a kernel binary, so
/// `docs/07§5`'s kernel-binary rules do not reach it — `crates/kernel/conformance`
/// is the host-oracle differential harness and is `std` by design.
pub fn dev_only_crate_dirs(root: &Path) -> HashSet<PathBuf> {
    let mut dir_of: HashMap<String, PathBuf> = HashMap::new();
    let mut runtime: HashSet<String> = HashSet::new();
    let mut dev: HashSet<String> = HashSet::new();

    for sub in &["crates", "kernel", "tools"] {
        let d = root.join(sub);
        if !d.is_dir() { continue; }
        for m in walk::files_with_ext(&d, "toml", &["target"]) {
            if m.file_name().and_then(|n| n.to_str()) != Some("Cargo.toml") { continue; }
            let text = read(&m);
            if let Some(n) = package_name(&text) {
                if let Some(p) = m.parent() { dir_of.insert(n, p.to_path_buf()); }
            }
            collect_deps(&text, &mut runtime, &mut dev);
        }
    }
    dev.difference(&runtime)
        .filter_map(|n| dir_of.get(n).cloned())
        .collect()
}

fn package_name(text: &str) -> Option<String> {
    let mut in_pkg = false;
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with('[') { in_pkg = t == "[package]"; continue; }
        if !in_pkg { continue; }
        if let Some(v) = t.strip_prefix("name") {
            let v = v.trim_start().strip_prefix('=')?.trim();
            return Some(v.trim_matches('"').to_string());
        }
    }
    None
}

/// Split each manifest's dependency keys into runtime and dev-only sets.
/// Handles both `[dev-dependencies]` tables and `[dev-dependencies.foo]` stanzas.
fn collect_deps(text: &str, runtime: &mut HashSet<String>, dev: &mut HashSet<String>) {
    let mut kind: Option<bool> = None; // Some(true) = dev
    for l in text.lines() {
        let t = l.trim();
        if let Some(hdr) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let hdr = hdr.trim_start_matches('[').trim_end_matches(']');
            kind = classify_section(hdr);
            // `[dev-dependencies.foo]` names the dependency in the header itself.
            if let (Some(is_dev), Some((sec, name))) = (kind, hdr.rsplit_once('.')) {
                if sec.ends_with("dependencies") {
                    if is_dev { dev.insert(name.to_string()); } else { runtime.insert(name.to_string()); }
                }
            }
            continue;
        }
        let Some(is_dev) = kind else { continue };
        if t.is_empty() || t.starts_with('#') { continue; }
        let Some((key, _)) = t.split_once('=') else { continue };
        let key = key.trim().trim_matches('"');
        if key.is_empty() || key.contains(' ') { continue; }
        // `foo.workspace = true` / `foo.path = ".."` name `foo`.
        let key = key.split('.').next().unwrap_or(key);
        if is_dev { dev.insert(key.to_string()); } else { runtime.insert(key.to_string()); }
    }
}

fn classify_section(hdr: &str) -> Option<bool> {
    let head = hdr.split('.').next().unwrap_or(hdr);
    let tail = hdr.split('.').next_back().unwrap_or(hdr);
    // `[target.'cfg(...)'.dev-dependencies]` puts the kind in the last segment.
    for seg in [head, tail, hdr] {
        if seg == "dev-dependencies" || seg.ends_with(".dev-dependencies") { return Some(true); }
    }
    if hdr.contains("dev-dependencies") { return Some(true); }
    if hdr == "dependencies" || hdr == "build-dependencies" || hdr.ends_with(".dependencies")
        || hdr.ends_with(".build-dependencies") || hdr.starts_with("dependencies.")
        || hdr.starts_with("build-dependencies.")
    { return Some(false); }
    None
}

#[cfg(test)]
mod tests;
