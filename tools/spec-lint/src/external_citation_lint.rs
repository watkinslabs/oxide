//! Repository prose must state the verified contract, not point at another
//! implementation tree. This detector feeds the per-unit ratchet, so an old
//! citation cannot hide a new one in a different crate.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{read, Findings};

const RULE: &str = "text/external-source-citation";
const ROOTS: &[&str] = &["crates", "docs", "scratch", "tools", "kernel"];
const TEXT_EXTS: &[&str] = &["c", "h", "md", "py", "rs", "sh", "toml", "tsv", "txt"];
const SOURCE_ROOTS: &[&str] = &[
    "arch/", "block/", "crypto/", "Documentation/", "drivers/", "fs/", "include/",
    "init/", "io_uring/", "ipc/", "kernel/", "lib/", "mm/", "net/", "rust/",
    "security/", "sound/", "virt/",
];

pub fn run(root: &Path, f: &mut Findings) {
    for name in ROOTS {
        collect(&root.join(name), &mut |path| lint_file(root, path, f));
    }
}

fn collect(dir: &Path, visit: &mut impl FnMut(&Path)) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
        if name == "target" || name == ".git" || name == "evidence" { continue; }
        if path.is_dir() { collect(&path, visit); }
        else if path.extension().and_then(|v| v.to_str()).is_some_and(|e| TEXT_EXTS.contains(&e)) {
            visit(&path);
        }
    }
}

fn lint_file(root: &Path, path: &Path, f: &mut Findings) {
    let rel = path.strip_prefix(root).unwrap_or(path);
    if rel == Path::new("scratch/syscall-compliance-matrix.md")
        || rel == Path::new("tools/spec-lint/src/external_citation_lint.rs")
    { return; }
    for (line, text) in read(path).lines().enumerate() {
        if let Some(citation) = first_citation(text) {
            f.push(path, line + 1, RULE,
                format!("state the verified contract; remove external implementation citation `{citation}`"));
        }
    }
}

fn first_citation(line: &str) -> Option<String> {
    for marker in ["../linux-master", "linux-master.zip"] {
        if line.contains(marker) { return Some(marker.into()); }
    }
    for host in ["git.kernel.org/", "lore.kernel.org/", "github.com/torvalds/linux"] {
        if line.contains(host) { return Some(host.into()); }
    }
    for raw in line.split_whitespace() {
        let token = raw.trim_matches(|c: char| matches!(c,
            '`' | '\'' | '"' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'));
        if token.contains("kpi/include/") || token.starts_with("userspace/") { continue; }
        let source = token.split("::").next().unwrap_or(token);
        let source = strip_line_suffix(source);
        if !source_ending(source) { continue; }
        let external = source.strip_prefix("../reference/")
            .or_else(|| source.strip_prefix("../linux-master/"))
            .unwrap_or(source);
        if SOURCE_ROOTS.iter().any(|root| external.starts_with(root))
            || external.starts_with("linux/")
        { return Some(source.into()); }
    }
    None
}

fn strip_line_suffix(token: &str) -> &str {
    let Some((head, tail)) = token.rsplit_once(':') else { return token };
    if tail.split('-').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())) {
        head
    } else { token }
}

fn source_ending(token: &str) -> bool {
    [".c", ".h", ".rst", ".tbl"].iter().any(|suffix| token.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn fixture(files: &[(&str, &str)]) -> (PathBuf, Findings) {
        let root = std::env::temp_dir().join(format!("spec-lint-citation-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        for (name, text) in files {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        let mut findings = Findings::default();
        run(&root, &mut findings);
        (root, findings)
    }

    #[test]
    fn external_tree_paths_and_source_urls_are_citations() {
        let (root, findings) = fixture(&[
            ("crates/kernel/demo/src/lib.rs", "// net/ipv4/tcp.c:42 decides it\n"),
            ("docs/10-demo.md", "See https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git\n"),
            ("tools/note.txt", "compare ../reference/security/demo/hooks.c::hook\n"),
        ]);
        assert_eq!(findings.items().len(), 3);
        assert!(findings.items().iter().all(|f| f.rule == RULE));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_paths_abi_paths_and_the_two_sanctioned_surfaces_are_not_citations() {
        let (root, findings) = fixture(&[
            ("crates/kernel/demo/src/lib.rs", "// crates/kernel/net/src/tcp.rs\n// /proc/sys/net/ipv4/tcp_syncookies\n"),
            ("scratch/done/kpi.md", "kpi/include/linux/slab.h is our compatibility header\n"),
            ("scratch/syscall-compliance-matrix.md", "| net/ipv4/tcp.c:42 |\n"),
        ]);
        assert!(findings.items().is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
