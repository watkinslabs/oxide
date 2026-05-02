// File-length cap per CLAUDE.md§"File length" + `08§7`. Hard fail at
// `MAX_LINES`; soft target `SOFT_TARGET` is documented but not lint-
// enforced (review-time guideline). Big files split into submodules.

use std::path::{Path, PathBuf};

use crate::{read, walk, Findings};

pub const MAX_LINES: usize = 1000;
#[allow(dead_code)]
pub const SOFT_TARGET: usize = 500;

pub fn run(root: &Path, f: &mut Findings) {
    let mut files: Vec<PathBuf> = Vec::new();
    for sub in &["crates", "kernel", "tools"] {
        let d = root.join(sub);
        if !d.is_dir() { continue; }
        files.extend(walk::files_with_ext(&d, "rs", &["target"]));
    }
    let docs = root.join("docs");
    if docs.is_dir() {
        files.extend(walk::files_with_ext(&docs, "md", &["v2", "v1"]));
    }
    for p in files { check_len(&p, f); }
}

fn check_len(path: &Path, f: &mut Findings) {
    let text = read(path);
    let n = text.lines().count();
    if n > MAX_LINES {
        f.push(
            path,
            n,
            "len/over-cap",
            format!("file is {n} lines; cap is {MAX_LINES}; split into submodules"),
        );
    }
}
