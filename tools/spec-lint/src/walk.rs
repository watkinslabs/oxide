// minimal recursive walker; no deps.

use std::fs;
use std::path::{Path, PathBuf};

pub fn files_with_ext(root: &Path, ext: &str, skip: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, ext, skip, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, ext: &str, skip: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = match p.file_name().and_then(|n| n.to_str()) { Some(n) => n.to_string(), None => continue };
        if skip.iter().any(|s| *s == name) { continue; }
        if p.is_dir() { walk(&p, ext, skip, out); }
        else if p.extension().and_then(|x| x.to_str()) == Some(ext) { out.push(p); }
    }
}
