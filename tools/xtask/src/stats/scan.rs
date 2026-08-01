// Tree scanning + git interrogation. Everything here answers "what files exist
// and how big are they"; kernel-shaped questions live in `kernel.rs`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{FileStat, HistoryStats, Totals};

pub(super) fn repo_root() -> Result<PathBuf, u8> {
    let out = run_git(Path::new("."), &["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(out.trim()))
}

fn run_git(dir: &Path, args: &[&str]) -> Result<String, u8> {
    let out = Command::new("git").current_dir(dir).args(args).output().map_err(|e| {
        eprintln!("xtask stats: failed to run git {}: {e}", args.join(" "));
        1u8
    })?;
    if !out.status.success() {
        eprintln!("xtask stats: git {} failed", args.join(" "));
        return Err(1);
    }
    String::from_utf8(out.stdout).map_err(|e| { eprintln!("xtask stats: non-utf8 git output: {e}"); 1u8 })
}

pub(super) fn git_ls_files(repo_root: &Path) -> Result<Vec<String>, u8> {
    let out = Command::new("git").current_dir(repo_root).args(["ls-files", "-z"]).output().map_err(|e| {
        eprintln!("xtask stats: failed to run git ls-files: {e}");
        1u8
    })?;
    if !out.status.success() { eprintln!("xtask stats: git ls-files failed"); return Err(1); }
    Ok(out.stdout.split(|b| *b == 0).filter(|s| !s.is_empty())
        .filter_map(|s| std::str::from_utf8(s).ok()).map(|s| s.to_string()).collect())
}

/// Text stats for every tracked file, minus binaries.
///
/// `vendor/` is dropped here rather than at each render site. Vendored code is
/// third-party: counting it inflated every headline number in the old report
/// (238 files, and a "largest files" table topped by zlib), and a reader has no
/// way to tell which figures were ours.
pub(super) fn build_file_stats(repo_root: &Path, files: &[String]) -> Vec<FileStat> {
    let mut out = Vec::with_capacity(files.len());
    for rel in files {
        if rel.starts_with("vendor/") { continue }
        let Ok(data) = std::fs::read(repo_root.join(rel)) else { continue };
        if looks_binary(&data) { continue }
        let (lang, kind) = classify(rel);
        out.push(FileStat { path: rel.clone(), lines: count_lines(&data), bytes: data.len() as u64, lang, kind });
    }
    out
}

/// Workspace member paths from the root manifest.
///
/// Comments are stripped FIRST. Without that, `find("members")` matched the
/// word inside the `exclude` stanza's prose ("makes them implicit members"),
/// then took the next `[` — which is `exclude = [...]`. The report has been
/// printing `Workspace members | 2` and a "top workspace members" table listing
/// the two excluded vendor crates. Both real members and real LOC were absent.
pub(super) fn parse_workspace_members(cargo_toml: &Path) -> Result<Vec<String>, u8> {
    let text = std::fs::read_to_string(cargo_toml).map_err(|e| {
        eprintln!("xtask stats: failed to read {}: {e}", cargo_toml.display()); 1u8
    })?;
    let stripped = strip_toml_comments(&text);
    let ws_idx = stripped.find("[workspace]").ok_or_else(|| {
        eprintln!("xtask stats: [workspace] not found in {}", cargo_toml.display()); 1u8
    })?;
    let rest = &stripped[ws_idx..];
    let ws_block = match rest[11..].find("\n[").map(|i| i + 11) { Some(end) => &rest[..end], None => rest };
    let members_idx = find_key(ws_block, "members").ok_or_else(|| {
        eprintln!("xtask stats: workspace members not found"); 1u8
    })?;
    let member_block = &ws_block[members_idx..];
    let open = member_block.find('[').ok_or_else(|| { eprintln!("xtask stats: workspace members missing '['"); 1u8 })?;
    let close = member_block.find(']').ok_or_else(|| { eprintln!("xtask stats: workspace members missing ']'"); 1u8 })?;
    Ok(quoted_strings(&member_block[open + 1..close]))
}

/// Byte-length-preserving comment strip, so recorded offsets stay usable.
fn strip_toml_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        match line.find('#') {
            Some(i) => { out.push_str(&line[..i]); for _ in line[i..].chars() { out.push(' ') } }
            None => out.push_str(line),
        }
    }
    out
}

/// Offset of `key` used as an assignment target, not as a word in prose.
fn find_key(block: &str, key: &str) -> Option<usize> {
    let mut from = 0usize;
    while let Some(rel) = block[from..].find(key) {
        let at = from + rel;
        let before_ok = at == 0 || block[..at].chars().next_back().is_some_and(|c| c == '\n' || c == ' ' || c == '\t');
        let after = block[at + key.len()..].trim_start();
        if before_ok && after.starts_with('=') { return Some(at) }
        from = at + key.len();
    }
    None
}

fn quoted_strings(list: &str) -> Vec<String> {
    let mut vals = Vec::new();
    let mut i = 0usize;
    while i < list.len() {
        let Some(open_rel) = list[i..].find('"') else { break };
        let start = i + open_rel + 1;
        let Some(close_rel) = list[start..].find('"') else { break };
        let end = start + close_rel;
        vals.push(list[start..end].to_string());
        i = end + 1;
    }
    vals
}

fn looks_binary(data: &[u8]) -> bool {
    if data.is_empty() { return false }
    data[..data.len().min(4096)].contains(&0)
}

fn count_lines(data: &[u8]) -> usize {
    if data.is_empty() { return 0 }
    let mut lines = data.iter().filter(|b| **b == b'\n').count();
    if data[data.len() - 1] != b'\n' { lines += 1 }
    lines
}

fn ext(path: &str) -> &str { path.rsplit_once('.').map(|(_, e)| e).unwrap_or("") }

fn classify(path: &str) -> (&'static str, &'static str) {
    if path.starts_with("docs/") { return ("Markdown", "docs") }
    match ext(path) {
        "rs" => ("Rust", "code"),
        "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" => ("C/C++", "code"),
        "S" | "asm" | "s" => ("Assembly", "code"),
        "py" => ("Python", "code"),
        "sh" => ("Shell", "code"),
        "go" => ("Go", "code"),
        "js" | "ts" | "tsx" => ("JS/TS", "code"),
        "md" => ("Markdown", "docs"),
        "toml" | "json" | "yaml" | "yml" => ("Config", "config"),
        "txt" => ("Text", "other"),
        _ => ("Other", "other"),
    }
}

pub(super) fn utc_now() -> Result<String, u8> {
    let out = Command::new("date").args(["-u", "+%Y-%m-%d %H:%M:%S UTC"]).output().map_err(|e| {
        eprintln!("xtask stats: failed to run date: {e}"); 1u8
    })?;
    if !out.status.success() { eprintln!("xtask stats: date command failed"); return Err(1) }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub(super) fn aggregate<'a>(items: impl Iterator<Item = &'a FileStat>) -> Totals {
    let mut t = Totals::default();
    for s in items { t.files += 1; t.lines += s.lines; t.bytes += s.bytes }
    t
}

pub(super) fn git_history_stats(repo_root: &Path) -> Result<HistoryStats, u8> {
    let history_ref = default_history_ref(repo_root)?;
    let commits = run_git(repo_root, &["rev-list", "--count", &history_ref])?
        .trim().parse::<usize>().unwrap_or(0);
    let log = run_git(repo_root, &["log", &history_ref, "--pretty=format:%s"])?;
    let mut prs = BTreeSet::<usize>::new();
    for line in log.lines() {
        if let Some(rem) = line.strip_prefix("Merge pull request #") {
            let n = rem.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<usize>().ok();
            if let Some(v) = n { prs.insert(v); }
            continue;
        }
        if let Some(v) = trailing_pr_number(line) { prs.insert(v); }
    }
    Ok(HistoryStats { commits, prs: prs.len() })
}

fn default_history_ref(repo_root: &Path) -> Result<String, u8> {
    let out = Command::new("git").current_dir(repo_root)
        .args(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"]).output()
        .map_err(|e| { eprintln!("xtask stats: failed to resolve origin/HEAD: {e}"); 1u8 })?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() { return Ok(s) }
    }
    Ok("HEAD".to_string())
}

fn trailing_pr_number(line: &str) -> Option<usize> {
    let line = line.trim_end();
    let hash_idx = line.rfind("(#")?;
    if !line.ends_with(')') { return None }
    let digits = &line[hash_idx + 2..line.len() - 1];
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) { return None }
    digits.parse::<usize>().ok()
}

pub(super) fn docs_status_breakdown(repo_root: &Path, file_stats: &[FileStat]) -> (usize, usize, usize) {
    let (mut draft, mut frozen, mut other) = (0usize, 0usize, 0usize);
    for f in file_stats.iter().filter(|f| f.path.starts_with("docs/") && f.path.ends_with(".md")) {
        let first = std::fs::read_to_string(repo_root.join(&f.path)).ok().and_then(|txt| {
            txt.lines().take(8).find(|l| l.starts_with("DRAFT ") || l.starts_with("FROZEN ")).map(|s| s.to_string())
        });
        match first {
            Some(s) if s.starts_with("DRAFT ") => draft += 1,
            Some(s) if s.starts_with("FROZEN ") => frozen += 1,
            _ => other += 1,
        }
    }
    (draft, frozen, other)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The bug this function shipped with: `members` matched inside the
    // `exclude` stanza's comment prose, so the report listed the two EXCLUDED
    // vendor crates as the workspace.
    #[test]
    fn members_not_confused_by_the_word_in_a_comment() {
        let dir = std::env::temp_dir().join(format!("xtask-stats-ws-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("Cargo.toml");
        std::fs::write(&p, "[workspace]\nresolver = \"2\"\n\
            # path deps inside the root are implicit members, so exclude them.\n\
            exclude = [\"vendor/rust/zlib\"]\nmembers = [\"crates/kernel/vfs\", \"tools/xtask\"]\n").unwrap();
        assert_eq!(parse_workspace_members(&p).unwrap(), vec!["crates/kernel/vfs", "tools/xtask"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn find_key_requires_an_assignment() {
        assert_eq!(find_key("# implicit members here\nmembers = [", "members"), Some(24));
        assert_eq!(find_key("these members are implicit", "members"), None);
    }

    #[test]
    fn comment_strip_preserves_byte_offsets() {
        let src = "a = 1 # trailing\nb = 2\n";
        assert_eq!(strip_toml_comments(src).len(), src.len());
        assert!(strip_toml_comments(src).starts_with("a = 1 "));
    }

    #[test]
    fn classify_puts_docs_before_extension() {
        assert_eq!(classify("docs/15-syscalls.md"), ("Markdown", "docs"));
        assert_eq!(classify("crates/kernel/vfs/src/lib.rs"), ("Rust", "code"));
        assert_eq!(classify("crates/arch/hal-x86_64/src/entry.S"), ("Assembly", "code"));
    }

    #[test]
    fn line_count_handles_missing_final_newline() {
        assert_eq!(count_lines(b""), 0);
        assert_eq!(count_lines(b"a\nb\n"), 2);
        assert_eq!(count_lines(b"a\nb"), 2);
    }
}
