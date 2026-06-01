use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

#[derive(Clone)]
struct FileStat {
    path: String,
    lines: usize,
    bytes: u64,
    lang: &'static str,
    kind: &'static str,
}

#[derive(Default, Clone)]
struct Totals {
    files: usize,
    lines: usize,
    bytes: u64,
}

#[derive(Default, Clone, Copy)]
struct HistoryStats {
    commits: usize,
    prs: usize,
}

pub(crate) fn cmd_stats(rest: &[String]) -> Result<(), u8> {
    let top_n = parse_usize_flag(rest, "--top").unwrap_or(15);
    let format = parse_str_flag(rest, "--format").unwrap_or_else(|| "markdown".to_string());
    if top_n == 0 {
        eprintln!("xtask stats: --top must be >= 1");
        return Err(2);
    }
    if format != "markdown" && format != "plain" {
        eprintln!("xtask stats: --format must be markdown|plain");
        return Err(2);
    }

    let repo_root = repo_root()?;
    let all_files = git_ls_files(&repo_root)?;
    let file_stats = build_file_stats(&repo_root, &all_files)?;
    let workspace_members = parse_workspace_members(&repo_root.join("Cargo.toml"))?;

    let crate_dirs = all_files
        .iter()
        .filter_map(|p| p.strip_suffix("/Cargo.toml"))
        .filter(|p| !p.is_empty())
        .map(|s| s.to_string())
        .collect::<BTreeSet<_>>();

    let generated_utc = utc_now()?;
    let history = git_history_stats(&repo_root)?;

    let docs_status = docs_status_breakdown(&repo_root, &file_stats);

    if format == "plain" {
        print_plain(
            &generated_utc,
            top_n,
            &all_files,
            &file_stats,
            &workspace_members,
            &crate_dirs,
            history,
        );
    } else {
        print_markdown(
            &generated_utc,
            top_n,
            &all_files,
            &file_stats,
            &workspace_members,
            &crate_dirs,
            docs_status,
            history,
        );
    }
    Ok(())
}

fn parse_usize_flag(args: &[String], flag: &str) -> Option<usize> {
    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        if a == flag && i + 1 < args.len() {
            return args[i + 1].parse::<usize>().ok();
        }
        if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
            return v.parse::<usize>().ok();
        }
        i += 1;
    }
    None
}

fn parse_str_flag(args: &[String], flag: &str) -> Option<String> {
    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        if a == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
            return Some(v.to_string());
        }
        i += 1;
    }
    None
}

fn repo_root() -> Result<std::path::PathBuf, u8> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| {
            eprintln!("xtask stats: failed to run git rev-parse: {e}");
            1u8
        })?;
    if !out.status.success() {
        eprintln!("xtask stats: git rev-parse failed");
        return Err(1);
    }
    let s = String::from_utf8(out.stdout).map_err(|e| {
        eprintln!("xtask stats: non-utf8 git output: {e}");
        1u8
    })?;
    Ok(std::path::PathBuf::from(s.trim()))
}

fn git_ls_files(repo_root: &Path) -> Result<Vec<String>, u8> {
    let out = Command::new("git")
        .current_dir(repo_root)
        .args(["ls-files", "-z"])
        .output()
        .map_err(|e| {
            eprintln!("xtask stats: failed to run git ls-files: {e}");
            1u8
        })?;
    if !out.status.success() {
        eprintln!("xtask stats: git ls-files failed");
        return Err(1);
    }
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| std::str::from_utf8(s).ok())
        .map(|s| s.to_string())
        .collect())
}

fn build_file_stats(repo_root: &Path, files: &[String]) -> Result<Vec<FileStat>, u8> {
    let mut out = Vec::with_capacity(files.len());
    for rel in files {
        let full = repo_root.join(rel);
        let data = match std::fs::read(&full) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if looks_binary(&data) {
            continue;
        }
        let lines = count_lines(&data);
        let bytes = data.len() as u64;
        let (lang, kind) = classify(rel);
        out.push(FileStat {
            path: rel.clone(),
            lines,
            bytes,
            lang,
            kind,
        });
    }
    Ok(out)
}

fn parse_workspace_members(cargo_toml: &Path) -> Result<Vec<String>, u8> {
    let text = std::fs::read_to_string(cargo_toml).map_err(|e| {
        eprintln!("xtask stats: failed to read {}: {e}", cargo_toml.display());
        1u8
    })?;
    let ws_idx = text.find("[workspace]").ok_or_else(|| {
        eprintln!(
            "xtask stats: [workspace] not found in {}",
            cargo_toml.display()
        );
        1u8
    })?;
    let rest = &text[ws_idx..];
    let next_section_rel = rest[11..].find("\n[").map(|i| i + 11);
    let ws_block = match next_section_rel {
        Some(end) => &rest[..end],
        None => rest,
    };
    let members_idx = ws_block.find("members").ok_or_else(|| {
        eprintln!("xtask stats: workspace members not found");
        1u8
    })?;
    let member_block = &ws_block[members_idx..];
    let open = member_block.find('[').ok_or_else(|| {
        eprintln!("xtask stats: workspace members missing '['");
        1u8
    })?;
    let close = member_block.find(']').ok_or_else(|| {
        eprintln!("xtask stats: workspace members missing ']'");
        1u8
    })?;
    let list = &member_block[open + 1..close];
    let mut vals = Vec::new();
    let mut i = 0usize;
    while i < list.len() {
        let rem = &list[i..];
        let Some(open_rel) = rem.find('"') else { break };
        let start = i + open_rel + 1;
        let Some(close_rel) = list[start..].find('"') else {
            break;
        };
        let end = start + close_rel;
        vals.push(list[start..end].to_string());
        i = end + 1;
    }
    Ok(vals)
}

fn looks_binary(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let probe = data.len().min(4096);
    data[..probe].contains(&0)
}

fn count_lines(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    let mut lines = data.iter().filter(|b| **b == b'\n').count();
    if data[data.len() - 1] != b'\n' {
        lines += 1;
    }
    lines
}

fn ext(path: &str) -> &str {
    path.rsplit_once('.').map(|(_, e)| e).unwrap_or("")
}

fn classify(path: &str) -> (&'static str, &'static str) {
    if path.starts_with("docs/") {
        return ("Markdown", "docs");
    }
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

fn utc_now() -> Result<String, u8> {
    let out = Command::new("date")
        .args(["-u", "+%Y-%m-%d %H:%M:%S UTC"])
        .output()
        .map_err(|e| {
            eprintln!("xtask stats: failed to run date: {e}");
            1u8
        })?;
    if !out.status.success() {
        eprintln!("xtask stats: date command failed");
        return Err(1);
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn aggregate<'a>(items: impl Iterator<Item = &'a FileStat>) -> Totals {
    let mut t = Totals::default();
    for s in items {
        t.files += 1;
        t.lines += s.lines;
        t.bytes += s.bytes;
    }
    t
}

fn git_history_stats(repo_root: &Path) -> Result<HistoryStats, u8> {
    let history_ref = default_history_ref(repo_root)?;

    let commits_out = Command::new("git")
        .current_dir(repo_root)
        .args(["rev-list", "--count", &history_ref])
        .output()
        .map_err(|e| {
            eprintln!("xtask stats: failed to run git rev-list: {e}");
            1u8
        })?;
    if !commits_out.status.success() {
        eprintln!("xtask stats: git rev-list failed");
        return Err(1);
    }
    let commits = String::from_utf8_lossy(&commits_out.stdout)
        .trim()
        .parse::<usize>()
        .unwrap_or(0);

    let log_out = Command::new("git")
        .current_dir(repo_root)
        .args(["log", &history_ref, "--pretty=format:%s"])
        .output()
        .map_err(|e| {
            eprintln!("xtask stats: failed to run git log: {e}");
            1u8
        })?;
    if !log_out.status.success() {
        eprintln!("xtask stats: git log failed");
        return Err(1);
    }
    let mut prs = BTreeSet::<usize>::new();
    let log = String::from_utf8_lossy(&log_out.stdout);
    for line in log.lines() {
        if let Some(rem) = line.strip_prefix("Merge pull request #") {
            let n = rem
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse::<usize>()
                .ok();
            if let Some(v) = n {
                prs.insert(v);
            }
            continue;
        }
        if let Some(v) = trailing_pr_number(line) {
            prs.insert(v);
        }
    }
    Ok(HistoryStats {
        commits,
        prs: prs.len(),
    })
}

fn default_history_ref(repo_root: &Path) -> Result<String, u8> {
    let out = Command::new("git")
        .current_dir(repo_root)
        .args(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])
        .output()
        .map_err(|e| {
            eprintln!("xtask stats: failed to resolve origin/HEAD: {e}");
            1u8
        })?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return Ok(s);
        }
    }
    Ok("HEAD".to_string())
}

fn trailing_pr_number(line: &str) -> Option<usize> {
    let line = line.trim_end();
    let hash_idx = line.rfind("(#")?;
    if !line.ends_with(')') {
        return None;
    }
    let digits = &line[hash_idx + 2..line.len() - 1];
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    digits.parse::<usize>().ok()
}

fn print_markdown(
    generated_utc: &str,
    top_n: usize,
    all_files: &[String],
    file_stats: &[FileStat],
    workspace_members: &[String],
    crate_dirs: &BTreeSet<String>,
    docs_status: (usize, usize, usize),
    history: HistoryStats,
) {
    let non_vendor: Vec<&FileStat> = file_stats
        .iter()
        .filter(|f| !f.path.starts_with("vendor/"))
        .collect();
    let vendor: Vec<&FileStat> = file_stats
        .iter()
        .filter(|f| f.path.starts_with("vendor/"))
        .collect();

    let tracked_total = all_files.len();
    let text_files = non_vendor.len();
    let code = aggregate(non_vendor.iter().copied().filter(|s| s.kind == "code"));
    let docs = aggregate(non_vendor.iter().copied().filter(|s| s.kind == "docs"));
    let rust = aggregate(non_vendor.iter().copied().filter(|s| s.lang == "Rust"));
    let tests = aggregate(non_vendor.iter().copied().filter(|s| {
        s.path.contains("/tests/") || s.path.ends_with("_test.rs") || s.path.ends_with(".test.rs")
    }));
    let vendor_totals = aggregate(vendor.iter().copied());

    println!("# oxide2 project code stats");
    println!();
    println!("_Generated: {generated_utc}_");
    println!();
    println!("| Metric | Value |");
    println!("|---|---:|");
    println!("| Tracked files (git) | {tracked_total} |");
    println!("| Commits (`git rev-list --all`) | {} |", history.commits);
    println!("| PRs (detected from commit subjects) | {} |", history.prs);
    println!("| Text files analyzed (non-vendor) | {text_files} |");
    println!("| Text files analyzed (`vendor/`) | {} |", vendor_totals.files);
    println!(
        "| Crates (`Cargo.toml` outside root) | {} |",
        crate_dirs.len()
    );
    println!("| Workspace members | {} |", workspace_members.len());
    println!("| Code files | {} |", code.files);
    println!("| Code LOC | {} |", code.lines);
    println!("| Rust files | {} |", rust.files);
    println!("| Rust LOC | {} |", rust.lines);
    println!("| Docs files | {} |", docs.files);
    println!("| Docs LOC | {} |", docs.lines);
    println!("| Test-like files | {} |", tests.files);
    println!("| Test-like LOC | {} |", tests.lines);
    println!();

    let mut by_lang: Vec<_> = {
        let mut map: BTreeMap<&str, Totals> = BTreeMap::new();
        for f in non_vendor.iter().copied() {
            let e = map.entry(f.lang).or_default();
            e.files += 1;
            e.lines += f.lines;
            e.bytes += f.bytes;
        }
        map.into_iter().collect()
    };
    by_lang.sort_by(|a, b| b.1.lines.cmp(&a.1.lines).then_with(|| a.0.cmp(b.0)));
    println!("## Language mix");
    println!();
    println!("| Rank | Language | Files | LOC | Share |");
    println!("|---:|---|---:|---:|---:|");
    for (i, (lang, t)) in by_lang.into_iter().take(top_n).enumerate() {
        let share = if text_files > 0 {
            (t.lines as f64 * 100.0)
                / (non_vendor.iter().copied().map(|f| f.lines).sum::<usize>() as f64)
        } else {
            0.0
        };
        println!(
            "| {} | {} | {} | {} | {:.1}% |",
            i + 1,
            lang,
            t.files,
            t.lines,
            share
        );
    }
    println!();

    println!("## Top workspace members by Rust LOC");
    println!();
    println!("| Rank | Path | Rust files | Rust LOC | Avg LOC/file |");
    println!("|---:|---|---:|---:|---:|");
    let mut ws = Vec::new();
    for member in workspace_members {
        let t = aggregate(
            file_stats
                .iter()
                .filter(|f| f.lang == "Rust" && f.path.starts_with(&format!("{member}/"))),
        );
        ws.push((member, t));
    }
    ws.sort_by(|a, b| b.1.lines.cmp(&a.1.lines).then_with(|| a.0.cmp(b.0)));
    for (i, (path, t)) in ws.into_iter().take(top_n).enumerate() {
        let avg = if t.files > 0 {
            t.lines as f64 / t.files as f64
        } else {
            0.0
        };
        println!(
            "| {} | `{}` | {} | {} | {:.1} |",
            i + 1,
            path,
            t.files,
            t.lines,
            avg
        );
    }
    println!();

    println!("## Largest files");
    println!();
    println!("| Rank | File | LOC | Language |");
    println!("|---:|---|---:|---|");
    let mut largest: Vec<FileStat> = non_vendor.iter().copied().cloned().collect();
    largest.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| a.path.cmp(&b.path)));
    for (i, f) in largest.into_iter().take(top_n).enumerate() {
        println!("| {} | `{}` | {} | {} |", i + 1, f.path, f.lines, f.lang);
    }
    println!();

    println!("## Vendor stats (`vendor/`)");
    println!();
    println!("| Metric | Value |");
    println!("|---|---:|");
    println!("| Vendor text files | {} |", vendor_totals.files);
    println!("| Vendor LOC | {} |", vendor_totals.lines);
    println!();

    let mut vendor_lang: Vec<_> = {
        let mut map: BTreeMap<&str, Totals> = BTreeMap::new();
        for f in vendor.iter().copied() {
            let e = map.entry(f.lang).or_default();
            e.files += 1;
            e.lines += f.lines;
            e.bytes += f.bytes;
        }
        map.into_iter().collect()
    };
    vendor_lang.sort_by(|a, b| b.1.lines.cmp(&a.1.lines).then_with(|| a.0.cmp(b.0)));
    println!("| Rank | Language | Files | LOC | Share |");
    println!("|---:|---|---:|---:|---:|");
    for (i, (lang, t)) in vendor_lang.into_iter().take(top_n).enumerate() {
        let share = if vendor_totals.lines > 0 {
            (t.lines as f64 * 100.0) / (vendor_totals.lines as f64)
        } else {
            0.0
        };
        println!(
            "| {} | {} | {} | {} | {:.1}% |",
            i + 1,
            lang,
            t.files,
            t.lines,
            share
        );
    }
    println!();

    println!("| Rank | File | LOC | Language |");
    println!("|---:|---|---:|---|");
    let mut vendor_largest: Vec<FileStat> = vendor.iter().copied().cloned().collect();
    vendor_largest.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| a.path.cmp(&b.path)));
    for (i, f) in vendor_largest.into_iter().take(top_n).enumerate() {
        println!("| {} | `{}` | {} | {} |", i + 1, f.path, f.lines, f.lang);
    }
    println!();

    println!("## Docs status (docs/*.md)");
    println!();
    println!("| DRAFT | FROZEN | Other/Unmarked |");
    println!("|---:|---:|---:|");
    println!(
        "| {} | {} | {} |",
        docs_status.0, docs_status.1, docs_status.2
    );
}

fn print_plain(
    generated_utc: &str,
    top_n: usize,
    all_files: &[String],
    file_stats: &[FileStat],
    workspace_members: &[String],
    crate_dirs: &BTreeSet<String>,
    history: HistoryStats,
) {
    let non_vendor: Vec<&FileStat> = file_stats
        .iter()
        .filter(|f| !f.path.starts_with("vendor/"))
        .collect();
    let vendor: Vec<&FileStat> = file_stats
        .iter()
        .filter(|f| f.path.starts_with("vendor/"))
        .collect();

    let tracked_total = all_files.len();
    let text_files = non_vendor.len();
    let code = aggregate(non_vendor.iter().copied().filter(|s| s.kind == "code"));
    let rust = aggregate(non_vendor.iter().copied().filter(|s| s.lang == "Rust"));
    let vendor_totals = aggregate(vendor.iter().copied());
    println!("oxide2 stats ({generated_utc})");
    println!("tracked={tracked_total} commits={} prs={} text_non_vendor={text_files} text_vendor={} crates={} workspace_members={} code_files={} code_loc={} rust_files={} rust_loc={}",
        history.commits, history.prs, vendor_totals.files, crate_dirs.len(), workspace_members.len(), code.files, code.lines, rust.files, rust.lines);
    let mut largest: Vec<FileStat> = non_vendor.iter().copied().cloned().collect();
    largest.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| a.path.cmp(&b.path)));
    println!("largest_non_vendor_files_top_{top_n}:");
    for f in largest.into_iter().take(top_n) {
        println!("  {:>6} {}", f.lines, f.path);
    }
    let mut vendor_largest: Vec<FileStat> = vendor.iter().copied().cloned().collect();
    vendor_largest.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| a.path.cmp(&b.path)));
    println!("largest_vendor_files_top_{top_n}:");
    for f in vendor_largest.into_iter().take(top_n) {
        println!("  {:>6} {}", f.lines, f.path);
    }
}

fn docs_status_breakdown(repo_root: &Path, file_stats: &[FileStat]) -> (usize, usize, usize) {
    let mut draft = 0usize;
    let mut frozen = 0usize;
    let mut other = 0usize;
    for f in file_stats
        .iter()
        .filter(|f| f.path.starts_with("docs/") && f.path.ends_with(".md"))
    {
        let first = std::fs::read_to_string(repo_root.join(&f.path))
            .ok()
            .and_then(|txt| {
                txt.lines()
                    .take(8)
                    .find(|l| l.starts_with("DRAFT ") || l.starts_with("FROZEN "))
                    .map(|s| s.to_string())
            });
        match first {
            Some(s) if s.starts_with("DRAFT ") => draft += 1,
            Some(s) if s.starts_with("FROZEN ") => frozen += 1,
            _ => other += 1,
        }
    }
    (draft, frozen, other)
}
