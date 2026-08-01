// Module manifest -- `xtask stats`.
//
// - `scan`:     tree walk, file classification, git history, workspace parse.
// - `kernel`:   kernel-shaped metrics (subsystems, drivers, syscalls, caps).
// - `markdown`: the report.
// - `plain`:    one-line machine-readable form.
//
// `vendor/` is excluded at the scan boundary, not per render site. Vendored
// third-party code is not ours and does not belong in any figure describing
// this kernel.

use std::collections::BTreeSet;

mod kernel;
mod markdown;
mod plain;
mod scan;

#[derive(Clone)]
pub(super) struct FileStat {
    path: String,
    lines: usize,
    bytes: u64,
    lang: &'static str,
    kind: &'static str,
}

#[derive(Default, Clone)]
pub(super) struct Totals { files: usize, lines: usize, bytes: u64 }

#[derive(Default, Clone, Copy)]
pub(super) struct HistoryStats { commits: usize, prs: usize }

/// Everything the renderers read, so neither renderer re-derives a figure.
pub(super) struct Report {
    generated_utc: String,
    top_n: usize,
    tracked_files: usize,
    file_stats: Vec<FileStat>,
    workspace_members: Vec<String>,
    crate_dirs: BTreeSet<String>,
    docs_status: (usize, usize, usize),
    history: HistoryStats,
    kernel: kernel::KernelStats,
}

pub(crate) fn cmd_stats(rest: &[String]) -> Result<(), u8> {
    let top_n = parse_usize_flag(rest, "--top").unwrap_or(15);
    let format = parse_str_flag(rest, "--format").unwrap_or_else(|| "markdown".to_string());
    if top_n == 0 { eprintln!("xtask stats: --top must be >= 1"); return Err(2) }
    if format != "markdown" && format != "plain" {
        eprintln!("xtask stats: --format must be markdown|plain");
        return Err(2);
    }

    let repo_root = scan::repo_root()?;
    let all_files = scan::git_ls_files(&repo_root)?;
    let file_stats = scan::build_file_stats(&repo_root, &all_files);
    let workspace_members = scan::parse_workspace_members(&repo_root.join("Cargo.toml"))?;

    let crate_dirs = all_files.iter()
        .filter(|p| !p.starts_with("vendor/"))
        .filter_map(|p| p.strip_suffix("/Cargo.toml"))
        .filter(|p| !p.is_empty())
        .map(|s| s.to_string())
        .collect::<BTreeSet<_>>();

    let report = Report {
        generated_utc: scan::utc_now()?,
        top_n,
        tracked_files: all_files.iter().filter(|p| !p.starts_with("vendor/")).count(),
        docs_status: scan::docs_status_breakdown(&repo_root, &file_stats),
        history: scan::git_history_stats(&repo_root)?,
        kernel: kernel::collect(&repo_root, &file_stats, &crate_dirs),
        file_stats,
        workspace_members,
        crate_dirs,
    };

    if format == "plain" { plain::print_plain(&report) } else { markdown::print_markdown(&report) }
    Ok(())
}

fn parse_usize_flag(args: &[String], flag: &str) -> Option<usize> {
    parse_str_flag(args, flag).and_then(|v| v.parse::<usize>().ok())
}

fn parse_str_flag(args: &[String], flag: &str) -> Option<String> {
    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        if a == flag && i + 1 < args.len() { return Some(args[i + 1].clone()) }
        if let Some(v) = a.strip_prefix(&format!("{flag}=")) { return Some(v.to_string()) }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> { v.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn flags_parse_both_spellings() {
        assert_eq!(parse_usize_flag(&args(&["--top", "20"]), "--top"), Some(20));
        assert_eq!(parse_usize_flag(&args(&["--top=7"]), "--top"), Some(7));
        assert_eq!(parse_str_flag(&args(&["--format", "plain"]), "--format").as_deref(), Some("plain"));
        assert_eq!(parse_usize_flag(&args(&["--top"]), "--top"), None);
        assert_eq!(parse_usize_flag(&args(&["--top", "x"]), "--top"), None);
    }

    #[test]
    fn bad_input_is_rejected_not_defaulted() {
        assert_eq!(cmd_stats(&args(&["--top", "0"])), Err(2));
        assert_eq!(cmd_stats(&args(&["--format", "csv"])), Err(2));
    }
}
