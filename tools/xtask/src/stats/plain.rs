use std::collections::BTreeSet;

use super::{aggregate, FileStat, HistoryStats};

pub(super) fn print_plain(
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
