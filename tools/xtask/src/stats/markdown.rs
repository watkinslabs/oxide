use std::collections::{BTreeMap, BTreeSet};

use super::{aggregate, FileStat, HistoryStats, Totals};

pub(super) fn print_markdown(
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
