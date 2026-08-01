// The report. One document, ordered so a reader learns what the kernel IS
// before how big it is: composition, then completeness, then bulk.

use std::collections::BTreeMap;

use super::kernel::{CrateStat, KernelStats};
use super::{scan::aggregate, FileStat, Report, Totals};

pub(super) fn print_markdown(r: &Report) {
    let k = &r.kernel;
    println!("# oxide2 kernel stats");
    println!();
    println!("_Generated: {}. Vendored third-party code (`vendor/`) is excluded from every figure._", r.generated_utc);
    println!();

    scale(r);
    composition(k);
    subsystems(k, r.top_n);
    drivers(k);
    arch(k);
    syscalls(k);
    surface(k);
    specs_and_tests(r, k);
    health(k, r.top_n);
    language_mix(r);
    largest(r);
}

fn scale(r: &Report) {
    let code = aggregate(r.file_stats.iter().filter(|s| s.kind == "code"));
    let rust = aggregate(r.file_stats.iter().filter(|s| s.lang == "Rust"));
    let docs = aggregate(r.file_stats.iter().filter(|s| s.kind == "docs"));
    println!("## Scale");
    println!();
    println!("| Metric | Value |");
    println!("|---|---:|");
    println!("| Tracked files | {} |", r.tracked_files);
    println!("| Crates | {} |", r.crate_dirs.len());
    println!("| Workspace members | {} |", r.workspace_members.len());
    println!("| Code files / LOC | {} / {} |", code.files, code.lines);
    println!("| Rust files / LOC | {} / {} |", rust.files, rust.lines);
    println!("| Docs files / LOC | {} / {} |", docs.files, docs.lines);
    println!("| Commits | {} |", r.history.commits);
    println!("| Merged PRs | {} |", r.history.prs);
    println!();
}

fn composition(k: &KernelStats) {
    println!("## Composition");
    println!();
    println!("| Group | Path | Crates | Rust files | Rust LOC |");
    println!("|---|---|---:|---:|---:|");
    for g in &k.groups {
        println!("| {} | `{}` | {} | {} | {} |", g.label, g.prefix, g.crates, g.files, g.lines);
    }
    println!();
}

fn crate_table(rows: &[CrateStat], limit: Option<usize>) {
    println!("| Crate | Rust files | Rust LOC |");
    println!("|---|---:|---:|");
    let n = limit.unwrap_or(rows.len());
    for c in rows.iter().take(n) {
        println!("| `{}` | {} | {} |", c.name, c.files, c.lines);
    }
    if rows.len() > n {
        let rest: usize = rows[n..].iter().map(|c| c.lines).sum();
        println!("| _{} more_ | | {} |", rows.len() - n, rest);
    }
    println!();
}

fn subsystems(k: &KernelStats, top_n: usize) {
    println!("## Kernel subsystems ({})", k.subsystems.len());
    println!();
    crate_table(&k.subsystems, Some(top_n));
}

fn drivers(k: &KernelStats) {
    println!("## Device drivers ({})", k.drivers.len());
    println!();
    println!("Crate name states the hardware each covers.");
    println!();
    crate_table(&k.drivers, None);
}

fn arch(k: &KernelStats) {
    println!("## Arch / HAL ({})", k.arch.len());
    println!();
    crate_table(&k.arch, None);
}

fn syscalls(k: &KernelStats) {
    let s = &k.syscall;
    println!("## Syscall ABI");
    println!();
    println!("| Metric | Value |");
    println!("|---|---:|");
    println!("| `NR_*` slots declared | {} |", s.nr_consts);
    println!("| ABI shim slot files | {} |", s.slot_files);
    println!("| Compliance-matrix rows | {} |", s.matrix_rows);
    println!();
    if s.by_status.is_empty() {
        println!("_Status breakdown unavailable: `tools/matrix-lint.py --counts` did not run._");
        println!();
        return;
    }
    println!("| Status | Count | Share |");
    println!("|---|---:|---:|");
    for (st, n) in &s.by_status {
        let share = if s.matrix_rows > 0 { (*n as f64 * 100.0) / s.matrix_rows as f64 } else { 0.0 };
        println!("| `{st}` | {n} | {share:.1}% |");
    }
    println!();
}

fn surface(k: &KernelStats) {
    println!("## Supported surface");
    println!();
    println!("| Kind | Count | Names |");
    println!("|---|---:|---|");
    row("Filesystems", &k.filesystems);
    row("Address families", &k.families);
    row("Socket types", &k.sock_types);
    row("IP protocols", &k.protocols);
    println!();
}

fn row(label: &str, names: &[String]) {
    let list = if names.is_empty() { "_none detected_".to_string() }
               else { names.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(", ") };
    println!("| {} | {} | {} |", label, names.len(), list);
}

fn specs_and_tests(r: &Report, k: &KernelStats) {
    let (draft, frozen, other) = r.docs_status;
    println!("## Specs and tests");
    println!();
    println!("| Metric | Value |");
    println!("|---|---:|");
    println!("| Specs in `docs/` | {} |", draft + frozen + other);
    println!("| DRAFT / FROZEN / unmarked | {draft} / {frozen} / {other} |");
    println!("| Hosted test functions | {} |", k.tests);
    println!();
}

fn health(k: &KernelStats, top_n: usize) {
    let i = &k.issues;
    println!("## Health");
    println!();
    println!("| Metric | Value |");
    println!("|---|---:|");
    println!("| Issue rows OPEN | {} |", i.open);
    println!("| Issue rows IN-PROGRESS | {} |", i.in_progress);
    println!("| Issue rows FIXED | {} |", i.fixed);
    println!("| Files at/over the 500-line split cutoff | {} |", k.caps.at_soft);
    println!("| Files over the 1000-line hard cap | {} |", k.caps.over_hard);
    println!();
    if k.caps.worst.is_empty() { return }
    println!("| Largest over the split cutoff | LOC |");
    println!("|---|---:|");
    for (p, n) in k.caps.worst.iter().take(top_n) { println!("| `{p}` | {n} |") }
    println!();
}

fn language_mix(r: &Report) {
    let total: usize = r.file_stats.iter().map(|f| f.lines).sum();
    let mut by_lang: Vec<_> = {
        let mut map: BTreeMap<&str, Totals> = BTreeMap::new();
        for f in &r.file_stats {
            let e = map.entry(f.lang).or_default();
            e.files += 1; e.lines += f.lines; e.bytes += f.bytes;
        }
        map.into_iter().collect()
    };
    by_lang.sort_by(|a, b| b.1.lines.cmp(&a.1.lines).then_with(|| a.0.cmp(b.0)));
    println!("## Language mix");
    println!();
    println!("| Language | Files | LOC | Share |");
    println!("|---|---:|---:|---:|");
    for (lang, t) in by_lang.into_iter().take(r.top_n) {
        let share = if total > 0 { (t.lines as f64 * 100.0) / total as f64 } else { 0.0 };
        println!("| {} | {} | {} | {:.1}% |", lang, t.files, t.lines, share);
    }
    println!();
}

fn largest(r: &Report) {
    println!("## Largest files");
    println!();
    println!("| File | LOC | Language |");
    println!("|---|---:|---|");
    let mut largest: Vec<&FileStat> = r.file_stats.iter().collect();
    largest.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| a.path.cmp(&b.path)));
    for f in largest.into_iter().take(r.top_n) {
        println!("| `{}` | {} | {} |", f.path, f.lines, f.lang);
    }
}
