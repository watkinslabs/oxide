// One-line key=value form for scripts. Same figures as the markdown report;
// neither renderer computes anything the other does not.

use super::{scan::aggregate, Report};

pub(super) fn print_plain(r: &Report) {
    let k = &r.kernel;
    let code = aggregate(r.file_stats.iter().filter(|s| s.kind == "code"));
    let rust = aggregate(r.file_stats.iter().filter(|s| s.lang == "Rust"));
    let (draft, frozen, other) = r.docs_status;

    println!("oxide2 stats ({})", r.generated_utc);
    println!("tracked={} commits={} prs={} crates={} workspace_members={} code_files={} code_loc={} rust_files={} rust_loc={}",
        r.tracked_files, r.history.commits, r.history.prs, r.crate_dirs.len(),
        r.workspace_members.len(), code.files, code.lines, rust.files, rust.lines);
    println!("subsystems={} drivers={} arch_crates={} filesystems={} address_families={} sock_types={} ip_protocols={}",
        k.subsystems.len(), k.drivers.len(), k.arch.len(), k.filesystems.len(),
        k.families.len(), k.sock_types.len(), k.protocols.len());
    println!("syscall_slots={} syscall_shim_files={} matrix_rows={} tests={} specs={} specs_draft={} specs_frozen={} specs_unmarked={}",
        k.syscall.nr_consts, k.syscall.slot_files, k.syscall.matrix_rows, k.tests,
        draft + frozen + other, draft, frozen, other);
    print!("matrix:");
    for (st, n) in &k.syscall.by_status { print!(" {st}={n}") }
    println!();
    println!("issues_open={} issues_in_progress={} issues_fixed={} files_over_soft_cap={} files_over_hard_cap={}",
        k.issues.open, k.issues.in_progress, k.issues.fixed, k.caps.at_soft, k.caps.over_hard);

    let mut largest: Vec<_> = r.file_stats.iter().collect();
    largest.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| a.path.cmp(&b.path)));
    println!("largest_files_top_{}:", r.top_n);
    for f in largest.into_iter().take(r.top_n) { println!("  {:>6} {}", f.lines, f.path) }
}
