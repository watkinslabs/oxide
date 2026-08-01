// Kernel-shaped metrics: how much kernel is there, and how complete is it.
//
// Every figure is derived from the tree at run time. Nothing here carries a
// hardcoded list of subsystems, drivers, filesystems or syscalls -- a hardcoded
// list is a second source of truth that goes stale silently and then reports a
// capability the kernel no longer has (`docs/53`, CLAUDE.md "no split source of
// truth"). Where a canonical registry already exists, this reads THAT file.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use super::{scan::aggregate, FileStat};

/// Canonical registry files. Reading the registry is the point: a list here
/// would disagree with the kernel the first time a lane adds a filesystem.
const FS_REGISTRY: &str = "crates/kernel/syscalls/src/fsmount_common/registry.rs";
const SOCKET_ARGS: &str = "crates/kernel/net/src/socket_args.rs";
const SYSCALL_NRS: &str = "crates/kernel/syscall/src/nrs.rs";
const SYSCALL_SLOTS: &str = "crates/kernel/syscalls/src";
const MATRIX: &str = "scratch/syscall-compliance-matrix.md";

/// `docs/08§7`: 500 lines is the split-now cutoff, 1000 the CI error.
const SOFT_CAP: usize = 500;
const HARD_CAP: usize = 1000;

pub(super) struct CrateStat { pub name: String, pub files: usize, pub lines: usize }

pub(super) struct GroupStat { pub label: &'static str, pub prefix: &'static str, pub crates: usize, pub files: usize, pub lines: usize }

#[derive(Default)]
pub(super) struct SyscallStats {
    pub nr_consts: usize,
    pub slot_files: usize,
    pub matrix_rows: usize,
    /// `(status, count)` straight from the matrix legend, via `matrix-lint.py`.
    pub by_status: Vec<(String, usize)>,
}

#[derive(Default)]
pub(super) struct IssueStats { pub open: usize, pub in_progress: usize, pub fixed: usize }

#[derive(Default)]
pub(super) struct CapStats { pub at_soft: usize, pub over_hard: usize, pub worst: Vec<(String, usize)> }

pub(super) struct KernelStats {
    pub groups: Vec<GroupStat>,
    pub subsystems: Vec<CrateStat>,
    pub drivers: Vec<CrateStat>,
    pub arch: Vec<CrateStat>,
    pub syscall: SyscallStats,
    pub filesystems: Vec<String>,
    pub families: Vec<String>,
    pub sock_types: Vec<String>,
    pub protocols: Vec<String>,
    pub tests: usize,
    pub issues: IssueStats,
    pub caps: CapStats,
}

/// Crate-directory groups, in dependency order from the metal upwards.
const GROUPS: &[(&str, &str)] = &[
    ("Kernel subsystems", "crates/kernel/"),
    ("Device drivers",    "crates/drivers/"),
    ("Arch / HAL",        "crates/arch/"),
    ("Shared kernel libs","crates/shared/"),
    ("Userspace libs",    "crates/user/"),
    ("Build tooling",     "tools/"),
];

pub(super) fn collect(root: &Path, file_stats: &[FileStat], crate_dirs: &BTreeSet<String>) -> KernelStats {
    let groups = GROUPS.iter().map(|(label, prefix)| {
        let t = aggregate(file_stats.iter().filter(|f| f.lang == "Rust" && f.path.starts_with(prefix)));
        GroupStat {
            label, prefix,
            crates: crate_dirs.iter().filter(|d| is_direct_child(d, prefix)).count(),
            files: t.files, lines: t.lines,
        }
    }).collect();

    KernelStats {
        groups,
        subsystems: crates_under(file_stats, crate_dirs, "crates/kernel/"),
        drivers:    crates_under(file_stats, crate_dirs, "crates/drivers/"),
        arch:       crates_under(file_stats, crate_dirs, "crates/arch/"),
        syscall:    syscall_stats(root, file_stats),
        filesystems: registered_filesystems(root),
        families:   consts_with_prefix(root, SOCKET_ARGS, "AF_"),
        sock_types: consts_with_prefix(root, SOCKET_ARGS, "SOCK_"),
        protocols:  consts_with_prefix(root, SOCKET_ARGS, "IPPROTO_"),
        tests:      count_tests(root, file_stats),
        issues:     issue_stats(root),
        caps:       cap_stats(file_stats),
    }
}

/// A crate directly under `prefix`, not one nested deeper inside another crate.
fn is_direct_child(dir: &str, prefix: &str) -> bool {
    dir.strip_prefix(prefix).is_some_and(|r| !r.contains('/'))
}

fn crates_under(file_stats: &[FileStat], crate_dirs: &BTreeSet<String>, prefix: &str) -> Vec<CrateStat> {
    let mut out: Vec<CrateStat> = crate_dirs.iter().filter(|d| is_direct_child(d, prefix)).map(|d| {
        let t = aggregate(file_stats.iter().filter(|f| f.lang == "Rust" && f.path.starts_with(&format!("{d}/"))));
        CrateStat { name: d[prefix.len()..].to_string(), files: t.files, lines: t.lines }
    }).collect();
    out.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| a.name.cmp(&b.name)));
    out
}

fn syscall_stats(root: &Path, file_stats: &[FileStat]) -> SyscallStats {
    let nr_consts = std::fs::read_to_string(root.join(SYSCALL_NRS)).map(|t|
        t.lines().filter(|l| l.trim_start().starts_with("pub const NR_")).count()).unwrap_or(0);
    // ABI shim slot files are named `NNN_name.rs` (`docs/53`).
    let slot_files = file_stats.iter().filter(|f| {
        f.path.strip_prefix(&format!("{SYSCALL_SLOTS}/")).is_some_and(|r| {
            !r.contains('/') && r.len() > 4 && r.as_bytes()[..3].iter().all(|b| b.is_ascii_digit()) && r.as_bytes()[3] == b'_'
        })
    }).count();
    let (matrix_rows, by_status) = matrix_counts(root);
    SyscallStats { nr_consts, slot_files, matrix_rows, by_status }
}

/// Status tally from `tools/matrix-lint.py --counts`.
///
/// Shelling out to the lint is deliberate. The matrix's notes column contains
/// escaped `\|`, and a counter that splits on bare `|` silently DROPS every row
/// carrying one -- which is exactly how `F789`'s retracted predecessor came to
/// report 66 syscalls as untracked when all 385 had rows. One escape-aware
/// parser exists; a second one written here could disagree with the gate.
fn matrix_counts(root: &Path) -> (usize, Vec<(String, usize)>) {
    let out = Command::new("python3")
        .current_dir(root)
        .args(["tools/matrix-lint.py", "--counts", MATRIX])
        .output();
    let Ok(out) = out else { return (0, Vec::new()) };
    if !out.status.success() { return (0, Vec::new()) }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut rows = 0usize;
    let mut by_status = Vec::new();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('\t') else { continue };
        let Ok(n) = v.trim().parse::<usize>() else { continue };
        if k == "ROWS" { rows = n } else if n > 0 { by_status.push((k.to_string(), n)) }
    }
    by_status.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    (rows, by_status)
}

/// Names passed to the VFS filesystem registry, in registration order.
fn registered_filesystems(root: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(root.join(FS_REGISTRY)) else { return Vec::new() };
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim_start();
        // Test-only and helper registrations never appear here: this file is
        // the boot-time registry, so its call sites are the shipped set.
        for marker in ["FsType::new(", "FsType::with_parameters(", "pseudo!("] {
            let Some(rest) = l.split_once(marker).map(|(_, r)| r) else { continue };
            let Some(name) = rest.strip_prefix('"').and_then(|r| r.split_once('"')).map(|(n, _)| n) else { continue };
            if !name.is_empty() && !out.contains(&name.to_string()) { out.push(name.to_string()) }
        }
    }
    out.sort();
    out
}

/// `pub const <PREFIX><NAME>: ty = <int>;` names from one canonical uapi file.
///
/// Derived aliases and mask/flag values are not capabilities: `AF_INET_WIRE` is
/// the same family re-typed for a wire struct, `SOCK_CLOEXEC` is an open flag,
/// `AF_MAX` is a bound. Counting them would overstate what the kernel speaks.
const NOT_A_CAPABILITY: &[&str] = &["_WIRE", "_RULE", "_MASK", "_MAX", "UNSPEC", "_CLOEXEC", "_NONBLOCK"];

fn consts_with_prefix(root: &Path, rel: &str, prefix: &str) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(root.join(rel)) else { return Vec::new() };
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix("pub const ") else { continue };
        let Some((name, value)) = rest.split_once(':') else { continue };
        let name = name.trim();
        if !name.starts_with(prefix) { continue }
        if NOT_A_CAPABILITY.iter().any(|s| name.contains(s)) { continue }
        // An alias is defined from another const; a real slot is a literal.
        let Some((_, v)) = value.split_once('=') else { continue };
        if !v.trim().trim_end_matches(';').trim().chars().next().is_some_and(|c| c.is_ascii_digit()) { continue }
        let short = name[prefix.len()..].to_string();
        if !short.is_empty() && !out.contains(&short) { out.push(short) }
    }
    out.sort();
    out
}

/// Hosted test functions. `#[test]` is the unit; `cargo test` would have to
/// build 117 crates to answer this and stats must stay cheap enough to run.
fn count_tests(root: &Path, file_stats: &[FileStat]) -> usize {
    file_stats.iter().filter(|f| f.lang == "Rust").map(|f| {
        std::fs::read_to_string(root.join(&f.path)).map(|t|
            t.lines().filter(|l| { let l = l.trim(); l == "#[test]" || l == "#[bench]" }).count()).unwrap_or(0)
    }).sum()
}

/// Ledger rows via `tools/issues.sh --status-count`, which already knows that
/// the ledger is curated file + per-lane drops under `scratch/issues.d/`.
fn issue_stats(root: &Path) -> IssueStats {
    let out = Command::new("tools/issues.sh").current_dir(root).arg("--status-count").output();
    let Ok(out) = out else { return IssueStats::default() };
    if !out.status.success() { return IssueStats::default() }
    let mut s = IssueStats::default();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some((k, v)) = line.split_once('\t') else { continue };
        let Ok(n) = v.trim().parse::<usize>() else { continue };
        match k { "OPEN" => s.open = n, "IN-PROGRESS" => s.in_progress = n, "FIXED" => s.fixed = n, _ => {} }
    }
    s
}

fn cap_stats(file_stats: &[FileStat]) -> CapStats {
    let ours = |f: &&FileStat| f.lang == "Rust" || f.path.starts_with("docs/");
    let mut over: Vec<(String, usize)> = file_stats.iter().filter(ours)
        .filter(|f| f.lines >= SOFT_CAP).map(|f| (f.path.clone(), f.lines)).collect();
    over.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    CapStats {
        at_soft: over.len(),
        over_hard: over.iter().filter(|(_, n)| *n > HARD_CAP).count(),
        worst: over,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_child_excludes_nested_crates() {
        assert!(is_direct_child("crates/kernel/vfs", "crates/kernel/"));
        assert!(!is_direct_child("crates/kernel/vfs/sub", "crates/kernel/"));
        assert!(!is_direct_child("crates/drivers/pci", "crates/kernel/"));
    }

    #[test]
    fn capability_filter_drops_aliases_and_bounds() {
        for n in ["AF_INET_WIRE", "AF_MAX", "AF_UNSPEC", "SOCK_CLOEXEC", "SOCK_TYPE_MASK", "AF_INET_RULE"] {
            assert!(NOT_A_CAPABILITY.iter().any(|s| n.contains(s)), "{n} should be filtered");
        }
        for n in ["AF_INET", "AF_VSOCK", "SOCK_STREAM", "IPPROTO_ICMP"] {
            assert!(!NOT_A_CAPABILITY.iter().any(|s| n.contains(s)), "{n} should be kept");
        }
    }

    // The whole point of the registry read: adding a filesystem to the kernel
    // must change this number without anyone editing the stats tool.
    #[test]
    fn filesystem_names_come_from_every_registration_form() {
        let dir = std::env::temp_dir().join(format!("xtask-stats-fs-{}", std::process::id()));
        let reg = dir.join(FS_REGISTRY);
        std::fs::create_dir_all(reg.parent().unwrap()).unwrap();
        std::fs::write(&reg, "    let _ = register_fs(FsType::new(\"tmpfs\", TMPFS_MAGIC,\n\
            let _ = register_fs(FsType::with_parameters(\"proc\", PROC_SUPER_MAGIC,\n\
            pseudo!(\"bpf\", BPF_FS_MAGIC);\n\
            let _ = register_fs(FsType::new(\"ext4\", EXT4_MAGIC,\n").unwrap();
        assert_eq!(registered_filesystems(&dir), vec!["bpf", "ext4", "proc", "tmpfs"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn const_scan_keeps_literals_and_drops_derived() {
        let dir = std::env::temp_dir().join(format!("xtask-stats-af-{}", std::process::id()));
        let p = dir.join(SOCKET_ARGS);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "pub const AF_UNSPEC:  u32 = 0;\npub const AF_UNIX:    u32 = 1;\n\
            pub const AF_INET:    u32 = 2;\npub const AF_MAX:     u32 = 46;\n\
            pub const AF_UNIX_SOCK_WIRE: u16 = AF_UNIX as u16;\n").unwrap();
        assert_eq!(consts_with_prefix(&dir, SOCKET_ARGS, "AF_"), vec!["INET", "UNIX"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn caps_split_soft_and_hard() {
        let f = |p: &str, n: usize| FileStat { path: p.into(), lines: n, bytes: 0, lang: "Rust", kind: "code" };
        let c = cap_stats(&[f("a.rs", 499), f("b.rs", 500), f("c.rs", 1001)]);
        assert_eq!((c.at_soft, c.over_hard), (2, 1));
        assert_eq!(c.worst[0].0, "c.rs");
    }
}
