// xtask gc — reclaim dead build namespaces + LRU-trim the rootfs cache.
//
// Build namespacing (buildns.rs) leaks per-id dirs under `target/builds/<id>`
// (C90: the ONE scheme — every build, incl. the no-id `default`, lives here)
// when xtask is driven directly (not via the MCP, which has its own GC). The
// content-addressed rootfs cache (rootfs_cache.rs) at
// `target/rootfs-cache/{root,home}-<hash>-<arch>.img` grows unbounded (one pair
// per distinct input hash). `gc` reclaims both.
//
// RESERVED: `target/builds/default` is the active default build (the no-id
// namespace) and is NEVER reclaimed, exactly as the cache dir is reserved.
//
// HARD GUARD: `remove_dir_all` is only ever called on a path whose `<id>`
// passes `buildns::validate` AND whose canonicalized parent is exactly
// `target/builds`; `remove_file` only on entries directly inside
// `target/rootfs-cache`. The roots themselves are NEVER removed. This
// mirrors the MCP's `_rmtree_namespace` resolved-parent assertion.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use crate::cmds::{parse_arg, run};
use crate::image_qemu::repo_root;

/// `xtask gc [--keep N] [--cache-keep M] [--all] [--dry-run]`.
pub(crate) fn cmd_gc(rest: &[String]) -> Result<(), u8> {
    let repo = repo_root();
    let all = rest.iter().any(|a| a == "--all");
    let dry = rest.iter().any(|a| a == "--dry-run");
    let keep: usize = parse_arg(rest, "--keep").and_then(|s| s.parse().ok()).unwrap_or(2);
    let cache_keep: usize = parse_arg(rest, "--cache-keep").and_then(|s| s.parse().ok()).unwrap_or(4);

    let builds_root = repo.join("target/builds");
    let cache_root = repo.join("target/rootfs-cache");

    let mut freed: u64 = 0;
    let mut reclaimed: Vec<String> = Vec::new();
    let mut trimmed: Vec<String> = Vec::new();

    // ---- Namespaces ------------------------------------------------------
    let ids = enumerate_namespaces(&builds_root);
    // Protected-by-recency set (skip when --all): the `keep` most recent by dir
    // mtime. `default` is ALWAYS reserved (never reclaimed), like `cache`.
    let recent: BTreeSet<String> = if all { BTreeSet::new() } else {
        let mut by_mtime: Vec<(u128, String)> = ids.iter()
            .map(|id| (dir_mtime(&builds_root.join(id)), id.clone())).collect();
        by_mtime.sort_by(|x, y| y.0.cmp(&x.0)); // newest first
        by_mtime.into_iter().take(keep).map(|(_, id)| id).collect()
    };

    for id in &ids {
        if id == "default" { continue; } // reserved active default build
        if !all {
            if recent.contains(id) { continue; }
            if live_marker_protects(&builds_root.join(id)) { continue; }
        }
        let p = builds_root.join(id);
        if p.is_dir() {
            freed += tree_bytes(&p);
            if dry { eprintln!("xtask gc: would reclaim {}", p.display()); }
            else { guarded_rmtree(&builds_root, id, &p)?; }
            reclaimed.push(id.clone());
        }
    }

    // ---- Rootfs cache LRU ------------------------------------------------
    if all {
        if let Ok(rd) = std::fs::read_dir(&cache_root) {
            for ent in rd.flatten() {
                let p = ent.path();
                if p.is_file() {
                    freed += std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                    let name = ent.file_name().to_string_lossy().into_owned();
                    if dry { eprintln!("xtask gc: would delete cache/{name}"); }
                    else { guarded_rmfile(&cache_root, &p)?; }
                    trimmed.push(name);
                }
            }
        }
    } else {
        trim_cache(&cache_root, cache_keep, dry, &mut freed, &mut trimmed)?;
    }

    println!("xtask gc: reclaimed {} namespace(s){}: {}",
             reclaimed.len(), if dry { " (dry-run)" } else { "" },
             if reclaimed.is_empty() { "-".into() } else { reclaimed.join(", ") });
    println!("xtask gc: trimmed {} cache entr(ies){}: {}",
             trimmed.len(), if dry { " (dry-run)" } else { "" },
             if trimmed.is_empty() { "-".into() } else { trimmed.join(", ") });
    println!("xtask gc: ~{} freed{}", human(freed), if dry { " (dry-run)" } else { "" });
    Ok(())
}

/// Namespace ids = directory names directly under `target/builds/`, EXCLUDING
/// the reserved `default` namespace (the active no-id build) and any name that
/// fails `buildns::validate`. `target/builds/*` is always gitignored, so every
/// valid subdir is a build namespace.
fn enumerate_namespaces(builds_root: &Path) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    if let Ok(rd) = std::fs::read_dir(builds_root) {
        for ent in rd.flatten() {
            if ent.path().is_dir() {
                let name = ent.file_name().to_string_lossy().into_owned();
                if name == "default" { continue; } // reserved active default build
                if crate::buildns::validate(&name).is_ok() { set.insert(name); }
            }
        }
    }
    set.into_iter().collect()
}

/// A `.live` marker protects iff it exists AND at least one listed PID is
/// alive (`/proc/<pid>` exists). Stale (all dead) or absent → not protected.
fn live_marker_protects(build_dir: &Path) -> bool {
    let marker = build_dir.join(".live");
    let txt = match std::fs::read_to_string(&marker) { Ok(t) => t, Err(_) => return false };
    txt.split_whitespace().any(|tok| {
        tok.parse::<u32>().ok().is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists())
    })
}

/// LRU-trim cache: keep the `keep` newest `root-*-<arch>.img` (and their
/// paired `home-*`) by mtime across BOTH arches; delete older pairs.
fn trim_cache(cache_root: &Path, keep: usize, dry: bool, freed: &mut u64, trimmed: &mut Vec<String>) -> Result<(), u8> {
    let rd = match std::fs::read_dir(cache_root) { Ok(r) => r, Err(_) => return Ok(()) };
    // (mtime, suffix) where suffix = "<hash>-<arch>.img" — identifies a pair.
    let mut roots: Vec<(u128, String)> = Vec::new();
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if let Some(suffix) = name.strip_prefix("root-") {
            if name.ends_with(".img") {
                let mt = file_mtime(&ent.path());
                roots.push((mt, suffix.to_string()));
            }
        }
    }
    roots.sort_by(|a, b| b.0.cmp(&a.0)); // newest first
    for (_, suffix) in roots.into_iter().skip(keep) {
        for prefix in ["root-", "home-"] {
            let name = format!("{prefix}{suffix}");
            let p = cache_root.join(&name);
            if p.is_file() {
                *freed += std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                if dry { eprintln!("xtask gc: would delete cache/{name}"); }
                else { guarded_rmfile(cache_root, &p)?; }
                trimmed.push(name);
            }
        }
    }
    Ok(())
}

// --- HARD GUARD -----------------------------------------------------------

/// `remove_dir_all(<root>/<id>)` ONLY when: `<id>` passes `buildns::validate`,
/// `target` == `<root>/<id>`, and `target.parent()` canonicalizes to exactly
/// `<root>`. Never removes `<root>` itself.
fn guarded_rmtree(root: &Path, id: &str, target: &Path) -> Result<(), u8> {
    crate::buildns::validate(id)?;
    if target != root.join(id) {
        eprintln!("xtask gc: GUARD: {} != {}/{id}", target.display(), root.display());
        return Err(1);
    }
    let parent = match target.parent() { Some(p) => p, None => { eprintln!("xtask gc: GUARD: no parent"); return Err(1); } };
    let cparent = parent.canonicalize().map_err(|e| { eprintln!("xtask gc: GUARD canon {}: {e}", parent.display()); 1u8 })?;
    let croot = root.canonicalize().map_err(|e| { eprintln!("xtask gc: GUARD canon {}: {e}", root.display()); 1u8 })?;
    if cparent != croot {
        eprintln!("xtask gc: GUARD: parent {} != root {}", cparent.display(), croot.display());
        return Err(1);
    }
    std::fs::remove_dir_all(target).map_err(|e| { eprintln!("xtask gc: rm {}: {e}", target.display()); 1u8 })?;
    Ok(())
}

/// `remove_file(p)` ONLY when `p`'s parent canonicalizes to exactly the cache
/// dir and `p` is a regular file. Never removes the cache dir itself.
fn guarded_rmfile(cache_root: &Path, p: &Path) -> Result<(), u8> {
    if !p.is_file() { eprintln!("xtask gc: GUARD: {} not a file", p.display()); return Err(1); }
    let parent = match p.parent() { Some(x) => x, None => { eprintln!("xtask gc: GUARD: no parent"); return Err(1); } };
    let cparent = parent.canonicalize().map_err(|e| { eprintln!("xtask gc: GUARD canon {}: {e}", parent.display()); 1u8 })?;
    let croot = cache_root.canonicalize().map_err(|e| { eprintln!("xtask gc: GUARD canon {}: {e}", cache_root.display()); 1u8 })?;
    if cparent != croot {
        eprintln!("xtask gc: GUARD: parent {} != cache {}", cparent.display(), croot.display());
        return Err(1);
    }
    std::fs::remove_file(p).map_err(|e| { eprintln!("xtask gc: rm {}: {e}", p.display()); 1u8 })?;
    Ok(())
}

// --- helpers --------------------------------------------------------------

fn dir_mtime(p: &Path) -> u128 {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos()).unwrap_or(0)
}
fn file_mtime(p: &Path) -> u128 { dir_mtime(p) }

/// Recursive byte count of a directory tree (best-effort; unstat-able skipped).
fn tree_bytes(p: &Path) -> u64 {
    let mut total = 0u64;
    let md = match std::fs::symlink_metadata(p) { Ok(m) => m, Err(_) => return 0 };
    if md.is_dir() {
        if let Ok(rd) = std::fs::read_dir(p) {
            for ent in rd.flatten() { total += tree_bytes(&ent.path()); }
        }
    } else if md.is_file() {
        total += md.len();
    }
    total
}

fn human(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64; let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 { v /= 1024.0; i += 1; }
    if i == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", U[i]) }
}

// --- vendor rebuild -------------------------------------------------------

/// Parse `--rebuild-vendor[=pkg,...]` and, when present, run
/// `bash vendor/<pkg>/build.sh <arch>` for each requested pkg BEFORE staging.
/// Presence with no `=value` rebuilds all 46 vendor deps (every `vendor/*`
/// with a `build.sh`). A bad pkg name errors before any build runs.
pub(crate) fn rebuild_vendor(repo: &Path, arch: &str, rest: &[String]) -> Result<(), u8> {
    let present = rest.iter().any(|a| a == "--rebuild-vendor" || a.starts_with("--rebuild-vendor="));
    if !present { return Ok(()); }
    let pkgs: Vec<String> = match parse_arg(rest, "--rebuild-vendor") {
        Some(list) => list.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect(),
        None => all_vendor_pkgs(repo),
    };
    if pkgs.is_empty() { eprintln!("xtask: --rebuild-vendor: no vendor packages found"); return Err(2); }
    // Validate ALL names first (no partial builds on a typo).
    for pkg in &pkgs {
        let sh = repo.join("vendor").join(pkg).join("build.sh");
        if !sh.is_file() {
            eprintln!("xtask: --rebuild-vendor: vendor/{pkg}/build.sh not found");
            return Err(2);
        }
    }
    for pkg in &pkgs {
        let sh = repo.join("vendor").join(pkg).join("build.sh");
        eprintln!("xtask: --rebuild-vendor: bash {} {arch}", sh.display());
        let mut c = Command::new("bash");
        c.arg(sh.to_str().unwrap()).arg(arch);
        run(c)?;
    }
    Ok(())
}

/// Every `vendor/*` dir carrying a `build.sh`, sorted.
fn all_vendor_pkgs(repo: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(repo.join("vendor")) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.join("build.sh").is_file() {
                out.push(ent.file_name().to_string_lossy().into_owned());
            }
        }
    }
    out.sort();
    out
}
