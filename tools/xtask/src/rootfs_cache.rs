// Content-addressed cache for the assembled rootfs DISK images
// (root-<arch>.img + home-<arch>.img). A kernel-only iteration reuses the
// cached image instead of re-running the slow ~50-app debugfs restage.
//
// Cache store: kernel/blobs/cache/{root,home}-<hash>-<arch>.img
// `cache/` is SHARED (not a per-id namespace); the MCP's per-id GC targets
// only `kernel/blobs/<id>` direct children, and `cache` is just another such
// name — its GC must SKIP `cache/`. `cache/` is LRU-managed separately
// (future work); nothing here prunes it yet.
//
// Fingerprint model (like cargo): hash (path,len,mtime_nanos) over the inputs,
// NOT file contents (too slow over GBs of vendor binaries). A change to any
// staged input or to the staging logic itself busts the cache.

use std::path::{Path, PathBuf};

/// Outcome of the pre-build cache check.
pub(crate) enum Plan { Skip, Build }

/// Pre-stage gate for `cmd_rootfs`. Handles --skip-rootfs / OXIDE_SKIP_ROOTFS,
/// the cache HIT/MISS decision, and the MISS/HIT eprintln!s. Returns Skip when
/// the dest is already satisfied (caller returns Ok), else Build (caller
/// stages, then calls `store_to_cache` with this same `arch`).
///
/// OXIDE_STUB_BLOBS short-circuits ALL cache logic (returns Build, no hash) so
/// CI's stub-blob behavior is byte-for-byte unchanged.
pub(crate) fn pre_build(repo: &Path, blobs: &Path, arch: &str, rest: &[String]) -> Result<Plan, u8> {
    if std::env::var_os("OXIDE_STUB_BLOBS").is_some() { return Ok(Plan::Build); }
    let has = |f: &str| rest.iter().any(|a| a == f);
    let rebuild = has("--rebuild-rootfs");
    let skip = has("--skip-rootfs") || std::env::var_os("OXIDE_SKIP_ROOTFS").is_some();
    let dest_root = blobs.join(format!("root-{arch}.img"));

    if skip && dest_root.is_file() {
        eprintln!("xtask rootfs: --skip-rootfs — reusing existing {} (no restage)", dest_root.display());
        return Ok(Plan::Skip);
    }
    if rebuild {
        eprintln!("xtask rootfs: --rebuild-rootfs — staging (cache overwrite)");
        return Ok(Plan::Build);
    }
    let hash = input_hash(repo, arch);
    if cache_present(repo, &hash, arch) {
        eprintln!("xtask rootfs: cache HIT {hash} — cp (no restage)");
        copy_from_cache(repo, blobs, &hash, arch)?;
        return Ok(Plan::Skip);
    }
    eprintln!("xtask rootfs: cache MISS {hash} — staging");
    Ok(Plan::Build)
}

/// Post-stage store: copy the freshly-built dest root+home images into the
/// cache (no-op under OXIDE_STUB_BLOBS). Recomputes the input hash — inputs
/// are unchanged across a single build, so it matches the pre_build hash.
pub(crate) fn post_build(repo: &Path, blobs: &Path, arch: &str) {
    if std::env::var_os("OXIDE_STUB_BLOBS").is_some() { return; }
    let hash = input_hash(repo, arch);
    eprintln!("xtask rootfs: cache STORE {hash}");
    store_to_cache(repo, blobs, &hash, arch);
}

/// Cache dir: `kernel/blobs/cache` (shared across ids).
pub(crate) fn cache_dir(repo: &Path) -> PathBuf { repo.join("kernel/blobs/cache") }

fn root_cache_path(repo: &Path, hash: &str, arch: &str) -> PathBuf {
    cache_dir(repo).join(format!("root-{hash}-{arch}.img"))
}
fn home_cache_path(repo: &Path, hash: &str, arch: &str) -> PathBuf {
    cache_dir(repo).join(format!("home-{hash}-{arch}.img"))
}

/// True iff both cache images for `hash`/`arch` exist.
pub(crate) fn cache_present(repo: &Path, hash: &str, arch: &str) -> bool {
    root_cache_path(repo, hash, arch).is_file() && home_cache_path(repo, hash, arch).is_file()
}

/// Copy cached root+home images to the destination blob dir (cache HIT).
/// Copy (NOT hardlink): boot mounts the image writable, so each build needs
/// its own copy; the cache copy stays pristine.
pub(crate) fn copy_from_cache(repo: &Path, blobs: &Path, hash: &str, arch: &str) -> Result<(), u8> {
    let cp = |src: &Path, dst: &Path| -> Result<(), u8> {
        std::fs::copy(src, dst).map(|_| ()).map_err(|e| {
            eprintln!("xtask rootfs: cache copy {} -> {}: {e}", src.display(), dst.display()); 1u8
        })
    };
    cp(&root_cache_path(repo, hash, arch), &blobs.join(format!("root-{arch}.img")))?;
    cp(&home_cache_path(repo, hash, arch), &blobs.join(format!("home-{arch}.img")))?;
    Ok(())
}

/// Copy the freshly-built dest root+home images INTO the cache (cache MISS
/// store, or --rebuild-rootfs overwrite). Failures are non-fatal: a populated
/// dest is what the build needs; a missing cache entry only costs the next
/// build a restage.
pub(crate) fn store_to_cache(repo: &Path, blobs: &Path, hash: &str, arch: &str) {
    let dir = cache_dir(repo);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("xtask rootfs: cache mkdir {}: {e} (skipping store)", dir.display()); return;
    }
    let cp = |src: PathBuf, dst: PathBuf| {
        if let Err(e) = std::fs::copy(&src, &dst) {
            eprintln!("xtask rootfs: cache store {} -> {}: {e}", src.display(), dst.display());
        }
    };
    cp(blobs.join(format!("root-{arch}.img")), root_cache_path(repo, hash, arch));
    cp(blobs.join(format!("home-{arch}.img")), home_cache_path(repo, hash, arch));
}

/// FNV-1a/64 streaming hasher (dependency-free; xtask has no hash crate).
struct Fnv64(u64);
impl Fnv64 {
    fn new() -> Self { Fnv64(0xcbf29ce484222325) }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes { self.0 ^= b as u64; self.0 = self.0.wrapping_mul(0x100000001b3); }
    }
    fn hex(&self) -> String {
        let mut s = String::with_capacity(16);
        for i in (0..8).rev() { s.push_str(&format!("{:02x}", (self.0 >> (i * 8)) as u8)); }
        s
    }
}

/// Input fingerprint over the rootfs INPUTS (sorted, deterministic):
/// - vendor/*/install-<arch>/**     (staged vendor binaries/libs — image bulk)
/// - userspace/**                    (the .c sources compiled into the image)
/// - assets/** (if present)          (staged configs)
/// - the xtask rootfs SOURCE files   (so staging-logic changes bust the cache):
///   rootfs.rs, rootfs_disks.rs, rootfs_lists.rs, l2_deps.rs, rootfs_dynprobe.rs
///
/// Per entry hashes (relative-path, len, mtime_nanos) — NOT contents.
pub(crate) fn input_hash(repo: &Path, arch: &str) -> String {
    // Collect (rel_path, len, mtime_nanos), then sort for determinism.
    let mut entries: Vec<(String, u64, u128)> = Vec::new();

    // vendor/*/install-<arch>/** — one install dir per vendor.
    let suffix = format!("install-{arch}");
    if let Ok(rd) = std::fs::read_dir(repo.join("vendor")) {
        let mut vendors: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        vendors.sort();
        for v in vendors {
            let inst = v.join(&suffix);
            if inst.is_dir() { walk(repo, &inst, &mut entries); }
        }
    }
    // userspace/** and assets/** (assets optional).
    walk(repo, &repo.join("userspace"), &mut entries);
    let assets = repo.join("assets");
    if assets.is_dir() { walk(repo, &assets, &mut entries); }

    // xtask rootfs staging-logic sources.
    for src in &["tools/xtask/src/rootfs.rs", "tools/xtask/src/rootfs_disks.rs",
                 "tools/xtask/src/rootfs_lists.rs", "tools/xtask/src/l2_deps.rs",
                 "tools/xtask/src/rootfs_dynprobe.rs"] {
        push_file(repo, &repo.join(src), &mut entries);
    }

    entries.sort();
    let mut h = Fnv64::new();
    h.write(arch.as_bytes());
    for (p, len, mt) in &entries {
        h.write(p.as_bytes()); h.write(&[0]);
        h.write(&len.to_le_bytes());
        h.write(&mt.to_le_bytes());
    }
    h.hex()
}

/// Record one file's (rel-path, len, mtime_nanos). Missing/unstat-able files
/// are skipped (their absence is itself reflected by the missing entry).
fn push_file(repo: &Path, p: &Path, out: &mut Vec<(String, u64, u128)>) {
    let md = match std::fs::metadata(p) { Ok(m) => m, Err(_) => return };
    if !md.is_file() { return; }
    let rel = p.strip_prefix(repo).unwrap_or(p).to_string_lossy().into_owned();
    let mt = md.modified().ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos()).unwrap_or(0);
    out.push((rel, md.len(), mt));
}

/// Recursively walk `dir` in sorted order, recording every regular file.
fn walk(repo: &Path, dir: &Path, out: &mut Vec<(String, u64, u128)>) {
    let rd = match std::fs::read_dir(dir) { Ok(r) => r, Err(_) => return };
    let mut kids: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    kids.sort();
    for k in kids {
        let md = match std::fs::symlink_metadata(&k) { Ok(m) => m, Err(_) => continue };
        if md.is_dir() { walk(repo, &k, out); }
        else if md.is_file() { push_file(repo, &k, out); }
        // symlinks: skip (vendor install dirs may carry soname symlinks; their
        // targets are regular files already counted — counting the link too
        // would just be redundant, and dangling links would error).
    }
}
