// Cross-build package system for oxide userspace.
//
// Each upstream we want on the rootfs (bash, util-linux, coreutils,
// nginx, …) gets one Rust recipe under `tools/xtask/src/pkg/<name>.rs`.
// A recipe is a `Recipe` struct plus a `build_and_install(ctx)` fn.
// The shared engine here drives:
//
//   xtask pkg fetch <name>     download tarball, verify sha256,
//                              extract to target/pkg-build/<name>-<v>/
//   xtask pkg build <name>     run the recipe's build_and_install
//                              (configure + make + copy to staging)
//   xtask pkg install <name>   alias for build (current single-step)
//   xtask pkg list             show available recipes + cache state
//
// Outputs land in target/pkg-staging/<name>/<rootfs-prefixed-paths>.
// `xtask rootfs` walks every directory under target/pkg-staging/ and
// copies its contents into the ext4 image at the matching paths, so
// adding a recipe automatically lands its artifacts on the next
// rootfs build.
//
// Why per-recipe Rust files instead of TOML manifests:
//   - configure/make idioms vary too much between projects (bash's
//     --without-bash-malloc, util-linux's --disable-makeinstall-chown,
//     etc). A typed Rust API makes the shape explicit.
//   - every recipe ends up depending on the same core helpers
//     (`musl_gcc_env`, `run_in`, `install_to_staging`) — Rust gives
//     us code reuse + compiler checks for free.

use std::path::{Path, PathBuf};
use std::process::Command;

mod bash;

/// All known recipes. New package = new module + new entry here.
fn recipes() -> Vec<Box<dyn Recipe>> {
    vec![
        Box::new(bash::Bash),
    ]
}

/// One install entry: copy `host` (under target/pkg-build/<name>-<v>/)
/// into target/pkg-staging/<name>/<dst>, with the given mode.
/// `dst` is rootfs-absolute (e.g. "/bin/bash").
pub struct InstallSpec {
    pub host: PathBuf,
    pub dst:  &'static str,
    pub mode: u32,
}

/// Static metadata for a recipe.
pub struct Meta {
    pub name:        &'static str,
    pub version:     &'static str,
    /// HTTPS URL to a tarball (.tar.gz, .tar.xz, .tar.bz2).
    pub url:         &'static str,
    /// Expected SHA-256 of the tarball, lowercase hex.
    pub sha256:      &'static str,
    /// Top-level directory inside the tarball after extract (often
    /// "<name>-<version>"). Engine cd's into this.
    pub extract_dir: &'static str,
}

pub trait Recipe {
    fn meta(&self) -> Meta;
    /// Run inside `target/pkg-build/<extract_dir>/` after fetch+extract.
    /// Run configure/make and emit the install specs.
    fn build_and_install(&self, ctx: &Ctx) -> Result<Vec<InstallSpec>, u8>;
}

pub struct Ctx {
    pub repo:        PathBuf,
    pub cache_dir:   PathBuf,
    pub build_dir:   PathBuf,
    pub staging_dir: PathBuf,
}

impl Ctx {
    fn new() -> Self {
        let repo = crate::image_qemu::repo_root();
        let cache   = repo.join("target/pkg-cache");
        let build   = repo.join("target/pkg-build");
        let staging = repo.join("target/pkg-staging");
        for d in [&cache, &build, &staging] {
            let _ = std::fs::create_dir_all(d);
        }
        Ctx { repo, cache_dir: cache, build_dir: build, staging_dir: staging }
    }
}

pub fn cmd(args: &[String]) -> Result<(), u8> {
    let sub = args.get(0).map(|s| s.as_str()).unwrap_or("");
    let rest: Vec<String> = args.iter().skip(1).cloned().collect();
    match sub {
        "list"             => list(),
        "fetch"            => with_recipe(&rest, |r, ctx| fetch(r, ctx)),
        "build" | "install" => with_recipe(&rest, |r, ctx| build(r, ctx)),
        "" => {
            eprintln!("usage: xtask pkg <list|fetch|build|install> [name]");
            Err(2)
        }
        other => {
            eprintln!("xtask pkg: unknown sub `{other}`");
            Err(2)
        }
    }
}

fn list() -> Result<(), u8> {
    let ctx = Ctx::new();
    for r in recipes() {
        let m = r.meta();
        let cached = ctx.cache_dir.join(tarball_name(&m)).exists();
        let staged = ctx.staging_dir.join(m.name).exists();
        println!("  {:<14} {:<10} cache={}  staged={}", m.name, m.version, cached, staged);
    }
    Ok(())
}

fn with_recipe<F>(rest: &[String], f: F) -> Result<(), u8>
where F: FnOnce(&dyn Recipe, &Ctx) -> Result<(), u8>
{
    let name = rest.get(0).ok_or_else(|| {
        eprintln!("xtask pkg: name required");
        2u8
    })?;
    let recs = recipes();
    let r = recs.iter().find(|r| r.meta().name == name).ok_or_else(|| {
        eprintln!("xtask pkg: no recipe `{name}`. Try `xtask pkg list`.");
        2u8
    })?;
    let ctx = Ctx::new();
    f(r.as_ref(), &ctx)
}

fn tarball_name(m: &Meta) -> String {
    // Last path component of url (after the last '/').
    m.url.rsplit('/').next().unwrap_or(m.url).to_string()
}

/// Download (if needed) + sha256-verify + extract into build_dir.
/// Idempotent: re-runs are no-ops once `extract_dir` already exists.
pub fn fetch(r: &dyn Recipe, ctx: &Ctx) -> Result<(), u8> {
    let m = r.meta();
    let tar = ctx.cache_dir.join(tarball_name(&m));
    let extract = ctx.build_dir.join(m.extract_dir);

    if !tar.exists() {
        eprintln!("pkg {}: fetch {}", m.name, m.url);
        let mut c = Command::new("curl");
        c.args(["-fL", "--retry", "3", "-o", tar.to_str().unwrap(), m.url]);
        run(c)?;
    }

    eprintln!("pkg {}: verify sha256", m.name);
    let out = Command::new("sha256sum").arg(&tar).output().map_err(|e| {
        eprintln!("sha256sum: {e}");
        1u8
    })?;
    let line = String::from_utf8_lossy(&out.stdout);
    let actual = line.split_whitespace().next().unwrap_or("");
    if actual != m.sha256 {
        eprintln!(
            "pkg {}: sha256 mismatch\n  expected: {}\n  actual:   {}\n  (delete {} and re-run if upstream changed; otherwise update the recipe)",
            m.name, m.sha256, actual, tar.display()
        );
        return Err(1);
    }

    if !extract.exists() {
        eprintln!("pkg {}: extract → {}", m.name, extract.display());
        let mut c = Command::new("tar");
        c.args(["-xf", tar.to_str().unwrap(), "-C", ctx.build_dir.to_str().unwrap()]);
        run(c)?;
    }
    Ok(())
}

/// Run the recipe's build_and_install + copy outputs into the
/// per-pkg staging tree. Re-running builds always re-installs.
pub fn build(r: &dyn Recipe, ctx: &Ctx) -> Result<(), u8> {
    fetch(r, ctx)?;
    let m = r.meta();
    eprintln!("pkg {}: build", m.name);
    let installs = r.build_and_install(ctx)?;
    let pkg_stage = ctx.staging_dir.join(m.name);
    let _ = std::fs::remove_dir_all(&pkg_stage);
    std::fs::create_dir_all(&pkg_stage).map_err(|_| 1u8)?;
    for inst in installs {
        let dst_rel = inst.dst.trim_start_matches('/');
        let dst = pkg_stage.join(dst_rel);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent).map_err(|_| 1u8)?;
        }
        std::fs::copy(&inst.host, &dst).map_err(|e| {
            eprintln!("pkg {}: copy {} → {}: {e}", m.name, inst.host.display(), dst.display());
            1u8
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(inst.mode));
        }
        eprintln!("pkg {}: staged {}", m.name, inst.dst);
    }
    Ok(())
}

/// Walk every directory under target/pkg-staging/<name>/ and copy
/// its tree into the ext4 image via debugfs. Called by xtask rootfs.
/// `dbg` is the closure rootfs() uses to invoke debugfs commands.
pub fn install_all_into_rootfs<F>(repo: &Path, mut dbg: F) -> Result<(), u8>
where F: FnMut(&str) -> Result<(), u8>
{
    let staging = repo.join("target/pkg-staging");
    if !staging.exists() { return Ok(()); }
    let entries = std::fs::read_dir(&staging).map_err(|_| 1u8)?;
    for ent in entries.flatten() {
        let pkg_dir = ent.path();
        if !pkg_dir.is_dir() { continue; }
        eprintln!("xtask rootfs: install pkg {}", pkg_dir.file_name().unwrap().to_string_lossy());
        walk_and_install(&pkg_dir, &pkg_dir, &mut dbg)?;
    }
    Ok(())
}

fn walk_and_install<F>(root: &Path, cur: &Path, dbg: &mut F) -> Result<(), u8>
where F: FnMut(&str) -> Result<(), u8>
{
    for ent in std::fs::read_dir(cur).map_err(|_| 1u8)?.flatten() {
        let p = ent.path();
        let rel = p.strip_prefix(root).map_err(|_| 1u8)?;
        let target = format!("/{}", rel.to_string_lossy());
        if p.is_dir() {
            // mkdir on the target side; ignore "already exists".
            let _ = dbg(&format!("mkdir {target}"));
            walk_and_install(root, &p, dbg)?;
        } else {
            dbg(&format!("write {} {target}", p.display()))?;
        }
    }
    Ok(())
}

/// Helpers exported to recipes.

pub fn run_in(cwd: &Path, mut c: Command) -> Result<(), u8> {
    c.current_dir(cwd);
    run(c)
}

pub fn musl_gcc_env() -> Vec<(&'static str, String)> {
    // -std=gnu89 + -Wno-error keep older K&R-style sources (bash,
    // util-linux) compiling on modern gcc. -fcommon restores the
    // pre-gcc-10 behaviour for tentative defs that some autotools
    // packages still rely on.
    vec![
        ("CC",      "musl-gcc".into()),
        ("HOSTCC",  "cc".into()),
        ("CFLAGS",  "-O2 -static -fno-pie -fno-pic -std=gnu89 -fcommon -Wno-implicit-int -Wno-implicit-function-declaration -Wno-error".into()),
        ("LDFLAGS", "-static".into()),
    ]
}

fn run(mut c: Command) -> Result<(), u8> {
    let st = c.status().map_err(|e| {
        eprintln!("spawn {:?}: {e}", c);
        1u8
    })?;
    if !st.success() {
        eprintln!("command failed: {:?} → {st}", c);
        return Err(st.code().unwrap_or(1) as u8);
    }
    Ok(())
}
