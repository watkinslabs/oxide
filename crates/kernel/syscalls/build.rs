// Produce the vDSO images the crate compiles in.
//
// `src/vdso.rs` and `src/vdso_elf.rs` both `include_bytes!` an ELF out of
// `vdso/`, and those blobs are gitignored build artifacts. Nothing in a normal
// `cargo` invocation used to make them: only `xtask kernel` ran `vdso/build.sh`,
// and only for the one arch it was building. So `cargo test -p syscalls`
// compiled in a directory where somebody had happened to run that script and
// failed everywhere else — a fresh clone, a new worktree, CI on a clean
// checkout. The vDSO tests were therefore checked by luck of the build
// directory, which for a walk that indexes at offsets read out of the buffer it
// is walking is barely better than never having compiled.
//
// The images are a product of building this crate, for BOTH arches on every
// host, because the aarch64 contract is checked by a hosted test that no
// aarch64 kernel build ever runs. A missing cross toolchain fails the build
// with an actionable message (see `vdso/build.sh`); it never silently drops an
// image, which would take the test with it.
//
// Staging: the script writes into `OUT_DIR/vdso-stage` and the result is moved
// into place, so a concurrent compile never reads a half-written blob.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;
use std::{env, fs};

const SHARED: [&str; 2] = ["build.sh", "vdso.lds"];
const ARCHES: [&str; 2] = ["x86_64", "aarch64"];

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("vdso");
    let stage = PathBuf::from(env::var("OUT_DIR").unwrap()).join("vdso-stage");
    for f in SHARED { rerun(&dir.join(f)); }
    for a in ARCHES { for f in sources(a) { rerun(&dir.join(f)); } }
    for a in ARCHES { ensure(&dir, &stage, a); }
}

fn rerun(p: &Path) { println!("cargo:rerun-if-changed={}", p.display()); }

fn sources(arch: &str) -> [String; 2] { [format!("vdso-{arch}.S"), format!("vdso-{arch}.map")] }

fn mtime(p: &Path) -> Option<SystemTime> { fs::metadata(p).ok()?.modified().ok() }

/// Rebuild `vdso-<arch>.so` when it is missing or older than any of its
/// sources. Up to date is the common case and costs a few `stat` calls.
fn ensure(dir: &Path, stage: &Path, arch: &str) {
    let out = dir.join(format!("vdso-{arch}.so"));
    let mut inputs: Vec<PathBuf> = SHARED.iter().map(|f| dir.join(f)).collect();
    inputs.extend(sources(arch).iter().map(|f| dir.join(f)));
    let newest = inputs.iter().filter_map(|p| mtime(p)).max();
    if let (Some(have), Some(src)) = (mtime(&out), newest) {
        if have >= src { return; }
    }
    println!("cargo:warning=syscalls: building vdso-{arch}.so (missing or stale)");
    fs::create_dir_all(stage).unwrap_or_else(|e| fail(format!("vdso: create {}: {e}", stage.display())));
    let st = Command::new("sh")
        .arg(dir.join("build.sh"))
        .arg(arch)
        .env("VDSO_OUT", stage)
        .status()
        .unwrap_or_else(|e| fail(format!("vdso: cannot run vdso/build.sh: {e}")));
    if !st.success() { fail(format!("vdso: vdso/build.sh {arch} failed ({st}) — see the message above")); }
    let built = stage.join(format!("vdso-{arch}.so"));
    install(&built, &out);
}

/// Move the staged image over the consumed one. A rename is atomic within a
/// filesystem; a copy covers `OUT_DIR` living on another one.
fn install(from: &Path, to: &Path) {
    if fs::rename(from, to).is_ok() { return; }
    fs::copy(from, to).unwrap_or_else(|e| {
        fail(format!("vdso: install {} -> {}: {e}", from.display(), to.display()))
    });
}

/// Fail the build with a message. Cargo prints a build script's stderr when it
/// exits non-zero, so the reason reaches the person building.
fn fail(msg: String) -> ! { eprintln!("{msg}"); std::process::exit(1); }
