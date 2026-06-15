// xtask folded — build the glibc folded-lib compatibility shims (docs/59§6
// G18a). Real binaries carry DT_NEEDED on libpthread.so.0, libdl.so.2, etc.;
// in the folded-libc model all those symbols live in libc.so.6. Each shim is
// an empty shared object whose only job is DT_SONAME=<lib> + DT_NEEDED on
// libc.so.6, so the rtld resolves the name and pulls libc.
//
// Usage:
//   xtask folded          build the 6 shims for x86_64 (+ aarch64 if installed)
//   xtask folded --check  build + verify each has SONAME + NEEDED(libc.so.6)
//
// Built with rust-lld (both arches, no cross-gcc), mirroring xtask glibc/ldso.
use crate::cmds::run;
use std::path::PathBuf;
use std::process::Command;

const X86: &str = "x86_64-unknown-linux-gnu";
const ARM: &str = "aarch64-unknown-linux-gnu";

// glibc's standard folded libraries (soname → folded into libc.so.6).
const STUBS: [&str; 6] = [
    "libpthread.so.0", "libdl.so.2", "librt.so.1",
    "libm.so.6", "libutil.so.1", "libresolv.so.2",
];

pub(crate) fn cmd_folded(rest: &[String]) -> Result<(), u8> {
    let check = rest.iter().any(|a| a == "--check");
    build_arch(X86)?;
    if target_installed(ARM) { build_arch(ARM)?; }
    else { eprintln!("xtask folded: aarch64 target not installed; skipping (rustup target add {ARM})"); }
    if check { check_arch(X86)?; }
    Ok(())
}

fn outdir(triple: &str) -> PathBuf { PathBuf::from("target/folded").join(triple) }

fn build_arch(triple: &str) -> Result<(), u8> {
    // Stage libc.so.6 next to the shims so the forced DT_NEEDED resolves at
    // link time.
    crate::glibc::build_sharedlib(triple)?;
    let dir = outdir(triple);
    let _ = std::fs::create_dir_all(&dir);
    std::fs::copy(crate::glibc::sharedlib_path(triple), dir.join("libc.so.6")).map_err(|_| 1u8)?;
    let dirabs = std::fs::canonicalize(&dir).map_err(|_| 1u8)?;

    let built = PathBuf::from("target").join(triple).join("release").join("libfolded_stub.so");
    for soname in STUBS {
        eprintln!("xtask folded: building {soname} for {triple}");
        let mut c = Command::new("cargo");
        c.args(["rustc", "-p", "folded-stub", "--release", "--target", triple,
                "--crate-type", "cdylib", "--",
                "-C", "linker-flavor=ld.lld", "-C", "linker=rust-lld",
                "-C", &format!("link-arg=--soname={soname}"),
                "-C", &format!("link-arg=-L{}", dirabs.display()),
                // --no-as-needed forces the libc.so.6 DT_NEEDED even though the
                // empty stub references none of its symbols.
                "-C", "link-arg=--no-as-needed",
                "-C", "link-arg=-l:libc.so.6",
                "-C", "relocation-model=pic", "-C", "panic=abort"]);
        run(c)?;
        std::fs::copy(&built, dir.join(soname)).map_err(|_| 1u8)?;
    }
    Ok(())
}

fn check_arch(triple: &str) -> Result<(), u8> {
    let dir = outdir(triple);
    for soname in STUBS {
        let p = dir.join(soname);
        let dynamic = readelf_dynamic(&p)?;
        let has_soname = dynamic.contains("SONAME") && dynamic.contains(soname);
        let has_needed = dynamic.contains("NEEDED") && dynamic.contains("libc.so.6");
        if !has_soname || !has_needed {
            eprintln!("xtask folded: {soname} missing SONAME/NEEDED:\n{dynamic}");
            return Err(1);
        }
        eprintln!("xtask folded: {soname} OK (SONAME={soname} + NEEDED libc.so.6)");
    }
    eprintln!("xtask folded: G18a folded-lib stubs PASS");
    Ok(())
}

// Read the .dynamic section via readelf (fall back to llvm-readelf).
fn readelf_dynamic(p: &std::path::Path) -> Result<String, u8> {
    let path = p.to_str().ok_or(1u8)?;
    for tool in ["readelf", "llvm-readelf"] {
        if let Ok(out) = Command::new(tool).args(["-d", path]).output() {
            if out.status.success() { return Ok(String::from_utf8_lossy(&out.stdout).into_owned()); }
        }
    }
    eprintln!("xtask folded: no readelf/llvm-readelf available to verify {path}");
    Err(1)
}

fn target_installed(triple: &str) -> bool {
    Command::new("rustc").args(["--print", "sysroot"]).output().ok()
        .map(|o| {
            let sr = String::from_utf8_lossy(&o.stdout).trim().to_string();
            std::path::Path::new(&format!("{sr}/lib/rustlib/{triple}")).exists()
        })
        .unwrap_or(false)
}
