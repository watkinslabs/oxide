// xtask sysroot — publish a glibc sysroot (docs/59§6 G18c). Lays out, per
// arch, target/sysroot/<triple>/ with the rtld, libc.so.6, libc.a, the 6
// folded-lib shims and a generated /etc/ld.so.cache — enough for a vendor
// cross-build to `--sysroot` link against. This closes G18.
//
// Usage:
//   xtask sysroot          build + lay out the sysroot for x86_64 (+ aarch64)
//   xtask sysroot --check  also: static-link + dynamic-link smokes against it,
//                          and verify the cache resolves via the rtld reader.
use crate::cmds::run;
use std::path::{Path, PathBuf};
use std::process::Command;

const X86: &str = "x86_64-unknown-linux-gnu";
const ARM: &str = "aarch64-unknown-linux-gnu";

fn ld_soname(triple: &str) -> &'static str {
    if triple == ARM { "ld-linux-aarch64.so.1" } else { "ld-linux-x86-64.so.2" }
}

pub(crate) fn cmd_sysroot(rest: &[String]) -> Result<(), u8> {
    let check = rest.iter().any(|a| a == "--check");
    build_sysroot(X86)?;
    if target_installed(ARM) { build_sysroot(ARM)?; }
    else { eprintln!("xtask sysroot: aarch64 target not installed; skipping (rustup target add {ARM})"); }
    if check { check_x86()?; }
    Ok(())
}

fn root_dir(triple: &str) -> PathBuf { PathBuf::from("target/sysroot").join(triple) }

fn build_sysroot(triple: &str) -> Result<(), u8> {
    eprintln!("xtask sysroot: building artifacts for {triple}");
    crate::glibc::build_staticlib(triple)?;
    crate::glibc::build_sharedlib(triple)?;
    crate::ldso::build_ldso(triple, ld_soname(triple))?;
    crate::folded::build_arch(triple)?; // → target/folded/<triple>/<stub>

    let root = root_dir(triple);
    let lib = root.join("lib");
    let etc = root.join("etc");
    for d in [&lib, &etc, &root.join("usr/include")] { std::fs::create_dir_all(d).map_err(|_| 1u8)?; }

    let ldso = ld_soname(triple);
    copy(&crate::ldso::ldso_path(triple), &lib.join(ldso))?;
    copy(&crate::glibc::sharedlib_path(triple), &lib.join("libc.so.6"))?;
    copy(&crate::glibc::staticlib_path(triple), &lib.join("libc.a"))?;
    let folded = crate::folded::outdir(triple);
    for stub in crate::folded::STUBS { copy(&folded.join(stub), &lib.join(stub))?; }

    // /etc/ld.so.cache mapping each soname → its installed /lib path.
    let cache = build_cache_image(ldso);
    std::fs::write(etc.join("ld.so.cache"), &cache).map_err(|_| 1u8)?;

    eprintln!("xtask sysroot: laid out {}", root.display());
    print_tree(&root);
    Ok(())
}

// (soname, "/lib/<soname>", FLAG_ELF_LIBC6) for libc + ld-linux + the stubs.
fn build_cache_image(ldso: &str) -> Vec<u8> {
    const LIBC6: i32 = 0x0001; // FLAG_ELF_LIBC6
    let mut names: Vec<String> = std::vec!["libc.so.6".into(), ldso.into()];
    for s in crate::folded::STUBS { names.push(s.to_string()); }
    let paths: Vec<String> = names.iter().map(|n| std::format!("/lib/{n}")).collect();
    let entries: Vec<(&[u8], &[u8], i32)> = names.iter().zip(&paths)
        .map(|(n, p)| (n.as_bytes(), p.as_bytes(), LIBC6)).collect();
    ldso::cache::build_cache(&entries)
}

fn check_x86() -> Result<(), u8> {
    let root = std::fs::canonicalize(root_dir(X86)).map_err(|_| 1u8)?;
    let lib = root.join("lib");

    // 1) static link + run hello.c against the sysroot's libc.a.
    let obj = "target/sysroot-hello.o";
    let mut cc = Command::new("cc");
    cc.args(["-c", "-O2", "-fno-stack-protector", "-fno-pie", "-ffreestanding",
             "userspace/glibc_hello/hello.c", "-o", obj]);
    run(cc)?;
    let sbin = "target/sysroot-hello-static";
    let mut ld = Command::new("cc");
    ld.args(["-static", "-no-pie", "-nostdlib", "-Wl,--gc-sections", obj]);
    ld.arg(lib.join("libc.a"));
    ld.args(["-o", sbin]);
    run(ld)?;
    let out = Command::new(format!("./{sbin}")).output().map_err(|_| 1u8)?;
    let code = out.status.code().unwrap_or(-1);
    let so = String::from_utf8_lossy(&out.stdout);
    eprintln!("xtask sysroot: static exit={code} stdout={so:?}");
    if code != 0 || !so.contains("hello from oxide-libc") {
        eprintln!("xtask sysroot: static-link smoke FAIL"); return Err(1);
    }

    // 2) dynamic link + run a PIE through the sysroot's ld-linux against its
    //    libc.so.6 (proves the laid-out dynamic toolchain is self-contained).
    let ld_abs = lib.join(ld_soname(X86));
    let dbin = "target/sysroot-dyn";
    let mut cc = Command::new("cc");
    cc.args(["-fPIE", "-pie", "-nostdlib", "-nostartfiles", "-Wl,-e,_start",
             "-Wl,--allow-shlib-undefined",
             &format!("-Wl,--dynamic-linker={}", ld_abs.display()),
             &format!("-Wl,-rpath,{}", lib.display()),
             &format!("-L{}", lib.display()), "-l:libc.so.6",
             "userspace/ldso_smoke/dyn_libc.c", "-o", dbin]);
    run(cc)?;
    let out = Command::new(format!("./{dbin}")).env("LD_LIBRARY_PATH", &lib).output().map_err(|_| 1u8)?;
    let code = out.status.code().unwrap_or(-1);
    eprintln!("xtask sysroot: dynamic exit={code} (want 13 via sysroot ld-linux + libc.so.6)");
    if code != 13 { eprintln!("xtask sysroot: dynamic-link smoke FAIL"); return Err(1); }

    // 3) the generated ld.so.cache resolves via the rtld's own reader.
    let cache = std::fs::read(root.join("etc/ld.so.cache")).map_err(|_| 1u8)?;
    let want: &[u8] = b"/lib/libc.so.6";
    if ldso::cache::lookup(&cache, b"libc.so.6") != Some(want) {
        eprintln!("xtask sysroot: ld.so.cache libc.so.6 lookup FAIL"); return Err(1);
    }
    if ldso::cache::lookup(&cache, b"libpthread.so.0") != Some(&b"/lib/libpthread.so.0"[..]) {
        eprintln!("xtask sysroot: ld.so.cache libpthread.so.0 lookup FAIL"); return Err(1);
    }

    eprintln!("xtask sysroot: G18c sysroot publish PASS — G18 COMPLETE");
    Ok(())
}

fn copy(from: &Path, to: &Path) -> Result<(), u8> {
    std::fs::copy(from, to).map(|_| ()).map_err(|e| {
        eprintln!("xtask sysroot: copy {} -> {} failed: {e}", from.display(), to.display()); 1u8
    })
}

fn print_tree(root: &Path) {
    for sub in ["lib", "etc"] {
        let d = root.join(sub);
        if let Ok(rd) = std::fs::read_dir(&d) {
            let mut names: Vec<String> = rd.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned())).collect();
            names.sort();
            for n in names { eprintln!("  {sub}/{n}"); }
        }
    }
}

fn target_installed(triple: &str) -> bool {
    Command::new("rustc").args(["--print", "sysroot"]).output().ok()
        .map(|o| {
            let sr = String::from_utf8_lossy(&o.stdout).trim().to_string();
            Path::new(&format!("{sr}/lib/rustlib/{triple}")).exists()
        })
        .unwrap_or(false)
}
