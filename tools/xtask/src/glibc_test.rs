// xtask glibc-test — differential conformance harness for the SHIPPED oxide
// glibc (docs/59§7). For each C program in userspace/glibc_conformance/:
//   1. compile once to a .o (host headers — glibc-ABI-compatible),
//   2. link + run against the HOST glibc (the oracle),
//   3. link + run against OUR sysroot (Scrt1.o + libc.so.6, through our
//      ld-linux on the host kernel),
//   4. diff stdout + exit code.
// Validates the real dynamic artifact end-to-end on the host (verify-left;
// the oxide-kernel boot is a separate gate). x86_64 for now.
use crate::cmds::run;
use std::path::{Path, PathBuf};
use std::process::Command;

const X86: &str = "x86_64-unknown-linux-gnu";

pub(crate) fn cmd_glibc_test(_rest: &[String]) -> Result<(), u8> {
    crate::sysroot::build_sysroot(X86)?;
    let root = std::fs::canonicalize(PathBuf::from("target/sysroot").join(X86)).map_err(|_| 1u8)?;
    let lib = root.join("lib");
    let dir = PathBuf::from("userspace/glibc_conformance");
    let mut progs: Vec<PathBuf> = std::fs::read_dir(&dir).map_err(|_| 1u8)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "c").unwrap_or(false))
        .collect();
    progs.sort();

    let mut pass = 0usize;
    let mut fail = 0usize;
    let _ = std::fs::create_dir_all("target/glibc-conf");
    for prog in &progs {
        let name = prog.file_stem().unwrap().to_string_lossy().into_owned();
        match run_one(prog, &name, &lib) {
            Ok(true) => { eprintln!("xtask glibc-test: PASS {name}"); pass += 1; }
            Ok(false) => { fail += 1; }
            Err(_) => { eprintln!("xtask glibc-test: ERROR {name} (build/run failed)"); fail += 1; }
        }
    }
    eprintln!("xtask glibc-test: {pass}/{} conformance programs match host glibc", pass + fail);
    if fail == 0 { Ok(()) } else { Err(1) }
}

// Returns Ok(true) if our-glibc output == host-glibc output; Ok(false) on mismatch.
fn run_one(src: &Path, name: &str, lib: &Path) -> Result<bool, u8> {
    let obj = format!("target/glibc-conf/{name}.o");
    let hbin = format!("target/glibc-conf/{name}.host");
    let obin = format!("target/glibc-conf/{name}.oxide");

    // 1. compile once (host headers; glibc-ABI-compatible).
    let mut cc = Command::new("cc");
    cc.args(["-c", "-O2", "-fPIE", "-fno-builtin", src.to_str().unwrap(), "-o", &obj]);
    run(cc)?;

    // 2. host-glibc link + run (the oracle).
    let mut hl = Command::new("cc");
    hl.args([&obj, "-lm", "-o", &hbin]);
    run(hl)?;
    let (ho, hc) = capture(&format!("./{hbin}"), None);

    // 3. oxide-sysroot link (Scrt1.o + libc.so.6 via our ld-linux) + run.
    let mut ol = Command::new("cc");
    ol.args(["-fPIE", "-pie", "-nostdlib", "-Wl,--allow-shlib-undefined",
             &format!("-Wl,--dynamic-linker={}", lib.join("ld-linux-x86-64.so.2").display()),
             &format!("-Wl,-rpath,{}", lib.display()),
             &obj]);
    ol.arg(lib.join("Scrt1.o"));
    ol.args([&format!("-L{}", lib.display()), "-l:libc.so.6", "-o", &obin]);
    run(ol)?;
    let (oo, oc) = capture(&format!("./{obin}"), Some(lib));

    if ho == oo && hc == oc {
        Ok(true)
    } else {
        eprintln!("xtask glibc-test: FAIL {name}");
        eprintln!("  host  (exit {hc}): {ho:?}");
        eprintln!("  oxide (exit {oc}): {oo:?}");
        Ok(false)
    }
}

fn capture(bin: &str, ld_lib: Option<&Path>) -> (String, i32) {
    let mut c = Command::new(bin);
    if let Some(l) = ld_lib { c.env("LD_LIBRARY_PATH", l); }
    match c.output() {
        Ok(o) => (String::from_utf8_lossy(&o.stdout).into_owned(), o.status.code().unwrap_or(-1)),
        Err(e) => (format!("<run failed: {e}>"), -1),
    }
}
