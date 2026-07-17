// xtask glibc-test — differential conformance harness for the SHIPPED oxide
// glibc (docs/59§7). For each C program in userspace/glibc_conformance/:
//   1. compile the host oracle and target objects,
//   2. link + run against the HOST glibc (the oracle),
//   3. link against OUR target sysroot; run it only when target matches host,
//   4. diff stdout + exit code.
// Validates the requested dynamic artifact through the host runner when the
// target is executable here. This is not guest-kernel differential testing.
use crate::cmds::{parse_arg, run};
use std::path::{Path, PathBuf};
use std::process::Command;

const X86: &str = "x86_64-unknown-linux-gnu";
const ARM: &str = "aarch64-unknown-linux-gnu";

pub(crate) fn cmd_glibc_test(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").unwrap_or_else(|| "x86_64".into());
    let triple = match arch.as_str() {
        "x86_64" => X86,
        "aarch64" => ARM,
        other => { eprintln!("xtask glibc-test: --arch must be x86_64 or aarch64 (got `{other}`)"); return Err(2); }
    };
    crate::sysroot::build_sysroot(triple)?;
    let root = std::fs::canonicalize(PathBuf::from("target/sysroot").join(triple)).map_err(|_| 1u8)?;
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
        match run_one(prog, &name, &lib, triple) {
            Ok(true) => { eprintln!("xtask glibc-test: PASS {name}"); pass += 1; }
            Ok(false) => { fail += 1; }
            Err(_) => { eprintln!("xtask glibc-test: ERROR {name} (build/run failed)"); fail += 1; }
        }
    }
    if triple == ARM { eprintln!("xtask glibc-test: aarch64 target compile/link PASS; host oracle was run, guest execution not attempted"); }
    if triple == X86 {
        eprintln!("xtask glibc-test: {pass}/{} conformance programs match host glibc", pass + fail);
    } else {
        eprintln!("xtask glibc-test: {pass}/{} conformance programs compiled and linked for {arch}", pass + fail);
    }
    if fail == 0 { Ok(()) } else { Err(1) }
}

// Returns Ok(true) on an oracle match for x86_64, or target compile/link for
// aarch64. Guest execution is a separate boot test.
fn run_one(src: &Path, name: &str, lib: &Path, triple: &str) -> Result<bool, u8> {
    let host_obj = format!("target/glibc-conf/{name}.host.o");
    let target_obj = format!("target/glibc-conf/{name}.{triple}.o");
    let hbin = format!("target/glibc-conf/{name}.host");
    let copy_reloc = name == "t_copyreloc_globals";

    // 1. compile once (host headers; glibc-ABI-compatible).
    let mut cc = Command::new("cc");
    cc.args(["-c", "-O2", "-fno-builtin"]);
    cc.arg(if copy_reloc { "-fno-pie" } else { "-fPIE" });
    cc.args([src.to_str().unwrap(), "-o", &host_obj]);
    run(cc)?;
    let mut tc = target_compiler(triple);
    tc.args(["-c", "-O2", "-fno-builtin"]);
    tc.arg(if copy_reloc { "-fno-pie" } else { "-fPIE" });
    tc.args([src.to_str().unwrap(), "-o", &target_obj]);
    run(tc)?;

    // 2. host-glibc link + run (the oracle). -lresolv for the inet_net_*/nsap
    // and resolver compat symbols; -lcrypt for libxcrypt symbols that host
    // glibc keeps outside libc proper.
    let mut hl = Command::new("cc");
    if copy_reloc { hl.arg("-no-pie"); }
    hl.args([&host_obj, "-lm", "-lresolv", "-lcrypt", "-o", &hbin]);
    run(hl)?;
    let (ho, hc) = capture(&format!("./{hbin}"), None);

    // 3. oxide-sysroot link (Scrt1.o + libc.so.6 via the selected loader).
    let mut ol = target_compiler(triple);
    if copy_reloc {
        ol.arg("-no-pie");
    } else {
        ol.args(["-fPIE", "-pie"]);
    }
    let ld_name = if triple == ARM { "ld-linux-aarch64.so.1" } else { "ld-linux-x86-64.so.2" };
    ol.args(["-nostdlib", "-Wl,--allow-shlib-undefined",
        &format!("-Wl,--dynamic-linker={}", lib.join(ld_name).display()),
        &format!("-Wl,-rpath,{}", lib.display()),
        &target_obj]);
    let target_bin = format!("target/glibc-conf/{name}.{triple}");
    ol.arg(lib.join("Scrt1.o"));
    ol.args([&format!("-L{}", lib.display()), "-l:libc.so.6", "-o", &target_bin]);
    run(ol)?;
    let guest_bin = format!("target/glibc-conf/{name}.{triple}.guest");
    let mut guest_link = target_compiler(triple);
    if copy_reloc { guest_link.arg("-no-pie"); }
    else { guest_link.args(["-fPIE", "-pie"]); }
    let guest_loader = if triple == ARM {
        "/lib64/ld-linux-aarch64.so.1"
    } else {
        "/lib64/ld-linux-x86-64.so.2"
    };
    guest_link.args(["-nostdlib", "-Wl,--allow-shlib-undefined",
        &format!("-Wl,--dynamic-linker={guest_loader}"),
        "-Wl,-rpath,/lib64", &target_obj]);
    guest_link.arg(lib.join("Scrt1.o"));
    guest_link.args([&format!("-L{}", lib.display()), "-l:libc.so.6", "-o", &guest_bin]);
    run(guest_link)?;
    if triple != X86 { return Ok(true); }
    let (oo, oc) = capture(&format!("./{target_bin}"), Some(lib));

    if ho == oo && hc == oc {
        Ok(true)
    } else {
        eprintln!("xtask glibc-test: FAIL {name}");
        eprintln!("  host  (exit {hc}): {ho:?}");
        eprintln!("  oxide (exit {oc}): {oo:?}");
        Ok(false)
    }
}

fn target_compiler(triple: &str) -> Command {
    if triple == X86 { return Command::new("cc"); }
    Command::new("aarch64-linux-gnu-gcc")
}

fn capture(bin: &str, ld_lib: Option<&Path>) -> (String, i32) {
    let mut c = Command::new(bin);
    if let Some(l) = ld_lib { c.env("LD_LIBRARY_PATH", l); }
    match c.output() {
        Ok(o) => (String::from_utf8_lossy(&o.stdout).into_owned(), o.status.code().unwrap_or(-1)),
        Err(e) => (format!("<run failed: {e}>"), -1),
    }
}
