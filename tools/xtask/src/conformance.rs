// xtask conformance — differential kernel conformance over the corpus in
// `userspace/glibc_conformance/`. For each C program:
//   1. link + run it on the HOST (Linux) against the system glibc — the oracle,
//   2. cross-link the same source for the target arch against the same glibc
//      ABI, and inject that binary into the guest root image,
//   3. `tools/oxide-conformance-ssh.sh` boots, runs it over ssh, and diffs the
//      guest frame against the oracle recorded in the manifest.
//
// Both sides are ordinary dynamically-linked glibc programs resolved by the
// image's own loader, so a difference is a KERNEL difference. This previously
// linked the guest side against `crates/user/glibc` + `crates/user/ldso` and
// shipped that libc into `/opt/oxide-conformance/lib`, which confounded every
// result: a guest-vs-host mismatch could be our libc rather than our kernel.
use crate::cmds::{parse_arg, run};
use std::path::{Path, PathBuf};
use std::process::Command;

const X86: &str = "x86_64-unknown-linux-gnu";
const ARM: &str = "aarch64-unknown-linux-gnu";
/// Vendor C headers paired with the installed AArch64 cross compiler.
/// The compiler's default sysroot intentionally contains only startup/runtime
/// pieces, while this sysroot owns the Linux UAPI and libc headers used by
/// conformance sources.
const ARM_C_HEADER_SYSROOT: &str = "/usr/aarch64-redhat-linux/sys-root/fc42";

pub(crate) fn cmd_conformance(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").unwrap_or_else(|| "x86_64".into());
    let triple = match arch.as_str() {
        "x86_64" => X86,
        "aarch64" => ARM,
        other => { eprintln!("xtask conformance: --arch must be x86_64 or aarch64 (got `{other}`)"); return Err(2); }
    };
    let inject = parse_arg(rest, "--inject");
    let selected = parse_arg(rest, "--tests");
    let build_id = parse_arg(rest, "--id");
    let dir = PathBuf::from("userspace/glibc_conformance");
    let mut progs: Vec<PathBuf> = std::fs::read_dir(&dir).map_err(|_| 1u8)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "c").unwrap_or(false))
        .collect();
    progs.sort();
    if let Some(names) = selected.as_deref() {
        let requested: Vec<&str> = names.split(',').map(str::trim)
            .filter(|name| !name.is_empty()).collect();
        if requested.is_empty() || requested.iter().any(|name| {
            !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }) {
            eprintln!("xtask conformance: --tests requires comma-separated test names");
            return Err(2);
        }
        progs.retain(|prog| requested.iter().any(|name| {
            prog.file_stem().is_some_and(|stem| stem == *name)
        }));
        if progs.len() != requested.len() {
            eprintln!("xtask conformance: one or more requested tests do not exist");
            return Err(2);
        }
    }

    let mut pass = 0usize;
    let mut fail = 0usize;
    let _ = std::fs::create_dir_all("target/glibc-conf");
    for prog in &progs {
        let name = prog.file_stem().unwrap().to_string_lossy().into_owned();
        match run_one(prog, &name, triple) {
            Ok(true) => { eprintln!("xtask conformance: PASS {name}"); pass += 1; }
            Ok(false) => { fail += 1; }
            Err(_) => { eprintln!("xtask conformance: ERROR {name} (build/run failed)"); fail += 1; }
        }
    }
    if let Some(names) = inject {
        inject_guest(&names, &arch, triple, build_id.as_deref())?;
    }
    eprintln!("xtask conformance: {pass}/{} oracles recorded and {arch} guest binaries linked",
        pass + fail);
    if fail == 0 { Ok(()) } else { Err(1) }
}

fn inject_guest(names: &str, arch: &str, triple: &str, id: Option<&str>) -> Result<(), u8> {
    let repo = crate::image_qemu::repo_root();
    let image = crate::buildns::blobs_dir(&repo, id).join(format!("root-{arch}.img"));
    if !image.is_file() {
        eprintln!("xtask conformance: root image not found at {}; run xtask rootfs first", image.display());
        return Err(2);
    }
    // Only the test binary is injected. It resolves through the image's OWN
    // Fedora loader and libc, the same pair every other program in the guest
    // uses — no private `/opt/oxide-conformance/lib` libc to confound the diff.
    let _ = debugfs(&image, "mkdir /etc/systemd/system/multi-user.target.wants");
    let _ = debugfs(&image, "symlink ../sshd.service /etc/systemd/system/multi-user.target.wants/sshd.service");
    for name in names.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            eprintln!("xtask conformance: unsafe test name `{name}`"); return Err(2);
        }
        let host = PathBuf::from(format!("target/glibc-conf/{name}.{triple}.guest"));
        let guest = format!("/usr/local/bin/oxide-conformance-{name}");
        inject_file(&image, &host, &guest, "0100755")?;
    }
    eprintln!("xtask conformance: injected guest artifacts into {}", image.display());
    Ok(())
}

fn inject_file(image: &Path, host: &Path, guest: &str, mode: &str) -> Result<(), u8> {
    if !host.is_file() { eprintln!("xtask conformance: missing injection source {}", host.display()); return Err(2); }
    let _ = debugfs(image, &format!("rm {guest}"));
    let write = format!("write {} {guest}", host.display());
    debugfs(image, &write)?;
    debugfs(image, &format!("sif {guest} mode {mode}"))
}

fn debugfs(image: &Path, request: &str) -> Result<(), u8> {
    let mut c = Command::new("debugfs");
    c.args(["-w", "-R", request, image.to_str().unwrap()]);
    run(c)
}

// Records the host oracle frame and produces the guest binary. Guest execution
// and the host-vs-guest diff belong to `tools/oxide-conformance-ssh.sh`.
fn run_one(src: &Path, name: &str, triple: &str) -> Result<bool, u8> {
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
    // and resolver compat symbols. No -lcrypt: libxcrypt is not in the AArch64
    // cross sysroot, and the one test that needed it exercised a libc, not the
    // kernel.
    let mut hl = Command::new("cc");
    if copy_reloc { hl.arg("-no-pie"); }
    hl.args([&host_obj, "-lm", "-lresolv", "-o", &hbin]);
    run(hl)?;
    let host_result = capture(&format!("./{hbin}"));

    // 3. the guest binary: the SAME source, cross-linked for the target against
    // the ordinary glibc ABI with the platform's default loader path. No
    // `--dynamic-linker` override and no `-nostdlib` — it is a normal
    // dynamically-linked program, so the guest resolves it through the image's
    // own Fedora `ld-linux` and `libc.so.6`.
    let guest_bin = format!("target/glibc-conf/{name}.{triple}.guest");
    let mut guest_link = target_compiler(triple);
    if copy_reloc { guest_link.arg("-no-pie"); } else { guest_link.args(["-fPIE", "-pie"]); }
    guest_link.args([&target_obj, "-lm", "-lresolv", "-o", &guest_bin]);
    run(guest_link)?;

    // 4. persist the oracle frame next to the guest binary so a guest result can
    // be diffed against exactly the frame this run recorded.
    write_frame(name, &host_result)?;
    if host_result.status == RUN_FAILED {
        eprintln!("xtask conformance: FAIL {name} — host oracle did not execute");
        eprintln!("  host stderr={:?}", String::from_utf8_lossy(&host_result.stderr));
        return Ok(false);
    }
    eprintln!("xtask conformance: oracle {name} exit={} stdout={:?}",
        host_result.status, String::from_utf8_lossy(&host_result.stdout));
    Ok(true)
}

/// `<name>.oracle` = exit status then stdout then stderr, each length-prefixed
/// so an empty stream and a missing stream stay distinguishable.
fn write_frame(name: &str, frame: &ResultFrame) -> Result<(), u8> {
    let mut out = std::format!("exit {}\n", frame.status).into_bytes();
    out.extend_from_slice(std::format!("stdout {}\n", frame.stdout.len()).as_bytes());
    out.extend_from_slice(&frame.stdout);
    out.extend_from_slice(std::format!("\nstderr {}\n", frame.stderr.len()).as_bytes());
    out.extend_from_slice(&frame.stderr);
    std::fs::write(std::format!("target/glibc-conf/{name}.oracle"), out).map_err(|_| 1u8)
}

fn target_compiler(triple: &str) -> Command {
    if triple == X86 { return Command::new("cc"); }
    let mut compiler = Command::new("aarch64-linux-gnu-gcc");
    compiler.arg(format!("--sysroot={ARM_C_HEADER_SYSROOT}"));
    compiler
}

/// `capture` could not launch the binary at all — distinct from any exit status
/// a program can produce, including a signal death.
const RUN_FAILED: i32 = -1;

#[derive(Debug, PartialEq, Eq)]
struct ResultFrame { stdout: Vec<u8>, stderr: Vec<u8>, status: i32 }

fn capture(bin: &str) -> ResultFrame {
    let mut c = Command::new(bin);
    // The oracle and oxide executions must not inherit build-shell library
    // state.  Keep the guest runner's clean-env contract identical here.
    c.env_clear();
    c.envs([
        ("PATH", "/usr/bin:/bin"),
        ("LC_ALL", "C"),
        ("TZ", "UTC"),
        ("HOME", "/"),
    ]);
    match c.output() {
        Ok(o) => ResultFrame { stdout: o.stdout, stderr: o.stderr, status: o.status.code().unwrap_or(RUN_FAILED) },
        Err(e) => ResultFrame { stdout: Vec::new(), stderr: format!("<run failed: {e}>").into_bytes(), status: RUN_FAILED },
    }
}

#[cfg(test)]
mod tests {
    use super::capture;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn capture_does_not_inherit_custom_library_path() {
        let path = "target/glibc-conf/env-capture-test";
        fs::create_dir_all("target/glibc-conf").unwrap();
        fs::write(path, b"#!/bin/sh\nprintf '%s\\n' \"${LD_LIBRARY_PATH-unset}\"\nprintf '%s\\n' \"$LC_ALL\"\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        let result = capture(path);
        fs::remove_file(path).unwrap();
        assert_eq!(result.status, 0);
        assert_eq!(result.stdout, b"unset\nC\n");
        assert!(result.stderr.is_empty());
    }
}
