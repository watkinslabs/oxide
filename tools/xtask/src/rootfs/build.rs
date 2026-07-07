use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cmds::run;
use crate::rootfs_dynprobe::dyn_probe;
use crate::l2_deps;

pub(super) struct BuildOutputs {
    pub user_out: PathBuf,
    pub pam_vendor_sec: PathBuf,
}

pub(super) fn build_userspace(
    repo: &Path,
    arch: &str,
    _rest: &[String],
) -> Result<BuildOutputs, u8> {
// Pick the compiler driver per arch.
let cc: std::path::PathBuf = if arch == "aarch64" {
    let cross = repo.join("vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc");
    if !cross.is_file() {
        eprintln!("xtask rootfs: aarch64 toolchain missing — running tools/fetch-cross.sh");
        run(Command::new(repo.join("tools/fetch-cross.sh").to_str().unwrap()))?;
    }
    cross
} else {
    std::path::PathBuf::from("/usr/bin/musl-gcc")
};
// Per-arch userspace build dir.
let user_out = repo.join(format!("target/userspace-{arch}"));
std::fs::create_dir_all(&user_out).map_err(|_| 1u8)?;
eprintln!("xtask rootfs: arch={arch} CC={}", cc.display());

// 1. Build userspace binaries via musl-gcc — static-musl
// kernel-acceptance smokes + dynamic-loader test binaries.
let crt_bins: &[(&str, &str)] = crate::rootfs_lists::CRT_BINS;
for (out_rel, src_rel) in crt_bins {
    let basename = out_rel.rsplit('/').next().unwrap();
    let out = user_out.join(basename);
    let src = repo.join(src_rel);
    eprintln!("xtask rootfs: {} -static {} → {}", cc.file_name().unwrap().to_string_lossy(), src.display(), out.display());
    let mut c = Command::new(&cc);
    c.args(["-static", "-no-pie", "-O2", "-fno-stack-protector",
            "-o", out.to_str().unwrap(), src.to_str().unwrap()]);
    run(c)?;
}

// pthread probes.
let pthread_bins: &[(&str, &str)] = &[
    ("userspace/pthread_socketpair_probe/pthread_socketpair_probe",
     "userspace/pthread_socketpair_probe/pthread_socketpair_probe.c"),
    ("userspace/mtmalloc_smoke/mtmalloc_smoke",
     "userspace/mtmalloc_smoke/mtmalloc_smoke.c"),
    ("userspace/uffd_probe/uffd_probe",
     "userspace/uffd_probe/uffd_probe.c"),
];
for (out_rel, src_rel) in pthread_bins {
    let basename = out_rel.rsplit('/').next().unwrap();
    let out = user_out.join(basename);
    let src = repo.join(src_rel);
    let mut c = Command::new(&cc);
    c.args(["-static", "-no-pie", "-O2", "-fno-stack-protector", "-pthread",
            "-o", out.to_str().unwrap(), src.to_str().unwrap(), "-lpthread"]);
    run(c)?;
}

let dynlink_bins: &[(&str, &str)] = &[
    ("userspace/dynlink/dynlink",   "userspace/dynlink/dynlink.c"),
];
for (out_rel, src_rel) in dynlink_bins {
    let basename = out_rel.rsplit('/').next().unwrap();
    let out = user_out.join(basename);
    let src = repo.join(src_rel);
    eprintln!("xtask rootfs: {} -static-pie {} → {}", cc.file_name().unwrap().to_string_lossy(), src.display(), out.display());
    let mut c = Command::new(&cc);
    c.args(["-static-pie", "-fPIE", "-O2", "-nostartfiles",
            "-fno-stack-protector",
            "-o", out.to_str().unwrap(), src.to_str().unwrap()]);
    run(c)?;
}

// -pie test binaries — PT_INTERP=/lib/ld-musl-<arch>.so.1.
let dyn_bins: &[(&str, &str)] =
    &[("userspace/hello_dyn/hello_dyn", "userspace/hello_dyn/hello_dyn.c")];
for (out_rel, src_rel) in dyn_bins {
    let basename = out_rel.rsplit('/').next().unwrap();
    let out = user_out.join(basename);
    let src = repo.join(src_rel);
    eprintln!("xtask rootfs: {} -pie {} → {}", cc.file_name().unwrap().to_string_lossy(), src.display(), out.display());
    let mut c = Command::new(&cc);
    c.args(["-fPIE", "-pie", "-O2", "-nostartfiles", "-nostdlib",
            "-fno-stack-protector",
            "-o", out.to_str().unwrap(), src.to_str().unwrap()]);
    run(c)?;
}
let dyn_libc_bins: &[(&str, &str)] = &[
    ("userspace/hello_dyn_libc/hello_dyn_libc",
     "userspace/hello_dyn_libc/hello_dyn_libc.c"),
    // B53: dynamic build of the mallocng-churn probe (same source as
    // the static mallocstress_smoke) — isolates whether the python
    // a_crash is mallocng-generic or specific to the dynamic layout.
    ("userspace/mallocstress_smoke/mallocstress_dyn",
     "userspace/mallocstress_smoke/mallocstress_smoke.c"),
];
for (out_rel, src_rel) in dyn_libc_bins {
    let basename = out_rel.rsplit('/').next().unwrap();
    let out = user_out.join(basename);
    let src = repo.join(src_rel);
    eprintln!("xtask rootfs: {} dynamic {} → {}", cc.file_name().unwrap().to_string_lossy(), src.display(), out.display());
    let mut c = Command::new(&cc);
    c.args(["-O2", "-fno-stack-protector",
            "-o", out.to_str().unwrap(), src.to_str().unwrap()]);
    run(c)?;
}

// G19b/c: the oxide glibc-on-kernel smoke — built against OUR glibc sysroot
// (not musl): Scrt1.o + -l:libc.so.6 + PT_INTERP=/lib/ld-linux-<arch>.so.{2,1}.
// Staged below alongside the sysroot's ld-linux/libc.so.6/folded stubs/
// ld.so.cache + a systemd oneshot unit. Both arches (G19b x86, G19c arm).
{
    let triple = format!("{arch}-unknown-linux-gnu");
    crate::sysroot::build_sysroot(&triple)?;
    let srlib = repo.join(format!("target/sysroot/{triple}/lib"));
    let ld = if arch == "aarch64" { "ld-linux-aarch64.so.1" } else { "ld-linux-x86-64.so.2" };
    // x86: host gcc (targets x86_64). arm: the vendored aarch64 cross driver.
    // -nostdlib keeps the driver from injecting its own (musl) crt/specs —
    // we supply our Scrt1.o + libc.so.6, so the binary is pure oxide-glibc.
    let smoke_cc: std::path::PathBuf = if arch == "aarch64" { cc.clone() } else { "cc".into() };
    // Build one glibc-sysroot binary: compile `<name>/<name>.c` then link
    // it against our Scrt1.o + libc.so.6 with the per-arch interp.
    let build_glibc_bin = |name: &str| -> Result<(), u8> {
        let obj = repo.join(format!("target/{name}-{arch}.o"));
        let mut o = Command::new(&smoke_cc);
        o.args(["-c", "-O2", "-fPIE", "-fno-stack-protector",
                repo.join(format!("userspace/{name}/{name}.c")).to_str().unwrap(),
                "-o", obj.to_str().unwrap()]);
        run(o)?;
        let out = user_out.join(name);
        let mut l = Command::new(&smoke_cc);
        l.args(["-fPIE", "-pie", "-nostdlib", "-Wl,--allow-shlib-undefined",
                &format!("-Wl,--dynamic-linker=/lib/{ld}"),
                obj.to_str().unwrap()]);
        l.arg(srlib.join("Scrt1.o"));
        l.args([&format!("-L{}", srlib.display()), "-l:libc.so.6",
                "-o", out.to_str().unwrap()]);
        run(l)?;
        eprintln!("xtask rootfs: built glibc-on-kernel bin ({arch}) → {}", out.display());
        Ok(())
    };
    build_glibc_bin("g19_glibc_smoke")?;
    build_glibc_bin("g19_glibc_test")?;
    build_glibc_bin("g19_glibc_pthread")?;
    build_glibc_bin("g19_glibc_jointest")?;
}

// F231 / B18: PAM modules come from vendor/pam/install-<arch>/modules/
// (upstream Linux-PAM 1.7.2 sources, built by vendor/pam/build.sh).
// Host binaries that dlopen these (login, sshd, su) must link with
// -Wl,--export-dynamic so pam_get_user / pam_get_item / pam_set_item
// resolve at runtime. The modules carry their own copies of libpam
// internals (pam_modutil_*, pam_prompt, pam_get_authtok, …) via the
// -Wl,--whole-archive libpam.a -Wl,-Bsymbolic link applied in
// vendor/pam/build.sh, so the host only needs to export the basic
// pam_get_user / pam_get_item surface that comes for free with -rdynamic.
let pam_vendor_sec = repo.join(format!("vendor/pam/install-{arch}/modules"));

// B18: login_sim — replicates util-linux login's post-PAM
// hand-off including the PAM session+setcred calls, so we can
// bisect where the actual login binary diverges. Dynamically
// linked against libpam.so.0 (same as login).
{
    let pam_root = repo.join(format!("vendor/pam/install-{arch}"));
    let out = user_out.join("login_sim");
    let src = repo.join("userspace/login_sim/login_sim.c");
    let mut c = Command::new(&cc);
    c.args(["-O2", "-fno-stack-protector",
            "-I", pam_root.to_str().unwrap(),
            "-L", pam_root.to_str().unwrap(),
            "-Wl,-rpath,/usr/lib",
            "-o", out.to_str().unwrap(), src.to_str().unwrap(),
            "-lpam"]);
    run(c)?;
}
{
    let pam_root = repo.join(format!("vendor/pam/install-{arch}"));
    let out = user_out.join("pamtest");
    let src = repo.join("userspace/pamtest/pamtest.c");
    let mut c = Command::new(&cc);
    c.args(["-O2", "-fno-stack-protector",
            "-I", pam_root.to_str().unwrap(),
            "-L", pam_root.to_str().unwrap(),
            "-Wl,-rpath,/usr/lib",
            "-o", out.to_str().unwrap(), src.to_str().unwrap(),
            "-lpam"]);
    run(c)?;
}
// L2 dynamic-link smokes — link the cross-built shared deps from
// /usr/lib (rpath). One per (vendor, probe, -l<lib>).
// L2 dynamic-link probes (table in l2_deps.rs).
for (vendor, probe, lflag) in l2_deps::L2_PROBES {
    dyn_probe(&cc, &repo, &arch, &user_out, vendor, probe, lflag)?;
}

    Ok(BuildOutputs { user_out, pam_vendor_sec })
}
