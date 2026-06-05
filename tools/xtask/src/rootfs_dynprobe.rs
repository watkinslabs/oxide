// Dynamic-link userspace probe builder, split out of `rootfs.rs` to keep
// it under the 1000-line cap (08§7).
use std::process::Command;
use crate::cmds::run;
use crate::l2_deps;

/// Build a dynamic-link probe (`userspace/<probe>/<probe>.c`) against a
/// cross-built L2 shared lib in `vendor/<vendor>/install-<arch>`, linking
/// `<lflag>` (e.g. `-lcap`) with rpath /usr/lib. Track L2 helper.
pub(crate) fn dyn_probe(cc: &std::path::Path, repo: &std::path::Path, arch: &str,
             user_out: &std::path::Path, vendor: &str, probe: &str, lflag: &str)
             -> Result<(), u8> {
    let root = repo.join(format!("vendor/{vendor}/install-{arch}"));
    let out = user_out.join(probe);
    let src = repo.join(format!("userspace/{probe}/{probe}.c"));
    let mut c = Command::new(cc);
    c.args(["-O2", "-fno-stack-protector",
            "-I", root.join("include").to_str().unwrap(),
            "-L", root.join("lib").to_str().unwrap(),
            "-Wl,-rpath,/usr/lib"]);
    // A probe's lib may DT_NEED another L2 lib in a different vendor dir
    // (e.g. libgcrypt.so → libgpg-error.so). The strict aarch64 cross-ld
    // re-checks those transitive undefined symbols at probe-link time and
    // must find the dependency .so. Point -rpath-link at every staged L2
    // vendor libdir so any cross-vendor transitive dep resolves (no effect
    // on the probe's own DT_NEEDED; runtime still uses /usr/lib via rpath).
    for (v, _, _, _) in l2_deps::L2_LIBS {
        let d = repo.join(format!("vendor/{v}/install-{arch}/lib"));
        if d.is_dir() { c.arg(format!("-Wl,-rpath-link,{}", d.to_str().unwrap())); }
    }
    // Some headers (e.g. libseccomp's seccomp.h → asm/unistd.h) need kernel
    // UAPI. The aarch64 cross sysroot bundles them; x86 musl-gcc doesn't, so
    // append the host kernel-headers at lowest priority (musl libc wins).
    if arch == "x86_64" { c.args(["-idirafter", "/usr/include"]); }
    c.args(["-o", out.to_str().unwrap(), src.to_str().unwrap()]);
    // lflag may carry several link flags (e.g. "-lmount -luuid").
    for f in lflag.split_whitespace() { c.arg(f); }
    run(c)
}
