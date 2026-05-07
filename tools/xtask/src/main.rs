// xtask: sole CI entry point per docs/07§8.
//
// Subcommand surface (07§8):
//   xtask kernel    --arch <x86_64|aarch64> --profile <release|dev|debug-build>
//   xtask user      --arch <a>
//   xtask image     --arch <a>
//   xtask test      [--hosted|--kernel|--loom|--miri|--proptest]
//   xtask qemu      --arch <a> [--gdb] [--smp N] [--mem MB]
//   xtask soak      --arch <a> --duration H
//   xtask bench     --arch <a>
//   xtask spec-lint
//   xtask doc-check
//
// Implementation status (P0-03 skeleton):
//   spec-lint  : implemented (delegates to tools/spec-lint binary)
//   kernel     : implemented for build (-Z build-std + target JSON);
//                kernel crate doesn't exist yet -> errors at cargo level
//   test       : --hosted implemented (delegates to `cargo test`)
//   user, image, qemu, soak, bench, doc-check : stubs that print
//                "not yet implemented; awaiting <spec>"

use std::ffi::OsStr;
use std::process::{Command, ExitCode};

mod image_qemu;
mod pkg;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() { return usage(); }

    let cmd = args[0].as_str();
    let rest = &args[1..];

    let res = match cmd {
        "spec-lint" => cmd_spec_lint(rest),
        "kernel"    => cmd_kernel(rest),
        "test"      => cmd_test(rest),
        "user"      => stub("user", "29a"),
        "rootfs"    => cmd_rootfs(rest),
        "image"     => image_qemu::cmd_image(rest),
        "qemu"      => image_qemu::cmd_qemu(rest),
        "pkg"       => pkg::cmd(rest),
        "soak"      => stub("soak", "40"),
        "bench"     => stub("bench", "04"),
        "doc-check" => cmd_doc_check(rest),
        "-h" | "--help" => return usage(),
        _ => { eprintln!("xtask: unknown subcommand `{cmd}`"); return usage(); }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: xtask <kernel|user|image|test|qemu|rootfs|soak|bench|spec-lint|doc-check> [args]");
    ExitCode::from(2)
}

// ---------------------------------------------------------------------------
// rootfs: build kernel/blobs/rootfs.img from source userspace binaries
// ---------------------------------------------------------------------------

/// Reproducible userspace rootfs image builder. Runs:
///   1. musl-gcc on every userspace/<bin>/<bin>.c we know about
///   2. dd + mkfs.ext4 to create a 1 MiB ext4 image
///   3. debugfs to populate /bin/* and /etc/{issue,os-release,passwd,…}
///
/// Output: kernel/blobs/rootfs.img (overwrites in place). Idempotent;
/// rerun whenever the userspace sources change. The kernel image
/// then picks the new bytes up via `include_bytes!` on the next
/// `xtask kernel` build.
pub(crate) fn cmd_rootfs(_rest: &[String]) -> Result<(), u8> {
    let repo = image_qemu::repo_root();
    let blobs = repo.join("kernel/blobs");
    std::fs::create_dir_all(&blobs).map_err(|e| { eprintln!("mkdir blobs: {e}"); 1u8 })?;

    // 1. Build userspace binaries via musl-gcc.
    let bins: &[(&str, &str)] = &[
        ("userspace/init/init",         "userspace/init/init.c"),
        ("userspace/sh/sh",             "userspace/sh/sh.c"),
        ("userspace/udp_echo/udp_echo", "userspace/udp_echo/udp_echo.c"),
        ("userspace/kill/kill",         "userspace/kill/kill.c"),
        ("userspace/sleep/sleep",       "userspace/sleep/sleep.c"),
        ("userspace/true/true",         "userspace/true/true.c"),
        ("userspace/false/false",       "userspace/false/false.c"),
        ("userspace/hostname/hostname", "userspace/hostname/hostname.c"),
        ("userspace/mkdir/mkdir",       "userspace/mkdir/mkdir.c"),
        ("userspace/rm/rm",             "userspace/rm/rm.c"),
        ("userspace/cat/cat",           "userspace/cat/cat.c"),
        ("userspace/echo/echo",         "userspace/echo/echo.c"),
        ("userspace/tcp_echo/tcp_echo", "userspace/tcp_echo/tcp_echo.c"),
        ("userspace/ps/ps",             "userspace/ps/ps.c"),
        ("userspace/ls/ls",             "userspace/ls/ls.c"),
        ("userspace/mount/mount",       "userspace/mount/mount.c"),
        ("userspace/cp/cp",             "userspace/cp/cp.c"),
        ("userspace/wc/wc",             "userspace/wc/wc.c"),
        ("userspace/head/head",         "userspace/head/head.c"),
        ("userspace/dmesg/dmesg",       "userspace/dmesg/dmesg.c"),
        ("userspace/pwd/pwd",           "userspace/pwd/pwd.c"),
        ("userspace/whoami/whoami",     "userspace/whoami/whoami.c"),
        ("userspace/uname/uname",       "userspace/uname/uname.c"),
        ("userspace/nc/nc",             "userspace/nc/nc.c"),
        ("userspace/tee/tee",           "userspace/tee/tee.c"),
        ("userspace/ln/ln",             "userspace/ln/ln.c"),
        ("userspace/find/find",         "userspace/find/find.c"),
        ("userspace/df/df",             "userspace/df/df.c"),
        ("userspace/cmp/cmp",           "userspace/cmp/cmp.c"),
        ("userspace/route/route",       "userspace/route/route.c"),
        ("userspace/xxd/xxd",           "userspace/xxd/xxd.c"),
        ("userspace/seq/seq",           "userspace/seq/seq.c"),
        ("userspace/yes/yes",           "userspace/yes/yes.c"),
        ("userspace/nproc/nproc",       "userspace/nproc/nproc.c"),
        ("userspace/getent/getent",     "userspace/getent/getent.c"),
        ("userspace/login/login",       "userspace/login/login.c"),
        ("userspace/su/su",             "userspace/su/su.c"),
        ("userspace/id/id",             "userspace/id/id.c"),
        ("userspace/svcd/svcd",         "userspace/svcd/svcd.c"),
        ("userspace/agetty/agetty",     "userspace/agetty/agetty.c"),
        ("userspace/rpm/rpm",           "userspace/rpm/rpm.c"),
        ("userspace/passwd/passwd",     "userspace/passwd/passwd.c"),
        ("userspace/dynlink/dynlink",   "userspace/dynlink/dynlink.c"),
    ];
    for (out_rel, src_rel) in bins {
        let out = repo.join(out_rel);
        let src = repo.join(src_rel);
        eprintln!("xtask rootfs: musl-gcc {} → {}", src.display(), out.display());
        let mut c = Command::new("musl-gcc");
        c.args(["-static-pie", "-fPIE", "-O2", "-nostartfiles",
                "-o", out.to_str().unwrap(), src.to_str().unwrap()]);
        run(c)?;
    }

    // -pie (non-static) test binaries — emit PT_INTERP=/lib/ld-musl-x86_64.so.1
    // so the kernel exercises the dual-image load path through our
    // stub interpreter. Keep this list short until the full ld-musl
    // runtime lands; static-pie is the only flavor most utilities
    // need today.
    let dyn_bins: &[(&str, &str)] = &[
        ("userspace/hello_dyn/hello_dyn", "userspace/hello_dyn/hello_dyn.c"),
    ];
    for (out_rel, src_rel) in dyn_bins {
        let out = repo.join(out_rel);
        let src = repo.join(src_rel);
        eprintln!("xtask rootfs: musl-gcc -pie {} → {}", src.display(), out.display());
        let mut c = Command::new("musl-gcc");
        c.args(["-fPIE", "-pie", "-O2", "-nostartfiles", "-nostdlib",
                "-o", out.to_str().unwrap(), src.to_str().unwrap()]);
        run(c)?;
    }

    // 1b. Refresh kernel/blobs/<init,sh>.elf from the freshly-built
    // userspace binaries so the embedded boot blobs (consumed via
    // `include_bytes!` from `kernel/src/elf_smoke.rs`) match what
    // we just compiled — without this, edits to userspace/init/init.c
    // ship in rootfs.img but the kernel keeps running the stale
    // blob it baked in at last `cargo build`.
    let blob_dir = repo.join("kernel/blobs");
    for (src_rel, blob_name) in &[
        ("userspace/init/init", "init.elf"),
        ("userspace/sh/sh",     "sh.elf"),
    ] {
        let src = repo.join(src_rel);
        let dst = blob_dir.join(blob_name);
        eprintln!("xtask rootfs: refresh {} ← {}", dst.display(), src.display());
        std::fs::copy(&src, &dst).map_err(|_| 1u8)?;
    }

    // 2. Build a fresh 1 MiB ext4 image.
    let img = repo.join("kernel/blobs/rootfs.img");
    eprintln!("xtask rootfs: mkfs.ext4 {}", img.display());
    {
        let mut c = Command::new("dd");
        c.args(["if=/dev/zero",
                &format!("of={}", img.display()),
                "bs=1M", "count=8"]);   // 8 MiB — fits bash + util-linux
                                          // with headroom. Bigger needs the
                                          // kernel to load rootfs from a
                                          // separate disk image instead of
                                          // include_bytes!ing it (planned).
        run(c)?;
    }
    {
        let mut c = Command::new("mkfs.ext4");
        c.args(["-F", "-O", "^has_journal", "-L", "oxide", img.to_str().unwrap()]);
        run(c)?;
    }

    // 3. Populate via debugfs (each command is its own invocation —
    //    debugfs's -R takes one command at a time).
    let dbg = |cmd: &str| -> Result<(), u8> {
        let mut c = Command::new("debugfs");
        c.args(["-w", "-R", cmd, img.to_str().unwrap()]);
        // debugfs writes to stderr by default; mute non-error noise.
        c.stdout(std::process::Stdio::null());
        c.stderr(std::process::Stdio::null());
        run(c)
    };
    dbg("mkdir /bin")?;
    dbg("mkdir /etc")?;
    dbg("mkdir /etc/svc")?;
    dbg("mkdir /sbin")?;
    dbg("mkdir /lib")?;
    dbg("mkdir /lib64")?;
    let put = |host: &std::path::Path, target: &str| -> Result<(), u8> {
        let cmd = format!("write {} {}", host.display(), target);
        dbg(&cmd)
    };
    put(&repo.join("userspace/sh/sh"),             "/bin/sh")?;
    put(&repo.join("userspace/init/init"),         "/bin/init")?;
    put(&repo.join("userspace/init/init"),         "/sbin/init")?;
    put(&repo.join("userspace/init/init"),         "/init")?;
    put(&repo.join("userspace/udp_echo/udp_echo"), "/bin/udp_echo")?;
    put(&repo.join("userspace/kill/kill"),         "/bin/kill")?;
    put(&repo.join("userspace/sleep/sleep"),       "/bin/sleep")?;
    put(&repo.join("userspace/true/true"),         "/bin/true")?;
    put(&repo.join("userspace/false/false"),       "/bin/false")?;
    put(&repo.join("userspace/hostname/hostname"), "/bin/hostname")?;
    put(&repo.join("userspace/mkdir/mkdir"),       "/bin/mkdir")?;
    put(&repo.join("userspace/rm/rm"),             "/bin/rm")?;
    put(&repo.join("userspace/cat/cat"),           "/bin/cat")?;
    put(&repo.join("userspace/echo/echo"),         "/bin/echo")?;
    put(&repo.join("userspace/tcp_echo/tcp_echo"), "/bin/tcp_echo")?;
    put(&repo.join("userspace/ps/ps"),             "/bin/ps")?;
    put(&repo.join("userspace/ls/ls"),             "/bin/ls")?;
    put(&repo.join("userspace/mount/mount"),       "/bin/mount")?;
    put(&repo.join("userspace/cp/cp"),             "/bin/cp")?;
    put(&repo.join("userspace/wc/wc"),             "/bin/wc")?;
    put(&repo.join("userspace/head/head"),         "/bin/head")?;
    put(&repo.join("userspace/dmesg/dmesg"),       "/bin/dmesg")?;
    put(&repo.join("userspace/pwd/pwd"),           "/bin/pwd")?;
    put(&repo.join("userspace/whoami/whoami"),     "/bin/whoami")?;
    put(&repo.join("userspace/uname/uname"),       "/bin/uname")?;
    put(&repo.join("userspace/nc/nc"),             "/bin/nc")?;
    put(&repo.join("userspace/tee/tee"),           "/bin/tee")?;
    put(&repo.join("userspace/ln/ln"),             "/bin/ln")?;
    put(&repo.join("userspace/find/find"),         "/bin/find")?;
    put(&repo.join("userspace/df/df"),             "/bin/df")?;
    put(&repo.join("userspace/cmp/cmp"),           "/bin/cmp")?;
    put(&repo.join("userspace/route/route"),       "/bin/route")?;
    put(&repo.join("userspace/xxd/xxd"),           "/bin/xxd")?;
    put(&repo.join("userspace/seq/seq"),           "/bin/seq")?;
    put(&repo.join("userspace/yes/yes"),           "/bin/yes")?;
    put(&repo.join("userspace/nproc/nproc"),       "/bin/nproc")?;
    put(&repo.join("userspace/getent/getent"),     "/bin/getent")?;
    put(&repo.join("userspace/login/login"),       "/bin/login")?;
    put(&repo.join("userspace/su/su"),             "/bin/su")?;
    put(&repo.join("userspace/id/id"),             "/bin/id")?;
    put(&repo.join("userspace/svcd/svcd"),         "/sbin/svcd")?;
    put(&repo.join("userspace/agetty/agetty"),     "/sbin/agetty")?;
    put(&repo.join("userspace/rpm/rpm"),           "/bin/rpm")?;
    put(&repo.join("userspace/passwd/passwd"),     "/bin/passwd")?;
    // /lib/ld-musl-x86_64.so.1 — minimal dynamic-linker stub (P13-06).
    // Kernel ELF loader sees PT_INTERP="/lib/ld-musl-x86_64.so.1"
    // in any -pie (non-static) binary and dual-loads this image
    // alongside the exec.
    put(&repo.join("userspace/dynlink/dynlink"),   "/lib/ld-musl-x86_64.so.1")?;
    put(&repo.join("userspace/hello_dyn/hello_dyn"), "/bin/hello_dyn")?;

    // Install everything that `xtask pkg build <name>` produced into
    // target/pkg-staging/<name>/. Adding a new package to the rootfs
    // is just `xtask pkg build foo`; this loop picks up the artifacts
    // automatically. Any pkg whose tree contains directories not yet
    // in the ext4 image gets `mkdir`'d on the way in.
    pkg::install_all_into_rootfs(&repo, |c| dbg(c))?;

    // /etc/issue + /etc/os-release + /etc/passwd + /etc/group +
    // /etc/shadow + /etc/inittab written via tempfile then put().
    let tmp = repo.join("target/oxide-rootfs-staging");
    std::fs::create_dir_all(&tmp).map_err(|_| 1u8)?;

    let stage = |name: &str, content: &[u8]| -> Result<std::path::PathBuf, u8> {
        let p = tmp.join(name);
        std::fs::write(&p, content).map_err(|_| 1u8)?;
        Ok(p)
    };

    put(&stage("issue", b"oxide \\s on \\l\n\n")?, "/etc/issue")?;
    put(&stage("os-release",
        b"NAME=oxide\nVERSION=0.1\nID=oxide\nPRETTY_NAME=\"oxide-os 0.1\"\n")?,
        "/etc/os-release")?;
    put(&stage("hostname", b"oxide\n")?, "/etc/hostname")?;
    // root has no password (NoPassword path); alice has hash for "swordfish".
    put(&stage("passwd",
        b"root:x:0:0:root:/root:/bin/bash\n\
          alice:x:1000:1000:Alice User:/home/alice:/bin/bash\n\
          nobody:x:65534:65534:nobody:/:/bin/false\n")?,
        "/etc/passwd")?;
    put(&stage("group",
        b"root:x:0:\n\
          wheel:x:10:alice\n\
          users:x:100:alice\n\
          nobody:x:65534:\n")?,
        "/etc/group")?;
    // shadow: root empty (no pw), alice = sha512(salt|swordfish|salt)
    // (matches crypt::sha512crypt v1; will be regenerated when we
    //  ship Drepper-2007 parity in P14-08).
    put(&stage("shadow",
        b"root::19000:0:99999:7:::\n\
          alice:$6$alsalt$Gy2r/DsI0Nj04MSfT1ob.ARb1hRHSZAx9elcKZSElN4EA7.NvTuioqQSs7hTeM7c/.mZ2Sk6GuR4vey3Lk1521:19000:0:99999:7:::\n\
          nobody:!:19000:0:99999:7:::\n")?,
        "/etc/shadow")?;
    put(&stage("inittab",
        b"# v1 inittab - agetty per tty\n\
          tty1::respawn:/sbin/agetty tty1\n\
          tty2::respawn:/sbin/agetty tty2\n")?,
        "/etc/inittab")?;
    put(&stage("hello.txt", b"hello-from-ext4-mini\n")?, "/hello.txt")?;

    // /etc/svc/*.service unit files for /sbin/svcd to consume.
    put(&stage("getty.service",
        b"[Unit]\n\
          Description=Console getty on tty1\n\
          \n\
          [Service]\n\
          ExecStart=/sbin/agetty tty1\n\
          Type=simple\n\
          Restart=always\n")?,
        "/etc/svc/getty.service")?;
    put(&stage("sshd.service",
        b"[Unit]\n\
          Description=OpenSSH placeholder (not yet built)\n\
          \n\
          [Service]\n\
          ExecStart=/bin/false\n\
          Type=oneshot\n\
          Restart=no\n")?,
        "/etc/svc/sshd.service")?;

    eprintln!("xtask rootfs: built {} ({} bytes)",
        img.display(),
        std::fs::metadata(&img).map(|m| m.len()).unwrap_or(0));
    Ok(())
}

fn stub(name: &str, awaiting_spec: &str) -> Result<(), u8> {
    eprintln!("xtask {name}: not yet implemented (awaiting `{awaiting_spec}` freeze + crate scaffold)");
    Err(64)
}

// ---------------------------------------------------------------------------
// spec-lint
// ---------------------------------------------------------------------------

fn cmd_spec_lint(rest: &[String]) -> Result<(), u8> {
    // Pass-through to the spec-lint binary.
    let mut c = Command::new("cargo");
    c.args(["run", "--quiet", "-p", "spec-lint", "--", "all"]);
    for a in rest { c.arg(a); }
    run(c)
}

// ---------------------------------------------------------------------------
// kernel
// ---------------------------------------------------------------------------

pub(crate) fn cmd_kernel(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").ok_or_else(|| {
        eprintln!("xtask kernel: --arch <x86_64|aarch64> required");
        2u8
    })?;
    let profile = parse_arg(rest, "--profile").unwrap_or("release".into());
    let features = parse_arg(rest, "--features");
    let target = match arch.as_str() {
        "x86_64"  => "./targets/x86_64-unknown-oxide-kernel.json",
        "aarch64" => "./targets/aarch64-unknown-oxide-kernel.json",
        other => { eprintln!("xtask kernel: unsupported arch `{other}`"); return Err(2); }
    };
    let (boot_pkg, bin_pkg) = match arch.as_str() {
        "x86_64"  => ("boot-x86_64",  "kernel-bin-x86_64"),
        "aarch64" => ("boot-aarch64", "kernel-bin-aarch64"),
        _ => unreachable!(),
    };
    let mut c = Command::new("cargo");
    c.args([
        "build",
        "-Z", "build-std=core,compiler_builtins,alloc",
        "-Z", "build-std-features=compiler-builtins-mem",
        "-Z", "unstable-options",
        "-Z", "json-target-spec",
        "--target", target,
        "--profile", &profile,
        "-p", "kernel",
        "-p", boot_pkg,
        "-p", bin_pkg,
    ]);
    if let Some(f) = features.as_ref() {
        c.args(["--features", f.as_str()]);
    }
    run(c)
}


// ---------------------------------------------------------------------------
// test
// ---------------------------------------------------------------------------

fn cmd_test(rest: &[String]) -> Result<(), u8> {
    let mode = rest.iter().map(|s| s.as_str()).find(|s| s.starts_with("--")).unwrap_or("--hosted");
    match mode {
        "--hosted" => {
            let mut c = Command::new("cargo");
            c.args(["test", "--workspace"]);
            run(c)
        }
        "--kernel" | "--loom" | "--miri" | "--proptest" => {
            eprintln!("xtask test {mode}: not yet implemented (awaiting `42` freeze + first kernel crate)");
            Err(64)
        }
        other => { eprintln!("xtask test: unknown mode `{other}`"); Err(2) }
    }
}

// ---------------------------------------------------------------------------
// doc-check
// ---------------------------------------------------------------------------

fn cmd_doc_check(_rest: &[String]) -> Result<(), u8> {
    // Equivalent to `spec-lint manifest + xref` per 02§6 + 02§5.
    let mut c = Command::new("cargo");
    c.args(["run", "--quiet", "-p", "spec-lint", "--", "manifest"]);
    run(c.clone_for_xref())?;
    let mut c = Command::new("cargo");
    c.args(["run", "--quiet", "-p", "spec-lint", "--", "xref"]);
    run(c)
}

// Quick shim because Command isn't Clone. We just rebuild it.
trait CommandExt { fn clone_for_xref(&mut self) -> Command; }
impl CommandExt for Command {
    fn clone_for_xref(&mut self) -> Command {
        let mut c = Command::new(self.get_program());
        for a in self.get_args() { c.arg(a); }
        c
    }
}

// ---------------------------------------------------------------------------
// shared
// ---------------------------------------------------------------------------

pub(crate) fn run(mut c: Command) -> Result<(), u8> {
    let status = c.status().map_err(|e| { eprintln!("xtask: spawn failed: {e}"); 1u8 })?;
    if status.success() { Ok(()) }
    else { Err(status.code().unwrap_or(1) as u8) }
}

pub(crate) fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter().enumerate();
    while let Some((_, a)) = iter.next() {
        if a == flag {
            if let Some((_, v)) = iter.next() { return Some(v.clone()); }
        }
        if let Some(rest) = a.strip_prefix(&format!("{flag}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

#[allow(dead_code)]
fn _osstr_keepalive(_: &OsStr) {}
