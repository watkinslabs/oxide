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

/// Reproducible per-arch userspace rootfs image builder.
///
/// Driven by `--arch <x86_64|aarch64>`. Runs:
///   1. arch-specific musl-gcc on every userspace/<bin>/<bin>.c.
///      x86_64 uses host /usr/bin/musl-gcc; aarch64 uses
///      vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc
///      (fetched via `tools/fetch-cross.sh` if missing).
///   2. dd + mkfs.ext4 → kernel/blobs/rootfs-<arch>.img.
///   3. debugfs to populate /bin/* and /etc/* in the per-arch image.
///
/// Idempotent; rerun whenever userspace sources change. The kernel
/// `include_bytes!`s the matching per-arch blob in dev_ext4.rs.
pub(crate) fn cmd_rootfs(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").unwrap_or_else(|| "x86_64".into());
    if arch != "x86_64" && arch != "aarch64" {
        eprintln!("xtask rootfs: --arch must be x86_64 or aarch64 (got `{arch}`)");
        return Err(2);
    }
    let repo = image_qemu::repo_root();
    let blobs = repo.join("kernel/blobs");
    std::fs::create_dir_all(&blobs).map_err(|e| { eprintln!("mkdir blobs: {e}"); 1u8 })?;

    // Pick the compiler driver per arch.
    let cc: std::path::PathBuf = if arch == "aarch64" {
        let cross = repo.join("vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc");
        if !cross.is_file() {
            eprintln!("xtask rootfs: aarch64 toolchain missing — running tools/fetch-cross.sh");
            let mut c = Command::new(repo.join("tools/fetch-cross.sh").to_str().unwrap());
            run(c)?;
        }
        cross
    } else {
        std::path::PathBuf::from("/usr/bin/musl-gcc")
    };
    // Per-arch userspace build dir so x86 + arm artifacts don't
    // overwrite each other when both rootfs builds run.
    let user_out = repo.join(format!("target/userspace-{arch}"));
    std::fs::create_dir_all(&user_out).map_err(|_| 1u8)?;
    eprintln!("xtask rootfs: arch={arch} CC={}", cc.display());

    // 1. Build userspace binaries via musl-gcc.
    //
    // `portable_bins` use musl libc wrappers (write/fork/execve/...)
    // and build on every arch. `x86_bins` still embed x86 `syscall`
    // inline asm and are skipped on aarch64 until they're ported
    // to libc-wrapper or arch-conditional syscall macros. The
    // aarch64 boot path only needs init to reach userspace today;
    // shell + applets come via vendored busybox once the aarch64
    // cross-build of busybox lands.
    let portable_bins: &[(&str, &str)] = &[
        ("userspace/init/init",         "userspace/init/init.c"),
    ];
    let x86_bins: &[(&str, &str)] = &[
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
    let mut bins: Vec<(&str, &str)> = portable_bins.to_vec();
    if arch == "x86_64" {
        bins.extend_from_slice(x86_bins);
    } else {
        eprintln!("xtask rootfs: arch={arch} skipping {} x86-asm-only userspace bins; init only", x86_bins.len());
    }
    for (out_rel, src_rel) in &bins {
        // Out path is per-arch: target/userspace-<arch>/<basename>.
        let basename = out_rel.rsplit('/').next().unwrap();
        let out = user_out.join(basename);
        let src = repo.join(src_rel);
        eprintln!("xtask rootfs: {} {} → {}", cc.file_name().unwrap().to_string_lossy(), src.display(), out.display());
        let mut c = Command::new(&cc);
        c.args(["-static-pie", "-fPIE", "-O2", "-nostartfiles",
                "-o", out.to_str().unwrap(), src.to_str().unwrap()]);
        run(c)?;
    }

    // -pie (non-static) test binaries — emit PT_INTERP=/lib/ld-musl-x86_64.so.1
    // so the kernel exercises the dual-image load path through our
    // stub interpreter. Keep this list short until the full ld-musl
    // runtime lands; static-pie is the only flavor most utilities
    // need today.
    let dyn_bins: &[(&str, &str)] = if arch == "x86_64" {
        &[("userspace/hello_dyn/hello_dyn", "userspace/hello_dyn/hello_dyn.c")]
    } else {
        &[]
    };
    for (out_rel, src_rel) in dyn_bins {
        let basename = out_rel.rsplit('/').next().unwrap();
        let out = user_out.join(basename);
        let src = repo.join(src_rel);
        eprintln!("xtask rootfs: {} -pie {} → {}", cc.file_name().unwrap().to_string_lossy(), src.display(), out.display());
        let mut c = Command::new(&cc);
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
    // 1b. Refresh kernel/blobs/<arch>/<init,sh>.elf per-arch so the
    // embedded boot blobs match what we just compiled.
    let blob_dir = repo.join("kernel/blobs");
    let elf_refresh: &[(&str, &str)] = if arch == "x86_64" {
        &[("init", "init.elf"), ("sh", "sh.elf")]
    } else {
        &[("init", "init.elf")]
    };
    for (basename, blob_name) in elf_refresh {
        let src = user_out.join(basename);
        // Per-arch blob filename; x86_64 keeps the existing
        // (un-suffixed) name for back-compat with elf_smoke's
        // include_bytes!, aarch64 gets a .arm-suffixed copy.
        let dst = if arch == "x86_64" {
            blob_dir.join(blob_name)
        } else {
            blob_dir.join(format!("{}-aarch64.elf", blob_name.trim_end_matches(".elf")))
        };
        eprintln!("xtask rootfs: refresh {} ← {}", dst.display(), src.display());
        std::fs::copy(&src, &dst).map_err(|_| 1u8)?;
    }

    // 2. Build a fresh 8 MiB ext4 image at kernel/blobs/rootfs-<arch>.img.
    let img = repo.join(format!("kernel/blobs/rootfs-{arch}.img"));
    eprintln!("xtask rootfs: mkfs.ext4 {}", img.display());
    {
        let mut c = Command::new("dd");
        c.args(["if=/dev/zero",
                &format!("of={}", img.display()),
                "bs=1M", "count=8"]);
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
    // Helper to resolve a userspace binary by name from the per-arch
    // build output dir. Replaces the older `repo.join("userspace/<x>/<x>")`
    // pattern that hard-coded host-arch artifacts.
    let user = |name: &str| user_out.join(name);
    // Vendored busybox 1.37.0 — pre-built static-musl per
    // vendor/busybox/build.sh. busybox keys on argv[0]: the same
    // binary at /bin/sh runs as ash, at /bin/ls runs as ls, etc.
    // Stage it at every applet path (incl. /bin/sh) so login →
    // /bin/sh hands straight into busybox-ash. The toy oxide-sh
    // moves to /bin/oxide-sh for dev probing / boot smoke.
    let bb = repo.join("vendor/busybox/busybox");
    if bb.is_file() {
        put(&bb, "/bin/busybox")?;
        for applet in &[
            "sh", "ash",
            "ls", "cat", "echo", "cp", "mv", "rm", "mkdir", "rmdir",
            "ps", "top", "uptime", "free", "dmesg", "mount", "umount",
            "grep", "find", "head", "tail", "wc", "sort", "uniq",
            "touch", "chmod", "chown", "ln", "test", "true", "false",
            "env", "printf", "yes", "seq", "expr", "id", "whoami",
            "tr", "cut", "sed", "awk", "date", "df", "du", "stat",
            "kill", "sleep", "tee", "xxd", "hostname", "uname",
            "pwd", "basename", "dirname", "which", "clear", "reset",
        ] {
            put(&bb, &format!("/bin/{applet}"))?;
        }
    }
    // init is portable and present on every arch.
    put(&user("init"),         "/bin/init")?;
    put(&user("init"),         "/sbin/init")?;
    put(&user("init"),         "/init")?;
    // The toy oxide-sh + applets below still embed x86 inline-asm
    // syscalls; only stage them on x86_64 until they're ported.
    if arch != "x86_64" {
        eprintln!("xtask rootfs: arch={arch} skipping toy applets (x86-asm only) — busybox will fill these once aarch64 cross-build lands");
    }
    if arch == "x86_64" {
    put(&user("sh"),             "/bin/oxide-sh")?;
    put(&user("udp_echo"), "/bin/udp_echo")?;
    put(&user("kill"),         "/bin/kill")?;
    put(&user("sleep"),       "/bin/sleep")?;
    put(&user("true"),         "/bin/true")?;
    put(&user("false"),       "/bin/false")?;
    put(&user("hostname"), "/bin/hostname")?;
    put(&user("mkdir"),       "/bin/mkdir")?;
    put(&user("rm"),             "/bin/rm")?;
    put(&user("cat"),           "/bin/cat")?;
    put(&user("echo"),         "/bin/echo")?;
    put(&user("tcp_echo"), "/bin/tcp_echo")?;
    put(&user("ps"),             "/bin/ps")?;
    put(&user("ls"),             "/bin/ls")?;
    put(&user("mount"),       "/bin/mount")?;
    put(&user("cp"),             "/bin/cp")?;
    put(&user("wc"),             "/bin/wc")?;
    put(&user("head"),         "/bin/head")?;
    put(&user("dmesg"),       "/bin/dmesg")?;
    put(&user("pwd"),           "/bin/pwd")?;
    put(&user("whoami"),     "/bin/whoami")?;
    put(&user("uname"),       "/bin/uname")?;
    put(&user("nc"),             "/bin/nc")?;
    put(&user("tee"),           "/bin/tee")?;
    put(&user("ln"),             "/bin/ln")?;
    put(&user("find"),         "/bin/find")?;
    put(&user("df"),             "/bin/df")?;
    put(&user("cmp"),           "/bin/cmp")?;
    put(&user("route"),       "/bin/route")?;
    put(&user("xxd"),           "/bin/xxd")?;
    put(&user("seq"),           "/bin/seq")?;
    put(&user("yes"),           "/bin/yes")?;
    put(&user("nproc"),       "/bin/nproc")?;
    put(&user("getent"),     "/bin/getent")?;
    put(&user("login"),       "/bin/login")?;
    put(&user("su"),             "/bin/su")?;
    put(&user("id"),             "/bin/id")?;
    put(&user("svcd"),         "/sbin/svcd")?;
    put(&user("agetty"),     "/sbin/agetty")?;
    put(&user("rpm"),           "/bin/rpm")?;
    put(&user("passwd"),     "/bin/passwd")?;
    // /lib/ld-musl-x86_64.so.1 — minimal dynamic-linker stub (P13-06).
    // Kernel ELF loader sees PT_INTERP="/lib/ld-musl-x86_64.so.1"
    // in any -pie (non-static) binary and dual-loads this image
    // alongside the exec.
    put(&user("dynlink"),   "/lib/ld-musl-x86_64.so.1")?;
    put(&user("hello_dyn"), "/bin/hello_dyn")?;
    } // end if arch == "x86_64"

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
        b"root:x:0:0:root:/root:/bin/sh\n\
          alice:x:1000:1000:Alice User:/home/alice:/bin/sh\n\
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
