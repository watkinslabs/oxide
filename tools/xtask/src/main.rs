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
    // F153-1 erased userspace/init/ — PID 1 is now /sbin/init,
    // a hardlink to /bin/busybox (busybox dispatches the `init`
    // applet). What stays in `userspace/` is the kernel-acceptance
    // test surface: syscall-corner smokes (sem/msg/mq/ptrace/
    // ptrace_singlestep/mprotect), bare3 (real-musl-crt1 isolation
    // case for F62), and the dynamic-loader smokes (dynlink +
    // hello_dyn). All of those build against full musl crt1 — the
    // same path upstream busybox/coreutils/bash use.
    let crt_bins: &[(&str, &str)] = &[
        ("userspace/bare/bare3",                      "userspace/bare/bare3.c"),
        ("userspace/sem_smoke/sem_smoke",             "userspace/sem_smoke/sem_smoke.c"),
        ("userspace/msg_smoke/msg_smoke",             "userspace/msg_smoke/msg_smoke.c"),
        ("userspace/mq_smoke/mq_smoke",               "userspace/mq_smoke/mq_smoke.c"),
        ("userspace/ptrace_smoke/ptrace_smoke",       "userspace/ptrace_smoke/ptrace_smoke.c"),
        ("userspace/ptrace_singlestep_smoke/ptrace_singlestep_smoke",
                                                      "userspace/ptrace_singlestep_smoke/ptrace_singlestep_smoke.c"),
        ("userspace/mprotect_smoke/mprotect_smoke",   "userspace/mprotect_smoke/mprotect_smoke.c"),
    ];
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

    // dynlink is our v1 dynamic linker stub — keeps its own _start
    // (no musl crt1) since it IS the loader. Built per-arch and
    // staged at /lib/ld-musl-<arch>.so.1 below.
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

    // -pie (non-static) test binaries — emit PT_INTERP=/lib/ld-musl-<arch>.so.1
    // so the kernel exercises the dual-image load path through our
    // stub interpreter. Keep this list short until the full ld-musl
    // runtime lands; static-pie is the only flavor most utilities
    // need today. hello_dyn is now arch-portable (#ifdef syscall ABI).
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

    // F153-1: no embedded init blob. PID 1 lives in the rootfs as a
    // /sbin/init busybox hardlink; the kernel reads it from ext4 at
    // boot. Nothing to refresh under kernel/blobs/.

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
    // FHS skeleton (51§4). Empty mount-point dirs for rcS, plus
    // /home /root for login shells, /var/log for syslog.
    for d in &[
        "/bin", "/sbin", "/lib", "/lib64",
        "/etc", "/etc/init.d",
        "/proc", "/sys", "/tmp", "/run",
        "/dev", "/dev/pts",
        "/home", "/home/alice", "/root",
        "/var", "/var/log",
    ] {
        dbg(&format!("mkdir {d}"))?;
    }
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
    // Per-arch vendored busybox. x86_64 binary in vendor/busybox/busybox
    // (built via vendor/busybox/build.sh against musl-gcc); aarch64
    // binary in vendor/busybox/busybox-aarch64 (extracted from Alpine
    // Linux's busybox-static apk, statically linked against musl).
    let bb = if arch == "aarch64" {
        repo.join("vendor/busybox/busybox-aarch64")
    } else {
        repo.join("vendor/busybox/busybox")
    };
    if bb.is_file() {
        // Single copy of busybox at /bin/busybox; every applet path
        // becomes a hardlink (debugfs `ln <existing> <new>`) so the
        // ext4 image holds one inode + one set of blocks instead of
        // ~70 duplicates. busybox routes on argv[0], so reading
        // /bin/sh actually opens /bin/busybox and the kernel passes
        // "/bin/sh" as argv[0].
        put(&bb, "/bin/busybox")?;
        let dbg_ln = |target: &str, link: &str| -> Result<(), u8> {
            let cmd = format!("ln {} {}", target, link);
            let mut c = Command::new("debugfs");
            c.args(["-w", "-R", &cmd, img.to_str().unwrap()]);
            c.stdout(std::process::Stdio::null());
            c.stderr(std::process::Stdio::null());
            run(c)
        };
        // /bin applets — every user-facing tool dispatched via argv[0].
        for applet in &[
            "sh", "ash", "hush",
            "ls", "cat", "echo", "cp", "mv", "rm", "mkdir", "rmdir",
            "ps", "top", "uptime", "free", "dmesg", "mount", "umount",
            "grep", "egrep", "fgrep", "find", "head", "tail", "wc", "sort", "uniq",
            "touch", "chmod", "chown", "ln", "test", "true", "false",
            "env", "printf", "yes", "seq", "expr", "id", "whoami",
            "tr", "cut", "sed", "awk", "date", "df", "du", "stat",
            "kill", "sleep", "tee", "xxd", "hostname", "uname",
            "pwd", "basename", "dirname", "which", "clear", "reset",
            "more", "less", "vi", "tar", "gzip", "gunzip",
            "ifconfig", "route", "ping", "nc", "wget",
            "su", "passwd", "login", "getty", "init",
            "mknod", "stty", "tty", "mesg",
        ] {
            dbg_ln("/bin/busybox", &format!("/bin/{applet}"))?;
        }
        // /sbin applets — system-management dispatch. Per FHS, init,
        // halt, reboot, getty, mount.* live here. Hardlinking under
        // both /bin and /sbin matches every standard distro layout.
        for applet in &[
            "init", "halt", "reboot", "poweroff", "shutdown",
            "getty", "agetty", "login",
            "mdev", "ifconfig", "route", "ip",
            "mount", "umount",
            "fdisk", "swapon", "swapoff",
        ] {
            dbg_ln("/bin/busybox", &format!("/sbin/{applet}"))?;
        }
        // Kernel boot path probes /sbin/init then /init.
        dbg_ln("/bin/busybox", "/init")?;
    }
    // Kernel-acceptance smoke binaries. Real-musl-crt1 builds; every
    // user-facing tool comes from busybox hardlinks above.
    put(&user("bare3"),        "/bin/bare3")?;
    put(&user("sem_smoke"),    "/bin/sem_smoke")?;
    put(&user("msg_smoke"),    "/bin/msg_smoke")?;
    put(&user("mq_smoke"),     "/bin/mq_smoke")?;
    put(&user("ptrace_smoke"), "/bin/ptrace_smoke")?;
    put(&user("ptrace_singlestep_smoke"), "/bin/ptrace_singlestep_smoke")?;
    put(&user("mprotect_smoke"), "/bin/mprotect_smoke")?;
    // dynamic-linker stub at the per-arch musl path. The kernel's
    // ELF loader sees PT_INTERP="/lib/ld-musl-<arch>.so.1" in any
    // -pie binary and dual-loads this stub alongside the exec.
    let interp_path = if arch == "aarch64" {
        "/lib/ld-musl-aarch64.so.1"
    } else {
        "/lib/ld-musl-x86_64.so.1"
    };
    put(&user("dynlink"),   interp_path)?;
    put(&user("hello_dyn"), "/bin/hello_dyn")?;

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
    // F149-3: marker file gates init's userspace acceptance smokes.
    // Present → init runs sem/msg/mq/ptrace/etc. before dropping to
    // sh. Absent → init goes straight to sh (interactive boot path).
    // Default = staged so CI keeps exercising the kernel-IPC suite.
    // Set OXIDE_INIT_SMOKES=0 to skip the marker (interactive boot).
    if std::env::var("OXIDE_INIT_SMOKES").as_deref() != Ok("0") {
        put(&stage("oxide-init-smokes", b"1\n")?, "/etc/oxide-init-smokes")?;
    }
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
    // /etc/inittab per 51§5.1. busybox init reads this verbatim:
    //   <id>:<runlevels>:<action>:<process>
    // sysinit runs synchronously before respawn lines start.
    put(&stage("inittab",
b"::sysinit:/etc/init.d/rcS
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
tty1::respawn:/sbin/getty -L 38400 tty1 vt100
tty2::respawn:/sbin/getty -L 38400 tty2 vt100
")?,
        "/etc/inittab")?;

    // /etc/init.d/rcS — sysinit shell script per 51§5.2. Mounts
    // virtual filesystems, sets hostname, brings up loopback, then
    // optionally runs the kernel-acceptance smokes.
    put(&stage("rcS",
b"#!/bin/sh
mount -t proc  proc  /proc 2>/dev/null
mount -t sysfs sysfs /sys  2>/dev/null
mount -t tmpfs tmpfs /tmp  2>/dev/null
mount -t devpts devpts /dev/pts 2>/dev/null
hostname -F /etc/hostname 2>/dev/null
ifconfig lo 127.0.0.1 up 2>/dev/null
[ -x /etc/init.d/oxide-smokes ] && /etc/init.d/oxide-smokes
:
")?,
        "/etc/init.d/rcS")?;
    dbg("sif /etc/init.d/rcS mode 0100755")?;

    // /etc/init.d/oxide-smokes — kernel-acceptance smoke harness
    // (replaces the C harness from old userspace/init/init.c).
    // Gated by the marker file so OXIDE_INIT_SMOKES=0 boots skip it.
    put(&stage("oxide-smokes",
b"#!/bin/sh
[ -e /etc/oxide-init-smokes ] || exit 0
echo init-fork-exec works
for s in /bin/bare3 /bin/sem_smoke /bin/msg_smoke /bin/mq_smoke \\
         /bin/ptrace_smoke /bin/ptrace_singlestep_smoke \\
         /bin/mprotect_smoke /bin/hello_dyn ; do
    [ -x \"$s\" ] && \"$s\"
done
")?,
        "/etc/init.d/oxide-smokes")?;
    dbg("sif /etc/init.d/oxide-smokes mode 0100755")?;

    // /etc/profile — login-shell environment.
    put(&stage("profile",
b"export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PS1='\\h:\\w\\$ '
export TERM=linux
")?,
        "/etc/profile")?;

    // /etc/fstab (informational; for `mount -a`).
    put(&stage("fstab",
b"proc    /proc    proc    defaults  0 0
sysfs   /sys     sysfs   defaults  0 0
tmpfs   /tmp     tmpfs   defaults  0 0
devpts  /dev/pts devpts  defaults  0 0
")?,
        "/etc/fstab")?;

    // /etc/nsswitch.conf — files-only resolver.
    put(&stage("nsswitch.conf",
b"passwd: files
group:  files
shadow: files
hosts:  files
")?,
        "/etc/nsswitch.conf")?;

    put(&stage("hello.txt", b"hello-from-ext4-mini\n")?, "/hello.txt")?;

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
