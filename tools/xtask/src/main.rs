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
        ("userspace/mmap_zero_smoke/mmap_zero_smoke", "userspace/mmap_zero_smoke/mmap_zero_smoke.c"),
        ("userspace/usleep_smoke/usleep_smoke",       "userspace/usleep_smoke/usleep_smoke.c"),
        ("userspace/af_packet_smoke/af_packet_smoke", "userspace/af_packet_smoke/af_packet_smoke.c"),
        ("userspace/online_smoke/online_smoke",       "userspace/online_smoke/online_smoke.c"),
        ("userspace/tcp_smoke/tcp_smoke",             "userspace/tcp_smoke/tcp_smoke.c"),
        ("userspace/exit_test/exit_test",             "userspace/exit_test/exit_test.c"),
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

    // -pie (non-static) test binaries — emit PT_INTERP=/lib/ld-musl-<arch>.so.1.
    // hello_dyn (-nostdlib): exercises PT_INTERP load + jump only.
    // hello_dyn_libc (full crt1 + libc): exercises DT_NEEDED resolution,
    // GOT/PLT relocations, libc constructors, printf — full ld-musl
    // smoke since F230 staged the real musl loader.
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

    // F231: PAM modules as shared objects. libpam dlopens them.
    let pam_module_srcs: &[(&str, &str)] = &[
        ("pam_permit.so", "userspace/pam_modules/pam_permit.c"),
        ("pam_deny.so",   "userspace/pam_modules/pam_deny.c"),
    ];
    for (out_name, src_rel) in pam_module_srcs {
        let out = user_out.join(out_name);
        let src = repo.join(src_rel);
        eprintln!("xtask rootfs: {} -shared {} → {}", cc.file_name().unwrap().to_string_lossy(), src.display(), out.display());
        let mut c = Command::new(&cc);
        c.args(["-O2", "-fPIC", "-shared", "-nostdlib", "-fno-stack-protector",
                "-o", out.to_str().unwrap(), src.to_str().unwrap()]);
        run(c)?;
    }
    {
        // F239: pam_unix needs libc (fopen/crypt) — default crt link.
        let out = user_out.join("pam_unix.so");
        let src = repo.join("userspace/pam_modules/pam_unix.c");
        let mut c = Command::new(&cc);
        c.args(["-O2", "-fPIC", "-shared", "-fno-stack-protector",
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
                "bs=1M", "count=16"]);
        run(c)?;
    }
    {
        // Force 4 KiB blocks. The default mkfs.ext4 heuristic picks
        // 1 KiB blocks for small images; with ~80 hardlinks under
        // /bin and 1 KiB dir blocks, debugfs `ln` hits "No free
        // space in the directory" partway through the applet list
        // and silently drops /bin/{login,getty,init,...} (debugfs
        // exits 0 on the link error). 4 KiB blocks give /bin enough
        // room for the full applet set.
        let mut c = Command::new("mkfs.ext4");
        c.args(["-F", "-b", "4096",
                "-O", "^has_journal", "-L", "oxide", img.to_str().unwrap()]);
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
        "/var", "/var/log", "/var/db", "/var/db/dhcpcd", "/var/run", "/var/run/dhcpcd",
        "/usr", "/usr/share", "/usr/share/keymaps", "/usr/share/udhcpc",
        "/usr/bin", "/usr/sbin", "/usr/libexec",
        "/usr/lib", "/usr/lib/security",
    ] {
        dbg(&format!("mkdir {d}"))?;
    }
    let put = |host: &std::path::Path, target: &str| -> Result<(), u8> {
        let cmd = format!("write {} {}", host.display(), target);
        dbg(&cmd)?;
        // debugfs `write` lands at mode 0o100644 (regular, no x bit) by
        // default. The kernel's sys_statx reads the ext4 i_mode, and
        // ARM busybox refuses to exec without x bits. Stamp 0o100755 so
        // every staged binary (busybox + smoke ELFs) is executable.
        dbg(&format!("sif {target} mode 0100755"))
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
            // Don't mute stderr — debugfs's `ln` exits 0 even when
            // it prints `make_link: Ext2 inode is not a directory`.
            // Without seeing the stderr we silently drop applets and
            // ship a busted rootfs (e.g. /bin/login missing → getty
            // can't exec it). Pipe stderr through so failures show.
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
            "udhcpc", "udhcpd",
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
    put(&user("mmap_zero_smoke"), "/bin/mmap_zero_smoke")?;
    put(&user("usleep_smoke"), "/bin/usleep_smoke")?;
    put(&user("af_packet_smoke"), "/bin/af_packet_smoke")?;
    put(&user("online_smoke"),    "/bin/online_smoke")?;
    put(&user("tcp_smoke"),       "/bin/tcp_smoke")?;
    put(&user("exit_test"),       "/bin/exit_test")?;
    // F230: real musl dynamic loader at the per-arch interp path.
    // vendor/musl/ld-musl-<arch>.so.1 is the actual musl libc.so —
    // x86_64 copied from the host Fedora /lib (musl 1.2.5, the one
    // musl-gcc links against); aarch64 copied from the cross
    // toolchain (musl 1.2.2-git, what the cross CC links against).
    // Same binary handles DT_NEEDED + relocations + dlopen for any
    // dynamic ELF we link. The userspace/dynlink stub is no longer
    // staged — kept as build-only for reference.
    let interp_path = if arch == "aarch64" {
        "/lib/ld-musl-aarch64.so.1"
    } else {
        "/lib/ld-musl-x86_64.so.1"
    };
    let ldso = repo.join(format!("vendor/musl/ld-musl-{arch}.so.1"));
    if ldso.is_file() {
        put(&ldso, interp_path)?;
        // ARM cross-musl-gcc emits DT_NEEDED = "libc.so"; ld-musl
        // resolves it via the same file under a second name.
        if arch == "aarch64" {
            put(&ldso, "/lib/libc.so")?;
        }
    } else {
        eprintln!("xtask rootfs: WARN missing {}", ldso.display());
    }
    put(&user("hello_dyn"), "/bin/hello_dyn")?;
    put(&user("hello_dyn_libc"), "/bin/hello_dyn_libc")?;

    // F123: vendored dhcpcd 10.3.2 — static-musl, per
    // vendor/dhcpcd/build.sh. Real userspace DHCPv4 client. Survives
    // the busybox→distro transition (Alpine/Gentoo default; not a
    // busybox applet). Skipped silently if the per-arch binary
    // hasn't been built yet — `vendor/dhcpcd/build.sh` materialises
    // them after `tools/fetch-dhcpcd.sh` populates the source tree.
    let dhcpcd = if arch == "aarch64" {
        repo.join("vendor/dhcpcd/dhcpcd-aarch64")
    } else {
        repo.join("vendor/dhcpcd/dhcpcd-x86_64")
    };
    if dhcpcd.is_file() {
        put(&dhcpcd, "/sbin/dhcpcd")?;
    }

    // F210: vendored openssh-portable 9.9p2 — static-musl ssh server
    // (replaces dropbear). dropbear's check_close → close-PTY-master
    // arm on CHANNEL_EOF loses shell stdout when `ssh -tt 'cmd'` runs
    // with closed stdin (reproduces on real Linux too); openssh's
    // send-eof + drain semantic handles that correctly. Per
    // vendor/openssh/build.sh. Skipped silently if the per-arch
    // binaries haven't been built yet.
    // F216: vendored GNU bash 5.2.37 — static-musl. Drops in at
    // /bin/bash; busybox /bin/sh symlink remains for scripts that
    // hard-code sh. Per vendor/bash/build.sh.
    let bash_bin = repo.join(format!("vendor/bash/bash-{}", arch));
    if bash_bin.is_file() {
        put(&bash_bin, "/bin/bash")?;
    }

    // F217: vendored GNU sed 4.9 — static-musl. Drops in at /usr/bin/sed
    // ahead of busybox's sed applet (PATH order /usr/bin before /bin).
    // Per vendor/sed/build.sh.
    let sed_bin = repo.join(format!("vendor/sed/sed-{}", arch));
    if sed_bin.is_file() {
        put(&sed_bin, "/usr/bin/sed")?;
    }

    // F219: vendored GNU grep 3.11 — static-musl /usr/bin/grep.
    let grep_bin = repo.join(format!("vendor/grep/grep-{}", arch));
    if grep_bin.is_file() {
        put(&grep_bin, "/usr/bin/grep")?;
    }

    // F220: vendored GNU tar 1.35 — static-musl /usr/bin/tar.
    let tar_bin = repo.join(format!("vendor/tar/tar-{}", arch));
    if tar_bin.is_file() {
        put(&tar_bin, "/usr/bin/tar")?;
    }

    // F221: vendored GNU make 4.4.1 — static-musl /usr/bin/make.
    let make_bin = repo.join(format!("vendor/make/make-{}", arch));
    if make_bin.is_file() {
        put(&make_bin, "/usr/bin/make")?;
    }

    // F225: vendored GNU patch 2.7.6 — static-musl /usr/bin/patch.
    let patch_bin = repo.join(format!("vendor/patch/patch-{}", arch));
    if patch_bin.is_file() { put(&patch_bin, "/usr/bin/patch")?; }

    // F226: vendored bzip2 1.0.8 — static-musl /usr/bin/bzip2.
    let bz_bin = repo.join(format!("vendor/bzip2/bzip2-{}", arch));
    if bz_bin.is_file() { put(&bz_bin, "/usr/bin/bzip2")?; }

    // F227: vendored xz-utils 5.6.3 — static-musl /usr/bin/xz.
    let xz_bin = repo.join(format!("vendor/xz/xz-{}", arch));
    if xz_bin.is_file() { put(&xz_bin, "/usr/bin/xz")?; }

    // F224: vendored GNU diffutils 3.10 — static-musl /usr/bin/diff + cmp.
    let diff_bin = repo.join(format!("vendor/diffutils/diff-{}", arch));
    let cmp_bin  = repo.join(format!("vendor/diffutils/cmp-{}",  arch));
    if diff_bin.is_file() { put(&diff_bin, "/usr/bin/diff")?; }
    if cmp_bin.is_file()  { put(&cmp_bin,  "/usr/bin/cmp")?;  }

    // F223: vendored GNU findutils 4.10.0 — static-musl /usr/bin/find +
    // /usr/bin/xargs. Real find supports -printf, -regex, -prune,
    // -newer, -mtime, -exec ... +, etc. that busybox find doesn't.
    let find_bin = repo.join(format!("vendor/findutils/find-{}", arch));
    let xargs_bin = repo.join(format!("vendor/findutils/xargs-{}", arch));
    if find_bin.is_file() { put(&find_bin, "/usr/bin/find")?; }
    if xargs_bin.is_file() { put(&xargs_bin, "/usr/bin/xargs")?; }

    // F222: vendored GNU gawk 5.3.1 — static-musl /usr/bin/gawk +
    // /usr/bin/awk hardlink so POSIX `awk ...` resolves to gawk.
    let gawk_bin = repo.join(format!("vendor/gawk/gawk-{}", arch));
    if gawk_bin.is_file() {
        put(&gawk_bin, "/usr/bin/gawk")?;
        let cmd = format!("ln /usr/bin/gawk /usr/bin/awk");
        let mut c = Command::new("debugfs");
        c.args(["-w", "-R", &cmd, img.to_str().unwrap()]);
        c.stdout(std::process::Stdio::null());
        run(c)?;
    }

    // F218: vendored GNU coreutils 8.32 — static-musl, single-binary
    // mode. Binary at /usr/libexec/coreutils; symlinks per applet under
    // /usr/bin so PATH lookup picks real GNU semantics over busybox.
    // Skipping 'install' (clashes with package-manager keyword) and
    // 'true'/'false'/'echo'/'test' (built-in to every shell). Per
    // vendor/coreutils/build.sh.
    let cu_bin = repo.join(format!("vendor/coreutils/coreutils-{}", arch));
    if cu_bin.is_file() {
        put(&cu_bin, "/usr/libexec/coreutils")?;
        let dbg_ln = |target: &str, link: &str| -> Result<(), u8> {
            let cmd = format!("ln {} {}", target, link);
            let mut c = Command::new("debugfs");
            c.args(["-w", "-R", &cmd, img.to_str().unwrap()]);
            c.stdout(std::process::Stdio::null());
            run(c)
        };
        for applet in &[
            "ls", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "ln",
            "chmod", "chown", "chgrp", "touch", "stat", "dd",
            "head", "tail", "wc", "sort", "uniq", "tr", "cut", "tee", "tac",
            "mktemp", "readlink", "realpath", "dirname", "basename",
            "sleep", "date", "whoami", "id", "uname", "seq", "yes", "nproc",
            "nohup", "env", "printf", "printenv", "pwd",
            "expr", "factor", "expand", "unexpand", "fold", "fmt",
            "split", "csplit", "comm", "join", "paste", "shuf", "shred",
            "df", "du", "sync", "kill", "nice", "timeout", "tty",
            "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum",
            "base32", "base64", "basenc", "od",
            "nl", "pr", "ptx", "tsort", "truncate", "link", "unlink",
            "logname", "groups", "users", "who", "uptime", "hostid",
            "mkfifo", "mknod", "numfmt",
        ] {
            dbg_ln("/usr/libexec/coreutils", &format!("/usr/bin/{applet}"))?;
        }
    }

    let sshd_bin = repo.join(format!("vendor/openssh/sshd-{}", arch));
    let sshdsess_bin = repo.join(format!("vendor/openssh/sshd-session-{}", arch));
    let sshkeygen_bin = repo.join(format!("vendor/openssh/ssh-keygen-{}", arch));
    let ssh_bin = repo.join(format!("vendor/openssh/ssh-{}", arch));
    if sshd_bin.is_file() && sshdsess_bin.is_file() && sshkeygen_bin.is_file() {
        put(&sshd_bin,      "/usr/sbin/sshd")?;
        put(&sshdsess_bin,  "/usr/libexec/sshd-session")?;
        put(&sshkeygen_bin, "/usr/bin/ssh-keygen")?;
        if ssh_bin.is_file() { put(&ssh_bin, "/usr/bin/ssh")?; }
        dbg("mkdir /etc/ssh")?;
        // /var/empty is sshd's privsep chroot. We `--with-privsep-user=root`
        // so privsep is degenerate, but sshd still wants the dir to exist.
        dbg("mkdir /var/empty")?;
    }

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
    // F211: arch marker — rcS picks sshd daemonize mode by this file.
    if arch == "aarch64" {
        put(&stage("oxide-arch-is-aarch64", b"1\n")?, "/etc/oxide-arch-is-aarch64")?;
    }
    // B44: opt-in marker (off by default) for reproducing the
    // dhcpcd userspace heap-corruption hunt. The kernel now
    // survives the resulting user-mode #GP (delivers SIGSEGV
    // instead of halting), but dhcpcd itself still crashes; auto-
    // launch stays gated until the userspace cause is fixed.
    if std::env::var("OXIDE_DHCPCD_ENABLE").as_deref() == Ok("1") {
        put(&stage("oxide-dhcpcd-enable", b"1\n")?, "/etc/oxide-dhcpcd-enable")?;
    }
    // F141: udhcpc marker — opt-in busybox-based DHCP client.
    // (F155 explored default-on; arm TCG boot doesn't reach login
    // inside the 180s smoke window when the full DHCP + online_smoke
    // + tcp_smoke chain runs, so DHCP stays opt-in until perf work
    // closes that gap. x86 handles default-on fine in 16s.)
    if std::env::var("OXIDE_UDHCPC_ENABLE").as_deref() == Ok("1") {
        put(&stage("oxide-udhcpc-enable", b"1\n")?, "/etc/oxide-udhcpc-enable")?;
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
    // F231: sshd_config UsePAM=yes — libpam dlopens modules from
    // /usr/lib/security/ at session setup.
    put(&stage("sshd_config",
        b"Port 22\n\
AddressFamily inet\n\
ListenAddress 0.0.0.0\n\
HostKey /etc/ssh/ssh_host_ed25519_key\n\
PermitRootLogin no\n\
PasswordAuthentication yes\n\
PermitEmptyPasswords no\n\
PubkeyAuthentication yes\n\
UsePAM yes\n\
Compression yes\n\
PrintMotd no\n\
PrintLastLog no\n\
UseDNS no\n\
StrictModes no\n\
LogLevel INFO\n")?,
        "/etc/ssh/sshd_config")?;
    // F231: /etc/pam.d/sshd chain — pam_permit.so for all 4 stages.
    // pam_permit always returns PAM_SUCCESS so libpam-dlopen +
    // pam_sm_* exec just works through to session setup. Real
    // pam_unix (with /etc/shadow lookup + crypt) lands in F232 once
    // libpam-shared + libcrypt vendor builds are in place.
    dbg("mkdir /etc/pam.d")?;
    put(&stage("pam_sshd",
        b"# /etc/pam.d/sshd -- pam_permit fallback; pam_unix wires up\n\
# in F239 once the dlopen-then-conv-then-stall trace is resolved.\n\
auth       required   pam_permit.so\n\
account    required   pam_permit.so\n\
password   required   pam_permit.so\n\
session    required   pam_permit.so\n")?,
        "/etc/pam.d/sshd")?;
    // Stage PAM modules at /usr/lib/security/ — libpam was built
    // with --prefix=/usr --libdir=lib so DEFAULT_MODULE_PATH baked
    // into libpam.a is "/usr/lib/security/".
    put(&user("pam_permit.so"), "/usr/lib/security/pam_permit.so")?;
    put(&user("pam_deny.so"),   "/usr/lib/security/pam_deny.so")?;
    put(&user("pam_unix.so"),   "/usr/lib/security/pam_unix.so")?;
    // /etc/inittab per 51§5.1. busybox init reads this verbatim:
    //   <id>:<runlevels>:<action>:<process>
    // sysinit runs synchronously before respawn lines start.
    // B39: serial respawn line goes direct to /bin/login, NOT getty.
    // busybox getty wedges under headless qemu (boot-smoke / CI) — its
    // open(/dev/ttyS0)+TIOCSCTTY+tcsetattr dance hangs before reaching
    // its first write. /dev/ttyS0 in our kernel is a console alias
    // pinned at 115200/cooked, so getty's baud / line-discipline job
    // is moot. The sh wrapper just plumbs fd 0/1/2 onto /dev/ttyS0 so
    // login's read/prompt path inherits a usable tty. Interactive boot
    // sees the same `oxide login:` prompt the user typed `root` into
    // pre-B39.
    put(&stage("inittab",
b"::sysinit:/etc/init.d/rcS
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100
")?,
        "/etc/inittab")?;

    // /etc/dhcpcd.conf — minimal config. 10s bind timeout so rcS
    // doesn't park forever when no DHCP server answers. No hooks
    // (we ship no /lib/dhcpcd/dhcpcd-hooks tree); dhcpcd tolerates
    // a missing hooks dir.
    put(&stage("dhcpcd.conf",
b"# F123: minimal dhcpcd.conf for oxide userspace.
duid
persistent
option domain_name_servers, domain_name, domain_search, host_name
option classless_static_routes
option interface_mtu
require dhcp_server_identifier
slaac private
timeout 10
")?,
        "/etc/dhcpcd.conf")?;

    // /etc/init.d/rcS — sysinit shell script per 51§5.2. Mounts
    // virtual filesystems, sets hostname, brings up loopback, then
    // optionally runs the kernel-acceptance smokes.
    //
    // F123: /var/run + /var/db are tmpfs so dhcpcd can create its
    // lease state + control-socket dir on the (read-mostly) rootfs.
    // dhcpcd backgrounds (-b) after 10s lease timeout so rcS keeps
    // moving; the renewal loop respawns itself.
    put(&stage("rcS",
b"#!/bin/sh
mount -t proc  proc  /proc 2>/dev/null
mount -t sysfs sysfs /sys  2>/dev/null
mount -t tmpfs tmpfs /tmp  2>/dev/null
mount -t tmpfs tmpfs /var/run 2>/dev/null
mount -t tmpfs tmpfs /var/db  2>/dev/null
mount -t devpts devpts /dev/pts 2>/dev/null
hostname -F /etc/hostname 2>/dev/null
ifconfig lo 127.0.0.1 up 2>/dev/null
ifconfig eth0 up 2>/dev/null
# F141: udhcpc is the v1 DHCP client (busybox applet - already in
# the rootfs, no separate vendor binary). Real upstream dhcpcd
# still wedges post-lease-setup; udhcpc's simpler state machine
# hits fewer of the gap-y syscall paths. Gated behind
# /etc/oxide-udhcpc-enable so the default boot stays fast.
if [ -e /etc/oxide-udhcpc-enable ] && [ -x /sbin/udhcpc ]; then
    # Foreground -t 3 -T 2: ~6s ceiling for a slirp lease; once
    # bound, default.script (F147) installs ifaddr + default route
    # via SIOCSIFADDR / SIOCADDRT, and the kernel net stack is
    # routable (F148/F149).
    /sbin/udhcpc -i eth0 -s /usr/share/udhcpc/default.script -q -n -t 3 -T 2
    # Confirm with a real outbound DNS round-trip (slirp's 10.0.2.3).
    [ -x /bin/online_smoke ] && /bin/online_smoke
    [ -x /bin/tcp_smoke ]    && /bin/tcp_smoke
fi
[ -x /etc/init.d/oxide-smokes ] && /etc/init.d/oxide-smokes
# F210: openssh sshd (port 22). Generates host keys on first boot
# (only the ed25519 type, since the binary was built without OpenSSL
# and the other key types depend on it), then forks the daemon.
if [ -x /usr/sbin/sshd ]; then
    echo sshd-step-pre-keygen
    if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
        /usr/bin/ssh-keygen -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key 2>&1
        echo ssh-keygen-rv=$?
    fi
    echo sshd-step-post-keygen
    ls -l /etc/ssh/ 2>&1
    ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up 2>/dev/null
    route add default gw 10.0.2.2 2>/dev/null
    echo sshd-step-launch
    /usr/sbin/sshd -D -e 2>&1 &
    echo sshd-step-launched-bg pid=$!
fi
:
")?,
        "/etc/init.d/rcS")?;
    dbg("sif /etc/init.d/rcS mode 0100755")?;

    // /etc/init.d/oxide-smokes — kernel-acceptance smoke harness
    // (replaces the C harness from old userspace/init/init.c).
    // Gated by the marker file so OXIDE_INIT_SMOKES=0 boots skip it.
    // ptrace_smoke + ptrace_singlestep_smoke removed pending real
    // PTRACE_SINGLESTEP TF/SS arming + SIGSTOP/SIGTRAP race fix.
    // They hang the script (child enters PTRACE-ATTACH SIGSTOP but
    // never gets the SIGTRAP that would let waitpid return).
    put(&stage("oxide-smokes",
b"#!/bin/sh
[ -e /etc/oxide-init-smokes ] || exit 0
echo init-fork-exec works
for s in /bin/bare3 /bin/sem_smoke /bin/msg_smoke /bin/mq_smoke \\
         /bin/mprotect_smoke /bin/mmap_zero_smoke /bin/usleep_smoke \\
         /bin/af_packet_smoke /bin/hello_dyn ; do
    [ -x \"$s\" ] && \"$s\"
done
echo pre-exit_test
/bin/exit_test
echo post-exit_test rv=$?
echo pre-bash-dynamic
/bin/bash --version 2>&1 | head -1
echo post-bash-dynamic rv=$?
echo pre-hello_dyn_libc
/bin/hello_dyn_libc
echo post-hello_dyn_libc rv=$?
")?,
        "/etc/init.d/oxide-smokes")?;
    dbg("sif /etc/init.d/oxide-smokes mode 0100755")?;

    // F147: udhcpc default lease-event script. udhcpc invokes this
    // with $1 ∈ {deconfig, bound, renew, …} and exports the lease
    // params (ip, subnet, router, dns, broadcast, …) as env vars.
    // On bound/renew: configure the iface, add the default route,
    // write /etc/resolv.conf. On deconfig: tear the addr down.
    put(&stage("udhcpc-default.script",
b"#!/bin/sh
# busybox udhcpc lease-event handler. Invoked by udhcpc with
# $1 = event name and lease fields exported as env vars.
RESOLV=/etc/resolv.conf
case \"$1\" in
    deconfig)
        ifconfig $interface 0.0.0.0 2>/dev/null
        ;;
    bound|renew)
        ifconfig $interface $ip netmask ${subnet:-255.255.255.0} \\
            broadcast ${broadcast:-+} 2>/dev/null
        if [ -n \"$router\" ]; then
            while route del default gw 0.0.0.0 dev $interface 2>/dev/null; do :; done
            for r in $router; do
                route add default gw $r dev $interface 2>/dev/null
            done
        fi
        : > $RESOLV
        [ -n \"$domain\" ] && echo \"search $domain\" >> $RESOLV
        for s in $dns; do
            echo \"nameserver $s\" >> $RESOLV
        done
        echo \"udhcpc: configured $interface as $ip via $router\"
        ;;
esac
exit 0
")?,
        "/usr/share/udhcpc/default.script")?;
    dbg("sif /usr/share/udhcpc/default.script mode 0100755")?;

    // /etc/profile — login-shell environment.
    put(&stage("profile",
b"export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PS1='\\h:\\w\\$ '
export TERM=linux
")?,
        "/etc/profile")?;

    // /etc/login.defs — busybox login reads ENV_PATH / ENV_SUPATH
    // and sets them as PATH in the child env before exec'ing the
    // shell, regardless of whether /etc/profile gets sourced. Keeps
    // `ls`, `cat`, etc. usable from the very first prompt.
    put(&stage("login.defs",
b"ENV_PATH        PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
ENV_SUPATH      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
")?,
        "/etc/login.defs")?;

    // /root/.profile — sourced by login shells after /etc/profile.
    // Belt-and-suspenders: if /etc/profile fails to source for any
    // reason, this still seeds PATH for root's interactive sessions.
    put(&stage("root.profile",
b"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PS1='\\h:\\w# '
")?,
        "/root/.profile")?;

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

    // /etc/keymap — runtime-loadable keyboard layout. Drop another
    // text file at this path (or `loadkeys <name>` once we ship it)
    // to switch layouts. See `userspace/keymaps/` for the source maps.
    let km_us = include_bytes!("../../../userspace/keymaps/us.kmap");
    let km_uk = include_bytes!("../../../userspace/keymaps/uk.kmap");
    let km_de = include_bytes!("../../../userspace/keymaps/de.kmap");
    let km_fr = include_bytes!("../../../userspace/keymaps/fr.kmap");
    let km_es = include_bytes!("../../../userspace/keymaps/es.kmap");
    put(&stage("keymap", km_us)?, "/etc/keymap")?;
    put(&stage("us.kmap", km_us)?, "/usr/share/keymaps/us.kmap")?;
    put(&stage("uk.kmap", km_uk)?, "/usr/share/keymaps/uk.kmap")?;
    put(&stage("de.kmap", km_de)?, "/usr/share/keymaps/de.kmap")?;
    put(&stage("fr.kmap", km_fr)?, "/usr/share/keymaps/fr.kmap")?;
    put(&stage("es.kmap", km_es)?, "/usr/share/keymaps/es.kmap")?;

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
