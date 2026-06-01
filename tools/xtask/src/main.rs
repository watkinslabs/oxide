// xtask: CI entry, 07§8.
use std::process::{Command, ExitCode};

mod cmds;
mod image_qemu;
mod l2_deps;

use crate::cmds::{cmd_doc_check, cmd_kernel, cmd_spec_lint, cmd_test, parse_arg, run, stub};

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

/// Build a dynamic-link probe (`userspace/<probe>/<probe>.c`) against a
/// cross-built L2 shared lib in `vendor/<vendor>/install-<arch>`, linking
/// `<lflag>` (e.g. `-lcap`) with rpath /usr/lib. Track L2 helper.
fn dyn_probe(cc: &std::path::Path, repo: &std::path::Path, arch: &str,
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

/// Per-arch rootfs build. --arch <x86_64|aarch64>.
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
    // Per-arch userspace build dir.
    let user_out = repo.join(format!("target/userspace-{arch}"));
    std::fs::create_dir_all(&user_out).map_err(|_| 1u8)?;
    eprintln!("xtask rootfs: arch={arch} CC={}", cc.display());

    // 1. Build userspace binaries via musl-gcc — static-musl
    // kernel-acceptance smokes + dynamic-loader test binaries.
    let crt_bins: &[(&str, &str)] = &[
        ("userspace/bare/bare3",                      "userspace/bare/bare3.c"),
        ("userspace/sem_smoke/sem_smoke",             "userspace/sem_smoke/sem_smoke.c"),
        ("userspace/msg_smoke/msg_smoke",             "userspace/msg_smoke/msg_smoke.c"),
        ("userspace/mq_smoke/mq_smoke",               "userspace/mq_smoke/mq_smoke.c"),
        ("userspace/ptrace_smoke/ptrace_smoke",       "userspace/ptrace_smoke/ptrace_smoke.c"),
        ("userspace/ptrace_singlestep_smoke/ptrace_singlestep_smoke",
                                                      "userspace/ptrace_singlestep_smoke/ptrace_singlestep_smoke.c"),
        ("userspace/mprotect_smoke/mprotect_smoke",   "userspace/mprotect_smoke/mprotect_smoke.c"),
        ("userspace/mremap_dontunmap_smoke/mremap_dontunmap_smoke",
                                                      "userspace/mremap_dontunmap_smoke/mremap_dontunmap_smoke.c"),
        ("userspace/inet6_smoke/inet6_smoke",         "userspace/inet6_smoke/inet6_smoke.c"),
        ("userspace/mmsg_smoke/mmsg_smoke",           "userspace/mmsg_smoke/mmsg_smoke.c"),
        ("userspace/scm_smoke/scm_smoke",             "userspace/scm_smoke/scm_smoke.c"),
        ("userspace/cgroup_smoke/cgroup_smoke",       "userspace/cgroup_smoke/cgroup_smoke.c"),
        ("userspace/cmdsubst_probe/cmdsubst_probe",   "userspace/cmdsubst_probe/cmdsubst_probe.c"),
        ("userspace/alarm_probe/alarm_probe",         "userspace/alarm_probe/alarm_probe.c"),
        ("userspace/symlink_probe/symlink_probe",     "userspace/symlink_probe/symlink_probe.c"),
        ("userspace/mount_smoke/mount_smoke",         "userspace/mount_smoke/mount_smoke.c"),
        ("userspace/statfs_smoke/statfs_smoke",       "userspace/statfs_smoke/statfs_smoke.c"),
        ("userspace/fsmount_probe/fsmount_probe",     "userspace/fsmount_probe/fsmount_probe.c"),
        ("userspace/memfd_seal_probe/memfd_seal_probe", "userspace/memfd_seal_probe/memfd_seal_probe.c"),
        ("userspace/uevent_probe/uevent_probe",       "userspace/uevent_probe/uevent_probe.c"),
        ("userspace/rtlink_probe/rtlink_probe",       "userspace/rtlink_probe/rtlink_probe.c"),
        ("userspace/dev_smoke/dev_smoke",             "userspace/dev_smoke/dev_smoke.c"),
        ("userspace/mmap_zero_smoke/mmap_zero_smoke", "userspace/mmap_zero_smoke/mmap_zero_smoke.c"),
        ("userspace/usleep_smoke/usleep_smoke",       "userspace/usleep_smoke/usleep_smoke.c"),
        ("userspace/af_packet_smoke/af_packet_smoke", "userspace/af_packet_smoke/af_packet_smoke.c"),
        ("userspace/online_smoke/online_smoke",       "userspace/online_smoke/online_smoke.c"),
        ("userspace/tcp_smoke/tcp_smoke",             "userspace/tcp_smoke/tcp_smoke.c"),
        ("userspace/exit_test/exit_test",             "userspace/exit_test/exit_test.c"),
        ("userspace/socketpair_fork_probe/socketpair_fork_probe",
                                                      "userspace/socketpair_fork_probe/socketpair_fork_probe.c"),
        ("userspace/vim_smoke/vim_smoke",             "userspace/vim_smoke/vim_smoke.c"),
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

    // pthread probes.
    let pthread_bins: &[(&str, &str)] = &[
        ("userspace/pthread_socketpair_probe/pthread_socketpair_probe",
         "userspace/pthread_socketpair_probe/pthread_socketpair_probe.c"),
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

    // F153-1: no embedded init blob. PID 1 lives in the rootfs as a
    // /sbin/init busybox hardlink; the kernel reads it from ext4 at
    // boot. Nothing to refresh under kernel/blobs/.

    // Rootfs 16→32(F251)→128(F345): L2 lib tree overflowed 32 MiB (arm wedged pre-init, dropped files); 128 leaves D6 headroom.
    let img = repo.join(format!("kernel/blobs/rootfs-{arch}.img"));
    eprintln!("xtask rootfs: mkfs.ext4 {}", img.display());
    {
        let mut c = Command::new("dd");
        c.args(["if=/dev/zero",
                &format!("of={}", img.display()),
                "bs=1M", "count=128"]);
        run(c)?;
    }
    {
        // 4 KiB blocks (default heuristic picks 1 KiB, too small for /bin).
        let mut c = Command::new("mkfs.ext4");
        c.args(["-F", "-b", "4096",
                "-O", "^has_journal", "-L", "oxide", img.to_str().unwrap()]);
        run(c)?;
    }

    // 3. Populate via debugfs (one -R command per invocation).
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
        // F252: terminfo db for ncurses-linked programs.
        "/usr/share/terminfo", "/usr/share/terminfo/d", "/usr/share/terminfo/l",
        "/usr/share/terminfo/s", "/usr/share/terminfo/v", "/usr/share/terminfo/x",
    ] {
        dbg(&format!("mkdir {d}"))?;
    }
    let put = |host: &std::path::Path, target: &str| -> Result<(), u8> {
        dbg(&format!("write {} {target}", host.display()))?;
        dbg(&format!("sif {target} mode 0100755"))  // make executable
    };
    let user = |name: &str| user_out.join(name);
    // busybox 1.37.0 static-musl. Per-arch binary, argv[0]-dispatched.
    let bb = if arch == "aarch64" {
        repo.join("vendor/busybox/busybox-aarch64")
    } else {
        repo.join("vendor/busybox/busybox")
    };
    if bb.is_file() {
        // Single copy at /bin/busybox; every applet path is a hardlink
        // (debugfs `ln`) → one inode vs ~70 dups. busybox routes on
        // argv[0], so /bin/sh opens /bin/busybox with argv[0]="/bin/sh".
        put(&bb, "/bin/busybox")?;
        let dbg_ln = |target: &str, link: &str| -> Result<(), u8> {
            let cmd = format!("ln {} {}", target, link);
            let mut c = Command::new("debugfs");
            c.args(["-w", "-R", &cmd, img.to_str().unwrap()]);
            c.stdout(std::process::Stdio::null());
            // Don't mute stderr — debugfs `ln` exits 0 even on
            // `make_link: Ext2 inode is not a directory`; muting it
            // silently drops applets and ships a busted rootfs.
            run(c)
        };
        // /bin applets — every user-facing tool dispatched via argv[0].
        for applet in &[
            "ash", "hush",
            "ls", "cat", "echo", "cp", "mv", "rm", "mkdir", "rmdir",
            "dmesg",
            "grep", "egrep", "fgrep", "find", "head", "tail", "wc", "sort", "uniq",
            "touch", "chmod", "chown", "ln", "test", "true", "false",
            "env", "printf", "yes", "seq", "expr", "id", "whoami",
            "tr", "cut", "sed", "awk", "date", "df", "du", "stat",
            "sleep", "tee", "xxd", "hostname", "uname",
            "pwd", "basename", "dirname", "which", "clear", "reset",
            "more", "less", "vi", "tar", "gzip", "gunzip",
            "ifconfig", "route", "ping", "nc", "wget",
            "mknod", "stty", "tty", "mesg",
        ] {
            dbg_ln("/bin/busybox", &format!("/bin/{applet}"))?;
        }
        // /sbin applets per FHS. F259 util-linux owns login/agetty/su.
        // mount/umount stay on busybox for rcS (util-linux mount on x86
        // is non-PIE dynamic, won't load yet; rebuild as PIE later).
        for applet in &[
            "init", "halt", "reboot", "poweroff", "shutdown",
            "mdev", "ifconfig", "route",
            "fdisk", "swapon", "swapoff",
            "mount", "umount",
            "udhcpc", "udhcpd",
        ] {
            dbg_ln("/bin/busybox", &format!("/sbin/{applet}"))?;
        }
        // /bin alias of mount/umount so rcS's `mount -t proc proc /proc`
        // (no leading slash) resolves -- /bin precedes /sbin in PATH.
        dbg_ln("/bin/busybox", "/bin/mount")?;
        dbg_ln("/bin/busybox", "/bin/umount")?;
        // Kernel boot path probes /sbin/init then /init.
        dbg_ln("/bin/busybox", "/init")?;
    }
    // Kernel-acceptance smoke binaries. Real-musl-crt1 builds; every
    // user-facing tool comes from busybox hardlinks above.
    put(&user("bare3"),        "/bin/bare3")?;
    put(&user("sptest"),       "/bin/sptest")?;
    put(&user("pamtest"),      "/bin/pamtest")?;
    put(&user("login_sim"),    "/bin/login_sim")?;
    put(&user("sem_smoke"),    "/bin/sem_smoke")?;
    put(&user("msg_smoke"),    "/bin/msg_smoke")?;
    put(&user("mq_smoke"),     "/bin/mq_smoke")?;
    put(&user("ptrace_smoke"), "/bin/ptrace_smoke")?;
    put(&user("ptrace_singlestep_smoke"), "/bin/ptrace_singlestep_smoke")?;
    put(&user("mprotect_smoke"), "/bin/mprotect_smoke")?;
    put(&user("mremap_dontunmap_smoke"), "/bin/mremap_dontunmap_smoke")?;
    put(&user("inet6_smoke"),  "/bin/inet6_smoke")?;
    put(&user("mmsg_smoke"),   "/bin/mmsg_smoke")?;
    put(&user("scm_smoke"),    "/bin/scm_smoke")?;
    put(&user("cgroup_smoke"), "/bin/cgroup_smoke")?;
    put(&user("cmdsubst_probe"), "/bin/cmdsubst_probe")?;
    put(&user("alarm_probe"), "/bin/alarm_probe")?;
    put(&user("symlink_probe"), "/bin/symlink_probe")?;
    put(&user("mount_smoke"), "/bin/mount_smoke")?;
    put(&user("statfs_smoke"), "/bin/statfs_smoke")?;
    put(&user("fsmount_probe"), "/bin/fsmount_probe")?;
    put(&user("memfd_seal_probe"), "/bin/memfd_seal_probe")?;
    put(&user("uevent_probe"), "/bin/uevent_probe")?;
    put(&user("rtlink_probe"), "/bin/rtlink_probe")?;
    put(&user("dev_smoke"), "/bin/dev_smoke")?;
    put(&user("vim_smoke"),      "/bin/vim_smoke")?;
    put(&user("mmap_zero_smoke"), "/bin/mmap_zero_smoke")?;
    put(&user("usleep_smoke"), "/bin/usleep_smoke")?;
    put(&user("af_packet_smoke"), "/bin/af_packet_smoke")?;
    put(&user("online_smoke"),    "/bin/online_smoke")?;
    put(&user("tcp_smoke"),       "/bin/tcp_smoke")?;
    put(&user("exit_test"),       "/bin/exit_test")?;
    put(&user("pthread_socketpair_probe"), "/bin/pthread_socketpair_probe")?;
    put(&user("socketpair_fork_probe"),    "/bin/socketpair_fork_probe")?;
    // F230: musl dynamic loader → /lib/ld-musl-<arch>.so.1.
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
    for (_, probe, _) in l2_deps::L2_PROBES {
        put(&user(probe), &format!("/bin/{probe}"))?;
    }

    // F123: dhcpcd 10.3.2 static-musl → /sbin/dhcpcd.
    let dhcpcd = if arch == "aarch64" {
        repo.join("vendor/dhcpcd/dhcpcd-aarch64")
    } else {
        repo.join("vendor/dhcpcd/dhcpcd-x86_64")
    };
    if dhcpcd.is_file() {
        put(&dhcpcd, "/sbin/dhcpcd")?;
    }

    // F216: bash 5.2.37 → /bin/bash and /bin/sh (F258).
    let bash_bin = repo.join(format!("vendor/bash/bash-{}", arch));
    if bash_bin.is_file() {
        put(&bash_bin, "/bin/bash")?;
        // F-bash-as-sh: bash IS the shell now. busybox-ash drops out
        // of /bin/sh slot (the "sh" applet is no longer hardlinked
        // above). Login / sshd / shebangs that resolve "/bin/sh"
        // now hit GNU bash 5.2.
        put(&bash_bin, "/bin/sh")?;
    }

    let ln_via_debugfs = |target: &str, link: &str| -> Result<(), u8> {
        let mut c = Command::new("debugfs");
        c.args(["-w", "-R", &format!("ln {target} {link}"), img.to_str().unwrap()]);
        c.stdout(std::process::Stdio::null());
        run(c)
    };
    // F259 (D1): util-linux.
    for (name, dest) in &[
        ("login",   "/bin/login"),
        ("agetty",  "/sbin/agetty"),
        // util-linux mount is non-PIE dynamic on x86 → fails to load
        // under our kernel; busybox mount stays at /bin/mount.
        ("mount",   "/usr/sbin/mount.util-linux"),
        ("umount",  "/usr/sbin/umount.util-linux"),
        ("su",      "/bin/su"),
        ("kill",    "/bin/kill"),
        ("cal",     "/usr/bin/cal"),
        ("losetup", "/sbin/losetup"),
    ] {
        let host = repo.join(format!("vendor/util-linux/{name}-{arch}"));
        if host.is_file() {
            put(&host, dest)?;
        }
    }
    ln_via_debugfs("/sbin/agetty",  "/sbin/getty")?;
    ln_via_debugfs("/bin/login",    "/usr/bin/login")?;
    ln_via_debugfs("/bin/su",       "/usr/bin/su")?;

    // F260 (D2): shadow-utils — useradd/passwd/groupadd/etc.
    for (name, dest) in &[
        ("useradd",   "/usr/sbin/useradd"),
        ("userdel",   "/usr/sbin/userdel"),
        ("usermod",   "/usr/sbin/usermod"),
        ("groupadd",  "/usr/sbin/groupadd"),
        ("groupdel",  "/usr/sbin/groupdel"),
        ("groupmod",  "/usr/sbin/groupmod"),
        ("passwd",    "/usr/bin/passwd"),
        ("chage",     "/usr/bin/chage"),
        ("gpasswd",   "/usr/bin/gpasswd"),
        ("newgrp",    "/usr/bin/newgrp"),
        ("chgpasswd", "/usr/sbin/chgpasswd"),
    ] {
        let host = repo.join(format!("vendor/shadow/{name}-{arch}"));
        if host.is_file() {
            put(&host, dest)?;
        }
    }
    ln_via_debugfs("/usr/bin/passwd", "/bin/passwd")?;

    // F261 (D3): procps-ng — ps/top/free/etc.
    for (name, dest) in &[
        ("ps","/bin/ps"),("top","/usr/bin/top"),("free","/usr/bin/free"),
        ("vmstat","/usr/bin/vmstat"),("uptime","/usr/bin/uptime"),
        ("pgrep","/usr/bin/pgrep"),("pkill","/usr/bin/pkill"),
        ("pmap","/usr/bin/pmap"),("tload","/usr/bin/tload"),
        ("w","/usr/bin/w"),("watch","/usr/bin/watch"),
        ("slabtop","/usr/bin/slabtop"),("sysctl","/sbin/sysctl"),
    ] {
        let host = repo.join(format!("vendor/procps-ng/{name}-{arch}"));
        if host.is_file() {
            put(&host, dest)?;
        }
    }

    // F262 (D4): iproute2 — ip, ss, tc, bridge, etc.
    for (name, dest) in &[
        ("ip","/sbin/ip"),("ss","/sbin/ss"),("tc","/sbin/tc"),
        ("bridge","/sbin/bridge"),("rtmon","/sbin/rtmon"),
        ("lnstat","/usr/sbin/lnstat"),("nstat","/usr/sbin/nstat"),
        ("ifstat","/usr/sbin/ifstat"),
    ] {
        let host = repo.join(format!("vendor/iproute2/{name}-{arch}"));
        if host.is_file() {
            put(&host, dest)?;
        }
    }
    ln_via_debugfs("/sbin/ip", "/bin/ip")?;

    // F251: vim 9.1.0950 static-musl + vendored ncurses → /usr/bin/vim.
    let vim_bin = repo.join(format!("vendor/vim/vim-{}", arch));
    if vim_bin.is_file() {
        put(&vim_bin, "/usr/bin/vim")?;
    }

    // F254: less 643 static-musl + vendored ncurses → /usr/bin/less.
    let less_bin = repo.join(format!("vendor/less/less-{}", arch));
    if less_bin.is_file() {
        put(&less_bin, "/usr/bin/less")?;
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

    // F218: coreutils 8.32 single-binary at /usr/libexec/coreutils.
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
    // K2V V6: symlink-follow fixture for /bin/symlink_probe (ext4 symlink
    // CREATE isn't implemented, so bake a real ext4 symlink at build).
    put(&stage("sl_target", b"SLOK")?, "/sl_target")?;
    dbg("symlink /sl_link /sl_target")?;
    // F149-3: present → init runs kernel-acceptance smokes (set 0 to skip).
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
    // F141: udhcpc marker — opt-in busybox DHCP client.
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
    dbg("mkdir /etc/pam.d")?;
    put(&stage("pam_sshd",
        b"# pam_unix activated -- openssh built with real pthread\n\
# (-DUNSUPPORTED_POSIX_THREADS_HACK) + 128 MB kernel heap (F246).\n\
auth       required   pam_unix.so\n\
account    required   pam_unix.so\n\
password   required   pam_unix.so\n\
session    required   pam_unix.so\n")?,
        "/etc/pam.d/sshd")?;
    // B18: util-linux login(1) calls pam_start("login",...); without
    // /etc/pam.d/login libpam aborts with PAM_ABORT before any prompt
    // ("PAM failure, aborting: Critical error - immediate abort"), so
    // console login was broken since util-linux landed in D1. Mirror
    // the sshd stack: full pam_unix once T14 lands a real one; for now
    // the stub unblocks the console.
    put(&stage("pam_login",
        b"# B18: console login PAM stack - mirrors the sshd stack so
# the same pam_unix.so + /etc/shadow flow drives both login paths.
auth       required   pam_unix.so
account    required   pam_unix.so
password   required   pam_unix.so
session    required   pam_unix.so
")?,
        "/etc/pam.d/login")?;
    // Stage PAM modules at /usr/lib/security/ — libpam was built
    // with --prefix=/usr --libdir=lib so DEFAULT_MODULE_PATH baked
    // into libpam.a is "/usr/lib/security/". Sources are upstream
    // Linux-PAM 1.7.2 under vendor/pam/Linux-PAM-1.7.2/modules/,
    // built by vendor/pam/build.sh into install-<arch>/modules/.
    let pam_vendor = |name: &str| pam_vendor_sec.join(name);
    put(&pam_vendor("pam_permit.so"),  "/usr/lib/security/pam_permit.so")?;
    put(&pam_vendor("pam_deny.so"),    "/usr/lib/security/pam_deny.so")?;
    put(&pam_vendor("pam_nologin.so"), "/usr/lib/security/pam_nologin.so")?;
    put(&pam_vendor("pam_warn.so"),    "/usr/lib/security/pam_warn.so")?;
    put(&pam_vendor("pam_rootok.so"),  "/usr/lib/security/pam_rootok.so")?;
    put(&pam_vendor("pam_unix.so"),    "/usr/lib/security/pam_unix.so")?;
    // unix_chkpwd setuid helper — non-root callers (su, passwd) fork
    // it to validate /etc/shadow without needing read access themselves.
    // B18 diagnostic: stage the real binary at .real, install a shell
    // wrapper at the canonical path that captures stdin + stderr to
    // /tmp/chkpwd.* so we can see exactly what pam_unix's child reads
    // and prints. Wrapper is staged here only — no vendor code touched.
    let chkpwd_src = repo.join(format!("vendor/pam/install-{arch}/unix_chkpwd"));
    put(&chkpwd_src, "/usr/sbin/unix_chkpwd")?;
    // Shared libpam + libpam_misc — login, sshd, su DT_NEEDED them.
    // Modules dlopen at runtime against the same libpam.so loaded in
    // the host process; that's the standard Linux-PAM ecosystem flow.
    let pam_lib = repo.join(format!("vendor/pam/install-{arch}/lib"));
    put(&pam_lib.join("libpam.so.0.85.1"),         "/usr/lib/libpam.so.0.85.1")?;
    put(&pam_lib.join("libpam_misc.so.0.82.1"),    "/usr/lib/libpam_misc.so.0.82.1")?;
    ln_via_debugfs("/usr/lib/libpam.so.0.85.1",      "/usr/lib/libpam.so.0")?;
    ln_via_debugfs("/usr/lib/libpam.so.0.85.1",      "/usr/lib/libpam.so")?;
    ln_via_debugfs("/usr/lib/libpam_misc.so.0.82.1", "/usr/lib/libpam_misc.so.0")?;
    ln_via_debugfs("/usr/lib/libpam_misc.so.0.82.1", "/usr/lib/libpam_misc.so")?;
    // L2: libcap (first cross-built systemd shared dep). Real libcap.so →
    // /usr/lib + soname/linker-name symlinks; libcap_probe links it.
    // L2 shared libs → /usr/lib: put the real .so + soname/linker symlinks.
    let stage_so = |vendor: &str, real: &str, soname: &str, linker: &str| -> Result<(), u8> {
        let dir = repo.join(format!("vendor/{vendor}/install-{arch}/lib"));
        put(&dir.join(real), &format!("/usr/lib/{real}"))?;
        // Some libs (e.g. openssl) name the real .so == its SONAME
        // (libssl.so.3), so skip the self-link in that case.
        if soname != real {
            ln_via_debugfs(&format!("/usr/lib/{real}"), &format!("/usr/lib/{soname}"))?;
        }
        ln_via_debugfs(&format!("/usr/lib/{real}"), &format!("/usr/lib/{linker}"))?;
        Ok(())
    };
    for (vendor, real, soname, linker) in l2_deps::L2_LIBS {
        stage_so(vendor, real, soname, linker)?;
    }
    // /etc/inittab — busybox init (B39: respawn login direct, no getty).
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

    // /etc/init.d/rcS — sysinit shell script.
    put(&stage("rcS",
b"#!/bin/sh
mount -t proc  proc  /proc 2>/dev/null
mount -t sysfs sysfs /sys  2>/dev/null
mount -t tmpfs tmpfs /tmp  2>/dev/null
mount -t tmpfs tmpfs /var/run 2>/dev/null
mount -t tmpfs tmpfs /var/db  2>/dev/null
mount -t devpts devpts /dev/pts 2>/dev/null
# B18: busybox syslogd creates /dev/log socket + writes /var/log/messages.
# Captures pam_unix's pam_syslog() so we can see why auth fails.
mkdir -p /var/log
syslogd -O /var/log/messages -S 2>/dev/null
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
    // (replaces the C harness from old userspace/init/init.c). Gated
    // by the marker file so OXIDE_INIT_SMOKES=0 boots skip it.
    // oxide-smokes script lives in assets/oxide-smokes.sh (kept out of
    // this file for the 1000-line cap; edit the .sh to add probes).
    put(&stage("oxide-smokes", include_bytes!("assets/oxide-smokes.sh"))?,
        "/etc/init.d/oxide-smokes")?;
    dbg("sif /etc/init.d/oxide-smokes mode 0100755")?;

    // F147/F149: udhcpc lease-event script. $1 ∈ {deconfig,bound,
    // renew}; bound/renew set iface+route+resolv.conf, deconfig tears
    // the addr down. Lease fields arrive as env vars from udhcpc.
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

    // F252: minimal terminfo db for ncurses-linked programs.
    for (sub, name) in &[
        ("d", "dumb"), ("l", "linux"), ("s", "screen"),
        ("v", "vt100"), ("x", "xterm"), ("x", "xterm-256color"),
    ] {
        let host = repo.join(format!("kernel/blobs/terminfo/{sub}/{name}"));
        put(&host, &format!("/usr/share/terminfo/{sub}/{name}"))?;
    }

    eprintln!("xtask rootfs: built {} ({} bytes)",
        img.display(),
        std::fs::metadata(&img).map(|m| m.len()).unwrap_or(0));
    Ok(())
}

