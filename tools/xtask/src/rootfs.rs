// xtask rootfs build — extracted from main.rs to keep both files
// under the 1000-line cap (08§7). The dynamic-link probe builder lives
// in `rootfs_dynprobe` (same cap reason).
use std::process::Command;

mod build;
#[path = "rootfs/stage_system.rs"]
mod stage_system;
#[path = "rootfs/stage_tools.rs"]
mod stage_tools;
use crate::cmds::{parse_arg, run};
use crate::{image_qemu, l2_deps};

/// Per-arch rootfs build. --arch <x86_64|aarch64>.
pub(crate) fn cmd_rootfs(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").unwrap_or_else(|| "x86_64".into());
    if arch != "x86_64" && arch != "aarch64" {
        eprintln!("xtask rootfs: --arch must be x86_64 or aarch64 (got `{arch}`)");
        return Err(2);
    }
    let repo = image_qemu::repo_root();
    let id = parse_arg(rest, "--id");
    if let Some(ref id) = id { crate::buildns::validate(id)?; }
    let blobs = crate::buildns::blobs_dir(&repo, id.as_deref());
    std::fs::create_dir_all(&blobs).map_err(|e| { eprintln!("mkdir blobs: {e}"); 1u8 })?;

    crate::gc::rebuild_vendor(&repo, &arch, rest)?; // --rebuild-vendor[=pkg,...] busts the cache hash below
    if let crate::rootfs_cache::Plan::Skip = crate::rootfs_cache::pre_build(&repo, &blobs, &arch, rest)? { return Ok(()); }

    let build = build::build_userspace(&repo, &arch, rest)?;
    let user_out = build.user_out;
    let pam_vendor_sec = build.pam_vendor_sec;

    // F153-1: no embedded init blob. PID 1 lives in the rootfs as a
    // /sbin/init entry; the kernel reads it from ext4 at
    // boot. Nothing to refresh under target/builds/<id>/.

    // 1 GiB ext4 staged DIRECTLY into root-<arch>.img (the boot disk, serial
    // `oxide-root`) — C90: no separate rootfs-<arch>.img + 1 GiB cp. The kernel
    // reads blocks lazily into the page cache (NOT include_bytes!d), so the old
    // embed-size limits are gone (history 16→1024 MiB forced by embed overflow).
    let img = blobs.join(format!("root-{arch}.img"));
    eprintln!("xtask rootfs: mkfs.ext4 {}", img.display());
    {
        let mut c = Command::new("dd");
        c.args(["if=/dev/zero",
                &format!("of={}", img.display()),
                "bs=1M", "count=1024"]);
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
        "/etc", "/etc/init.d", "/etc/profile.d", "/etc/skel",
        "/proc", "/sys", "/tmp", "/run", "/run/systemd", "/run/systemd/ask-password", "/run/lock",
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
    // Userspace tools come from real GNU/util-linux/etc. binaries: bash is
    // /bin/sh + /bin/bash (below), coreutils owns the file/text applets
    // (F218 block), GNU grep/sed/gawk/tar/gzip/findutils/less/vim own their
    // tools (rip-to-GNU block), util-linux owns login/agetty/mount/su/etc.,
    // shadow owns useradd/passwd/etc., and PID1 is systemd (kernel boots
    // /lib/systemd/systemd directly).
    // Kernel-acceptance smoke binaries (real-musl-crt1 builds).
    for b in &[
        "bare3", "sptest", "pamtest", "login_sim", "sem_smoke", "msg_smoke",
        "mq_smoke", "ptrace_smoke", "ptrace_singlestep_smoke", "mprotect_smoke",
        "mremap_dontunmap_smoke", "inet6_smoke", "mmsg_smoke", "scm_smoke",
        "cgroup_smoke", "cmdsubst_probe", "alarm_probe", "cputime_probe", "quota_probe", "tcflow_probe", "tty_ioctl_probe", "io_uring_probe", "io_uring_reg_probe", "aio_probe", "tkill_probe", "pid_identity_probe", "sigframe_self_probe", "sigchld_probe", "symlink_probe", "pmadvise_probe",
        "mount_smoke", "statfs_smoke", "fsmount_probe", "memfd_seal_probe",
        "uevent_probe", "rtlink_probe", "nlmcast_probe", "tracemark_probe", "tracepipe_probe", "tracesched_probe", "tracesys_probe", "bpf_filter_probe", "fanotify_probe", "fanotify_perm_probe", "dev_smoke", "vim_smoke",
        "mmap_zero_smoke", "mmchurn_smoke", "mallocstress_smoke", "mallocstress_dyn",
        "mtmalloc_smoke", "uffd_probe", "sigmalloc_smoke", "mremap_alias_smoke", "rawecho_smoke", "termios_rt_smoke", "isatty_smoke", "pollecho_smoke",
        "usleep_smoke", "af_packet_smoke", "online_smoke",
        "tcp_smoke", "exit_test", "pthread_socketpair_probe", "robust_probe",
        "socketpair_fork_probe", "tty_reset_probe", "dsr_probe", "vtswitch_probe", "vtmode_probe", "vtresize_probe", "kdfont_probe", "fbdev_probe", "fbdev_probe2", "vcs_probe", "ptyhup_probe", "hwrng_probe", "virtio_rng_rebind_probe", "virtio_parent_child_rebind_probe", "uart_rebind_probe", "ps2_rebind_probe", "virtio_input_rebind_probe", "netstats_probe", "vsock_probe", "drm_probe", "drm_probe2", "drm_probe3", "sysblock_probe", "sysbus_bind_probe", "snd_probe", "mouseprobe",
        "msix_net_rx_probe", "virtio_net_multidev_probe", "virtio_snd_multidev_probe", "virtio_gpu_multidev_probe", "virtio_blk_multidev_probe", "storage_multictrl_probe",
    ] {
        put(&user(b), &format!("/bin/{b}"))?;
    }
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
    // G19b: stage the oxide glibc system libc + loader + folded stubs +
    // ld.so.cache from target/sysroot (parallel to musl — distinct paths:
    // /lib/ld-linux-x86-64.so.2 vs /lib/ld-musl-x86_64.so.1). A systemd
    // oneshot unit runs /bin/g19_glibc_smoke early, before the gettys.
    {
        let triple = format!("{arch}-unknown-linux-gnu");
        let srlib = repo.join(format!("target/sysroot/{triple}/lib"));
        let ld = if arch == "aarch64" { "ld-linux-aarch64.so.1" } else { "ld-linux-x86-64.so.2" };
        put(&srlib.join(ld), &format!("/lib/{ld}"))?;
        put(&srlib.join("libc.so.6"), "/lib/libc.so.6")?;
        for s in ["libpthread.so.0", "libdl.so.2", "librt.so.1", "libm.so.6", "libutil.so.1", "libresolv.so.2"] {
            put(&srlib.join(s), &format!("/lib/{s}"))?;
        }
        let cache = repo.join(format!("target/sysroot/{triple}/etc/ld.so.cache"));
        put(&cache, "/etc/ld.so.cache")?;
        put(&user("g19_glibc_smoke"),   "/bin/g19_glibc_smoke")?;
        put(&user("g19_glibc_test"),    "/bin/g19_glibc_test")?;
        put(&user("g19_glibc_pthread"), "/bin/g19_glibc_pthread")?;
        put(&user("g19_glibc_jointest"), "/bin/g19_glibc_jointest")?;
        // oneshot unit (pulled in by the Oxide Default Target's Wants) runs the
        // glibc-on-kernel bins before the gettys so their output cannot race
        // against login prompts.
        // pthread runs on BOTH arches now: the aarch64 join hang (clone ctid/tls
        // swapped in the CLONE_BACKWARDS ABI) is fixed in dispatch.rs.
        // TimeoutStartSec keeps a hung ExecStart from wedging the getty.
        let svc = repo.join("target/g19smoke.service");
        std::fs::write(&svc,
b"[Unit]
Description=G19 glibc-on-kernel smoke
DefaultDependencies=no
Before=console-getty.service serial-getty-ttyS0.service
[Service]
Type=oneshot
TimeoutStartSec=30
ExecStart=/bin/g19_glibc_smoke
ExecStart=/bin/g19_glibc_test
ExecStart=/bin/g19_glibc_jointest
ExecStart=/bin/g19_glibc_pthread
").map_err(|_| 1u8)?;
        // /usr/lib/systemd/system is created by the later L2 systemd staging,
        // so it does not exist yet at this point — `debugfs write` would fail
        // SILENTLY (debugfs exits 0 even on error), dropping the unit. Create
        // the parents first (mkdir on an existing dir is a harmless no-op:
        // debugfs prints to the muted stderr and still exits 0).
        dbg("mkdir /usr/lib/systemd")?;
        dbg("mkdir /usr/lib/systemd/system")?;
        put(&svc, "/usr/lib/systemd/system/g19smoke.service")?;
        dbg("sif /usr/lib/systemd/system/g19smoke.service mode 0100644")?;
        dbg("mkdir /usr/lib/systemd/system/default.target.wants")?;
        dbg("symlink /usr/lib/systemd/system/default.target.wants/g19smoke.service ../g19smoke.service")?;
    }
    if std::env::var_os("OXIDE_DRIVER_PATH_SMOKE").is_some() {
        let sh = repo.join("target/driver_path_smoke.sh");
        let script: &[u8] = if std::env::var_os("OXIDE_STORAGE_MULTICTRL_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/storage_multictrl_probe
"
        } else if std::env::var_os("OXIDE_VIRTIO_PARENT_CHILD_REBIND_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/virtio_parent_child_rebind_probe
"
        } else if std::env::var_os("OXIDE_VIRTIO_RNG_REBIND_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/virtio_rng_rebind_probe
"
        } else if std::env::var_os("OXIDE_UART_REBIND_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/uart_rebind_probe
"
        } else if std::env::var_os("OXIDE_PS2_REBIND_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/ps2_rebind_probe
"
        } else if std::env::var_os("OXIDE_VIRTIO_INPUT_REBIND_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/virtio_input_rebind_probe
"
        } else if std::env::var_os("OXIDE_VIRTIO_SND_MULTIDEV_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/virtio_snd_multidev_probe
"
        } else if std::env::var_os("OXIDE_VIRTIO_GPU_MULTIDEV_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/virtio_gpu_multidev_probe
"
        } else if std::env::var_os("OXIDE_VIRTIO_NET_MULTIDEV_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/virtio_net_multidev_probe
"
        } else if std::env::var_os("OXIDE_VIRTIO_BLK_MULTIDEV_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/virtio_blk_multidev_probe
"
        } else if std::env::var_os("OXIDE_SYSBLOCK_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/sysblock_probe
"
        } else if std::env::var_os("OXIDE_SYSBUS_BIND_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/sysbus_bind_probe
"
        } else if std::env::var_os("OXIDE_MSIX_NET_RX_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/msix_net_rx_probe
"
        } else if std::env::var_os("OXIDE_VSOCK_SMOKE").is_some() {
b"#!/bin/sh
set -eu
exec /bin/vsock_probe
"
        } else {
b"#!/bin/sh
set -eu
echo driver_path_smoke: START
check_read() {
    path=$1
    tag=$2
    if test -r \"$path\"; then return 0; fi
    echo \"$tag: FAIL path=$path\"
    ls -l /sys/class/net 2>&1 || true
    ls -l \"$path\" 2>&1 || true
    exit 1
}
/bin/fbdev_probe
/bin/drm_probe
/bin/sysblock_probe
/bin/snd_probe
/bin/uevent_probe
/bin/rtlink_probe
check_read /sys/class/net/eth0/address b002_eth0_address
check_read /sys/class/net/eth0/statistics/rx_packets b002_eth0_rx_packets
echo b002_net_eth0: PASS
echo driver_path_smoke: run mouseprobe
sleep 1
/bin/mouseprobe
echo driver_path_smoke: PASS - GPU input sound block net
"
        };
        std::fs::write(&sh, script).map_err(|_| 1u8)?;
        let svc = repo.join("target/driver-path-smoke.service");
        std::fs::write(&svc,
b"[Unit]
Description=B002 driver path smoke
DefaultDependencies=no
Before=console-getty.service serial-getty-ttyS0.service
[Service]
Type=oneshot
TimeoutStartSec=60
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0
ExecStart=/bin/driver_path_smoke.sh
").map_err(|_| 1u8)?;
        put(&sh, "/bin/driver_path_smoke.sh")?;
        dbg("sif /bin/driver_path_smoke.sh mode 0100755")?;
        dbg("mkdir /usr/lib/systemd")?;
        dbg("mkdir /usr/lib/systemd/system")?;
        put(&svc, "/usr/lib/systemd/system/driver-path-smoke.service")?;
        dbg("sif /usr/lib/systemd/system/driver-path-smoke.service mode 0100644")?;
        dbg("mkdir /usr/lib/systemd/system/default.target.wants")?;
        dbg("symlink /usr/lib/systemd/system/default.target.wants/driver-path-smoke.service ../driver-path-smoke.service")?;
        if std::env::var_os("OXIDE_VIRTIO_NET_MULTIDEV_SMOKE").is_some() {
            put(&user("virtio_net_multidev_probe"), "/init")?;
        }
        if std::env::var_os("OXIDE_VIRTIO_BLK_MULTIDEV_SMOKE").is_some() {
            put(&user("virtio_blk_multidev_probe"), "/init")?;
        }
        if std::env::var_os("OXIDE_VIRTIO_RNG_REBIND_SMOKE").is_some() {
            put(&user("virtio_rng_rebind_probe"), "/init")?;
        }
        if std::env::var_os("OXIDE_VIRTIO_PARENT_CHILD_REBIND_SMOKE").is_some() {
            put(&user("virtio_parent_child_rebind_probe"), "/init")?;
        }
        if std::env::var_os("OXIDE_UART_REBIND_SMOKE").is_some() {
            put(&user("uart_rebind_probe"), "/init")?;
        }
        if std::env::var_os("OXIDE_PS2_REBIND_SMOKE").is_some() {
            put(&user("ps2_rebind_probe"), "/init")?;
        }
        if std::env::var_os("OXIDE_VIRTIO_INPUT_REBIND_SMOKE").is_some() {
            put(&user("virtio_input_rebind_probe"), "/init")?;
        }
        if std::env::var_os("OXIDE_VIRTIO_SND_MULTIDEV_SMOKE").is_some() {
            put(&user("virtio_snd_multidev_probe"), "/init")?;
        }
        if std::env::var_os("OXIDE_VIRTIO_GPU_MULTIDEV_SMOKE").is_some() {
            put(&user("virtio_gpu_multidev_probe"), "/init")?;
        }
        if std::env::var_os("OXIDE_VSOCK_SMOKE").is_some() {
            put(&user("vsock_probe"), "/init")?;
        }
        if std::env::var_os("OXIDE_SHUTDOWN_SMOKE").is_some() {
            put(&user("shutdown_probe"), "/init")?;
        }
    }
    if std::env::var_os("OXIDE_USERSPACE_SEAT_SMOKE").is_some() {
        let sh = repo.join("target/userspace_seat_smoke.sh");
        std::fs::write(&sh,
b"#!/bin/sh
set -eu
fail=0
check_file() { if [ -e \"$1\" ]; then echo \"userspace_seat_smoke: PASS $1\"; else echo \"userspace_seat_smoke: FAIL missing $1\"; fail=1; fi; }
check_grep() { if [ -f \"$1\" ] && grep -q \"$2\" \"$1\"; then echo \"userspace_seat_smoke: PASS $1 has $2\"; else echo \"userspace_seat_smoke: FAIL $1 lacks $2\"; fail=1; fi; }
echo userspace_seat_smoke: START
/bin/fbdev_probe
/bin/drm_probe
/bin/sysblock_probe
/bin/snd_probe
/bin/rtlink_probe
check_file /run/udev
check_file /run/udev/data/c226:0
check_grep /run/udev/data/c226:0 G:master-of-seat
check_file /run/udev/tags/master-of-seat/c226:0
check_file /run/systemd/seats/seat0
check_grep /run/systemd/seats/seat0 CAN_GRAPHICAL=1
check_file /usr/bin/udevadm
check_file /lib/systemd/systemd-udevd
check_file /usr/bin/loginctl
check_file /lib/systemd/systemd-logind
if [ \"$fail\" -eq 0 ]; then echo userspace_seat_smoke: PASS; else echo userspace_seat_smoke: FAIL; fi
exit \"$fail\"
").map_err(|_| 1u8)?;
        let svc = repo.join("target/userspace-seat-smoke.service");
        std::fs::write(&svc,
b"[Unit]
Description=B326 userspace seat smoke
DefaultDependencies=no
Before=console-getty.service serial-getty-ttyS0.service
[Service]
Type=oneshot
TimeoutStartSec=60
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0
ExecStart=/bin/userspace_seat_smoke.sh
").map_err(|_| 1u8)?;
        put(&sh, "/bin/userspace_seat_smoke.sh")?;
        dbg("sif /bin/userspace_seat_smoke.sh mode 0100755")?;
        dbg("mkdir /usr/lib/systemd")?;
        dbg("mkdir /usr/lib/systemd/system")?;
        put(&svc, "/usr/lib/systemd/system/userspace-seat-smoke.service")?;
        dbg("sif /usr/lib/systemd/system/userspace-seat-smoke.service mode 0100644")?;
        dbg("mkdir /usr/lib/systemd/system/default.target.wants")?;
        dbg("symlink /usr/lib/systemd/system/default.target.wants/userspace-seat-smoke.service ../userspace-seat-smoke.service")?;
    }
    put(&user("hello_dyn"), "/bin/hello_dyn")?;
    put(&user("hello_dyn_libc"), "/bin/hello_dyn_libc")?;
    put(&user("sigframe_probe"), "/bin/sigframe_probe")?;
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
        // F-bash-as-sh: bash IS the shell now (no other sh provider drops
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
    stage_tools::stage_tools(&repo, &arch, &put, &dbg, &ln_via_debugfs)?;

    stage_system::stage_system(&repo, &arch, &pam_vendor_sec, &put, &dbg, &ln_via_debugfs)?;

    eprintln!("xtask rootfs: built {} ({} bytes)",
        img.display(),
        std::fs::metadata(&img).map(|m| m.len()).unwrap_or(0));

    // root-<arch>.img is now staged in place above; add the /home + /usr/local
    // mount-points, then build the standalone home disk (virtio-blk drives).
    crate::rootfs_disks::build_disks(&blobs, &arch)?;
    crate::rootfs_cache::post_build(&repo, &blobs, &arch); // store images in cache for next HIT
    Ok(())
}
