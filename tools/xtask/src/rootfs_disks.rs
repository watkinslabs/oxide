// Stage-2 disk-rootfs migration (BUILD side): produce standalone disk
// images attached as virtio-blk drives so the kernel mounts root from disk.
//
// - root-<arch>.img : the base distro + tools, staged in place by cmd_rootfs,
//   plus empty mount-point dirs /home and /usr/local added here. Identified by
//   the kernel via virtio-blk serial `oxide-root`.
// - home-<arch>.img : small (64 MiB) ext4 with /home/alice (0755, uid/gid
//   1000) — the /home volume. Serial `oxide-home`.
//
// Split out of rootfs.rs for the 1000-line cap (08§7).
//
// Module manifest:
// - af_packet_diff: GNU glibc probe build and opt-in systemd injection.
mod af_packet_diff;

use std::path::{Path, PathBuf};
use std::process::Command;
use crate::cmds::run;

/// Finalize root-<arch>.img (add mount-points) + build home-<arch>.img next to
/// it. Called at the end of `cmd_rootfs`, which already staged root-<arch>.img.
pub(crate) fn build_disks(
    blobs: &std::path::Path,
    arch: &str,
) -> Result<(), u8> {
    build_root(blobs, arch)?;
    build_home(blobs, arch)?;
    Ok(())
}

/// root disk = the already-staged boot rootfs (carries /lib/systemd/systemd,
/// bash, coreutils, libs, /etc — everything to boot+login). C90: no longer a
/// copy of a separate rootfs-<arch>.img; this adds the empty /home and
/// /usr/local mount-points IN PLACE for the Stage-5 volume mounts.
fn build_root(
    blobs: &std::path::Path,
    arch: &str,
) -> Result<(), u8> {
    let root_img = blobs.join(format!("root-{arch}.img"));
    clean_dev_underlay(&root_img)?;
    for path in ["/usr/local", "/usr/local/bin", "/usr/local/sbin", "/home"] {
        require_dir(&root_img, path)?;
    }
    if std::env::var_os("OXIDE_DRM_RENDER_SMOKE").is_some() {
        inject_drm_render_smoke(&root_img, arch)?;
    }
    if std::env::var_os("OXIDE_AF_PACKET_DIFF_SMOKE").is_some() {
        af_packet_diff::inject(&root_img, arch)?;
    }
    eprintln!("xtask rootfs: finalized {} ({} bytes)",
        root_img.display(),
        std::fs::metadata(&root_img).map(|m| m.len()).unwrap_or(0));
    Ok(())
}

/// Remove distro-packed device entries from the ext4 underlay. `/dev` is
/// mounted from the kernel-owned devtmpfs before userspace starts; retaining
/// regular files here turns a detached/private mount into an `EROFS` trap and
/// hides the real mount-lifecycle failure. Keep the underlay directory-only so
/// every device node has one canonical owner.
fn clean_dev_underlay(img: &Path) -> Result<(), u8> {
    for name in ["console", "full", "null", "random", "tty", "urandom", "zero"] {
        let mut c = Command::new("debugfs");
        c.args(["-w", "-R", &format!("rm /dev/{name}"), img.to_str().unwrap()]);
        c.stdout(std::process::Stdio::null());
        c.stderr(std::process::Stdio::null());
        if !c.status().map(|s| s.success()).unwrap_or(false) {
            eprintln!("xtask rootfs: failed to remove packed /dev/{name}");
            return Err(2);
        }
    }
    eprintln!("xtask rootfs: cleared packed /dev device underlay");
    Ok(())
}

fn require_dir(img: &Path, path: &str) -> Result<(), u8> {
    let mut c = Command::new("debugfs");
    c.args(["-R", &format!("stat {path}"), img.to_str().unwrap()]);
    c.stdout(std::process::Stdio::null());
    c.stderr(std::process::Stdio::null());
    if !c.status().map(|s| s.success()).unwrap_or(false) {
        eprintln!("xtask rootfs: packed root image missing required directory {path}");
        return Err(2);
    }
    Ok(())
}

fn inject_drm_render_smoke(root_img: &Path, arch: &str) -> Result<(), u8> {
    let bin = build_drm_probe(arch)?;
    let service = write_drm_render_service()?;
    dbg(root_img, "mkdir /etc/systemd/system")?;
    dbg(root_img, "mkdir /etc/systemd/system/multi-user.target.wants")?;
    dbg_ignore(root_img, "rm /usr/local/bin/drm_render_probe");
    dbg(root_img, &format!("write {} /usr/local/bin/drm_render_probe", bin.display()))?;
    dbg(root_img, "sif /usr/local/bin/drm_render_probe mode 0100755")?;
    dbg_ignore(root_img, "rm /etc/systemd/system/drm-render-smoke.service");
    dbg(root_img, &format!("write {} /etc/systemd/system/drm-render-smoke.service", service.display()))?;
    dbg_ignore(root_img, "rm /etc/systemd/system/multi-user.target.wants/drm-render-smoke.service");
    dbg(root_img, "symlink /etc/systemd/system/multi-user.target.wants/drm-render-smoke.service ../drm-render-smoke.service")?;
    eprintln!("xtask rootfs: injected DRM render smoke into {}", root_img.display());
    Ok(())
}

fn build_drm_probe(arch: &str) -> Result<PathBuf, u8> {
    let (trip, dir) = match arch {
        "x86_64"  => ("x86_64-linux-musl", "x86_64-linux-musl-cross"),
        "aarch64" => ("aarch64-linux-musl", "aarch64-linux-musl-cross"),
        _ => { eprintln!("xtask rootfs: unsupported arch `{arch}` for DRM render smoke"); return Err(2); }
    };
    let cc = PathBuf::from(format!("vendor/cross/{dir}/bin/{trip}-cc"));
    if !cc.is_file() {
        eprintln!("xtask rootfs: missing {} for DRM render smoke", cc.display());
        return Err(2);
    }
    let out_dir = PathBuf::from("target").join("smoke").join(arch);
    std::fs::create_dir_all(&out_dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let out = out_dir.join("drm_render_probe");
    let mut c = Command::new(cc);
    c.args([
        "-O2", "-static", "-Wall", "-Wextra",
        "userspace/drm_probe/drm_probe.c",
        "-o", out.to_str().unwrap(),
    ]);
    run(c)?;
    Ok(out)
}

fn write_drm_render_service() -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let path = dir.join("drm-render-smoke.service");
    let body = "[Unit]\n\
Description=Oxide DRM render node smoke\n\
After=basic.target systemd-udev-settle.service\n\
\n\
[Service]\n\
Type=oneshot\n\
ExecStart=/bin/sh -c '/usr/local/bin/drm_render_probe >/dev/console 2>&1'\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n";
    std::fs::write(&path, body).map_err(|e| { eprintln!("xtask rootfs: write service failed: {e}"); 1u8 })?;
    Ok(path)
}

fn dbg(img: &Path, cmd: &str) -> Result<(), u8> {
    let mut c = Command::new("debugfs");
    c.args(["-w", "-R", cmd, img.to_str().unwrap()]);
    c.stdout(std::process::Stdio::null());
    c.stderr(std::process::Stdio::null());
    run(c)
}

fn dbg_ignore(img: &Path, cmd: &str) {
    let _ = dbg(img, cmd);
}

/// home disk = fresh 64 MiB ext4 with /home/alice owned by uid/gid 1000
/// (mode 0755), mirroring the rootfs /etc/passwd alice entry.
fn build_home(blobs: &std::path::Path, arch: &str) -> Result<(), u8> {
    let home_img = blobs.join(format!("home-{arch}.img"));
    eprintln!("xtask rootfs: mkfs.ext4 {}", home_img.display());
    {
        let mut c = Command::new("dd");
        c.args(["if=/dev/zero",
                &format!("of={}", home_img.display()),
                "bs=1M", "count=64"]);
        run(c)?;
    }
    {
        let mut c = Command::new("mkfs.ext4");
        c.args(["-F", "-b", "4096", "-O", "^has_journal",
                "-L", "oxide-home", home_img.to_str().unwrap()]);
        run(c)?;
    }
    let dbg = |cmd: &str| -> Result<(), u8> {
        let mut c = Command::new("debugfs");
        c.args(["-w", "-R", cmd, home_img.to_str().unwrap()]);
        c.stdout(std::process::Stdio::null());
        c.stderr(std::process::Stdio::null());
        run(c)
    };
    dbg("mkdir /home")?;
    dbg("mkdir /home/alice")?;
    // alice = uid/gid 1000 (rootfs /etc/passwd), dir mode 0755.
    dbg("sif /home/alice mode 040755")?;
    dbg("sif /home/alice uid 1000")?;
    dbg("sif /home/alice gid 1000")?;
    eprintln!("xtask rootfs: built {} ({} bytes)",
        home_img.display(),
        std::fs::metadata(&home_img).map(|m| m.len()).unwrap_or(0));
    Ok(())
}
