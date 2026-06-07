// Stage-2 disk-rootfs migration (BUILD side): produce standalone disk
// images attached as virtio-blk drives so a later stage mounts root from
// disk instead of the kernel-embedded rootfs.
//
// - root-<arch>.img : same content as rootfs-<arch>.img (base distro +
//   tools) plus empty mount-point dirs /home and /usr/local. Identified by
//   the kernel via virtio-blk serial `oxide-root`.
// - home-<arch>.img : small (64 MiB) ext4 with /home/alice (0755, uid/gid
//   1000) — the /home volume. Serial `oxide-home`.
//
// Split out of rootfs.rs for the 1000-line cap (08§7).
use std::process::Command;
use crate::cmds::run;

/// Build root-<arch>.img + home-<arch>.img next to the (already-built)
/// rootfs-<arch>.img. Called at the end of `cmd_rootfs`.
pub(crate) fn build_disks(
    blobs: &std::path::Path,
    rootfs_img: &std::path::Path,
    arch: &str,
) -> Result<(), u8> {
    build_root(blobs, rootfs_img, arch)?;
    build_home(blobs, arch)?;
    Ok(())
}

/// root disk = a byte-for-byte copy of the boot rootfs (so it carries
/// /lib/systemd/systemd, bash, coreutils, libs, /etc — everything to
/// boot+login) with empty /home and /usr/local mount-points added for the
/// Stage-5 volume mounts.
fn build_root(
    blobs: &std::path::Path,
    rootfs_img: &std::path::Path,
    arch: &str,
) -> Result<(), u8> {
    let root_img = blobs.join(format!("root-{arch}.img"));
    eprintln!("xtask rootfs: cp {} -> {}", rootfs_img.display(), root_img.display());
    std::fs::copy(rootfs_img, &root_img).map_err(|e| {
        eprintln!("xtask rootfs: copy root img: {e}"); 1u8
    })?;
    // Empty mount-point dirs. /home already exists in the rootfs (with
    // /home/alice); make it an empty mount-point on the ROOT disk by leaving
    // the existing dir (harmless — the /home volume mounts over it). Ensure
    // /usr/local exists (rootfs references it in PATH but never mkdir's it).
    let dbg = |cmd: &str| -> Result<(), u8> {
        let mut c = Command::new("debugfs");
        c.args(["-w", "-R", cmd, root_img.to_str().unwrap()]);
        c.stdout(std::process::Stdio::null());
        c.stderr(std::process::Stdio::null());
        run(c)
    };
    // mkdir is a no-op (EEXIST, muted) if the dir already exists.
    dbg("mkdir /usr/local")?;
    dbg("mkdir /usr/local/bin")?;
    dbg("mkdir /usr/local/sbin")?;
    dbg("mkdir /home")?;
    eprintln!("xtask rootfs: built {} ({} bytes)",
        root_img.display(),
        std::fs::metadata(&root_img).map(|m| m.len()).unwrap_or(0));
    Ok(())
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
