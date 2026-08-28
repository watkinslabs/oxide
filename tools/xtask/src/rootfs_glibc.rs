// Quick-boot glibc rootfs. Composition is owned by the images repo
// (`../images`, imagectl + dnf5 from `../packages`/Fedora): the kernel repo
// does NOT build userspace. The images repo already packs each profile into a
// complete ext4 image at `../images/output/<profile>-<arch>-root.img`; the
// quick-boot simply COPIES that pre-packed glibc image as root-<arch>.img
// (reflink where the filesystem supports it, so it's ~instant).
//
// Replaces the retired musl userspace staging. Default profile is `gnome` (real Fedora
// glibc systemd + login + htop — where the echo/VT bugs reproduce); override
// with OXIDE_QUICKBOOT_PROFILE. The profiles that exist are whatever the
// images repo has packed, so the hint on a miss is DERIVED from that
// directory rather than restated here — the restated list had gone stale in
// both directions, naming two profiles that do not exist and omitting the
// ones that do.
//
// The image is composed + packed with root privileges in the images repo, so
// its root-only files (/etc/shadow, gshadow) are already inside the ext4 —
// copying the finished image needs no sudo, unlike re-packing the tree.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cmds::run;

/// Default images profile to boot: `gnome` — the glibc GNOME image
/// packed for BOTH arches (ARM lockstep). The images repo builds these
/// (`cd ../images && make <profile>-<arch>`) → output/<profile>-<arch>-root.img.
const DEFAULT_PROFILE: &str = "gnome";

/// Build the glibc `root-<arch>.img` boot disk by copying the images-repo
/// pre-packed root image for `arch`.
pub(crate) fn build_glibc_root_img(repo: &Path, arch: &str, img: &Path) -> Result<(), u8> {
    let src = packed_image(repo, arch)?;
    copy_image(&src, img)
}

/// Locate `$OXIDE_IMAGES_DIR/output/<profile>-<arch>-root.img` (images dir
/// defaults to the sibling `../images`).
fn packed_image(repo: &Path, arch: &str) -> Result<PathBuf, u8> {
    let profile = std::env::var("OXIDE_QUICKBOOT_PROFILE").unwrap_or_else(|_| DEFAULT_PROFILE.into());
    let images = std::env::var("OXIDE_IMAGES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo.parent().map(|p| p.join("images")).unwrap_or_else(|| PathBuf::from("../images")));
    let src = images.join("output").join(format!("{profile}-{arch}-root.img"));
    if !src.is_file() {
        eprintln!("xtask rootfs: no packed glibc root image at {}", src.display());
        eprintln!("  build it in the images repo: (cd {} && make {profile}-{arch})", images.display());
        let found = packed_profiles(&images.join("output"), arch);
        if found.is_empty() {
            eprintln!("  no packed images for {arch} in {}", images.join("output").display());
        } else {
            eprintln!("  or select another with OXIDE_QUICKBOOT_PROFILE=<{}>", found.join("|"));
        }
        return Err(2);
    }
    Ok(src)
}

/// Copy the pre-packed image to the boot disk path, reflinking where the
/// filesystem supports CoW (instant, no data copy). Every boot starts from a
/// fresh copy: QEMU writes this image and the smoke harness terminates the VM
/// without a guest unmount, so reusing yesterday's newer destination can feed
/// partially committed filesystem metadata into the next boot.
fn copy_image(src: &Path, dst: &Path) -> Result<(), u8> {
    eprintln!("xtask rootfs: cp --reflink=auto {} -> {}", src.display(), dst.display());
    let mut c = Command::new("cp");
    c.arg("--reflink=auto").arg("-f").arg(src).arg(dst);
    run(c)?;
    eprintln!("xtask rootfs: built {} ({} bytes) [glibc, images profile]",
        dst.display(), std::fs::metadata(dst).map(|m| m.len()).unwrap_or(0));
    Ok(())
}

/// Profiles the images repo has actually packed for `arch`, from the names of
/// the `<profile>-<arch>-root.img` files in its output directory. Split out of
/// the error path so the parse is testable without an images checkout.
fn packed_profiles(output: &Path, arch: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(output) else { return Vec::new() };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|n| profile_of(&n, arch))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// `<profile>-<arch>-root.img` -> `profile`, for this `arch` only. # C: O(len)
fn profile_of(file: &str, arch: &str) -> Option<String> {
    let suffix = format!("-{arch}-root.img");
    let stem = file.strip_suffix(&suffix)?;
    if stem.is_empty() { return None; }
    Some(stem.to_string())
}

#[cfg(test)]
mod tests {
    use super::profile_of;

    #[test]
    fn a_packed_image_name_yields_its_profile() {
        assert_eq!(profile_of("nano-x86_64-root.img", "x86_64").as_deref(), Some("nano"));
        assert_eq!(profile_of("live-gnome-aarch64-root.img", "aarch64").as_deref(), Some("live-gnome"));
    }

    #[test]
    fn another_arch_and_the_backup_copies_are_not_profiles() {
        // The output directory carries the other arch, `.premerge.bak` copies
        // and the squashfs packs beside the ext4 images.
        assert_eq!(profile_of("gnome-aarch64-root.img", "x86_64"), None);
        assert_eq!(profile_of("lite-x86_64-root.img.premerge.bak", "x86_64"), None);
        assert_eq!(profile_of("micro-x86_64-root-slim.squashfs", "x86_64"), None);
        assert_eq!(profile_of("-x86_64-root.img", "x86_64"), None);
    }
}
