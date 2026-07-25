// xtask rootfs build. The quick-boot root disk is a glibc userspace composed
// from the sibling `../packages` RPM repo — see `rootfs_glibc`. The old musl
// userspace staging is retired: the kernel + `../images` are glibc, so the
// quick boot matches.

use crate::cmds::parse_arg;
use crate::image_qemu;

/// Per-arch rootfs build. --arch <x86_64|aarch64>. Produces the glibc
/// `root-<arch>.img` boot disk plus the auxiliary home/nvme/ahci disks.
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

    // glibc boot disk (compose oxide CLI package set, cached; pack via mkfs -d).
    let img = blobs.join(format!("root-{arch}.img"));
    crate::rootfs_glibc::build_glibc_root_img(&repo, &arch, &img)?;

    // Standalone home/nvme/ahci disks the qemu launch attaches as virtio-blk.
    crate::rootfs_disks::build_disks(&blobs, &arch)?;
    Ok(())
}
