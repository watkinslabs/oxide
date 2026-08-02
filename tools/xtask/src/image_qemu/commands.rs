use crate::parse_arg;

use super::aarch64::{build_arm_image, build_grub_arm_iso, qemu_run_aarch64_grub};
use super::common::kernel_elf_path;
use super::common::repo_root;
use super::x86_64::{build_grub_iso, qemu_run_grub_x86_64};

/// `xtask image --arch <arch>` — build the bootable artifact
/// (`target/oxide-<arch>-grub.iso`) without launching qemu.
pub(crate) fn cmd_image(rest: &[String]) -> Result<(), u8> {
    let mut args = rest.to_vec();
    if !rest.iter().any(|a| a == "--build-only") {
        args.push("--build-only".into());
    }
    cmd_grub(&args)
}

/// `xtask grub --arch <x86_64|aarch64>` — build a GRUB-bootable artifact
/// that loads our kernel DIRECTLY (x86 multiboot2; aarch64 EFI-stub
/// `linux`) and boot it under QEMU.
pub(crate) fn cmd_grub(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").unwrap_or_else(|| "x86_64".into());
    if rest.iter().any(|arg| arg == "--run-existing") {
        return cmd_run_existing(rest, &arch);
    }
    if arch == "aarch64" {
        return cmd_grub_aarch64(rest);
    }
    if arch != "x86_64" {
        eprintln!("xtask grub: arch must be x86_64 or aarch64");
        return Err(2);
    }
    let smp: u32 = parse_arg(rest, "--smp").and_then(|s| s.parse().ok()).unwrap_or(1);
    let repo = prepare_rootfs(rest, &arch)?;
    // No debug features by default. The serial mirror of the console is
    // unconditional, so a default build boots and logs in with none of them;
    // `--features debug-all` (or `make qemu-x86-debug`) is the firehose.
    crate::cmd_kernel(rest)?;
    let id = parse_arg(rest, "--id");
    if let Some(ref id) = id { crate::buildns::validate(id)?; }
    let kernel_elf = kernel_elf_path(&repo, &arch, rest)?;
    let iso = build_grub_iso(&repo, id.as_deref(), &arch, &kernel_elf)?;
    // `--build-only`: produce the GRUB ISO + rootfs but skip the qemu launch.
    // The qemu-mcp / accept.py use this to build the boot artifact, then
    // spawn their own qemu against it.
    if rest.iter().any(|a| a == "--build-only") {
        println!("xtask grub: built {} (--build-only, not launching qemu)", iso.display());
        return Ok(());
    }
    qemu_run_grub_x86_64(&repo, id.as_deref(), &iso, smp)
}

/// Stage the rootfs disk before an image build, unless a cached one is reused.
fn prepare_rootfs(rest: &[String], arch: &str) -> Result<std::path::PathBuf, u8> {
    let _ = arch;
    let repo = repo_root();
    let skip = std::env::var("OXIDE_SKIP_ROOTFS").is_ok();
    prepare_rootfs_in(skip, || crate::cmd_rootfs(rest))?;
    Ok(repo)
}

fn prepare_rootfs_in<F>(skip: bool, stage: F) -> Result<(), u8>
where
    F: FnOnce() -> Result<(), u8>,
{
    // OXIDE_SKIP_ROOTFS=1 reuses the cached rootfs disk instead of restaging
    // the guest userspace + rebuilding the ext4 image every boot. Kernel-only
    // changes don't touch the rootfs, so this turns a multi-minute rebuild
    // into a no-op. Unset (default) = always rebuild, for correctness/CI.
    if skip {
        eprintln!("xtask grub: OXIDE_SKIP_ROOTFS set — reusing cached rootfs (no restage)");
    } else {
        stage()?;
    }
    Ok(())
}

/// GRUB on aarch64: build the EFI-stub flat Image, stage it
/// + a grub.cfg that `linux`-boots it, `grub2-mkrescue` an EFI ISO using
/// the vendored arm64-efi GRUB modules (no host grub2-efi-aa64 install
/// needed — see tools/fetch-grub.sh), then boot under OVMF. OVMF loads
/// GRUB, GRUB's `linux` loads our PE Image, the kernel's EFI stub exits
/// boot services + drops the MMU and joins the self-boot trampoline. Root
/// mounts from the root-aarch64.img virtio-blk disk (serial `oxide-root`,
/// attached below) — NOT embedded; the EFI stub's ACPI RSDP brings up PCI
/// (virtio-blk/net/gpu).
fn cmd_grub_aarch64(rest: &[String]) -> Result<(), u8> {
    let smp: u32 = parse_arg(rest, "--smp").and_then(|s| s.parse().ok()).unwrap_or(1);
    let repo = prepare_rootfs(rest, "aarch64")?;
    // No debug features by default (parity with the x86 grub path).
    crate::cmd_kernel(rest)?;
    let id = parse_arg(rest, "--id");
    if let Some(ref id) = id { crate::buildns::validate(id)?; }
    let kernel_elf = kernel_elf_path(&repo, "aarch64", rest)?;
    let image = build_arm_image(&repo, id.as_deref(), &kernel_elf)?;
    let iso = build_grub_arm_iso(&repo, id.as_deref(), &image)?;
    // `--build-only`: produce the ISO but skip the qemu launch (qemu-mcp /
    // boot-smoke build the artifact then spawn their own qemu).
    if rest.iter().any(|a| a == "--build-only") {
        println!("xtask grub: built {} (--build-only, not launching qemu)", iso.display());
        return Ok(());
    }
    qemu_run_aarch64_grub(&repo, id.as_deref(), &iso, smp)
}

/// Launch a previously built namespaced ISO without rebuilding its kernel or
/// rootfs. Conformance starts its wall-clock guest deadline only after this
/// preflight has completed, so compilation cannot consume QEMU runtime.
fn cmd_run_existing(rest: &[String], arch: &str) -> Result<(), u8> {
    if rest.iter().any(|arg| arg == "--build-only") {
        eprintln!("xtask grub: --run-existing cannot combine with --build-only");
        return Err(2);
    }
    let id = parse_arg(rest, "--id").ok_or_else(|| {
        eprintln!("xtask grub: --run-existing requires --id");
        2u8
    })?;
    crate::buildns::validate(&id)?;
    let smp: u32 = parse_arg(rest, "--smp").and_then(|s| s.parse().ok()).unwrap_or(1);
    let repo = repo_root();
    let iso = crate::buildns::iso_path(&repo, Some(&id), arch);
    if !iso.is_file() {
        eprintln!("xtask grub: prebuilt ISO not found at {}; run xtask image first", iso.display());
        return Err(2);
    }
    match arch {
        "x86_64" => qemu_run_grub_x86_64(&repo, Some(&id), &iso, smp),
        "aarch64" => qemu_run_aarch64_grub(&repo, Some(&id), &iso, smp),
        _ => { eprintln!("xtask grub: arch must be x86_64 or aarch64"); Err(2) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // OXIDE_SKIP_ROOTFS is the difference between booting the kernel you just
    // built against a fresh rootfs and booting it against a cached one. Both
    // directions are asserted: a skip that still staged would cost minutes a
    // boot, and a non-skip that did not stage would boot a stale userspace.
    #[test]
    fn skip_reuses_the_cached_rootfs_and_clear_stages_it() {
        let staged = Cell::new(false);
        prepare_rootfs_in(true, || { staged.set(true); Ok(()) }).unwrap();
        assert!(!staged.get(), "OXIDE_SKIP_ROOTFS must not restage");

        let staged = Cell::new(false);
        prepare_rootfs_in(false, || { staged.set(true); Ok(()) }).unwrap();
        assert!(staged.get(), "default must restage the rootfs");
    }

    #[test]
    fn a_staging_failure_is_propagated() {
        assert_eq!(prepare_rootfs_in(false, || Err(7)), Err(7));
    }
}
