// `xtask image`, `xtask grub` per `07§8`. GRUB boots both arches:
// x86 boots via GRUB multiboot2, aarch64 via the GRUB EFI-stub `linux`
// path (arm64 Image + self-boot MMU trampoline). `image` is a thin alias
// that builds the GRUB boot artifact without launching qemu; `grub`
// builds + boots. Helpers are pub(crate) so main can dispatch.

use crate::parse_arg;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// QEMU user-net `-netdev` arg. The host→guest SSH port-forward
/// (`hostfwd=tcp::2222-:22`) is OFF by default — we no longer test ssh,
/// and the fixed host-port binding made overlapping/stale qemus collide
/// ("Could not set up host forwarding"), which silently failed boot
/// smokes. User networking itself stays on (the net udp/iface smoke
/// still runs). Re-enable the forward with `OXIDE_QEMU_SSH_FWD=1`.
/// # C: O(1)
pub(super) fn ssh_fwd_netdev() -> String {
    match std::env::var("OXIDE_QEMU_SSH_FWD") {
        Ok(v) if v == "1" || v.eq_ignore_ascii_case("on") || v.eq_ignore_ascii_case("true") => {
            // Per-launch host port (a fixed 2222 collides across concurrent
            // worktrees — "Could not set up host forwarding"). Pid-derived so
            // parallel launches differ; override with OXIDE_QEMU_SSH_PORT.
            let port: u16 = std::env::var("OXIDE_QEMU_SSH_PORT").ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| 20000 + (std::process::id() % 20000) as u16);
            eprintln!("xtask grub: ssh forward on host tcp::{port} → guest :22");
            format!("user,id=net0,hostfwd=tcp::{port}-:22")
        }
        _ => "user,id=net0".to_string(),
    }
}

/// D3.5: ensure a small raw NVMe scratch disk exists at
/// `target/builds/<id>/nvme-<arch>.img` (16 MiB, zeroed). Created if missing so the
/// `nvme` QEMU device always has a backing file. Returns its path. # C: O(1)
fn ensure_storage_img(
    repo: &std::path::Path,
    id: Option<&str>,
    arch: &str,
    stem: &str,
) -> std::path::PathBuf {
    let img = crate::buildns::blobs_dir(repo, id).join(format!("{stem}-{arch}.img"));
    if !img.exists() {
        if let Some(parent) = img.parent() { let _ = std::fs::create_dir_all(parent); }
        if let Ok(f) = std::fs::File::create(&img) {
            // 16 MiB zeroed scratch volume (sparse where supported).
            let _ = f.set_len(16 * 1024 * 1024);
        }
    }
    img
}

pub(super) fn ensure_nvme_img(
    repo: &std::path::Path,
    id: Option<&str>,
    arch: &str,
) -> std::path::PathBuf {
    ensure_storage_img(repo, id, arch, "nvme")
}

pub(super) fn ensure_nvme_extra_img(
    repo: &std::path::Path,
    id: Option<&str>,
    arch: &str,
) -> std::path::PathBuf {
    ensure_storage_img(repo, id, arch, "nvme1")
}

/// D3.6: ensure a small raw AHCI/SATA scratch disk exists at
/// `target/builds/<id>/ahci-<arch>.img` (16 MiB, zeroed). Created if missing so the
/// `ich9-ahci` + `ide-hd` QEMU devices always have a backing file. Returns its
/// path. # C: O(1)
pub(super) fn ensure_ahci_img(
    repo: &std::path::Path,
    id: Option<&str>,
    arch: &str,
) -> std::path::PathBuf {
    ensure_storage_img(repo, id, arch, "ahci")
}

pub(super) fn ensure_ahci_extra_img(
    repo: &std::path::Path,
    id: Option<&str>,
    arch: &str,
) -> std::path::PathBuf {
    ensure_storage_img(repo, id, arch, "ahci1")
}

pub(super) fn ensure_virtio_blk_extra_img(
    repo: &std::path::Path,
    id: Option<&str>,
    arch: &str,
) -> std::path::PathBuf {
    ensure_storage_img(repo, id, arch, "vblk-scratch")
}

/// `xtask image --arch <arch>` — build the bootable artifact
/// (`target/oxide-<arch>-grub.iso`) without launching qemu. GRUB is
/// gone, so this is a thin alias for `grub --arch <arch> --build-only`:
/// one "produce the boot artifact" entry point for external harnesses
/// (qemu-mcp, accept.py, run-smokes.sh).
pub(super) fn kernel_elf_path(
    repo: &std::path::Path,
    arch: &str,
    rest: &[String],
) -> Result<std::path::PathBuf, u8> {
    let profile = parse_arg(rest, "--profile").unwrap_or("release".into());
    let prof_dir = if profile == "dev" { "debug".to_string() } else { profile };
    let id = parse_arg(rest, "--id");
    let p = crate::buildns::kernel_elf(repo, id.as_deref(), arch, &prof_dir);
    if !p.exists() {
        eprintln!("xtask: kernel ELF not at {}", p.display());
        return Err(2);
    }
    Ok(p)
}

pub(crate) fn repo_root() -> std::path::PathBuf {
    let here = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(here)
        .ancestors().nth(2).map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap())
}

pub(super) fn which(prog: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for p in std::env::split_paths(&path) {
        let cand = p.join(prog);
        if cand.is_file() { return Some(cand); }
    }
    None
}

/// Default virtio-gpu scanout size the guest is powered on with. QEMU's own
/// default is smaller than a usable desktop, and it is what
/// `GET_DISPLAY_INFO` reports as the connector's preferred mode, so the
/// compositor adopts it verbatim. Override with `OXIDE_GPU_XRES`/`OXIDE_GPU_YRES`.
pub const DEFAULT_GPU_XRES: u32 = 1920;
pub const DEFAULT_GPU_YRES: u32 = 1080;

/// `-device` argument for the primary virtio-gpu, carrying the scanout size.
/// # C: O(1)
pub fn virtio_gpu_device_arg(id: Option<&str>) -> String {
    let xres = env_dim("OXIDE_GPU_XRES", DEFAULT_GPU_XRES);
    let yres = env_dim("OXIDE_GPU_YRES", DEFAULT_GPU_YRES);
    let id = match id { Some(i) => format!(",id={i}"), None => String::new() };
    format!("virtio-gpu-pci{id},bus=pcie.0,xres={xres},yres={yres}")
}

fn env_dim(key: &str, dflt: u32) -> u32 {
    std::env::var(key).ok().and_then(|v| v.parse::<u32>().ok()).filter(|v| *v > 0).unwrap_or(dflt)
}
