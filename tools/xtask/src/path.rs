// `xtask path <kind> --arch <arch> [--id <id>] [--profile <p>]` — the single
// build-path resolver. Prints ONE absolute path to stdout and nothing else, so
// shell `$(...)` capture is clean. All paths come from `buildns` (the one
// scheme: `target/builds/<id-or-"default">/...`) so scripts never hardcode.

use crate::cmds::parse_arg;
use crate::image_qemu::repo_root;

/// kinds: root-img home-img nvme-img ahci-img iso elf build-dir
pub(crate) fn cmd_path(rest: &[String]) -> Result<(), u8> {
    let kind = rest.first().filter(|a| !a.starts_with("--")).cloned().ok_or_else(|| {
        eprintln!("xtask path: <kind> required (root-img|home-img|nvme-img|ahci-img|iso|elf|build-dir)");
        2u8
    })?;
    let arch = parse_arg(rest, "--arch").ok_or_else(|| {
        eprintln!("xtask path: --arch <x86_64|aarch64> required");
        2u8
    })?;
    match arch.as_str() {
        "x86_64" | "aarch64" => {}
        other => { eprintln!("xtask path: unsupported arch `{other}`"); return Err(2); }
    }
    let id = parse_arg(rest, "--id");
    if let Some(ref id) = id { crate::buildns::validate(id)?; }
    let id = id.as_deref();
    let profile = parse_arg(rest, "--profile").unwrap_or_else(|| "release".into());
    let prof_dir = if profile == "dev" { "debug" } else { profile.as_str() };
    let repo = repo_root();

    let p = match kind.as_str() {
        "root-img"  => crate::buildns::blobs_dir(&repo, id).join(format!("root-{arch}.img")),
        "home-img"  => crate::buildns::blobs_dir(&repo, id).join(format!("home-{arch}.img")),
        "nvme-img"  => crate::buildns::blobs_dir(&repo, id).join(format!("nvme-{arch}.img")),
        "ahci-img"  => crate::buildns::blobs_dir(&repo, id).join(format!("ahci-{arch}.img")),
        "iso"       => crate::buildns::iso_path(&repo, id, &arch),
        "elf"       => crate::buildns::kernel_elf(&repo, id, &arch, prof_dir),
        "build-dir" => crate::buildns::target_dir(&repo, id),
        other => { eprintln!("xtask path: unknown kind `{other}`"); return Err(2); }
    };
    println!("{}", p.display());
    Ok(())
}
