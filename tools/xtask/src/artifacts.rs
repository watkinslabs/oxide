// Stable artifact export for external package/image repos.
//
// The internal developer layout stays under target/builds/<id>; this command
// copies the subset that packaging is allowed to consume into target/artifacts
// (or --out <dir>) so external tooling does not depend on buildns internals.

use std::fs;
use std::path::{Path, PathBuf};

use crate::cmds::parse_arg;
use crate::image_qemu::repo_root;

const ARCHES: [&str; 2] = ["x86_64", "aarch64"];

pub(crate) fn cmd_artifacts(rest: &[String]) -> Result<(), u8> {
    let repo = repo_root();
    let id = parse_arg(rest, "--id");
    if let Some(ref id) = id { crate::buildns::validate(id)?; }
    let profile = parse_arg(rest, "--profile").unwrap_or_else(|| "release".into());
    let prof_dir = if profile == "dev" { "debug" } else { profile.as_str() };
    let out = parse_arg(rest, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.join("target/artifacts"));
    let arch_arg = parse_arg(rest, "--arch").unwrap_or_else(|| "both".into());
    let arches: Vec<&str> = match arch_arg.as_str() {
        "both" => ARCHES.to_vec(),
        "x86_64" => vec!["x86_64"],
        "aarch64" => vec!["aarch64"],
        other => {
            eprintln!("xtask artifacts: --arch must be x86_64, aarch64, or both (got `{other}`)");
            return Err(2);
        }
    };

    fs::create_dir_all(&out).map_err(|e| {
        eprintln!("xtask artifacts: mkdir {} failed: {e}", out.display());
        1u8
    })?;

    let mut manifest = String::new();
    manifest.push_str("schema=1\n");
    manifest.push_str(&format!("profile={profile}\n"));
    manifest.push_str(&format!("id={}\n", id.as_deref().unwrap_or("default")));

    for arch in arches {
        export_arch(&repo, id.as_deref(), arch, prof_dir, &out, &mut manifest)?;
    }
    export_sysroot(&repo, &out, &mut manifest)?;

    fs::write(out.join("manifest.txt"), manifest).map_err(|e| {
        eprintln!("xtask artifacts: write manifest failed: {e}");
        1u8
    })?;
    println!("xtask artifacts: exported {}", out.display());
    Ok(())
}

fn export_arch(
    repo: &Path,
    id: Option<&str>,
    arch: &str,
    prof_dir: &str,
    out: &Path,
    manifest: &mut String,
) -> Result<(), u8> {
    let arch_out = out.join(arch);
    fs::create_dir_all(&arch_out).map_err(|_| 1u8)?;

    let elf = crate::buildns::kernel_elf(repo, id, arch, prof_dir);
    copy_required(&elf, &arch_out.join("kernel.elf"))?;
    manifest.push_str(&format!("{arch}.kernel_elf={}/kernel.elf\n", arch));

    let iso = crate::buildns::iso_path(repo, id, arch);
    if copy_optional(&iso, &arch_out.join("boot.iso"))? {
        manifest.push_str(&format!("{arch}.boot_iso={}/boot.iso\n", arch));
    }

    if arch == "aarch64" {
        let image = crate::buildns::arm_image(repo, id);
        if copy_optional(&image, &arch_out.join("kernel.Image"))? {
            manifest.push_str("aarch64.kernel_image=aarch64/kernel.Image\n");
        }
    }
    Ok(())
}

fn export_sysroot(repo: &Path, out: &Path, manifest: &mut String) -> Result<(), u8> {
    for (arch, triple, ldso) in [
        ("x86_64", "x86_64-unknown-linux-gnu", "ld-linux-x86-64.so.2"),
        ("aarch64", "aarch64-unknown-linux-gnu", "ld-linux-aarch64.so.1"),
    ] {
        let src = repo.join("target/sysroot").join(triple);
        if !src.is_dir() {
            eprintln!("xtask artifacts: WARN missing sysroot {}", src.display());
            continue;
        }
        let dst = out.join("sysroot").join(triple);
        let lib_dst = dst.join("lib");
        let etc_dst = dst.join("etc");
        let include_dst = dst.join("usr/include");
        fs::create_dir_all(&lib_dst).map_err(|_| 1u8)?;
        fs::create_dir_all(&etc_dst).map_err(|_| 1u8)?;
        fs::create_dir_all(&include_dst).map_err(|_| 1u8)?;
        for file in [
            ldso,
            "libc.so.6",
            "libc.a",
            "Scrt1.o",
            "libpthread.so.0",
            "libdl.so.2",
            "librt.so.1",
            "libm.so.6",
            "libutil.so.1",
            "libresolv.so.2",
        ] {
            copy_required(&src.join("lib").join(file), &lib_dst.join(file))?;
        }
        copy_required(&src.join("etc/ld.so.cache"), &etc_dst.join("ld.so.cache"))?;
        copy_dir_optional(&src.join("usr/include"), &include_dst)?;
        manifest.push_str(&format!("{arch}.sysroot=sysroot/{triple}\n"));
        manifest.push_str(&format!("{arch}.sysroot_include=sysroot/{triple}/usr/include\n"));
    }
    Ok(())
}

fn copy_required(src: &Path, dst: &Path) -> Result<(), u8> {
    if !src.is_file() {
        eprintln!("xtask artifacts: required input missing: {}", src.display());
        return Err(2);
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|_| 1u8)?;
    }
    fs::copy(src, dst).map(|_| ()).map_err(|e| {
        eprintln!("xtask artifacts: copy {} -> {} failed: {e}", src.display(), dst.display());
        1u8
    })
}

fn copy_optional(src: &Path, dst: &Path) -> Result<bool, u8> {
    if !src.is_file() { return Ok(false); }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|_| 1u8)?;
    }
    fs::copy(src, dst).map(|_| true).map_err(|e| {
        eprintln!("xtask artifacts: copy {} -> {} failed: {e}", src.display(), dst.display());
        1u8
    })
}

fn copy_dir_optional(src: &Path, dst: &Path) -> Result<(), u8> {
    if !src.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dst).map_err(|_| 1u8)?;
    let rd = fs::read_dir(src).map_err(|e| {
        eprintln!("xtask artifacts: read {} failed: {e}", src.display());
        1u8
    })?;
    for ent in rd.flatten() {
        let from = ent.path();
        let to = dst.join(ent.file_name());
        if from.is_dir() {
            copy_dir_optional(&from, &to)?;
        } else if from.is_file() {
            fs::copy(&from, &to).map(|_| ()).map_err(|e| {
                eprintln!(
                    "xtask artifacts: copy {} -> {} failed: {e}",
                    from.display(),
                    to.display()
                );
                1u8
            })?;
        }
    }
    Ok(())
}
