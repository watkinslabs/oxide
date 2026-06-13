// Build-namespacing helpers. An optional `--id <slot>` isolates ALL build
// outputs of one xtask invocation into a per-id namespace so multiple
// different builds coexist on disk without overwriting each other.
//
// HARD INVARIANT: when `id == None` every returned path is BYTE-IDENTICAL
// to the pre-namespacing literals (CI / pre-push run with no --id and must
// be unaffected). The `None` branch reuses the exact original strings.

use std::path::{Path, PathBuf};

/// Validate `id` is a safe slug: non-empty, only `[A-Za-z0-9._-]`, and not
/// `.`/`..` (no path traversal / separators). Returns Err(2) on a bad id so
/// callers can `?` it into an xtask exit code.
pub(crate) fn validate(id: &str) -> Result<(), u8> {
    if id.is_empty()
        || id == "."
        || id == ".."
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        eprintln!("xtask: unsafe build id `{id}` — allowed: [A-Za-z0-9._-], not . or ..");
        return Err(2);
    }
    Ok(())
}

/// Build-output target dir: `repo/target/builds/<id>` when id set, else the
/// plain `repo/target`.
pub(crate) fn target_dir(repo: &Path, id: Option<&str>) -> PathBuf {
    match id {
        Some(id) => repo.join("target").join("builds").join(id),
        None => repo.join("target"),
    }
}

/// Disk-image blob dir. C90: an id'd build puts EVERYTHING under one folder
/// `repo/target/builds/<id>` (disk images alongside the ISO + ELF snapshot);
/// the no-id legacy path stays `repo/kernel/blobs` BYTE-IDENTICAL (CI / make /
/// smoke hardcode it — the CI-safety invariant).
pub(crate) fn blobs_dir(repo: &Path, id: Option<&str>) -> PathBuf {
    match id {
        Some(id) => repo.join("target").join("builds").join(id),
        None => repo.join("kernel/blobs"),
    }
}

/// GRUB ISO output path for `arch`.
pub(crate) fn iso_path(repo: &Path, id: Option<&str>, arch: &str) -> PathBuf {
    target_dir(repo, id).join(format!("oxide-{arch}-grub.iso"))
}

/// grub-stage scratch dir for `arch`.
pub(crate) fn grub_stage(repo: &Path, id: Option<&str>, arch: &str) -> PathBuf {
    target_dir(repo, id).join(format!("grub-stage-{arch}"))
}

/// aarch64 flat `Image` artifact path.
pub(crate) fn arm_image(repo: &Path, id: Option<&str>) -> PathBuf {
    target_dir(repo, id).join("oxide-aarch64.Image")
}

/// Per-id kernel ELF SNAPSHOT path (where an id'd build's ELF is copied to):
/// `<target_dir(id)>/<arch>-unknown-oxide-kernel/<prof_dir>/oxide-<arch>`.
/// For `id == None` this equals `kernel_elf_build` (the shared build output).
pub(crate) fn kernel_elf(repo: &Path, id: Option<&str>, arch: &str, prof_dir: &str) -> PathBuf {
    target_dir(repo, id).join(format!("{arch}-unknown-oxide-kernel/{prof_dir}/oxide-{arch}"))
}

/// SHARED build output path — where cargo actually writes the kernel ELF when
/// building in the default `target/` (no `CARGO_TARGET_DIR` override):
/// `target/<arch>-unknown-oxide-kernel/<prof_dir>/oxide-<arch>`. The kernel
/// always compiles here so cargo's incremental cache is reused across ids; an
/// id'd build then snapshots this ELF to `kernel_elf(.. Some(id) ..)`.
pub(crate) fn kernel_elf_build(repo: &Path, arch: &str, prof_dir: &str) -> PathBuf {
    kernel_elf(repo, None, arch, prof_dir)
}
