// Build-namespacing helpers. An optional `--id <slot>` isolates ALL build
// outputs of one xtask invocation into a per-id namespace so multiple
// different builds coexist on disk without overwriting each other.
//
// HARD INVARIANT (C90): there is ONE scheme — every build lives under
// `target/builds/<id>`. The no-id build is simply the `default` namespace
// (`id == None` ≡ `"default"`); there is no special-case `kernel/blobs` or
// `target/blobs` dir anymore. The shared cargo compile output stays at the
// canonical `target/<arch>-unknown-oxide-kernel/...` (see `kernel_elf_build`).

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

/// Build-output target dir: `repo/target/builds/<id-or-"default">`. The no-id
/// build is the `default` namespace (C90 — no special-case `target/` dir).
pub(crate) fn target_dir(repo: &Path, id: Option<&str>) -> PathBuf {
    repo.join("target").join("builds").join(id.unwrap_or("default"))
}

/// Per-launch vhost-vsock guest CID. A vsock CID is a HOST-GLOBAL kernel
/// resource (exactly one qemu per host may own it), so hardcoding `3` made
/// concurrent boots collide — across worktrees AND across a single worktree's
/// boot-smoke RETRIES (a dying prior qemu still holds the CID). Derive it from
/// the repo path + build id + THIS process's pid so every concurrent launch is
/// unique. CIDs 0-2 are reserved; a second device uses `cid+1`, so pick an even
/// base ≥100 with headroom. Override with `OXIDE_QEMU_VSOCK_CID`. # C: O(1)
pub(crate) fn qemu_vsock_cid(repo: &Path, id: Option<&str>) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    repo.hash(&mut h);
    id.hash(&mut h);
    std::process::id().hash(&mut h);
    100 + (h.finish() % 1_000_000) as u32 * 2
}

/// A host TCP port for a per-launch forward (ssh/gdb), derived like
/// [`qemu_vsock_cid`] so concurrent worktree launches don't fight over a fixed
/// port. `salt` distinguishes multiple ports in one launch. Kept in the
/// ephemeral range. # C: O(1)
pub(crate) fn qemu_host_port(repo: &Path, id: Option<&str>, salt: u16) -> u16 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    repo.hash(&mut h);
    id.hash(&mut h);
    std::process::id().hash(&mut h);
    salt.hash(&mut h);
    20000 + (h.finish() % 20000) as u16
}

/// Disk-image blob dir. C90: a build puts EVERYTHING under one folder
/// `repo/target/builds/<id-or-"default">` (disk images alongside the ISO + ELF
/// snapshot). Identical to `target_dir` — there is no separate blobs location.
pub(crate) fn blobs_dir(repo: &Path, id: Option<&str>) -> PathBuf {
    target_dir(repo, id)
}

/// GRUB ISO output path for `arch`.
pub(crate) fn iso_path(repo: &Path, id: Option<&str>, arch: &str) -> PathBuf {
    target_dir(repo, id).join(format!("oxide-{arch}-grub.iso"))
}

/// QEMU's own PID-file path for one namespaced launch. The harness consumes
/// this instead of inferring liveness from an argv regex. # C: O(1)
pub(crate) fn qemu_pidfile(repo: &Path, id: Option<&str>, arch: &str) -> PathBuf {
    target_dir(repo, id).join(format!("qemu-{arch}.pid"))
}

/// grub-stage scratch dir for `arch`.
pub(crate) fn grub_stage(repo: &Path, id: Option<&str>, arch: &str) -> PathBuf {
    target_dir(repo, id).join(format!("grub-stage-{arch}"))
}

/// aarch64 flat `Image` artifact path.
pub(crate) fn arm_image(repo: &Path, id: Option<&str>) -> PathBuf {
    target_dir(repo, id).join("oxide-aarch64.Image")
}

/// Per-build kernel ELF SNAPSHOT path (where a build's ELF is copied to):
/// `<target_dir(id)>/<arch>-unknown-oxide-kernel/<prof_dir>/oxide-<arch>`.
/// Every build (incl. the `default` no-id one) snapshots here; this is NOT the
/// cargo working dir — that is `kernel_elf_build` (the shared compile output).
pub(crate) fn kernel_elf(repo: &Path, id: Option<&str>, arch: &str, prof_dir: &str) -> PathBuf {
    target_dir(repo, id).join(format!("{arch}-unknown-oxide-kernel/{prof_dir}/oxide-{arch}"))
}

/// SHARED build output path — where cargo actually writes the kernel ELF when
/// building in the plain `target/` (no `CARGO_TARGET_DIR` override):
/// `target/<arch>-unknown-oxide-kernel/<prof_dir>/oxide-<arch>`. This is the
/// cargo working dir, NOT a namespace (so cargo's incremental cache is reused
/// across ids); EVERY build — including the `default` no-id one — then snapshots
/// this ELF into `kernel_elf(repo, id, ..)` under `target/builds/<id>/`.
pub(crate) fn kernel_elf_build(repo: &Path, arch: &str, prof_dir: &str) -> PathBuf {
    repo.join("target").join(format!("{arch}-unknown-oxide-kernel/{prof_dir}/oxide-{arch}"))
}
