// `kexec_file_load`: the kernel, not the caller, builds the segment list.
//
// The caller hands over two descriptors and a command line; an arch loader
// recognises the kernel file and lays out the segments, the purgatory and the
// boot parameters. Everything up to and around that hand-off is here.
//
// Module manifest:
// - `kbuf`:     ungated — where a buffer lands: constraints, hole search,
//               collision test, blob accumulation.
// - `purgatory`: ungated — the verification stage the loaded image starts in
//               on the architecture that has one, and the digest over the
//               segments it checks.
// - `x86_bzimage`: the `bzImage` loader — header probe, boot parameters, the
//               64-bit entry contract.
// - `arm_image`: the arm64 `Image` loader — header probe, placement, and the
//               device tree the new kernel is handed.
//
// WHY THE LOADER LIST IS A LIST. The reference walks `kexec_file_loaders[]` in
// declaration order and takes the first loader whose probe accepts the file.
// Keeping that shape means "no loader recognised this" stays ENOEXEC rather
// than becoming an unconditional refusal that happens to have the same errno.

extern crate alloc;
use alloc::vec::Vec;

pub mod kbuf;
pub mod purgatory;
pub mod x86_bzimage;
pub mod arm_image;

use crate::frames::Frames;
use crate::uapi::*;
use crate::validate::{cmdline_ok, Error, KResult};

/// What the descriptors and the user command line produced.
pub struct FileImage {
    /// The kernel file's bytes.
    pub kernel: Vec<u8>,
    /// The initramfs bytes; empty when `KEXEC_FILE_NO_INITRAMFS` was given.
    pub initrd: Vec<u8>,
    /// The command line INCLUDING its terminating NUL, as the caller passed it.
    pub cmdline: Vec<u8>,
}

impl FileImage {
    /// The command line without its terminating NUL, as a loader wants it.
    /// # C: O(1)
    pub fn cmdline_str(&self) -> &[u8] {
        match self.cmdline.split_last() {
            Some((0, rest)) => rest,
            _ => &self.cmdline,
        }
    }
}

/// Everything a loader needs about the machine it is placing an image on.
///
/// Passed in rather than read from globals, so every loader is reachable from
/// a hosted test that states the memory map. A loader that consulted the live
/// PMM directly could only ever be exercised by a boot, and a boot cannot tell
/// you WHERE it placed a segment — only that the machine did or did not
/// come back.
pub struct LoadCtx<'a> {
    /// The files and the command line.
    pub img: &'a FileImage,
    /// Usable RAM, `[start, end)` physical, in address order.
    pub ram: &'a [(u64, u64)],
    /// The running kernel's own device tree, when this machine boots from one.
    /// The new kernel's tree is derived from it.
    pub fdt: &'a [u8],
}

/// A laid-out image, ready for `stage_image`.
pub struct Loaded {
    /// The segment list; every `buf` is an offset into `blob`.
    pub segments: Vec<KexecSegment>,
    /// Physical address control transfers to once relocation is complete.
    pub entry: u64,
    /// The bytes every segment is cut from.
    pub blob: Vec<u8>,
    /// Address handed to the new kernel as its boot argument — the device tree
    /// on one architecture, the boot-parameter page on the other. Zero when the
    /// architecture passes nothing.
    pub boot_arg: u64,
}

/// An arch kernel-image loader: probe a file, then lay out its segments.
///
/// Registered by the arch rather than discovered, so the probe ORDER is
/// explicit — the loaders are probed in declaration order
/// and takes the first loader that accepts the file.
pub trait FileLoader {
    /// `Ok(())` when this loader recognises `kernel`.
    fn probe(&self, kernel: &[u8]) -> KResult<()>;
    /// Lay the image out.
    fn load(&self, ctx: &LoadCtx) -> KResult<Loaded>;
}

/// The registered loaders, in probe order.
///
/// One per architecture, because a `bzImage` is not a thing an aarch64 machine
/// can start and an `Image` is not a thing an x86_64 machine can start. Both
/// are compiled in on their own arch only; the hosted build sees an empty list
/// and answers `ENOEXEC`, which is what a kernel with no matching loader
/// answers anyway.
#[cfg(target_arch = "x86_64")]
const LOADERS: &[&dyn FileLoader] = &[&x86_bzimage::BzImage64];
#[cfg(target_arch = "aarch64")]
const LOADERS: &[&dyn FileLoader] = &[&arm_image::Arm64Image];

/// `kexec_image_probe_default`: first loader that accepts the file wins.
/// # C: O(N_loaders)
pub fn probe(kernel: &[u8]) -> KResult<&'static dyn FileLoader> {
    for l in LOADERS {
        if l.probe(kernel).is_ok() { return Ok(*l); }
    }
    Err(Error::NoExec)
}

/// `SYSCALL_DEFINE5(kexec_file_load)`'s body below the permission and flag
/// checks, which the shim has already made.
///
/// Order: the kexec lock (EBUSY), the unload
/// short-circuit, the descriptor reads (EBADF / EIO), the command-line rule
/// (EFAULT then EINVAL), the loader probe (ENOEXEC), the segment staging.
///
/// `read` is a closure so the descriptor reads happen INSIDE the lock, where
/// they must happen. Reading first and locking after would let a
/// caller that is about to be told EBUSY spend a whole file read finding out.
/// # C: O(file size); # Lk: KEXEC_LOCK, SLOTS
pub fn kexec_file_load<F: Frames, R>(f: &mut F, flags: u64, read: R) -> KResult<()>
where R: FnOnce() -> KResult<FileImage> {
    crate::store::with_kexec_lock(|| {
        if flags & KEXEC_FILE_UNLOAD != 0 {
            crate::store::drop_image(f, flags & KEXEC_FILE_ON_CRASH != 0);
            return Ok(());
        }
        let img = read()?;
        cmdline_ok(&img.cmdline)?;
        let loader = probe(&img.kernel)?;
        let mut ram: Vec<(u64, u64)> = Vec::new();
        for i in 0..f.ram_range_count() {
            if let Some(r) = f.ram_range(i) { ram.push(r); }
        }
        let limits = crate::stage::Limits::current();
        let crash = flags & KEXEC_FILE_ON_CRASH != 0;
        let ram = kbuf::placement_ranges(crash, &ram, limits.crash.map(|r| (r.start, r.end)))?;
        let fdt = machine_fdt();
        let ctx = LoadCtx { img: &img, ram: &ram, fdt: &fdt };
        let loaded = loader.load(&ctx)?;
        // The file-mode flag word spells the crash bit differently; translate
        // it into the shared one so ONE store decides which slot is written.
        let store_flags = if crash { KEXEC_ON_CRASH } else { 0 };
        let src = crate::stage::KernelSource { bytes: &loaded.blob };
        crate::store::install_staged(f, loaded.entry, loaded.segments, store_flags,
                                     limits, &src, loaded.boot_arg)
    })
}

/// The running kernel's device tree, or empty on a machine that has none.
/// # C: O(fdt size)
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn machine_fdt() -> Vec<u8> { arm_image::running_fdt() }
/// # C: O(1)
#[cfg(not(all(target_os = "oxide-kernel", target_arch = "aarch64")))]
fn machine_fdt() -> Vec<u8> { Vec::new() }

#[cfg(test)]
mod tests {
    use super::*;

    fn img(cmdline: &[u8]) -> FileImage {
        FileImage { kernel: Vec::new(), initrd: Vec::new(), cmdline: cmdline.to_vec() }
    }

    #[test]
    fn the_command_line_a_loader_sees_has_no_terminating_nul() {
        // Every arch boot protocol wants the string, and a loader that passed
        // the NUL through would place a command line one byte longer than the
        // one the caller wrote — visible to the new kernel as a trailing NUL
        // inside `bootargs`, where it truncates nothing and looks like nothing.
        assert_eq!(img(b"console=ttyS0\0").cmdline_str(), b"console=ttyS0");
        assert_eq!(img(b"").cmdline_str(), b"");
        // A caller that passed no NUL at all is refused before this by
        // `cmdline_ok`; if it ever were not, the string must still be whole.
        assert_eq!(img(b"quiet").cmdline_str(), b"quiet");
    }

    #[test]
    fn a_file_no_loader_recognises_is_enoexec() {
        assert_eq!(probe(b"not a kernel").err(), Some(Error::NoExec));
    }
}
