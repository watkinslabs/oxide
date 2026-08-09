// `kexec_file_load`: the kernel, not the caller, builds the segment list.
//
// The caller hands over two descriptors and a command line; an arch loader
// recognises the kernel file and lays out the segments, the purgatory and the
// boot parameters. Everything up to that hand-off is here; the loaders
// themselves are registered by the arch and there are none yet, which is why
// this path ends in ENOEXEC — the same answer the reference gives when no
// registered loader probes a file successfully.

extern crate alloc;
use alloc::vec::Vec;

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

/// An arch kernel-image loader: probe a file, then lay out its segments.
///
/// Registered by the arch rather than discovered, so the probe ORDER is
/// explicit — the reference walks `kexec_file_loaders[]` in declaration order
/// and takes the first loader that accepts the file.
pub trait FileLoader {
    /// `Ok(())` when this loader recognises `kernel`.
    fn probe(&self, kernel: &[u8]) -> KResult<()>;
    /// Lay the image out: the segment list, the entry point, and the blob the
    /// segments are cut from — each segment's `buf` is an OFFSET into it.
    fn load(&self, img: &FileImage) -> KResult<(Vec<KexecSegment>, u64, Vec<u8>)>;
}

/// The registered loaders, in probe order.
///
/// EMPTY on both arches. A loader has to place the kernel, the initramfs, the
/// boot parameters and a purgatory into memory holes and relocate the
/// purgatory against the image — and none of that is reachable while the
/// relocation trampoline in `machine` does not exist, because nothing could
/// ever consume the result. `scratch/known_issues.md` carries the row.
///
/// It is a real, walked list rather than an unconditional refusal: with no
/// loader accepting the file, `ENOEXEC` is exactly what the reference returns,
/// so the errno is right today and stays right when the first loader lands.
const LOADERS: &[&dyn FileLoader] = &[];

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
/// Order, unchanged from the reference: the kexec lock (EBUSY), the unload
/// short-circuit, the descriptor reads (EBADF / EIO), the command-line rule
/// (EFAULT then EINVAL), the loader probe (ENOEXEC), the segment staging.
///
/// `read` is a closure so the descriptor reads happen INSIDE the lock, where
/// the reference performs them. Reading first and locking after would let a
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
        let (segments, entry, blob) = loader.load(&img)?;
        // The file-mode flag word spells the crash bit differently; translate
        // it into the shared one so ONE store decides which slot is written.
        let store_flags = if flags & KEXEC_FILE_ON_CRASH != 0 { KEXEC_ON_CRASH } else { 0 };
        let src = crate::stage::KernelSource { bytes: &blob };
        crate::store::install_staged(f, entry, segments, store_flags,
                                     crate::stage::Limits::default(), &src)
    })
}
