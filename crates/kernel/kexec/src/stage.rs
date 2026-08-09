// Turning a validated segment list into a staged image: `kimage_alloc_init`
// plus the per-segment load loop, with no global state touched.
//
// Split from `store` on purpose. Everything here is reachable from a hosted
// test with a fake page supply, which is the only way the control-page choice,
// the destination-collision swap and the relocation chain get exercised at all
// — a boot can only report that the machine did or did not come back.

extern crate alloc;
use alloc::vec::Vec;

use crate::frames::Frames;
use crate::image::{load_segment, KImage, SegmentSource};
use crate::uapi::*;
use crate::validate::{crash_entry_ok, sanity_check_segment_list, CrashRange, Error, KResult};

/// Machine facts the staging decisions depend on, passed in rather than read
/// from globals so a test can state them.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Highest destination address + 1 (`KEXEC_DESTINATION_MEMORY_LIMIT`).
    pub dest_limit: u64,
    /// Reserved crash region, when one exists.
    pub crash: Option<CrashRange>,
}

impl Default for Limits {
    /// Both arches this port builds place no destination limit, and no
    /// crashkernel region is reserved at boot — so a `KEXEC_ON_CRASH` load has
    /// nowhere legal to land and is refused with EADDRNOTAVAIL, exactly as a
    /// reference kernel booted without `crashkernel=` refuses it.
    /// # C: O(1)
    fn default() -> Self { Self { dest_limit: u64::MAX, crash: None } }
}

/// `kimage_alloc_init` + `kimage_load_segment` over the whole list.
///
/// Refusal order, unchanged from the reference: the crash entry point, then
/// the segment list, then the control pages, then the per-segment copy. A
/// caller whose entry point is outside the crash region learns that before a
/// single page is allocated.
/// # C: O(total memsz)
pub fn stage_image<F: Frames, S: SegmentSource>(
    f: &mut F,
    entry: u64,
    segments: Vec<KexecSegment>,
    flags: u64,
    limits: Limits,
    src: &S,
) -> KResult<KImage> {
    let ty = crate::validate::image_type(flags);
    if ty == ImageType::Crash { crash_entry_ok(entry, limits.crash)?; }
    sanity_check_segment_list(
        &segments, ty, f.total_ram_pages(), limits.dest_limit, limits.crash)?;

    let mut image = KImage::new(entry, ty, segments);
    let build = |image: &mut KImage, f: &mut F| -> KResult<()> {
        image.control_code_page = image.alloc_control_page(f)?;
        // The swap page is what lets the trampoline exchange a page with its
        // destination while `preserve_context` is in force. A crash image never
        // returns to this kernel, so it needs none — and its control pages come
        // from the reserved region, where a spare page is not free.
        if ty == ImageType::Default { image.swap_page = image.alloc_control_page(f)?; }
        for i in 0..image.segments.len() { load_segment(image, f, i, src)?; }
        image.terminate(f);
        Ok(())
    };
    match build(&mut image, f) {
        Ok(()) => Ok(image),
        // A half-staged image owns pages and a partial relocation chain. Left
        // to the caller it would be indistinguishable from a good one.
        Err(e) => { image.free(f); Err(e) }
    }
}

/// A segment source in user memory: each segment's own `buf + off`, read
/// through the exception table so a bad address is EFAULT, not a kernel fault.
pub struct UserSource {
    /// Reader, so the uaccess dependency does not reach this crate.
    pub read: fn(&mut [u8], u64) -> Result<(), ()>,
}

impl SegmentSource for UserSource {
    /// # C: O(len)
    fn read_at(&self, buf: u64, off: u64, dst: &mut [u8]) -> KResult<()> {
        (self.read)(dst, buf.wrapping_add(off)).map_err(|()| Error::Fault)
    }
}

/// A segment source already in kernel memory (`kexec_file_load`). In file mode
/// a segment's `buf` field is an OFFSET into the blob the loader built, not an
/// address — the loader owns the blob and the image never leaves the kernel.
pub struct KernelSource<'a> {
    /// The blob every segment is cut from.
    pub bytes: &'a [u8],
}

impl SegmentSource for KernelSource<'_> {
    /// # C: O(len)
    fn read_at(&self, buf: u64, off: u64, dst: &mut [u8]) -> KResult<()> {
        let start = match (buf.checked_add(off)).and_then(|v| usize::try_from(v).ok()) {
            Some(v) => v, None => return Err(Error::Fault),
        };
        let end = match start.checked_add(dst.len()) { Some(v) => v, None => return Err(Error::Fault) };
        if end > self.bytes.len() { return Err(Error::Fault); }
        dst.copy_from_slice(&self.bytes[start..end]);
        Ok(())
    }
}
