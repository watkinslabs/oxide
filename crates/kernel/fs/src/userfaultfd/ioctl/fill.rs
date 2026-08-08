// UFFDIO_COPY / UFFDIO_ZEROPAGE / UFFDIO_CONTINUE / UFFDIO_POISON.
//
// Four commands, one tail: they differ in what they validate up front and in
// where the page contents come from, and share the destination ladder, the
// reply-word protocol and the wake. That is deliberate — the destination
// ladder is the security boundary, and a second copy of it is a second chance
// to get it wrong.

use hal::UserVirtAddr;
use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};
use crate::userfaultfd::policy::{self, DstVma, FillKind};
use crate::userfaultfd::{uapi::*, work, UfData};

use super::structs::{err, read_req, write_reply, UffdioCopy, UffdioRangeOp};

/// Fill `[dst, dst+len)` from the monitor's source bytes.
/// # C: O(len/PAGE)
pub fn ioc_copy(ufd: &UfData, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, UFFDIO_COPY_SIZE, 1) { return rv; }
    if let Some(rv) = refuse_if_changing(ufd, arg + UFFDIO_COPY_COPY_OFF) { return rv; }
    // SAFETY: arg validated writable for the full uffdio_copy object.
    let c: UffdioCopy = unsafe { read_req(arg) };
    // The SOURCE is validated before the destination, and the mode word after
    // both — an ordering a monitor can observe through which errno it gets.
    if let Err(e) = policy::validate_unaligned_range(c.src, c.len) { return err(e); }
    if let Err(e) = policy::validate_range(c.dst, c.len) { return err(e); }
    if let Err(e) = policy::check_copy_mode(c.mode) { return err(e); }
    // The source is read through the CALLER's address space even when the
    // target address space differs, so it is validated against the caller —
    // unlike the destination, which belongs to the context.
    if let Err(rv) = validate_user_buf_readable(c.src, c.len, 1) { return rv; }
    let req = work::FillReq {
        kind: FillKind::Copy, dst: c.dst, src: Some(c.src), len: c.len,
        wp: c.mode & UFFDIO_COPY_MODE_WP != 0,
    };
    fill(ufd, &req, c.mode, arg + UFFDIO_COPY_COPY_OFF)
}

/// Fill `[start, start+len)` with zero pages.
/// # C: O(len/PAGE)
pub fn ioc_zeropage(ufd: &UfData, arg: u64) -> i64 {
    let Some(z) = range_op(arg, UFFDIO_ZEROPAGE_SIZE) else { return err(Errno::Efault) };
    if let Some(rv) = refuse_if_changing(ufd, arg + UFFDIO_ZEROPAGE_ZEROPAGE_OFF) { return rv; }
    if let Err(e) = policy::validate_range(z.range.start, z.range.len) { return err(e); }
    if let Err(e) = policy::check_zeropage_mode(z.mode) { return err(e); }
    let req = work::FillReq {
        kind: FillKind::Zeropage, dst: z.range.start, src: None, len: z.range.len, wp: false,
    };
    fill(ufd, &req, z.mode, arg + UFFDIO_ZEROPAGE_ZEROPAGE_OFF)
}

/// Map the pages the backing ALREADY holds for `[start, start+len)`. This is
/// the resolve for a minor fault: nothing is written, the existing contents
/// are simply published into the page table.
/// # C: O(len/PAGE)
pub fn ioc_continue(ufd: &UfData, arg: u64) -> i64 {
    let Some(k) = range_op(arg, UFFDIO_CONTINUE_SIZE) else { return err(Errno::Efault) };
    if let Some(rv) = refuse_if_changing(ufd, arg + UFFDIO_CONTINUE_MAPPED_OFF) { return rv; }
    if let Err(e) = policy::validate_range(k.range.start, k.range.len) { return err(e); }
    if let Err(e) = policy::check_continue_mode(k.mode) { return err(e); }
    let req = work::FillReq {
        kind: FillKind::Continue, dst: k.range.start, src: None, len: k.range.len,
        wp: k.mode & UFFDIO_CONTINUE_MODE_WP != 0,
    };
    fill(ufd, &req, k.mode, arg + UFFDIO_CONTINUE_MAPPED_OFF)
}

/// Mark `[start, start+len)` unrecoverable: a later access raises a memory
/// error instead of faulting a page in.
/// # C: O(len/PAGE)
pub fn ioc_poison(ufd: &UfData, arg: u64) -> i64 {
    let Some(p) = range_op(arg, UFFDIO_POISON_SIZE) else { return err(Errno::Efault) };
    if let Some(rv) = refuse_if_changing(ufd, arg + UFFDIO_POISON_UPDATED_OFF) { return rv; }
    if let Err(e) = policy::validate_range(p.range.start, p.range.len) { return err(e); }
    if let Err(e) = policy::check_poison_mode(p.mode) { return err(e); }
    let req = work::FillReq {
        kind: FillKind::Poison, dst: p.range.start, src: None, len: p.range.len, wp: false,
    };
    fill(ufd, &req, p.mode, arg + UFFDIO_POISON_UPDATED_OFF)
}

/// The in-flight-change refusal, in the position every fill shares: AFTER the
/// request object has been proven writable (the reply word has to be written
/// for the monitor to read the errno out of it) and BEFORE anything in the
/// request is looked at. A monitor that gets this back has a pending event to
/// read, after which the same command succeeds.
/// # C: O(1)
fn refuse_if_changing(ufd: &UfData, reply_slot: u64) -> Option<i64> {
    let e = policy::check_mmap_changing(ufd.changes_in_flight()).err()?;
    write_reply(reply_slot, err(e));
    Some(err(e))
}

/// Read one of the three range-shaped request objects. `None` when the object
/// itself is unreadable.
/// # C: O(1)
fn range_op(arg: u64, size: u64) -> Option<UffdioRangeOp> {
    if validate_user_buf_writable(arg, size, 1).is_err() { return None; }
    // SAFETY: arg validated writable for the full request object, which is larger than UffdioRangeOp only in name.
    Some(unsafe { read_req(arg) })
}

/// The shared tail: resolve the target address space, prove the destination is
/// a registered VMA this fill is legal on, do the work, then write the byte
/// count and encode the return.
///
/// The destination ladder is the whole point of this function. Without it a
/// fill ran against the CALLER's address space and fell back to plain
/// read-write page flags when no VMA was found — i.e. any holder of a uffd fd
/// could materialise a writable page at an arbitrary user address.
/// # C: O(N_vmas) lookup + O(len/PAGE) work
fn fill(ufd: &UfData, req: &work::FillReq, mode: u64, count_slot: u64) -> i64 {
    // The "address space is gone" arm returns WITHOUT touching the reply word,
    // unlike the ladder failures below.
    let Some(mm) = ufd.mm() else { return err(Errno::Esrch) };
    let vma = UserVirtAddr::new(req.dst).and_then(|v| mm.uffd_vma_at(v));
    let dst = vma.as_ref().map(|v| DstVma {
        end: v.end,
        uffd_registered: v.ctx.is_some(),
        uffd_wp: v.modes.contains(vmm::VmaFlags::UFFD_WP),
        anonymous: v.anonymous,
        shmem: v.shmem,
    });
    // A ladder rejection still writes the reply word: the monitor reads the
    // errno out of it, exactly as it reads a byte count out of a success.
    let (done, fail) = match policy::check_dst_vma(req.dst + req.len, dst, req.wp, req.kind) {
        Err(e) => (0, Some(e)),
        Ok(()) => {
            let v = vma.as_ref().expect("the ladder rejects a missing VMA");
            match req.kind {
                FillKind::Poison => work::poison_range(&mm, req.dst, req.dst + req.len),
                _ => work::fill_pages(&mm, req, v),
            }
        }
    };
    let (rv, count) = policy::fill_retval(done, req.len, fail);
    write_reply(count_slot, count);
    if policy::should_wake(mode, done) { ufd.wake_faulters(); }
    rv
}
