// Every kexec refusal decision, in the order the reference makes it.
//
// Ungated on purpose (`docs/53`, CLAUDE.md phantom-test rule): the slot files
// are `#[cfg(target_os = "oxide-kernel")]`, so a `#[cfg(test)]` block there
// would compile out silently. The order encoded here is the contract, and the
// tests in `tests/order.rs` are its provenance.

use crate::uapi::*;

/// Refusal reasons, mapped to errno by the syscall shim.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// `-EPERM` — no `CAP_SYS_BOOT`, loading disabled, or the per-type load
    /// limit is exhausted.
    Perm,
    /// `-EINVAL`.
    Inval,
    /// `-EADDRNOTAVAIL` — a destination address this kernel cannot use.
    AddrNotAvail,
    /// `-ENOMEM`.
    Nomem,
    /// `-EBUSY` — another load or a kexec reboot holds the kexec lock.
    Busy,
    /// `-EFAULT` — a source buffer is not readable.
    Fault,
    /// `-EBADF` — `kernel_fd` / `initrd_fd` is not an open descriptor.
    BadFd,
    /// `-ENOEXEC` — no loader recognises the kernel file.
    NoExec,
    /// `-ENOSYS` — the machine-specific step is not built (`machine`).
    NoSys,
}

/// Result alias for the kexec decision surface.
pub type KResult<T> = Result<T, Error>;

/// Image type a `flags` word selects.
/// # C: O(1)
pub fn image_type(flags: u64) -> ImageType {
    if flags & KEXEC_ON_CRASH != 0 { ImageType::Crash } else { ImageType::Default }
}

/// `kexec_load_check`: permission, then flag legality, then the segment cap.
///
/// The ORDER is load-bearing. Permission comes FIRST, so an unprivileged caller
/// passing nonsense flags learns only that it may not load a kernel — reversing
/// the two tells a process that could never kexec anything which flag words are
/// well formed.
///
/// The flag test is `(flags & KEXEC_FLAGS) == (flags & !KEXEC_ARCH_MASK)`, not a
/// plain `flags & !KEXEC_FLAGS == 0`: the architecture field is checked
/// separately and must be excluded from the "unknown bit" test rather than
/// silently permitted.
/// # C: O(1)
pub fn kexec_load_check(permitted: bool, nr_segments: u64, flags: u64) -> KResult<()> {
    if !permitted { return Err(Error::Perm); }
    if (flags & KEXEC_FLAGS) != (flags & !KEXEC_ARCH_MASK) { return Err(Error::Inval); }
    if nr_segments > KEXEC_SEGMENT_MAX { return Err(Error::Inval); }
    Ok(())
}

/// Architecture field test, made AFTER `kexec_load_check` and BEFORE the
/// segment array is copied in: a caller naming a foreign machine is refused
/// without reading its array.
/// # C: O(1)
pub fn arch_ok(flags: u64) -> KResult<()> {
    let arch = flags & KEXEC_ARCH_MASK;
    if arch != KEXEC_ARCH && arch != KEXEC_ARCH_DEFAULT { return Err(Error::Inval); }
    Ok(())
}

/// `kexec_file_load`'s flag test: exact membership, no architecture field.
/// # C: O(1)
pub fn kexec_file_load_check(permitted: bool, flags: u64) -> KResult<()> {
    if !permitted { return Err(Error::Perm); }
    if flags != (flags & KEXEC_FILE_FLAGS) { return Err(Error::Inval); }
    Ok(())
}

/// Physical range a crash image must stay inside, when one is reserved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CrashRange {
    /// First byte of the reserved region.
    pub start: u64,
    /// LAST byte of the reserved region, inclusive — the reference stores
    /// `crashk_res.end` inclusively and compares `mend > end`.
    pub end: u64,
}

/// Entry-point containment test for `KEXEC_ON_CRASH`, made before the image is
/// even allocated: an entry outside the reserved region can only jump into the
/// running kernel's memory.
/// # C: O(1)
pub fn crash_entry_ok(entry: u64, crash: Option<CrashRange>) -> KResult<()> {
    match crash {
        // No reservation: nothing to contain the image, so a crash load has
        // nowhere legal to go. The reference reaches the same refusal through
        // an empty `crashk_res` (start == end == 0), which no valid entry
        // point can satisfy.
        None => Err(Error::AddrNotAvail),
        Some(r) if entry < r.start || entry > r.end => Err(Error::AddrNotAvail),
        Some(_) => Ok(()),
    }
}

/// `sanity_check_segment_list`, in the reference's order:
///
/// 1. every destination range is well formed, page aligned and below the
///    architecture's destination limit — `EADDRNOTAVAIL`;
/// 2. no two destination ranges overlap — `EINVAL`;
/// 3. `bufsz <= memsz` for every segment — `EINVAL`;
/// 4. neither one segment nor the whole list may claim more than half of RAM —
///    `EINVAL`;
/// 5. a crash image's destinations lie inside the reserved region —
///    `EADDRNOTAVAIL`.
///
/// The order matters at every seam: an unaligned, overlapping segment list
/// reports `EADDRNOTAVAIL`, not `EINVAL`, because alignment is decided first —
/// and an overlap that only exists after rounding to page granularity is
/// exactly the case step 1 exists to make impossible.
///
/// Whether the destination is backed by usable RAM is NOT checked, and that is
/// deliberate: the reference states the caller owns that choice, because the
/// destination is not touched during staging at all. Pages are copied there by
/// the relocation trampoline, after the running kernel has stopped using them.
/// # C: O(N^2) in nr_segments, bounded by `KEXEC_SEGMENT_MAX`
pub fn sanity_check_segment_list(
    segs: &[KexecSegment],
    ty: ImageType,
    total_ram_pages: u64,
    dest_limit: u64,
    crash: Option<CrashRange>,
) -> KResult<()> {
    for s in segs {
        let mend = match s.mem.checked_add(s.memsz) { Some(v) => v, None => return Err(Error::AddrNotAvail) };
        if s.mem > mend { return Err(Error::AddrNotAvail); }
        if (s.mem & !PAGE_MASK) != 0 || (mend & !PAGE_MASK) != 0 { return Err(Error::AddrNotAvail); }
        if mend >= dest_limit { return Err(Error::AddrNotAvail); }
    }
    for (i, s) in segs.iter().enumerate() {
        let (mstart, mend) = (s.mem, s.mem + s.memsz);
        for p in &segs[..i] {
            let (pstart, pend) = (p.mem, p.mem + p.memsz);
            if mend > pstart && mstart < pend { return Err(Error::Inval); }
        }
    }
    for s in segs {
        if s.bufsz > s.memsz { return Err(Error::Inval); }
    }
    let mut total = 0u64;
    for s in segs {
        if page_count(s.memsz) > total_ram_pages / 2 { return Err(Error::Inval); }
        total += page_count(s.memsz);
    }
    if total > total_ram_pages / 2 { return Err(Error::Inval); }
    if ty == ImageType::Crash {
        let r = match crash { Some(r) => r, None => return Err(Error::AddrNotAvail) };
        for s in segs {
            // memsz == 0 would underflow the inclusive end; such a segment
            // occupies no bytes and cannot leave the region.
            if s.memsz == 0 { continue; }
            let mend = s.mem + s.memsz - 1;
            if s.mem < r.start || mend > r.end { return Err(Error::AddrNotAvail); }
        }
    }
    Ok(())
}

/// `kexec_file_load`'s command-line rule: a non-empty command line must be
/// NUL terminated, checked after the copy so a caller learns EFAULT before
/// EINVAL.
/// # C: O(1)
pub fn cmdline_ok(cmdline: &[u8]) -> KResult<()> {
    if cmdline.is_empty() { return Ok(()); }
    if cmdline[cmdline.len() - 1] != 0 { return Err(Error::Inval); }
    Ok(())
}

/// Signature-verification policy for `kexec_file_load`.
///
/// Read rather than assumed: with `CONFIG_KEXEC_SIG` unset the reference runs
/// NO signature check at all — `kimage_validate_signature` is compiled out and
/// the load proceeds on an unsigned image. With it set but no keyring able to
/// verify, the loader's missing `verify_sig` hook yields `EKEYREJECTED`, and a
/// failure is fatal only when `kexec_sig_force` (or lockdown) says so.
///
/// This port has no kernel keyring and no platform keyring to verify against,
/// so it takes the unset-`CONFIG_KEXEC_SIG` behaviour: no check, no refusal.
/// Rejecting every image instead would be a refusal the reference never makes;
/// pretending to verify would be worse.
/// # C: O(1)
pub fn signature_check_required() -> bool { false }
