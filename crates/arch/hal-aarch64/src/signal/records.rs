// aarch64 signal-frame record chain — `sigcontext.__reserved[4096]`.
//
// Linux fills `__reserved` with a chain of `struct _aarch64_ctx { magic, size }`
// records terminated by a zero record, and `restore_sigframe` REQUIRES an
// `FPSIMD_MAGIC` record: `if (!user.fpsimd) return -EINVAL`
// (`arch/arm64/kernel/signal.c:1044-1046`). A frame without one is not a
// "reduced" frame, it is a frame Linux itself rejects — and without the record
// a handler that calls any glibc string routine (all NEON-optimised) destroys
// the interrupted code's Q registers with nothing to put them back.
//
// Pure layout + validation, NO target gate, so every rule below is
// host-unit-tested in `records/tests.rs`. The caller (`super`) owns the
// user-memory accesses; this module never dereferences a user pointer.

/// `sizeof(struct _aarch64_ctx)` — the `{ magic, size }` head every record
/// starts with. `size` counts the head.
pub const CTX_HEAD_BYTES: usize = 8;
/// Linux `TERMINATOR_SIZE` = `round_up(sizeof(struct _aarch64_ctx), 16)`.
pub const TERMINATOR_SIZE: usize = 16;
/// Linux `EXTRA_CONTEXT_SIZE` = `round_up(sizeof(struct extra_context), 16)`.
pub const EXTRA_CONTEXT_SIZE: usize = 32;
/// `sizeof(sigcontext.__reserved)`.
pub const RESERVED_BYTES: usize = 4096;
/// Linux `SIGFRAME_MAXSZ` (`SZ_256K`) — the sanity bound an `extra_context`
/// area may not push the frame past.
pub const SIGFRAME_MAXSZ: u64 = 256 * 1024;
/// Every record starts on a 16-byte boundary, so every `size` is a multiple
/// of 16 (`parse_user_sigframe` re-checks `IS_ALIGNED(offset, 16)`).
pub const RECORD_ALIGN: usize = 16;

/// `FPSIMD_MAGIC`. The one record Linux makes mandatory.
pub const FPSIMD_MAGIC: u32 = 0x4650_8001;
/// `ESR_MAGIC` — fault syndrome. Written only when `thread.fault_code` is
/// set; ignored entirely on restore (`case ESR_MAGIC: /* ignore */`).
pub const ESR_MAGIC: u32 = 0x4553_5201;
/// `EXTRA_MAGIC` — the record that re-bases the walk into a spill area past
/// `__reserved`. We never need to WRITE one (see `ReservedAlloc`), but a
/// process — or CRIU restoring a checkpoint — may hand us one, and Linux
/// accepts it, so the parser must too.
pub const EXTRA_MAGIC: u32 = 0x4558_5401;

// Magics Linux only accepts when the matching `system_supports_*()` holds.
// This kernel enables neither SVE nor SME for EL0: `CPACR_EL1.ZEN` is never
// set (`fpu_enable` touches only `FPEN`) and `AT_HWCAP` advertises
// `HWCAP_FP | HWCAP_ASIMD` plus ISAR0 crypto bits and NOTHING else, so an SVE
// instruction at EL0 traps. On such a CPU Linux emits no SVE/SME record and
// its parser sends every magic below down `default: goto invalid`. Named here
// so the rejection is visibly deliberate rather than an unlisted default;
// `records/tests.rs` `sve_and_sme_records_are_rejected_as_they_are_on_a_non_sve_cpu`
// pins that rejection for every entry.
#[allow(dead_code, reason = "complete `_aarch64_ctx` magic table; these entries are the ones Linux gates behind system_supports_*() and this kernel enables none of them, so they are deliberately matched by scan_region's reject arm rather than by name")]
pub mod unsupported_magic {
    /// `SVE_MAGIC` — rejected: `!system_supports_sve() && !system_supports_sme()`.
    pub const SVE_MAGIC: u32 = 0x5356_4501;
    /// `ZA_MAGIC` — rejected: `!system_supports_sme()`.
    pub const ZA_MAGIC: u32 = 0x54366345;
    /// `ZT_MAGIC` — rejected: `!system_supports_sme2()`.
    pub const ZT_MAGIC: u32 = 0x5a544e01;
    /// `TPIDR2_MAGIC` — rejected: `!system_supports_tpidr2()`.
    pub const TPIDR2_MAGIC: u32 = 0x5450_4902;
    /// `FPMR_MAGIC` — rejected: `!system_supports_fpmr()`.
    pub const FPMR_MAGIC: u32 = 0x4650_4d52;
    /// `POE_MAGIC` — rejected: `!system_supports_poe()`.
    pub const POE_MAGIC: u32 = 0x504f_4530;
    /// `GCS_MAGIC` — rejected: `!system_supports_gcs()`.
    pub const GCS_MAGIC: u32 = 0x4743_5300;
}

/// `sizeof(struct fpsimd_context)` = head + fpsr + fpcr + 32 × 16 B vregs.
pub const FPSIMD_CONTEXT_BYTES: usize = CTX_HEAD_BYTES + 8 + 32 * 16;
/// `fpsr` offset inside `struct fpsimd_context` — note it precedes `fpcr`,
/// and BOTH precede the vector registers. `struct user_fpsimd_state` (and our
/// `FpuStateAArch64`) order them the other way round, so a memcpy of the save
/// area into the record would swap them.
pub const FPSIMD_FPSR_OFF: usize = CTX_HEAD_BYTES;
/// `fpcr` offset inside `struct fpsimd_context`.
pub const FPSIMD_FPCR_OFF: usize = CTX_HEAD_BYTES + 4;
/// `vregs[0]` offset inside `struct fpsimd_context`.
pub const FPSIMD_VREGS_OFF: usize = CTX_HEAD_BYTES + 8;

const _: () = {
    assert!(FPSIMD_CONTEXT_BYTES == 0x210);
    assert!(FPSIMD_CONTEXT_BYTES % RECORD_ALIGN == 0);
    assert!(EXTRA_CONTEXT_SIZE % RECORD_ALIGN == 0);
};

/// Linux's `__sigframe_alloc` cursor over `__reserved[]`, in offsets relative
/// to the start of `__reserved`.
///
/// `limit` starts `TERMINATOR_SIZE + EXTRA_CONTEXT_SIZE` short of the end so
/// an `extra_context` plus its mandatory terminator can always be planted.
/// Linux splices those in when a record does not fit and spills the remainder
/// into a variable-length area past the frame; the only record set that
/// overflows is an SVE one, and this kernel does not enable SVE for EL0
/// (see the magic constants above), so `alloc` here reports the overflow
/// instead — Linux's `-ENOMEM`, which `get_sigframe` turns into a failed
/// delivery and `handle_signal` into `force_sigsegv`. Adding a record that
/// does not fit therefore fails loudly rather than silently truncating the
/// chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReservedAlloc {
    /// Bytes consumed so far.
    pub size: usize,
    /// Ceiling `size` may not pass.
    pub limit: usize,
}

impl ReservedAlloc {
    /// Linux `init_user_layout()`, rebased to `__reserved`. # C: O(1)
    pub fn new() -> Self {
        Self { size: 0, limit: RESERVED_BYTES - TERMINATOR_SIZE - EXTRA_CONTEXT_SIZE }
    }

    /// Linux `sigframe_alloc()`: reserve `size` bytes, padded to 16.
    /// `None` = `-ENOMEM`. # C: O(1)
    pub fn alloc(&mut self, size: usize) -> Option<usize> {
        let padded = (size + RECORD_ALIGN - 1) & !(RECORD_ALIGN - 1);
        if padded > self.limit.checked_sub(self.size)? { return None; }
        let off = self.size;
        self.size += padded;
        Some(off)
    }

    /// Linux `sigframe_alloc_end()`: un-reserve the terminator's space, place
    /// it, and freeze the cursor. # C: O(1)
    pub fn alloc_end(&mut self) -> Option<usize> {
        self.limit += TERMINATOR_SIZE;
        let off = self.alloc(CTX_HEAD_BYTES)?;
        self.limit = self.size;
        Some(off)
    }
}

impl Default for ReservedAlloc {
    fn default() -> Self { Self::new() }
}

/// Fill `__reserved` with the chain Linux writes for an ordinary (non-fault,
/// non-SVE) delivery: one `fpsimd_context` then the null terminator.
///
/// `q` / `fpcr` / `fpsr` come from the task's FP/SIMD save area, which the
/// caller has already synced from the hardware (Linux
/// `fpsimd_save_and_flush_current_state` + `preserve_fpsimd_context`).
/// Returns false only if the chain does not fit, which the caller must turn
/// into a failed delivery.
/// # C: O(n) in the 528-byte record
pub fn write_chain(reserved: &mut [u8], q: &[u8], fpcr: u32, fpsr: u32) -> bool {
    if reserved.len() < RESERVED_BYTES || q.len() < 32 * 16 { return false; }
    let mut a = ReservedAlloc::new();
    let Some(fp_off) = a.alloc(FPSIMD_CONTEXT_BYTES) else { return false };
    let Some(end_off) = a.alloc_end() else { return false };
    // Linux `preserve_fpsimd_context`.
    put_u32(reserved, fp_off, FPSIMD_MAGIC);
    put_u32(reserved, fp_off + 4, FPSIMD_CONTEXT_BYTES as u32);
    put_u32(reserved, fp_off + FPSIMD_FPSR_OFF, fpsr);
    put_u32(reserved, fp_off + FPSIMD_FPCR_OFF, fpcr);
    reserved[fp_off + FPSIMD_VREGS_OFF..fp_off + FPSIMD_CONTEXT_BYTES]
        .copy_from_slice(&q[..32 * 16]);
    // Linux's "end" magic — the record the parser stops on.
    put_u32(reserved, end_off, 0);
    put_u32(reserved, end_off + 4, 0);
    true
}

/// Write only the null terminator, for a delivery with no FP/SIMD image to
/// carry: `__reserved` holds whatever the process left there, so the chain
/// must be terminated or the parser walks user garbage.
/// # C: O(1)
pub fn write_terminator(reserved: &mut [u8]) {
    if reserved.len() < TERMINATOR_SIZE { return; }
    put_u32(reserved, 0, 0);
    put_u32(reserved, 4, 0);
}

/// What one pass of Linux `parse_user_sigframe` found in a region.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Scan {
    /// `(offset, size)` of an `FPSIMD_MAGIC` record inside this region.
    pub fpsimd: Option<(usize, u32)>,
    /// `(datap, size)` of an `extra_context` the caller must re-scan. The
    /// walk of THIS region ends there; Linux deliberately ignores the
    /// trailing `__reserved` terminator and continues in the extra area.
    pub rebase: Option<(u64, usize)>,
}

/// Linux `parse_user_sigframe()`, one region at a time. `region` is either
/// `sigcontext.__reserved` or the `extra_context` area; `region_va` is its
/// user address (Linux checks `IS_ALIGNED(base, 16)`) and `frame_va` the
/// rt_sigframe base, needed for the `SIGFRAME_MAXSZ` bound.
///
/// `Err(())` is Linux's `goto invalid` → `-EINVAL` → `arm64_notify_segfault`.
/// EVERY malformed chain lands there — unlike x86, arm64's parser rejects,
/// it does not degrade.
/// # C: O(n) in the number of records
pub fn scan_region(region: &[u8], region_va: u64, frame_va: u64,
                   seen_fpsimd: bool, have_extra: bool) -> Result<Scan, ()> {
    if region_va % RECORD_ALIGN as u64 != 0 { return Err(()); }
    let limit = region.len();
    let mut offset = 0usize;
    let mut out = Scan::default();
    let mut seen_fpsimd = seen_fpsimd;
    loop {
        if limit - offset < CTX_HEAD_BYTES { return Err(()); }
        if offset % RECORD_ALIGN != 0 { return Err(()); }
        let magic = get_u32(region, offset);
        let size = get_u32(region, offset + 4) as usize;
        if limit - offset < size { return Err(()); }
        match magic {
            0 => {
                if size != 0 { return Err(()); }
                return Ok(out);
            }
            FPSIMD_MAGIC => {
                if seen_fpsimd { return Err(()); }
                seen_fpsimd = true;
                out.fpsimd = Some((offset, size as u32));
            }
            // Linux ignores the fault-syndrome record on restore.
            ESR_MAGIC => {}
            EXTRA_MAGIC => {
                if have_extra || out.rebase.is_some() { return Err(()); }
                if size < EXTRA_CONTEXT_SIZE { return Err(()); }
                let datap = get_u64(region, offset + CTX_HEAD_BYTES);
                let extra_size = get_u32(region, offset + CTX_HEAD_BYTES + 8) as usize;
                // The mandatory `{0,0}` immediately after the extra_context:
                // "If extra_context is present, it must be followed
                // immediately in __reserved[] by the terminating null".
                if limit - offset - size < TERMINATOR_SIZE { return Err(()); }
                let end = offset + size;
                if get_u32(region, end) != 0 || get_u32(region, end + 4) != 0 { return Err(()); }
                let userp = region_va.checked_add((end + TERMINATOR_SIZE) as u64).ok_or(())?;
                if datap % RECORD_ALIGN as u64 != 0 { return Err(()); }
                if extra_size % RECORD_ALIGN != 0 { return Err(()); }
                // The extra area must start EXACTLY after that terminator —
                // this is what makes extra_context the last record in
                // `__reserved`, and what stops `datap` aiming anywhere else.
                if datap != userp { return Err(()); }
                // "Reject unreasonably large frames".
                let cap = frame_va.checked_add(SIGFRAME_MAXSZ).ok_or(())?;
                if (extra_size as u64) > cap.checked_sub(userp).ok_or(())? { return Err(()); }
                out.rebase = Some((datap, extra_size));
                return Ok(out);
            }
            _ => return Err(()),
        }
        if size < CTX_HEAD_BYTES { return Err(()); }
        if limit - offset < size { return Err(()); }
        offset += size;
    }
}

/// Linux `read_fpsimd_context()`: the record's size must be EXACTLY
/// `sizeof(struct fpsimd_context)`, else `-EINVAL`. Returns
/// `(fpsr, fpcr, vregs_offset)`.
/// # C: O(1)
pub fn read_fpsimd(region: &[u8], off: usize, size: u32) -> Result<(u32, u32, usize), ()> {
    if size as usize != FPSIMD_CONTEXT_BYTES { return Err(()); }
    if off.checked_add(FPSIMD_CONTEXT_BYTES).filter(|e| *e <= region.len()).is_none() {
        return Err(());
    }
    Ok((get_u32(region, off + FPSIMD_FPSR_OFF), get_u32(region, off + FPSIMD_FPCR_OFF),
        off + FPSIMD_VREGS_OFF))
}

/// Little-endian u32 at `off`. # C: O(1)
fn get_u32(b: &[u8], off: usize) -> u32 {
    let mut v = [0u8; 4];
    v.copy_from_slice(&b[off..off + 4]);
    u32::from_le_bytes(v)
}

/// Little-endian u64 at `off`. # C: O(1)
fn get_u64(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

/// Store a little-endian u32 at `off`. # C: O(1)
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests;
