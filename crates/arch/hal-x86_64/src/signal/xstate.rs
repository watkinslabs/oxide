// x86_64 signal-frame FPU/extended-state area (`uc_mcontext.fpstate`).
//
// Linux `arch/x86/kernel/fpu/signal.c` writes the task's XSAVE image into
// the signal frame and re-loads it at `rt_sigreturn`. Without it a handler
// that runs ANY glibc string/memory routine — every one of which is
// SSE/AVX-optimised — destroys the interrupted code's XMM/YMM/ZMM and
// nothing puts them back: a silent wrong answer at an arbitrary point.
//
// Pure layout + validation, NO target gate, so every rule below is
// host-unit-tested in `xstate/tests.rs`. The caller (`super`) owns the
// user-memory accesses; this module never dereferences a user pointer.
//
// Byte map of the area `sigcontext.fpstate` points at (Linux
// `struct _xstate`, `arch/x86/include/uapi/asm/sigcontext.h:149-197`):
//
//   0x000..0x200  legacy FXSAVE image (`struct _fpstate_64`)
//   0x0d0..0x0e0    mxcsr @0x18, mxcsr_mask @0x1c inside it
//   0x1d0..0x200    `_fpx_sw_bytes` SW-reserved footer (offset 464)
//   0x200..0x240  xstate `_header`: xfeatures, xcomp_bv, 48 reserved bytes
//   0x240..        extended components (YMM/ZMM/opmask), CPUID.0Dh offsets
//   +user_size    `FP_XSTATE_MAGIC2` trailer (4 bytes)

/// Linux `FP_XSTATE_MAGIC1` — `sw_reserved.magic1` when an xstate (not a
/// bare FXSAVE) image follows. ASCII "SXPF".
pub const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
/// Linux `FP_XSTATE_MAGIC2` — trailer word proving the extended area was
/// actually copied, not just the legacy 512 bytes. ASCII "EXPF".
pub const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
/// `FP_XSTATE_MAGIC2_SIZE` = `sizeof(FP_XSTATE_MAGIC2)`.
pub const FP_XSTATE_MAGIC2_SIZE: usize = core::mem::size_of::<u32>();

/// `sizeof(struct fxregs_state)` — the legacy FXSAVE image.
pub const FXSAVE_BYTES: usize = 512;
/// `sizeof(struct xstate_header)`.
pub const XSTATE_HEADER_BYTES: usize = 64;
/// Linux `min_xstate_size` in `check_xstate_in_sigframe`: an xstate image
/// cannot be smaller than the legacy area plus its header.
pub const MIN_XSTATE_SIZE: usize = FXSAVE_BYTES + XSTATE_HEADER_BYTES;

/// Offset of `_fpx_sw_bytes` inside the legacy area (Linux: "Bytes 464..511
/// ... are reserved for SW usage").
pub const SW_RESERVED_OFF: usize = 464;
/// `sizeof(struct _fpx_sw_bytes)`.
pub const SW_RESERVED_BYTES: usize = 48;
/// Offset of the xstate `_header` — immediately after the legacy area.
pub const XSTATE_HEADER_OFF: usize = FXSAVE_BYTES;
/// `_header.xfeatures` (XSTATE_BV).
pub const XFEATURES_OFF: usize = XSTATE_HEADER_OFF;
/// `_header.xcomp_bv`. Userspace images are ALWAYS uncompacted, so a
/// non-zero value here is a forgery (and would #GP `xrstor64`).
pub const XCOMP_BV_OFF: usize = XSTATE_HEADER_OFF + 8;
/// First of the 48 header bytes Linux requires to be zero.
pub const HDR_RESERVED_OFF: usize = XSTATE_HEADER_OFF + 16;
/// Count of those bytes (`BUILD_BUG_ON(sizeof(hdr->reserved) != 48)`).
pub const HDR_RESERVED_BYTES: usize = 48;
/// `mxcsr` inside the FXSAVE image.
pub const MXCSR_OFF: usize = 24;
/// `mxcsr_mask` inside the FXSAVE image.
// Read by `fpu::mxcsr_mask_init`'s `fxsave` probe, which is kernel-target-only.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub const MXCSR_MASK_OFF: usize = 28;

/// Linux `XFEATURE_MASK_FPSSE` = x87 | SSE. Always forced present in a
/// frame's XSTATE_BV so a legacy app that rewrites only the FXSAVE bytes
/// still has them picked up (`save_xstate_epilog`).
pub const XFEATURE_MASK_FPSSE: u64 = 0b11;
/// Linux `XFEATURE_MASK_YMM`, joined with FP|SSE to decide when MXCSR is
/// live and must be range-checked (`copy_uabi_to_xstate`).
pub const XFEATURE_MASK_YMM: u64 = 1 << 2;
/// `XFEATURE_PKRU` — the four-byte PKRU component whose standard-format
/// offset is supplied by CPUID.0Dh:9.
pub const XFEATURE_PKRU: u64 = 1 << 9;
/// Fallback `mxcsr_feature_mask` when the CPU reports `mxcsr_mask == 0`
/// (`arch/x86/kernel/fpu/init.c` `fpu__init_system_mxcsr`).
// Consumed by `fpu::mxcsr_mask_init`, which is kernel-target-only.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub const MXCSR_DEFAULT_FEATURE_MASK: u32 = 0x0000_ffbf;

/// XSAVE demands a 64-byte-aligned area; `xsave64`/`xrstor64` #GP below it.
pub const XSTATE_ALIGN: u64 = 64;

/// Linux `struct _fpx_sw_bytes` (`sigcontext.h:40-70`) — the SW-reserved
/// footer at offset 464 of the legacy area, describing what follows it.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct FpxSwBytes {
    pub magic1: u32,
    pub extended_size: u32,
    pub xfeatures: u64,
    pub xstate_size: u32,
    pub padding: [u32; 7],
}

const _: () = {
    assert!(core::mem::size_of::<FpxSwBytes>() == SW_RESERVED_BYTES);
    assert!(SW_RESERVED_OFF + SW_RESERVED_BYTES == FXSAVE_BYTES);
    assert!(HDR_RESERVED_OFF + HDR_RESERVED_BYTES == FXSAVE_BYTES + XSTATE_HEADER_BYTES);
};

/// Linux `fpstate->user_size`: bytes of XSAVE image the kernel writes.
/// `xsave_area` is `fpu::xsave_area_bytes()` — 0 on the FXSAVE fallback,
/// where the image is exactly the 512-byte legacy area.
/// # C: O(1)
pub fn user_xstate_size(xsave_area: usize) -> usize {
    if xsave_area != 0 { xsave_area } else { FXSAVE_BYTES }
}

/// Linux `xstate_sigframe_size()`: the user_size plus the `MAGIC2` trailer
/// when XSAVE is in use. This is the byte count `fpu__alloc_mathframe`
/// carves out of the user stack.
/// # C: O(1)
pub fn math_frame_size(xsave_area: usize) -> usize {
    let size = user_xstate_size(xsave_area);
    if xsave_area != 0 { size + FP_XSTATE_MAGIC2_SIZE } else { size }
}

/// Linux `init_sigframe_size()` → `get_sigframe_size()`, the value exported
/// as `AT_MINSIGSTKSZ`. `uctxt` is `sizeof(struct rt_sigframe)`.
/// `MAX_FRAME_PADDING` = 15 and `MAX_XSAVE_PADDING` = 63 are the worst-case
/// alignment slacks for the 16-byte frame and the 64-byte xsave area.
/// # C: O(1)
pub fn min_sigstksz(uctxt: usize, xsave_area: usize) -> usize {
    const MAX_FRAME_PADDING: usize = 15;
    const MAX_XSAVE_PADDING: usize = 63;
    let raw = uctxt + MAX_FRAME_PADDING + math_frame_size(xsave_area) + MAX_XSAVE_PADDING;
    (raw + 15) & !15
}

/// Linux `save_sw_bytes()` — the footer describing the image just written.
/// # C: O(1)
pub fn sw_bytes(xsave_area: usize, xcr0: u64) -> FpxSwBytes {
    let user_size = user_xstate_size(xsave_area);
    FpxSwBytes {
        magic1: FP_XSTATE_MAGIC1,
        extended_size: (user_size + FP_XSTATE_MAGIC2_SIZE) as u32,
        // Linux: `fpstate->user_xfeatures`. Our XCR0 IS the user component
        // set — `xstate_init` never enables a supervisor component.
        xfeatures: xcr0,
        xstate_size: user_size as u32,
    padding: [0; 7],
    }
}

/// Stamp the SW footer, the `MAGIC2` trailer and the forced FP|SSE bits into
/// a freshly-XSAVEd image — Linux `save_xstate_epilog()`. `img` is the whole
/// math frame (`math_frame_size(xsave_area)` bytes). Returns false when the
/// buffer is too short for the image it claims to hold.
/// # C: O(n) in the 48-byte footer
pub fn write_epilog(img: &mut [u8], xsave_area: usize, xcr0: u64) -> bool {
    let user_size = user_xstate_size(xsave_area);
    if img.len() < math_frame_size(xsave_area) { return false; }
    let sw = sw_bytes(xsave_area, xcr0);
    // SAFETY: FpxSwBytes is repr(C) plain-old-data (u32/u64 only, no padding — asserted 48 bytes above), so its bytes are always initialised and a byte view cannot observe uninit memory.
    let sw_raw: &[u8; SW_RESERVED_BYTES] = unsafe { &*(&sw as *const FpxSwBytes as *const [u8; SW_RESERVED_BYTES]) };
    img[SW_RESERVED_OFF..SW_RESERVED_OFF + SW_RESERVED_BYTES].copy_from_slice(sw_raw);
    if xsave_area == 0 { return true; }
    img[user_size..user_size + FP_XSTATE_MAGIC2_SIZE]
        .copy_from_slice(&FP_XSTATE_MAGIC2.to_le_bytes());
    // Linux `set_xfeature_in_sigframe(x, XFEATURE_MASK_FPSSE)`: XSAVE leaves
    // XSTATE_BV bits clear for components still in their init state, but the
    // UABI promises FP|SSE are always present in the frame.
    let bv = read_u64(img, XFEATURES_OFF) | XFEATURE_MASK_FPSSE;
    img[XFEATURES_OFF..XFEATURES_OFF + 8].copy_from_slice(&bv.to_le_bytes());
    true
}

/// Outcome of Linux `check_xstate_in_sigframe()`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SwCheck {
    /// A well-formed xstate image of `xstate_size` bytes claiming
    /// `xfeatures`; restore the extended components from it.
    Xstate { xstate_size: usize, xfeatures: u64 },
    /// Linux's `setfx:` arm. A bad magic1, an out-of-range `xstate_size`, or
    /// a missing `MAGIC2` trailer does NOT fail the sigreturn — Linux
    /// silently degrades to restoring the 512-byte legacy image and
    /// re-initialising every other component.
    FxOnly,
}

/// Linux `check_xstate_in_sigframe()` (`fpu/signal.c:27-64`), as a pure
/// decision over the two words the caller fetched from user memory.
/// `kernel_user_size` is our own `fpstate->user_size` — the user cannot
/// claim a larger image than the kernel is prepared to consume.
///
/// Note the shape: EVERY malformed header lands on `FxOnly`, not an error.
/// Only a FAULT reading the footer or the trailer rejects, and that is the
/// caller's business (it owns the user access).
/// # C: O(1)
pub fn check_xstate_in_sigframe(sw: &FpxSwBytes, magic2: u32, kernel_user_size: usize) -> SwCheck {
    if sw.magic1 != FP_XSTATE_MAGIC1
        || (sw.xstate_size as usize) < MIN_XSTATE_SIZE
        || (sw.xstate_size as usize) > kernel_user_size
        || sw.xstate_size > sw.extended_size
        || magic2 != FP_XSTATE_MAGIC2
    {
        return SwCheck::FxOnly;
    }
    SwCheck::Xstate { xstate_size: sw.xstate_size as usize, xfeatures: sw.xfeatures }
}

/// Linux `validate_user_xstate_header()` (`fpu/xstate.c:431-453`). On the
/// x86_64 fast path Linux lets `XRSTOR` raise #GP on exactly these
/// conditions and treats the #GP as fatal; we copy-then-restore, so the
/// check has to happen HERE or the `xrstor64` in `fpu_restore` faults inside
/// the kernel with no handler.
/// # C: O(1)
pub fn header_is_valid(img: &[u8], allowed_xfeatures: u64) -> bool {
    if img.len() < MIN_XSTATE_SIZE { return false; }
    // No unknown or supervisor features may be set.
    if read_u64(img, XFEATURES_OFF) & !allowed_xfeatures != 0 { return false; }
    // Userspace must use the uncompacted format.
    if read_u64(img, XCOMP_BV_OFF) != 0 { return false; }
    // No reserved bits may be set.
    img[HDR_RESERVED_OFF..HDR_RESERVED_OFF + HDR_RESERVED_BYTES].iter().all(|b| *b == 0)
}

/// Linux's x86_64 arm of the MXCSR check: "Reject invalid MXCSR values"
/// (`fpu/signal.c:395-398`, `fpu/xstate.c:1343`). 32-bit masks instead; we
/// are 64-bit, so `build_restore_image` invokes this when FP, SSE, or YMM
/// is being restored. A reserved MXCSR bit would then #GP `xrstor64`.
/// # C: O(1)
pub fn mxcsr_is_valid(img: &[u8], feature_mask: u32) -> bool {
    if img.len() < FXSAVE_BYTES { return false; }
    read_u32(img, MXCSR_OFF) & !feature_mask == 0
}

/// Build the image `fpu_restore` will load, from the user's frame bytes —
/// Linux `restore_fpregs_from_user()` plus its `os_xrstor(&init_fpstate,
/// init_bv)` companion, expressed as a buffer transform.
///
/// `user` is what the process supplied, `out` the task's save area. Any
/// component the user did not claim has its XSTATE_BV bit cleared, which is
/// exactly how `xrstor64` re-initialises it — the same end state as Linux's
/// separate `os_xrstor(&init_fpstate, init_bv)`.
///
/// Returns false when the image must be rejected (Linux: #GP from `XRSTOR`
/// → `fpu__clear_user_states` + `SIGSEGV`).
/// # C: O(n) in the image size
pub fn build_restore_image(user: &[u8], out: &mut [u8], check: SwCheck,
                           allowed_xfeatures: u64, mxcsr_mask: u32, xsave: bool) -> bool {
    let legacy = FXSAVE_BYTES;
    if user.len() < legacy || out.len() < legacy { return false; }
    if !xsave {
        // FXSAVE-only CPU: the 512-byte legacy image IS the whole state.
        if !mxcsr_is_valid(user, mxcsr_mask) { return false; }
        out[..legacy].copy_from_slice(&user[..legacy]);
        return true;
    }
    if out.len() < MIN_XSTATE_SIZE { return false; }
    let (size, want) = match check {
        // Linux `setfx:` — FXRSTOR the legacy area, init everything else.
        SwCheck::FxOnly => (MIN_XSTATE_SIZE, XFEATURE_MASK_FPSSE),
        SwCheck::Xstate { xstate_size, xfeatures } => (xstate_size, xfeatures),
    };
    if size > user.len() || size > out.len() { return false; }
    let hdr_bv = match check {
        // Linux FXRSTORs the legacy image, so x87 and SSE come back from it
        // whatever the ignored header said.
        SwCheck::FxOnly => want,
        SwCheck::Xstate { .. } => {
            if !header_is_valid(&user[..size], allowed_xfeatures) { return false; }
            read_u64(user, XFEATURES_OFF)
        }
    };
    // Linux `copy_uabi_to_xstate`: MXCSR is consumed only when the header
    // restores x87, SSE, or YMM. With all three bits clear, XRSTOR
    // initialises those components and ignores the legacy MXCSR field.
    if hdr_bv & (XFEATURE_MASK_FPSSE | XFEATURE_MASK_YMM) != 0
        && !mxcsr_is_valid(user, mxcsr_mask)
    {
        return false;
    }
    out[..legacy].copy_from_slice(&user[..legacy]);
    // Zero from the header on: components the user does not restore must be
    // init, and `xrstor64` reads the header before anything else.
    for b in out[legacy..].iter_mut() { *b = 0; }
    if matches!(check, SwCheck::Xstate { .. }) {
        out[legacy..size].copy_from_slice(&user[legacy..size]);
    }
    // `xrstor64` restores component i from the image when XSTATE_BV[i] and
    // RFBM[i], and INITIALISES it otherwise — so intersecting here reproduces
    // Linux's `xrstor_from_user_sigframe(buf, xrestore)` plus its companion
    // `os_xrstor(&init_fpstate, init_bv)` in a single load. A feature bit the
    // kernel does not offer is dropped, never trusted.
    let bv = hdr_bv & want & allowed_xfeatures;
    out[XFEATURES_OFF..XFEATURES_OFF + 8].copy_from_slice(&bv.to_le_bytes());
    // The header's reserved words came from `user` and were validated zero
    // for the Xstate arm; the FxOnly arm zeroed them above. `xcomp_bv` is
    // covered by the same validation.
    true
}

/// Little-endian u64 at `off`; callers bound-check via the length guards
/// above. # C: O(1)
fn read_u64(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

/// Little-endian u32 at `off`. # C: O(1)
fn read_u32(b: &[u8], off: usize) -> u32 {
    let mut v = [0u8; 4];
    v.copy_from_slice(&b[off..off + 4]);
    u32::from_le_bytes(v)
}

/// Architectural x87 control word after `FNINIT` — every exception masked.
/// A zeroed FXSAVE image would restore FCW = 0 instead.
pub const FCW_INIT: u16 = 0x037f;
/// Architectural MXCSR after a reset — every SSE exception MASKED. Restoring
/// a zeroed MXCSR unmasks them, so the first inexact/denormal op in userspace
/// raises #XM → a spurious SIGFPE.
pub const MXCSR_INIT: u32 = 0x1f80;
/// `FCW` offset inside the FXSAVE image.
pub const FCW_OFF: usize = 0;

/// Linux `fpu__clear_user_states()` expressed as a buffer: the image that
/// resets every user component to `init_fpstate`.
///
/// Under XSAVE an all-zero header (XSTATE_BV = 0) is already exactly that —
/// `xrstor64` initialises every component whose bit is clear, which gives
/// FCW = 0x37F, MXCSR = 0x1F80 and zeroed YMM/ZMM. Under the FXSAVE fallback
/// there is no header to say so, so the two control words must be written.
/// # C: O(n) in the image size
pub fn write_init_image(img: &mut [u8], xsave: bool) {
    for b in img.iter_mut() { *b = 0; }
    if xsave || img.len() < FXSAVE_BYTES { return; }
    img[FCW_OFF..FCW_OFF + 2].copy_from_slice(&FCW_INIT.to_le_bytes());
    img[MXCSR_OFF..MXCSR_OFF + 4].copy_from_slice(&MXCSR_INIT.to_le_bytes());
}

/// The `MAGIC2` trailer word at the user-claimed `xstate_size`. Out of range
/// yields 0, which is not `FP_XSTATE_MAGIC2` and therefore degrades to
/// fx-only — the same answer Linux reaches, since `check_xstate_in_sigframe`
/// has already rejected an oversized `xstate_size` before it reads here.
/// # C: O(1)
pub fn read_trailer(img: &[u8], off: usize) -> u32 {
    match off.checked_add(FP_XSTATE_MAGIC2_SIZE) {
        Some(end) if end <= img.len() => read_u32(img, off),
        _ => 0,
    }
}

/// Decode the SW footer out of a legacy image the caller copied in.
/// # C: O(1)
pub fn read_sw_bytes(img: &[u8]) -> Option<FpxSwBytes> {
    if img.len() < FXSAVE_BYTES { return None; }
    Some(FpxSwBytes {
        magic1:        read_u32(img, SW_RESERVED_OFF),
        extended_size: read_u32(img, SW_RESERVED_OFF + 4),
        xfeatures:     read_u64(img, SW_RESERVED_OFF + 8),
        xstate_size:   read_u32(img, SW_RESERVED_OFF + 16),
        padding:       [0; 7],
    })
}

#[cfg(test)]
mod tests;
