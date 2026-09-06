//! Callee-saved FP/SIMD state inside each architecture's saved FPU image, for
//! the user-mode callback continuation. Pure byte layout so the contract is
//! hosted-testable; the hardware save/restore around it is the kernel owner's.
use sched::nt_callback::FP_BYTES;

/// x87 control word offset inside the FXSAVE/XSAVE legacy region.
pub const X86_FCW_OFF: usize = 0;
/// MXCSR offset inside the legacy region.
pub const X86_MXCSR_OFF: usize = 24;
/// xmm0 offset inside the legacy region; xmm`n` follows at 16-byte stride.
pub const X86_XMM_OFF: usize = 160;
/// First callee-saved xmm register in the Windows x64 ABI.
pub const X86_FIRST_CALLEE_XMM: usize = 6;
/// Callee-saved xmm registers: xmm6..=xmm15.
pub const X86_CALLEE_XMM_COUNT: usize = 10;
/// XSAVE header offset; bit 0 = x87, bit 1 = SSE in `XSTATE_BV`.
pub const X86_XSTATE_BV_OFF: usize = 512;
pub const X86_XSTATE_BV_X87_SSE: u64 = 0b11;
const X86_XMM_BYTES: usize = X86_CALLEE_XMM_COUNT * 16;
const X86_SAVED_MXCSR: usize = X86_XMM_BYTES;
const X86_SAVED_FCW: usize = X86_SAVED_MXCSR + 4;
/// Legacy region bytes the x86 extract reads and patch writes.
pub const X86_IMAGE_BYTES: usize = X86_XMM_OFF + 16 * 16;

/// First callee-saved SIMD register in the AArch64 PCS (low 64 bits).
pub const ARM_FIRST_CALLEE_V: usize = 8;
/// Callee-saved SIMD registers: v8..=v15.
pub const ARM_CALLEE_V_COUNT: usize = 8;
pub const ARM_FPCR_OFF: usize = 0x200;
pub const ARM_FPSR_OFF: usize = 0x204;
const ARM_V_BYTES: usize = ARM_CALLEE_V_COUNT * 16;
const ARM_SAVED_FPCR: usize = ARM_V_BYTES;
const ARM_SAVED_FPSR: usize = ARM_SAVED_FPCR + 4;
/// Image bytes the AArch64 extract reads and patch writes.
pub const ARM_IMAGE_BYTES: usize = ARM_FPSR_OFF + 4;

const _: () = assert!(X86_SAVED_FCW + 2 <= FP_BYTES);
const _: () = assert!(ARM_SAVED_FPSR + 4 <= FP_BYTES);

/// Copy the x86-64 callee-saved FP set out of a saved image. # C: O(1)
pub fn x86_extract(image: &[u8], out: &mut [u8; FP_BYTES]) -> bool {
    if image.len() < X86_IMAGE_BYTES { return false; }
    let xmm = X86_XMM_OFF + X86_FIRST_CALLEE_XMM * 16;
    out[..X86_XMM_BYTES].copy_from_slice(&image[xmm..xmm + X86_XMM_BYTES]);
    out[X86_SAVED_MXCSR..X86_SAVED_MXCSR + 4].copy_from_slice(&image[X86_MXCSR_OFF..X86_MXCSR_OFF + 4]);
    out[X86_SAVED_FCW..X86_SAVED_FCW + 2].copy_from_slice(&image[X86_FCW_OFF..X86_FCW_OFF + 2]);
    true
}

/// Write the x86-64 callee-saved FP set back into a freshly saved image,
/// marking x87+SSE present in the XSAVE header when the image carries one so
/// the restore loads the legacy area instead of re-initialising it. # C: O(1)
pub fn x86_patch(image: &mut [u8], saved: &[u8; FP_BYTES], xsave: bool) -> bool {
    if image.len() < X86_IMAGE_BYTES || (xsave && image.len() < X86_XSTATE_BV_OFF + 8) { return false; }
    let xmm = X86_XMM_OFF + X86_FIRST_CALLEE_XMM * 16;
    image[xmm..xmm + X86_XMM_BYTES].copy_from_slice(&saved[..X86_XMM_BYTES]);
    image[X86_MXCSR_OFF..X86_MXCSR_OFF + 4].copy_from_slice(&saved[X86_SAVED_MXCSR..X86_SAVED_MXCSR + 4]);
    image[X86_FCW_OFF..X86_FCW_OFF + 2].copy_from_slice(&saved[X86_SAVED_FCW..X86_SAVED_FCW + 2]);
    if xsave {
        let bv = u64::from_le_bytes(image[X86_XSTATE_BV_OFF..X86_XSTATE_BV_OFF + 8].try_into().unwrap()) | X86_XSTATE_BV_X87_SSE;
        image[X86_XSTATE_BV_OFF..X86_XSTATE_BV_OFF + 8].copy_from_slice(&bv.to_le_bytes());
    }
    true
}

/// Copy the AArch64 callee-saved FP set out of a saved image. # C: O(1)
pub fn arm_extract(image: &[u8], out: &mut [u8; FP_BYTES]) -> bool {
    if image.len() < ARM_IMAGE_BYTES { return false; }
    let v = ARM_FIRST_CALLEE_V * 16;
    out[..ARM_V_BYTES].copy_from_slice(&image[v..v + ARM_V_BYTES]);
    out[ARM_SAVED_FPCR..ARM_SAVED_FPCR + 4].copy_from_slice(&image[ARM_FPCR_OFF..ARM_FPCR_OFF + 4]);
    out[ARM_SAVED_FPSR..ARM_SAVED_FPSR + 4].copy_from_slice(&image[ARM_FPSR_OFF..ARM_FPSR_OFF + 4]);
    true
}

/// Write the AArch64 callee-saved FP set back into a freshly saved image. # C: O(1)
pub fn arm_patch(image: &mut [u8], saved: &[u8; FP_BYTES]) -> bool {
    if image.len() < ARM_IMAGE_BYTES { return false; }
    let v = ARM_FIRST_CALLEE_V * 16;
    image[v..v + ARM_V_BYTES].copy_from_slice(&saved[..ARM_V_BYTES]);
    image[ARM_FPCR_OFF..ARM_FPCR_OFF + 4].copy_from_slice(&saved[ARM_SAVED_FPCR..ARM_SAVED_FPCR + 4]);
    image[ARM_FPSR_OFF..ARM_FPSR_OFF + 4].copy_from_slice(&saved[ARM_SAVED_FPSR..ARM_SAVED_FPSR + 4]);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numbered(len: usize) -> alloc::vec::Vec<u8> { (0..len).map(|i| (i * 7 % 251) as u8).collect() }

    #[test]
    fn x86_round_trip_restores_only_the_callee_saved_set() {
        let original = numbered(1024);
        let mut saved = [0u8; FP_BYTES];
        assert!(x86_extract(&original, &mut saved));
        let mut clobbered = alloc::vec![0xeeu8; 1024];
        assert!(x86_patch(&mut clobbered, &saved, true));
        for reg in X86_FIRST_CALLEE_XMM..X86_FIRST_CALLEE_XMM + X86_CALLEE_XMM_COUNT {
            let at = X86_XMM_OFF + reg * 16;
            assert_eq!(&clobbered[at..at + 16], &original[at..at + 16], "xmm{reg}");
        }
        for reg in 0..X86_FIRST_CALLEE_XMM {
            let at = X86_XMM_OFF + reg * 16;
            assert!(clobbered[at..at + 16].iter().all(|b| *b == 0xee), "xmm{reg} is caller-saved");
        }
        assert_eq!(&clobbered[X86_MXCSR_OFF..X86_MXCSR_OFF + 4], &original[X86_MXCSR_OFF..X86_MXCSR_OFF + 4]);
        assert_eq!(&clobbered[X86_FCW_OFF..X86_FCW_OFF + 2], &original[X86_FCW_OFF..X86_FCW_OFF + 2]);
        let bv = u64::from_le_bytes(clobbered[X86_XSTATE_BV_OFF..X86_XSTATE_BV_OFF + 8].try_into().unwrap());
        assert_eq!(bv & X86_XSTATE_BV_X87_SSE, X86_XSTATE_BV_X87_SSE);
    }

    #[test]
    fn x86_fxsave_only_image_leaves_no_header_and_short_images_are_refused() {
        let mut image = numbered(512);
        let saved = [1u8; FP_BYTES];
        assert!(x86_patch(&mut image, &saved, false));
        assert!(!x86_patch(&mut image, &saved, true));
        let mut out = [0u8; FP_BYTES];
        assert!(!x86_extract(&image[..X86_IMAGE_BYTES - 1], &mut out));
    }

    #[test]
    fn arm_round_trip_restores_v8_to_v15_and_control_only() {
        let original = numbered(0x210);
        let mut saved = [0u8; FP_BYTES];
        assert!(arm_extract(&original, &mut saved));
        let mut clobbered = alloc::vec![0xeeu8; 0x210];
        assert!(arm_patch(&mut clobbered, &saved));
        for reg in ARM_FIRST_CALLEE_V..ARM_FIRST_CALLEE_V + ARM_CALLEE_V_COUNT {
            assert_eq!(&clobbered[reg * 16..reg * 16 + 16], &original[reg * 16..reg * 16 + 16], "v{reg}");
        }
        assert!(clobbered[..ARM_FIRST_CALLEE_V * 16].iter().all(|b| *b == 0xee));
        assert!(clobbered[16 * 16..ARM_FPCR_OFF].iter().all(|b| *b == 0xee));
        assert_eq!(&clobbered[ARM_FPCR_OFF..ARM_FPSR_OFF + 4], &original[ARM_FPCR_OFF..ARM_FPSR_OFF + 4]);
        assert!(!arm_extract(&original[..ARM_IMAGE_BYTES - 1], &mut saved));
    }
}
