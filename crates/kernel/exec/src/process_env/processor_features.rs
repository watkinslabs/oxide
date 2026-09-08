//! The processor-feature vector the shared read-only page publishes.
//!
//! A running image asks whether a feature is present by indexing this byte
//! array directly, so an unpublished vector reads as "no feature present" for
//! every query — including the ones the architecture guarantees. The mapping
//! from architectural identification words to feature slots is built here,
//! ungated, so it is testable without a target build; the words themselves are
//! read by the architecture-specific collector below.

/// Slot count of the published vector.
pub const PROCESSOR_FEATURE_MAX: usize = 64;

/// Feature slots, by the published numbering.
pub const PF_COMPARE_EXCHANGE_DOUBLE: usize = 2;
pub const PF_MMX_INSTRUCTIONS_AVAILABLE: usize = 3;
pub const PF_XMMI_INSTRUCTIONS_AVAILABLE: usize = 6;
pub const PF_3DNOW_INSTRUCTIONS_AVAILABLE: usize = 7;
pub const PF_RDTSC_INSTRUCTION_AVAILABLE: usize = 8;
pub const PF_PAE_ENABLED: usize = 9;
pub const PF_XMMI64_INSTRUCTIONS_AVAILABLE: usize = 10;
pub const PF_SSE_DAZ_MODE_AVAILABLE: usize = 11;
pub const PF_NX_ENABLED: usize = 12;
pub const PF_SSE3_INSTRUCTIONS_AVAILABLE: usize = 13;
pub const PF_COMPARE_EXCHANGE128: usize = 14;
pub const PF_XSAVE_ENABLED: usize = 17;
pub const PF_ARM_VFP_32_REGISTERS_AVAILABLE: usize = 18;
pub const PF_ARM_NEON_INSTRUCTIONS_AVAILABLE: usize = 19;
pub const PF_VIRT_FIRMWARE_ENABLED: usize = 21;
pub const PF_RDWRFSGSBASE_AVAILABLE: usize = 22;
pub const PF_FASTFAIL_AVAILABLE: usize = 23;
pub const PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE: usize = 24;
pub const PF_ARM_64BIT_LOADSTORE_ATOMIC: usize = 25;
pub const PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE: usize = 27;
pub const PF_RDRAND_INSTRUCTION_AVAILABLE: usize = 28;
pub const PF_ARM_V8_INSTRUCTIONS_AVAILABLE: usize = 29;
pub const PF_RDTSCP_INSTRUCTION_AVAILABLE: usize = 32;
pub const PF_RDPID_INSTRUCTION_AVAILABLE: usize = 33;
pub const PF_MONITORX_INSTRUCTION_AVAILABLE: usize = 35;
pub const PF_SSSE3_INSTRUCTIONS_AVAILABLE: usize = 36;
pub const PF_SSE4_1_INSTRUCTIONS_AVAILABLE: usize = 37;
pub const PF_SSE4_2_INSTRUCTIONS_AVAILABLE: usize = 38;
pub const PF_AVX_INSTRUCTIONS_AVAILABLE: usize = 39;
pub const PF_AVX2_INSTRUCTIONS_AVAILABLE: usize = 40;
pub const PF_AVX512F_INSTRUCTIONS_AVAILABLE: usize = 41;
pub const PF_ERMS_AVAILABLE: usize = 42;
pub const PF_BMI2_INSTRUCTIONS_AVAILABLE: usize = 60;
pub const PF_MOVDIR64B_INSTRUCTION_AVAILABLE: usize = 61;

/// The architectural identification words the mapping reads.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct X86Identification {
    pub max_leaf: u32,
    pub max_extended_leaf: u32,
    pub leaf1_ecx: u32,
    pub leaf1_edx: u32,
    pub leaf7_ebx: u32,
    pub leaf7_ecx: u32,
    pub extended1_ecx: u32,
    pub extended1_edx: u32,
    /// The denormals-are-zero control bit is writable in the SSE control word.
    pub denormals_are_zero: bool,
}

const fn bit(word: u32, index: u32) -> bool { word & (1 << index) != 0 }

/// Map x86-64 identification words onto the published feature vector.
///
/// Two slots are set unconditionally: a compare-exchange of a double word and
/// the fail-fast entry are architectural on every processor that can run this
/// image.
/// # C: O(1)
pub fn x86_features(id: &X86Identification) -> [u8; PROCESSOR_FEATURE_MAX] {
    let mut out = [0u8; PROCESSOR_FEATURE_MAX];
    let mut set = |slot: usize, value: bool| out[slot] = value as u8;
    set(PF_FASTFAIL_AVAILABLE, true);
    set(PF_COMPARE_EXCHANGE_DOUBLE, true);
    if id.max_leaf >= 1 {
        set(PF_RDTSC_INSTRUCTION_AVAILABLE, bit(id.leaf1_edx, 4));
        set(PF_PAE_ENABLED, bit(id.leaf1_edx, 6));
        set(PF_MMX_INSTRUCTIONS_AVAILABLE, bit(id.leaf1_edx, 23));
        set(PF_XMMI_INSTRUCTIONS_AVAILABLE, bit(id.leaf1_edx, 24) && bit(id.leaf1_edx, 25));
        set(PF_XMMI64_INSTRUCTIONS_AVAILABLE, bit(id.leaf1_edx, 26));
        set(PF_SSE3_INSTRUCTIONS_AVAILABLE, bit(id.leaf1_ecx, 0));
        set(PF_VIRT_FIRMWARE_ENABLED, bit(id.leaf1_ecx, 5));
        set(PF_SSSE3_INSTRUCTIONS_AVAILABLE, bit(id.leaf1_ecx, 9));
        set(PF_COMPARE_EXCHANGE128, bit(id.leaf1_ecx, 13));
        set(PF_SSE4_1_INSTRUCTIONS_AVAILABLE, bit(id.leaf1_ecx, 19));
        set(PF_SSE4_2_INSTRUCTIONS_AVAILABLE, bit(id.leaf1_ecx, 20));
        set(PF_XSAVE_ENABLED, bit(id.leaf1_ecx, 27));
        set(PF_AVX_INSTRUCTIONS_AVAILABLE, bit(id.leaf1_ecx, 28));
        set(PF_RDRAND_INSTRUCTION_AVAILABLE, bit(id.leaf1_ecx, 30));
        set(PF_SSE_DAZ_MODE_AVAILABLE, bit(id.leaf1_edx, 26) && id.denormals_are_zero);
    }
    if id.max_leaf >= 7 {
        set(PF_RDWRFSGSBASE_AVAILABLE, bit(id.leaf7_ebx, 0));
        set(PF_AVX2_INSTRUCTIONS_AVAILABLE, bit(id.leaf7_ebx, 5));
        set(PF_BMI2_INSTRUCTIONS_AVAILABLE, bit(id.leaf7_ebx, 8));
        set(PF_ERMS_AVAILABLE, bit(id.leaf7_ebx, 9));
        set(PF_AVX512F_INSTRUCTIONS_AVAILABLE, bit(id.leaf7_ebx, 16));
        set(PF_RDPID_INSTRUCTION_AVAILABLE, bit(id.leaf7_ecx, 22));
        set(PF_MOVDIR64B_INSTRUCTION_AVAILABLE, bit(id.leaf7_ecx, 28));
    }
    if id.max_extended_leaf >= 0x8000_0001 {
        set(PF_MONITORX_INSTRUCTION_AVAILABLE, bit(id.extended1_ecx, 29));
        set(PF_NX_ENABLED, bit(id.extended1_edx, 20));
        set(PF_RDTSCP_INSTRUCTION_AVAILABLE, bit(id.extended1_edx, 27));
        set(PF_3DNOW_INSTRUCTIONS_AVAILABLE, bit(id.extended1_edx, 31));
        if bit(id.extended1_ecx, 2) { set(PF_VIRT_FIRMWARE_ENABLED, true); }
    }
    out
}

/// The vector for a 64-bit ARM image: the slots the architecture makes
/// mandatory, and nothing optional. Optional extensions stay clear until the
/// collector reports them.
/// # C: O(1)
pub fn aarch64_features() -> [u8; PROCESSOR_FEATURE_MAX] {
    let mut out = [0u8; PROCESSOR_FEATURE_MAX];
    for slot in [PF_FASTFAIL_AVAILABLE, PF_COMPARE_EXCHANGE_DOUBLE, PF_NX_ENABLED,
        PF_ARM_VFP_32_REGISTERS_AVAILABLE, PF_ARM_NEON_INSTRUCTIONS_AVAILABLE,
        PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE, PF_ARM_64BIT_LOADSTORE_ATOMIC,
        PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE, PF_ARM_V8_INSTRUCTIONS_AVAILABLE] { out[slot] = 1; }
    out
}

#[cfg(target_arch = "x86_64")]
/// Read this processor's identification words. # C: O(1)
pub fn local() -> [u8; PROCESSOR_FEATURE_MAX] {
    use core::arch::x86_64::__cpuid_count;
    // SAFETY: `__cpuid_count` executes CPUID, which is unprivileged, has no
    // memory operands and no side effects beyond the returned registers; every
    // leaf below is guarded by the maximum-leaf value CPUID itself reports.
    let (basic, extended) = unsafe { (__cpuid_count(0, 0), __cpuid_count(0x8000_0000, 0)) };
    let mut id = X86Identification { max_leaf: basic.eax, max_extended_leaf: extended.eax, ..Default::default() };
    if id.max_leaf >= 1 {
        // SAFETY: CPUID leaf 1 is reported available by the maximum-leaf value
        // read above; the instruction is unprivileged and writes no memory.
        let leaf1 = unsafe { __cpuid_count(1, 0) };
        id.leaf1_ecx = leaf1.ecx; id.leaf1_edx = leaf1.edx;
        id.denormals_are_zero = denormals_are_zero();
    }
    if id.max_leaf >= 7 {
        // SAFETY: CPUID leaf 7 subleaf 0 is reported available by the
        // maximum-leaf value read above; the instruction writes no memory.
        let leaf7 = unsafe { __cpuid_count(7, 0) };
        id.leaf7_ebx = leaf7.ebx; id.leaf7_ecx = leaf7.ecx;
    }
    if id.max_extended_leaf >= 0x8000_0001 {
        // SAFETY: extended leaf 1 is reported available by the maximum
        // extended-leaf value read above; the instruction writes no memory.
        let leaf = unsafe { __cpuid_count(0x8000_0001, 0) };
        id.extended1_ecx = leaf.ecx; id.extended1_edx = leaf.edx;
    }
    x86_features(&id)
}

#[cfg(target_arch = "x86_64")]
/// The denormals-are-zero control bit is writable exactly when the saved
/// control-word mask says it is. # C: O(1)
fn denormals_are_zero() -> bool {
    const MXCSR_MASK_OFFSET: usize = 28;
    const DENORMALS_ARE_ZERO_BIT: u32 = 1 << 6;
    #[repr(align(16))]
    struct SaveArea([u8; 512]);
    let mut area = SaveArea([0u8; 512]);
    // SAFETY: `_fxsave` writes 512 bytes to the 16-byte aligned local
    // `SaveArea` and only reads processor state; no other state is touched.
    unsafe { core::arch::x86_64::_fxsave(area.0.as_mut_ptr()) };
    let mask = u32::from_le_bytes(area.0[MXCSR_MASK_OFFSET..MXCSR_MASK_OFFSET + 4].try_into().unwrap_or([0; 4]));
    mask & DENORMALS_ARE_ZERO_BIT != 0
}

#[cfg(not(target_arch = "x86_64"))]
/// Read this processor's published feature vector. # C: O(1)
pub fn local() -> [u8; PROCESSOR_FEATURE_MAX] { aarch64_features() }

#[cfg(test)]
#[path = "tests/processor_features.rs"]
mod tests;
