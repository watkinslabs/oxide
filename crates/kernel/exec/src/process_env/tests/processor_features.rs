use super::*;

// Identification words for a processor with every mapped feature reported.
fn everything() -> X86Identification {
    X86Identification { max_leaf: 7, max_extended_leaf: 0x8000_0001,
        leaf1_ecx: u32::MAX, leaf1_edx: u32::MAX, leaf7_ebx: u32::MAX, leaf7_ecx: u32::MAX,
        extended1_ecx: u32::MAX, extended1_edx: u32::MAX, denormals_are_zero: true }
}

#[test]
fn the_architectural_slots_are_set_even_when_identification_reports_nothing() {
    let out = x86_features(&X86Identification::default());
    assert_eq!(out[PF_FASTFAIL_AVAILABLE], 1);
    assert_eq!(out[PF_COMPARE_EXCHANGE_DOUBLE], 1);
    // A zero maximum leaf means no identification word may be believed.
    assert_eq!(out[PF_XMMI_INSTRUCTIONS_AVAILABLE], 0);
    assert_eq!(out[PF_NX_ENABLED], 0);
}

#[test]
fn every_mapped_slot_reads_its_own_identification_bit() {
    let all = x86_features(&everything());
    for (slot, id) in [
        (PF_RDTSC_INSTRUCTION_AVAILABLE, X86Identification { leaf1_edx: 1 << 4, ..base() }),
        (PF_PAE_ENABLED, X86Identification { leaf1_edx: 1 << 6, ..base() }),
        (PF_MMX_INSTRUCTIONS_AVAILABLE, X86Identification { leaf1_edx: 1 << 23, ..base() }),
        (PF_XMMI_INSTRUCTIONS_AVAILABLE, X86Identification { leaf1_edx: (1 << 24) | (1 << 25), ..base() }),
        (PF_XMMI64_INSTRUCTIONS_AVAILABLE, X86Identification { leaf1_edx: 1 << 26, ..base() }),
        (PF_SSE3_INSTRUCTIONS_AVAILABLE, X86Identification { leaf1_ecx: 1, ..base() }),
        (PF_SSSE3_INSTRUCTIONS_AVAILABLE, X86Identification { leaf1_ecx: 1 << 9, ..base() }),
        (PF_COMPARE_EXCHANGE128, X86Identification { leaf1_ecx: 1 << 13, ..base() }),
        (PF_SSE4_1_INSTRUCTIONS_AVAILABLE, X86Identification { leaf1_ecx: 1 << 19, ..base() }),
        (PF_SSE4_2_INSTRUCTIONS_AVAILABLE, X86Identification { leaf1_ecx: 1 << 20, ..base() }),
        (PF_XSAVE_ENABLED, X86Identification { leaf1_ecx: 1 << 27, ..base() }),
        (PF_AVX_INSTRUCTIONS_AVAILABLE, X86Identification { leaf1_ecx: 1 << 28, ..base() }),
        (PF_RDRAND_INSTRUCTION_AVAILABLE, X86Identification { leaf1_ecx: 1 << 30, ..base() }),
        (PF_RDWRFSGSBASE_AVAILABLE, X86Identification { leaf7_ebx: 1, ..base() }),
        (PF_AVX2_INSTRUCTIONS_AVAILABLE, X86Identification { leaf7_ebx: 1 << 5, ..base() }),
        (PF_BMI2_INSTRUCTIONS_AVAILABLE, X86Identification { leaf7_ebx: 1 << 8, ..base() }),
        (PF_ERMS_AVAILABLE, X86Identification { leaf7_ebx: 1 << 9, ..base() }),
        (PF_AVX512F_INSTRUCTIONS_AVAILABLE, X86Identification { leaf7_ebx: 1 << 16, ..base() }),
        (PF_RDPID_INSTRUCTION_AVAILABLE, X86Identification { leaf7_ecx: 1 << 22, ..base() }),
        (PF_MOVDIR64B_INSTRUCTION_AVAILABLE, X86Identification { leaf7_ecx: 1 << 28, ..base() }),
        (PF_MONITORX_INSTRUCTION_AVAILABLE, X86Identification { extended1_ecx: 1 << 29, ..base() }),
        (PF_NX_ENABLED, X86Identification { extended1_edx: 1 << 20, ..base() }),
        (PF_RDTSCP_INSTRUCTION_AVAILABLE, X86Identification { extended1_edx: 1 << 27, ..base() }),
        (PF_3DNOW_INSTRUCTIONS_AVAILABLE, X86Identification { extended1_edx: 1 << 31, ..base() }),
    ] {
        assert_eq!(all[slot], 1, "slot {slot} must be set when everything is reported");
        assert_eq!(x86_features(&id)[slot], 1, "slot {slot} must follow its own bit");
        assert_eq!(x86_features(&base())[slot], 0, "slot {slot} must be clear without its bit");
    }
}

fn base() -> X86Identification {
    X86Identification { max_leaf: 7, max_extended_leaf: 0x8000_0001, ..Default::default() }
}

#[test]
fn the_streaming_extension_slot_needs_both_of_its_identification_bits() {
    assert_eq!(x86_features(&X86Identification { leaf1_edx: 1 << 24, ..base() })[PF_XMMI_INSTRUCTIONS_AVAILABLE], 0);
    assert_eq!(x86_features(&X86Identification { leaf1_edx: 1 << 25, ..base() })[PF_XMMI_INSTRUCTIONS_AVAILABLE], 0);
}

#[test]
fn the_denormal_slot_needs_the_extension_and_the_writable_control_bit() {
    let with_extension = X86Identification { leaf1_edx: 1 << 26, ..base() };
    assert_eq!(x86_features(&with_extension)[PF_SSE_DAZ_MODE_AVAILABLE], 0);
    assert_eq!(x86_features(&X86Identification { denormals_are_zero: true, ..with_extension })[PF_SSE_DAZ_MODE_AVAILABLE], 1);
    assert_eq!(x86_features(&X86Identification { denormals_are_zero: true, ..base() })[PF_SSE_DAZ_MODE_AVAILABLE], 0);
}

#[test]
fn a_leaf_beyond_the_reported_maximum_is_never_believed() {
    let id = X86Identification { max_leaf: 1, max_extended_leaf: 0,
        leaf7_ebx: u32::MAX, leaf7_ecx: u32::MAX, extended1_ecx: u32::MAX, extended1_edx: u32::MAX,
        ..Default::default() };
    let out = x86_features(&id);
    for slot in [PF_AVX2_INSTRUCTIONS_AVAILABLE, PF_ERMS_AVAILABLE, PF_NX_ENABLED,
        PF_RDTSCP_INSTRUCTION_AVAILABLE, PF_MONITORX_INSTRUCTION_AVAILABLE] {
        assert_eq!(out[slot], 0, "slot {slot} read an unreported leaf");
    }
}

#[test]
fn the_virtualization_slot_takes_either_vendor_bit() {
    assert_eq!(x86_features(&X86Identification { leaf1_ecx: 1 << 5, ..base() })[PF_VIRT_FIRMWARE_ENABLED], 1);
    assert_eq!(x86_features(&X86Identification { extended1_ecx: 1 << 2, ..base() })[PF_VIRT_FIRMWARE_ENABLED], 1);
    assert_eq!(x86_features(&base())[PF_VIRT_FIRMWARE_ENABLED], 0);
}

#[test]
fn the_arm_vector_publishes_the_mandatory_slots_and_nothing_optional() {
    let out = aarch64_features();
    for slot in [PF_FASTFAIL_AVAILABLE, PF_COMPARE_EXCHANGE_DOUBLE, PF_NX_ENABLED,
        PF_ARM_VFP_32_REGISTERS_AVAILABLE, PF_ARM_NEON_INSTRUCTIONS_AVAILABLE,
        PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE, PF_ARM_64BIT_LOADSTORE_ATOMIC,
        PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE, PF_ARM_V8_INSTRUCTIONS_AVAILABLE] {
        assert_eq!(out[slot], 1, "mandatory slot {slot} must be published");
    }
    assert_eq!(out.len(), PROCESSOR_FEATURE_MAX);
    assert_eq!(out[PF_XMMI_INSTRUCTIONS_AVAILABLE], 0);
}

#[test]
fn every_published_byte_is_a_boolean() {
    for out in [x86_features(&everything()), x86_features(&base()), aarch64_features()] {
        assert!(out.iter().all(|byte| *byte <= 1));
    }
}

#[test]
fn this_processor_reports_the_extensions_its_own_instruction_set_requires() {
    // The hosted suite runs on the same 64-bit processor family the image
    // targets, where these three are architectural rather than optional.
    let out = local();
    for slot in [PF_XMMI_INSTRUCTIONS_AVAILABLE, PF_XMMI64_INSTRUCTIONS_AVAILABLE,
        PF_COMPARE_EXCHANGE_DOUBLE] {
        assert_eq!(out[slot], 1, "slot {slot} must be present on this processor");
    }
}
