// Header provenance. Every offset is checked against a header built field by
// field, and then against a real vendor aarch64 kernel from the image tree —
// the fixture that would catch a layout the boot protocol changed under us.

use super::*;
use crate::file_load::arm_image::caps::decode_mmfr0;
use alloc::vec;
use alloc::vec::Vec;

/// A header with every field set to a value that cannot be confused with any
/// other field's.
fn hdr(text_offset: u64, image_size: u64, flags: u64) -> Vec<u8> {
    let mut b = vec![0u8; HDR_SIZE];
    b[OFF_CODE0..OFF_CODE0 + 4].copy_from_slice(&0x1111_1111u32.to_le_bytes());
    b[OFF_CODE1..OFF_CODE1 + 4].copy_from_slice(&0x2222_2222u32.to_le_bytes());
    b[OFF_TEXT_OFFSET..OFF_TEXT_OFFSET + 8].copy_from_slice(&text_offset.to_le_bytes());
    b[OFF_IMAGE_SIZE..OFF_IMAGE_SIZE + 8].copy_from_slice(&image_size.to_le_bytes());
    b[OFF_FLAGS..OFF_FLAGS + 8].copy_from_slice(&flags.to_le_bytes());
    b[OFF_RES2..OFF_RES2 + 8].copy_from_slice(&0x3333_3333_3333_3333u64.to_le_bytes());
    b[OFF_RES3..OFF_RES3 + 8].copy_from_slice(&0x4444_4444_4444_4444u64.to_le_bytes());
    b[OFF_RES4..OFF_RES4 + 8].copy_from_slice(&0x5555_5555_5555_5555u64.to_le_bytes());
    b[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&IMAGE_MAGIC);
    b[OFF_RES5..OFF_RES5 + 4].copy_from_slice(&0x40u32.to_le_bytes());
    b
}

/// Everything implemented — the machine that refuses nothing on capability.
fn all_caps() -> Caps {
    Caps { g4: true, g16: true, g64: true, mixed_endian: true, be_kernel: false }
}

/// QEMU `virt` / Cortex-A72: 4 KiB and 64 KiB, no 16 KiB, no mixed endian.
fn virt_caps() -> Caps {
    Caps { g4: true, g16: false, g64: true, mixed_endian: false, be_kernel: false }
}

#[test]
fn every_field_is_decoded_at_its_own_offset_and_not_its_neighbours() {
    // The failure this catches: a header whose `image_size` is read at the
    // `text_offset` offset places the image at a plausible address with a
    // plausible size and boots into rubble. Distinct per-field values make an
    // offset slip visible as the WRONG neighbour's value, not as garbage.
    let b = hdr(0x8_0000, 0x0482_0000, 0x0a);
    let h = decode(&b).expect("a full-length header decodes");
    assert_eq!(h.code0, 0x1111_1111);
    assert_eq!(h.code1, 0x2222_2222);
    assert_eq!(h.text_offset, 0x8_0000);
    assert_eq!(h.image_size, 0x0482_0000);
    assert_eq!(h.flags, 0x0a);
    assert_eq!(h.magic, IMAGE_MAGIC);
}

#[test]
fn the_magic_is_the_ascii_bytes_arm_then_zero_x_sixty_four() {
    // Spelled `ARM\x64` by the boot protocol; `0x64` is `d`. A constant
    // written as the four characters `ARM6` would compare against a byte the
    // protocol never emits and refuse every real kernel.
    assert_eq!(IMAGE_MAGIC, [b'A', b'R', b'M', 0x64]);
    assert_eq!(IMAGE_MAGIC[3], b'd');
}

#[test]
fn a_file_with_the_magic_anywhere_but_offset_0x38_is_not_recognised() {
    let mut b = hdr(0, 1, 0);
    b[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&[0, 0, 0, 0]);
    b[OFF_CODE0..OFF_CODE0 + 4].copy_from_slice(&IMAGE_MAGIC);
    assert_eq!(probe(&b), Err(Error::Inval));
    assert!(probe(&hdr(0, 1, 0)).is_ok());
}

#[test]
fn a_file_shorter_than_the_header_is_refused_rather_than_read_past_its_end() {
    let b = hdr(0, 1, 0);
    assert_eq!(decode(&b[..HDR_SIZE - 1]), Err(Error::Inval));
    assert_eq!(probe(&b[..HDR_SIZE - 1]), Err(Error::Inval));
    assert_eq!(probe(&[]), Err(Error::Inval));
}

#[test]
fn an_image_size_of_zero_is_refused_because_the_extent_is_unknowable() {
    let h = decode(&hdr(0, 0, 0)).expect("decodes");
    assert_eq!(check_features(&h, &all_caps()), Err(Error::Inval));
    // The same header with a size is accepted, so the refusal is the size and
    // not something else in the header.
    let h = decode(&hdr(0, 0x1000, 0)).expect("decodes");
    assert_eq!(check_features(&h, &all_caps()), Ok(()));
}

#[test]
fn a_big_endian_image_is_refused_unless_the_machine_can_run_both_orders() {
    let be = decode(&hdr(0, 0x1000, FLAG_BE << FLAG_BE_SHIFT)).expect("decodes");
    assert_eq!(be.endianness(), FLAG_BE);
    assert_eq!(check_features(&be, &virt_caps()), Err(Error::Inval));
    assert_eq!(check_features(&be, &all_caps()), Ok(()));
    // The little-endian image is accepted on the same machine, so the refusal
    // is the byte order and not the capability set as a whole.
    let le = decode(&hdr(0, 0x1000, FLAG_LE << FLAG_BE_SHIFT)).expect("decodes");
    assert_eq!(check_features(&le, &virt_caps()), Ok(()));
}

#[test]
fn a_granule_the_machine_does_not_implement_is_refused_and_the_others_are_not() {
    let g = |v: u64| decode(&hdr(0, 0x1000, v << FLAG_PAGE_SIZE_SHIFT)).expect("decodes");
    assert_eq!(g(FLAG_PAGE_SIZE_4K).page_size_field(), FLAG_PAGE_SIZE_4K);
    assert_eq!(check_features(&g(FLAG_PAGE_SIZE_4K), &virt_caps()), Ok(()));
    assert_eq!(check_features(&g(FLAG_PAGE_SIZE_64K), &virt_caps()), Ok(()));
    assert_eq!(check_features(&g(FLAG_PAGE_SIZE_16K), &virt_caps()), Err(Error::Inval));
    assert_eq!(check_features(&g(FLAG_PAGE_SIZE_16K), &all_caps()), Ok(()));
}

#[test]
fn the_unspecified_page_size_field_states_no_requirement_to_fail() {
    // A machine that implements nothing at all still accepts an image that
    // asks for nothing — the field is reserved in pre-v3.17 headers and
    // treating it as "4 KiB" would refuse images the reference accepts.
    let none = Caps { g4: false, g16: false, g64: false, mixed_endian: false, be_kernel: false };
    let h = decode(&hdr(0, 0x1000, FLAG_PAGE_SIZE_UNSPEC << FLAG_PAGE_SIZE_SHIFT))
        .expect("decodes");
    assert_eq!(check_features(&h, &none), Ok(()));
}

#[test]
fn the_flag_fields_do_not_overlap_each_other() {
    // Bit 0 is byte order, bits [2:1] the page size, bit 3 the physical base.
    // An off-by-one shift makes a 64 KiB image look 16 KiB and a
    // position-independent image look big-endian.
    let h = decode(&hdr(0, 0x1000, 0b1000)).expect("decodes");
    assert_eq!(h.endianness(), FLAG_LE);
    assert_eq!(h.page_size_field(), FLAG_PAGE_SIZE_UNSPEC);
    assert_eq!(h.phys_base_field(), FLAG_PHYS_BASE);
    let h = decode(&hdr(0, 0x1000, 0b0110)).expect("decodes");
    assert_eq!(h.endianness(), FLAG_LE);
    assert_eq!(h.page_size_field(), FLAG_PAGE_SIZE_64K);
    assert_eq!(h.phys_base_field(), 0);
}

// ---------------------------------------------------------------------------
// Real vendor kernel.

/// The aarch64 kernel the image tree composes its root filesystem from.
const VENDOR_VMLINUZ: &str =
    "/home/nd/oxide/images/build/lite-aarch64-root/lib/modules/6.19.14-108.fc42.aarch64/vmlinuz";

/// The EFI zboot container's own header: `MZ`, then the four-byte tag at
/// offset 4, then the payload offset and size.
const ZBOOT_TAG_OFF: usize = 0x04;
/// See [`ZBOOT_TAG_OFF`].
const ZBOOT_TAG: [u8; 4] = *b"zimg";

fn vendor_bytes(n: usize) -> Option<Vec<u8>> {
    let all = std::fs::read(VENDOR_VMLINUZ).ok()?;
    if all.len() < n { return None; }
    Some(all[..n].to_vec())
}

#[test]
fn the_vendor_vmlinuz_is_an_efi_zboot_container_the_image_loader_must_refuse() {
    let Some(b) = vendor_bytes(HDR_SIZE) else {
        std::eprintln!("skipped: {VENDOR_VMLINUZ} absent");
        return;
    };
    // It is a zboot wrapper, not a raw `Image`: the tag says so, and the four
    // bytes at the `Image` magic offset are the PE magic instead.
    assert_eq!(&b[ZBOOT_TAG_OFF..ZBOOT_TAG_OFF + 4], &ZBOOT_TAG);
    assert_ne!(&b[OFF_MAGIC..OFF_MAGIC + 4], &IMAGE_MAGIC);
    // So the loader refuses it, which is what the reference does too: the
    // `Image` loader recognises the decompressed payload, never the container.
    assert_eq!(probe(&b), Err(Error::Inval));
}

/// Decompress the zboot payload with the system `zstd`, 64 bytes of it.
fn vendor_payload_header() -> Option<Vec<u8>> {
    let all = std::fs::read(VENDOR_VMLINUZ).ok()?;
    if all.len() < 0x10 { return None; }
    let off = u32::from_le_bytes([all[8], all[9], all[10], all[11]]) as usize;
    let sz = u32::from_le_bytes([all[12], all[13], all[14], all[15]]) as usize;
    if off + sz > all.len() { return None; }
    let tmp = std::env::temp_dir().join("oxide-kexec-arm-payload.zst");
    std::fs::write(&tmp, &all[off..off + sz]).ok()?;
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(std::format!("zstd -qdc '{}' 2>/dev/null | head -c 64", tmp.display()))
        .output()
        .ok()?;
    let _ = std::fs::remove_file(&tmp);
    if out.stdout.len() < HDR_SIZE { return None; }
    Some(out.stdout)
}

#[test]
fn the_decompressed_vendor_image_probes_and_its_fields_are_the_protocols() {
    let Some(b) = vendor_payload_header() else {
        std::eprintln!("skipped: vendor payload or zstd unavailable");
        return;
    };
    assert_eq!(probe(&b), Ok(()));
    let h = decode(&b).expect("decodes");
    assert_eq!(h.magic, IMAGE_MAGIC);
    // A vendor arm64 kernel is little-endian, 4 KiB granule, and states a
    // non-zero image size. `text_offset` is zero on every image built since
    // the physical-base bit was introduced, and that bit is set here.
    assert_eq!(h.endianness(), FLAG_LE);
    assert_eq!(h.page_size_field(), FLAG_PAGE_SIZE_4K);
    assert_eq!(h.phys_base_field(), FLAG_PHYS_BASE);
    assert_ne!(h.image_size, 0);
    assert_eq!(h.text_offset, 0);
    // And it is startable on a machine whose feature register reports the
    // 4 KiB and 64 KiB granules, no 16 KiB, and no mixed endian.
    let mmfr0: u64 = 0x0000_0000_0000_1022;
    let c = decode_mmfr0(mmfr0);
    assert!(c.g4 && c.g64 && !c.g16 && !c.mixed_endian);
    assert_eq!(check_features(&h, &c), Ok(()));
}
