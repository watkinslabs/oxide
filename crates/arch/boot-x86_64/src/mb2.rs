// Multiboot2 boot path (GRUB loads our kernel directly, replacing
// Limine). Stage 1 scaffolding: the Multiboot2 header GRUB scans for in
// the first 32 KiB of the ELF. The 32→64-bit long-mode trampoline +
// MB2-info→BootInfo parsing land in the following commits; this commit
// is just the header so `grub2-file --is-x86-multiboot2` recognises the
// kernel as loadable (the verifiable foundation).
//
// Header layout per the Multiboot2 spec §3.1.2: magic, architecture,
// header_length, checksum, then 8-byte-aligned tags terminated by the
// end tag (type 0, size 8).

#![allow(dead_code)]

/// Multiboot2 header magic (spec §3.1.2).
const MB2_MAGIC: u32 = 0xE852_50D6;
/// Architecture 0 = i386 (GRUB enters in 32-bit protected mode).
const MB2_ARCH_I386: u32 = 0;

/// The Multiboot2 header. `#[repr(C)]`, 8-byte aligned, placed in
/// `.multiboot2_header` which the linker pins within the first 32 KiB.
/// v1 carries only the mandatory end tag; information-request /
/// framebuffer / entry-address tags ride the trampoline commit.
#[repr(C, align(8))]
struct Mb2Header {
    magic:         u32,
    architecture:  u32,
    header_length: u32,
    checksum:      u32,
    // End tag (type 0, flags 0, size 8).
    end_type:  u16,
    end_flags: u16,
    end_size:  u32,
}

const HEADER_LEN: u32 = core::mem::size_of::<Mb2Header>() as u32;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[link_section = ".multiboot2_header"]
#[used]
static MB2_HEADER: Mb2Header = Mb2Header {
    magic:         MB2_MAGIC,
    architecture:  MB2_ARCH_I386,
    header_length: HEADER_LEN,
    // checksum: magic + arch + header_length + checksum == 0 (mod 2^32).
    checksum:      (0u32)
        .wrapping_sub(MB2_MAGIC)
        .wrapping_sub(MB2_ARCH_I386)
        .wrapping_sub(HEADER_LEN),
    end_type:  0,
    end_flags: 0,
    end_size:  8,
};
