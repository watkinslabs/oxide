// x86 boot-protocol numbers: the field offsets of `struct setup_header` and
// `struct boot_params`, the flag bits the probe tests, and the floors the
// loader places against. Numbers only; every decision lives in `header`,
// `bootparams` and `layout`.
//
// Offsets rather than a Rust struct ON PURPOSE (`07§5`, `54§5`). `boot_params`
// is a packed 4 KiB ABI page with padding at fixed places and a nested packed
// header at 0x1F1; a `#[repr(C, packed)]` transcription of it would be a
// hundred fields whose agreement with the protocol nothing checks, and a single
// wrong padding array silently shifts every field after it. The protocol states
// its layout as offsets, so the port does too, and the tests assert them
// against a real kernel image.

/// `struct setup_header`'s offset inside `struct boot_params`.
pub const BP_HDR: usize = 0x1F1;
/// Bytes `struct boot_params` occupies — the "zero page".
pub const BP_SIZE: usize = 0x1000;
/// `screen_info.ext_mem_k`, at the very start of the page.
pub const BP_EXT_MEM_K: usize = 0x002;
/// High 32 bits of the initramfs address.
pub const BP_EXT_RAMDISK_IMAGE: usize = 0x0C0;
/// High 32 bits of the initramfs length.
pub const BP_EXT_RAMDISK_SIZE: usize = 0x0C4;
/// High 32 bits of the command-line pointer.
pub const BP_EXT_CMD_LINE_PTR: usize = 0x0C8;
/// Memory above 1 MiB in KiB, 32-bit.
pub const BP_ALT_MEM_K: usize = 0x1E0;
/// Live entries in `e820_table`.
pub const BP_E820_ENTRIES: usize = 0x1E8;
/// The E820 table itself.
pub const BP_E820_TABLE: usize = 0x2D0;

/// `setup_sects`: 512-byte sectors of real-mode setup after the boot sector.
pub const HDR_SETUP_SECTS: usize = 0x1F1;
/// `boot_flag`.
pub const HDR_BOOT_FLAG: usize = 0x1FE;
/// Second byte of the `jump` instruction; the setup header ends
/// `0x202 + jump_offset` bytes into the file.
pub const HDR_JUMP_OFFSET: usize = 0x201;
/// `header`, the "HdrS" signature.
pub const HDR_MAGIC: usize = 0x202;
/// `version`, the boot-protocol version, BCD-ish major/minor.
pub const HDR_VERSION: usize = 0x206;
/// `type_of_loader`.
pub const HDR_TYPE_OF_LOADER: usize = 0x210;
/// `loadflags`.
pub const HDR_LOADFLAGS: usize = 0x211;
/// `ramdisk_image`, low 32 bits.
pub const HDR_RAMDISK_IMAGE: usize = 0x218;
/// `ramdisk_size`, low 32 bits.
pub const HDR_RAMDISK_SIZE: usize = 0x21C;
/// `cmd_line_ptr`, low 32 bits.
pub const HDR_CMD_LINE_PTR: usize = 0x228;
/// `kernel_alignment`.
pub const HDR_KERNEL_ALIGNMENT: usize = 0x230;
/// `xloadflags`.
pub const HDR_XLOADFLAGS: usize = 0x236;
/// `cmdline_size`, the longest command line this kernel accepts.
pub const HDR_CMDLINE_SIZE: usize = 0x238;
/// `pref_address`, where the kernel would rather be loaded.
pub const HDR_PREF_ADDRESS: usize = 0x258;
/// `init_size`, memory the kernel needs while decompressing itself.
pub const HDR_INIT_SIZE: usize = 0x260;

/// The `header` signature a bzImage carries.
pub const MAGIC: [u8; 4] = *b"HdrS";
/// The `boot_flag` value at the end of the boot sector.
pub const BOOT_FLAG: u16 = 0xAA55;
/// Oldest boot protocol this loader will start: 2.12, which is the version
/// that introduced `xloadflags`.
pub const MIN_VERSION: u16 = 0x020C;
/// `LOADED_HIGH`: the protected-mode kernel loads at 0x100000, not 0x10000.
pub const LOADED_HIGH: u8 = 1 << 0;
/// `XLF_KERNEL_64`: a 64-bit entry point exists at +0x200.
pub const XLF_KERNEL_64: u16 = 1 << 0;
/// `XLF_CAN_BE_LOADED_ABOVE_4G`.
pub const XLF_CAN_BE_LOADED_ABOVE_4G: u16 = 1 << 1;

/// `type_of_loader` for a kexec-loaded image: loader id 0x0D, revision 0.
pub const TYPE_OF_LOADER: u8 = 0x0D << 4;
/// `loadflags` handed to the new kernel: cleared, exactly as the reference
/// clears it — none of the flags the previous boot loader set apply.
pub const LOADFLAGS: u8 = 0;

/// `setup_sects` of zero means four, a rule older than the header itself.
pub const DEFAULT_SETUP_SECTS: u64 = 4;
/// Bytes per setup sector.
pub const SECTOR_SIZE: u64 = 512;
/// Shortest file that can be a bzImage: a boot sector and one setup sector.
pub const MIN_FILE_LEN: usize = 2 * 512;
/// Offset of the 64-bit entry point within the loaded kernel segment.
pub const ENTRY64_OFFSET: u64 = 0x200;

/// Lowest address the purgatory may be placed at.
pub const MIN_PURGATORY_ADDR: u64 = 0x3000;
/// Lowest address the boot-parameter page may be placed at.
pub const MIN_BOOTPARAM_ADDR: u64 = 0x3000;
/// Lowest address the kernel may be placed at, when `pref_address` is lower.
pub const MIN_KERNEL_LOAD_ADDR: u64 = 0x100000;
/// Lowest address the initramfs may be placed at.
pub const MIN_INITRD_LOAD_ADDR: u64 = 0x1000000;
/// Alignment of the boot-parameter buffer.
pub const BOOTPARAM_ALIGN: u64 = 16;

/// `E820_MAX_ENTRIES_ZEROPAGE`: entries `boot_params.e820_table` holds.
pub const E820_MAX_ENTRIES_ZEROPAGE: usize = 128;
/// Bytes one `struct boot_e820_entry` occupies: `addr`, `size`, `type`, packed.
pub const E820_ENTRY_SIZE: usize = 20;
/// `E820_TYPE_RAM`.
pub const E820_TYPE_RAM: u32 = 1;

/// Bytes reserved after the command line for the `elfcorehdr=0x…` a crash
/// image appends. Reserved on every image, as the reference reserves it, so
/// the command-line length test is the same test for both kinds.
pub const MAX_ELFCOREHDR_STR_LEN: usize = 30;
/// Ceiling on `screen_info.ext_mem_k`, which is a 16-bit field: 64 MiB.
pub const EXT_MEM_K_MAX: u64 = 0xfc00;
/// Ceiling on `alt_mem_k`, which is 32-bit.
pub const ALT_MEM_K_MAX: u64 = 0xffff_ffff;
/// The 1 MiB boundary `ext_mem_k` and `alt_mem_k` are measured above.
pub const LOW_MEMORY_TOP: u64 = 0x100000;
