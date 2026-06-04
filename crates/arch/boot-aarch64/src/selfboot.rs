// aarch64 self-bootstrap boot path (no Limine). QEMU `-machine virt
// -kernel <Image>` (and U-Boot `booti`) load a flat arm64 Image at RAM
// base 0x4000_0000 (text_offset 0) and jump to byte 0 with the MMU off,
// caches off, x0 = DTB phys, at EL2 (cortex-a72 on virt) or EL1.
//
// Byte 0 is the 64-byte arm64 Image header (Linux `Documentation/arm64/
// booting.rst`); its first word branches to `_arm_entry`, the MMU
// trampoline. The trampoline drops EL2->EL1 if needed, builds boot page
// tables, enables the MMU, jumps to the kernel's higher-half VMA, then
// tail-calls the shared `_start` (which Limine also enters). The Limine
// path is unaffected: Limine enters at the ELF `e_entry` (`_start`) with
// the MMU already on and never touches the Image header / trampoline.
//
// Address-space layout the boot page tables install (4 KiB granule,
// 1 GiB level-1 block descriptors, 48-bit VA):
//   TTBR0 (low / identity, VA[47]=0):
//     0..1 GiB    -> phys 0..1 GiB   Device-nGnRE (GIC, PL011 @0x0900_0000)
//     1..4 GiB    -> phys 1..4 GiB   Normal-WB     (RAM; kernel @0x4000_0000)
//   TTBR1 (high, VA[47]=1):
//     HHDM 0xFFFF_8000_0000_0000 -> phys 0   (reuses the TTBR0 ident L1:
//                                  device 0..1G, normal 1..4G)
//     KB   0xFFFF_FFFF_8000_0000 -> phys 0x4000_0000 (== KERNEL_PHYS) one
//                                  1 GiB Normal block covering the image.
// After the high jump TTBR0 is cleared (mirrors x86 PML4[0] teardown) so
// the kernel's per-process user mappings start from an empty low half.

#![cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]

use core::sync::atomic::{AtomicU64, Ordering};

/// HHDM offset the trampoline installs (TTBR1 0xFFFF_8000… -> phys 0).
/// Mirrors the x86 `MB2_HHDM`; reported as `BootInfo.hhdm_offset` and
/// used by the PL011 driver to reach the UART after the MMU is on.
pub const ARM_SELFBOOT_HHDM: u64 = 0xFFFF_8000_0000_0000;

/// Set to 1 by the trampoline (after the high jump) when we booted via
/// the Image protocol rather than Limine. `_start_rust` reads it to pick
/// `ARM_SELFBOOT_HHDM` instead of the (absent) Limine HHDM response.
#[no_mangle]
pub static SB_SELFBOOT_FLAG: AtomicU64 = AtomicU64::new(0);

/// Actual physical load base, recorded by the trampoline (`adrp
/// _arm_image_start`). QEMU loads the kernel 2 MiB above the RAM base
/// (it reserves the low 2 MiB for the DTB), so this is 0x4020_0000 on
/// `virt`, not the 0x4000_0000 RAM base. `build_selfboot_memmap` reserves
/// `[load_base, load_base+image_size)` so the PMM never clobbers the
/// loaded kernel — the bug that made baked `&str` pointers read zero.
#[no_mangle]
pub static SB_LOAD_BASE: AtomicU64 = AtomicU64::new(0);

/// True when we entered via the self-bootstrap Image trampoline.
/// # C: O(1)
pub fn is_selfboot() -> bool { SB_SELFBOOT_FLAG.load(Ordering::Acquire) != 0 }

/// EFI device-tree config-table GUID (gFdtTableGuid,
/// b1b621d5-f19c-41a5-830b-d9152c69aae0) in EFI mixed-endian byte order:
/// Data1/2/3 little-endian, Data4 big-endian.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const FDT_TABLE_GUID: [u8; 16] = [
    0xd5, 0x21, 0xb6, 0xb1, 0x9c, 0xf1, 0xa5, 0x41,
    0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0,
];

/// EFI-stub bring-up, called from `_arm_entry` when entered MMU-on (GRUB
/// `linux` / UEFI LoadImage). Walks the EFI configuration table for the
/// flattened device tree, then sizes the memory map and calls
/// `ExitBootServices` (retry loop — the map key goes stale if the
/// firmware mutates the map between calls). Returns the DTB phys (== VA
/// under the firmware's identity map) for the trampoline; the caller
/// disables the MMU on return. Touches only its args, the stack, and the
/// firmware tables — no kernel statics (HHDM/klog aren't up yet).
///
/// EFI_SYSTEM_TABLE / EFI_BOOT_SERVICES field offsets per UEFI 2.x;
/// AArch64 UEFI uses AAPCS64 so the fn pointers are plain `extern "C"`.
///
/// # SAFETY: invoked once from the asm EFI entry with valid firmware
/// `handle`/`systab`; boot services live until ExitBootServices returns.
/// # C: O(config_entries + memmap_descriptors)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[no_mangle]
pub unsafe extern "C" fn efi_stub_setup(handle: u64, systab: *const u8) -> u64 {
    // SAFETY: systab is the firmware EFI_SYSTEM_TABLE; offsets 0x60/0x68/
    // 0x70 are BootServices/NumberOfTableEntries/ConfigurationTable.
    unsafe {
        let boot_services = *(systab.add(0x60) as *const *const u8);
        let num_entries   = *(systab.add(0x68) as *const u64);
        let cfg_table     = *(systab.add(0x70) as *const *const u8);

        // Find the FDT config-table entry (24 bytes each: 16-byte GUID +
        // 8-byte VendorTable pointer).
        let mut dtb: u64 = 0;
        let mut i: u64 = 0;
        while i < num_entries {
            let ent = cfg_table.add((i * 24) as usize);
            let mut hit = true;
            let mut k = 0usize;
            while k < 16 {
                if *ent.add(k) != FDT_TABLE_GUID[k] { hit = false; break; }
                k += 1;
            }
            if hit { dtb = *(ent.add(16) as *const u64); break; }
            i += 1;
        }

        // GetMemoryMap @ bs+0x38, ExitBootServices @ bs+0xE8.
        type GetMemoryMapFn =
            extern "C" fn(*mut u64, *mut u8, *mut u64, *mut u64, *mut u32) -> u64;
        type ExitBootServicesFn = extern "C" fn(u64, u64) -> u64;
        let get_memory_map: GetMemoryMapFn =
            core::mem::transmute(*(boot_services.add(0x38) as *const u64));
        let exit_boot_services: ExitBootServicesFn =
            core::mem::transmute(*(boot_services.add(0xE8) as *const u64));

        // QEMU virt's map is a few KiB; 16 KiB of stack covers it.
        let mut buf = [0u8; 16384];
        let mut map_key: u64 = 0;
        let mut desc_size: u64 = 0;
        let mut desc_ver: u32 = 0;
        let mut tries = 0;
        loop {
            let mut map_size: u64 = buf.len() as u64;
            let _ = get_memory_map(
                &mut map_size, buf.as_mut_ptr(),
                &mut map_key, &mut desc_size, &mut desc_ver,
            );
            // ExitBootServices must immediately follow GetMemoryMap with
            // the fresh key; on EFI_INVALID_PARAMETER the map changed —
            // re-fetch and retry.
            if exit_boot_services(handle, map_key) == 0 { break; }
            tries += 1;
            if tries > 8 { break; }
        }
        dtb
    }
}

core::arch::global_asm!(
    r#"
    /* ---- arm64 Image header + PE32+/EFI header --------------------- */
    /* Dual boot protocol:
       - U-Boot `booti` / QEMU `-kernel` enter at byte 0 with MMU OFF,
         x0 = DTB phys. code0 (the "MZ" add) is harmless; code1 branches
         to _arm_entry.
       - GRUB `linux` / UEFI LoadImage enter (per AddressOfEntryPoint = 0)
         with MMU ON, x0 = EFI image handle, x1 = EFI system table. The
         same code0/code1 run; _arm_entry reads SCTLR_EL1.M to tell the
         two apart and runs the EFI stub (find DTB, ExitBootServices,
         MMU off) before falling into the shared trampoline.
       Offsets 0..63 are the arm64 Image header (Linux booting.rst);
       offset 60 points at the PE header so GRUB accepts us as an EFI
       application (a plain Image is rejected: "rebuild with EFI_STUB"). */
    .section .text.boot.header, "ax"
    .global _arm_image_start
_arm_image_start:
    add     x13, x18, #0x16       /* code0: 0x91005A4D = "MZ" + harmless */
    b       _arm_entry            /* code1: booti / -kernel entry        */
    .quad   0                     /* text_offset = 0                     */
    .quad   __image_size          /* image_size                          */
    .quad   0xA                   /* flags: 4 KiB pages, anywhere, LE    */
    .quad   0                     /* res2 */
    .quad   0                     /* res3 */
    .quad   0                     /* res4 */
    .ascii  "ARM\x64"             /* magic 0x644d5241 @ offset 56        */
    .long   _pe_header - _arm_image_start  /* @60: PE header RVA         */

    .balign 8
_pe_header:
    .ascii  "PE\0\0"              /* PE signature                        */
_coff_header:
    .short  0xAA64                /* Machine = IMAGE_FILE_MACHINE_ARM64  */
    .short  1                     /* NumberOfSections                    */
    .long   0                     /* TimeDateStamp                       */
    .long   0                     /* PointerToSymbolTable                */
    .long   0                     /* NumberOfSymbols                     */
    .short  _section_table - _optional_header  /* SizeOfOptionalHeader   */
    .short  0x0206                /* EXECUTABLE|LINE_STRIPPED|DEBUG_STRIPPED */
_optional_header:
    .short  0x020B                /* PE32+ magic                         */
    .byte   0x02                  /* MajorLinkerVersion                  */
    .byte   0x14                  /* MinorLinkerVersion                  */
    .long   __bss_start - _arm_image_start - 0x1000  /* SizeOfCode       */
    .long   0                     /* SizeOfInitializedData               */
    .long   0                     /* SizeOfUninitializedData             */
    .long   0                     /* AddressOfEntryPoint = image base    */
    .long   0x1000                /* BaseOfCode                          */
    .quad   0                     /* ImageBase                           */
    .long   0x1000                /* SectionAlignment                    */
    .long   0x200                 /* FileAlignment                       */
    .short  0                     /* MajorOSVersion */
    .short  0                     /* MinorOSVersion */
    .short  0                     /* MajorImageVersion */
    .short  0                     /* MinorImageVersion */
    .short  0                     /* MajorSubsystemVersion */
    .short  0                     /* MinorSubsystemVersion */
    .long   0                     /* Win32VersionValue */
    .long   __image_size          /* SizeOfImage (4K-aligned, incl bss)  */
    .long   0x1000                /* SizeOfHeaders                       */
    .long   0                     /* CheckSum                            */
    .short  0x000A                /* Subsystem = EFI_APPLICATION         */
    .short  0                     /* DllCharacteristics                  */
    .quad   0                     /* SizeOfStackReserve */
    .quad   0                     /* SizeOfStackCommit */
    .quad   0                     /* SizeOfHeapReserve */
    .quad   0                     /* SizeOfHeapCommit */
    .long   0                     /* LoaderFlags                         */
    .long   6                     /* NumberOfRvaAndSizes                 */
    .quad   0                     /* DataDirectory[0] Export             */
    .quad   0                     /* [1] Import                          */
    .quad   0                     /* [2] Resource                        */
    .quad   0                     /* [3] Exception                       */
    .quad   0                     /* [4] Certificate                     */
    .quad   0                     /* [5] BaseReloc                       */
_section_table:
    .ascii  ".text\0\0\0"
    .long   __image_size - 0x1000             /* VirtualSize (incl bss)  */
    .long   0x1000                            /* VirtualAddress          */
    .long   __bss_start - _arm_image_start - 0x1000  /* SizeOfRawData    */
    .long   0x1000                            /* PointerToRawData        */
    .long   0                                 /* PointerToRelocations    */
    .long   0                                 /* PointerToLinenumbers    */
    .short  0                                 /* NumberOfRelocations     */
    .short  0                                 /* NumberOfLinenumbers     */
    .long   0xE0000020            /* CODE|EXECUTE|READ|WRITE             */
    /* Pad the header region to SizeOfHeaders=0x1000 so the .text section
       (RVA/file-offset 0x1000) starts on a SectionAlignment boundary and
       file-offset == RVA (the flat objcopy image is loaded 1:1). */
    .balign 0x1000

    /* ---- MMU trampoline (runs MMU off; phys = wherever loaded) ----- */
    .section .text.boot, "ax"
    .global _arm_entry
_arm_entry:
    /* Distinguish EFI (MMU on; x0=handle, x1=systab) from booti (MMU
       off; x0=DTB). On EFI, run the stub: it returns DTB in x0 and
       leaves boot services exited; then drop the MMU and join booti. */
    mrs     x9, sctlr_el1
    tbz     x9, #0, 1f            /* M==0 -> booti, x0 already = DTB     */
    bl      efi_stub_setup        /* (x0=handle,x1=systab) -> x0 = DTB   */
    mov     x21, x0               /* save DTB across the cache flush     */
    /* GRUB/UEFI copied the image into RAM with the D-cache ON, so the
       loaded code + the page tables we are about to build can sit dirty
       in cache. We are about to run MMU+cache OFF, where fetches/walks
       read RAM directly — clean+invalidate the whole D-cache to PoC and
       invalidate the I-cache first, or _arm_high faults on a stale line. */
    bl      __efi_dcache_flush_all
    mov     x0, x21
    mrs     x9, sctlr_el1         /* drop MMU+caches (still identity)    */
    bic     x9, x9, #(1 << 0)     /* M  */
    bic     x9, x9, #(1 << 2)     /* C  */
    bic     x9, x9, #(1 << 12)    /* I  */
    msr     sctlr_el1, x9
    isb
    dsb     sy
    tlbi    vmalle1
    ic      iallu
    dsb     sy
    isb
1:
    mov     x19, x0               /* preserve DTB phys across the dance */

    /* breadcrumb 'A' to PL011 DR @ 0x0900_0000 (QEMU UART, no init)   */
    movz    x9, #0x0900, lsl #16
    mov     w10, #0x41
    str     w10, [x9]

    /* If at EL2, drop to EL1. cortex-a72 on `virt` enters at EL2.     */
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    /* breadcrumb: ASCII EL digit ('1' or '2')                        */
    movz    x9, #0x0900, lsl #16
    add     w10, w0, #0x30
    str     w10, [x9]
    cmp     x0, #2
    b.ne    1f
    /* EL2: route EL1 as AArch64, allow EL1 timer, seed SCTLR_EL1.     */
    movz    x0, #0x8000, lsl #16  /* HCR_EL2.RW (bit 31)               */
    msr     hcr_el2, x0
    mov     x0, #3                /* CNTHCTL_EL2.EL1PCTEN|EL1PCEN      */
    msr     cnthctl_el2, x0
    msr     cntvoff_el2, xzr
    /* GICv3 CPU interface: ICC_SRE_EL2 = Enable|DFB|DIB|SRE (0xf) so
       EL1 may use the ICC_ system registers; without SRE the kernel's
       GICv3 init cannot deliver IRQs (the timer tick never fires and
       the scheduler wedges). Linux/Limine set this at EL2.           */
    mov     x0, #0xf
    msr     S3_4_C12_C9_5, x0     /* ICC_SRE_EL2 */
    isb
    /* (SCTLR_EL1 left at QEMU's EL1 reset value — setting it to
       0x30d00800 here wedged the later MMU enable.) */
    movz    x0, #0x03c5           /* SPSR_EL2: EL1h, DAIF masked       */
    msr     spsr_el2, x0
    adr     x0, 1f                /* ELR_EL2 = phys label 1f           */
    msr     elr_el2, x0
    eret
1:
    /* breadcrumb 'B' (now definitely EL1)                            */
    movz    x9, #0x0900, lsl #16
    mov     w10, #0x42
    str     w10, [x9]

    /* l1_ident[0]=Device@0, [1..3]=Normal@1/2/3 GiB (1 GiB blocks).
       block desc: OA | AF(1<<10) | SH | AttrIdx<<2 | type(0b01).
       Device: AttrIdx0, SH=0  -> 0x401.
       Normal: AttrIdx1(<<2=4), SH=3(<<8=0x300), AF=0x400 -> 0x705.    */
    adrp    x1, _sb_l1_ident
    add     x1, x1, #:lo12:_sb_l1_ident
    movz    x2, #0x0401
    str     x2, [x1, #0]
    movz    x4, #0x0705                 /* normal-block attr bits      */
    movz    x3, #0x4000, lsl #16        /* 1 GiB                       */
    orr     x3, x3, x4
    str     x3, [x1, #8]
    movz    x3, #0x8000, lsl #16        /* 2 GiB                       */
    orr     x3, x3, x4
    str     x3, [x1, #16]
    movz    x3, #0xC000, lsl #16        /* 3 GiB                       */
    orr     x3, x3, x4
    str     x3, [x1, #24]
    /* l1_ident[4..512] = Device 1 GiB blocks (4..512 GiB). Covers the
       virt PCIe ECAM/MMIO windows at high phys (e.g. 0x40_1000_0000 =
       256 GiB) so HHDM-based PCIe enumeration doesn't fault. RAM is
       <=4 GiB here, so device attrs beyond 4 GiB are correct.        */
    mov     x2, #4
    movz    x5, #0x0401                 /* device-block attr bits      */
2:
    lsl     x6, x2, #30                 /* OA = i * 1 GiB              */
    orr     x6, x6, x5
    str     x6, [x1, x2, lsl #3]        /* l1_ident[i]                 */
    add     x2, x2, #1
    cmp     x2, #512
    b.lt    2b

    /* ttbr0_l0[0] = l1_ident | table(0b11)                           */
    adrp    x0, _sb_ttbr0_l0
    add     x0, x0, #:lo12:_sb_ttbr0_l0
    orr     x5, x1, #0x3
    str     x5, [x0, #0]
    /* ap_l0[0] = l1_ident | table — a DEDICATED low-identity L0 for PSCI
       AP startup. _sb_ttbr0_l0[0] gets cleared at _arm_high (user-AS root),
       so secondaries can't reuse it for their MMU-off → MMU-on jump. This
       copy is never torn down, so each AP can use it as TTBR0 to fetch its
       own trampoline at the physical PC until it reaches the higher half.  */
    adrp    x6, _sb_ap_l0
    add     x6, x6, #:lo12:_sb_ap_l0
    str     x5, [x6, #0]

    /* ttbr1_l0[256] = l1_ident | table  (HHDM reuse)                 */
    adrp    x6, _sb_ttbr1_l0
    add     x6, x6, #:lo12:_sb_ttbr1_l0
    str     x5, [x6, #(256*8)]
    /* ttbr1_l0[511] = l1_kernel | table                             */
    adrp    x7, _sb_l1_kernel
    add     x7, x7, #:lo12:_sb_l1_kernel
    orr     x8, x7, #0x3
    str     x8, [x6, #(511*8)]
    /* l1_kernel[510] = l2_kernel | table. KB[38:30]=510 selects it.   */
    adrp    x15, _sb_l2_kernel
    add     x15, x15, #:lo12:_sb_l2_kernel
    orr     x16, x15, #0x3
    str     x16, [x7, #(510*8)]
    /* Actual phys load base = adrp of the image start (PC-relative, MMU
       off → real load addr). Record it for build_selfboot_memmap.
       booti/-kernel loads 2 MiB-aligned, but the GRUB/UEFI PE loader can
       place us at only 4 KiB alignment, so map KB -> load_base with 4 KiB
       L3 PAGES (valid OA for any 4K-aligned base) rather than 2 MiB
       blocks (which need a 2 MiB-aligned OA — a 4K-aligned base corrupts
       the block descriptor and the higher-half jump faults).           */
    adrp    x14, _arm_image_start
    adrp    x17, SB_LOAD_BASE
    add     x17, x17, #:lo12:SB_LOAD_BASE
    str     x14, [x17]
    /* N = ceil(__image_size / 2 MiB), capped at 256 (=> <= 512 MiB).   */
    movz    x3, #:abs_g0_nc:__image_size
    movk    x3, #:abs_g1_nc:__image_size
    movk    x3, #:abs_g2_nc:__image_size
    movk    x3, #:abs_g3:__image_size
    mov     x4, #0x200000
    sub     x4, x4, #1                 /* 0x1F_FFFF                      */
    add     x3, x3, x4
    lsr     x3, x3, #21                /* x3 = N (number of 2 MiB chunks) */
    cmp     x3, #256
    b.ls    11f
    mov     x3, #256
11:
    /* _sb_l3_kernel[k] = (load_base + k*4 KiB) | page, k in 0 .. N*512.
       0x707 = page(0b11) | AttrIdx1(Normal) | SH-inner(0b11) | AF.      */
    adrp    x16, _sb_l3_kernel
    add     x16, x16, #:lo12:_sb_l3_kernel
    lsl     x5, x3, #9                 /* total pages = N * 512          */
    movz    x4, #0x0707
    mov     x2, #0
12:
    lsl     x8, x2, #12                /* k * 4 KiB                      */
    add     x8, x8, x14                /* + load_base                    */
    orr     x8, x8, x4
    str     x8, [x16, x2, lsl #3]
    add     x2, x2, #1
    cmp     x2, x5
    b.lt    12b
    /* l2_kernel[j] = (_sb_l3_kernel + j*4 KiB) | table, j in 0 .. N.   */
    mov     x2, #0
13:
    lsl     x8, x2, #12                /* j-th L3 table (4 KiB each)     */
    add     x8, x8, x16                /* + _sb_l3_kernel base           */
    orr     x8, x8, #0x3
    str     x8, [x15, x2, lsl #3]
    add     x2, x2, #1
    cmp     x2, x3
    b.lt    13b

    /* MAIR: Attr0=Device-nGnRE(0x04), Attr1=Normal-WB(0xFF)          */
    movz    x0, #0xFF04
    msr     mair_el1, x0
    /* TCR: T0SZ=T1SZ=16, 4 KiB granule both, WB/WA, inner-shareable,
       IPS=48-bit -> 0x5_B510_3510                                    */
    movz    x0, #0x3510
    movk    x0, #0xB510, lsl #16
    movk    x0, #0x0005, lsl #32
    msr     tcr_el1, x0
    adrp    x0, _sb_ttbr0_l0
    add     x0, x0, #:lo12:_sb_ttbr0_l0
    msr     ttbr0_el1, x0
    adrp    x0, _sb_ttbr1_l0
    add     x0, x0, #:lo12:_sb_ttbr1_l0
    msr     ttbr1_el1, x0
    dsb     sy
    tlbi    vmalle1
    dsb     sy
    isb

    /* breadcrumb 'C' (page tables built, about to enable MMU)        */
    movz    x9, #0x0900, lsl #16
    mov     w10, #0x43
    str     w10, [x9]

    /* SCTLR_EL1: enable M(0)|C(2)|I(12)                              */
    mrs     x0, sctlr_el1
    mov     x1, #0x1005
    orr     x0, x0, x1
    msr     sctlr_el1, x0
    isb

    /* breadcrumb 'D' (MMU on; 0x0900_0000 still mapped via TTBR0)    */
    movz    x9, #0x0900, lsl #16
    mov     w10, #0x44
    str     w10, [x9]

    /* Jump to the higher-half linked VMA of _arm_high. The 4 KiB pages
       map KB -> load_base, so the linked VMA = phys(_arm_high) -
       load_base + KB. x14 still holds load_base.                      */
    adrp    x0, _arm_high
    add     x0, x0, #:lo12:_arm_high
    sub     x0, x0, x14                 /* linked offset from image base */
    movz    x1, #0x8000, lsl #16
    movk    x1, #0xFFFF, lsl #32
    movk    x1, #0xFFFF, lsl #48        /* KB = 0xFFFF_FFFF_8000_0000    */
    add     x0, x0, x1
    br      x0

_arm_high:
    /* breadcrumb 'E' (reached the higher-half jump). Use the LOW-identity
       UART (0x0900_0000, still mapped via TTBR0[0] until the teardown
       below) — NOT HHDM. HHDM-over-the-device-region is unused by the
       real kernel (MMIO goes through KERNEL_DEVICE_BASE), and writing it
       here faults under the GRUB/UEFI entry path.                       */
    movz    x9, #0x0900, lsl #16
    mov     w10, #0x45
    str     w10, [x9]

    /* Running at KB now. Drop the low identity by clearing the TTBR0
       root's entry[0] (the 1 GiB-block L1 chain) — but keep TTBR0_EL1
       pointing at the (now empty) root so the kernel can install
       per-process user mappings under it with 4 KiB pages. Setting
       TTBR0_EL1=0 instead would leave map()/translate() of a user VA
       with no root -> the user-map smoke + exec/login fail. (x86 mirror:
       clear PML4[0], keep CR3.)                                       */
    adrp    x1, _sb_ttbr0_l0
    add     x1, x1, #:lo12:_sb_ttbr0_l0
    str     xzr, [x1, #0]
    dsb     sy
    tlbi    vmalle1
    dsb     sy
    isb
    /* Mark self-boot so _start_rust uses ARM_SELFBOOT_HHDM.          */
    adrp    x1, SB_SELFBOOT_FLAG
    add     x1, x1, #:lo12:SB_SELFBOOT_FLAG
    mov     x2, #1
    str     x2, [x1]
    /* Hand DTB back in x0 and enter the shared bootloader-agnostic
       _start (it installs SP_EL1 and tail-calls _start_rust).        */
    mov     x0, x19
    b       _start

    /* Clean+invalidate the entire data cache to PoC by set/way, then
       invalidate the I-cache. Standard ARMv8 routine (mirrors Linux
       __flush_dcache_all). Clobbers x0-x11; preserves nothing else.
       Used only on the EFI-stub path before dropping MMU+caches. */
    .global __efi_dcache_flush_all
__efi_dcache_flush_all:
    dsb     sy
    mrs     x0, clidr_el1
    and     w3, w0, #0x07000000        /* LoC                          */
    lsr     w3, w3, #23
    cbz     w3, 5f
    mov     w10, #0                     /* w10 = 2*level                */
0:
    add     w2, w10, w10, lsr #1        /* w2 = 3*level                 */
    lsr     w1, w0, w2                  /* cache type this level        */
    and     w1, w1, #7
    cmp     w1, #2
    b.lt    4f                          /* no D-cache at this level     */
    msr     csselr_el1, x10
    isb
    mrs     x1, ccsidr_el1
    and     w2, w1, #7                  /* log2(line)-4                 */
    add     w2, w2, #4
    ubfx    w4, w1, #3, #10             /* ways-1                       */
    clz     w5, w4                      /* way bit position             */
    ubfx    w7, w1, #13, #15            /* sets-1                       */
1:
    mov     w9, w4
2:
    lsl     w6, w9, w5
    orr     w11, w10, w6               /* level | way<<wayshift         */
    lsl     w6, w7, w2
    orr     w11, w11, w6               /* | set<<setshift               */
    dc      cisw, x11                   /* clean+invalidate by set/way  */
    subs    w9, w9, #1
    b.ge    2b
    subs    w7, w7, #1
    b.ge    1b
4:
    add     w10, w10, #2
    cmp     w3, w10
    b.gt    0b
5:
    dsb     sy
    ic      iallu
    dsb     sy
    isb
    ret

    /* ---- boot page tables (zero-init BSS, 4 KiB each) ------------- */
    /* .global the tables the PSCI AP trampoline (hal-aarch64) reaches by
       physical address: the AP identity L0, the shared kernel high map,
       and the (cleared-[0]) kernel user-AS root it switches to up high.  */
    .global _sb_ap_l0
    .global _sb_l1_ident
    .global _sb_ttbr0_l0
    .global _sb_ttbr1_l0
    .section .bss
    .align 12
_sb_ttbr0_l0:  .skip 4096
_sb_ap_l0:     .skip 4096
_sb_l1_ident:  .skip 4096
_sb_ttbr1_l0:  .skip 4096
_sb_l1_kernel: .skip 4096
_sb_l2_kernel: .skip 4096
    /* L3 page tables for the KB->load_base mapping: 256 tables (one per
       2 MiB of image, up to 512 MiB) so any 4 KiB-aligned load base maps
       with 4 KiB pages. BSS (zero-cost in the file; zeroed by the EFI PE
       loader / unused entries never walked under booti).               */
    .align 12
_sb_l3_kernel: .skip 256 * 4096
    "#,
);
