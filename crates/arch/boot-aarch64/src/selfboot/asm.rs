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

    /* SCTLR_EL1: enable M(0)|C(2)|I(12); CLEAR A(1)+SA0(4) so EL0
       unaligned Normal-memory access is hardware-handled, not trapped.
       Firmware (OVMF w/ >1 vCPU) can leave A=1 at handoff; ORing M|C|I
       without clearing A let that leak through → musl memcpy's `ldr`
       on a misaligned ptr faulted (DFSC=0x21) only at -smp 2. Linux
       always sets SCTLR explicitly; mirror that.                     */
    mrs     x0, sctlr_el1
    mov     x1, #0x1005
    orr     x0, x0, x1
    bic     x0, x0, #(1 << 1)     /* A — alignment check off (Linux)    */
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

    /* Return the assembler to .text before this block ends. `lto = "fat"` +
       `codegen-units = 1` concatenate every crate's module-level asm into ONE
       assembly unit, so the section left current here is inherited by whichever
       block follows. Leaving it as .bss made the next crate's instructions land
       in a NOBITS section: "BSS section '.bss' cannot have non-zero bytes",
       appearing and disappearing with unrelated edits that only perturbed the
       LTO module order. */
    .section .text
    "#,
);
