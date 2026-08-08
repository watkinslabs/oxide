// arm64 Image header + PE32+/EFI header. Placed by the linker script ahead of
// the trampoline in its own section, so this block's position does not depend
// on the order the assembly units are concatenated in.

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

    /* Return the assembler to .text before this block ends. `lto = "fat"` +
       `codegen-units = 1` concatenate every crate's module-level asm into ONE
       assembly unit, so the section left current here is inherited by whichever
       block follows. Leaving a non-.text section current made the next crate's
       instructions land in the wrong section: "BSS section '.bss' cannot have
       non-zero bytes", appearing and disappearing with unrelated edits that only
       perturbed the LTO module order. Every block in this module therefore names
       its own section on entry and restores .text on exit. */
    .section .text
    "#,
);
