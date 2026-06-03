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

/// True when we entered via the self-bootstrap Image trampoline.
/// # C: O(1)
pub fn is_selfboot() -> bool { SB_SELFBOOT_FLAG.load(Ordering::Acquire) != 0 }

core::arch::global_asm!(
    r#"
    /* ---- arm64 Image header (Linux booting.rst) -------------------- */
    .section .text.boot.header, "ax"
    .global _arm_image_start
_arm_image_start:
    b       _arm_entry            /* code0: branch to trampoline       */
    .long   0                     /* code1: reserved (must be 0)       */
    .quad   0                     /* text_offset = 0                   */
    .quad   __image_size          /* image_size                        */
    .quad   0xA                   /* flags: 4 KiB pages, anywhere, LE  */
    .quad   0                     /* res2 */
    .quad   0                     /* res3 */
    .quad   0                     /* res4 */
    .ascii  "ARM\x64"             /* magic 0x644d5241 @ offset 56      */
    .long   0                     /* res5 (PE header offset)           */

    /* ---- MMU trampoline (runs at phys KERNEL_PHYS, MMU off) -------- */
    .section .text.boot, "ax"
    .global _arm_entry
_arm_entry:
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
    movz    x0, #0x0800
    movk    x0, #0x30d0, lsl #16  /* INIT_SCTLR_EL1_MMU_OFF=0x30d00800 */
    msr     sctlr_el1, x0
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

    /* ttbr1_l0[256] = l1_ident | table  (HHDM reuse)                 */
    adrp    x6, _sb_ttbr1_l0
    add     x6, x6, #:lo12:_sb_ttbr1_l0
    str     x5, [x6, #(256*8)]
    /* ttbr1_l0[511] = l1_kernel | table                             */
    adrp    x7, _sb_l1_kernel
    add     x7, x7, #:lo12:_sb_l1_kernel
    orr     x8, x7, #0x3
    str     x8, [x6, #(511*8)]
    /* l1_kernel[510] = Normal block @ KERNEL_PHYS (0x4000_0000).
       KB=0xFFFF_FFFF_8000_0000: VA[38:30]=510 selects this entry.    */
    movz    x3, #0x4000, lsl #16
    movz    x4, #0x0705
    orr     x3, x3, x4
    str     x3, [x7, #(510*8)]

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

    /* Jump to the higher-half VMA (now mapped via TTBR1). Compute it
       as phys(_arm_high) + (KB - KP) to avoid any literal-pool
       placement hazard. KB-KP = 0xFFFF_FFFF_8000_0000 - 0x4000_0000
       = 0xFFFF_FFFF_4000_0000.                                       */
    adrp    x0, _arm_high
    add     x0, x0, #:lo12:_arm_high
    movz    x1, #0x4000, lsl #16
    movk    x1, #0xFFFF, lsl #32
    movk    x1, #0xFFFF, lsl #48
    add     x0, x0, x1
    br      x0

_arm_high:
    /* breadcrumb 'E' via HHDM UART (0xFFFF_8000_0900_0000)           */
    movz    x9, #0x0900, lsl #16
    movk    x9, #0x8000, lsl #32
    movk    x9, #0xFFFF, lsl #48
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
    /* breadcrumb 'F' via HHDM UART (post-E asm tail complete)         */
    movz    x9, #0x0900, lsl #16
    movk    x9, #0x8000, lsl #32
    movk    x9, #0xFFFF, lsl #48
    mov     w10, #0x46
    str     w10, [x9]
    /* Hand DTB back in x0 and enter the shared bootloader-agnostic
       _start (it installs SP_EL1 and tail-calls _start_rust).        */
    mov     x0, x19
    b       _start

    /* ---- boot page tables (zero-init BSS, 4 KiB each) ------------- */
    .section .bss
    .align 12
_sb_ttbr0_l0:  .skip 4096
_sb_l1_ident:  .skip 4096
_sb_ttbr1_l0:  .skip 4096
_sb_l1_kernel: .skip 4096
    "#,
);
