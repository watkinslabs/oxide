// x86_64 kernel-owned GDT install per `20§3` step 2.
//
// Replaces the Limine-provided GDT with one we own, in BSS, before
// any code path requires user descriptors or a TSS. Selector offsets
// match Limine v6+ layout so `KERNEL_CS = 0x28` / `KERNEL_DS = 0x30`
// callers (`idt.rs`, `context.rs`) keep working unchanged:
//
//   sel 0x00       null
//   sel 0x08..0x20 reserved (zero — kept for selector-offset stability)
//   sel 0x28       kernel CS64 (DPL=0, L=1)
//   sel 0x30       kernel DS   (DPL=0)
//   sel 0x38       user   CS64 (DPL=3, L=1)
//   sel 0x40       user   DS   (DPL=3)
//
// TSS descriptor + `ltr` lands with the userspace `iretq` smoke
// (Phase 2, P1-82); not in scope here.
//
// Descriptor layout per Intel SDM Vol. 3 §3.4.5:
//   bits  0..15  limit_lo
//   bits 16..39  base_lo (24)
//   bits 40..47  access  (P|DPL|S|Type)
//   bits 48..51  limit_hi
//   bits 52..55  flags   (G|D/B|L|AVL)
//   bits 56..63  base_hi

use core::cell::UnsafeCell;

/// 9 entries × 8 B = 72 B. Last sel = 0x40 (user DS).
pub const GDT_LEN: usize = 9;

/// User CS64 selector (DPL=3, L=1). Wired in Phase 2 (P1-82).
/// Kernel CS/DS = 0x28 / 0x30 are exported as `idt::KERNEL_CS` and
/// hard-coded in `context.rs` per `14§R07`; not redefined here.
pub const USER_CS: u16 = 0x38 | 3;
/// User DS selector (DPL=3). Wired in Phase 2 (P1-82).
pub const USER_DS: u16 = 0x40 | 3;

/// Access-byte for a 64-bit kernel code segment: P=1 DPL=0 S=1
/// type=Execute/Read/Accessed (0xA + accessed=1 → 0xB; we set
/// accessed=0 since CPU sets it on load).
const ACCESS_KERNEL_CS: u8 = 0x9A;
/// Access-byte for a 64-bit kernel data segment: P=1 DPL=0 S=1
/// type=Read/Write.
const ACCESS_KERNEL_DS: u8 = 0x92;
/// Access-byte for a 64-bit user code segment: P=1 DPL=3 S=1 type=ER.
const ACCESS_USER_CS: u8 = 0xFA;
/// Access-byte for a user data segment: P=1 DPL=3 S=1 type=RW.
const ACCESS_USER_DS: u8 = 0xF2;

/// Flags nibble for code: G=1 (4 KiB granularity), D=0, L=1.
const FLAGS_CODE64: u8 = 0xA;
/// Flags nibble for data: G=1, D=1 (32-bit default; ignored in 64-bit
/// mode for data segments but conventional).
const FLAGS_DATA: u8 = 0xC;

/// Build an 8-byte descriptor: base=0, limit=0xFFFFF, given access +
/// flags nibble. The CPU ignores base/limit for CS/DS in 64-bit
/// mode, but the descriptor must still be well-formed.
/// # C: O(1)
const fn segment(access: u8, flags: u8) -> u64 {
    let mut d: u64 = 0;
    d |= 0xFFFF;                                  // limit_lo
    d |= (access as u64) << 40;                   // access byte
    d |= 0xF_u64 << 48;                           // limit_hi[19:16]
    d |= ((flags & 0xF) as u64) << 52;            // flags nibble
    d
}

/// GDTR operand for `lgdt`. Per Intel SDM Vol. 3 §2.4.1: 2-byte limit
/// (size − 1) + 8-byte linear base.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct GdtPointer {
    pub limit: u16,
    pub base:  u64,
}

#[repr(C, align(8))]
struct Gdt(UnsafeCell<[u64; GDT_LEN]>);

// SAFETY: cross-thread access mediated by single-threaded boot install
// (`install_kernel_gdt`); after install, entries are read-only from
// kernel code and the CPU dereferences via GDTR asynchronously.
unsafe impl Sync for Gdt {}

static GDT: Gdt = Gdt(UnsafeCell::new([0u64; GDT_LEN]));

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".intel_syntax noprefix",
    ".section .text",
    ".globl oxide_gdt_load_and_reload",
    ".type  oxide_gdt_load_and_reload, @function",
    // rdi = &GdtPointer (SysV ABI). lgdt + reload data segs to
    // KERNEL_DS, then far-return to reload CS to KERNEL_CS. The
    // far-return must use 64-bit operand size: in long mode `lret`
    // defaults to 32-bit, so we emit `.byte 0x48, 0xcb` (REX.W +
    // retf) to force a 64-bit pop of (RIP, CS).
    "oxide_gdt_load_and_reload:",
    "    lgdt [rdi]",
    "    mov  ax, 0x30",
    "    mov  ds, ax",
    "    mov  es, ax",
    "    mov  ss, ax",
    "    mov  fs, ax",
    "    mov  gs, ax",
    "    push 0x28",                       // CS selector (qword)
    "    lea  rax, [rip + 1f]",
    "    push rax",                         // target RIP
    "    .byte 0x48, 0xcb",                 // lretq (REX.W + retf)
    "1:",
    "    ret",
    ".size oxide_gdt_load_and_reload, . - oxide_gdt_load_and_reload",
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_gdt_load_and_reload(ptr: *const GdtPointer);
}

/// Populate the kernel-owned GDT and load it via `lgdt`, then reload
/// CS via far return and DS/ES/SS/FS/GS via `mov`. After return, all
/// segment registers reference the kernel-owned GDT; the bootloader's
/// GDT is no longer referenced by hardware and may be reclaimed.
///
/// # SAFETY: caller is the boot path; runs single-CPU with IRQs
/// masked, on the kernel stack mapped in the active page tables.
/// Invalidates the bootloader's GDT — must be called exactly once
/// per boot before any code that depends on user descriptors or
/// a TSS (TSS install lands with Phase 2 P1-82).
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn install_kernel_gdt() {
    // SAFETY: single-CPU boot; we own the GDT static during install.
    // `06§11` + `07§5` ban `static mut`, so write through UnsafeCell.
    let gdt = unsafe { &mut *GDT.0.get() };
    gdt[0] = 0;
    gdt[1] = 0;
    gdt[2] = 0;
    gdt[3] = 0;
    gdt[4] = 0;
    gdt[5] = segment(ACCESS_KERNEL_CS, FLAGS_CODE64); // 0x28
    gdt[6] = segment(ACCESS_KERNEL_DS, FLAGS_DATA);   // 0x30
    gdt[7] = segment(ACCESS_USER_CS,   FLAGS_CODE64); // 0x38
    gdt[8] = segment(ACCESS_USER_DS,   FLAGS_DATA);   // 0x40

    let pointer = GdtPointer {
        limit: (core::mem::size_of::<[u64; GDT_LEN]>() - 1) as u16,
        base:  gdt.as_ptr() as u64,
    };
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: pointer references the GDT static which outlives
        // the call; the asm follows SysV ABI (rdi = first arg) and
        // returns normally after CS reload. Preconditions on IRQ
        // mask and single-CPU handed down from this fn's contract.
        unsafe { oxide_gdt_load_and_reload(&pointer); }
    }
    let _ = pointer;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdt_pointer_packs_to_10_bytes() {
        // Vol. 3 §2.4.1: 2-byte limit + 8-byte base.
        assert_eq!(core::mem::size_of::<GdtPointer>(), 10);
    }

    #[test]
    fn descriptor_kernel_cs_encoding() {
        // Expected bits: limit=0xFFFFF, access=0x9A, flags=0xA, base=0.
        let d = segment(ACCESS_KERNEL_CS, FLAGS_CODE64);
        assert_eq!(d & 0xFFFF, 0xFFFF, "limit_lo");
        assert_eq!((d >> 40) & 0xFF, ACCESS_KERNEL_CS as u64, "access byte");
        assert_eq!((d >> 48) & 0xF, 0xF, "limit_hi");
        assert_eq!((d >> 52) & 0xF, FLAGS_CODE64 as u64, "flags nibble");
        assert_eq!((d >> 56) & 0xFF, 0, "base_hi");
        // L bit = bit 53; must be 1 for 64-bit code.
        assert_eq!((d >> 53) & 1, 1, "L bit (64-bit code)");
        // P bit = bit 47; must be 1.
        assert_eq!((d >> 47) & 1, 1, "P bit (present)");
        // DPL = bits 45..46; kernel = 0.
        assert_eq!((d >> 45) & 0x3, 0, "DPL=0");
    }

    #[test]
    fn descriptor_kernel_ds_encoding() {
        let d = segment(ACCESS_KERNEL_DS, FLAGS_DATA);
        assert_eq!((d >> 40) & 0xFF, 0x92);
        assert_eq!((d >> 47) & 1, 1, "P bit");
        assert_eq!((d >> 45) & 0x3, 0, "DPL=0");
        // S bit = bit 44; data = 1.
        assert_eq!((d >> 44) & 1, 1, "S=1 (code/data)");
        // Type bit 43 (executable) = 0 for data.
        assert_eq!((d >> 43) & 1, 0, "type.E=0 (data)");
    }

    #[test]
    fn descriptor_user_cs_dpl_is_3() {
        let d = segment(ACCESS_USER_CS, FLAGS_CODE64);
        assert_eq!((d >> 45) & 0x3, 3, "DPL=3");
        assert_eq!((d >> 53) & 1, 1, "L=1");
    }

    #[test]
    fn descriptor_user_ds_dpl_is_3() {
        let d = segment(ACCESS_USER_DS, FLAGS_DATA);
        assert_eq!((d >> 45) & 0x3, 3, "DPL=3");
        assert_eq!((d >> 44) & 1, 1, "S=1");
    }

    #[test]
    fn user_selectors_have_dpl_3() {
        assert_eq!(USER_CS, 0x38 | 3);
        assert_eq!(USER_DS, 0x40 | 3);
        assert_eq!(USER_CS & 3, 3);
        assert_eq!(USER_DS & 3, 3);
    }

    #[test]
    fn gdt_static_size_is_72() {
        // 9 × 8 = 72 bytes. Last entry covers selector 0x40.
        assert_eq!(core::mem::size_of::<[u64; GDT_LEN]>(), 72);
    }

    #[test]
    fn install_kernel_gdt_compiles_on_host() {
        // Hosted: asm path cfg'd out; exercises only the descriptor
        // population branch.
        // SAFETY: hosted test; the asm path is cfg'd out, so install
        // exercises only the static-array writes and pointer build.
        unsafe { install_kernel_gdt() };
    }
}
