// rtld entry + handoff (docs/59§5, docs/31§4). `_start` (asm) captures the
// initial SP and the runtime address of our own `_DYNAMIC`, then calls
// `_dl_start`, which self-relocates the rtld and runs `_dl_main`; `_dl_main`
// relocates the app the kernel already mapped and returns its entry, which
// `_start` jumps to with the original stack intact.
//
// G12d ships the minimal runnable path: self-reloc + the app's R_*_RELATIVE
// relocations + handoff (enough for a no-DT_NEEDED PIE). DT_NEEDED loading,
// the full reloc set and init_array arrive with the harness/G12e+.
#![cfg(feature = "freestanding")]
use crate::dynamic::Dyn;

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl _start",
    ".type _start,@function",
    "_start:",
    "  xor ebp, ebp",
    "  mov rdi, rsp",                  // arg1 = initial SP (→ argc)
    "  lea rsi, [rip + _DYNAMIC]",     // arg2 = runtime &_DYNAMIC
    "  call _dl_start",                // rsp is 16-aligned at entry; call/ret
    "  jmp rax",                       // balance leaves rsp at argc → jump app
);
// note: SP is 16-aligned at process entry per SysV; `call` pushes the return
// address (rsp≡8 mod 16 inside _dl_start, the correct ABI state) and `ret`
// restores rsp to the original argc pointer before `jmp rax`.

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl _start",
    ".type _start,%function",
    "_start:",
    "  mov x0, sp",                    // arg1 = initial SP
    "  adrp x1, _DYNAMIC",             // arg2 = runtime &_DYNAMIC
    "  add x1, x1, :lo12:_DYNAMIC",
    "  bl _dl_start",                  // → x0 = app entry
    "  br x0",
);

// # C: void *_dl_start(void *sp, ElfW(Dyn) *dynamic) — self-relocate, then _dl_main
#[no_mangle]
pub unsafe extern "C" fn _dl_start(sp: *const usize, dynamic: *const Dyn) -> usize {
    // SAFETY: sp is the kernel initial stack; dynamic is our own _DYNAMIC at
    // its runtime address. We self-relocate before touching any global.
    unsafe {
        let base = crate::auxv::auxval(sp, crate::auxv::AT_BASE).unwrap_or(0) as u64;
        crate::reloc::relocate_self(base, dynamic);
        _dl_main(sp)
    }
}

// Relocate the kernel-mapped app and return its entry point.
// # C: void *_dl_main(void *sp)
unsafe fn _dl_main(sp: *const usize) -> usize {
    // SAFETY: sp is the initial stack; AT_PHDR/AT_PHNUM/AT_ENTRY describe the
    // app the kernel already mapped. We read its phdrs, apply RELATIVE relocs
    // against its load bias, and return AT_ENTRY for _start to jump to.
    unsafe {
        let at_phdr = crate::auxv::auxval(sp, crate::auxv::AT_PHDR).unwrap_or(0);
        let phnum = crate::auxv::auxval(sp, crate::auxv::AT_PHNUM).unwrap_or(0);
        let entry = crate::auxv::auxval(sp, crate::auxv::AT_ENTRY).unwrap_or(0);
        if at_phdr == 0 || phnum == 0 { return entry; }
        let phdrs = core::slice::from_raw_parts(at_phdr as *const u8, phnum * crate::phdr::PHDR_SIZE);
        let bias = crate::phdr::load_bias(phdrs, phnum, at_phdr as u64).unwrap_or(0);
        if let Some(dynv) = crate::phdr::find_vaddr(phdrs, phnum, crate::phdr::PT_DYNAMIC) {
            let app_dyn = bias.wrapping_add(dynv) as *const Dyn;
            crate::reloc::relocate_self(bias, app_dyn);
        }
        entry
    }
}
