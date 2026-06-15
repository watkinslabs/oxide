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
    ".hidden _dl_start",               // direct PC-relative call (no unrelocated PLT)
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
    ".hidden _dl_start",               // direct PC-relative call (no unrelocated PLT)
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

// Link the kernel-mapped app + its DT_NEEDED graph and return its entry.
// # C: void *_dl_main(void *sp)
unsafe fn _dl_main(sp: *const usize) -> usize {
    // SAFETY: sp is the initial stack; link() reads AT_* and the app's phdrs,
    // loads dependencies, relocates the link map, runs initializers, and
    // returns AT_ENTRY for _start to jump to.
    unsafe { crate::link::link(sp) }
}
