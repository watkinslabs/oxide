// Initial user-stack layout for execve per docs/31§4 step 5 +
// SysV x86_64 / AArch64 ABI. Builds the canonical
//   [argc, argv*, NULL, envp*, NULL, auxv*, AT_NULL, ..., strings]
// structure at the top of the user stack VMA, returns the new SP
// for the syscall epilogue's `sysretq` / `eret`.
//
// Caller must ACTIVATE the new AS (CR3 / TTBR0 = new_root) before
// calling so the kernel-side direct writes against user VAs land
// in the new AS's PT. Pages demand-fault via `user_fault_handler`
// on first kernel write per `11§5`.

#![cfg(target_os = "oxide-kernel")]

use crate::elf_load::LoadedImage;

/// SysV auxv keys (subset). Full set in `linux/auxvec.h`.
const AT_NULL:    u64 = 0;
const AT_IGNORE:  u64 = 1;
const AT_PHDR:    u64 = 3;
const AT_PHENT:   u64 = 4;
const AT_PHNUM:   u64 = 5;
const AT_PAGESZ:  u64 = 6;
const AT_BASE:    u64 = 7;
const AT_FLAGS:   u64 = 8;
const AT_ENTRY:   u64 = 9;
const AT_UID:     u64 = 11;
const AT_EUID:    u64 = 12;
const AT_GID:     u64 = 13;
const AT_EGID:    u64 = 14;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP:   u64 = 16;
const AT_CLKTCK:  u64 = 17;
const AT_SECURE:  u64 = 23;
const AT_RANDOM:  u64 = 25;
const AT_EXECFN:  u64 = 31;

#[cfg(target_arch = "x86_64")]
const PLATFORM: &[u8] = b"x86_64\0";
#[cfg(target_arch = "aarch64")]
const PLATFORM: &[u8] = b"aarch64\0";

/// Build the initial user stack at `[stack_top - SIZE, stack_top)`.
/// `argv`/`envp` are slices of NUL-free byte strings; the builder
/// adds the trailing NUL. Returns the new SP (16-byte aligned,
/// pointing at the `argc` slot) on success, `None` if the
/// computed layout would not fit in a single 4 KiB page.
///
/// Layout (high → low):
/// ```text
///   stack_top           ──┐
///                         │ random16 (AT_RANDOM target)
///                         │ platform string
///                         │ execfn string
///                         │ argv[*] strings (NUL-terminated)
///                         │ envp[*] strings (NUL-terminated)
///                         │ ── 16-byte alignment pad
///                         │ auxv [(AT_NULL,0)]   ← terminator
///                         │ auxv [...]
///                         │ envp NULL
///                         │ envp[N-1] ... envp[0]
///                         │ argv NULL
///                         │ argv[argc-1] ... argv[0]
///   sp →                  │ argc
/// ```
/// # SAFETY: caller activated the destination AS (`MmuOps::activate`)
/// so the kernel-side direct writes land in the user PT; user_fault_handler
/// resolves any not-present stack pages.
/// # C: O(strings_total + auxv_count)
pub unsafe fn build_user_stack(
    stack_top: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    img:  &LoadedImage,
    random16: &[u8; 16],
) -> Option<u64> {
    let mut cursor = stack_top;

    // 1. Strings region (top-down): random, platform, execfn,
    //    argv[*], envp[*]. Track the user VA each lands at.
    // SAFETY: caller activated the destination AS so each push lands in the active CR3's user PT; user_fault_handler resolves the stack page on demand.
    let random_va  = unsafe { push_bytes(&mut cursor, random16) }?;
    // SAFETY: same as above; PLATFORM is a 'static byte slice, in-bounds writes only.
    let platform_va = unsafe { push_bytes(&mut cursor, PLATFORM) }?;

    let execfn_bytes: &[u8] = if !argv.is_empty() { argv[0] } else { b"\0" };
    // SAFETY: same as above; bytes len is bounded by caller-supplied argv slice.
    let execfn_va = unsafe { push_cstr(&mut cursor, execfn_bytes) }?;

    let mut argv_vas: heapless8 = heapless8::new();
    for s in argv {
        // SAFETY: same as above; argv element pushed onto stack.
        let va = unsafe { push_cstr(&mut cursor, s) }?;
        argv_vas.push(va)?;
    }
    let mut envp_vas: heapless8 = heapless8::new();
    for s in envp {
        // SAFETY: same as above; envp element pushed onto stack.
        let va = unsafe { push_cstr(&mut cursor, s) }?;
        envp_vas.push(va)?;
    }

    // 2. Compute total size of the pointer/auxv vector area, then
    //    align the resulting SP down to 16. The vector area is
    //    written bottom-up (low → high) starting at `vec_base`.
    let auxv: [(u64, u64); 17] = [
        (AT_PHDR,    img.phdr_va),
        (AT_PHENT,   img.phentsize as u64),
        (AT_PHNUM,   img.phnum as u64),
        (AT_PAGESZ,  4096),
        (AT_BASE,    img.interp_base),
        (AT_FLAGS,   0),
        (AT_ENTRY,   img.entry.as_u64()),
        (AT_UID,     0),
        (AT_EUID,    0),
        (AT_GID,     0),
        (AT_EGID,    0),
        (AT_SECURE,  0),
        (AT_PLATFORM, platform_va),
        (AT_EXECFN,  execfn_va),
        (AT_RANDOM,  random_va),
        (AT_HWCAP,   0),
        (AT_CLKTCK,  100),
    ];
    let n_auxv = auxv.len() + 1;          // + AT_NULL terminator
    let n_argv = argv.len() + 1;          // + NULL
    let n_envp = envp.len() + 1;          // + NULL
    let words  = 1 + n_argv + n_envp + 2 * n_auxv; // argc + ptrs + auxv pairs
    let bytes  = words * 8;

    // Cursor currently points at the top of the strings region's
    // bottom byte. Reserve `bytes` below it, aligned down to 16.
    let raw_sp = cursor.checked_sub(bytes as u64)?;
    let sp = raw_sp & !0xfu64;

    if sp < stack_top.saturating_sub(0x1000) {
        // Single 4 KiB stack page is not enough; v1 caller
        // pre-mmaps exactly one page.
        return None;
    }

    // 3. Write the vector area at sp, low → high.
    let mut w = sp;
    // SAFETY: caller activated the destination AS; sp is computed within the reserved range; each write_u64 advances by 8 bytes within bounds tracked above.
    unsafe {
        write_u64(&mut w, argv.len() as u64);   // argc
        for &va in argv_vas.as_slice() { write_u64(&mut w, va); }
        write_u64(&mut w, 0);                    // argv NULL
        for &va in envp_vas.as_slice() { write_u64(&mut w, va); }
        write_u64(&mut w, 0);                    // envp NULL
        for &(k, v) in auxv.iter() {
            write_u64(&mut w, k);
            write_u64(&mut w, v);
        }
        write_u64(&mut w, AT_NULL);
        write_u64(&mut w, 0);
    }

    let _ = AT_IGNORE;                       // silence unused
    Some(sp)
}

/// Push a byte slice to the user stack at `*cursor`, decrementing
/// `*cursor`. No NUL added. Returns the user VA the bytes start at.
unsafe fn push_bytes(cursor: &mut u64, bytes: &[u8]) -> Option<u64> {
    let n = bytes.len() as u64;
    let dst = cursor.checked_sub(n)?;
    // SAFETY: caller activated the destination AS so the user VA is the active CR3's translation; CPL=0 writes through user pages directly per `15§3`; user_fault_handler resolves any not-present stack page on demand.
    unsafe {
        for i in 0..bytes.len() {
            core::ptr::write_volatile((dst + i as u64) as *mut u8, bytes[i]);
        }
    }
    *cursor = dst;
    Some(dst)
}

/// Like `push_bytes` but appends a trailing NUL.
unsafe fn push_cstr(cursor: &mut u64, bytes: &[u8]) -> Option<u64> {
    // SAFETY: each byte write is bounded; cursor decremented sequentially per push_bytes contract; both push_bytes calls share the same active-AS precondition.
    unsafe {
        let _ = push_bytes(cursor, &[0u8])?;
        push_bytes(cursor, bytes)
    }
}

/// Write a u64 at `*w`, advancing.
unsafe fn write_u64(w: &mut u64, val: u64) {
    // SAFETY: caller activated the destination AS; user_fault_handler resolves any not-present stack page; 8-byte aligned write into user mapping.
    unsafe { core::ptr::write_volatile(*w as *mut u64, val); }
    *w += 8;
}

/// Tiny stack-allocated Vec<u64, 8>. Avoids alloc::Vec inside the
/// no_std stack builder (we run pre-`activate` and want zero
/// alloc-side faults).
struct heapless8 { items: [u64; 8], len: usize }

#[allow(non_camel_case_types)]
impl heapless8 {
    const fn new() -> Self { Self { items: [0; 8], len: 0 } }
    fn push(&mut self, v: u64) -> Option<()> {
        if self.len == 8 { None } else { self.items[self.len] = v; self.len += 1; Some(()) }
    }
    fn as_slice(&self) -> &[u64] { &self.items[..self.len] }
}
