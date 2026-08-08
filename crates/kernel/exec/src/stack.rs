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

use crate::{uapi::*, LoadedImage};

/// SysV auxv keys (subset). Full set in the SysV auxiliary-vector UAPI.

#[cfg(target_arch = "x86_64")]
const PLATFORM: &[u8] = b"x86_64\0";
#[cfg(target_arch = "aarch64")]
const PLATFORM: &[u8] = b"aarch64\0";

/// Result of `build_user_stack`: the initial user SP plus the argv/env
/// string-block bounds the caller feeds to `AddressSpace::set_arg_env_stack`
/// (Linux `mm->arg_start`..`env_end` + `start_stack`), the source for
/// `/proc/<pid>/{cmdline,environ,stat}`. `arg_*`/`env_*` are `0` when the
/// corresponding vector is empty.
/// The credential half of the auxiliary vector (Linux's
/// `create_elf_tables`): `AT_UID`/`AT_EUID`/`AT_GID`/`AT_EGID` are the NEW
/// credentials `from_kuid_munged` through the task's user namespace, and
/// `AT_SECURE` is `bprm->secureexec`.
///
/// `AT_SECURE` is what glibc's `__libc_enable_secure` reads. On 1 the dynamic
/// loader ignores `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT` and the whole
/// `LD_*` tunables set, and glibc drops `MALLOC_*`, `GCONV_PATH`,
/// `RESOLV_HOST_CONF` and friends. A hardcoded 0 there is a privilege
/// escalation the moment anything on the system is setuid.
#[derive(Copy, Clone, Debug, Default)]
pub struct AuxCreds {
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    pub secure: bool,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct StackLayout {
    pub sp:        u64,
    pub arg_start: u64,
    pub arg_end:   u64,
    pub env_start: u64,
    pub env_end:   u64,
    /// The auxiliary vector written onto the stack, for the mm's
    /// `saved_auxv` copy (Linux fills `mm->saved_auxv`
    /// FIRST and copies it to the stack from there). `prctl(PR_GET_AUXV)`
    /// and `/proc/<pid>/auxv` serve that copy, so it has to survive here.
    pub auxv:      [(u64, u64); AUXV_SLOTS],
    pub auxv_len:  usize,
}

/// Entries `build_user_stack` can carry into `StackLayout::auxv`.
pub const AUXV_SLOTS: usize = 24;

/// Build the initial user stack in `[stack_top - stack_len, stack_top)`.
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
///                         │ envp[*] strings (NUL-term; envp[0] low→envp[last] high)
///                         │ argv[*] strings (NUL-term; argv[0] low→argv[last] high)
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
    stack_len: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    img:  &LoadedImage,
    random16: &[u8; 16],
    exec_path: &[u8],
    vdso_ehdr: u64,
    hwcap: u64,
    hwcap2: u64,
    creds: AuxCreds,
    min_sigstksz: u64,
    rnd: &aslr::ExecRnd,
) -> Option<StackLayout> {
    // Linux `create_elf_tables` opens with `p = arch_align_stack(p)`
    // — a sub-page shuffle of the string area so
    // sibling processes on an SMT pair do not share L1 cache sets, then a hard
    // 16-byte align for the SysV ABI. Applied to the cursor before the first
    // push, which is exactly where Linux applies it.
    let mut cursor = rnd.align_stack(stack_top);

    // 1. Strings region (top-down): random, platform, execfn,
    //    argv[*], envp[*]. Track the user VA each lands at.
    // SAFETY: caller activated the destination AS so each push lands in the active CR3's user PT; user_fault_handler resolves the stack page on demand.
    let random_va  = unsafe { push_bytes(&mut cursor, random16) }?;
    // SAFETY: same as above; PLATFORM is a 'static byte slice, in-bounds writes only.
    let platform_va = unsafe { push_bytes(&mut cursor, PLATFORM) }?;

    // F62 attempted to set AT_EXECFN to the real exec path — but that
    // broke the shell's startup path. Revert to the legacy argv[0]
    // value while we investigate.
    let _ = exec_path;
    let execfn_bytes: &[u8] = if !argv.is_empty() { argv[0] } else { b"\0" };
    // SAFETY: same as above; bytes len is bounded by caller-supplied argv slice.
    let execfn_va = unsafe { push_cstr(&mut cursor, execfn_bytes) }?;

    // Push envp then argv, each from the LAST element to the FIRST. The
    // cursor moves top-down, so pushing last→first makes the WITHIN-block
    // memory order FORWARD — argv[0] at the LOWEST address, argv[last] just
    // below envp[0] — byte-for-byte matching Linux's `copy_strings`
    // (so `/proc/<pid>/cmdline` reads argv[0]\0argv[1]\0… in order). envp is
    // pushed first so the env block sits ABOVE the argv block: util-linux
    // login's process_title_init needs env strings above argv[0], else its
    //   argv_lth = envp[last] + strlen(envp[last]) - argv[0]
    // underflows to a huge size_t and the memset faults. VAs are stored at
    // their ORIGINAL index so the pointer vectors below stay forward
    // (argv[0] pointer first).
    if argv.len() > 256 || envp.len() > 256 { return None; }
    let mut envp_vas = [0u64; 256];
    for i in (0..envp.len()).rev() {
        // SAFETY: same as above; envp element pushed onto stack.
        envp_vas[i] = unsafe { push_cstr(&mut cursor, envp[i]) }?;
    }
    let mut argv_vas = [0u64; 256];
    for i in (0..argv.len()).rev() {
        // SAFETY: same as above; argv element pushed onto stack.
        argv_vas[i] = unsafe { push_cstr(&mut cursor, argv[i]) }?;
    }

    // 2. Compute total size of the pointer/auxv vector area, then
    //    align the resulting SP down to 16. The vector area is
    //    written bottom-up (low → high) starting at `vec_base`.
    let auxv: [(u64, u64); 20] = [
        (AT_PHDR,    img.phdr_va),
        (AT_PHENT,   img.phentsize as u64),
        (AT_PHNUM,   img.phnum as u64),
        (AT_PAGESZ,  crate::PAGE),
        (AT_BASE,    img.interp_base),
        (AT_FLAGS,   0),
        (AT_ENTRY,   img.entry.as_u64()),
        (AT_UID,     creds.uid  as u64),
        (AT_EUID,    creds.euid as u64),
        (AT_GID,     creds.gid  as u64),
        (AT_EGID,    creds.egid as u64),
        (AT_SECURE,  creds.secure as u64),
        (AT_PLATFORM, platform_va),
        (AT_EXECFN,  execfn_va),
        (AT_RANDOM,  random_va),
        (AT_HWCAP,   hwcap),
        (AT_HWCAP2,  hwcap2),
        (AT_CLKTCK,  syscall::rusage::USER_HZ),
        (AT_MINSIGSTKSZ, min_sigstksz),
        // 0 = "no vDSO mapped" — glibc / musl skip the AT_SYSINFO_EHDR
        // entry under that value. Non-zero = vDSO load VA per K14.
        (AT_SYSINFO_EHDR, vdso_ehdr),
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

    // Linux `setup_arg_pages` fails the exec with E2BIG when the argument
    // block will not fit under `RLIMIT_STACK`. `stack_len` is what the caller
    // actually mapped at `[stack_top - stack_len, stack_top)`; writing below it
    // faults in kernel context, where no handler can demand-page it. A fixed
    // 64 KiB bound lived here before and silently capped every process's
    // argv+env at 64 KiB regardless of its real stack limit.
    if sp < stack_top.saturating_sub(stack_len) { return None; }

    // 3. Write the vector area at sp, low → high.
    let mut w = sp;
    // SAFETY: caller activated the destination AS; sp is computed within the reserved range; each write_u64 advances by 8 bytes within bounds tracked above.
    unsafe {
        write_u64(&mut w, argv.len() as u64);   // argc
        for i in 0..argv.len() { write_u64(&mut w, argv_vas[i]); }
        write_u64(&mut w, 0);                    // argv NULL
        for i in 0..envp.len() { write_u64(&mut w, envp_vas[i]); }
        write_u64(&mut w, 0);                    // envp NULL
        for &(k, v) in auxv.iter() {
            write_u64(&mut w, k);
            write_u64(&mut w, v);
        }
        write_u64(&mut w, AT_NULL);
        write_u64(&mut w, 0);
    }

    let _ = AT_IGNORE;                       // silence unused

    // argv/env string-block bounds (Linux `mm->arg_start`..`env_end`).
    // Forward layout: argv[0] is the LOWEST arg VA (arg_start), argv[last]
    // the highest; arg_end = past argv[last]'s NUL. Same for env. So
    // `/proc/<pid>/cmdline` reads [arg_start,arg_end) = argv[0]\0…argv[last]\0
    // in order, exactly like Linux. 0/0 when the vector is empty.
    let bounds = |vas: &[u64; 256], v: &[&[u8]]| -> (u64, u64) {
        if v.is_empty() { return (0, 0); }
        let n = v.len();
        let lo = vas[0];
        let hi = vas[n - 1] + v[n - 1].len() as u64 + 1;
        (lo, hi)
    };
    let (arg_start, arg_end) = bounds(&argv_vas, argv);
    let (env_start, env_end) = bounds(&envp_vas, envp);
    let mut saved = [(0u64, 0u64); AUXV_SLOTS];
    let n = core::cmp::min(auxv.len(), AUXV_SLOTS);
    saved[..n].copy_from_slice(&auxv[..n]);
    Some(StackLayout { sp, arg_start, arg_end, env_start, env_end, auxv: saved, auxv_len: n })
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
