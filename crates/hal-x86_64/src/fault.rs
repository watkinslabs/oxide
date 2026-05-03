// CPU-exception fault handler per `22§4`.
//
// Replaces the silent `cli; hlt; jmp 1b` default with per-vector stubs
// that capture the vector number, normalize the optional CPU-pushed
// error code, and tail into a Rust printer that emits a one-line
// fault summary via `klog::write_raw`. Then halts.
//
// Stack layout at `oxide_fault_common` entry (after stub pushes):
//   [rsp + 0x00]  vector       (stub-pushed)
//   [rsp + 0x08]  error_code   (CPU-pushed for vec 8/10..14/17/21,
//                               otherwise stub-pushed 0)
//   [rsp + 0x10]  RIP          (CPU-pushed)
//   [rsp + 0x18]  CS           (CPU-pushed)
//   [rsp + 0x20]  RFLAGS       (CPU-pushed)
//   [rsp + 0x28]  RSP          (CPU-pushed)
//   [rsp + 0x30]  SS           (CPU-pushed)
//
// CR2 holds the page-fault linear address for vector 14.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".intel_syntax noprefix",
    ".section .text",

    // ----- per-vector stubs --------------------------------------------------
    // Macros: with-err vs no-err. Vectors 8/10/11/12/13/14/17/21 push an
    // error code; others don't. We always synthesize a slot so the common
    // path sees a uniform layout.
    ".macro VECNE vec",         // no error code on stack
    "    push 0",
    "    push \\vec",
    "    jmp oxide_fault_common",
    ".endm",
    ".macro VECE  vec",         // error code already on stack
    "    push \\vec",
    "    jmp oxide_fault_common",
    ".endm",

    ".globl oxide_vec_0", "oxide_vec_0:",  "VECNE 0",
    ".globl oxide_vec_1", "oxide_vec_1:",  "VECNE 1",
    ".globl oxide_vec_2", "oxide_vec_2:",  "VECNE 2",
    ".globl oxide_vec_3", "oxide_vec_3:",  "VECNE 3",
    ".globl oxide_vec_4", "oxide_vec_4:",  "VECNE 4",
    ".globl oxide_vec_5", "oxide_vec_5:",  "VECNE 5",
    ".globl oxide_vec_6", "oxide_vec_6:",  "VECNE 6",
    ".globl oxide_vec_7", "oxide_vec_7:",  "VECNE 7",
    ".globl oxide_vec_8", "oxide_vec_8:",  "VECE  8",
    ".globl oxide_vec_9", "oxide_vec_9:",  "VECNE 9",
    ".globl oxide_vec_10","oxide_vec_10:", "VECE  10",
    ".globl oxide_vec_11","oxide_vec_11:", "VECE  11",
    ".globl oxide_vec_12","oxide_vec_12:", "VECE  12",
    ".globl oxide_vec_13","oxide_vec_13:", "VECE  13",
    ".globl oxide_vec_14","oxide_vec_14:", "VECE  14",
    ".globl oxide_vec_15","oxide_vec_15:", "VECNE 15",
    ".globl oxide_vec_16","oxide_vec_16:", "VECNE 16",
    ".globl oxide_vec_17","oxide_vec_17:", "VECE  17",
    ".globl oxide_vec_18","oxide_vec_18:", "VECNE 18",
    ".globl oxide_vec_19","oxide_vec_19:", "VECNE 19",
    ".globl oxide_vec_20","oxide_vec_20:", "VECNE 20",
    ".globl oxide_vec_21","oxide_vec_21:", "VECE  21",
    ".globl oxide_vec_22","oxide_vec_22:", "VECNE 22",
    ".globl oxide_vec_23","oxide_vec_23:", "VECNE 23",
    ".globl oxide_vec_24","oxide_vec_24:", "VECNE 24",
    ".globl oxide_vec_25","oxide_vec_25:", "VECNE 25",
    ".globl oxide_vec_26","oxide_vec_26:", "VECNE 26",
    ".globl oxide_vec_27","oxide_vec_27:", "VECNE 27",
    ".globl oxide_vec_28","oxide_vec_28:", "VECNE 28",
    ".globl oxide_vec_29","oxide_vec_29:", "VECNE 29",
    ".globl oxide_vec_30","oxide_vec_30:", "VECNE 30",
    ".globl oxide_vec_31","oxide_vec_31:", "VECNE 31",
    // Pooled stub for vectors >= 32 (no CPU error code).
    ".globl oxide_vec_default", "oxide_vec_default:", "VECNE 0xff",

    // ----- common path -------------------------------------------------------
    // Frame layout at stub-tail entry:
    //   [vec][err][rip][cs][rflags][rsp][ss]  = 7 × 8 = 56 bytes
    // CPU pushed 5 (no-err) or 6 (with-err) words; stub pushed 2 or 1.
    //
    // We save *all* caller-saved GPRs before calling the Rust
    // dispatcher so that on a recoverable fault (handler returns
    // true) the retry executes with the original register state
    // intact. SysV preserves rbx/rbp/r12-r15 across the call, but
    // rax/rcx/rdx/rsi/rdi/r8-r11 must be saved by us. Without this,
    // a #PF at e.g. `mov %rax, [%rsi+disp]` would retry with a
    // clobbered `%rsi` and re-fault at a garbage address.
    //
    // Stack after GPR save (10 × 8 = 80 B pushed):
    //   [rsp+0x00] r11
    //   [rsp+0x08] r10
    //   [rsp+0x10] r9
    //   [rsp+0x18] r8
    //   [rsp+0x20] rdi
    //   [rsp+0x28] rsi
    //   [rsp+0x30] rdx
    //   [rsp+0x38] rcx
    //   [rsp+0x40] rax
    //   [rsp+0x48] (pad — keeps total even × 8 so post-save rsp is
    //              16-aligned for the SysV ABI call)
    //   [rsp+0x50..]  fault frame (vec/err/rip/cs/rflags/rsp/ss)
    ".globl oxide_fault_common",
    ".type  oxide_fault_common, @function",
    "oxide_fault_common:",
    "    cld",
    "    push rax",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    sub  rsp, 8",                   // align to 16 before call
    "    lea  rdi, [rsp + 0x50]",        // arg 0 = pointer to fault frame
    "    call oxide_fault_print_rust",   // returns bool in al
    "    add  rsp, 8",                   // undo align
    "    test al, al",
    "    jnz 2f",
    "    cli",
    "1:  hlt",
    "    jmp 1b",
    "2:  pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rax",
    "    add rsp, 16",                   // drop synthetic vec + err
    "    iretq",
    ".size oxide_fault_common, . - oxide_fault_common",
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_vec_0();
    fn oxide_vec_1();
    fn oxide_vec_2();
    fn oxide_vec_3();
    fn oxide_vec_4();
    fn oxide_vec_5();
    fn oxide_vec_6();
    fn oxide_vec_7();
    fn oxide_vec_8();
    fn oxide_vec_9();
    fn oxide_vec_10();
    fn oxide_vec_11();
    fn oxide_vec_12();
    fn oxide_vec_13();
    fn oxide_vec_14();
    fn oxide_vec_15();
    fn oxide_vec_16();
    fn oxide_vec_17();
    fn oxide_vec_18();
    fn oxide_vec_19();
    fn oxide_vec_20();
    fn oxide_vec_21();
    fn oxide_vec_22();
    fn oxide_vec_23();
    fn oxide_vec_24();
    fn oxide_vec_25();
    fn oxide_vec_26();
    fn oxide_vec_27();
    fn oxide_vec_28();
    fn oxide_vec_29();
    fn oxide_vec_30();
    fn oxide_vec_31();
    fn oxide_vec_default();
}

/// Address of the per-vector stub for `vec`. Vectors >= 32 share
/// `oxide_vec_default`. On host the asm symbols are absent.
/// # C: O(1)
pub fn vector_stub_addr(vec: u8) -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let f: unsafe extern "C" fn() = match vec {
            0  => oxide_vec_0,  1  => oxide_vec_1,  2  => oxide_vec_2,  3  => oxide_vec_3,
            4  => oxide_vec_4,  5  => oxide_vec_5,  6  => oxide_vec_6,  7  => oxide_vec_7,
            8  => oxide_vec_8,  9  => oxide_vec_9,  10 => oxide_vec_10, 11 => oxide_vec_11,
            12 => oxide_vec_12, 13 => oxide_vec_13, 14 => oxide_vec_14, 15 => oxide_vec_15,
            16 => oxide_vec_16, 17 => oxide_vec_17, 18 => oxide_vec_18, 19 => oxide_vec_19,
            20 => oxide_vec_20, 21 => oxide_vec_21, 22 => oxide_vec_22, 23 => oxide_vec_23,
            24 => oxide_vec_24, 25 => oxide_vec_25, 26 => oxide_vec_26, 27 => oxide_vec_27,
            28 => oxide_vec_28, 29 => oxide_vec_29, 30 => oxide_vec_30, 31 => oxide_vec_31,
            _  => oxide_vec_default,
        };
        f as *const () as usize as u64
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    {
        let _ = vec;
        0
    }
}

/// Frame layout at `oxide_fault_common` entry — see module-level
/// stack diagram. Read once via `*const u64` offsets, never written.
#[repr(C)]
struct FaultFrame {
    vector:    u64,
    error:     u64,
    rip:       u64,
    cs:        u64,
    rflags:    u64,
    rsp:       u64,
    ss:        u64,
}

/// Read CR2 (page-fault linear address). Only meaningful for vec 14.
/// # SAFETY: privileged read; legal at CPL=0.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn read_cr2() -> u64 {
    let v: u64;
    // SAFETY: `mov rax, cr2` is privileged; legal at CPL=0; pure read.
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Rust side of the fault handler. Called from `oxide_fault_common`
/// with `frame_ptr = rsp at common entry`. Emits a one-line fault
/// summary on the boot UART then returns to the asm halt loop.
///
/// # SAFETY: caller (asm stub) passes a valid pointer to a
/// `FaultFrame` on the kernel stack. We only read.
/// # C: O(constant)
/// # Ctx: exception context, IRQs off
// Per `04§4.0` (R06): emit-path call sites gated under `debug-irq`.
// Default builds halt silently on a fault; the diagnostic dump rides
// the same gate as the rest of the IRQ/exception trace surface.
#[cfg(feature = "debug-irq")]
macro_rules! debug_irq { ($($t:tt)*) => { $($t)* } }
#[cfg(not(feature = "debug-irq"))]
macro_rules! debug_irq { ($($t:tt)*) => {} }

/// Optional fault handler. Default is `default_handler` which
/// returns `false` (= asm halts). Kernel installs a real handler
/// via `install_fault_handler` once VMM AddressSpace integration
/// is in. The returned `bool` is the recovery signal: `true` =
/// asm pops the frame and `iretq`s (CPU retries the faulting
/// instruction); `false` = asm halts forever.
pub type FaultHandler = fn(vec: u64, error: u64, rip: u64, cr2: u64) -> bool;

fn default_handler(_vec: u64, _error: u64, _rip: u64, _cr2: u64) -> bool { false }

static FAULT_HANDLER: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(default_handler as *const () as *mut ());

/// Install a kernel-side fault handler. Returns the previous one
/// so callers can compose / restore.
/// # SAFETY: caller must guarantee `h` lives for the rest of the
/// kernel's lifetime; single-CPU pre-init context (no concurrent
/// faults during the swap).
/// # C: O(1)
pub unsafe fn install_fault_handler(h: FaultHandler) -> FaultHandler {
    let new = h as *const () as *mut ();
    let prev = FAULT_HANDLER.swap(new, core::sync::atomic::Ordering::AcqRel);
    // SAFETY: `prev` was installed via this same fn (or the default
    // initialiser) which only writes valid `FaultHandler` values;
    // the transmute is sound under that single-writer invariant.
    unsafe { core::mem::transmute::<*mut (), FaultHandler>(prev) }
}

fn current_handler() -> FaultHandler {
    let p = FAULT_HANDLER.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: non-null by initialisation; written only by `install_fault_handler` with valid `FaultHandler` values.
    unsafe { core::mem::transmute::<*mut (), FaultHandler>(p) }
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_fault_print_rust(frame_ptr: *const FaultFrame) -> bool {
    // SAFETY: stub-built frame on the kernel stack, valid for read.
    let f = unsafe { &*frame_ptr };
    let cr2 = if f.vector == 14 {
        // SAFETY: read_cr2 is a privileged register read, legal at CPL=0.
        unsafe { read_cr2() }
    } else { 0 };

    // Consult the registered handler first. A resolved fault (e.g.
    // demand-page) is normal kernel operation per `11§5` — silent in
    // production, no log line. Only log loudly when we're about to
    // halt (handler returned false → unrecoverable).
    let handled = (current_handler())(f.vector, f.error, f.rip, cr2);
    if !handled {
        debug_irq! {
            klog::write_raw(b"[FAULT] vec=");
            klog::write_hex_u64(f.vector);
            klog::write_raw(b" (");
            klog::write_raw(vector_label(f.vector));
            klog::write_raw(b") err=");
            klog::write_hex_u64(f.error);
            klog::write_raw(b" rip=");
            klog::write_hex_u64(f.rip);
            klog::write_raw(b" rflags=");
            klog::write_hex_u64(f.rflags);
            if f.vector == 14 {
                klog::write_raw(b" cr2=");
                klog::write_hex_u64(cr2);
                klog::write_raw(b" pf=");
                klog::write_raw(decode_pfec(f.error));
            }
            klog::write_raw(b"\n");
        }
        #[cfg(not(feature = "debug-irq"))]
        { let _ = f; }
    }
    handled
}

/// Map an Intel-SDM exception vector to a short label (Vol. 3
/// Tab. 6-1). Returns a static byte slice; unknown vectors fall
/// through to `"reserved"`.
const fn vector_label(vec: u64) -> &'static [u8] {
    match vec {
         0 => b"#DE",        1 => b"#DB",        2 => b"NMI",        3 => b"#BP",
         4 => b"#OF",        5 => b"#BR",        6 => b"#UD",        7 => b"#NM",
         8 => b"#DF",       10 => b"#TS",       11 => b"#NP",       12 => b"#SS",
        13 => b"#GP",       14 => b"#PF",       16 => b"#MF",       17 => b"#AC",
        18 => b"#MC",       19 => b"#XM",       20 => b"#VE",       21 => b"#CP",
        _  => b"reserved",
    }
}

/// Decode the page-fault error code (PFEC) per Intel SDM Vol. 3
/// §6.15. Returns a fixed label encoding the four bits we care
/// about: P/!P (present?), W/R (write?), U/K (user/kernel?), I
/// (instruction fetch). Sixteen possible labels statically.
const fn decode_pfec(err: u64) -> &'static [u8] {
    let p   = (err & (1 << 0)) != 0;     // 1 = protection violation, 0 = not present
    let w   = (err & (1 << 1)) != 0;     // 1 = write, 0 = read
    let u   = (err & (1 << 2)) != 0;     // 1 = user, 0 = kernel
    let id  = (err & (1 << 4)) != 0;     // 1 = instruction fetch
    match (p, w, u, id) {
        (false, false, false, false) => b"NP-R-K",
        (false, false, false, true ) => b"NP-R-K-IFetch",
        (false, false, true,  false) => b"NP-R-U",
        (false, false, true,  true ) => b"NP-R-U-IFetch",
        (false, true,  false, false) => b"NP-W-K",
        (false, true,  false, true ) => b"NP-W-K-IFetch",
        (false, true,  true,  false) => b"NP-W-U",
        (false, true,  true,  true ) => b"NP-W-U-IFetch",
        (true,  false, false, false) => b"PV-R-K",
        (true,  false, false, true ) => b"PV-R-K-IFetch",
        (true,  false, true,  false) => b"PV-R-U",
        (true,  false, true,  true ) => b"PV-R-U-IFetch",
        (true,  true,  false, false) => b"PV-W-K",
        (true,  true,  false, true ) => b"PV-W-K-IFetch",
        (true,  true,  true,  false) => b"PV-W-U",
        (true,  true,  true,  true ) => b"PV-W-U-IFetch",
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_pfec, vector_label};

    #[test]
    fn vector_label_matches_intel_sdm_vol3_tab_6_1() {
        assert_eq!(vector_label(0),  b"#DE");
        assert_eq!(vector_label(13), b"#GP");
        assert_eq!(vector_label(14), b"#PF");
        assert_eq!(vector_label(99), b"reserved");
    }

    #[test]
    fn decode_pfec_writes_kernel_not_present() {
        // err = 0b00010 (W=1, P=0, U=0, I=0) — kernel write to a
        // not-present page; common kalloc failure path.
        assert_eq!(decode_pfec(0b00010), b"NP-W-K");
    }

    #[test]
    fn decode_pfec_user_protection_violation_instruction_fetch() {
        // err = 0b10101 (P=1, W=0, U=1, I=1) — user instruction
        // fetch from a no-exec mapping; the W^X enforcement signal.
        assert_eq!(decode_pfec(0b10101), b"PV-R-U-IFetch");
    }

    #[test]
    fn decode_pfec_uses_only_low_5_bits() {
        // High garbage bits don't perturb the decode.
        assert_eq!(decode_pfec(0xffff_ffff_ffff_0001), decode_pfec(0b1));
    }
}
