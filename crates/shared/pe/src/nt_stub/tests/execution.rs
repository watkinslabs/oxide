//! Execute generated thunks with only syscall replaced by call rax. That call
//! installs the same return slot as native_x64_call_rsp; the mock captures the
//! boundary registers and returns through the emitted epilogue. No kernel boot.
use super::*;
use core::{ffi::c_void, mem::offset_of};

#[repr(C)]
#[derive(Default)]
struct Trace {
    input: [u64; 6],
    output: [u64; 6],
    native_rsp: u64,
    continuation: u64,
    before: u64,
    after: u64,
    rdi: u64,
    rsi: u64,
    status: u64,
    want_status: u64,
    mxcsr_before: u32,
    mxcsr_after: u32,
    xmm: [[u8; 16]; 10],
}

core::arch::global_asm!(r#"
.text
.global trampoline_invoke
trampoline_invoke:
    push r12
    push r13
    sub rsp, 56
    mov r12, rsi
    mov r13, rdi
    mov [r12 + {before}], rsp
    stmxcsr [r12 + {mxcsr_before}]
    movdqu xmm6, [r12 + {xmm} + 0]
    movdqu xmm7, [r12 + {xmm} + 16]
    movdqu xmm8, [r12 + {xmm} + 32]
    movdqu xmm9, [r12 + {xmm} + 48]
    movdqu xmm10, [r12 + {xmm} + 64]
    movdqu xmm11, [r12 + {xmm} + 80]
    movdqu xmm12, [r12 + {xmm} + 96]
    movdqu xmm13, [r12 + {xmm} + 112]
    movdqu xmm14, [r12 + {xmm} + 128]
    movdqu xmm15, [r12 + {xmm} + 144]
    mov rcx, [r12]
    mov rdx, [r12 + 8]
    mov r8, [r12 + 16]
    mov r9, [r12 + 24]
    mov rax, [r12 + 32]
    mov [rsp + 32], rax
    mov rax, [r12 + 40]
    mov [rsp + 40], rax
    mov edi, 0x13579bdf
    mov esi, 0x2468ace0
    call r13
    mov [r12 + {status}], rax
    mov [r12 + {after}], rsp
    mov [r12 + {rdi}], rdi
    mov [r12 + {rsi}], rsi
    stmxcsr [r12 + {mxcsr_after}]
    ldmxcsr [r12 + {mxcsr_before}]
    movdqu [r12 + {xmm} + 0], xmm6
    movdqu [r12 + {xmm} + 16], xmm7
    movdqu [r12 + {xmm} + 32], xmm8
    movdqu [r12 + {xmm} + 48], xmm9
    movdqu [r12 + {xmm} + 64], xmm10
    movdqu [r12 + {xmm} + 80], xmm11
    movdqu [r12 + {xmm} + 96], xmm12
    movdqu [r12 + {xmm} + 112], xmm13
    movdqu [r12 + {xmm} + 128], xmm14
    movdqu [r12 + {xmm} + 144], xmm15
    add rsp, 56
    pop r13
    pop r12
    ret

.global trampoline_unix
trampoline_unix:
    mov [rdx + {output}], rdi
    mov [rdx + {output} + 8], rsi
    mov [rdx + {output} + 16], rdx
    mov rdi, rdx
    jmp trampoline_native

.global trampoline_six
trampoline_six:
    mov [rdi + {output}], rdi
    mov [rdi + {output} + 8], rsi
    mov [rdi + {output} + 16], rdx
    mov [rdi + {output} + 24], r10
    mov [rdi + {output} + 32], r8
    mov [rdi + {output} + 40], r9
    mov [rdi + {native_rsp}], rsp
    mov rax, [rsp]
    mov [rdi + {continuation}], rax
    mov rax, [rdi + {want_status}]
    ret

trampoline_native:
    mov [rdi + {native_rsp}], rsp
    mov rax, [rsp]
    mov [rdi + {continuation}], rax
    // Use the full SysV red zone, including its lowest eightbyte.
    mov qword ptr [rsp - 128], -1
    mov qword ptr [rsp - 8], -1
    // Exception-status bits are SysV caller-saved; Wine restores MXCSR.
    stmxcsr [rsp - 16]
    xor dword ptr [rsp - 16], 1
    ldmxcsr [rsp - 16]
    pxor xmm6, xmm6
    pxor xmm7, xmm7
    pxor xmm8, xmm8
    pxor xmm9, xmm9
    pxor xmm10, xmm10
    pxor xmm11, xmm11
    pxor xmm12, xmm12
    pxor xmm13, xmm13
    pxor xmm14, xmm14
    pxor xmm15, xmm15
    mov rax, [rdi + {want_status}]
    mov rdi, -1
    mov rsi, -1
    ret
"#,
    output = const offset_of!(Trace, output),
    native_rsp = const offset_of!(Trace, native_rsp),
    continuation = const offset_of!(Trace, continuation),
    before = const offset_of!(Trace, before), after = const offset_of!(Trace, after),
    rdi = const offset_of!(Trace, rdi), rsi = const offset_of!(Trace, rsi),
    status = const offset_of!(Trace, status), want_status = const offset_of!(Trace, want_status),
    mxcsr_before = const offset_of!(Trace, mxcsr_before), mxcsr_after = const offset_of!(Trace, mxcsr_after),
    xmm = const offset_of!(Trace, xmm),
);

unsafe extern "C" {
    fn trampoline_invoke(code: *const u8, trace: *mut Trace);
    fn trampoline_unix();
    fn trampoline_six();
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut c_void;
    fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
}

struct Code { address: *mut c_void, len: usize, resume: u64 }
impl Code {
    fn new(mut bytes: Vec<u8>) -> Self {
        let sites: Vec<_> = bytes.windows(2).enumerate().filter(|(_, pair)| *pair == [0x0f, 0x05]).map(|(at, _)| at).collect();
        assert_eq!(sites.len(), 1);
        let at = sites[0];
        bytes[at..at + 2].copy_from_slice(&[0xff, 0xd0]);
        const PROT_RW: i32 = 3;
        const PROT_RX: i32 = 5;
        const MAP_PRIVATE_ANONYMOUS: i32 = 0x22;
        // SAFETY: mmap allocates fresh private storage, copied before mprotect
        // makes the generated test instructions executable and nonwritable.
        unsafe {
            let address = mmap(core::ptr::null_mut(), bytes.len(), PROT_RW, MAP_PRIVATE_ANONYMOUS, -1, 0);
            assert_ne!(address as usize, usize::MAX);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), address.cast(), bytes.len());
            let code = Self { address, len: bytes.len(), resume: address as u64 + at as u64 + 2 };
            assert_eq!(mprotect(address, bytes.len(), PROT_RX), 0);
            code
        }
    }
    fn run(&self, trace: &mut Trace) {
        // SAFETY: trampoline_invoke preserves the host SysV nonvolatiles and
        // executes only this live mapping with a writable Trace for captures.
        unsafe { trampoline_invoke(self.address.cast(), trace); }
    }
}
impl Drop for Code {
    fn drop(&mut self) {
        // SAFETY: Code owns this mmap allocation and invocation has returned.
        unsafe { assert_eq!(munmap(self.address, self.len), 0); }
    }
}

#[test]
fn unix_machine_code_round_trip_matches_handoff_and_preserves_windows_state() {
    let code = Code::new(encode_x64_unix_call_dispatcher_stub(trampoline_unix as *const () as u64));
    for status in [0, 0x1234, 0xc000_000d] {
        let mut trace = Trace { want_status: status, ..Trace::default() };
        let args = &mut trace as *mut Trace as u64;
        trace.input = [0xfeed, 0xabcd_0000_0000_0007, args, 0, 0, 0];
        let saved = core::array::from_fn(|i| [i as u8 + 1; 16]);
        trace.xmm = saved;
        code.run(&mut trace);
        assert_eq!(trace.output[..3], [0xfeed, 7, args]);
        assert_eq!(trace.before, trace.after);
        assert_eq!((trace.rdi, trace.rsi), (0x13579bdf, 0x2468ace0));
        assert_eq!(trace.xmm, saved);
        assert_eq!(trace.mxcsr_after, trace.mxcsr_before);
        assert_eq!(trace.status, status);
        assert_eq!(trace.native_rsp & 15, 8);
        let syscall_rsp = trace.native_rsp + 8;
        let call = prepare_x64_unix_call(0xfeed, 7, args, trampoline_unix as *const () as u64,
            code.resume, syscall_rsp, 1 << 47).unwrap();
        assert_eq!(native_x64_call_rsp(syscall_rsp, 1 << 47), Some(trace.native_rsp));
        assert_eq!(call.return_rip, trace.continuation);
        assert_eq!(call.return_rsp, trace.after);
        assert_eq!(trace.before - 8 - syscall_rsp, X64_UNIX_CALL_PUSH_BYTES);
        assert_eq!(complete_x64_unix_call(call, trace.status).status, status);
    }
}

#[test]
fn six_arg_machine_code_reads_windows_stack_slots_after_two_saves() {
    let code = Code::new(encode_x64_six_arg_stub(trampoline_six as *const () as u64).to_vec());
    let mut trace = Trace { want_status: 0xc000_000d, ..Trace::default() };
    trace.input = [&mut trace as *mut Trace as u64, 0x18, 0x1234_5678_abcd, 0x28, 0xabcd_1234_5678, 0x38];
    code.run(&mut trace);
    assert_eq!(trace.output, trace.input);
    assert_eq!(trace.before, trace.after);
    assert_eq!((trace.rdi, trace.rsi), (0x13579bdf, 0x2468ace0));
    assert_eq!(trace.status, trace.want_status);
    assert_eq!(trace.continuation, code.resume);
    assert_eq!(trace.before - (trace.native_rsp + 8), 24);
}
