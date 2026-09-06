/// Length of the x86-64 NTDLL thunk for a one-request-pointer service.
pub const X64_UNARY_STUB_BYTES: usize = 18;
pub const X64_ZERO_ARG_STUB_BYTES: usize = 13;
pub const X64_SIX_ARG_STUB_BYTES: usize = 39;
pub const X64_BREAKPOINT_STUB_BYTES: usize = 2;
pub const X64_RELAY_STUB_BYTES: usize = 233;
const STATUS_PROCEDURE_NOT_FOUND: u32 = 0xc000_007a;

/// Wine's x86-64 `exc_stack_layout` contract passed to
/// `KiUserExceptionDispatcher`.  These offsets are part of the user ABI, not
/// an implementation detail of the kernel exception path.
pub const X64_EXCEPTION_CONTEXT_OFFSET: u64 = 0x000;
pub const X64_EXCEPTION_CONTEXT_EX_OFFSET: u64 = 0x4d0;
pub const X64_EXCEPTION_RECORD_OFFSET: u64 = 0x4f0;
pub const X64_EXCEPTION_MACHINE_FRAME_OFFSET: u64 = 0x590;
pub const X64_EXCEPTION_FRAME_BYTES: u64 = 0x5c0;

const X64_UNIX_CALL_XMM_BYTES: u32 = 10 * 16;
const X64_UNIX_CALL_LOCAL_BYTES: u32 = X64_UNIX_CALL_XMM_BYTES + 8;
/// Two GPR saves, ten XMM saves, and an MXCSR/alignment slot before `syscall`.
pub const X64_UNIX_CALL_PUSH_BYTES: u64 = 16 + X64_UNIX_CALL_LOCAL_BYTES as u64;
/// Bytes between the syscall-time stack pointer and the caller's continuation:
/// all callee-owned storage plus the return address consumed by `ret`.
pub const X64_UNIX_CALL_RETURN_BYTES: u64 = X64_UNIX_CALL_PUSH_BYTES + 8;

/// Validated handoff from the published Unixlib table to one NT dispatch.
/// `syscall_rsp` points at the saved XMM area; `return_rip` resumes the stub
/// epilogue, while `return_rsp` describes the caller's stack after its `ret`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct X64UnixCallHandoff {
    pub handle: u64,
    pub code: u32,
    pub args: u64,
    pub callable: u64,
    pub return_rip: u64,
    pub syscall_rsp: u64,
    pub return_rsp: u64,
}

/// The sole return channel for one completed native Unixlib call.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct X64UnixCallReturn {
    pub call: X64UnixCallHandoff,
    pub status: u64,
}

/// Build the typed x86-64 call/return transaction after the ELF table lookup.
/// This validates only ABI/frame facts; the caller owns descriptor membership
/// and executable-range validation before supplying `callable`.
pub fn prepare_x64_unix_call(handle: u64, code: u64, args: u64, callable: u64,
    return_rip: u64, syscall_rsp: u64, user_va_end: u64) -> Option<X64UnixCallHandoff> {
    if handle == 0 || code > u32::MAX as u64 || callable == 0 || return_rip == 0
        || return_rip >= user_va_end || syscall_rsp == 0 || syscall_rsp & 15 != 0 {
        return None;
    }
    let return_rsp = syscall_rsp.checked_add(X64_UNIX_CALL_RETURN_BYTES)?;
    if return_rsp >= user_va_end || syscall_rsp < X64_UNIX_CALL_PUSH_BYTES {
        return None;
    }
    Some(X64UnixCallHandoff { handle, code: code as u32, args, callable,
        return_rip, syscall_rsp, return_rsp })
}

/// Compute the user stack presented to one native SysV Unixlib entry. The
/// syscall frame points at Wine's saved-register area; one return slot below
/// it makes the native `ret` continue through Wine's existing epilogue.
pub fn native_x64_call_rsp(syscall_rsp: u64, user_va_end: u64) -> Option<u64> {
    if syscall_rsp == 0 || syscall_rsp >= user_va_end || syscall_rsp & 15 != 0 || syscall_rsp < 8 { return None; }
    let native_rsp = syscall_rsp.checked_sub(8)?;
    if native_rsp == 0 || native_rsp >= user_va_end { return None; }
    Some(native_rsp)
}

/// Complete one validated Unix-call transaction with the NTSTATUS returned by
/// its canonical slot. No alternate return channel or callback is permitted.
pub fn complete_x64_unix_call(call: X64UnixCallHandoff, status: u64) -> X64UnixCallReturn {
    X64UnixCallReturn { call, status }
}

/// Windows x64 rejects an unwind target below the active stack frame.  Keep
/// this arithmetic independent of the kernel so the target-gated transfer
/// path and hosted contract test use one decision.
pub fn valid_x64_unwind_target(current_rsp: u64, end_frame: u64) -> bool {
    end_frame >= current_rsp && end_frame.checked_add(8).is_some()
}

/// Addresses of the fixed portions of one Wine x86-64 exception frame.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct X64ExceptionFrame {
    pub stack: u64,
    pub context: u64,
    pub exception_record: u64,
    pub machine_frame: u64,
}

/// Compute the 64-byte-aligned user stack address used by Wine when entering
/// `KiUserExceptionDispatcher`.  Keeping this arithmetic in the shared PE
/// contract prevents the kernel and runtime from developing separate frame
/// layouts; callers still own the user-access validation and writes.
pub fn x64_exception_stack(user_rsp: u64, xstate_bytes: u64) -> Option<u64> {
    user_rsp.checked_sub(X64_EXCEPTION_FRAME_BYTES)?.checked_sub(xstate_bytes)
        .map(|address| address & !63)
}

/// Derive every fixed frame address before any user-memory writes occur.
/// Keeping the offsets together makes partial frame construction impossible
/// for callers that use the returned contract as one transaction.
pub fn x64_exception_frame(user_rsp: u64, xstate_bytes: u64) -> Option<X64ExceptionFrame> {
    let stack = x64_exception_stack(user_rsp, xstate_bytes)?;
    Some(X64ExceptionFrame {
        stack,
        context: stack.checked_add(X64_EXCEPTION_CONTEXT_OFFSET)?,
        exception_record: stack.checked_add(X64_EXCEPTION_RECORD_OFFSET)?,
        machine_frame: stack.checked_add(X64_EXCEPTION_MACHINE_FRAME_OFFSET)?,
    })
}

/// Prove that the complete dispatcher frame is contained by one writable VMA
/// before a caller performs its single user-memory transaction.
pub fn valid_x64_exception_frame_range(stack: u64, vma_start: u64, vma_end: u64, writable: bool) -> bool {
    writable && stack >= vma_start && stack.checked_add(X64_EXCEPTION_FRAME_BYTES).is_some_and(|end| end <= vma_end)
}

/// Encode Wine's Unix-call dispatcher ABI: `(unixlib_handle, code, args)` in
/// the Windows x64 registers becomes `(rdi, rsi, rdx)` for the NT entry.
pub fn encode_x64_unix_call_dispatcher_stub(selector: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x57, 0x56]); // preserve Windows nonvolatiles
    // RSP is aligned before the synthetic SysV return slot is installed.
    // SysV callees may destroy every XMM register; Windows owns XMM6..15.
    code.extend_from_slice(&[0x48, 0x81, 0xec]);
    code.extend_from_slice(&X64_UNIX_CALL_LOCAL_BYTES.to_le_bytes());
    unix_call_xmm(&mut code, false);
    code.extend_from_slice(&[0x0f, 0xae, 0x9c, 0x24]); // stmxcsr [rsp+disp32]
    code.extend_from_slice(&X64_UNIX_CALL_XMM_BYTES.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0xcf, 0x89, 0xd6, 0x4c, 0x89, 0xc2]);
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&selector.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05]);
    code.extend_from_slice(&[0x0f, 0xae, 0x94, 0x24]); // ldmxcsr [rsp+disp32]
    code.extend_from_slice(&X64_UNIX_CALL_XMM_BYTES.to_le_bytes());
    unix_call_xmm(&mut code, true);
    code.extend_from_slice(&[0x48, 0x81, 0xc4]);
    code.extend_from_slice(&X64_UNIX_CALL_LOCAL_BYTES.to_le_bytes());
    code.extend_from_slice(&[0x5e, 0x5f, 0xc3]);
    code
}

fn unix_call_xmm(code: &mut Vec<u8>, restore: bool) {
    for register in 6u8..16 {
        code.push(0x66);
        if register >= 8 { code.push(0x44); }
        code.extend_from_slice(&[0x0f, if restore { 0x6f } else { 0x7f }, 0x84 | ((register & 7) << 3), 0x24]);
        code.extend_from_slice(&(u32::from(register - 6) * 16).to_le_bytes());
    }
}

/// Encode the x86-64 Wine syscall dispatcher ABI used by win32u and ntdll.
/// Wine places the syscall ordinal in EAX and passes the Windows ABI argument
/// list in registers plus the caller stack; Oxide receives the ordinal in RDI
/// and a contiguous seventeen-slot argument array in RSI.
pub fn encode_x64_wine_dispatcher_stub(selector: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x53, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x56, 0x57]);
    code.extend_from_slice(&[0x4c, 0x8d, 0x64, 0x24, 0x40]); // r12 = entry rsp
    code.extend_from_slice(&[0x41, 0x89, 0xc5]); // r13d = Wine ordinal; stack loads below use rax
    // The copied argument envelope contains all seventeen Windows parameters
    // (four register arguments plus thirteen stack arguments). Keep it in a
    // distinct local area and pass that area's address, not the saved-register
    // prefix, to the tagged NT service.
    code.extend_from_slice(&[0x48, 0x81, 0xec, 0xb8, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0x48, 0x89, 0x0c, 0x24, 0x48, 0x89, 0x54, 0x24, 0x08]);
    code.extend_from_slice(&[0x4c, 0x89, 0x44, 0x24, 0x10, 0x4c, 0x89, 0x4c, 0x24, 0x18]);
    for index in 4..17u32 {
        let source = 0x28 + (index - 4) * 8;
        let target = 0x20 + index * 8;
        code.extend_from_slice(&[0x49, 0x8b, 0x84, 0x24]);
        code.extend_from_slice(&source.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x84, 0x24]);
        code.extend_from_slice(&target.to_le_bytes());
    }
    for (source, target) in [(0u32, 0x20u32), (8, 0x28), (16, 0x30), (24, 0x38)] {
        code.extend_from_slice(&[0x48, 0x8b, 0x84, 0x24]);
        code.extend_from_slice(&source.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x84, 0x24]);
        code.extend_from_slice(&target.to_le_bytes());
    }
    code.extend_from_slice(&[0x44, 0x89, 0xef, 0x48, 0x8d, 0x74, 0x24, 0x20, 0x48, 0xb8]);
    code.extend_from_slice(&selector.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0x48, 0x81, 0xc4, 0xb8, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0x5f, 0x5e, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5d, 0x5b, 0xc3]);
    code
}

/// Encode the native relay resolver used as Wine's per-module `relay_call`.
/// The Wine thunk has already saved the original Windows register arguments in
/// its home area before entering this function. Translate the Windows relay
/// call `(descriptor, index, stack)` into Oxide's syscall ABI
/// `(rdi, rsi, rdx)`. The NT service returns the original target; this stub
/// restores the Windows arguments, calls it, and returns with the caller's
/// stack unchanged.
pub fn encode_x64_relay_stub(selector: u64) -> [u8; X64_RELAY_STUB_BYTES] {
    let mut code = [0u8; X64_RELAY_STUB_BYTES];
    let mut at = 0;
    code[at] = 0x53; at += 1; // save Windows nonvolatile rbx
    code[at] = 0x55; at += 1; // save Windows nonvolatile rbp
    code[at..at + 2].copy_from_slice(&[0x41, 0x54]); at += 2; // save Windows nonvolatile r12
    code[at..at + 2].copy_from_slice(&[0x41, 0x55]); at += 2; // save Windows nonvolatile r13
    code[at..at + 2].copy_from_slice(&[0x41, 0x56]); at += 2; // save Windows nonvolatile r14
    code[at..at + 2].copy_from_slice(&[0x41, 0x57]); at += 2; // save Windows nonvolatile r15
    code[at] = 0x56; at += 1; // save Windows nonvolatile rsi
    code[at] = 0x57; at += 1; // save Windows nonvolatile rdi
    code[at..at + 4].copy_from_slice(&[0x4c, 0x8d, 0x64, 0x24]); at += 4;
    code[at] = 72; at += 1; // r12 = first thunk argument: return address + eight saved registers
    code[at..at + 3].copy_from_slice(&[0x48, 0x89, 0xcf]); at += 3; // rdi = descriptor (rcx)
    code[at..at + 3].copy_from_slice(&[0x48, 0x89, 0xd6]); at += 3; // rsi = relay index (rdx)
    code[at..at + 5].copy_from_slice(&[0x49, 0x8d, 0x54, 0x24, 0]); at += 5; // rdx = Wine's contiguous argument array
    code[at..at + 2].copy_from_slice(&[0x48, 0xb8]); at += 2;
    code[at..at + 8].copy_from_slice(&selector.to_le_bytes()); at += 8;
    code[at..at + 2].copy_from_slice(&[0x0f, 0x05]); at += 2;
    code[at..at + 3].copy_from_slice(&[0x48, 0x85, 0xc0]); at += 3; // unresolved target is the only non-call result
    code[at..at + 2].copy_from_slice(&[0x0f, 0x84]); at += 2;
    let unresolved_branch = at; at += 4;
    code[at..at + 5].copy_from_slice(&[0x4c, 0x8d, 0x64, 0x24, 72]); at += 5; // re-derive args after syscall restores registers
    code[at..at + 4].copy_from_slice(&[0x48, 0x83, 0xec, 0x60]); at += 4; // target home + eight stack arguments, 16-byte aligned
    code[at..at + 5].copy_from_slice(&[0x4d, 0x8b, 0x54, 0x24, 0]); at += 5;
    code[at..at + 4].copy_from_slice(&[0x4c, 0x89, 0x14, 0x24]); at += 4;
    code[at..at + 5].copy_from_slice(&[0x4d, 0x8b, 0x54, 0x24, 8]); at += 5;
    code[at..at + 5].copy_from_slice(&[0x4c, 0x89, 0x54, 0x24, 8]); at += 5;
    code[at..at + 5].copy_from_slice(&[0x4d, 0x8b, 0x54, 0x24, 16]); at += 5;
    code[at..at + 5].copy_from_slice(&[0x4c, 0x89, 0x54, 0x24, 16]); at += 5;
    code[at..at + 5].copy_from_slice(&[0x4d, 0x8b, 0x54, 0x24, 24]); at += 5;
    code[at..at + 5].copy_from_slice(&[0x4c, 0x89, 0x54, 0x24, 24]); at += 5;
    for (source, target) in [(32, 32), (40, 40), (48, 48), (56, 56), (64, 64), (72, 72), (80, 80), (88, 88)] {
        code[at..at + 5].copy_from_slice(&[0x4d, 0x8b, 0x54, 0x24, source]); at += 5;
        code[at..at + 5].copy_from_slice(&[0x4c, 0x89, 0x54, 0x24, target]); at += 5;
    }
    code[at..at + 4].copy_from_slice(&[0x48, 0x8b, 0x0c, 0x24]); at += 4;
    code[at..at + 5].copy_from_slice(&[0x48, 0x8b, 0x54, 0x24, 8]); at += 5;
    code[at..at + 5].copy_from_slice(&[0x4c, 0x8b, 0x44, 0x24, 16]); at += 5;
    code[at..at + 5].copy_from_slice(&[0x4c, 0x8b, 0x4c, 0x24, 24]); at += 5;
    code[at..at + 2].copy_from_slice(&[0xff, 0xd0]); at += 2;
    code[at..at + 4].copy_from_slice(&[0x48, 0x83, 0xc4, 0x60]); at += 4;
    code[at] = 0x5f; at += 1; // restore rdi
    code[at] = 0x5e; at += 1; // restore rsi
    code[at..at + 2].copy_from_slice(&[0x41, 0x5f]); at += 2; // restore r15
    code[at..at + 2].copy_from_slice(&[0x41, 0x5e]); at += 2; // restore r14
    code[at..at + 2].copy_from_slice(&[0x41, 0x5d]); at += 2; // restore r13
    code[at..at + 2].copy_from_slice(&[0x41, 0x5c]); at += 2; // restore r12
    code[at] = 0x5d; at += 1; // restore rbp
    code[at] = 0x5b; at += 1; // restore rbx
    code[at] = 0xc3; at += 1;
    let unresolved = at;
    code[at] = 0xb8; at += 1;
    code[at..at + 4].copy_from_slice(&STATUS_PROCEDURE_NOT_FOUND.to_le_bytes()); at += 4;
    code[at] = 0x5f; at += 1;
    code[at] = 0x5e; at += 1;
    code[at..at + 2].copy_from_slice(&[0x41, 0x5f]); at += 2;
    code[at..at + 2].copy_from_slice(&[0x41, 0x5e]); at += 2;
    code[at..at + 2].copy_from_slice(&[0x41, 0x5d]); at += 2;
    code[at..at + 2].copy_from_slice(&[0x41, 0x5c]); at += 2;
    code[at] = 0x5d; at += 1;
    code[at] = 0x5b; at += 1;
    code[at] = 0xc3; at += 1;
    let displacement = (unresolved as i64 - (unresolved_branch as i64 + 4)) as i32;
    code[unresolved_branch..unresolved_branch + 4].copy_from_slice(&displacement.to_le_bytes());
    debug_assert_eq!(at, X64_RELAY_STUB_BYTES);
    code
}

/// Encode the user continuation used by `RtlRunOnceExecuteOnce`. It receives
/// the initializer's BOOL in EAX, calls the native completion selector, and
/// jumps to the post-syscall ntdll epilogue saved in R14/R15.
pub fn encode_x64_run_once_continuation(selector: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x85, 0xc0, 0x0f, 0x85, 0, 0, 0, 0]);
    code.extend_from_slice(&[0x4c, 0x89, 0xe7, 0xbe, 0x04, 0, 0, 0, 0, 0x31, 0xd2, 0x48, 0xb8]);
    code.extend_from_slice(&selector.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0xb8, 0x01, 0x00, 0x00, 0xc0, 0x4c, 0x89, 0xfc, 0x41, 0xff, 0xe6]);
    let success = code.len();
    let displacement = (success as i64 - 8) as i32;
    code[4..8].copy_from_slice(&displacement.to_le_bytes());
    code.extend_from_slice(&[0x4c, 0x89, 0xe7, 0x31, 0xf6, 0x4d, 0x85, 0xed, 0x74, 0]);
    code.extend_from_slice(&[0x49, 0x8b, 0x55, 0x00]);
    let no_context = code.len();
    let short = (no_context as i64 - (success as i64 + 10)) as i8;
    code[success + 9] = short as u8;
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&selector.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0x4c, 0x89, 0xfc, 0x41, 0xff, 0xe6]);
    code
}

/// Return leg for a synchronous x86-64 Windows window-procedure callback.
/// The WndProc's LRESULT is written into the callback home area and returned
/// through the native `NtCallbackReturn` service.
pub fn encode_x64_wndproc_continuation(selector: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]); // [rsp] = WndProc RAX
    code.extend_from_slice(&[0x48, 0x89, 0xe1]); // RCX = result pointer
    code.extend_from_slice(&[0xba, 0x08, 0x00, 0x00, 0x00]); // EDX = sizeof(LRESULT)
    code.extend_from_slice(&[0x45, 0x31, 0xc0]); // R8D = STATUS_SUCCESS
    // The continuation is executing a raw `syscall`, whose architectural
    // entry presents Linux's six-argument order (RDI, RSI, RDX, R10, R8,
    // R9).  The raw NT decoder converts that snapshot back to Windows order;
    // marshal this three-argument call before loading RAX so NtCallbackReturn
    // receives the result pointer, size, and status rather than stale frame
    // registers.
    code.extend_from_slice(&[0x48, 0x89, 0xcf]); // RDI = RCX
    code.extend_from_slice(&[0x48, 0x89, 0xd6]); // RSI = RDX
    code.extend_from_slice(&[0x4c, 0x89, 0xc2]); // RDX = R8
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&selector.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0xcc]);
    code
}

/// Return leg for a native x86-64 user APC.  The APC routine returns through
/// this code with `rsp` pointing immediately after its return address; the
/// saved volatile register image and original control state follow the
/// Windows shadow space.  The original `r11` is intentionally not restored:
/// it is caller-clobbered by the Windows x64 ABI, while all nonvolatile
/// registers are restored before jumping to the interrupted instruction.
pub fn encode_x64_apc_continuation() -> Vec<u8> {
    let mut code = Vec::new();
    // Saved image offsets after RET: rax..rbp at 0x20..0x98, rip 0x98,
    // rsp 0xa0.  Each load is a 64-bit RIP-independent stack-relative move.
    for (reg, offset) in [
        (0, 0x20u8), // rax
        (3, 0x28),    // rbx
        (1, 0x30),    // rcx
        (2, 0x38),    // rdx
        (6, 0x40),    // rsi
        (7, 0x48),    // rdi
        (8, 0x50),    // r8
        (9, 0x58),    // r9
        (10, 0x60),   // r10
        (12, 0x78),   // r12
        (13, 0x80),   // r13
        (14, 0x88),   // r14
        (15, 0x90),   // r15
        (5, 0x98),    // rbp
    ] {
        if reg < 8 {
            code.extend_from_slice(&[0x48, 0x8b, 0x44 + (reg << 3), 0x24, offset]);
        } else {
            code.extend_from_slice(&[0x4c, 0x8b, 0x44 + ((reg - 8) << 3), 0x24, offset]);
        }
    }
    // mov r11, [rsp+0xa0] (original RIP), then mov rsp, [rsp+0xa8].
    code.extend_from_slice(&[0x4c, 0x8b, 0x5c, 0x24, 0xa0]);
    code.extend_from_slice(&[0x48, 0x8b, 0x64, 0x24, 0xa8]);
    code.extend_from_slice(&[0x41, 0xff, 0xe3]); // jmp r11
    code
}

/// Encode Wine's x86-64 debugger breakpoint entry. The trap is intentional:
/// Windows exception dispatch, rather than the NT syscall adapter, owns the
/// observable result when a process executes this export.
pub fn encode_x64_breakpoint_stub() -> [u8; X64_BREAKPOINT_STUB_BYTES] {
    [0xcc, 0xc3]
}

/// Encode a Windows x64 ABI-preserving NTDLL entry stub. The first Windows
/// argument arrives in RCX; the native NT entry consumes it in RDI. RDI is a
/// Windows nonvolatile register, so the thunk saves and restores it around the
/// syscall instruction.
pub fn encode_x64_unary_stub(selector: u64) -> [u8; X64_UNARY_STUB_BYTES] {
    let mut code = [0u8; X64_UNARY_STUB_BYTES];
    code[0] = 0x57;
    code[1..4].copy_from_slice(&[0x48, 0x89, 0xcf]);
    code[4..6].copy_from_slice(&[0x48, 0xb8]);
    code[6..14].copy_from_slice(&selector.to_le_bytes());
    code[14..16].copy_from_slice(&[0x0f, 0x05]);
    code[16] = 0x5f;
    code[17] = 0xc3;
    code
}

/// Encode a Windows x64 ABI NTDLL entry with no user arguments.
pub fn encode_x64_zero_arg_stub(selector: u64) -> [u8; X64_ZERO_ARG_STUB_BYTES] {
    let mut code = [0u8; X64_ZERO_ARG_STUB_BYTES];
    code[0..2].copy_from_slice(&[0x48, 0xb8]);
    code[2..10].copy_from_slice(&selector.to_le_bytes());
    code[10..12].copy_from_slice(&[0x0f, 0x05]);
    code[12] = 0xc3;
    code
}

/// Encode a Windows x64 six-argument NTDLL stub. Windows passes arguments as
/// RCX,RDX,R8,R9,[RSP+28],[RSP+30] at function entry; the native entry wants
/// RDI,RSI,RDX,R10,R8,R9. The two stack loads happen after two pushes, hence
/// their adjusted offsets of `38h` and `40h`.
pub fn encode_x64_six_arg_stub(selector: u64) -> [u8; X64_SIX_ARG_STUB_BYTES] {
    let mut code = [0u8; X64_SIX_ARG_STUB_BYTES];
    let mut at = 0;
    code[at] = 0x57; at += 1;
    code[at] = 0x56; at += 1;
    for bytes in [[0x48, 0x89, 0xcf], [0x48, 0x89, 0xd6], [0x4c, 0x89, 0xc2], [0x4d, 0x89, 0xca]] {
        code[at..at + 3].copy_from_slice(&bytes); at += 3;
    }
    code[at..at + 5].copy_from_slice(&[0x4c, 0x8b, 0x44, 0x24, 0x38]); at += 5;
    code[at..at + 5].copy_from_slice(&[0x4c, 0x8b, 0x4c, 0x24, 0x40]); at += 5;
    code[at..at + 2].copy_from_slice(&[0x48, 0xb8]); at += 2;
    code[at..at + 8].copy_from_slice(&selector.to_le_bytes()); at += 8;
    code[at..at + 2].copy_from_slice(&[0x0f, 0x05]); at += 2;
    code[at..at + 3].copy_from_slice(&[0x5e, 0x5f, 0xc3]);
    code
}

#[cfg(test)]
#[path = "nt_stub/tests/contracts.rs"]
mod tests;
#[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
#[path = "nt_stub/tests/execution.rs"]
mod execution;
use alloc::vec::Vec;
