/// Length of the x86-64 NTDLL thunk for a one-request-pointer service.
pub const X64_UNARY_STUB_BYTES: usize = 18;
pub const X64_SIX_ARG_STUB_BYTES: usize = 39;
pub const X64_BREAKPOINT_STUB_BYTES: usize = 2;
pub const X64_RELAY_STUB_BYTES: usize = 206;

/// Encode the x86-64 Wine syscall dispatcher ABI used by win32u and ntdll.
/// Wine places the syscall ordinal in EAX and passes the Windows ABI argument
/// list in registers plus the caller stack; Oxide receives the ordinal in RDI
/// and a contiguous seventeen-slot argument array in RSI.
pub fn encode_x64_wine_dispatcher_stub(selector: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x53, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x56, 0x57]);
    code.extend_from_slice(&[0x4c, 0x8d, 0x64, 0x24, 0x40]); // r12 = entry rsp
    code.extend_from_slice(&[0x41, 0x89, 0xc5]); // r13d = Wine ordinal; stack loads below use rax
    code.extend_from_slice(&[0x48, 0x81, 0xec, 0x88, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0x48, 0x89, 0x0c, 0x24, 0x48, 0x89, 0x54, 0x24, 0x08]);
    code.extend_from_slice(&[0x4c, 0x89, 0x44, 0x24, 0x10, 0x4c, 0x89, 0x4c, 0x24, 0x18]);
    for index in 0..13u32 {
        let source = 0x28 + index * 8;
        let target = 0x20 + index * 8;
        code.extend_from_slice(&[0x49, 0x8b, 0x84, 0x24]);
        code.extend_from_slice(&source.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x84, 0x24]);
        code.extend_from_slice(&target.to_le_bytes());
    }
    code.extend_from_slice(&[0x44, 0x89, 0xef, 0x48, 0x89, 0xe6, 0x48, 0xb8]);
    code.extend_from_slice(&selector.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0x48, 0x81, 0xc4, 0x88, 0x00, 0x00, 0x00]);
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
    code[at] = 80; at += 1; // r12 = first thunk argument: return address + eight saves + call return slot
    code[at..at + 3].copy_from_slice(&[0x48, 0x89, 0xcf]); at += 3; // rdi = descriptor (rcx)
    code[at..at + 3].copy_from_slice(&[0x48, 0x89, 0xd6]); at += 3; // rsi = relay index (rdx)
    code[at..at + 5].copy_from_slice(&[0x49, 0x8d, 0x54, 0x24, 0]); at += 5; // rdx = Wine's contiguous argument array
    code[at..at + 2].copy_from_slice(&[0x48, 0xb8]); at += 2;
    code[at..at + 8].copy_from_slice(&selector.to_le_bytes()); at += 8;
    code[at..at + 2].copy_from_slice(&[0x0f, 0x05]); at += 2;
    code[at..at + 5].copy_from_slice(&[0x4c, 0x8d, 0x64, 0x24, 80]); at += 5; // re-derive args after syscall restores registers
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
    code[at] = 0xc3;
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
mod tests {
    use super::*;

    #[test]
    fn unary_stub_preserves_windows_nonvolatile_rdi_and_moves_rcx() {
        let bytes = encode_x64_unary_stub(0x4e54_0000_0000_0006);
        assert_eq!(&bytes[..4], &[0x57, 0x48, 0x89, 0xcf]);
        assert_eq!(&bytes[4..14], &[0x48, 0xb8, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x4e]);
        assert_eq!(&bytes[14..], &[0x0f, 0x05, 0x5f, 0xc3]);
    }

    #[test]
    fn six_arg_stub_translates_register_and_stack_arguments() {
        let bytes = encode_x64_six_arg_stub(0x4e54_0000_0000_0000);
        assert_eq!(&bytes[..8], &[0x57, 0x56, 0x48, 0x89, 0xcf, 0x48, 0x89, 0xd6]);
        assert_eq!(&bytes[8..14], &[0x4c, 0x89, 0xc2, 0x4d, 0x89, 0xca]);
        assert_eq!(&bytes[14..19], &[0x4c, 0x8b, 0x44, 0x24, 0x38]);
        assert_eq!(&bytes[19..24], &[0x4c, 0x8b, 0x4c, 0x24, 0x40]);
        assert_eq!(&bytes[24..34], &[0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0x54, 0x4e]);
        assert_eq!(&bytes[34..], &[0x0f, 0x05, 0x5e, 0x5f, 0xc3]);
    }

    #[test]
    fn breakpoint_stub_matches_wine_x64_entry() {
        assert_eq!(encode_x64_breakpoint_stub(), [0xcc, 0xc3]);
    }

    #[test]
    fn relay_stub_preserves_the_wine_home_area_before_calling_target() {
        let bytes = encode_x64_relay_stub(0x4e54_0000_0000_0216);
        assert_eq!(&bytes[..15], &[0x53, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x56, 0x57, 0x4c, 0x8d, 0x64]);
        assert_eq!(bytes.windows(5).filter(|window| *window == [0x4c, 0x8d, 0x64, 0x24, 80]).count(), 2);
        assert!(bytes.windows(5).any(|window| window == [0x49, 0x8d, 0x54, 0x24, 0]));
        assert_eq!(&bytes[38..40], &[0x0f, 0x05]);
        assert_eq!(&bytes[40..45], &[0x4c, 0x8d, 0x64, 0x24, 80]);
        assert_eq!(&bytes[45..49], &[0x48, 0x83, 0xec, 0x60]);
        assert!(bytes.windows(5).any(|window| window == [0x4d, 0x8b, 0x54, 0x24, 0]));
        let epilogue = [0xff, 0xd0, 0x48, 0x83, 0xc4, 0x60, 0x5f, 0x5e, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5d, 0x5b, 0xc3];
        assert!(bytes.windows(epilogue.len()).any(|window| window == epilogue));
    }

    #[test]
    fn wine_dispatcher_copies_all_x64_arguments_and_ordinal() {
        let bytes = encode_x64_wine_dispatcher_stub(0x4e54_0000_0000_0217);
        assert!(bytes.len() > 200);
        assert!(bytes.windows(5).any(|window| window == [0x44, 0x89, 0xef, 0x48, 0x89]));
        assert!(bytes.windows(3).any(|window| window == [0x41, 0x89, 0xc5]));
        assert!(bytes.windows(3).any(|window| window == [0x44, 0x89, 0xef]));
        assert!(bytes.windows(4).any(|window| window == [0x49, 0x8b, 0x84, 0x24]));
        assert!(bytes.windows(4).any(|window| window == [0x48, 0x89, 0x84, 0x24]));
        assert!(bytes.windows(2).any(|window| window == [0x0f, 0x05]));
        assert_eq!(&bytes[bytes.len() - 13..], &[0x5f, 0x5e, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5d, 0x5b, 0xc3]);
    }
}
use alloc::vec::Vec;
