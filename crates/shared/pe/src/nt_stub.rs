/// Length of the x86-64 NTDLL thunk for a one-request-pointer service.
pub const X64_UNARY_STUB_BYTES: usize = 18;
pub const X64_SIX_ARG_STUB_BYTES: usize = 39;

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
}
