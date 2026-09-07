//! The language-specific handler for compiler-generated structured exception
//! handling on x86-64. The unwinder finds its address in a function's unwind
//! data and enters it with the exception record, the establishing frame, the
//! machine context, and the dispatcher record whose handler data points at
//! the function's scope table.
//!
//! It is user-mode control flow over user-mode data that calls user-mode
//! filters and termination handlers, so it lives on the export page as
//! machine code rather than as a kernel entry: a kernel entry would have to
//! call back out to those handlers, which the Windows boundary never asks any
//! kernel to do. The one address it cannot know at assembly time is the
//! unwind entry it tail-calls, which the page's own layout supplies.
//!
//! Two passes over the scope table, selected by the record's unwinding flags,
//! starting at the dispatcher's scope index so a re-entry resumes where the
//! previous one stopped:
//!
//! - Unwinding: every scope covering the control address that names no jump
//!   target has its termination handler called with the scope index already
//!   advanced past it. A target unwind stops at the scope holding the target.
//! - Searching: every scope covering the control address that names a jump
//!   target has its filter called, unless the scope asks to execute its
//!   handler outright. A filter that continues the search moves on, one that
//!   continues execution returns at once, and any other answer unwinds to the
//!   scope's jump target and does not come back.
//!
//! ```text
//!     push rbp / rbx / rsi / rdi / r12 / r13 / r14 / r15
//!     sub  rsp, 0x38                  ; shadow space, two stacked arguments
//!     mov  rbx, r9                    ; dispatcher record
//!     mov  r12, rcx                   ; exception record
//!     mov  r13, rdx                   ; establishing frame
//!     mov  rbp, r8                    ; context record
//!     mov  rsi, [rbx+0x38]            ; scope table = handler data
//!     mov  rdi, [rbx+0x08]            ; image base
//!     mov  r14, [rbx+0x00]            ; control address
//!     mov  r15d, [rbx+0x48]           ; scope index
//!     mov  eax, [r12+0x04]            ; exception flags
//!     test al, 6                      ; unwinding or exit unwind
//!     jnz  unwind_loop
//! search_loop:
//!     cmp  r15d, [rsi]                ; index against scope count
//!     jae  done
//!     mov  eax, r15d / shl rax, 4 / lea rax, [rsi+rax+4]   ; scope record
//!     mov  ecx, [rax]   / add rcx, rdi / cmp r14, rcx / jb  search_next
//!     mov  ecx, [rax+4] / add rcx, rdi / cmp r14, rcx / jae search_next
//!     mov  ecx, [rax+12]/ test ecx, ecx / jz search_next   ; no jump target
//!     mov  ecx, [rax+8] / cmp ecx, 1 / je do_unwind        ; execute handler
//!     mov  [rsp+0x20], r12 / mov [rsp+0x28], rbp           ; exception pointers
//!     add  rcx, rdi / mov r10, rcx / mov rdx, r13 / lea rcx, [rsp+0x20]
//!     call r10                                             ; the filter
//!     test eax, eax / jz search_next                       ; continue search
//!     cmp  eax, -1  / je continue_execution
//! do_unwind:
//!     mov  eax, r15d / shl rax, 4 / lea rax, [rsi+rax+4]
//!     mov  ecx, [rax+12] / add rcx, rdi / mov rdx, rcx     ; jump target
//!     mov  rcx, r13 / mov r8, r12 / mov r9d, [r12]         ; frame, record, code
//!     mov  rax, [rbx+0x28] / mov [rsp+0x20], rax           ; context record
//!     mov  rax, [rbx+0x40] / mov [rsp+0x28], rax           ; history table
//!     movabs r10, <unwind entry> / call r10
//! search_next:
//!     add  r15d, 1 / jmp search_loop
//! continue_execution:
//!     xor  eax, eax / jmp epilogue
//! unwind_loop:
//!     cmp  r15d, [rsi] / jae done
//!     mov  eax, r15d / shl rax, 4 / lea rax, [rsi+rax+4]
//!     mov  ecx, [rax]   / add rcx, rdi / cmp r14, rcx / jb  unwind_next
//!     mov  ecx, [rax+4] / add rcx, rdi / cmp r14, rcx / jae unwind_next
//!     mov  ecx, [rax+12]/ test ecx, ecx / jnz unwind_next  ; has a jump target
//!     mov  edx, [r12+0x04] / test dl, 0x20 / jz call_finally
//!     mov  r10, [rbx+0x20]                                 ; target address
//!     mov  ecx, [rax]   / add rcx, rdi / cmp r10, rcx / jb call_finally
//!     mov  ecx, [rax+4] / add rcx, rdi / cmp r10, rcx / jb done
//! call_finally:
//!     mov  ecx, [rax+8] / add rcx, rdi / mov r10, rcx
//!     mov  eax, r15d / add eax, 1 / mov [rbx+0x48], eax    ; index past this scope
//!     mov  ecx, 1 / mov rdx, r13 / call r10                ; the termination handler
//! unwind_next:
//!     add  r15d, 1 / jmp unwind_loop
//! done:
//!     mov  eax, 1                                          ; continue search
//! epilogue:
//!     add  rsp, 0x38 / pop r15 / r14 / r13 / r12 / rdi / rsi / rbx / rbp / ret
//! ```

/// Length of the language-specific handler's machine code.
pub const X64_C_SPECIFIC_HANDLER_BYTES: usize = 361;
/// Offset of the unwind entry the handler tail-calls, as an eight-byte
/// immediate the page's layout fills in.
const UNWIND_ENTRY_IMMEDIATE_OFFSET: usize = 200;
/// Placeholder occupying that immediate in the assembled body.
const UNWIND_ENTRY_PLACEHOLDER: u64 = 0x1122_3344_5566_7788;

/// The assembled body, with the unwind entry still a placeholder.
const BODY: [u8; X64_C_SPECIFIC_HANDLER_BYTES] = [
    0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x83, 0xec, 0x38, 0x4c, 0x89, 0xcb, 0x49, 0x89, 0xcc, 0x49, 0x89,
    0xd5, 0x4c, 0x89, 0xc5, 0x48, 0x8b, 0x73, 0x38, 0x48, 0x8b, 0x7b, 0x08,
    0x4c, 0x8b, 0x33, 0x44, 0x8b, 0x7b, 0x48, 0x41, 0x8b, 0x44, 0x24, 0x04,
    0xa8, 0x06, 0x0f, 0x85, 0xa8, 0x00, 0x00, 0x00, 0x44, 0x3b, 0x3e, 0x0f,
    0x83, 0x12, 0x01, 0x00, 0x00, 0x44, 0x89, 0xf8, 0x48, 0xc1, 0xe0, 0x04,
    0x48, 0x8d, 0x44, 0x06, 0x04, 0x8b, 0x08, 0x48, 0x01, 0xf9, 0x49, 0x39,
    0xce, 0x72, 0x7c, 0x8b, 0x48, 0x04, 0x48, 0x01, 0xf9, 0x49, 0x39, 0xce,
    0x73, 0x71, 0x8b, 0x48, 0x0c, 0x85, 0xc9, 0x74, 0x6a, 0x8b, 0x48, 0x08,
    0x83, 0xf9, 0x01, 0x74, 0x24, 0x4c, 0x89, 0x64, 0x24, 0x20, 0x48, 0x89,
    0x6c, 0x24, 0x28, 0x48, 0x01, 0xf9, 0x49, 0x89, 0xca, 0x4c, 0x89, 0xea,
    0x48, 0x8d, 0x4c, 0x24, 0x20, 0x41, 0xff, 0xd2, 0x85, 0xc0, 0x74, 0x43,
    0x83, 0xf8, 0xff, 0x74, 0x47, 0x44, 0x89, 0xf8, 0x48, 0xc1, 0xe0, 0x04,
    0x48, 0x8d, 0x44, 0x06, 0x04, 0x8b, 0x48, 0x0c, 0x48, 0x01, 0xf9, 0x48,
    0x89, 0xca, 0x4c, 0x89, 0xe9, 0x4d, 0x89, 0xe0, 0x45, 0x8b, 0x0c, 0x24,
    0x48, 0x8b, 0x43, 0x28, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8b, 0x43,
    0x40, 0x48, 0x89, 0x44, 0x24, 0x28, 0x49, 0xba, 0x88, 0x77, 0x66, 0x55,
    0x44, 0x33, 0x22, 0x11, 0x41, 0xff, 0xd2, 0x41, 0x83, 0xc7, 0x01, 0xe9,
    0x5c, 0xff, 0xff, 0xff, 0x31, 0xc0, 0xeb, 0x78, 0x44, 0x3b, 0x3e, 0x73,
    0x6e, 0x44, 0x89, 0xf8, 0x48, 0xc1, 0xe0, 0x04, 0x48, 0x8d, 0x44, 0x06,
    0x04, 0x8b, 0x08, 0x48, 0x01, 0xf9, 0x49, 0x39, 0xce, 0x72, 0x52, 0x8b,
    0x48, 0x04, 0x48, 0x01, 0xf9, 0x49, 0x39, 0xce, 0x73, 0x47, 0x8b, 0x48,
    0x0c, 0x85, 0xc9, 0x75, 0x40, 0x41, 0x8b, 0x54, 0x24, 0x04, 0xf6, 0xc2,
    0x20, 0x74, 0x19, 0x4c, 0x8b, 0x53, 0x20, 0x8b, 0x08, 0x48, 0x01, 0xf9,
    0x49, 0x39, 0xca, 0x72, 0x0b, 0x8b, 0x48, 0x04, 0x48, 0x01, 0xf9, 0x49,
    0x39, 0xca, 0x72, 0x23, 0x8b, 0x48, 0x08, 0x48, 0x01, 0xf9, 0x49, 0x89,
    0xca, 0x44, 0x89, 0xf8, 0x83, 0xc0, 0x01, 0x89, 0x43, 0x48, 0xb9, 0x01,
    0x00, 0x00, 0x00, 0x4c, 0x89, 0xea, 0x41, 0xff, 0xd2, 0x41, 0x83, 0xc7,
    0x01, 0xeb, 0x8d, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x38,
    0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5f, 0x5e, 0x5b, 0x5d,
    0xc3,];

/// Encode the language-specific handler, binding the unwind entry it enters
/// when a filter elects to run its scope's handler.
/// # C: O(1)
pub fn encode_x64_c_specific_handler(unwind_entry: u64) -> [u8; X64_C_SPECIFIC_HANDLER_BYTES] {
    let mut code = BODY;
    let at = UNWIND_ENTRY_IMMEDIATE_OFFSET;
    code[at..at + 8].copy_from_slice(&unwind_entry.to_le_bytes());
    code
}

/// The placeholder the encoder replaces, so a test can prove it was replaced
/// rather than merely present.
/// # C: O(1)
pub const fn unwind_entry_placeholder() -> u64 { UNWIND_ENTRY_PLACEHOLDER }
