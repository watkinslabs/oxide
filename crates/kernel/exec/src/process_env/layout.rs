pub const X64_SHADOW_SPACE: u64 = 32;
pub const X64_RETURN_SLOT: u64 = 8;
#[cfg(test)]
pub(super) const PAGE: usize = 4096;
pub const THREAD_TEB_BYTES: usize = 0x4000;
pub(super) const TEB_SYSCALL_FRAME_OFFSET: usize = 0x378;
pub(super) const TEB_ACTIVATION_CONTEXT_STACK_OFFSET: usize = 0x2c8;
pub(super) const TEB_ACTIVATION_CONTEXT_STACK_INLINE: usize = 0x290;
pub(super) const THREAD_SYSCALL_FRAME_OFF: usize = 0x3000;
pub(super) const PROCESS_SYSCALL_FRAME_OFF: usize = TEB_OFF + THREAD_SYSCALL_FRAME_OFF;
pub const NT_DEBUG_INFO_OFFSET: u64 = 0x2800;
pub(super) const PEB_OFF: usize = 0x000;
pub(super) const TEB_OFF: usize = 0x1000;
pub(super) const TEB_STACK_BASE_OFF: usize = 0x08;
pub(super) const TEB_STACK_LIMIT_OFF: usize = 0x10;
pub(super) const TEB_DEALLOCATION_STACK_OFF: usize = 0x1478;
pub(super) const THREAD_TLS_OFF: usize = 0x2000;
pub(super) const THREAD_TLS_BYTES: usize = 0x800;
pub(super) const TLS_OFF: usize = TEB_OFF + THREAD_TLS_OFF;
// Module TLS vector and inline Win32 TLS slots have distinct storage.
pub(super) const TEB_CURRENT_LOCALE_OFF: usize = 0x108;
// NT_TIB.FiberData carries a fixed non-zero constant on a freshly created
// thread; a fiber-aware caller distinguishes it from a real fiber pointer.
pub(super) const TEB_FIBER_DATA_OFF: usize = 0x20;
pub(super) const TEB_FIBER_DATA: u64 = 0x1e00;
// The per-thread scratch UNICODE_STRING the ANSI entry points convert into.
// Its descriptor must name the inline buffer that follows it; a zero
// MaximumLength makes every ANSI-to-Unicode conversion overflow instead.
pub(super) const TEB_STATIC_UNICODE_STRING_OFF: usize = 0x1258;
pub(super) const TEB_STATIC_UNICODE_BUFFER_OFF: usize = 0x1268;
pub(super) const TEB_STATIC_UNICODE_BUFFER_WCHARS: usize = 261;
pub(super) const TEB_STATIC_UNICODE_BUFFER_BYTES: usize = TEB_STATIC_UNICODE_BUFFER_WCHARS * WCHAR_BYTES;
#[cfg(test)]
pub(super) const TEB_TLS_SLOTS_OFF: usize = 0x1480;
#[cfg(test)]
pub(super) const TEB_TLS_SLOTS: usize = 64;
#[cfg(test)]
pub(super) const TEB_TLS_EXPANSION_SLOTS_OFF: usize = 0x1780;
pub(super) const PARAM_OFF: usize = 0x5000;
pub(super) const PARAM_CURRENT_DIRECTORY_OFF: usize = 0x38;
pub(super) const PARAM_COMMAND_LINE_OFF: usize = 0x70;
pub(super) const PARAM_WINDOW_TITLE_OFF: usize = 0xb0;
pub(super) const PARAM_CURRENT_DIRECTORY_HANDLE_OFF: usize = 0x48;
pub(super) const PARAM_SIZE: u32 = (PROCESS_STR_OFF - PARAM_OFF) as u32;
pub(super) const PARAM_FLAGS_NORMALIZED: u32 = 1;
pub(super) const PARAM_SHOW_WINDOW_OFF: usize = 0xa8;
pub(super) const PARAM_DESKTOP_OFF: usize = 0xc0;
pub(super) const PARAM_SHELL_INFO_OFF: usize = 0xd0;
// One always-NUL WCHAR inside the parameter extent. The empty descriptors
// address it so a caller that dereferences Buffer reads an empty string
// rather than a null pointer.
pub(super) const PARAM_EMPTY_STRING_OFF: usize = 0x410;
pub(super) const PARAM_EMPTY_STRING_BYTES: u16 = WCHAR_BYTES as u16;
pub(super) const PARAM_ENVIRONMENT_SIZE_OFF: usize = 0x3f0;
pub(super) const PARAM_PROCESS_GROUP_ID_OFF: usize = 0x408;
pub(super) const SHOW_WINDOW_NORMAL: u32 = 1;
pub(super) const LDR_OFF: usize = 0x8000;
pub(super) const MOD_OFF: usize = 0x8100;
pub(super) const MOD_STRIDE: usize = 0x70;
pub(super) const MAX_MODULES: usize = 64;
pub(super) const ENV_OFF: usize = 0x12000;
pub(super) const ENV_BYTES: usize = 0x3000;
pub(super) const PROCESS_STR_OFF: usize = 0x6000;
pub(super) const STR_OFF: usize = 0xa000;
// A published current directory always ends with the path separator: relative
// resolution concatenates the directory and the name with no separator of its
// own.
pub(super) const CURRENT_DIR: &str = "C:\\windows\\";
pub(super) const PATH_SEPARATOR: char = '\\';
pub(super) const CURRENT_DIR_STORAGE: usize = 0x400;
pub(super) const API_SET_OFF: usize = 0x15000;
pub(super) const PEB_PROCESS_HEAP_OFF: usize = 0x30;
/// PEB.ImageBaseAddress.
pub(super) const PEB_IMAGE_BASE_OFF: usize = 0x10;
pub(super) const PEB_NUMBER_OF_PROCESSORS_OFF: usize = 0xb8;
pub(super) const PROCESS_HEAP_HANDLE: u64 = 1;
pub(super) const INITIAL_PROCESSOR_COUNT: u32 = 1;
// Descriptors follow the complete PEB, within its dedicated page.
pub(super) const TLS_BITMAP_DESC_OFF: usize = 0x800;
pub(super) const TLS_EXP_BITMAP_DESC_OFF: usize = 0x820;
pub(super) const BLOCK_BYTES: usize = 0x16000;
pub(super) const ACTIVATION_LIST_OFF: usize = 8;
pub(super) const POINTER_BYTES: usize = 8;
pub(super) const WCHAR_BYTES: usize = 2;
const _: () = assert!(THREAD_TLS_OFF + THREAD_TLS_BYTES <= NT_DEBUG_INFO_OFFSET as usize);
const _: () = assert!(NT_DEBUG_INFO_OFFSET as usize + 8 + 1020 <= THREAD_SYSCALL_FRAME_OFF);
const _: () = assert!(TEB_STATIC_UNICODE_BUFFER_OFF + TEB_STATIC_UNICODE_BUFFER_BYTES <= TEB_DEALLOCATION_STACK_OFF);
const _: () = assert!(PARAM_EMPTY_STRING_OFF + PARAM_EMPTY_STRING_BYTES as usize <= PARAM_SIZE as usize);
const _: () = assert!(MOD_OFF + MAX_MODULES * MOD_STRIDE <= STR_OFF);
const _: () = assert!(ENV_OFF + ENV_BYTES <= API_SET_OFF);
// The shared page carries its own layout in `user_shared_data`, which builds
// the bytes ungated so the syscall-entry flag can be tested off-target.
