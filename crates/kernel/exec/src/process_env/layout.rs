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
pub(super) const CURRENT_DIR: &str = "C:\\Windows";
pub(super) const CURRENT_DIR_STORAGE: usize = 0x400;
pub(super) const API_SET_OFF: usize = 0x15000;
pub(super) const PEB_PROCESS_HEAP_OFF: usize = 0x30;
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
const _: () = assert!(MOD_OFF + MAX_MODULES * MOD_STRIDE <= STR_OFF);
const _: () = assert!(ENV_OFF + ENV_BYTES <= API_SET_OFF);
#[cfg(target_os = "oxide-kernel")]
pub(super) const USER_SHARED_DATA_BASE: u64 = 0x7ffe_0000;
#[cfg(target_os = "oxide-kernel")]
pub(super) const USER_SHARED_DATA_BYTES: usize = 0x1000;
