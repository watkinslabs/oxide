// Module manifest: NT personality adapters and shared hosted ABI contracts.
mod nt_system_info;
mod nt_process_parameters;
mod nt_process_policy;
mod nt_thread_lifecycle;
#[cfg(target_os = "oxide-kernel")]
#[path = "nt_rtl/native_thread/mod.rs"]
pub(crate) mod nt_native_thread;
#[cfg(target_os = "oxide-kernel")]
#[path = "nt_rtl/native_gdi/mod.rs"]
pub(crate) mod nt_native_gdi;
mod nt_directory_abi;
pub(crate) mod nt_callback_fp_layout;
pub(crate) mod nt_callback_frame;
#[path = "nt_wine_window/dc_raw.rs"]
mod nt_dc_raw;
#[path = "nt_wine_window/pen_raw.rs"]
mod nt_pen_raw;
#[path = "nt_wine_window/dc_state_raw.rs"]
mod nt_dc_state_raw;
#[path = "nt_wine_window/xform_raw.rs"]
mod nt_xform_raw;
#[path = "nt_wine_window/draw_raw.rs"]
mod nt_draw_raw;
#[path = "nt_wine_window/print_raw.rs"]
mod nt_print_raw;
pub(crate) mod nt_file_policy;
pub(crate) mod nt_token_pseudo;
pub(crate) mod nt_file_status;
pub(crate) mod nt_file_args;
pub(crate) mod nt_file_sig;
pub(crate) mod nt_file_trace;
pub(crate) mod nt_object_name;
mod nt_file_async_policy;
mod nt_file_scatter_policy;
mod nt_file_gather_policy;
mod nt_file_volume_abi;
mod nt_loader_dir_policy;
pub(crate) mod nt_file_lock_policy;
pub(crate) mod nt_registry_policy;
pub(crate) mod nt_registry_endpoint;
pub(crate) mod nt_registry_reply;
pub(crate) mod nt_locale;
pub(crate) mod nt_registry_path;
// The loader's known-module directory and the generic-rights translation its
// two opens need. The call sites are the named-object opens (the directory
// open and the section opens beneath it), which this crate keeps elsewhere.
#[allow(dead_code)]
pub(crate) mod nt_known_dlls;
pub(crate) mod nt_desktop_names;
// nt_process_create (its sole real caller) is x86-64-only (KI-0713: no
// AArch64 NtCreateUserProcess yet); kept hosted-testable on every host arch.
#[cfg(any(test, target_arch = "x86_64"))]
pub(crate) mod nt_process_membership;
pub(crate) mod nt_process_naming;
pub(crate) mod nt_ulong;
// Argument positions, ULONG widths and refusals of the virtual-memory and
// section services; ungated so each decision is answerable by a test. The
// recorded positions of the arguments no decision reads are what makes the
// arity checkable, so the module keeps them whether or not code names them.
#[allow(dead_code)]
pub(crate) mod nt_memory_args;
pub(crate) mod nt_directory_notify_policy;
mod nt_path;
mod nt_path_type;
// PE resource-directory walk (type/name/language) shared by the loader's
// resource services; ungated so `cargo test` exercises it.
pub(crate) mod nt_resource;
mod nt_image;
mod nt_dos83;
#[cfg(target_os = "oxide-kernel")]
mod nt_heap_lock;
#[cfg(target_os = "oxide-kernel")]
mod nt_oem;
#[cfg(target_os = "oxide-kernel")]
mod nt_exec;
#[cfg(target_os = "oxide-kernel")]
mod nt_file;
#[cfg(target_os = "oxide-kernel")]
mod nt_file_scatter;
#[cfg(target_os = "oxide-kernel")]
mod nt_file_gather;
#[cfg(target_os = "oxide-kernel")]
mod nt_file_volume;
#[cfg(target_os = "oxide-kernel")]
mod nt_file_lock;
#[cfg(target_os = "oxide-kernel")]
mod nt_duplicate;
#[cfg(target_os = "oxide-kernel")]
mod nt_process_handles;
mod nt_process_vm_counters;
mod nt_process_image_policy;
mod nt_process_info_policy;
mod nt_process_command_line;
mod nt_handle_close_policy;
mod nt_window_policy;
#[cfg(any(test, target_os = "oxide-kernel"))]
#[path = "nt_gdi/frame.rs"]
mod nt_gdi_frame;
// The flush trace is a diagnostic: `debug-winframe` selects the reporting
// implementation, and its absence selects the empty one, so no call site
// carries the feature test.
#[cfg(any(test, target_os = "oxide-kernel"))]
#[path = "nt_gdi/frame_trace.rs"]
mod nt_gdi_frame_trace_on;
#[cfg(any(test, target_os = "oxide-kernel"))]
#[path = "nt_gdi/frame_trace_off.rs"]
mod nt_gdi_frame_trace_off;
#[cfg(all(any(test, target_os = "oxide-kernel"), feature = "debug-winframe"))]
pub(crate) use nt_gdi_frame_trace_on as nt_gdi_frame_trace;
// Every real call site (nt_gdi::output::snapshot's callers, nt_compositor::worker)
// is behind target_os = "oxide-kernel"; a hosted `cargo test -p syscalls --lib`
// cannot reach it.
#[cfg(all(any(test, target_os = "oxide-kernel"), not(feature = "debug-winframe")))]
#[allow(unused_imports)]
pub(crate) use nt_gdi_frame_trace_off as nt_gdi_frame_trace;
#[cfg(any(test, target_os = "oxide-kernel"))]
#[path = "nt_compositor/mod.rs"]
mod nt_compositor;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
mod nt_process_create;
mod nt_process_memory;
mod nt_process_memory_policy;
mod nt_vulkan_policy;
mod nt_system_time;
#[cfg(target_os = "oxide-kernel")]
mod nt_timer;
#[cfg(target_os = "oxide-kernel")]
mod nt_completion;
#[cfg(target_os = "oxide-kernel")]
mod nt_signal_wait;
#[cfg(target_os = "oxide-kernel")]
mod nt_token;
#[cfg(target_os = "oxide-kernel")]
mod nt_priority;
mod nt_thread_info_policy;
#[cfg(target_os = "oxide-kernel")]
mod nt_registry;
#[cfg(target_os = "oxide-kernel")]
mod nt_directory_notify;
#[cfg(target_os = "oxide-kernel")]
mod nt_wine_window;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod hosted_contracts;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
pub(crate) use hosted_contracts::*;
#[path = "nt_wine_window/paint_open.rs"]
mod nt_wine_paint_open;
#[path = "nt_gdi/text_callback_policy.rs"]
mod nt_gdi_text_policy;
#[path = "nt_window/retrieval_policy.rs"]
mod nt_retrieval_policy;
mod nt_win32_long_error;
mod nt_user_callback;
#[path = "nt_wine_window/message_call_abi.rs"]
mod nt_message_call_abi;
#[path = "nt_wine_window/font_query_raw.rs"]
mod nt_wine_font_query_contract;
#[path = "nt_wine_window/gdi_bitmap_shape.rs"]
mod nt_gdi_bitmap_shape;

#[path = "nt_wine_window/font_family_raw.rs"]
mod nt_wine_font_family_contract;
#[path = "nt_wine_window/system_color_raw.rs"]
mod nt_system_color_raw;
#[path = "nt_wine_window/nonclient_raw.rs"]
mod nt_nonclient_raw;
#[path = "nt_wine_window/visibility_raw.rs"]
mod nt_visibility_raw;
#[path = "nt_wine_window/region_raw.rs"]
mod nt_region_raw;
#[path = "nt_wine_window/gdi_shape_raw.rs"]
pub(crate) mod nt_wine_gdi_shape;
#[path = "nt_wine_window/set_rect_rgn_raw.rs"]
mod nt_set_rect_rgn_raw;
#[path = "nt_wine_window/dc_query_raw.rs"]
mod nt_dc_query_raw;
#[path = "nt_wine_window/message_params.rs"]
mod nt_message_params;
#[cfg(test)]
#[path = "nt_wine_window/object_raw.rs"]
mod nt_wine_object_contract;
mod nt_milestone;
mod nt_ip_string;
mod nt_md4;
mod nt_crc32;
mod nt_srw;
mod nt_counted_string;
#[cfg(target_os = "oxide-kernel")]
mod nt_function_table;
pub(crate) mod nt_status_dos;
