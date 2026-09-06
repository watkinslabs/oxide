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
#[path = "nt_wine_window/dc_raw.rs"]
mod nt_dc_raw;
#[path = "nt_wine_window/pen_raw.rs"]
mod nt_pen_raw;
pub(crate) mod nt_file_policy;
mod nt_file_async_policy;
mod nt_file_scatter_policy;
mod nt_file_gather_policy;
mod nt_file_volume_abi;
mod nt_loader_dir_policy;
pub(crate) mod nt_file_lock_policy;
pub(crate) mod nt_registry_policy;
pub(crate) mod nt_registry_endpoint;
pub(crate) mod nt_desktop_names;
pub(crate) mod nt_process_membership;
pub(crate) mod nt_directory_notify_policy;
mod nt_path;
mod nt_path_type;
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
mod nt_process_command_line;
mod nt_handle_close_policy;
mod nt_window_policy;
#[cfg(any(test, target_os = "oxide-kernel"))]
#[path = "nt_gdi/frame.rs"]
mod nt_gdi_frame;
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
#[path = "nt_gdi/text_callback_policy.rs"]
mod nt_gdi_text_policy;
#[path = "nt_window/retrieval_policy.rs"]
mod nt_retrieval_policy;
#[path = "nt_wine_window/message_call_abi.rs"]
mod nt_message_call_abi;
#[path = "nt_wine_window/font_query_raw.rs"]
mod nt_wine_font_query_contract;
#[path = "nt_wine_window/system_color_raw.rs"]
mod nt_system_color_raw;
#[path = "nt_wine_window/nonclient_raw.rs"]
mod nt_nonclient_raw;
#[path = "nt_wine_window/visibility_raw.rs"]
mod nt_visibility_raw;
#[path = "nt_wine_window/region_raw.rs"]
mod nt_region_raw;
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
