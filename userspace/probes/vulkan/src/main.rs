//! Native Vulkan ABI probe for the Linux personality and the W6 graphics gate.
//!
//! The probe deliberately loads the platform Vulkan loader at runtime. It does
//! not provide an ICD or shadow the loader's device state; it proves that the
//! userspace boundary can discover a real implementation and enumerate a
//! physical device through the standard dispatch path.

use std::ffi::{c_char, c_void, CStr};
use std::ptr;

const VK_SUCCESS: i32 = 0;
const VK_INCOMPLETE: i32 = 5;
const VK_API_VERSION_1_0: u32 = 1 << 22;

#[repr(C)]
struct ApplicationInfo {
    s_type: u32,
    next: *const c_void,
    application_name: *const c_char,
    application_version: u32,
    engine_name: *const c_char,
    engine_version: u32,
    api_version: u32,
}

#[repr(C)]
struct InstanceCreateInfo {
    s_type: u32,
    next: *const c_void,
    flags: u32,
    application_info: *const ApplicationInfo,
    enabled_layer_count: u32,
    enabled_layer_names: *const *const c_char,
    enabled_extension_count: u32,
    enabled_extension_names: *const *const c_char,
}

type GetProcAddr = unsafe extern "C" fn(*mut c_void, *const c_char) -> *const c_void;
type CreateInstance = unsafe extern "C" fn(*const InstanceCreateInfo, *const c_void, *mut *mut c_void) -> i32;
type DestroyInstance = unsafe extern "C" fn(*mut c_void, *const c_void);
type EnumeratePhysicalDevices = unsafe extern "C" fn(*mut c_void, *mut u32, *mut *mut c_void) -> i32;
type EnumerateInstanceVersion = unsafe extern "C" fn(*mut u32) -> i32;

unsafe fn symbol<T>(get_proc: GetProcAddr, instance: *mut c_void, name: &'static CStr) -> Option<T> {
    let address = get_proc(instance, name.as_ptr());
    if address.is_null() { None } else { Some(std::mem::transmute_copy(&address)) }
}

fn version_text(version: u32) -> String {
    format!("{}.{}.{}", version >> 22, (version >> 12) & 0x3ff, version & 0xfff)
}

fn main() {
    // SAFETY: the handle is used only for symbol lookup and is closed after all
    // Vulkan objects and function pointers obtained from it are no longer used.
    let loader = unsafe { libc::dlopen(c"libvulkan.so.1".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if loader.is_null() { panic!("libvulkan.so.1 is unavailable"); }
    let result = run(loader);
    // SAFETY: run has returned and no loader-owned object or function is live.
    unsafe { libc::dlclose(loader); }
    if let Err(error) = result { panic!("native Vulkan probe failed: {error}"); }
}

fn run(loader: *mut c_void) -> Result<(), &'static str> {
    // SAFETY: dlsym returns the Vulkan loader entry point or null; the symbol
    // name is NUL-terminated and all calls use the Vulkan C ABI declarations.
    let get_proc = unsafe { libc::dlsym(loader, c"vkGetInstanceProcAddr".as_ptr()) };
    if get_proc.is_null() { return Err("vkGetInstanceProcAddr is unavailable"); }
    // SAFETY: the address came from the Vulkan loader and matches GetProcAddr.
    let get_proc: GetProcAddr = unsafe { std::mem::transmute(get_proc) };
    let enumerate_version = unsafe { symbol::<EnumerateInstanceVersion>(get_proc, ptr::null_mut(), c"vkEnumerateInstanceVersion") };
    let mut api_version = VK_API_VERSION_1_0;
    if let Some(enumerate_version) = enumerate_version {
        // SAFETY: api_version points to writable storage owned by this call.
        let status = unsafe { enumerate_version(&mut api_version) };
        if status != VK_SUCCESS { return Err("vkEnumerateInstanceVersion failed"); }
    }
    let create_instance = unsafe { symbol::<CreateInstance>(get_proc, ptr::null_mut(), c"vkCreateInstance") }.ok_or("vkCreateInstance is unavailable")?;
    let app_name = c"oxide-vulkan-probe";
    let app = ApplicationInfo { s_type: 0, next: ptr::null(), application_name: app_name.as_ptr(), application_version: 1, engine_name: app_name.as_ptr(), engine_version: 1, api_version };
    let create = InstanceCreateInfo { s_type: 1, next: ptr::null(), flags: 0, application_info: &app, enabled_layer_count: 0, enabled_layer_names: ptr::null(), enabled_extension_count: 0, enabled_extension_names: ptr::null() };
    let mut instance = ptr::null_mut();
    // SAFETY: create points to initialized Vulkan ABI records and instance is
    // writable storage; no extensions or layers are requested by this probe.
    let status = unsafe { create_instance(&create, ptr::null(), &mut instance) };
    if status != VK_SUCCESS || instance.is_null() { return Err("vkCreateInstance failed"); }
    let enumerate = unsafe { symbol::<EnumeratePhysicalDevices>(get_proc, instance, c"vkEnumeratePhysicalDevices") }.ok_or("physical-device enumeration is unavailable")?;
    let mut count = 0;
    // SAFETY: count is writable storage and the live instance owns enumeration.
    let status = unsafe { enumerate(instance, &mut count, ptr::null_mut()) };
    if status != VK_SUCCESS && status != VK_INCOMPLETE { return Err("physical-device count failed"); }
    if count == 0 { return Err("Vulkan reports no physical devices"); }
    println!("native-vulkan: PASS api={} physical_devices={count}", version_text(api_version));
    // SAFETY: instance was created by this function and no child objects exist.
    let destroy = unsafe { symbol::<DestroyInstance>(get_proc, instance, c"vkDestroyInstance") }.ok_or("vkDestroyInstance is unavailable")?;
    unsafe { destroy(instance, ptr::null()); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::version_text;

    #[test]
    fn vulkan_version_fields_are_rendered_without_losing_bits() {
        assert_eq!(version_text((1 << 22) | (4 << 12) | 313), "1.4.313");
        assert_eq!(version_text((1 << 22) | (0 << 12) | 0), "1.0.0");
    }
}
