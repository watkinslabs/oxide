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
const VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO: u32 = 2;
const VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO: u32 = 3;
const VK_QUEUE_GRAPHICS_BIT: u32 = 1;

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

#[derive(Clone, Copy)]
#[repr(C)]
struct QueueFamilyProperties {
    queue_flags: u32,
    queue_count: u32,
    timestamp_valid_bits: u32,
    min_image_transfer_granularity: [u32; 3],
}

#[repr(C)]
struct DeviceQueueCreateInfo {
    s_type: u32,
    next: *const c_void,
    flags: u32,
    queue_family_index: u32,
    queue_count: u32,
    queue_priorities: *const f32,
}

#[repr(C)]
struct DeviceCreateInfo {
    s_type: u32,
    next: *const c_void,
    flags: u32,
    queue_create_info_count: u32,
    queue_create_infos: *const DeviceQueueCreateInfo,
    enabled_layer_count: u32,
    enabled_layer_names: *const *const c_char,
    enabled_extension_count: u32,
    enabled_extension_names: *const *const c_char,
    enabled_features: *const c_void,
}

type GetProcAddr = unsafe extern "C" fn(*mut c_void, *const c_char) -> *const c_void;
type CreateInstance = unsafe extern "C" fn(*const InstanceCreateInfo, *const c_void, *mut *mut c_void) -> i32;
type DestroyInstance = unsafe extern "C" fn(*mut c_void, *const c_void);
type EnumeratePhysicalDevices = unsafe extern "C" fn(*mut c_void, *mut u32, *mut *mut c_void) -> i32;
type EnumerateInstanceVersion = unsafe extern "C" fn(*mut u32) -> i32;
type GetPhysicalDeviceQueueFamilyProperties = unsafe extern "C" fn(*mut c_void, *mut u32, *mut QueueFamilyProperties);
type CreateDevice = unsafe extern "C" fn(*mut c_void, *const DeviceCreateInfo, *const c_void, *mut *mut c_void) -> i32;
type GetDeviceQueue = unsafe extern "C" fn(*mut c_void, u32, u32, *mut *mut c_void);
type DeviceWaitIdle = unsafe extern "C" fn(*mut c_void) -> i32;
type DestroyDevice = unsafe extern "C" fn(*mut c_void, *const c_void);

fn usable_device_handles(status: i32, handles: &[*mut c_void]) -> bool {
    (status == VK_SUCCESS || status == VK_INCOMPLETE)
        && !handles.is_empty()
        && handles.iter().all(|handle| !handle.is_null())
}

fn graphics_queue_family(properties: &[QueueFamilyProperties]) -> Option<u32> {
    properties.iter().enumerate().find(|(_, property)| {
        property.queue_count != 0 && property.queue_flags & VK_QUEUE_GRAPHICS_BIT != 0
    }).map(|(index, _)| index as u32)
}

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
    let mut devices = vec![ptr::null_mut(); count as usize];
    let status = unsafe { enumerate(instance, &mut count, devices.as_mut_ptr()) };
    devices.truncate(count as usize);
    if !usable_device_handles(status, &devices) {
        return Err("Vulkan returned no usable physical-device handles");
    }
    let queue_properties = unsafe { symbol::<GetPhysicalDeviceQueueFamilyProperties>(get_proc, instance, c"vkGetPhysicalDeviceQueueFamilyProperties") }.ok_or("queue-family enumeration is unavailable")?;
    let mut queue_count = 0;
    // SAFETY: the physical device belongs to the live instance and the null
    // properties pointer requests the loader's required count-only query.
    unsafe { queue_properties(devices[0], &mut queue_count, ptr::null_mut()); }
    if queue_count == 0 { return Err("Vulkan reports no queue families"); }
    let mut properties = vec![QueueFamilyProperties { queue_flags: 0, queue_count: 0, timestamp_valid_bits: 0, min_image_transfer_granularity: [0; 3] }; queue_count as usize];
    // SAFETY: properties has exactly the capacity returned by the preceding
    // count query and remains owned and writable for this call.
    unsafe { queue_properties(devices[0], &mut queue_count, properties.as_mut_ptr()); }
    properties.truncate(queue_count as usize);
    let queue_family = graphics_queue_family(&properties).ok_or("Vulkan has no graphics queue family")?;
    let priority = 1.0f32;
    let queue_info = DeviceQueueCreateInfo { s_type: VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, next: ptr::null(), flags: 0, queue_family_index: queue_family, queue_count: 1, queue_priorities: &priority };
    let device_info = DeviceCreateInfo { s_type: VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, next: ptr::null(), flags: 0, queue_create_info_count: 1, queue_create_infos: &queue_info, enabled_layer_count: 0, enabled_layer_names: ptr::null(), enabled_extension_count: 0, enabled_extension_names: ptr::null(), enabled_features: ptr::null() };
    let create_device = unsafe { symbol::<CreateDevice>(get_proc, instance, c"vkCreateDevice") }.ok_or("vkCreateDevice is unavailable")?;
    let get_queue = unsafe { symbol::<GetDeviceQueue>(get_proc, instance, c"vkGetDeviceQueue") }.ok_or("vkGetDeviceQueue is unavailable")?;
    let wait_idle = unsafe { symbol::<DeviceWaitIdle>(get_proc, instance, c"vkDeviceWaitIdle") }.ok_or("vkDeviceWaitIdle is unavailable")?;
    let destroy_device = unsafe { symbol::<DestroyDevice>(get_proc, instance, c"vkDestroyDevice") }.ok_or("vkDestroyDevice is unavailable")?;
    let destroy_instance = unsafe { symbol::<DestroyInstance>(get_proc, instance, c"vkDestroyInstance") }.ok_or("vkDestroyInstance is unavailable")?;
    let mut device = ptr::null_mut();
    // SAFETY: the selected physical device and queue description came from the
    // live instance; device is writable storage owned by this function.
    let status = unsafe { create_device(devices[0], &device_info, ptr::null(), &mut device) };
    if status != VK_SUCCESS || device.is_null() { return Err("vkCreateDevice failed"); }
    let mut queue = ptr::null_mut();
    // SAFETY: device owns the selected queue family and queue is writable
    // storage for the first queue requested from that family.
    unsafe { get_queue(device, queue_family, 0, &mut queue); }
    if queue.is_null() {
        // SAFETY: device creation succeeded, no queue was returned, and the
        // device is the sole child object that must be retired before instance.
        unsafe { destroy_device(device, ptr::null()); }
        return Err("Vulkan returned a null graphics queue");
    }
    // SAFETY: device is live and no command is submitted; this still proves
    // the synchronization entry point is callable before teardown.
    if unsafe { wait_idle(device) } != VK_SUCCESS {
        // SAFETY: device creation succeeded and the failed idle query still
        // leaves its ownership with this function for deterministic teardown.
        unsafe { destroy_device(device, ptr::null()); }
        return Err("vkDeviceWaitIdle failed");
    }
    // SAFETY: queue is owned by device and is idle, so device destruction is
    // the first valid lifetime boundary before destroying its parent instance.
    unsafe { destroy_device(device, ptr::null()); }
    println!("native-vulkan: PASS api={} physical_devices={}", version_text(api_version), devices.len());
    // SAFETY: the device was destroyed above, so the instance has no live child
    // objects and remains owned by this function until this call completes.
    unsafe { destroy_instance(instance, ptr::null()); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{graphics_queue_family, usable_device_handles, version_text, QueueFamilyProperties, VK_INCOMPLETE, VK_SUCCESS, VK_QUEUE_GRAPHICS_BIT};

    #[test]
    fn vulkan_version_fields_are_rendered_without_losing_bits() {
        assert_eq!(version_text((1 << 22) | (4 << 12) | 313), "1.4.313");
        assert_eq!(version_text((1 << 22) | (0 << 12) | 0), "1.0.0");
    }

    #[test]
    fn physical_device_enumeration_requires_non_null_handles() {
        let valid = [1usize as *mut std::ffi::c_void];
        assert!(usable_device_handles(VK_SUCCESS, &valid));
        assert!(usable_device_handles(VK_INCOMPLETE, &valid));
        assert!(!usable_device_handles(VK_SUCCESS, &[]));
        assert!(!usable_device_handles(VK_SUCCESS, &[std::ptr::null_mut()]));
        assert!(!usable_device_handles(-1, &valid));
    }

    #[test]
    fn device_admission_requires_a_live_graphics_queue() {
        let compute_only = [QueueFamilyProperties { queue_flags: 2, queue_count: 1, timestamp_valid_bits: 0, min_image_transfer_granularity: [1; 3] }];
        assert_eq!(graphics_queue_family(&compute_only), None);
        let graphics = [QueueFamilyProperties { queue_flags: VK_QUEUE_GRAPHICS_BIT, queue_count: 1, timestamp_valid_bits: 0, min_image_transfer_granularity: [1; 3] }];
        assert_eq!(graphics_queue_family(&graphics), Some(0));
    }

    #[test]
    fn queue_family_with_no_queues_is_not_admitted() {
        let empty = [QueueFamilyProperties { queue_flags: VK_QUEUE_GRAPHICS_BIT, queue_count: 0, timestamp_valid_bits: 0, min_image_transfer_granularity: [1; 3] }];
        assert_eq!(graphics_queue_family(&empty), None);
    }
}
