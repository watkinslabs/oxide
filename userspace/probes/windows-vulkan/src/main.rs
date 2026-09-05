use windows_vulkan::query;

fn main() {
    match query() {
        Ok(capability) => println!("windows-vulkan: PASS version={} max={}x{} formats=0x{:x}", capability.version, capability.max_width, capability.max_height, capability.format_mask),
        Err(windows_vulkan::VulkanError::Unsupported) => println!("windows-vulkan: UNSUPPORTED native 3D/render capability absent"),
        Err(error) => panic!("windows-vulkan: failed: {error:?}"),
    }
}
