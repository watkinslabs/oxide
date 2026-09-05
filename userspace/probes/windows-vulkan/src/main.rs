use windows_vulkan::{query, HandoffResult, PresentSession, SurfaceDescription, SurfaceFormat, SurfaceHandoff};

fn main() {
    match query() {
        Ok(capability) => {
            let format = if capability.format_mask & 1 != 0 { SurfaceFormat::Xrgb8888 } else { SurfaceFormat::Argb8888 };
            let description = SurfaceDescription { window: 41, window_owner: 7, device: 11, queue: 13, resource: 17, device_ready: true, surface_alive: true, present_supported: true, width: capability.max_width.min(1280), height: capability.max_height.min(720), format };
            let mut session = PresentSession::create(capability, description).expect("native capability cannot admit its own WSI contract");
            session.acquire(SurfaceHandoff { window: 41, window_owner: 7, device: 11, queue: 13, resource: 17 }).expect("WSI acquire contract failed");
            session.present(HandoffResult::Submitted).expect("WSI present contract failed");
            println!("windows-vulkan: PASS version={} max={}x{} formats=0x{:x} present=ready", capability.version, capability.max_width, capability.max_height, capability.format_mask);
        },
        Err(windows_vulkan::VulkanError::Unsupported) => println!("windows-vulkan: UNSUPPORTED native 3D/render capability absent"),
        Err(error) => panic!("windows-vulkan: failed: {error:?}"),
    }
}
