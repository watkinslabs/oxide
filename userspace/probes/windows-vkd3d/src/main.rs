use windows_vkd3d::{D3d12FeatureLevel, TranslationMetadata, VulkanVersion};

fn main() {
    let metadata = TranslationMetadata::new(D3d12FeatureLevel::Level12_0, VulkanVersion::new(1, 2, 0), ["VK_KHR_swapchain", "VK_KHR_timeline_semaphore"]).expect("fixed W8 metadata must be valid");
    println!("windows-vkd3d d3d12={} vulkan={} extensions={}", metadata.feature_level(), metadata.vulkan_version(), metadata.required_extensions().len());
}
