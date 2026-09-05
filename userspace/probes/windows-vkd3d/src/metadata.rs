const MAX_EXTENSIONS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum D3d12FeatureLevel { Level11_0, Level12_0, Level12_1 }
impl D3d12FeatureLevel { pub fn as_str(self) -> &'static str { match self { Self::Level11_0 => "11.0", Self::Level12_0 => "12.0", Self::Level12_1 => "12.1" } } }

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VulkanVersion { pub major: u8, pub minor: u8, pub patch: u16 }
impl VulkanVersion { pub const fn new(major: u8, minor: u8, patch: u16) -> Self { Self { major, minor, patch } } }
impl std::fmt::Display for VulkanVersion { fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(out, "{}.{}.{}", self.major, self.minor, self.patch) } }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslationMetadata { feature_level: D3d12FeatureLevel, vulkan: VulkanVersion, extensions: Box<[Box<str>]> }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataError { UnsupportedVulkan, EmptyExtension, InvalidExtension, TooManyExtensions, DuplicateExtension }

/// Validate bounded metadata consumed by the D3D12-to-Vulkan translator.
/// # C: O(extension count × extension length)
impl TranslationMetadata {
    pub fn new<I, S>(feature_level: D3d12FeatureLevel, vulkan: VulkanVersion, extensions: I) -> Result<Self, MetadataError> where I: IntoIterator<Item = S>, S: AsRef<str> {
        if vulkan.major != 1 || vulkan.minor < 1 { return Err(MetadataError::UnsupportedVulkan); }
        let mut owned: Vec<Box<str>> = Vec::new();
        for extension in extensions {
            if owned.len() == MAX_EXTENSIONS { return Err(MetadataError::TooManyExtensions); }
            let extension = extension.as_ref();
            if extension.is_empty() { return Err(MetadataError::EmptyExtension); }
            if !extension.starts_with("VK_") || !extension.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') { return Err(MetadataError::InvalidExtension); }
            if owned.iter().any(|item| item.as_ref() == extension) { return Err(MetadataError::DuplicateExtension); }
            owned.push(extension.into());
        }
        if !owned.iter().any(|extension| extension.as_ref() == "VK_KHR_swapchain") { return Err(MetadataError::InvalidExtension); }
        Ok(Self { feature_level, vulkan, extensions: owned.into_boxed_slice() })
    }
    pub fn feature_level(&self) -> &'static str { self.feature_level.as_str() }
    pub fn vulkan_version(&self) -> VulkanVersion { self.vulkan }
    pub fn required_extensions(&self) -> &[Box<str>] { &self.extensions }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> TranslationMetadata { TranslationMetadata::new(D3d12FeatureLevel::Level12_0, VulkanVersion::new(1, 2, 0), ["VK_KHR_swapchain", "VK_KHR_timeline_semaphore"]).unwrap() }
    #[test] fn metadata_preserves_d3d12_source_and_vulkan_target() { let value = valid(); assert_eq!(value.feature_level(), "12.0"); assert_eq!(value.vulkan_version(), VulkanVersion::new(1, 2, 0)); assert_eq!(value.required_extensions().len(), 2); }
    #[test] fn metadata_rejects_missing_swapchain_and_bad_versions() { assert_eq!(TranslationMetadata::new(D3d12FeatureLevel::Level11_0, VulkanVersion::new(1, 2, 0), ["VK_KHR_timeline_semaphore"]), Err(MetadataError::InvalidExtension)); assert_eq!(TranslationMetadata::new(D3d12FeatureLevel::Level12_1, VulkanVersion::new(1, 0, 0), ["VK_KHR_swapchain"]), Err(MetadataError::UnsupportedVulkan)); }
    #[test] fn metadata_rejects_duplicate_malformed_and_oversized_extension_sets() { assert_eq!(TranslationMetadata::new(D3d12FeatureLevel::Level12_0, VulkanVersion::new(1, 2, 0), ["VK_KHR_swapchain", "VK_KHR_swapchain"]), Err(MetadataError::DuplicateExtension)); assert_eq!(TranslationMetadata::new(D3d12FeatureLevel::Level12_0, VulkanVersion::new(1, 2, 0), ["swapchain"]), Err(MetadataError::InvalidExtension)); let many = (0..17).map(|n| format!("VK_EXT_TEST_{n}")); assert_eq!(TranslationMetadata::new(D3d12FeatureLevel::Level12_0, VulkanVersion::new(1, 2, 0), many.chain(std::iter::once(String::from("VK_KHR_swapchain")))), Err(MetadataError::TooManyExtensions)); }
    #[test] fn metadata_requires_nonempty_extension_names() { assert_eq!(TranslationMetadata::new(D3d12FeatureLevel::Level12_0, VulkanVersion::new(1, 2, 0), ["VK_KHR_swapchain", ""]), Err(MetadataError::EmptyExtension)); }
}
