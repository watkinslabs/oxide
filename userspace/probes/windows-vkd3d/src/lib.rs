//! W8 D3D12-to-Vulkan admission: immutable component identity and translation metadata.

mod admission;
mod metadata;

pub use admission::{admit, ComponentError, Vkd3dComponent};
pub use metadata::{D3d12FeatureLevel, MetadataError, TranslationMetadata, VulkanVersion};
