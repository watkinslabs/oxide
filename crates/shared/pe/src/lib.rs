#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
extern crate alloc;
#[cfg(any(test, feature = "hosted"))] extern crate std;
mod parser;
pub use parser::*;
pub mod image_info;
pub mod image_view;
pub use image_info::{image_information, ImageInformation, SECTION_IMAGE_INFORMATION_BYTES};
pub use image_view::{image_section, shared_writable_sections, materialize_view, view_alignment, view_layout, ImageSection, SpanProt, ViewSpan};
pub mod nt_stub;
pub mod catalog;
pub mod apiset;
pub mod loader_list;
pub mod loader_name;
pub mod relay;
pub mod ntdll;
#[cfg(test)] mod tests;
