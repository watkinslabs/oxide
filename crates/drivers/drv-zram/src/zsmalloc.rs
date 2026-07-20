//! Module manifest: Linux zsmalloc-shaped class layout, object handles, pool storage, and tests.

mod class;
mod handle;
mod limits;
mod platform;
mod pool;

pub(crate) use handle::Handle;
pub(crate) use pool::ZsPool;
pub use platform::{install_page_provider, page_provider_ready, PageProvider};

#[cfg(any(test, feature = "hosted"))]
pub(crate) use platform::install_hosted_test_provider;

#[cfg(test)]
mod tests;
