//! Module manifest: native owns font resources; render uses windows-gdi; platform owns callback ABI.
mod native;
mod render;
mod measure;
mod query;
mod resource;
mod outline;
mod nonclient;
mod platform;
pub use native::install;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod measure_tests;
#[cfg(test)]
mod query_tests;
#[cfg(test)]
mod glyph_tests;
#[cfg(test)]
mod query_entry_tests;
#[cfg(test)]
mod nonclient_tests;
