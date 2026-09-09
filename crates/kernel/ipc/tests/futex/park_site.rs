//! Thread-local scheduler diagnostic seam; production wait sites call note.
use core::panic::Location;
std::thread_local! {
    static SITE: std::cell::Cell<Option<&'static Location<'static>>> = const { std::cell::Cell::new(None) };
}
pub fn note(site: &'static Location<'static>) { SITE.with(|s| s.set(Some(site))); }
pub fn get() -> Option<&'static Location<'static>> { SITE.with(|s| s.get()) }
