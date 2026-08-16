//! The state carried down a layer walk.
//!
//! The name being looked up is NOT constant: a redirect found on one layer
//! rewrites it before the next layer is tried. Everything else here is an
//! answer accumulated on the way down — whether to keep descending, whether
//! what was found is a directory, and what the topmost layer said about the
//! object's data.

extern crate alloc;

use alloc::string::{String, ToString};

use crate::layers::LayerStack;

/// State threaded through one lookup of one name.
pub struct Data<'a> {
    pub stack: &'a LayerStack,
    /// Name currently being resolved. A redirect replaces it, and an absolute
    /// redirect makes it a whole path from a layer's root.
    pub name: String,
    /// Something found so far is a directory, so lower layers must offer a
    /// directory too for the merge to continue.
    pub is_dir: bool,
    /// The topmost layer said nothing below this name is visible.
    pub opaque: bool,
    /// Some layer walked through carries regular-file whiteouts.
    pub xwhiteouts: bool,
    /// Stop descending: a whiteout, an opaque directory, or a complete
    /// non-directory was found.
    pub stop: bool,
    /// This is the last layer worth asking, so the cheaper checks that only
    /// matter for continuing may be skipped.
    pub last: bool,
    /// The rewritten name, once any redirect has been followed.
    pub redirect: Option<String>,
    /// The rewritten name as of the end of the WRITABLE layer's walk, kept
    /// separately because it is what gets recorded on the overlay object.
    pub upperredirect: Option<String>,
    /// Size of the metadata-only record on the object found, zero when there
    /// is none. A non-zero value means the walk must keep going to find data.
    pub metacopy: usize,
    /// The redirect last followed started at a layer root.
    pub absolute_redirect: bool,
}

impl<'a> Data<'a> {
    /// Start a walk for `name`. # C: O(len(name))
    pub fn new(stack: &'a LayerStack, name: &str, last: bool) -> Data<'a> {
        Data {
            stack, name: name.to_string(), is_dir: false, opaque: false, xwhiteouts: false,
            stop: false, last, redirect: None, upperredirect: None, metacopy: 0,
            absolute_redirect: false,
        }
    }

    /// May the walk act on what it has found?
    ///
    /// Following a redirect or a metadata-only record is reaching into a lower
    /// layer without having walked, and therefore without having been
    /// permission-checked, through the directories along the way. When the
    /// mount did not ask for the feature that wrote the record, the record was
    /// not written by anything this mount trusts, and following it is refused
    /// rather than obeyed.
    /// # C: O(1)
    pub fn may_follow(&self) -> bool {
        let c = &self.stack.config;
        if self.metacopy > 0 && !c.metacopy { return false; }
        if (self.redirect.is_some() || self.upperredirect.is_some()) && !c.redirect_follow() {
            return false;
        }
        true
    }
}
