extern crate alloc;

mod parser;
mod runtime;

pub use parser::{parse_psf2, Font, Psf1Header, Psf2Header};
pub use runtime::{
    active, clear_unimap, get_font, set_default, set_font, set_unimap, unimap,
};

#[cfg(test)]
pub use parser::set_font_with_map;

#[cfg(test)]
mod tests;
